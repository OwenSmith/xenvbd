/* Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */ 

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include <xen.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <evtchn_interface.h>

#include "blockring.h"
#include "target.h"
#include "adapter.h"
#include "granter.h"
#include "adapter.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define XEN_IO_PROTO_ABI            "x86_64-abi"
#define XENVBD_MAX_RING_PAGE_ORDER  (4)
#define XENVBD_MAX_RING_PAGES       (1 << XENVBD_MAX_RING_PAGE_ORDER)

struct _XENVBD_BLOCKRING {
    PXENVBD_TARGET          Target;
    BOOLEAN                 Connected;
    BOOLEAN                 Enabled;

    XENBUS_STORE_INTERFACE  StoreInterface;
    XENBUS_DEBUG_INTERFACE  DebugInterface;
    XENBUS_EVTCHN_INTERFACE EvtchnInterface;

    PXENBUS_DEBUG_CALLBACK  DebugCallback;

    KSPIN_LOCK              Lock;
    PMDL                    Mdl;
    blkif_sring_t*          Shared;
    blkif_front_ring_t      Front;
    ULONG                   Order;
    PVOID                   Grants[XENVBD_MAX_RING_PAGES];

    PXENBUS_EVTCHN_CHANNEL  Channel;
    KDPC                    Dpc;

    ULONG                   Submitted;
    ULONG                   Completed;
    ULONG                   Interrupts;
    ULONG                   Dpcs;
};

#define BLOCKRING_POOL_TAG  'gnRX'
#define xen_mb              KeMemoryBarrier
#define xen_wmb             KeMemoryBarrier
#define xen_rmb             KeMemoryBarrier

static FORCEINLINE PVOID
__BlockRingAllocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;
    Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   Size,
                                   BLOCKRING_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);
    return Buffer;
}

static FORCEINLINE VOID
__BlockRingFree(
    IN  PVOID   Buffer
    )
{
    if (Buffer)
        ExFreePoolWithTag(Buffer, BLOCKRING_POOL_TAG);
}

KSERVICE_ROUTINE BlockRingInterrupt;

BOOLEAN
BlockRingInterrupt(
    __in  PKINTERRUPT   Interrupt,
    _In_opt_ PVOID      Context
    )
{
    PXENVBD_BLOCKRING   BlockRing = Context;
    
    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(BlockRing != NULL);

	++BlockRing->Interrupts;
	if (KeInsertQueueDpc(&BlockRing->Dpc, NULL, NULL))
		++BlockRing->Dpcs;

    return TRUE;
}

KDEFERRED_ROUTINE BlockRingDpc;

VOID 
BlockRingDpc(
    __in  PKDPC         Dpc,
    __in_opt PVOID      Context,
    __in_opt PVOID      Arg1,
    __in_opt PVOID      Arg2
    )
{
    PXENVBD_BLOCKRING   BlockRing = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(BlockRing != NULL);

    (VOID) BlockRingPoll(BlockRing);

    XENBUS_EVTCHN(Unmask,
                  &BlockRing->EvtchnInterface,
                  BlockRing->Channel,
                  FALSE);
}

static DECLSPEC_NOINLINE VOID
BlockRingDebugCallback(
    IN  PVOID           Context,
    IN  BOOLEAN         Crashing
    )
{
    PXENVBD_BLOCKRING   BlockRing = Context;
    PXENVBD_GRANTER     Granter;
    ULONG               Port;
    ULONG               Grant;
    ULONG               Index;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Order: %u\n",
                 BlockRing->Order);

    Granter = TargetGetGranter(BlockRing->Target);
    for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
        Grant = GranterReference(Granter, BlockRing->Grants[Index]);

        XENBUS_DEBUG(Printf,
                     &BlockRing->DebugInterface,
                     "Grant[%02u] : 0x%p (%u)\n",
                     Index,
                     BlockRing->Grants[Index],
                     Grant);
    }

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Shared:0x%p : req_prod:%u, req_event:%u, rsp_prod:%u, rsp_event:%u\n",
                 BlockRing->Shared,
                 BlockRing->Shared->req_prod,
                 BlockRing->Shared->req_event,
                 BlockRing->Shared->rsp_prod,
                 BlockRing->Shared->rsp_event);

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Front: req_prod_pvt:%u, rsp_cons:%u, nr_ents:%u, sring:0x%p\n",
                 BlockRing->Front.req_prod_pvt,
                 BlockRing->Front.rsp_cons,
                 BlockRing->Front.nr_ents,
                 BlockRing->Front.sring);

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Submitted: %u, Completed: %u\n",
                 BlockRing->Submitted,
                 BlockRing->Completed);

    Port = XENBUS_EVTCHN(GetPort,
                         &BlockRing->EvtchnInterface,
                         BlockRing->Channel);

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Channel: 0x%p (%u)\n",
                 BlockRing->Channel,
                 Port);

    XENBUS_DEBUG(Printf,
                 &BlockRing->DebugInterface,
                 "Interrupts: %u, DPCs: %u\n",
                 BlockRing->Interrupts,
                 BlockRing->Dpcs);

    BlockRing->Interrupts = 0;
    BlockRing->Dpcs = 0;
}

NTSTATUS
BlockRingCreate(
    IN  PXENVBD_TARGET      Target,
    OUT PXENVBD_BLOCKRING*  BlockRing
    )
{
    *BlockRing = __BlockRingAllocate(sizeof(XENVBD_BLOCKRING));
    if (*BlockRing == NULL)
        goto fail1;

    (*BlockRing)->Target = Target;
    KeInitializeSpinLock(&(*BlockRing)->Lock);
    KeInitializeDpc(&(*BlockRing)->Dpc, BlockRingDpc, *BlockRing);

    return STATUS_SUCCESS;

fail1:
    return STATUS_NO_MEMORY;
}

VOID
BlockRingDestroy(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    BlockRing->Target = NULL;
    RtlZeroMemory(&BlockRing->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&BlockRing->Dpc, sizeof(KDPC));
    
    ASSERT(IsZeroMemory(BlockRing, sizeof(XENVBD_BLOCKRING)));
    
    __BlockRingFree(BlockRing);
}

NTSTATUS
BlockRingConnect(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    PXENVBD_GRANTER         Granter;
    PXENVBD_ADAPTER         Adapter;
    PCHAR                   Buffer;
    ULONG                   Index;
    NTSTATUS                status;

    ASSERT(BlockRing->Connected == FALSE);

    Adapter = TargetGetAdapter(BlockRing->Target);

    AdapterGetStoreInterface(Adapter, &BlockRing->StoreInterface);
    AdapterGetDebugInterface(Adapter, &BlockRing->DebugInterface);
    AdapterGetEvtchnInterface(Adapter, &BlockRing->EvtchnInterface);

    status = XENBUS_STORE(Acquire, &BlockRing->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &BlockRing->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &BlockRing->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_STORE(Read,
                          &BlockRing->StoreInterface,
                          NULL,
                          TargetGetBackendPath(BlockRing->Target),
                          "max-ring-page-order",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        BlockRing->Order = strtoul(Buffer, NULL, 10);
        BlockRing->Order = min(BlockRing->Order, XENVBD_MAX_RING_PAGE_ORDER);

        XENBUS_STORE(Free,
                     &BlockRing->StoreInterface, 
                     Buffer);
    } else {
        BlockRing->Order = 0;
    }

    status = STATUS_NO_MEMORY;
    BlockRing->Mdl = __AllocatePages(1 << BlockRing->Order);
    if (BlockRing->Mdl == NULL)
        goto fail4;

    BlockRing->Shared = MmGetSystemAddressForMdlSafe(BlockRing->Mdl, NormalPagePriority); 
    ASSERT(BlockRing->Shared != NULL);

#pragma warning(push)
#pragma warning(disable: 4305)
#pragma warning(disable: 4311)
    SHARED_RING_INIT(BlockRing->Shared);
    FRONT_RING_INIT(&BlockRing->Front, BlockRing->Shared, PAGE_SIZE << BlockRing->Order);
#pragma warning(pop)

    Granter = TargetGetGranter(BlockRing->Target);
    for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
        status = GranterGet(Granter,
                            MmGetMdlPfnArray(BlockRing->Mdl)[Index],
                            FALSE,
                            &BlockRing->Grants[Index]);
        if (!NT_SUCCESS(status))
            goto fail5;
    }

    status = STATUS_NO_MEMORY;
    BlockRing->Channel = XENBUS_EVTCHN(Open,
                                       &BlockRing->EvtchnInterface,
                                       XENBUS_EVTCHN_TYPE_UNBOUND,
                                       BlockRingInterrupt,
                                       BlockRing,
                                       TargetGetBackendId(BlockRing->Target),
                                       TRUE);
    if (BlockRing->Channel == NULL)
        goto fail6;

    status = XENBUS_DEBUG(Register,
                          &BlockRing->DebugInterface,
                          __MODULE__,
                          BlockRingDebugCallback,
                          BlockRing,
                          &BlockRing->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail7;

    XENBUS_EVTCHN(Unmask,
                  &BlockRing->EvtchnInterface,
                  BlockRing->Channel,
                  FALSE);

    BlockRing->Connected = TRUE;
    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");
    XENBUS_EVTCHN(Close,
                  &BlockRing->EvtchnInterface,
                  BlockRing->Channel);
    BlockRing->Channel = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
        if (BlockRing->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, BlockRing->Grants[Index]);
        BlockRing->Grants[Index] = NULL;
    }

    RtlZeroMemory(&BlockRing->Front, sizeof(blkif_front_ring_t));
    BlockRing->Shared = NULL;

    __FreePages(BlockRing->Mdl);
    BlockRing->Mdl = NULL;
fail4:
    Error("fail4\n");
    XENBUS_EVTCHN(Release, &BlockRing->EvtchnInterface);
    RtlZeroMemory(&BlockRing->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));
fail3:
    Error("fail3\n"); 
    XENBUS_DEBUG(Release, &BlockRing->DebugInterface);
    RtlZeroMemory(&BlockRing->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
fail2:
    Error("fail2\n"); 
    XENBUS_STORE(Release, &BlockRing->StoreInterface);
    RtlZeroMemory(&BlockRing->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));
fail1:
     Error("fail1 %08x\n", status);
     return status;
}

NTSTATUS
BlockRingStoreWrite(
    IN  PXENVBD_BLOCKRING   BlockRing,
    IN  PVOID               Transaction
    )
{
    PXENVBD_GRANTER         Granter;
    ULONG                   Port;
    ULONG                   Grant;
    NTSTATUS                status;

    Granter = TargetGetGranter(BlockRing->Target);
    if (BlockRing->Order == 0) {
        Grant = GranterReference(Granter, BlockRing->Grants[0]);

        status = XENBUS_STORE(Printf, 
                              &BlockRing->StoreInterface, 
                              Transaction, 
                              TargetGetPath(BlockRing->Target),
                              "ring-ref", 
                              "%u", 
                              Grant);
        if (!NT_SUCCESS(status))
            return status;
    } else {
        ULONG               Index;

        status = XENBUS_STORE(Printf, 
                              &BlockRing->StoreInterface, 
                              Transaction, 
                              TargetGetPath(BlockRing->Target),
                              "ring-page-order", 
                              "%u", 
                              BlockRing->Order);
        if (!NT_SUCCESS(status))
            return status;

        for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
            CHAR            Name[sizeof("ring-refXX")];

            status = RtlStringCbPrintfA(Name,
                                        sizeof(Name),
                                        "ring-ref%u",
                                        Index);
            if (!NT_SUCCESS(status))
                return status;

            Grant = GranterReference(Granter, BlockRing->Grants[Index]);

            status = XENBUS_STORE(Printf, 
                                  &BlockRing->StoreInterface, 
                                  Transaction, 
                                  TargetGetPath(BlockRing->Target),
                                  Name, 
                                  "%u", 
                                  Grant);
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    status = XENBUS_STORE(Printf, 
                          &BlockRing->StoreInterface, 
                          Transaction, 
                          TargetGetPath(BlockRing->Target), 
                          "protocol", 
                          "%s", 
                          XEN_IO_PROTO_ABI);
    if (!NT_SUCCESS(status))
        return status;

    Port = XENBUS_EVTCHN(GetPort,
                         &BlockRing->EvtchnInterface,
                         BlockRing->Channel);

    status = XENBUS_STORE(Printf, 
                          &BlockRing->StoreInterface, 
                          Transaction, 
                          TargetGetPath(BlockRing->Target), 
                          "event-channel", 
                          "%u", 
                          Port);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

VOID
BlockRingEnable(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    ASSERT(BlockRing->Enabled == FALSE);
    BlockRing->Enabled = TRUE;

    XENBUS_EVTCHN(Trigger,
                  &BlockRing->EvtchnInterface,
                  BlockRing->Channel);
}

VOID
BlockRingDisable(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    ASSERT(BlockRing->Enabled == TRUE);

    BlockRing->Enabled = FALSE;
}

VOID
BlockRingDisconnect(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    PXENVBD_GRANTER         Granter;
    ULONG                   Index;

    ASSERT(BlockRing->Connected == TRUE);

    XENBUS_DEBUG(Deregister,
                 &BlockRing->DebugInterface,
                 BlockRing->DebugCallback);
    BlockRing->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &BlockRing->EvtchnInterface,
                  BlockRing->Channel);
    BlockRing->Channel = NULL;

    Granter = TargetGetGranter(BlockRing->Target);
    for (Index = 0; Index < (1ul << BlockRing->Order); ++Index) {
        if (BlockRing->Grants[Index] == NULL)
            continue;

        GranterPut(Granter, BlockRing->Grants[Index]);
        BlockRing->Grants[Index] = NULL;
    }

    RtlZeroMemory(&BlockRing->Front, sizeof(blkif_front_ring_t));
    BlockRing->Shared = NULL;

    __FreePages(BlockRing->Mdl);
    BlockRing->Mdl = NULL;

    XENBUS_EVTCHN(Release, &BlockRing->EvtchnInterface);
    RtlZeroMemory(&BlockRing->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));

    XENBUS_DEBUG(Release, &BlockRing->DebugInterface);
    RtlZeroMemory(&BlockRing->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));

    XENBUS_STORE(Release, &BlockRing->StoreInterface);
    RtlZeroMemory(&BlockRing->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

    BlockRing->Connected = FALSE;
}

ULONG
BlockRingPoll(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    ULONG                   Outstanding;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    KeAcquireSpinLockAtDpcLevel(&BlockRing->Lock);

    // Guard against this locked region being called after the 
    // lock on FrontendSetState
    if (BlockRing->Enabled == FALSE)
        goto done;

    for (;;) {
        ULONG   rsp_prod;
        ULONG   rsp_cons;

        KeMemoryBarrier();

        rsp_prod = BlockRing->Shared->rsp_prod;
        rsp_cons = BlockRing->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod)
            break;

        while (rsp_cons != rsp_prod) {
            blkif_response_t*   rsp;

            rsp = RING_GET_RESPONSE(&BlockRing->Front, rsp_cons);
            ++rsp_cons;

            if (!TargetCompleteResponse(BlockRing->Target,
                                        rsp->id,
                                        rsp->status)) {
                XENBUS_DEBUG(Trigger,
                             &BlockRing->DebugInterface,
                             BlockRing->DebugCallback);
            }
            ++BlockRing->Completed;

            // zero entire ring slot (to detect further failures)
            RtlZeroMemory(rsp, sizeof(union blkif_sring_entry));
        }

        KeMemoryBarrier();

        BlockRing->Front.rsp_cons = rsp_cons;
        BlockRing->Shared->rsp_event = rsp_cons + 1;
    }

done:

    // submit all prepared requests, prepare the next srb
    TargetSubmitRequests(BlockRing->Target);

    Outstanding = BlockRing->Submitted - BlockRing->Completed;
    KeReleaseSpinLockFromDpcLevel(&BlockRing->Lock);

    return Outstanding;
}

BOOLEAN
BlockRingSubmit(
    IN  PXENVBD_BLOCKRING   BlockRing,
    IN  PXENVBD_REQUEST     Request
    )
{
    PLIST_ENTRY             ListEntry;
    ULONG                   Index;
    PXENVBD_GRANTER         Granter;
    blkif_request_t*        req;
    BOOLEAN                 Notify;

    // Always called from BlockRing DPC (with BlockRing:Lock held, and Target:QueueLock held)
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL); 

    if (RING_FULL(&BlockRing->Front))
        return FALSE;

    req = RING_GET_REQUEST(&BlockRing->Front, BlockRing->Front.req_prod_pvt);
    ++BlockRing->Front.req_prod_pvt;
    ++BlockRing->Submitted;

    Granter = TargetGetGranter(BlockRing->Target);
    switch (Request->Operation) {
    case BLKIF_OP_DISCARD: {
        blkif_request_discard_t*        req_d;
        req_d = (blkif_request_discard_t*)req;
        req_d->operation        = BLKIF_OP_DISCARD;
        req_d->flag             = Request->Flags;
        req_d->handle           = (USHORT)TargetGetDeviceId(BlockRing->Target);
        req_d->id               = Request->Id;
        req_d->sector_number    = Request->FirstSector;
        req_d->nr_sectors       = Request->NrSectors;
        } break;

    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            // Indirect
            blkif_request_indirect_t*   req_i;
            ULONG                       PageIdx;
            ULONG                       SegIdx;
            PLIST_ENTRY                 PageEntry;
            PLIST_ENTRY                 SegEntry;

            req_i = (blkif_request_indirect_t*)req;
            req_i->operation         = BLKIF_OP_INDIRECT;
            req_i->indirect_op       = Request->Operation;
            req_i->nr_segments       = Request->NrSegments;
            req_i->id                = Request->Id;
            req_i->sector_number     = Request->FirstSector;
            req_i->handle            = (USHORT)TargetGetDeviceId(BlockRing->Target);

            PageEntry = Request->Indirects.Flink;
            SegEntry = Request->Segments.Flink;
            for (PageIdx = 0; PageIdx < BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST; ++PageIdx) {
                PXENVBD_INDIRECT Page;

                if (PageEntry == &Request->Indirects)
                    break;
                if (SegEntry == &Request->Segments)
                    break;

                Page = CONTAINING_RECORD(PageEntry, XENVBD_INDIRECT, ListEntry);
                req_i->indirect_grefs[PageIdx] = GranterReference(Granter, Page->Grant);

                for (SegIdx = 0; SegIdx < XENVBD_MAX_SEGMENTS_PER_PAGE; ++SegIdx) {
                    PXENVBD_SEGMENT Segment;

                    if (SegEntry == &Request->Segments)
                        break;

                    Segment = CONTAINING_RECORD(SegEntry, XENVBD_SEGMENT, ListEntry);
                    Page->Page[SegIdx].GrantRef = GranterReference(Granter, Segment->Grant);
                    Page->Page[SegIdx].First    = Segment->FirstSector;
                    Page->Page[SegIdx].Last     = Segment->LastSector;

                    SegEntry = SegEntry->Flink;
                }

                PageEntry = PageEntry->Flink;
            }
            break; // out of switch
        }
        // intentional fall through
    case BLKIF_OP_WRITE_BARRIER:
    case BLKIF_OP_FLUSH_DISKCACHE:
    default:
        req->operation      = Request->Operation;
        req->nr_segments    = (UCHAR)Request->NrSegments;
        req->handle         = (USHORT)TargetGetDeviceId(BlockRing->Target);
        req->id             = Request->Id;
        req->sector_number  = Request->FirstSector;

        for (ListEntry = Request->Segments.Flink, Index = 0;
             ListEntry != &Request->Segments && Index < BLKIF_MAX_SEGMENTS_PER_REQUEST;
             ListEntry = ListEntry->Flink, ++Index) {
            PXENVBD_SEGMENT Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
            ULONG           Grant;

            Grant = GranterReference(Granter, Segment->Grant);

            req->seg[Index].first_sect = Segment->FirstSector;
            req->seg[Index].last_sect  = Segment->LastSector;
            req->seg[Index].gref       = Grant;
        }
        break;
    }

    KeMemoryBarrier();

    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&BlockRing->Front, Notify);

    if (Notify) {
        XENBUS_EVTCHN(Send,
                      &BlockRing->EvtchnInterface,
                      BlockRing->Channel);
    }

    return TRUE;
}

VOID
BlockRingKick(
    IN  PXENVBD_BLOCKRING   BlockRing
    )
{
    KeInsertQueueDpc(&BlockRing->Dpc, NULL, NULL);
}
