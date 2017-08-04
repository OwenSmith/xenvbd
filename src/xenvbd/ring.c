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
#include <storport.h>
#include <ntstrsafe.h>
#include <stdlib.h>

#include <xen.h>
#include <xencdb.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <cache_interface.h>
#include <debug_interface.h>

#include "ring.h"
#include "target.h"
#include "srbext.h"
#include "adapter.h"
#include "driver.h"

#include "debug.h"
#include "assert.h"
#include "util.h"

#define MAX_RING_PAGE_ORDER (4)
#define MAX_RING_PAGES      (1 << MAX_RING_PAGE_ORDER)
#define xen_mb              KeMemoryBarrier
#define xen_wmb             KeMemoryBarrier
#define XEN_IO_PROTO_ABI    "x86_64-abi"

typedef enum _XENVBD_STAT {
    XENVBD_STAT_READ = 0,
    XENVBD_STAT_WRITE,
    XENVBD_STAT_BARRIER,
    XENVBD_STAT_FLUSH,
    XENVBD_STAT_DISCARD,
    XENVBD_STAT_IND_READ,
    XENVBD_STAT_IND_WRITE,

    // must be last item
    XENVBD_STAT_MAX
} XENVBD_STAT, *PXENVBD_STAT;

struct _XENVBD_RING {
    PXENVBD_TARGET          Target;
    BOOLEAN                 Connected;
    BOOLEAN                 Enabled;
    BOOLEAN                 Stopped;

    XENBUS_DEBUG_INTERFACE  DebugInterface;
    XENBUS_STORE_INTERFACE  StoreInterface;
    XENBUS_CACHE_INTERFACE  CacheInterface;
    XENBUS_EVTCHN_INTERFACE EvtchnInterface;
    XENBUS_GNTTAB_INTERFACE GnttabInterface;

    PXENBUS_GNTTAB_CACHE    GrantCache;
    PXENBUS_DEBUG_CALLBACK  DebugCallback;
    PXENBUS_CACHE           RequestCache;
    PXENBUS_CACHE           SegmentCache;
    PXENBUS_CACHE           IndirectCache;

    PVOID                   Lock;
    PKTHREAD                LockThread;

    LIST_ENTRY              QueuedSrbs;
    ULONG                   SrbsQueued;
    ULONG                   SrbsCompleted;

    LIST_ENTRY              PreparedReqs;
    ULONG                   ReqsPrepared;
    LIST_ENTRY              InFlightReqs;
    ULONG                   ReqsInFlight;

    KDPC                    Dpc;
    KDPC                    TimerDpc;
    KTIMER                  Timer;
    ULONG                   NumInts;
    ULONG                   NumDpcs;
    ULONG                   NumTimeouts;
    blkif_front_ring_t      Front;
    blkif_sring_t           *Shared;
    PMDL                    Mdl;
    ULONG                   Order;
    PXENBUS_GNTTAB_ENTRY    Grants[MAX_RING_PAGES];
    PXENBUS_EVTCHN_CHANNEL  Channel;

    ULONG                   SegmentsGranted;
    ULONG                   SegmentsBounced;
    ULONG                   RequestsPosted;
    ULONG                   RequestsPushed;
    ULONG                   ResponsesProcessed;
    ULONG                   BlkifOpCount[XENVBD_STAT_MAX];
};

#define RING_POOL_TAG   'gniR'
#define MAX_NAME_LEN    128

static FORCEINLINE PVOID
__RingAllocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;

    Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   Size,
                                   RING_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);

    return Buffer;
}

static FORCEINLINE VOID
__RingFree(
    IN  PVOID   Buffer
    )
{
    ExFreePoolWithTag(Buffer, RING_POOL_TAG);
}

static FORCEINLINE VOID
__RingIncStat(
    IN  PXENVBD_RING    Ring,
    IN  UCHAR           Operation,
    IN  USHORT          NrSegments
    )
{
    XENVBD_STAT         Stat;

    switch (Operation) {
    case BLKIF_OP_READ:
        if (NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            Stat = XENVBD_STAT_IND_READ;
        else
            Stat = XENVBD_STAT_READ;
        break;
    case BLKIF_OP_WRITE:
        if (NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
            Stat = XENVBD_STAT_IND_WRITE;
        else
            Stat = XENVBD_STAT_WRITE;
        break;
    case BLKIF_OP_WRITE_BARRIER:
        Stat = XENVBD_STAT_BARRIER;
        break;
    case BLKIF_OP_FLUSH_DISKCACHE:
        Stat = XENVBD_STAT_FLUSH;
        break;
    case BLKIF_OP_DISCARD:
        Stat = XENVBD_STAT_DISCARD;
        break;
    default:
        return;
    }

    ASSERT3U((ULONG)Stat, <, XENVBD_STAT_MAX);
    ++Ring->BlkifOpCount[Stat];
}

static FORCEINLINE PXENVBD_INDIRECT
__RingGetIndirect(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_INDIRECT    Indirect;

    Indirect = XENBUS_CACHE(Get,
                            &Ring->CacheInterface,
                            Ring->IndirectCache,
                            TRUE);
    if (Indirect == NULL)
        goto fail1;

    ASSERT3P(Indirect->Mdl, !=, NULL);
    ASSERT3P(Indirect->Page, !=, NULL);

    InitializeListHead(&Indirect->ListEntry);

    return Indirect;

fail1:
    Error("fail1\n");
    return NULL;
}

static FORCEINLINE VOID
__RingPutIndirect(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_INDIRECT Indirect
    )
{
    if (Indirect->Grant)
        XENBUS_GNTTAB(RevokeForeignAccess,
                      &Ring->GnttabInterface,
                      Ring->GrantCache,
                      TRUE,
                      Indirect->Grant);
    Indirect->Grant = NULL;

    RtlZeroMemory(&Indirect->ListEntry, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 Ring->IndirectCache,
                 Indirect,
                 TRUE);
}

static FORCEINLINE PXENVBD_SEGMENT
__RingGetSegment(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_SEGMENT     Segment;

    Segment = XENBUS_CACHE(Get,
                           &Ring->CacheInterface,
                           Ring->SegmentCache,
                           TRUE);
    if (Segment == NULL)
        goto fail1;

    InitializeListHead(&Segment->ListEntry);

    return Segment;

fail1:
    Error("fail1\n");
    return NULL;
}

static FORCEINLINE VOID
__RingPutSegment(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SEGMENT Segment
    )
{
    PXENVBD_BOUNCE      Bounce;

    if (Segment->Grant)
        XENBUS_GNTTAB(RevokeForeignAccess,
                      &Ring->GnttabInterface,
                      Ring->GrantCache,
                      TRUE,
                      Segment->Grant);
    Segment->Grant = NULL;

    Bounce = Segment->Bounce;
    Segment->Bounce = NULL;

    if (Bounce) {
        if (Bounce->SourcePtr) {
            MmUnmapLockedPages(Bounce->SourcePtr,
                               &Bounce->SourceMdl);
        }

        AdapterPutBounce(TargetGetAdapter(Ring->Target),
                         Bounce);
    }

    RtlZeroMemory(&Segment->ListEntry, sizeof(LIST_ENTRY));
    Segment->FirstSector = 0;
    Segment->LastSector = 0;

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 Ring->SegmentCache,
                 Segment,
                 TRUE);
}

static FORCEINLINE PXENVBD_REQUEST
__RingGetRequest(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_REQUEST     Request;

    Request = XENBUS_CACHE(Get,
                           &Ring->CacheInterface,
                           Ring->RequestCache,
                           TRUE);
    if (Request == NULL)
        goto fail1;

    Request->Id = (ULONG64)(ULONG_PTR)Request;

    InitializeListHead(&Request->ListEntry);
    InitializeListHead(&Request->Segments);
    InitializeListHead(&Request->Indirects);

    return Request;

fail1:
    Error("fail1\n");
    return NULL;
}

static FORCEINLINE VOID
__RingPutRequest(
    IN  PXENVBD_RING        Ring,
    IN  PXENVBD_REQUEST     Request
    )
{
    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_INDIRECT    Indirect;

        ListEntry = RemoveHeadList(&Request->Indirects);
        if (ListEntry == &Request->Indirects)
            break;

        Indirect = CONTAINING_RECORD(ListEntry, XENVBD_INDIRECT, ListEntry);
        __RingPutIndirect(Ring, Indirect);
    }
    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_SEGMENT     Segment;

        ListEntry = RemoveHeadList(&Request->Segments);
        if (ListEntry == &Request->Segments)
            break;

        Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
        __RingPutSegment(Ring, Segment);
    }

    Request->SrbExt = NULL;
    Request->Id = 0;
    Request->Operation = 0;
    Request->Flags = 0;
    Request->NrSegments = 0;
    Request->FirstSector = 0;
    Request->NrSectors = 0;
    RtlZeroMemory(&Request->ListEntry, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Request->Segments, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Request->Indirects, sizeof(LIST_ENTRY));

    XENBUS_CACHE(Put,
                 &Ring->CacheInterface,
                 Ring->RequestCache,
                 Request,
                 TRUE);
}

static FORCEINLINE VOID
__RingInsertDirect(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request,
    IN  blkif_request_t *req,
    IN  BOOLEAN         HasSegments
    )
{
    req->operation      = Request->Operation;
    req->handle         = (USHORT)TargetGetDeviceId(Ring->Target);
    req->id             = Request->Id;
    req->sector_number  = Request->FirstSector;

    if (!HasSegments) {
        ASSERT(IsListEmpty(&Request->Segments));
        ASSERT(Request->NrSegments == 0);

        req->nr_segments = 0;
    } else {
        ULONG           Index;
        PLIST_ENTRY     ListEntry;

        ASSERT(!IsListEmpty(&Request->Segments));
        ASSERT3U(Request->NrSegments, <=, BLKIF_MAX_SEGMENTS_PER_REQUEST);

        req->nr_segments = (UCHAR)Request->NrSegments;

        Index = 0;
        for (ListEntry = Request->Segments.Flink;
             ListEntry != &Request->Segments;
             ListEntry = ListEntry->Flink) {
            PXENVBD_SEGMENT Segment;
            ULONG           GrantRef;

            if (Index >= BLKIF_MAX_SEGMENTS_PER_REQUEST)
                break;

            Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);

            ASSERT3P(Segment->Grant, !=, NULL);
            GrantRef = XENBUS_GNTTAB(GetReference,
                                     &Ring->GnttabInterface,
                                     Segment->Grant);

            req->seg[Index].gref        = GrantRef;
            req->seg[Index].first_sect  = Segment->FirstSector;
            req->seg[Index].last_sect   = Segment->LastSector;

            ++Index;
        }
    }
}

static FORCEINLINE VOID
__RingInsertIndirect(
    IN  PXENVBD_RING                Ring,
    IN  PXENVBD_REQUEST             Request,
    IN  blkif_request_indirect_t    *req
    )
{
    ULONG                           PageIdx;
    PLIST_ENTRY                     PageEntry;
    PLIST_ENTRY                     SegEntry;

    req->operation     = BLKIF_OP_INDIRECT;
    req->indirect_op   = Request->Operation;
    req->nr_segments   = Request->NrSegments;
    req->id            = Request->Id;
    req->sector_number = Request->FirstSector;
    req->handle        = (USHORT)TargetGetDeviceId(Ring->Target);

    ASSERT(Request->NrSegments != 0);
    ASSERT(!IsListEmpty(&Request->Segments));
    ASSERT(!IsListEmpty(&Request->Indirects));

    PageIdx = 0;
    PageEntry = Request->Indirects.Flink;
    SegEntry = Request->Segments.Flink;
    for (;;) {
        PXENVBD_INDIRECT            Page;
        ULONG                       GrantRef;
        ULONG                       SegIdx;
        
        if (PageEntry == &Request->Indirects)
            break;
        if (SegEntry == &Request->Segments)
            break;
        if (PageIdx >= BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST)
            break;

        Page = CONTAINING_RECORD(PageEntry, XENVBD_INDIRECT, ListEntry);

        ASSERT3P(Page->Grant, !=, NULL);
        GrantRef = XENBUS_GNTTAB(GetReference,
                                 &Ring->GnttabInterface,
                                 Page->Grant);

        req->indirect_grefs[PageIdx] = GrantRef;

        SegIdx = 0;
        for (;;) {
            PXENVBD_SEGMENT         Segment;

            if (SegIdx >= XENVBD_MAX_SEGMENTS_PER_PAGE)
                break;
            if (SegEntry == &Request->Segments)
                break;

            Segment = CONTAINING_RECORD(SegEntry, XENVBD_SEGMENT, ListEntry);

            ASSERT3P(Segment->Grant, !=, NULL);
            GrantRef = XENBUS_GNTTAB(GetReference,
                                     &Ring->GnttabInterface,
                                     Segment->Grant);

            Page->Page[SegIdx].GrantRef = GrantRef;
            Page->Page[SegIdx].First    = Segment->FirstSector;
            Page->Page[SegIdx].Last     = Segment->LastSector;

            ++SegIdx;
            SegEntry = SegEntry->Flink;
        }

        ++PageIdx;
        PageEntry = PageEntry->Flink;
    }
}

static FORCEINLINE VOID
__RingInsertDiscard(
    IN  PXENVBD_RING            Ring,
    IN  PXENVBD_REQUEST         Request,
    IN  blkif_request_discard_t *req
    )
{
    req->operation      = BLKIF_OP_DISCARD;
    req->flag           = Request->Flags;
    req->handle         = (USHORT)TargetGetDeviceId(Ring->Target);
    req->id             = Request->Id;
    req->sector_number  = Request->FirstSector;
    req->nr_sectors     = Request->NrSectors;
}

static FORCEINLINE VOID
__RingSend(
    IN  PXENVBD_RING    Ring
    )
{
    if (!Ring->Connected)
        return;

    XENBUS_EVTCHN(Send,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
}

static FORCEINLINE NTSTATUS
__RingPostRequests(
    IN  PXENVBD_RING    Ring
    )
{
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;
        blkif_request_t *req;

        ListEntry = RemoveHeadList(&Ring->PreparedReqs);
        if (ListEntry == &Ring->PreparedReqs)
            break;

        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);

        // dont completely fill ring - leave some space for responses
        if (RING_FREE_REQUESTS(&Ring->Front) < 2)
            goto abort;

        req = RING_GET_REQUEST(&Ring->Front, Ring->Front.req_prod_pvt);
        ++Ring->Front.req_prod_pvt;

        ASSERT(IsZeroMemory(req, sizeof(union blkif_sring_entry)));

        switch (Request->Operation) {
        case BLKIF_OP_READ:
        case BLKIF_OP_WRITE:
            if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST)
                __RingInsertIndirect(Ring, Request, (blkif_request_indirect_t*)req);
            else
                __RingInsertDirect(Ring, Request, req, TRUE);
            break;
        case BLKIF_OP_DISCARD:
            __RingInsertDiscard(Ring, Request, (blkif_request_discard_t*)req);
            break;
        case BLKIF_OP_WRITE_BARRIER:
        case BLKIF_OP_FLUSH_DISKCACHE:
            __RingInsertDirect(Ring, Request, req, FALSE);
            break;
        default:
            ASSERT(FALSE);
            break;
        }

        InsertTailList(&Ring->InFlightReqs, &Request->ListEntry);
        ++Ring->ReqsInFlight;

        ++Ring->RequestsPosted;
        continue;

abort:
        InsertHeadList(&Ring->PreparedReqs, &Request->ListEntry);
        return STATUS_ALLOTTED_SPACE_EXCEEDED;
    }

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
__RingPushRequests(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             Notify;

    if (Ring->RequestsPosted == Ring->RequestsPushed)
        return;

#pragma warning (push)
#pragma warning (disable:4244)

    // Make the requests visible to the backend
    RING_PUSH_REQUESTS_AND_CHECK_NOTIFY(&Ring->Front, Notify);

#pragma warning (pop)

    if (Notify)
        __RingSend(Ring);

    Ring->RequestsPushed = Ring->RequestsPosted;
}

static ULONG
__RingUnprepareRequests(
    IN  PXENVBD_RING    Ring,
    IN  PLIST_ENTRY     List
    )
{
    ULONG               Count = 0;
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;

        ListEntry = RemoveHeadList(List);
        if (ListEntry == List)
            break;

        ++Count;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        __RingPutRequest(Ring, Request);
    }
    return Count;
}

static FORCEINLINE ULONG
__RingGetMaxSegments(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               MaxSegments;

    MaxSegments = TargetGetFeatureMaxIndirectSegments(Ring->Target);
    if (MaxSegments < BLKIF_MAX_SEGMENTS_PER_REQUEST)
        MaxSegments = BLKIF_MAX_SEGMENTS_PER_REQUEST;
    else if (MaxSegments > XENVBD_MAX_SEGMENTS_PER_INDIRECT)
        MaxSegments = XENVBD_MAX_SEGMENTS_PER_INDIRECT;

    return MaxSegments;
}

static DECLSPEC_NOINLINE NTSTATUS
RingPrepareRW(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  UCHAR           Operation
    )
{
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(Ring->Target);
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    ULONG64             SectorStart = Cdb_LogicalBlock(Srb);
    ULONG               SectorsLeft = Cdb_TransferBlock(Srb);
    ULONG               RequestCount;
    LIST_ENTRY          List;
    NTSTATUS            status;

    const ULONG         SectorSize = TargetGetSectorSize(Ring->Target);
    const ULONG         SectorMask = SectorSize - 1;
    const ULONG         SectorsPerPage = PAGE_SIZE / SectorSize;
    const ULONG         MaxSegments = __RingGetMaxSegments(Ring);

    InitializeListHead(&List);
    ASSERT3S(SrbExt->RequestCount, ==, 0);

    RequestCount = 0;
    while (SectorsLeft != 0) {
        PXENVBD_REQUEST Request;
        ULONG           NrSegments;

        Request = __RingGetRequest(Ring);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);
        ++RequestCount;

        Request->SrbExt = SrbExt;
        Request->Operation = Operation;
        Request->FirstSector = SectorStart;

        for (NrSegments = 0;
             NrSegments < MaxSegments && SectorsLeft != 0;
             ++NrSegments) {
            PXENVBD_SEGMENT Segment;
            PFN_NUMBER      Pfn;
            ULONG           Offset;
            ULONG           Length;
            ULONG           SectorsDone;

            Segment = __RingGetSegment(Ring);
            if (Segment == NULL)
                goto fail2;
            InsertTailList(&Request->Segments, &Segment->ListEntry);
            ++Request->NrSegments;

            Pfn = AdapterGetNextSGEntry(Adapter,
                                        SrbExt,
                                        0,
                                        &Offset,
                                        &Length);
            if ((Offset & SectorMask) == 0 &&
                (Length & SectorMask) == 0) {
                Segment->FirstSector = (UCHAR)(Offset / SectorSize);
                SectorsDone = min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
                Segment->LastSector = (UCHAR)(Segment->FirstSector + SectorsDone - 1);

                ++Ring->SegmentsGranted;
            } else {
                PXENVBD_BOUNCE  Bounce;

                Segment->FirstSector = 0;
                SectorsDone = min(SectorsLeft, SectorsPerPage);
                Segment->LastSector = (UCHAR)(SectorsDone - 1);

                Bounce = AdapterGetBounce(Adapter);
                if (Bounce == NULL)
                    goto fail3;
                Segment->Bounce = Bounce;

#pragma warning(push)
#pragma warning(disable:28145)
                //Bounce->SourceMdl.Next = NULL;
                Bounce->SourceMdl.Size = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
                Bounce->SourceMdl.MdlFlags = MDL_PAGES_LOCKED;
                Bounce->SourceMdl.ByteCount = Length;
                Bounce->SourceMdl.ByteOffset = Offset;
                Bounce->SourcePfn[0] = Pfn;

                if (Length < SectorsDone * SectorSize) {
                    Pfn = AdapterGetNextSGEntry(Adapter,
                                                SrbExt,
                                                Length,
                                                &Offset,
                                                &Length);
                    Bounce->SourceMdl.Size += sizeof(PFN_NUMBER);
                    Bounce->SourceMdl.ByteCount += Length;
                    Bounce->SourcePfn[1] = Pfn;
                }
#pragma warning(pop)

                Bounce->SourcePtr = MmMapLockedPagesSpecifyCache(&Bounce->SourceMdl,
                                                                 KernelMode,
                                                                 MmCached,
                                                                 NULL,
                                                                 FALSE,
                                                                 NormalPagePriority);
                if (Bounce->SourcePtr == NULL)
                    goto fail4;

                if (Operation == BLKIF_OP_WRITE) {
                    RtlCopyMemory(Bounce->BouncePtr,
                                  Bounce->SourcePtr,
                                  MmGetMdlByteCount(&Bounce->SourceMdl));
                }

                Pfn = MmGetMdlPfnArray(Bounce->BounceMdl)[0];
                ++Ring->SegmentsBounced;
            }

            status = XENBUS_GNTTAB(PermitForeignAccess,
                                   &Ring->GnttabInterface,
                                   Ring->GrantCache,
                                   TRUE,
                                   TargetGetBackendId(Ring->Target),
                                   Pfn,
                                   Operation == BLKIF_OP_WRITE,
                                   (PXENBUS_GNTTAB_ENTRY*)&Segment->Grant);
            if (!NT_SUCCESS(status))
                goto fail5;

            SectorsLeft -= SectorsDone;
            SectorStart += SectorsDone;
        }
        ASSERT3U(NrSegments, ==, Request->NrSegments);

        __RingIncStat(Ring, Operation, Request->NrSegments);

        if (Request->NrSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            ULONG       NrIndirect = 0;

            for (NrSegments = 0;
                 NrSegments < Request->NrSegments;
                 NrSegments += XENVBD_MAX_SEGMENTS_PER_PAGE) {
                PXENVBD_INDIRECT    Indirect;

                Indirect = __RingGetIndirect(Ring);
                if (Indirect == NULL)
                    goto fail6;
                InsertTailList(&Request->Indirects, &Indirect->ListEntry);

                status = XENBUS_GNTTAB(PermitForeignAccess,
                                       &Ring->GnttabInterface,
                                       Ring->GrantCache,
                                       TRUE,
                                       TargetGetBackendId(Ring->Target),
                                       MmGetMdlPfnArray(Indirect->Mdl)[0],
                                       TRUE,
                                       (PXENBUS_GNTTAB_ENTRY*)&Indirect->Grant);
                if (!NT_SUCCESS(status))
                    goto fail7;

                ++NrIndirect;
            }
            ASSERT3U(NrIndirect, <=, BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST);
        }
    }

    if (!IsListEmpty(&List)) {
        PLIST_ENTRY     ListEntry;

        ListEntry = List.Flink;
        RemoveEntryList(&List);
        AppendTailList(&Ring->PreparedReqs, ListEntry);
        Ring->ReqsPrepared += RequestCount;
    }
    return STATUS_PENDING;

fail7:
    Error("fail7\n");
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
fail1:
    Error("fail1\n");

    RequestCount = __RingUnprepareRequests(Ring, &List);
    ASSERT3S((LONG)RequestCount, ==, SrbExt->RequestCount);
    SrbExt->RequestCount = 0;

    return STATUS_RETRY;
}

static DECLSPEC_NOINLINE NTSTATUS
RingPrepareUnmap(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb;
    LIST_ENTRY          List;
    ULONG               Index;
    ULONG               Count;
    PUNMAP_LIST_HEADER  Header;

    InitializeListHead(&List);
    ASSERT3S(SrbExt->RequestCount, ==, 0);
    
    Srb = SrbExt->Srb;
    Header = Srb->DataBuffer;
    Count = _byteswap_ushort(*(PUSHORT)Header->BlockDescrDataLength) / sizeof(UNMAP_BLOCK_DESCRIPTOR);

    for (Index = 0; Index < Count; ++Index) {
        PXENVBD_REQUEST         Request;
        PUNMAP_BLOCK_DESCRIPTOR Block;

        Block = &Header->Descriptors[Index];

        Request = __RingGetRequest(Ring);
        if (Ring == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);

        Request->SrbExt = SrbExt;
        Request->Operation = BLKIF_OP_DISCARD;
        Request->FirstSector = _byteswap_uint64(*(PULONG64)Block->StartingLba);
        Request->NrSectors = _byteswap_ulong(*(PULONG)Block->LbaCount);
        Request->Flags = TargetGetFeatureDiscardSecure(Ring->Target) ? 1 : 0;

        __RingIncStat(Ring, BLKIF_OP_DISCARD, 0);
    }

    if (!IsListEmpty(&List)) {
        PLIST_ENTRY     ListEntry;

        ListEntry = List.Flink;
        RemoveEntryList(&List);
        AppendTailList(&Ring->PreparedReqs, ListEntry);
        Ring->ReqsPrepared += Count;
    }
    return STATUS_PENDING;

fail1:
    Error("fail1\n");

    Count = __RingUnprepareRequests(Ring, &List);
    ASSERT3S((LONG)Count, ==, SrbExt->RequestCount);
    SrbExt->RequestCount = 0;

    return STATUS_RETRY;
}

static DECLSPEC_NOINLINE NTSTATUS
RingPrepareSync(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  UCHAR           Operation
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PXENVBD_REQUEST     Request;

    ASSERT3S(SrbExt->RequestCount, ==, 0);

    Request = __RingGetRequest(Ring);
    if (Request == NULL)
        goto fail1;

    Request->SrbExt = SrbExt;
    Request->Operation = Operation;
    Request->FirstSector = Cdb_LogicalBlock(Srb);

    __RingIncStat(Ring, Operation, 0);

    InterlockedIncrement(&SrbExt->RequestCount);

    InsertTailList(&Ring->PreparedReqs, &Request->ListEntry);
    ++Ring->ReqsPrepared;

    return STATUS_PENDING;

fail1:
    Error("fail1\n");

    __RingPutRequest(Ring, Request);
    ASSERT3S(SrbExt->RequestCount, ==, 0);

    return STATUS_RETRY;
}

static FORCEINLINE NTSTATUS
__RingPrepareRequests(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    NTSTATUS            status;

    switch (Cdb_OperationEx(Srb)) {
    case SCSIOP_READ:
        status = RingPrepareRW(Ring, SrbExt, BLKIF_OP_READ);
        break;
    case SCSIOP_WRITE:
        status = RingPrepareRW(Ring, SrbExt, BLKIF_OP_WRITE);
        break;
    case SCSIOP_SYNCHRONIZE_CACHE:
        if (TargetGetFeatureFlushCache(Ring->Target))
            status = RingPrepareSync(Ring, SrbExt, BLKIF_OP_FLUSH_DISKCACHE);
        else if (TargetGetFeatureBarrier(Ring->Target))
            status = RingPrepareSync(Ring, SrbExt, BLKIF_OP_FLUSH_DISKCACHE);
        else
            status = STATUS_SUCCESS;
        break;
    case SCSIOP_UNMAP:
        status = RingPrepareUnmap(Ring, SrbExt);
        break;
    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }
    return status;
}

static FORCEINLINE PXENVBD_REQUEST
__RingFindRequest(
    IN  PXENVBD_RING    Ring,
    IN  ULONG64         Id
    )
{
    PLIST_ENTRY         ListEntry;

    for (ListEntry = Ring->InFlightReqs.Flink;
         ListEntry != &Ring->InFlightReqs;
         ListEntry = ListEntry->Flink) {
        PXENVBD_REQUEST Request;

        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        if (Request->Id == Id) {
            RemoveEntryList(&Request->ListEntry);
            ASSERT3P(Request, ==, (PVOID)(ULONG_PTR)Id);
            return Request;
        }
    }

    return NULL;
}

static FORCEINLINE VOID
__RingCompleteSrb(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  UCHAR           Status
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PXENVBD_ADAPTER     Adapter = TargetGetAdapter(Ring->Target);

    if (Srb->SrbStatus == SRB_STATUS_PENDING)
        Srb->SrbStatus = Status;

    ++Ring->SrbsCompleted;

    AdapterCompleteSrb(Adapter, SrbExt);
}

static VOID
RingCompleteRequest(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_REQUEST Request,
    IN  SHORT           Status
    )
{
    PLIST_ENTRY         ListEntry;
    PXENVBD_SRBEXT      SrbExt;
    PSCSI_REQUEST_BLOCK Srb;

    SrbExt = Request->SrbExt;
    Srb = SrbExt->Srb;

    switch (Status) {
    case BLKIF_RSP_OKAY:
        // if Read, copy bounce buffers back
        if (Request->Operation != BLKIF_OP_READ)
            break;

        for (ListEntry = Request->Segments.Flink;
             ListEntry != &Request->Segments;
             ListEntry = ListEntry->Flink) {
            PXENVBD_SEGMENT Segment;
            PXENVBD_BOUNCE  Bounce;

            Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
            Bounce = Segment->Bounce;

            if (Bounce) {
                RtlCopyMemory(Bounce->SourcePtr,
                              Bounce->BouncePtr,
                              MmGetMdlByteCount(&Bounce->SourceMdl));
            }
        }
        break;

    case BLKIF_RSP_EOPNOTSUPP:
        TargetDisableFeature(Ring->Target,
                             Request->Operation);
        break;

    case BLKIF_RSP_ERROR:
    default:
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
    }

    __RingPutRequest(Ring, Request);

    if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
        __RingCompleteSrb(Ring,
                          SrbExt,
                          SRB_STATUS_SUCCESS);
    }
}

static FORCEINLINE BOOLEAN
__RingValidateResponse(
    IN  PXENVBD_REQUEST     Request,
    IN  blkif_response_t    *rsp
    )
{
    if (Request == NULL)
        return FALSE;

    switch (rsp->status) {
    case BLKIF_RSP_OKAY:
    case BLKIF_RSP_ERROR:
    case BLKIF_RSP_EOPNOTSUPP:
        break;
    default:
        return FALSE;
    }

    switch (rsp->operation) {
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
    case BLKIF_OP_WRITE_BARRIER:
    case BLKIF_OP_FLUSH_DISKCACHE:
    case BLKIF_OP_DISCARD:
        if (Request->Operation == rsp->operation)
            break;
        return FALSE;
    case BLKIF_OP_INDIRECT:
        if (Request->Operation == BLKIF_OP_READ ||
            Request->Operation == BLKIF_OP_WRITE)
            break;
        return FALSE;
    default:
        return FALSE;
    }

    return TRUE;
}

static DECLSPEC_NOINLINE BOOLEAN
RingPoll(
    IN  PXENVBD_RING    Ring
    )
{
#define XENVBD_BATCH(_Front) (RING_SIZE(_Front) / 4)

    BOOLEAN             Retry;
    
    Retry = FALSE;

    if (!Ring->Enabled)
        goto done;

    for (;;) {
        RING_IDX        rsp_prod;
        RING_IDX        rsp_cons;

        KeMemoryBarrier();

        rsp_prod = Ring->Shared->rsp_prod;
        rsp_cons = Ring->Front.rsp_cons;

        KeMemoryBarrier();

        if (rsp_cons == rsp_prod || Retry)
            break;

        while (rsp_cons != rsp_prod && !Retry) {
            blkif_response_t    *rsp;
            PXENVBD_REQUEST     Request;

            rsp = RING_GET_RESPONSE(&Ring->Front, rsp_cons);
            ++Ring->ResponsesProcessed;

            Ring->Stopped = FALSE;

            Request = __RingFindRequest(Ring, rsp->id);
            if (__RingValidateResponse(Request, rsp)) {
                RingCompleteRequest(Ring, Request, rsp->status);
            } else {
                Error("Possible ring corruption detected @ %u rsp={ %llu, %u, %d }\n",
                      rsp_cons,
                      rsp->id,
                      rsp->operation,
                      rsp->status);
            }
            ++rsp_cons;

            RtlZeroMemory(rsp, sizeof(union blkif_sring_entry));

            if (rsp_cons - Ring->Front.rsp_cons > XENVBD_BATCH(&Ring->Front))
                Retry = TRUE;
        }

        KeMemoryBarrier();

        Ring->Front.rsp_cons = rsp_cons;
        Ring->Shared->rsp_event = rsp_cons + 1;
    }

done:
    return Retry;

#undef XENVBD_BATCH
}

#define XENVBD_LOCK_BIT ((ULONG_PTR)1)

static VOID
RingSwizzle(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG_PTR           Old;
    ULONG_PTR           New;
    PLIST_ENTRY         ListEntry;
    LIST_ENTRY          List;
    ULONG               Count;

    ASSERT3P(Ring->LockThread, ==, KeGetCurrentThread());

    InitializeListHead(&List);

    New = XENVBD_LOCK_BIT;    
    Old = (ULONG_PTR)InterlockedExchangePointer(&Ring->Lock, (PVOID)New);

    ASSERT(Old & XENVBD_LOCK_BIT);
    ListEntry = (PVOID)(Old & ~XENVBD_LOCK_BIT);

    if (ListEntry == NULL)
        return;

    // Packets are held in the atomic packet list in reverse order
    // so that the most recent is always head of the list. This is
    // necessary to allow addition to the list to be done atomically.

    for (Count = 0; ListEntry != NULL; ++Count) {
        PLIST_ENTRY     NextEntry;

        NextEntry = ListEntry->Blink;
        ListEntry->Flink = ListEntry->Blink = ListEntry;

        InsertHeadList(&List, ListEntry);

        ListEntry = NextEntry;
    }

    if (!IsListEmpty(&List)) {
        ListEntry = List.Flink;

        RemoveEntryList(&List);
        AppendTailList(&Ring->QueuedSrbs, ListEntry);

        Ring->SrbsQueued += Count;
    }
}

static VOID
RingSchedule(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             Polled;

    if (!Ring->Enabled)
        return;

    Polled = FALSE;

    while (!Ring->Stopped) {
        NTSTATUS    status;

        status = __RingPostRequests(Ring);
        if (!NT_SUCCESS(status))
            Ring->Stopped = TRUE;

        if (Ring->Stopped) {
            if (!Polled) {
                (VOID) RingPoll(Ring);
                Polled = TRUE;
            }
            continue;
        }

        if (Ring->RequestsPosted - Ring->RequestsPushed >=
            RING_SIZE(&Ring->Front) / 4)
            __RingPushRequests(Ring);

        if (!IsListEmpty(&Ring->QueuedSrbs)) {
            PLIST_ENTRY     ListEntry;
            PXENVBD_SRBEXT  SrbExt;

            ListEntry = RemoveHeadList(&Ring->QueuedSrbs);
            ASSERT3P(ListEntry, !=, &Ring->QueuedSrbs);

            RtlZeroMemory(ListEntry, sizeof (LIST_ENTRY));

            SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);

            status = __RingPrepareRequests(Ring, SrbExt);
            if (status == STATUS_SUCCESS) {
                // just succeed this now
                __RingCompleteSrb(Ring,
                                  SrbExt,
                                  SRB_STATUS_SUCCESS);
            } else if (status == STATUS_RETRY) {
                // requeue
                InsertHeadList(&Ring->QueuedSrbs, &SrbExt->ListEntry);
                break;
            } else if (status != STATUS_PENDING) {
                // fail it
                __RingCompleteSrb(Ring,
                                  SrbExt,
                                  SRB_STATUS_ERROR);
            }

            // try to post the now-prepared requests
            continue;
        }

        break;
    }

    __RingPushRequests(Ring);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingTryAcquireLock(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG_PTR           Old;
    ULONG_PTR           New;
    BOOLEAN             Acquired;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    KeMemoryBarrier();

    Old = (ULONG_PTR)Ring->Lock & ~XENVBD_LOCK_BIT;
    New = Old | XENVBD_LOCK_BIT;

    Acquired = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;
    KeMemoryBarrier();
    
    if (Acquired) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Acquired;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingAcquireLock(
    IN  PXENVBD_RING    Ring
    )
{
    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    for (;;) {
        if (__RingTryAcquireLock(Ring))
            break;

        _mm_pause();
    }
}

VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
RingAcquireLock(
    IN  PVOID   Context
    )
{
    __RingAcquireLock(Context);
}

static FORCEINLINE BOOLEAN
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingTryReleaseLock(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG_PTR           Old;
    ULONG_PTR           New;
    BOOLEAN             Released;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);
    ASSERT3P(KeGetCurrentThread(), ==, Ring->LockThread);

    Old = XENVBD_LOCK_BIT;
    New = 0;

    Ring->LockThread = NULL;

    KeMemoryBarrier();

    Released = ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock,
                                                             (PVOID)New,
                                                             (PVOID)Old) == Old) ? TRUE : FALSE;

    KeMemoryBarrier();

    if (!Released) {
        ASSERT3P(Ring->LockThread, ==, NULL);
        Ring->LockThread = KeGetCurrentThread();
        KeMemoryBarrier();
    }

    return Released;
}

static FORCEINLINE VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
__RingReleaseLock(
    IN  PXENVBD_RING    Ring
    )
{
    BOOLEAN             QueuesEmpty;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    // As lock holder it is our responsibility to drain the atomic
    // srbext list into the pending queue before we actually drop the
    // lock. This may, of course, take a few attempts as another
    // thread could be simuntaneously adding to the list.

    do {
        RingSwizzle(Ring);
        RingSchedule(Ring);

        // if there is anything outstanding, dont call TargetCompleteShutdown
        // only the last iteration of this do-while loop matters
        QueuesEmpty = IsListEmpty(&Ring->QueuedSrbs) &&
                      IsListEmpty(&Ring->PreparedReqs) &&
                      IsListEmpty(&Ring->InFlightReqs);
    } while (!__RingTryReleaseLock(Ring));

    // should check for nothing outstanding or pending
    if (QueuesEmpty)
        TargetCompleteShutdown(Ring->Target);
}

VOID
__drv_requiresIRQL(DISPATCH_LEVEL)
RingReleaseLock(
    IN  PVOID   Context
    )
{
    __RingReleaseLock(Context);
}

KSERVICE_ROUTINE RingInterrupt;

BOOLEAN
RingInterrupt(
    __in  PKINTERRUPT   Interrupt,
    _In_opt_ PVOID      Context
    )
{
    PXENVBD_RING        Ring = Context;
    
    UNREFERENCED_PARAMETER(Interrupt);

    ASSERT(Ring != NULL);

	++Ring->NumInts;
	if (Ring->Connected) {
		if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL)) {
			++Ring->NumDpcs;
        }
	}

    return TRUE;
}

static FORCEINLINE BOOLEAN
__RingDpcTimeout(
    IN  PXENVBD_RING            Ring
    )
{
    KDPC_WATCHDOG_INFORMATION   Watchdog;
    NTSTATUS                    status;

    UNREFERENCED_PARAMETER(Ring);

    RtlZeroMemory(&Watchdog, sizeof (Watchdog));

    status = KeQueryDpcWatchdogInformation(&Watchdog);
    ASSERT(NT_SUCCESS(status));

    if (Watchdog.DpcTimeLimit == 0 ||
        Watchdog.DpcWatchdogLimit == 0)
        return FALSE;

    if (Watchdog.DpcTimeCount > (Watchdog.DpcTimeLimit / 2) &&
        Watchdog.DpcWatchdogCount > (Watchdog.DpcWatchdogLimit / 2))
        return FALSE;

    return TRUE;
}

#define TIME_US(_us)        ((_us) * 10)
#define TIME_MS(_ms)        (TIME_US((_ms) * 1000))
#define TIME_S(_s)          (TIME_MS((_s) * 1000))
#define TIME_RELATIVE(_t)   (-(_t))

KDEFERRED_ROUTINE RingDpc;

VOID 
RingDpc(
    __in  PKDPC      Dpc,
    __in_opt PVOID   Context,
    __in_opt PVOID   Arg1,
    __in_opt PVOID   Arg2
    )
{
    PXENVBD_RING    Ring = Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    ASSERT(Ring != NULL);

    for (;;) {
        BOOLEAN     Retry;

        __RingAcquireLock(Ring);
        Retry = RingPoll(Ring);
        __RingReleaseLock(Ring);
       
        if (!Retry) {
            XENBUS_EVTCHN(Unmask,
                          &Ring->EvtchnInterface,
                          Ring->Channel,
                          FALSE);
            break;
        }

        if (__RingDpcTimeout(Ring)) {
            LARGE_INTEGER   Delay;

            Delay.QuadPart = TIME_RELATIVE(TIME_US(100));
            ++Ring->NumTimeouts;

            KeSetTimer(&Ring->Timer,
                       Delay,
                       &Ring->TimerDpc);
            break;
        }
    }
}

VOID
RingQueue(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PLIST_ENTRY         ListEntry;
    ULONG_PTR           Old;
    ULONG_PTR           LockBit;
    ULONG_PTR           New;

    ListEntry = &SrbExt->ListEntry;

    do {
        Old = (ULONG_PTR)Ring->Lock;
        LockBit = Old & XENVBD_LOCK_BIT;

        ListEntry->Blink = (PVOID)(Old & ~XENVBD_LOCK_BIT);
        New = (ULONG_PTR)ListEntry;
        ASSERT((New & XENVBD_LOCK_BIT) == 0);
        New |= LockBit;
    } while ((ULONG_PTR)InterlockedCompareExchangePointer(&Ring->Lock, (PVOID)New, (PVOID)Old) != Old);

    // _RingReleaseLock() drains the atomic srb list into the pending queue therefore,
    // after adding to the list we need to attempt to grab and release the lock. If we can't
    // grab it then that's ok because whichever thread is holding it will have to call
    // __RingReleaseLock() and will therefore drain the atomic srb list.

    if (__RingTryAcquireLock(Ring))
        __RingReleaseLock(Ring);
}

VOID
RingNotify(
    IN  PXENVBD_RING    Ring
    )
{
    if (KeInsertQueueDpc(&Ring->Dpc, NULL, NULL))
        ++Ring->NumDpcs;
}

VOID
RingReset(
    IN  PXENVBD_RING    Ring
    )
{
    Verbose("=====>\n");

    XENBUS_DEBUG(Trigger,
                 &Ring->DebugInterface,
                 Ring->DebugCallback);

    Verbose("<=====\n");
}

static DECLSPEC_NOINLINE VOID
RingDebugCallback(
    IN  PVOID       Context,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_RING    Ring = Context;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "TargetId: %u%s%s\n",
                 TargetGetTargetId(Ring->Target),
                 Ring->Connected ? " CONNECTED" : "",
                 Ring->Enabled ? " ENABLED" : "");

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "SRBs queued: %u, completed: %u\n",
                 Ring->SrbsQueued,
                 Ring->SrbsCompleted);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "REQs prepared: %u, inflight: %u\n",
                 Ring->ReqsPrepared,
                 Ring->ReqsInFlight);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "REQs posted: %u, pushed: %u, responses: %u\n",
                 Ring->RequestsPosted,
                 Ring->RequestsPushed,
                 Ring->ResponsesProcessed);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "SEGs granted: %u, bounced: %u\n",
                 Ring->SegmentsGranted,
                 Ring->SegmentsBounced);

    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Shared req_prod: %u, req_event: %u\n",
                 Ring->Shared->req_prod,
                 Ring->Shared->req_event);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Shared rsp_prod: %u, rsp_event: %u\n",
                 Ring->Shared->rsp_prod,
                 Ring->Shared->rsp_event);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Front req_prod: %u, rsp_cons: %u, nr_ents: %u\n",
                 Ring->Front.req_prod_pvt,
                 Ring->Front.rsp_cons,
                 Ring->Front.nr_ents);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "Interrupts: %u, DPCs: %u, Timeouts: %u\n",
                 Ring->NumInts,
                 Ring->NumDpcs,
                 Ring->NumTimeouts);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "READ: %u, WRITE: %u, BARRIER: %u, FLUSH: %u\n",
                 Ring->BlkifOpCount[XENVBD_STAT_READ],
                 Ring->BlkifOpCount[XENVBD_STAT_WRITE],
                 Ring->BlkifOpCount[XENVBD_STAT_BARRIER],
                 Ring->BlkifOpCount[XENVBD_STAT_FLUSH]);
    XENBUS_DEBUG(Printf,
                 &Ring->DebugInterface,
                 "DISCARD: %u, IND_READ: %u, IND_WRITE: %u\n",
                 Ring->BlkifOpCount[XENVBD_STAT_DISCARD],
                 Ring->BlkifOpCount[XENVBD_STAT_IND_READ],
                 Ring->BlkifOpCount[XENVBD_STAT_IND_WRITE]);
}

static VOID
RingPauseDatapath(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Attempt;
    PXENVBD_ADAPTER     Adapter;

    Trace("[%u] =====>\n", TargetGetTargetId(Ring->Target));

    Adapter = TargetGetAdapter(Ring->Target);

    // unprepare prepared requests, put srbext back on queued srbs
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;
        PXENVBD_SRBEXT  SrbExt;

        ListEntry = RemoveTailList(&Ring->PreparedReqs);
        if (ListEntry == &Ring->PreparedReqs)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        SrbExt = Request->SrbExt;

        __RingPutRequest(Ring, Request);

        if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
            InsertHeadList(&Ring->QueuedSrbs, &SrbExt->ListEntry);
        }
    }

    // abort all queued srbs
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_SRBEXT  SrbExt;
        PSCSI_REQUEST_BLOCK Srb;

        ListEntry = RemoveHeadList(&Ring->QueuedSrbs);
        if (ListEntry == &Ring->QueuedSrbs)
            break;
        SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);

        Srb = SrbExt->Srb;
        Srb->SrbStatus = SRB_STATUS_ABORTED;

        AdapterCompleteSrb(Adapter, SrbExt);
    }

    // try to force inflight requests to complete
    Attempt = 0;
    ASSERT3U(Ring->RequestsPushed, ==, Ring->RequestsPosted);
    while (Ring->ResponsesProcessed != Ring->RequestsPushed) {
        ++Attempt;
        if (Attempt > 100) {
            Warning("[%u] Backend not responding? - %u posted, %u responses\n",
                    TargetGetTargetId(Ring->Target),
                    Ring->RequestsPushed,
                    Ring->ResponsesProcessed);
            break;
        }

        __RingSend(Ring);
        (VOID) RingPoll(Ring);

        // We are waiting for a watch event at DISPATCH_LEVEL so
        // it is our responsibility to poll the store ring.
        XENBUS_STORE(Poll,
                     &Ring->StoreInterface);

        KeStallExecutionProcessor(1000); // 1ms
    }

    Trace("[%u] <=====\n", TargetGetTargetId(Ring->Target));
}

NTSTATUS
RingEnable(
    IN  PXENVBD_RING    Ring
    )
{
    Trace("[%u] =====>\n", TargetGetTargetId(Ring->Target));

    __RingAcquireLock(Ring);

    ASSERT(!Ring->Enabled);
    Ring->Enabled = TRUE;

    KeInsertQueueDpc(&Ring->Dpc, NULL, NULL);

    __RingReleaseLock(Ring);

    Trace("[%u] <=====\n", TargetGetTargetId(Ring->Target));
    return STATUS_SUCCESS;
}

VOID
RingDisable(
    IN  PXENVBD_RING    Ring
    )
{
    PXENVBD_ADAPTER     Adapter;

    Trace("[%u] =====>\n", TargetGetTargetId(Ring->Target));

    Adapter = TargetGetAdapter(Ring->Target);

    __RingAcquireLock(Ring);

    ASSERT(Ring->Enabled);
    Ring->Enabled = FALSE;

    RingPauseDatapath(Ring);

    __RingReleaseLock(Ring);

    //
    // No new timers can be scheduled once Enabled goes to FALSE.
    // Cancel any existing ones.
    //
    (VOID) KeCancelTimer(&Ring->Timer);

    Trace("[%u] <=====\n", TargetGetTargetId(Ring->Target));
}

static NTSTATUS
RingRequestCtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static VOID
RingRequestDtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static NTSTATUS
RingSegmentCtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
    return STATUS_SUCCESS;
}

static VOID
RingSegmentDtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    UNREFERENCED_PARAMETER(Argument);
    UNREFERENCED_PARAMETER(Object);
}

static NTSTATUS
RingIndirectCtor(
    IN  PVOID           Argument,
    IN  PVOID           Object
    )
{
    PXENVBD_INDIRECT    Indirect = Object;

    UNREFERENCED_PARAMETER(Argument);

    Indirect->Mdl = __AllocatePage();
    if (Indirect->Mdl == NULL)
        goto fail1;
    Indirect->Page = MmGetSystemAddressForMdlSafe(Indirect->Mdl,
                                                  NormalPagePriority);

    return STATUS_SUCCESS;

fail1:
    Error("fail1\n");
    return STATUS_NO_MEMORY;
}

static VOID
RingIndirectDtor(
    IN  PVOID   Argument,
    IN  PVOID   Object
    )
{
    PXENVBD_INDIRECT    Indirect = Object;

    UNREFERENCED_PARAMETER(Argument);

    Indirect->Page = NULL;
    __FreePages(Indirect->Mdl);
    Indirect->Mdl = NULL;
}

NTSTATUS
RingStoreWrite(
    IN  PXENVBD_RING    Ring,
    IN  PVOID           Transaction
    )
{
    ULONG               Port;
    ULONG               Index;
    ULONG               GrantRef;
    NTSTATUS            status;

    Port = XENBUS_EVTCHN(GetPort,
                         &Ring->EvtchnInterface,
                         Ring->Channel);

    status = XENBUS_STORE(Printf,
                          &Ring->StoreInterface,
                          Transaction,
                          TargetGetPath(Ring->Target),
                          "event-channel",
                          "%u",
                          Port);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf, 
                          &Ring->StoreInterface,
                          Transaction,
                          TargetGetPath(Ring->Target),
                          "protocol",
                          XEN_IO_PROTO_ABI);
    if (!NT_SUCCESS(status))
        return status;

    if (Ring->Order == 0) {
        ASSERT3P(Ring->Grants[0], !=, NULL);
        GrantRef = XENBUS_GNTTAB(GetReference,
                                 &Ring->GnttabInterface,
                                 Ring->Grants[0]);

        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              TargetGetPath(Ring->Target),
                              "ring-ref",
                              "%u",
                              GrantRef);
        if (!NT_SUCCESS(status))
            return status;
    } else {
        status = XENBUS_STORE(Printf,
                              &Ring->StoreInterface,
                              Transaction,
                              TargetGetPath(Ring->Target),
                              "ring-page-order",
                              "%u",
                              Ring->Order);
        if (!NT_SUCCESS(status))
            return status;

        for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
            CHAR        Name[sizeof("ring-refXXXX")];

            status = RtlStringCbPrintfA(Name,
                                        sizeof(Name),
                                        "ring-ref%u",
                                        Index);
            if (!NT_SUCCESS(status))
                return status;

            ASSERT3P(Ring->Grants[Index], !=, NULL);
            GrantRef = XENBUS_GNTTAB(GetReference,
                                     &Ring->GnttabInterface,
                                     Ring->Grants[Index]);

            status = XENBUS_STORE(Printf,
                                  &Ring->StoreInterface,
                                  Transaction,
                                  TargetGetPath(Ring->Target),
                                  Name,
                                  "%u",
                                  GrantRef);
            if (!NT_SUCCESS(status))
                return status;
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
RingConnect(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Index;
    PCHAR               Value;
    CHAR                Name[MAX_NAME_LEN];
    NTSTATUS            status;

    Trace("[%u] =====>\n", TargetGetTargetId(Ring->Target));

    ASSERT(!Ring->Connected);
    Ring->Connected = TRUE;

    status = XENBUS_STORE(Acquire, &Ring->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &Ring->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_EVTCHN(Acquire, &Ring->EvtchnInterface);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_GNTTAB(Acquire, &Ring->GnttabInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u",
                                TargetGetTargetId(Ring->Target));
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_GNTTAB(CreateCache,
                           &Ring->GnttabInterface,
                           Name,
                           0,
                           RingAcquireLock,
                           RingReleaseLock,
                           Ring,
                           &Ring->GrantCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = XENBUS_STORE(Read,
                          &Ring->StoreInterface,
                          NULL,
                          TargetGetPath(Ring->Target),
                          "max-ring-page-order",
                          &Value);
    if (NT_SUCCESS(status)) {
        ULONG           MaxOrder;

        Ring->Order = strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Ring->StoreInterface,
                     Value);

        Ring->Order = min(Ring->Order, MAX_RING_PAGE_ORDER);

        if (DriverGetFeatureOverride(FeatureMaxRingPageOrder, &MaxOrder))
            Ring->Order = min(Ring->Order, MaxOrder);
    } else {
        Ring->Order = 0;
    }

    status = STATUS_NO_MEMORY;
    Ring->Mdl = __AllocatePages(1 << Ring->Order);
    if (Ring->Mdl == NULL)
        goto fail7;
    // __AllocatePages has zeroed the memory

    Ring->Shared = MmGetSystemAddressForMdlSafe(Ring->Mdl, NormalPagePriority);
    ASSERT(Ring->Shared != NULL);

#pragma warning(push)
#pragma warning(disable: 4305)
#pragma warning(disable: 4311)
    SHARED_RING_INIT(Ring->Shared);
    FRONT_RING_INIT(&Ring->Front, Ring->Shared, PAGE_SIZE << Ring->Order);
#pragma warning(pop)

    for (Index = 0; Index < (1ul << Ring->Order); ++Index) {
        status = XENBUS_GNTTAB(PermitForeignAccess,
                               &Ring->GnttabInterface,
                               Ring->GrantCache,
                               TRUE,
                               TargetGetBackendId(Ring->Target),
                               MmGetMdlPfnArray(Ring->Mdl)[Index],
                               FALSE,
                               &Ring->Grants[Index]);
        if (!NT_SUCCESS(status))
            goto fail8;
    }

    status = STATUS_UNSUCCESSFUL;
    Ring->Channel = XENBUS_EVTCHN(Open,
                                  &Ring->EvtchnInterface,
                                  XENBUS_EVTCHN_TYPE_UNBOUND,
                                  RingInterrupt,
                                  Ring,
                                  TargetGetBackendId(Ring->Target),
                                  TRUE);
    if (Ring->Channel == NULL)
        goto fail9;

    status = XENBUS_DEBUG(Register,
                          &Ring->DebugInterface,
                          __MODULE__ "|RING",
                          RingDebugCallback,
                          Ring,
                          &Ring->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail10;

    XENBUS_EVTCHN(Unmask,
                  &Ring->EvtchnInterface,
                  Ring->Channel,
                  FALSE);

    Trace("[%u] <=====\n", TargetGetTargetId(Ring->Target));
    return STATUS_SUCCESS;

fail10:
    Error("fail10\n");
    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;
fail9:
    Error("fail9\n");
fail8:
    Error("fail8\n");
    while (Index--) {
        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Ring->GnttabInterface,
                             Ring->GrantCache,
                             TRUE,
                             Ring->Grants[Index]);
        Ring->Grants[Index] = NULL;
    }

    RtlZeroMemory(&Ring->Front, sizeof(blkif_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE << Ring->Order);

    Ring->Shared = NULL;

    __FreePages(Ring->Mdl);
    Ring->Mdl = NULL;
fail7:
    Error("fail7\n");
    Ring->Order = 0;

    XENBUS_GNTTAB(DestroyCache,
                  &Ring->GnttabInterface,
                  Ring->GrantCache);
    Ring->GrantCache = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    XENBUS_GNTTAB(Release, &Ring->GnttabInterface);
fail4:
    Error("fail4\n");
    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);
fail3:
    Error("fail3\n");
    XENBUS_DEBUG(Release, &Ring->DebugInterface);
fail2:
    Error("fail2\n");
    XENBUS_STORE(Release, &Ring->StoreInterface);
fail1:
    Error("fail1 %08x\n", status);
    Ring->Connected = FALSE;
    return status;
}

VOID
RingDisconnect(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               Index;

    Trace("[%u] =====>\n", TargetGetTargetId(Ring->Target));

    ASSERT(Ring->Connected);
    Ring->Connected = FALSE;

    XENBUS_DEBUG(Deregister,
                 &Ring->DebugInterface,
                 Ring->DebugCallback);
    Ring->DebugCallback = NULL;

    XENBUS_EVTCHN(Close,
                  &Ring->EvtchnInterface,
                  Ring->Channel);
    Ring->Channel = NULL;

    for (Index = 0; Index < MAX_RING_PAGES; ++Index) {
        if (Ring->Grants[Index] == NULL)
            continue;

        (VOID) XENBUS_GNTTAB(RevokeForeignAccess,
                             &Ring->GnttabInterface,
                             Ring->GrantCache,
                             TRUE,
                             Ring->Grants[Index]);
        Ring->Grants[Index] = NULL;
    }

    RtlZeroMemory(&Ring->Front, sizeof(blkif_front_ring_t));
    RtlZeroMemory(Ring->Shared, PAGE_SIZE << Ring->Order);

    Ring->Shared = NULL;

    __FreePages(Ring->Mdl);
    Ring->Mdl = NULL;

    Ring->Order = 0;

    XENBUS_GNTTAB(DestroyCache,
                  &Ring->GnttabInterface,
                  Ring->GrantCache);
    Ring->GrantCache = NULL;

    XENBUS_GNTTAB(Release, &Ring->GnttabInterface);
    XENBUS_EVTCHN(Release, &Ring->EvtchnInterface);
    XENBUS_DEBUG(Release, &Ring->DebugInterface);
    XENBUS_STORE(Release, &Ring->StoreInterface);

    Trace("[%u] <=====\n", TargetGetTargetId(Ring->Target));
}

NTSTATUS
RingCreate(
    IN  PXENVBD_TARGET  Target,
    OUT PXENVBD_RING    *_Ring
    )
{
    PXENVBD_ADAPTER     Adapter;
    PXENVBD_RING        Ring;
    CHAR                Name[MAX_NAME_LEN];
    NTSTATUS            status;

    Trace("[%u] =====>\n", TargetGetTargetId(Target));

    status = STATUS_NO_MEMORY;
    Ring = __RingAllocate(sizeof(XENVBD_RING));
    if (Ring == NULL)
        goto fail1;

    Ring->Target = Target;
    KeInitializeDpc(&Ring->Dpc, RingDpc, Ring);
    KeInitializeDpc(&Ring->TimerDpc, RingDpc, Ring);
    KeInitializeTimer(&Ring->Timer);
    InitializeListHead(&Ring->QueuedSrbs);
    InitializeListHead(&Ring->PreparedReqs);
    InitializeListHead(&Ring->InFlightReqs);

    Adapter = TargetGetAdapter(Target);
    AdapterGetStoreInterface(Adapter, &Ring->StoreInterface);
    AdapterGetDebugInterface(Adapter, &Ring->DebugInterface);
    AdapterGetCacheInterface(Adapter, &Ring->CacheInterface);
    AdapterGetEvtchnInterface(Adapter, &Ring->EvtchnInterface);
    AdapterGetGnttabInterface(Adapter, &Ring->GnttabInterface);

    status = XENBUS_CACHE(Acquire,
                          &Ring->CacheInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_requests",
                                TargetGetTargetId(Target));
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_REQUEST),
                          0,
                          RingRequestCtor,
                          RingRequestDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          Ring,
                          &Ring->RequestCache);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_segments",
                                TargetGetTargetId(Target));
    if (!NT_SUCCESS(status))
        goto fail5;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_SEGMENT),
                          0,
                          RingSegmentCtor,
                          RingSegmentDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          Ring,
                          &Ring->SegmentCache);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = RtlStringCbPrintfA(Name,
                                sizeof(Name),
                                "vbd_%u_indirect",
                                TargetGetTargetId(Target));
    if (!NT_SUCCESS(status))
        goto fail7;

    status = XENBUS_CACHE(Create,
                          &Ring->CacheInterface,
                          Name,
                          sizeof(XENVBD_INDIRECT),
                          0,
                          RingIndirectCtor,
                          RingIndirectDtor,
                          RingAcquireLock,
                          RingReleaseLock,
                          Ring,
                          &Ring->IndirectCache);
    if (!NT_SUCCESS(status))
        goto fail8;

    *_Ring = Ring;

    Trace("[%u] <=====\n", TargetGetTargetId(Target));

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");
fail7:
    Error("fail7\n");
    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->SegmentCache);
    Ring->SegmentCache = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->RequestCache);
    Ring->RequestCache = NULL;
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
    XENBUS_CACHE(Release, &Ring->CacheInterface);
fail2:
    Error("fail2\n");
    RtlZeroMemory(&Ring->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));
    RtlZeroMemory(&Ring->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Ring->CacheInterface, sizeof(XENBUS_CACHE_INTERFACE));
    RtlZeroMemory(&Ring->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Ring->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Ring->Timer, sizeof(KTIMER));
    RtlZeroMemory(&Ring->TimerDpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->Dpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->QueuedSrbs, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Ring->PreparedReqs, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Ring->InFlightReqs, sizeof(LIST_ENTRY));

    Ring->Target = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof(XENVBD_RING)));
    __RingFree(Ring);
fail1:
    Error("fail1 %08x\n", status);
    *_Ring = NULL;
    return status;
}

VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    )
{
    ULONG               TargetId;

    TargetId = TargetGetTargetId(Ring->Target);

    Trace("[%u] =====>\n", TargetId);

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->IndirectCache);
    Ring->IndirectCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->SegmentCache);
    Ring->SegmentCache = NULL;

    XENBUS_CACHE(Destroy,
                 &Ring->CacheInterface,
                 Ring->RequestCache);
    Ring->RequestCache = NULL;

    XENBUS_CACHE(Release, &Ring->CacheInterface);

    RtlZeroMemory(&Ring->GnttabInterface, sizeof(XENBUS_GNTTAB_INTERFACE));
    RtlZeroMemory(&Ring->EvtchnInterface, sizeof(XENBUS_EVTCHN_INTERFACE));
    RtlZeroMemory(&Ring->CacheInterface, sizeof(XENBUS_CACHE_INTERFACE));
    RtlZeroMemory(&Ring->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Ring->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));

    RtlZeroMemory(&Ring->Timer, sizeof(KTIMER));
    RtlZeroMemory(&Ring->TimerDpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->Dpc, sizeof(KDPC));
    RtlZeroMemory(&Ring->QueuedSrbs, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Ring->PreparedReqs, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Ring->InFlightReqs, sizeof(LIST_ENTRY));

    Ring->Target = NULL;

    ASSERT(IsZeroMemory(Ring, sizeof(XENVBD_RING)));
    __RingFree(Ring);

    Trace("[%u] <=====\n", TargetId);
}
