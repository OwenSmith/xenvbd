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

#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>

#include "target.h"
#include "driver.h"
#include "adapter.h"
#include "thread.h"
#include "srbext.h"
#include "buffer.h"
#include "granter.h"
#include "blockring.h"

#include "util.h"
#include "debug.h"
#include "assert.h"

#define TARGET_POOL_TAG         'raTX'
#define REQUEST_POOL_TAG        'qeRX'
#define SEGMENT_POOL_TAG        'geSX'
#define INDIRECT_POOL_TAG       'dnIX'
#define XENVBD_MAX_QUEUE_DEPTH  (254)

typedef enum _XENVBD_STATE {
    XENVBD_STATE_INVALID,
    XENVBD_INITIALIZED, // -> { CLOSED }
    XENVBD_CLOSING,     // -> { CLOSED }
    XENVBD_CLOSED,      // -> { PREPARED }
    XENVBD_PREPARED,    // -> { CLOSING, CONNECTED }
    XENVBD_CONNECTED,   // -> { ENABLED, CLOSING }
    XENVBD_ENABLED      // -> { CLOSING }
} XENVBD_STATE;

struct _XENVBD_TARGET {
    PXENVBD_ADAPTER             Adapter;
    PDEVICE_OBJECT              DeviceObject;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    XENVBD_STATE                State;
    KSPIN_LOCK                  StateLock;
    KSPIN_LOCK                  QueueLock;
    BOOLEAN                     Missing;
    PXENVBD_GRANTER             Granter;
    PXENVBD_BLOCKRING           BlockRing;

    ULONG                       DeviceId;
    ULONG                       TargetId;
    PCHAR                       Path;
    PCHAR                       TargetPath;
    PCHAR                       BackendPath;
    USHORT                      BackendId;

    BOOLEAN                     DeviceUsage[4];
    ULONG64                     SectorCount;
    ULONG                       SectorSize;
    ULONG                       PhysicalSectorSize;
    ULONG                       DiskInfo;
    BOOLEAN                     Removable;
    BOOLEAN                     FeatureBarrier;
    BOOLEAN                     FeatureFlush;
    BOOLEAN                     FeatureDiscard;
    BOOLEAN                     DiscardSecure;
    ULONG                       DiscardAlignment;
    ULONG                       DiscardGranularity;
    ULONG                       FeatureIndirect;

    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;
    XENBUS_STORE_INTERFACE      StoreInterface;

    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;

    PXENVBD_THREAD              BackendThread;
    PXENBUS_STORE_WATCH         BackendWatch;

    LIST_ENTRY                  Fresh;
    LIST_ENTRY                  Prepared;
    LIST_ENTRY                  Submitted;
    LIST_ENTRY                  Shutdown;

    NPAGED_LOOKASIDE_LIST       RequestList;
    NPAGED_LOOKASIDE_LIST       SegmentList;
    NPAGED_LOOKASIDE_LIST       IndirectList;
};

typedef struct _XENVBD_SG_LIST {
    // SGList from SRB
    PSTOR_SCATTER_GATHER_LIST   SGList;
    // "current" values
    STOR_PHYSICAL_ADDRESS       PhysAddr;
    ULONG                       PhysLen;
    // iteration
    ULONG                       Index;
    ULONG                       Offset;
    ULONG                       Length;
} XENVBD_SG_LIST, *PXENVBD_SG_LIST;

static FORCEINLINE VOID
SGListInit(
    IN OUT  PXENVBD_SG_LIST     SGList,
    IN  PVOID                   Adapter,
    IN  PSCSI_REQUEST_BLOCK     Srb
    )
{
    RtlZeroMemory(SGList, sizeof(XENVBD_SG_LIST));
    SGList->SGList = StorPortGetScatterGatherList(Adapter, Srb);
}

static FORCEINLINE VOID
SGListGet(
    IN OUT  PXENVBD_SG_LIST         SGList
    )
{
    PSTOR_SCATTER_GATHER_ELEMENT    SGElement;
    ULONG                           Offset;

    ASSERT3U(SGList->Index, <, SGList->SGList->NumberOfElements);

    SGElement = &SGList->SGList->List[SGList->Index];

    SGList->PhysAddr.QuadPart = SGElement->PhysicalAddress.QuadPart + SGList->Offset;
    Offset = (ULONG)(SGList->PhysAddr.QuadPart & (PAGE_SIZE - 1));
    SGList->PhysLen           = __min(PAGE_SIZE - Offset - SGList->Length,
                                      SGElement->Length - SGList->Offset);

    ASSERT3U(SGList->PhysLen, <=, PAGE_SIZE);
    ASSERT3U(SGList->Offset, <, SGElement->Length);

    SGList->Length = SGList->PhysLen; // gets reset every time for Granted, every 1or2 times for Bounced
    SGList->Offset = SGList->Offset + SGList->PhysLen;
    if (SGList->Offset >= SGElement->Length) {
        SGList->Index  = SGList->Index + 1;
        SGList->Offset = 0;
    }
}

static FORCEINLINE BOOLEAN
SGListNext(
    IN OUT  PXENVBD_SG_LIST         SGList,
    IN  ULONG                       AlignmentMask
    )
{
    SGList->Length = 0;
    SGListGet(SGList);  // get next PhysAddr and PhysLen
    return !((SGList->PhysAddr.QuadPart & AlignmentMask) || (SGList->PhysLen & AlignmentMask));
}

static FORCEINLINE PFN_NUMBER
SGListPfn(
    IN  PXENVBD_SG_LIST SGList
    )
{
    return (PFN_NUMBER)(SGList->PhysAddr.QuadPart >> PAGE_SHIFT);
}

static FORCEINLINE ULONG
SGListOffset(
    IN  PXENVBD_SG_LIST SGList
    )
{
    return (ULONG)(SGList->PhysAddr.QuadPart & (PAGE_SIZE - 1));
}

static FORCEINLINE ULONG
SGListLength(
    IN  PXENVBD_SG_LIST SGList
    )
{
    return SGList->PhysLen;
}

static FORCEINLINE PVOID
__TargetAllocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;
    Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   Size,
                                   TARGET_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);
    return Buffer;
}

static FORCEINLINE VOID
__TargetFree(
    IN  PVOID   Buffer
    )
{
    if (Buffer)
        ExFreePoolWithTag(Buffer, TARGET_POOL_TAG);
}

#define TARGET_GET_PROPERTY(_name, _type)       \
_type                                           \
TargetGet ## _name ## (                         \
    IN  PXENVBD_TARGET  Target                  \
    )                                           \
{                                               \
    return Target-> ## _name ## ;               \
}

TARGET_GET_PROPERTY(DeviceId, ULONG)
TARGET_GET_PROPERTY(TargetId, ULONG)
TARGET_GET_PROPERTY(DeviceObject, PDEVICE_OBJECT)
TARGET_GET_PROPERTY(Missing, BOOLEAN)
TARGET_GET_PROPERTY(DevicePnpState, DEVICE_PNP_STATE)
TARGET_GET_PROPERTY(Adapter, PXENVBD_ADAPTER)
TARGET_GET_PROPERTY(Granter, PXENVBD_GRANTER)
TARGET_GET_PROPERTY(Path, PCHAR)
TARGET_GET_PROPERTY(BackendPath, PCHAR)
TARGET_GET_PROPERTY(BackendId, USHORT)
TARGET_GET_PROPERTY(Removable, BOOLEAN)

#undef TARGET_GET_PROPERTY

static FORCEINLINE PCHAR
DevicePnpStateName(
    IN  DEVICE_PNP_STATE    State
    )
{
    switch (State) {
    case Invalid:               return "Invalid";
    case Present:               return "Present";
    case Enumerated:            return "Enumerated";
    case Added:                 return "Added";
    case Started:               return "Started";
    case StopPending:           return "StopPending";
    case Stopped:               return "Stopped";
    case RemovePending:         return "RemovePending";
    case SurpriseRemovePending: return "SurpriseRemovePending";
    case Deleted:               return "Deleted";
    default:                    return "<UNKNOWN>";
    }
}

static FORCEINLINE VOID
TargetRestoreDevicePnpState(
    IN  PXENVBD_TARGET      Target
    )
{
    Verbose("[%u] %s --> %s\n",
            Target->TargetId,
            DevicePnpStateName(Target->DevicePnpState),
            DevicePnpStateName(Target->PrevPnpState));
    Target->DevicePnpState = Target->PrevPnpState;
}

VOID
TargetSetDevicePnpState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_PNP_STATE    State
    )
{
    Verbose("[%u] %s --> %s\n",
            Target->TargetId,
            DevicePnpStateName(Target->DevicePnpState),
            DevicePnpStateName(State));
    Target->PrevPnpState = Target->DevicePnpState;
    Target->DevicePnpState = State;
}
VOID
TargetSetDeviceObject(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    Verbose("[%u] DevObj = 0x%p\n",
            Target->TargetId,
            DeviceObject);
    Target->DeviceObject = DeviceObject;
}

VOID
TargetSetMissing(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR*     Reason
    )
{
    Verbose("[%u] Missing: %s\n", Target->TargetId, Reason);
    Target->Missing = TRUE;
}

static PXENVBD_INDIRECT
TargetGetIndirect(
    IN  PXENVBD_TARGET  Target
    )
{
    PXENVBD_INDIRECT    Indirect;
    NTSTATUS            status;

    Indirect = ExAllocateFromNPagedLookasideList(&Target->IndirectList);
    if (Indirect == NULL)
        goto fail1;

    RtlZeroMemory(Indirect, sizeof(XENVBD_INDIRECT));

    InitializeListHead(&Indirect->ListEntry);
    Indirect->Mdl = __AllocatePage();
    if (Indirect->Mdl == NULL)
        goto fail2;

    Indirect->Page = MmGetSystemAddressForMdlSafe(Indirect->Mdl,
                                                  NormalPagePriority);
    ASSERT(Indirect->Page != NULL);

    status = GranterGet(Target->Granter,
                        MmGetMdlPfnArray(Indirect->Mdl)[0],
                        TRUE,
                        &Indirect->Grant);
    if (!NT_SUCCESS(status))
        goto fail3;

    return Indirect;

fail3:
    __FreePage(Indirect->Mdl);
fail2:
    RtlZeroMemory(Indirect, sizeof(XENVBD_INDIRECT));
    ExFreeToNPagedLookasideList(&Target->IndirectList, Indirect);
fail1:
    return NULL;
}

static VOID
TargetPutIndirect(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_INDIRECT    Indirect
    )
{
    if (Indirect->Grant)
        GranterPut(Target->Granter, Indirect->Grant);

    if (Indirect->Page)
        __FreePage(Indirect->Mdl);

    RtlZeroMemory(Indirect, sizeof(XENVBD_INDIRECT));
    ExFreeToNPagedLookasideList(&Target->IndirectList, Indirect);
}

static PXENVBD_SEGMENT
TargetGetSegment(
    IN  PXENVBD_TARGET  Target
    )
{
    PXENVBD_SEGMENT     Segment;

    Segment = ExAllocateFromNPagedLookasideList(&Target->SegmentList);
    if (Segment == NULL)
        goto fail1;

    RtlZeroMemory(Segment, sizeof(XENVBD_SEGMENT));

    InitializeListHead(&Segment->ListEntry);

    return Segment;

fail1:
    return NULL;
}

static VOID
TargetPutSegment(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SEGMENT Segment
    )
{
    if (Segment->Grant)
        GranterPut(Target->Granter, Segment->Grant);
 
    if (Segment->Buffer)
        MmUnmapLockedPages(Segment->Buffer, &Segment->Mdl);

    if (Segment->BufferId)
        BufferPut(Segment->BufferId);

    RtlZeroMemory(Segment, sizeof(XENVBD_SEGMENT));
    ExFreeToNPagedLookasideList(&Target->SegmentList, Segment);
}

static PXENVBD_REQUEST
TargetGetRequest(
    IN  PXENVBD_TARGET  Target
    )
{
    PXENVBD_REQUEST     Request;

    Request = ExAllocateFromNPagedLookasideList(&Target->RequestList);
    if (Request == NULL)
        goto fail1;

    RtlZeroMemory(Request, sizeof(XENVBD_REQUEST));
    Request->Id = (ULONG64)(ULONG_PTR)Request;

    InitializeListHead(&Request->ListEntry);
    InitializeListHead(&Request->Segments);
    InitializeListHead(&Request->Indirects);

    return Request;

fail1:
    return NULL;
}

static VOID
TargetPutRequest(
    IN  PXENVBD_TARGET      Target,
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
        TargetPutIndirect(Target, Indirect);
    }
    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_SEGMENT     Segment;

        ListEntry = RemoveHeadList(&Request->Segments);
        if (ListEntry == &Request->Segments)
            break;

        Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);
        TargetPutSegment(Target, Segment);
    }

    RtlZeroMemory(Request, sizeof(XENVBD_REQUEST));
    ExFreeToNPagedLookasideList(&Target->RequestList, Request);
}

static FORCEINLINE BOOLEAN
BufferMap(
    IN  PXENVBD_SEGMENT Segment,
    IN  PXENVBD_SG_LIST SGList,
    IN  ULONG           Length
    )
{
    // map PhysAddr to 1 or 2 pages and lock for VirtAddr
#pragma warning(push)
#pragma warning(disable:28145)
    Segment->Mdl.Next           = NULL;
    Segment->Mdl.Size           = (SHORT)(sizeof(MDL) + sizeof(PFN_NUMBER));
    Segment->Mdl.MdlFlags       = MDL_PAGES_LOCKED;
    Segment->Mdl.Process        = NULL;
    Segment->Mdl.MappedSystemVa = NULL;
    Segment->Mdl.StartVa        = NULL;
    Segment->Mdl.ByteCount      = SGListLength(SGList);
    Segment->Mdl.ByteOffset     = SGListOffset(SGList);
    Segment->Pfn[0]             = SGListPfn(SGList);

    if (Segment->Mdl.ByteCount < Length) {
        // need part of next page
        SGListGet(SGList);
        Segment->Mdl.Size       += sizeof(PFN_NUMBER);
        Segment->Mdl.ByteCount  = Segment->Mdl.ByteCount + SGListLength(SGList);
        Segment->Pfn[1]         = SGListPfn(SGList);
    }
#pragma warning(pop)

    ASSERT3U(Segment->Mdl.ByteCount, <=, PAGE_SIZE);
    ASSERT3U(Segment->Mdl.ByteCount, ==, Length);
                
    Segment->Length = min(Segment->Mdl.ByteCount, PAGE_SIZE);
    Segment->Buffer = MmMapLockedPagesSpecifyCache(&Segment->Mdl,
                                                   KernelMode,
                                                   MmCached,
                                                   NULL,
                                                   FALSE,
                                                   NormalPagePriority);
    if (Segment->Buffer == NULL)
        goto fail;

    ASSERT3P(MmGetMdlPfnArray(&Segment->Mdl)[0], ==, Segment->Pfn[0]);
    // if only 1 Pfn is used, this triggers an array-out-of-bounds condition!
    //ASSERT3P(MmGetMdlPfnArray(&Segment->Mdl)[1], ==, Segment->Pfn[1]);
 
    return TRUE;

fail:
    return FALSE;
}

static BOOLEAN
TargetPrepareRW(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  UCHAR           Operation
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    ULONG64             SectorStart = Cdb_LogicalBlock(Srb);
    ULONG               SectorsLeft = Cdb_TransferBlock(Srb);
    LIST_ENTRY          List;
    XENVBD_SG_LIST      SGList;
    KIRQL               Irql;
    const ULONG         SectorSize = Target->SectorSize;
    const ULONG         SectorMask = SectorSize - 1;
    const ULONG         SectorsPerPage = PAGE_SIZE / SectorSize;

    InitializeListHead(&List);
    SGListInit(&SGList, TargetGetAdapter(Target), Srb);

    // validate SectorStart, SectorsLeft fits in this target (prevent read/write beyond extents)

    while (SectorsLeft > 0) {
        PXENVBD_REQUEST Request;
        ULONG           Index;
        ULONG           MaxSegments;

        MaxSegments = Target->FeatureIndirect;
        MaxSegments = min(MaxSegments, XENVBD_MAX_SEGMENTS_PER_INDIRECT); // limit to sensible value
        MaxSegments = max(MaxSegments, BLKIF_MAX_SEGMENTS_PER_REQUEST);   // ensure at least 11
        ASSERT3U(MaxSegments, >=, BLKIF_MAX_SEGMENTS_PER_REQUEST);
        ASSERT3U(MaxSegments, <=, XENVBD_MAX_SEGMENTS_PER_INDIRECT);

        Request = TargetGetRequest(Target);
        if (Request == NULL) 
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);
        
        Request->SrbExt     = SrbExt;
        Request->Operation  = Operation;
        Request->FirstSector = SectorStart;

        // build segments
        for (Index = 0; Index < MaxSegments; ++Index) {
            PXENVBD_SEGMENT Segment;
            ULONG           SectorsNow;
            PFN_NUMBER      Pfn;
            NTSTATUS        status;

            if (SectorsLeft == 0)
                break;

            Segment = TargetGetSegment(Target);
            if (Segment == NULL)
                goto fail2;
            InsertTailList(&Request->Segments, &Segment->ListEntry);
            ++Request->NrSegments;

            if (SGListNext(&SGList, SectorMask)) {
                ASSERT((SGListOffset(&SGList) & SectorMask) == 0);

                Segment->FirstSector = (UCHAR)(SGListOffset(&SGList) / SectorSize);
                SectorsNow           = min(SectorsLeft, SectorsPerPage - Segment->FirstSector);
                Segment->LastSector  = (UCHAR)(Segment->FirstSector + SectorsNow - 1);

                Pfn = SGListPfn(&SGList);
            } else {
                ASSERT((SGListOffset(&SGList) & SectorMask) != 0);

                Segment->FirstSector = (UCHAR)0;
                SectorsNow           = min(SectorsLeft, SectorsPerPage);
                Segment->LastSector  = (UCHAR)(SectorsNow - 1);

                if (!BufferMap(Segment, &SGList, SectorsNow * SectorSize))
                    goto fail3;

                if (!BufferGet(Segment, &Segment->BufferId, &Pfn))
                    goto fail4;

                if (Operation == BLKIF_OP_WRITE) {
                    BufferCopyIn(Segment->BufferId,
                                 Segment->Buffer,
                                 Segment->Length);
                }
            }

            status = GranterGet(Target->Granter,
                                Pfn,
                                Operation == BLKIF_OP_WRITE,
                                &Segment->Grant);
            if (!NT_SUCCESS(status))
                goto fail5;

            SectorStart += SectorsNow;
            SectorsLeft -= SectorsNow;
        }

        // build indirects
        if (MaxSegments > BLKIF_MAX_SEGMENTS_PER_REQUEST) {
            // round up
            ULONG   NumInd = (Request->NrSegments + XENVBD_MAX_SEGMENTS_PER_PAGE - 1) /
                              XENVBD_MAX_SEGMENTS_PER_PAGE;

            ASSERT(NumInd <= BLKIF_MAX_INDIRECT_PAGES_PER_REQUEST);
            while (NumInd--) {
                PXENVBD_INDIRECT    Indirect;

                Indirect = TargetGetIndirect(Target);
                if (Indirect == NULL)
                    goto fail6;

                InsertTailList(&Request->Indirects, &Indirect->ListEntry);
            }
        }
    }

    Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;

        ListEntry = RemoveHeadList(&List);
        if (ListEntry == &List)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        InsertTailList(&Target->Prepared, &Request->ListEntry);
    }
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    return TRUE;

fail6:
fail5:
fail4:
fail3:
fail2:
fail1:
    Srb->SrbStatus = SRB_STATUS_ERROR;
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;

        ListEntry = RemoveHeadList(&List);
        if (ListEntry == &List)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        TargetPutRequest(Target, Request);
    }
    return FALSE;
}

static BOOLEAN
TargetPrepareUnmap(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PUNMAP_LIST_HEADER  Unmap = Srb->DataBuffer;
	ULONG               Count;
    ULONG               Index;
    LIST_ENTRY          List;
    KIRQL               Irql;

    InitializeListHead(&List);
    Count = _byteswap_ushort(*(PUSHORT)Unmap->BlockDescrDataLength) / 
            sizeof(UNMAP_BLOCK_DESCRIPTOR);

    for (Index = 0; Index < Count; ++Index) {
        PUNMAP_BLOCK_DESCRIPTOR Descr = &Unmap->Descriptors[Index];
        PXENVBD_REQUEST         Request;

        Request = TargetGetRequest(Target);
        if (Request == NULL)
            goto fail1;
        InsertTailList(&List, &Request->ListEntry);
        InterlockedIncrement(&SrbExt->RequestCount);

        Request->SrbExt         = SrbExt;
        Request->Operation      = BLKIF_OP_DISCARD;
        Request->FirstSector    = _byteswap_uint64(*(PULONG64)Descr->StartingLba);
        Request->NrSectors      = _byteswap_ulong(*(PULONG)Descr->LbaCount);
        Request->Flags          = 0;
    }

    Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;

        ListEntry = RemoveHeadList(&List);
        if (ListEntry == &List)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        InsertTailList(&Target->Prepared, &Request->ListEntry);
    }
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    return TRUE;

fail1: 
    Srb->SrbStatus = SRB_STATUS_ERROR;
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;

        ListEntry = RemoveHeadList(&List);
        if (ListEntry == &List)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        TargetPutRequest(Target, Request);
    }
    return FALSE;
}

static BOOLEAN
TargetPrepareSync(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt,
    IN  UCHAR           Operation
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PXENVBD_REQUEST     Request;
    KIRQL               Irql;

    Srb->SrbStatus = SRB_STATUS_ERROR;
    Request = TargetGetRequest(Target);
    if (Request == NULL)
        return FALSE;
    InterlockedIncrement(&SrbExt->RequestCount);

    Request->SrbExt     = SrbExt;
    Request->Operation  = Operation;
    Request->FirstSector = Cdb_LogicalBlock(Srb);

    Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    InsertTailList(&Target->Prepared, &Request->ListEntry);
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    return TRUE;
}

static BOOLEAN
TargetPrepareRequest(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    UCHAR               Operation;

    Operation = Cdb_OperationEx(SrbExt->Srb);
    switch (Operation) {
    case SCSIOP_READ:
        return TargetPrepareRW(Target, SrbExt, BLKIF_OP_READ);

    case SCSIOP_WRITE:
        return TargetPrepareRW(Target, SrbExt, BLKIF_OP_WRITE);

    case SCSIOP_UNMAP:
        return TargetPrepareUnmap(Target, SrbExt);

    case SCSIOP_SYNCHRONIZE_CACHE:
        if (Target->FeatureFlush)
            return TargetPrepareSync(Target, SrbExt, BLKIF_OP_FLUSH_DISKCACHE);
        if (Target->FeatureBarrier)
            return TargetPrepareSync(Target, SrbExt, BLKIF_OP_WRITE_BARRIER);
        
        // nothing supported - shouldnt really get here, but just complete if it did
        Warning("[%u] FLUSH & BARRIER not supported, SCSIOP_SYNCHRONIZE_CACHE got to Prepare\n",
                Target->TargetId);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterCompleteSrb(Target->Adapter, SrbExt);
        return TRUE;

    default:
        ASSERT(FALSE);
        break;
    }
    return FALSE;
}

static FORCEINLINE BOOLEAN
TargetPrepareFresh(
    IN  PXENVBD_TARGET  Target
    ) 
{
    PXENVBD_SRBEXT      SrbExt;
    PLIST_ENTRY         ListEntry;
    KIRQL               Irql;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    ListEntry = RemoveHeadList(&Target->Fresh);
    if (ListEntry == &Target->Fresh) {
        KeReleaseSpinLock(&Target->QueueLock, Irql);
        return FALSE;
    }
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);

    if (TargetPrepareRequest(Target, SrbExt))
        return TRUE;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    InsertHeadList(&Target->Fresh, ListEntry);
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    return FALSE;
}

static FORCEINLINE BOOLEAN
TargetSubmitPrepared(
    IN  PXENVBD_TARGET  Target
    )
{
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;
        KIRQL           Irql;

        KeAcquireSpinLock(&Target->QueueLock, &Irql);
        ListEntry = RemoveHeadList(&Target->Prepared);
        if (ListEntry == &Target->Prepared) {
            KeReleaseSpinLock(&Target->QueueLock, Irql);
            break;
        }
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);

        InsertTailList(&Target->Submitted, ListEntry);
        KeReleaseSpinLock(&Target->QueueLock, Irql);

        if (BlockRingSubmit(Target->BlockRing, Request))
            continue;

        KeAcquireSpinLock(&Target->QueueLock, &Irql);
        RemoveEntryList(&Request->ListEntry);
        InsertHeadList(&Target->Prepared, &Request->ListEntry);
        KeReleaseSpinLock(&Target->QueueLock, Irql);

        return FALSE;
    }

    return TRUE;
}

static FORCEINLINE VOID
TargetCompleteShutdown(
    IN  PXENVBD_TARGET  Target
    )
{
    if (IsListEmpty(&Target->Shutdown))
        return;
    if (!IsListEmpty(&Target->Fresh))
        return;
    if (!IsListEmpty(&Target->Prepared))
        return;
    if (!IsListEmpty(&Target->Shutdown))
        return;

    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_SRBEXT  SrbExt;
        KIRQL           Irql;

        KeAcquireSpinLock(&Target->QueueLock, &Irql);
        ListEntry = RemoveHeadList(&Target->Shutdown);
        if (ListEntry == &Target->Shutdown) {
            KeReleaseSpinLock(&Target->QueueLock, Irql);
            break;
        }
        KeReleaseSpinLock(&Target->QueueLock, Irql);

        SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);
        SrbExt->Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterCompleteSrb(TargetGetAdapter(Target), SrbExt);
    }
}

VOID
TargetSubmitRequests(
    IN  PXENVBD_TARGET  Target
    )
{
    for (;;) {
        // submit all prepared requests (0 or more requests)
        // return TRUE if submitted 0 or more requests from prepared queue
        // return FALSE iff ring is full
        if (!TargetSubmitPrepared(Target))
            break;

        // prepare a single SRB (into 1 or more requests)
        // return TRUE if prepare succeeded
        // return FALSE if prepare failed or fresh queue empty
        if (!TargetPrepareFresh(Target))
            break;
    }

    // if no requests/SRBs outstanding, complete any shutdown SRBs
    TargetCompleteShutdown(Target);
}

static FORCEINLINE VOID
TargetDisableFeature(
    IN  PXENVBD_TARGET  Target,
    IN  UCHAR           Operation
    )
{
    switch (Operation) {
    case BLKIF_OP_WRITE_BARRIER:
        Target->FeatureBarrier = FALSE;
        break;
    case BLKIF_OP_FLUSH_DISKCACHE:
        Target->FeatureFlush = FALSE;
        break;
    case BLKIF_OP_DISCARD:
        Target->FeatureDiscard = FALSE;
        break;
    default:
        break;
    }
}

VOID
TargetCompleteResponse(
    IN  PXENVBD_TARGET  Target,
    IN  ULONG64         Id,
    IN  SHORT           Status
    )
{
    PLIST_ENTRY         ListEntry;
    PXENVBD_REQUEST     Request;
    PXENVBD_SRBEXT      SrbExt;
    PSCSI_REQUEST_BLOCK Srb;
    KIRQL               Irql;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    Request = NULL;
    for (ListEntry = Target->Submitted.Flink;
         ListEntry != &Target->Submitted;
         ListEntry = ListEntry->Flink) {
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);

        if (Request->Id == Id) {
            RemoveEntryList(&Request->ListEntry);

            ASSERT3P(Request, ==, (PVOID)(ULONG_PTR)Id);
            break;
        }

        Request = NULL;
    }
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    ASSERT3P(Request, !=, NULL);
    SrbExt = Request->SrbExt;
    ASSERT3P(SrbExt, !=, NULL);
    Srb = SrbExt->Srb;
    ASSERT3P(Srb, !=, NULL);

    switch (Status) {
    case BLKIF_RSP_OKAY:
        if (Request->Operation == BLKIF_OP_READ) {
            for (ListEntry = Request->Segments.Flink;
                 ListEntry != &Request->Segments;
                 ListEntry = ListEntry->Flink) {
                PXENVBD_SEGMENT Segment = CONTAINING_RECORD(ListEntry, XENVBD_SEGMENT, ListEntry);

                if (Segment->BufferId) {
                    ASSERT(Segment->Buffer);
                    ASSERT(Segment->Length);
                    BufferCopyOut(Segment->BufferId,
                                  Segment->Buffer,
                                  Segment->Length);
                }
            }
        }
        break;
    case BLKIF_RSP_EOPNOTSUPP:
        TargetDisableFeature(Target, Request->Operation);
        break;
    case BLKIF_RSP_ERROR:
    default:
        Srb->SrbStatus = SRB_STATUS_ERROR;
        break;
    }

    TargetPutRequest(Target, Request);

    if (InterlockedDecrement(&SrbExt->RequestCount) != 0)
        return;

    if (Srb->SrbStatus == SRB_STATUS_PENDING)
        Srb->SrbStatus = SRB_STATUS_SUCCESS;

    AdapterCompleteSrb(Target->Adapter, SrbExt);
}

VOID
TargetReset(
    IN  PXENVBD_TARGET  Target
    )
{
    ULONG               Outstanding;

    Verbose("[%u] =====>\n", Target->TargetId);

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Trace("polling...\n");
    Outstanding = BlockRingPoll(Target->BlockRing);
    Trace("%u requests outstanding\n", Outstanding);

    Verbose("[%u] <=====\n", Target->TargetId);
}

VOID
TargetFlush(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    KIRQL               Irql;

    SrbExt->Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    InsertTailList(&Target->Shutdown, &SrbExt->ListEntry);
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    BlockRingKick(Target->BlockRing);
}

VOID
TargetShutdown(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    KIRQL               Irql;

    SrbExt->Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    InsertTailList(&Target->Shutdown, &SrbExt->ListEntry);
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    BlockRingKick(Target->BlockRing);
}

VOID
TargetPrepareSrb(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_PENDING;
}

static FORCEINLINE VOID
TargetQueueSrb(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    KIRQL               Irql;

    SrbExt->Srb->SrbStatus = SRB_STATUS_PENDING;

    KeAcquireSpinLock(&Target->QueueLock, &Irql);
    InsertTailList(&Target->Fresh, &SrbExt->ListEntry);
    KeReleaseSpinLock(&Target->QueueLock, Irql);

    BlockRingKick(Target->BlockRing);
}

static FORCEINLINE VOID
TargetInquiryStd(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PINQUIRYDATA        Data = Srb->DataBuffer;
   
    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(INQUIRYDATA))
        return;

    RtlZeroMemory(Data, Srb->DataTransferLength);
    Data->DeviceType            = DIRECT_ACCESS_DEVICE;
    Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
    Data->Versions              = 4;
    Data->ResponseDataFormat    = 2;
    Data->AdditionalLength      = INQUIRYDATABUFFERSIZE - 4;
    Data->CommandQueue          = 1;
    RtlCopyMemory(Data->VendorId,               "XENSRC  ", 8);
    RtlCopyMemory(Data->ProductId,              "PVDISK          ", 16);
    RtlCopyMemory(Data->ProductRevisionLevel,   "3.0 ", 4);

    Srb->DataTransferLength = sizeof(INQUIRYDATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry00(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PUCHAR              Data = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < 7)
        return;

    RtlZeroMemory(Data, Srb->DataTransferLength);
    Data[3] = 3;
    Data[5] = 0x80;
    Data[6] = 0x83;

    Srb->DataTransferLength = 7;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry80(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PVPD_SERIAL_NUMBER_PAGE Data = Srb->DataBuffer;
   
    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(VPD_SERIAL_NUMBER_PAGE) + 4)
        return;

    RtlZeroMemory(Data, Srb->DataTransferLength);
    Data->PageCode = 0x80;
    Data->PageLength = 4;
    RtlStringCchPrintfA((PCHAR)Data->SerialNumber, 4, "%04u", Target->TargetId);

    Srb->DataTransferLength = sizeof(VPD_SERIAL_NUMBER_PAGE) + 4;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry83(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK         Srb = SrbExt->Srb;
    PVPD_IDENTIFICATION_PAGE    Data = Srb->DataBuffer;
    PVPD_IDENTIFICATION_DESCRIPTOR  Descr;

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(VPD_IDENTIFICATION_PAGE) - 1 +
                                  sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16)
        return;

    RtlZeroMemory(Data, Srb->DataTransferLength);
    Data->PageCode = 0x83;
    Data->PageLength = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16;

    Descr = (PVPD_IDENTIFICATION_DESCRIPTOR)Data->Descriptors;
    Descr->CodeSet          = VpdCodeSetAscii;
    Descr->IdentifierType   = VpdIdentifierTypeVendorId;
    Descr->IdentifierLength = 16;
    RtlStringCbPrintfA((PCHAR)Descr->Identifier,
                       16,
                       "XEN:%u:%u",
                       Target->DeviceId,
                       Target->TargetId);

    Srb->DataTransferLength = sizeof(VPD_IDENTIFICATION_PAGE) - 1 +
                              sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + 16;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetInquiry(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    if (Cdb_EVPD(SrbExt->Srb)) {
        switch (Cdb_PageCode(SrbExt->Srb)) {
        case 0x00:  TargetInquiry00(Target, SrbExt);            break;
        case 0x80:  TargetInquiry80(Target, SrbExt);            break;
        case 0x83:  TargetInquiry83(Target, SrbExt);            break;
        default:    SrbExt->Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    } else {
        switch (Cdb_PageCode(SrbExt->Srb)) {
        case 0x00:  TargetInquiryStd(Target, SrbExt);           break;
        default:    SrbExt->Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    }
}

static FORCEINLINE VOID
TargetModeSense(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PMODE_PARAMETER_HEADER  Header;
    ULONG                   Offset;
    UCHAR                   PageCode;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(MODE_PARAMETER_HEADER))
        return;
    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    Header = Srb->DataBuffer;
    Header->ModeDataLength = sizeof(MODE_PARAMETER_HEADER) - 1;

    Offset = sizeof(MODE_PARAMETER_HEADER);
    PageCode = Cdb_PageCode(Srb);
    if (Cdb_Dbd(Srb) == 0 &&
        Srb->DataTransferLength >= Offset + sizeof(MODE_PARAMETER_BLOCK)) {
        PMODE_PARAMETER_BLOCK   Block = (PMODE_PARAMETER_BLOCK)((PUCHAR)Header + Offset);
         
        // Block is ZEROed
        UNREFERENCED_PARAMETER(Block);

        Header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
        Header->ModeDataLength += sizeof(MODE_PARAMETER_BLOCK);
        Offset += sizeof(MODE_PARAMETER_BLOCK);
    }

    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        Srb->DataTransferLength >= Offset + sizeof(MODE_CACHING_PAGE)) {
        PMODE_CACHING_PAGE  Caching = (PMODE_CACHING_PAGE)((PUCHAR)Header + Offset);

        Caching->PageCode   = MODE_PAGE_CACHING;
        Caching->PageLength = sizeof(MODE_CACHING_PAGE);
        // Caching is ZEROed

        Header->ModeDataLength += sizeof(MODE_CACHING_PAGE);
        Offset += sizeof(MODE_CACHING_PAGE);
    }

    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        Srb->DataTransferLength >= Offset + sizeof(MODE_CACHING_PAGE)) {
        PMODE_INFO_EXCEPTIONS  Info = (PMODE_INFO_EXCEPTIONS)((PUCHAR)Header + Offset);

        Info->PageCode      = MODE_PAGE_FAULT_REPORTING;
        Info->PageLength    = sizeof(MODE_INFO_EXCEPTIONS);
        Info->Dexcpt        = 1;
        // Info is ZEROed

        Header->ModeDataLength += sizeof(MODE_CACHING_PAGE);
        Offset += sizeof(MODE_CACHING_PAGE);
    }

    Srb->DataTransferLength = Offset;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetRequestSense(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(SENSE_DATA))
        return;
    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;

    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetReportLuns(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    ULONG               Length;
    ULONG               Offset;
    ULONG               AllocLength = Cdb_AllocationLength(Srb);
    PUCHAR              Buffer = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);
     
    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < 8)
        return;
    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    Length = 0;
    Offset = 8;

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = 0;
        Offset += 8;
        Length += 8;
    }

    if (Offset + 8 <= AllocLength) {
        Buffer[Offset] = XENVBD_MAX_TARGETS;
        Offset += 8;
        Length += 8;
    }

    REVERSE_BYTES(Buffer, &Length);

    Srb->DataTransferLength = __min(Length, AllocLength);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetReadCapacity(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PREAD_CAPACITY_DATA Capacity = Srb->DataBuffer;
    ULONG64             SectorCount = Target->SectorCount;
    ULONG               SectorSize = Target->SectorSize;
    ULONG               LastBlock;

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(READ_CAPACITY_DATA))
        return;
    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    Srb->SrbStatus = SRB_STATUS_ERROR;
    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0)
        return;

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~0ul;

    Capacity->LogicalBlockAddress   = _byteswap_ulong(LastBlock);
    Capacity->BytesPerBlock         = _byteswap_ulong(SectorSize);

    Srb->DataTransferLength = sizeof(READ_CAPACITY_DATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS; 
}

static FORCEINLINE VOID
TargetReadCapacity16(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PREAD_CAPACITY16_DATA   Capacity = Srb->DataBuffer;
    ULONG64                 SectorCount = Target->SectorCount;
    ULONG                   SectorSize = Target->SectorSize;
    ULONG                   LogPerPhysExp;

    Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
    if (Srb->DataTransferLength < sizeof(READ_CAPACITY16_DATA))
        return;
    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    Srb->SrbStatus = SRB_STATUS_ERROR;
    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0)
        return;

    if (Target->PhysicalSectorSize == 0)
        LogPerPhysExp = 0;
    else if (!_BitScanReverse(&LogPerPhysExp, Target->PhysicalSectorSize / SectorSize))
        LogPerPhysExp = 0;

    Capacity->LogicalBlockAddress.QuadPart  = _byteswap_uint64(SectorCount - 1);
    Capacity->BytesPerBlock                 = _byteswap_ulong(SectorSize);
    Capacity->LogicalPerPhysicalExponent    = (UCHAR)LogPerPhysExp;

    Srb->DataTransferLength = sizeof(READ_CAPACITY16_DATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE BOOLEAN
TargetCheckSectors(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    ULONG64             StartSector = Cdb_LogicalBlock(SrbExt->Srb);
    ULONG               SectorCount = Cdb_TransferBlock(SrbExt->Srb);

    // prevent read/write beyond the end of the disk
    if (StartSector >= Target->SectorCount)
        return FALSE;
    if (StartSector + SectorCount >= Target->SectorCount)
        return FALSE;
    return TRUE;
}

VOID
TargetStartSrb(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    UCHAR               Operation;

    Operation = Cdb_OperationEx(Srb);
    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        if (!TargetCheckSectors(Target, SrbExt))
            Srb->SrbStatus = SRB_STATUS_ERROR;
        else
            TargetQueueSrb(Target, SrbExt);
        break;

    case SCSIOP_UNMAP:
        if (Target->FeatureDiscard)
            TargetQueueSrb(Target, SrbExt);
        else
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SCSIOP_SYNCHRONIZE_CACHE:
        if (Target->FeatureBarrier || Target->FeatureFlush)
            TargetQueueSrb(Target, SrbExt);
        else
            Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    case SCSIOP_INQUIRY:
        TargetInquiry(Target, SrbExt);
        break;
    case SCSIOP_MODE_SENSE:
        TargetModeSense(Target, SrbExt);
        break;
    case SCSIOP_REQUEST_SENSE:
        TargetRequestSense(Target, SrbExt);
        break;
    case SCSIOP_REPORT_LUNS:
        TargetReportLuns(Target, SrbExt);
        break;
    case SCSIOP_READ_CAPACITY:
        TargetReadCapacity(Target, SrbExt);
        break;
    case SCSIOP_READ_CAPACITY16:
        TargetReadCapacity16(Target, SrbExt);
        break;

    case SCSIOP_MEDIUM_REMOVAL:
    case SCSIOP_TEST_UNIT_READY:
    case SCSIOP_RESERVE_UNIT:
    case SCSIOP_RESERVE_UNIT10:
    case SCSIOP_RELEASE_UNIT:
    case SCSIOP_RELEASE_UNIT10:
    case SCSIOP_VERIFY:
    case SCSIOP_VERIFY16:
    case SCSIOP_START_STOP_UNIT:
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        break;

    default:
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }
}

static VOID
TargetStoreReadDiskInfo(
    IN  PXENVBD_TARGET  Target
    )
{
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "info",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->DiskInfo = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "sectors",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->SectorCount = _strtoui64(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "sector-size",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->SectorSize = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "physical-sector-size",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->PhysicalSectorSize = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    } else {
        Target->PhysicalSectorSize = Target->SectorSize;
    }
}

static VOID
TargetStoreReadFeatures(
    IN  PXENVBD_TARGET  Target
    )
{
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "removable",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->Removable = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "feature-barrier",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->FeatureBarrier = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "feature-flush-cache",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->FeatureFlush = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "feature-discard",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->FeatureDiscard = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "discard-enable",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        BOOLEAN Enabled = (BOOLEAN)strtoul(Buffer, NULL, 2);
        if (!Enabled)
            Target->FeatureDiscard = FALSE;

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "discard-secure",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->DiscardSecure = (BOOLEAN)strtoul(Buffer, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "discard-alignment",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->DiscardAlignment = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "discard-secure",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->DiscardGranularity = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          "feature-max-indirect-segments",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->FeatureIndirect = strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }
}

static NTSTATUS
TargetStoreWrite(
    IN  PXENVBD_TARGET              Target,
    IN  PXENBUS_STORE_TRANSACTION   Transaction
    )
{
    NTSTATUS                        status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          Transaction,
                          Target->Path,
                          "target-id",
                          "%u",
                          Target->TargetId);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          Transaction,
                          Target->Path,
                          "feature-surprise-remove",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          Transaction,
                          Target->Path,
                          "feature-online-resize",
                          "%u",
                          TRUE);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

static NTSTATUS
TargetWriteTargetPath(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          Target->TargetPath,
                          "frontend",
                          "%s",
                          Target->Path);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          Target->TargetPath,
                          "device",
                          "%u",
                          Target->DeviceId);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static VOID
TargetWaitForBackendStateChange(
    IN  PXENVBD_TARGET  Target,
    OUT XenbusState*    State
    )
{
    KEVENT              Event;
    PXENBUS_STORE_WATCH Watch;
    LARGE_INTEGER       Start;
    ULONGLONG           TimeDelta;
    LARGE_INTEGER       Timeout;
    XenbusState         Old = *State;
    NTSTATUS            status;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    status = XENBUS_STORE(WatchAdd,
                          &Target->StoreInterface,
                          Target->BackendPath,
                          "state",
                          &Event,
                          &Watch);
    if (!NT_SUCCESS(status))
        Watch = NULL;

    KeQuerySystemTime(&Start);
    TimeDelta = 0;

    Timeout.QuadPart = 0;

    while (*State == Old && TimeDelta < 120000) {
        PCHAR           Buffer;
        LARGE_INTEGER   Now;

        if (Watch != NULL) {
            ULONG   Attempt = 0;

            while (++Attempt < 1000) {
                status = KeWaitForSingleObject(&Event,
                                               Executive,
                                               KernelMode,
                                               FALSE,
                                               &Timeout);
                if (status != STATUS_TIMEOUT)
                    break;

                // We are waiting for a watch event at DISPATCH_LEVEL so
                // it is our responsibility to poll the store ring.
                XENBUS_STORE(Poll,
                             &Target->StoreInterface);

                KeStallExecutionProcessor(1000);   // 1ms
            }

            KeClearEvent(&Event);
        }

        status = XENBUS_STORE(Read,
                              &Target->StoreInterface,
                              NULL,
                              Target->BackendPath,
                              "state",
                              &Buffer);
        if (!NT_SUCCESS(status)) {
            *State = XenbusStateUnknown;
        } else {
            *State = (XenbusState)strtol(Buffer, NULL, 10);

            XENBUS_STORE(Free,
                         &Target->StoreInterface,
                         Buffer);
        }

        KeQuerySystemTime(&Now);

        TimeDelta = (Now.QuadPart - Start.QuadPart) / 10000ull;
    }

    if (Watch != NULL)
        (VOID) XENBUS_STORE(WatchRemove,
                            &Target->StoreInterface,
                            Watch);
}

static NTSTATUS
TargetUpdatePath(
    IN  PXENVBD_TARGET  Target
    )
{
    ULONG               Length;
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->Path,
                          "backend-id",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        Target->BackendId = (USHORT)strtoul(Buffer, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    } else {
        Target->BackendId = 0;
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          Target->Path,
                          "backend",
                          &Buffer);
    if (!NT_SUCCESS(status))
        goto fail1;

    __TargetFree(Target->BackendPath);
    Target->BackendPath = NULL;

    Length = (ULONG)strlen(Buffer);

    status = STATUS_NO_MEMORY;
    Target->BackendPath = __TargetAllocate(Length + 1);
    if (Target->BackendPath == NULL)
        goto fail2;

    RtlCopyMemory(Target->BackendPath, Buffer, Length);

    XENBUS_STORE(Free,
                 &Target->StoreInterface,
                 Buffer);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");
    XENBUS_STORE(Free,
                 &Target->StoreInterface,
                 Buffer);
fail1:
    Error("fail1 %08x\n", status);
    return status;

}

static NTSTATUS
TargetClose(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] ----->\n", Target->TargetId);

    if (Target->BackendWatch)
        XENBUS_STORE(WatchRemove,
                     &Target->StoreInterface,
                     Target->BackendWatch);
    Target->BackendWatch = NULL;

    status = TargetUpdatePath(Target);
    if (!NT_SUCCESS(status))
        goto fail1;

    State = XenbusStateUnknown;
    do {
        TargetWaitForBackendStateChange(Target, &State);

        status = STATUS_UNSUCCESSFUL;
        if (State == XenbusStateUnknown)
            goto fail2;
    } while (State == XenbusStateInitialising);

    while (State != XenbusStateClosing && 
           State != XenbusStateClosed) {
        status = XENBUS_STORE(Printf,
                                &Target->StoreInterface,
                                NULL,
                                Target->Path,
                                "state",
                                "%u",
                                (ULONG)XenbusStateClosing);
        if (!NT_SUCCESS(status))
            goto fail3;

        TargetWaitForBackendStateChange(Target, &State);

        status = STATUS_UNSUCCESSFUL;
        if (State == XenbusStateUnknown)
            goto fail4;
    }

    while (State != XenbusStateClosed) {
        status = XENBUS_STORE(Printf,
                                &Target->StoreInterface,
                                NULL,
                                Target->Path,
                                "state",
                                "%u",
                                (ULONG)XenbusStateClosed);
        if (!NT_SUCCESS(status))
            goto fail3;

        TargetWaitForBackendStateChange(Target, &State);

        status = STATUS_UNSUCCESSFUL;
        if (State == XenbusStateUnknown)
            goto fail4;
    }

    Trace("[%u] <-----\n", Target->TargetId);
    return STATUS_SUCCESS;

fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static NTSTATUS
TargetPrepare(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] ----->\n", Target->TargetId);

    status = TargetUpdatePath(Target);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(WatchAdd,
                          &Target->StoreInterface,
                          NULL,
                          Target->BackendPath,
                          ThreadGetEvent(Target->BackendThread),
                          &Target->BackendWatch);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = TargetWriteTargetPath(Target);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          Target->Path,
                          "state",
                          "%u",
                          (ULONG)XenbusStateInitialising);
    if (!NT_SUCCESS(status))
        goto fail4;

    State = XenbusStateUnknown;
    do {
        TargetWaitForBackendStateChange(Target, &State);

        status = STATUS_UNSUCCESSFUL;
        if (State == XenbusStateUnknown)
            goto fail5;
    } while (State == XenbusStateClosed || 
             State == XenbusStateInitialising);

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateInitWait)
        goto fail6;

    Trace("[%u] <-----\n", Target->TargetId);
    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
    XENBUS_STORE(WatchRemove,
                 &Target->StoreInterface,
                 Target->BackendWatch);
    Target->BackendWatch = NULL;
fail2:
    Error("fail2\n");
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static NTSTATUS
TargetConnect(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] ----->\n", Target->TargetId);

    status = GranterConnect(Target->Granter);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = BlockRingConnect(Target->BlockRing);
    if (!NT_SUCCESS(status))
        goto fail2;

    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = XENBUS_STORE(TransactionStart,
                              &Target->StoreInterface,
                              &Transaction);
        if (!NT_SUCCESS(status))
            break;

        status = BlockRingStoreWrite(Target->BlockRing, Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = GranterStoreWrite(Target->Granter, Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = TargetStoreWrite(Target, Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(TransactionEnd,
                              &Target->StoreInterface,
                              Transaction,
                              TRUE);
        if (status == STATUS_RETRY)
            continue;
        break;

abort:
        (VOID) XENBUS_STORE(TransactionEnd,
                            &Target->StoreInterface,
                            Transaction,
                            FALSE);   
        break;
    }
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          Target->Path,
                          "state",
                          "%u",
                          (ULONG)XenbusStateInitialised);
    if (!NT_SUCCESS(status))
        goto fail4;

    State = XenbusStateUnknown;
    do {
       TargetWaitForBackendStateChange(Target, &State);

       status = STATUS_UNSUCCESSFUL;
       if (State == XenbusStateUnknown)
           goto fail5;
    } while (State == XenbusStateInitWait ||
             State == XenbusStateInitialising ||
             State == XenbusStateInitialised);

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateConnected)
        goto fail6;

    TargetStoreReadDiskInfo(Target);
    TargetStoreReadFeatures(Target);

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          Target->Path,
                          "state",
                          "%u",
                          (ULONG)XenbusStateConnected);
    if (!NT_SUCCESS(status))
        goto fail7;

    Trace("[%u] <-----\n", Target->TargetId);
    return STATUS_SUCCESS;

fail7:
    Error("fail7\n");
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
fail4:
    Error("fali4\n");
fail3:
    Error("fail3\n");
    BlockRingDisconnect(Target->BlockRing);
fail2:
    Error("fail2\n");
    GranterDisconnect(Target->Granter);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static VOID
TargetEnable(
    IN  PXENVBD_TARGET  Target
    )
{
    Trace("[%u] ----->\n", Target->TargetId);

    GranterEnable(Target->Granter);
    BlockRingEnable(Target->BlockRing);

    Trace("[%u] <-----\n", Target->TargetId);
}

static VOID
TargetDisable(
    IN  PXENVBD_TARGET  Target
    )
{
    Trace("[%u] ----->\n", Target->TargetId);

    BlockRingDisable(Target->BlockRing);
    GranterDisable(Target->Granter);

    Trace("[%u] <-----\n", Target->TargetId);
}

static VOID
TargetDisconnect(
    IN  PXENVBD_TARGET  Target
    )
{
    Trace("[%u] ----->\n", Target->TargetId);

    BlockRingDisconnect(Target->BlockRing);
    GranterDisconnect(Target->Granter);

    Trace("[%u] <-----\n", Target->TargetId);
}

static FORCEINLINE PCHAR
XenvbdStateName(
    IN  XENVBD_STATE    State
    )
{
    switch (State) {
    case XENVBD_STATE_INVALID:  return "INVALID";
    case XENVBD_INITIALIZED:    return "INITIAIZED";
    case XENVBD_CLOSING:        return "CLOSING";
    case XENVBD_CLOSED:         return "CLOSED";
    case XENVBD_PREPARED:       return "PREPARED";
    case XENVBD_CONNECTED:      return "CONNECTED";
    case XENVBD_ENABLED:        return "ENABLED";
    default:                    return "<UNKNOWN>";
    }
}

static NTSTATUS
TargetSetState(
    IN  PXENVBD_TARGET  Target,
    IN  XENVBD_STATE    State
    )
{
    NTSTATUS            status = STATUS_SUCCESS;

    Verbose("[%u] %s -> %s\n",
            Target->TargetId,
            XenvbdStateName(Target->State),
            XenvbdStateName(State));

    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);

    while (NT_SUCCESS(status) && Target->State != State) {
        switch (Target->State) {
        case XENVBD_INITIALIZED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                status = TargetClose(Target);
                if (!NT_SUCCESS(status))
                    break;
                Target->State = XENVBD_CLOSED;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        case XENVBD_CLOSING:
            switch (State) {
            case XENVBD_INITIALIZED:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                TargetDisconnect(Target);
                Target->State = XENVBD_CLOSED;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        case XENVBD_CLOSED:
            switch (State) {
            //case XENVBD_INITIALIZING:
            //    Target->State = XENVBD_INITIALISED;
            //    break;
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                status = TargetPrepare(Target);
                if (!NT_SUCCESS(status)) {
                    TargetClose(Target);
                    Target->State = XENVBD_CLOSED;
                    break;
                }
                Target->State = XENVBD_PREPARED;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        case XENVBD_PREPARED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
                status = TargetClose(Target);
                if (!NT_SUCCESS(status))
                    break;
                Target->State = XENVBD_CLOSED;
                break;
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                status = TargetConnect(Target);
                if (!NT_SUCCESS(status)) {
                    TargetClose(Target);
                    Target->State = XENVBD_CLOSED;
                    break;
                }
                Target->State = XENVBD_CONNECTED;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        case XENVBD_CONNECTED:
            switch (State) {
            case XENVBD_ENABLED:
                TargetEnable(Target);
                Target->State = XENVBD_ENABLED;
                break;
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
                status = TargetClose(Target);
                if (!NT_SUCCESS(status))
                    break;
                Target->State = XENVBD_CLOSING;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        case XENVBD_ENABLED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_CONNECTED:
                TargetDisable(Target);
                Target->State = XENVBD_CONNECTED;
                break;
            default:
                status = STATUS_UNSUCCESSFUL;
                break;
            }
            break;

        default:
            status = STATUS_UNSUCCESSFUL;
            break;
        }
    }

    Verbose("[%u] in state %s\n",
            Target->TargetId,
            XenvbdStateName(Target->State));

    return status;
}

static FORCEINLINE NTSTATUS
__TargetD3ToD0(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;

    status = XENBUS_STORE(Acquire, &Target->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = TargetSetState(Target, XENVBD_ENABLED);
    if (!NT_SUCCESS(status))
        goto fail2;

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");
    XENBUS_STORE(Release, &Target->StoreInterface);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static FORCEINLINE VOID
__TargetD0ToD3(
    IN  PXENVBD_TARGET  Target
    )
{
    TargetSetState(Target, XENVBD_CLOSED);

    XENBUS_STORE(Release, &Target->StoreInterface);
}

static DECLSPEC_NOINLINE VOID
TargetSuspendCallback(
    IN  PVOID       Context
    )
{
    PXENVBD_TARGET  Target = Context;
    LIST_ENTRY      List;
    NTSTATUS        status;

    // Any outstanding requests are going to cause problems...
    // Submitted requests are lost
    // Prepared requests will need re-preparing (different grant/backend)
    // Fresh SRBs will be ok
    InitializeListHead(&List);
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;
        PXENVBD_SRBEXT  SrbExt;

        ListEntry = RemoveHeadList(&Target->Submitted);
        if (ListEntry == &Target->Submitted)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        SrbExt = Request->SrbExt;

        TargetPutRequest(Target, Request);
        if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
            SrbExt->Srb->SrbStatus = SRB_STATUS_ABORTED;
            AdapterCompleteSrb(Target->Adapter, SrbExt);
        }
    }
    for (;;) {
        PLIST_ENTRY     ListEntry;
        PXENVBD_REQUEST Request;
        PXENVBD_SRBEXT  SrbExt;

        ListEntry = RemoveHeadList(&Target->Prepared);
        if (ListEntry == &Target->Prepared)
            break;
        Request = CONTAINING_RECORD(ListEntry, XENVBD_REQUEST, ListEntry);
        SrbExt = Request->SrbExt;

        TargetPutRequest(Target, Request);
        if (InterlockedDecrement(&SrbExt->RequestCount) == 0) {
            InsertHeadList(&List, &SrbExt->ListEntry);
        }
    }
    for (;;) {
        PLIST_ENTRY     ListEntry;

        ListEntry = RemoveHeadList(&List);
        if (ListEntry == &List)
            break;

        InsertHeadList(&Target->Fresh, ListEntry);
    }

    __TargetD0ToD3(Target);

    status = __TargetD3ToD0(Target);
    ASSERT(NT_SUCCESS(status));
}

static DECLSPEC_NOINLINE VOID
TargetDebugCallback(
    IN  PVOID       Context,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_TARGET  Target = Context;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Adapter: 0x%p DeviceObject: 0x%p\n",
                 Target->Adapter,
                 Target->DeviceObject);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TargetI: %u DeviceId: %u BackendId: %u\n",
                 Target->TargetId,
                 Target->DeviceId,
                 Target->BackendId);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Path: %s\n",
                 Target->Path);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "BackendPath: %s\n",
                 Target->BackendPath ? Target->BackendPath : "NULL");

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TargetPath: %s\n",
                 Target->TargetPath);

    XENBUS_DEBUG(Printf,
                &Target->DebugInterface,
                "Features: %s%s%s%s%s\n",
                Target->Removable ? "REMOVABLE " : "",
                Target->FeatureBarrier ? "BARRIER " : "",
                Target->FeatureDiscard ? "DISCARD " : "",
                Target->FeatureFlush ? "FLUSH " : "",
                Target->FeatureIndirect ? "INDIRECT " : "");

    if (Target->FeatureDiscard) {
        XENBUS_DEBUG(Printf,
                    &Target->DebugInterface,
                    "DISCARD: %s%u @ %u\n",
                    Target->DiscardSecure ? "SECURE " : "",
                    Target->DiscardAlignment,
                    Target->DiscardGranularity);
    }

    if (Target->FeatureIndirect) {
        XENBUS_DEBUG(Printf,
                    &Target->DebugInterface,
                    "INDIRECT: %u MaxSegsPerInd\n",
                    Target->FeatureIndirect);
    }

    XENBUS_DEBUG(Printf,
                &Target->DebugInterface,
                "%llu sectors @ %u (%u) %08x\n",
                Target->SectorCount,
                Target->SectorSize,
                Target->PhysicalSectorSize,
                Target->DiskInfo);
}

static DECLSPEC_NOINLINE NTSTATUS
TargetBackendThread(
    IN  PXENVBD_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVBD_TARGET      Target = Context;
    PKEVENT             Event = ThreadGetEvent(Self); 
    LARGE_INTEGER       Start;
    LARGE_INTEGER       Now;

    KeQuerySystemTime(&Start);
    for (;;) {
        PCHAR           Buffer;
        NTSTATUS        status;
        KIRQL           Irql;
        BOOLEAN         Online = TRUE;

        (VOID) KeWaitForSingleObject(Event,
                                     Executive,
                                     KernelMode,
                                     FALSE,
                                     NULL);
        if (ThreadIsAlerted(Self))
            break;

        KeQuerySystemTime(&Now);
        // Rate limit checking to once a second
        if ((Now.QuadPart - Start.QuadPart) < 10000000ull)
            continue;
        Start.QuadPart = Now.QuadPart;

        KeAcquireSpinLock(&Target->StateLock, &Irql);
        if (Target->DevicePowerState != PowerDeviceD0) {
            KeReleaseSpinLock(&Target->StateLock, Irql);
            continue;
        }
        KeReleaseSpinLock(&Target->StateLock, Irql);

        TargetStoreReadDiskInfo(Target);

        status = XENBUS_STORE(Read,
                              &Target->StoreInterface,
                              NULL,
                              Target->BackendPath,
                              "online",
                              &Buffer);
        if (NT_SUCCESS(status)) {
            Online = (BOOLEAN)strtoul(Buffer, NULL, 2);

            XENBUS_STORE(Free,
                            &Target->StoreInterface,
                            Buffer);
        }

        if (!Online) {
            // eject!
            TargetSetMissing(Target, "Ejecting");
            AdapterTargetListChanged(TargetGetAdapter(Target));
        }
    }

    return STATUS_SUCCESS;
}

NTSTATUS
TargetD3ToD0(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;
    NTSTATUS            status;

    if (Target->DevicePowerState == PowerDeviceD0)
        return STATUS_SUCCESS;

    Verbose("[%u] =====>\n",
            Target->TargetId);

    status = XENBUS_DEBUG(Acquire, &Target->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_SUSPEND(Acquire, &Target->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Register,
                          &Target->DebugInterface,
                         __MODULE__,
                         TargetDebugCallback,
                         Target,
                         &Target->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_SUSPEND(Register,
                            &Target->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            TargetSuspendCallback,
                            Target,
                            &Target->SuspendCallback);
    if (!NT_SUCCESS(status))
        goto fail4;

    KeAcquireSpinLock(&Target->StateLock, &Irql);
    status = __TargetD3ToD0(Target);
    KeReleaseSpinLock(&Target->StateLock, Irql);
    if (!NT_SUCCESS(status))
        goto fail5;

    Target->DevicePowerState = PowerDeviceD0;
    Verbose("[%u] <=====\n",
            Target->TargetId);
    return STATUS_SUCCESS;

fail5:
    Error("fail5\n");
    XENBUS_SUSPEND(Deregister,
                    &Target->SuspendInterface,
                    Target->SuspendCallback);
    Target->SuspendCallback = NULL;
fail4:
    Error("fail4\n");
    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;
fail3:
    Error("fail3\n");
    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);
fail2:
    Error("fail2\n");
    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
TargetD0ToD3(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;

    if (Target->DevicePowerState == PowerDeviceD3)
        return;

    Verbose("[%u] =====>\n",
            Target->TargetId);
    Target->DevicePowerState = PowerDeviceD3;

    KeAcquireSpinLock(&Target->StateLock, &Irql);
    __TargetD0ToD3(Target);
    KeReleaseSpinLock(&Target->StateLock, Irql);

    XENBUS_SUSPEND(Deregister,
                    &Target->SuspendInterface,
                    Target->SuspendCallback);
    Target->SuspendCallback = NULL;

    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);

    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

    Verbose("[%u] <=====\n",
            Target->TargetId);
}

static FORCEINLINE PCHAR
__DeviceUsageName(
    IN  ULONG   Index
    )
{
    switch (Index) {
    case DeviceUsageTypeUndefined:      return NULL;
    case DeviceUsageTypePaging:         return "paging";
    case DeviceUsageTypeHibernation:    return "hibernation";
    case DeviceUsageTypeDumpFile:       return "dump";
    default:                            return NULL;
    }
}

static FORCEINLINE VOID
__TargetDeviceUsageNotification(
    IN  PXENVBD_TARGET      Target,
    IN  PIRP                Irp
    )
{
    PIO_STACK_LOCATION      StackLocation;
    ULONG                   Index;
    BOOLEAN                 Value;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Index = (ULONG)StackLocation->Parameters.UsageNotification.Type;

    if (__DeviceUsageName(Index) == NULL)
        return;
    if (Target->DeviceUsage[Index] == Value)
        return;

    Target->DeviceUsage[Index] = Value;

    Verbose("[%u] %s %s\n",
            Target->TargetId,
            Value ? "ADDING" : "REMOVING",
            __DeviceUsageName(Index));

    (VOID) XENBUS_STORE(Printf,
                        &Target->StoreInterface,
                        NULL,
                        Target->TargetPath,
                        __DeviceUsageName(Index),
                        "%u",
                        Value);
}

NTSTATUS
TargetDispatchPnp(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    )
{
    PIO_STACK_LOCATION  StackLocation;
    
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        (VOID) TargetD3ToD0(Target);
        TargetSetDevicePnpState(Target, Started);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        TargetSetDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        TargetRestoreDevicePnpState(Target);
        break;

    case IRP_MN_STOP_DEVICE:
        TargetD0ToD3(Target);
        TargetSetDevicePnpState(Target, Stopped);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        TargetSetDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        // Should write something to Xenstore to indicate the VETO on deviceeject
        TargetRestoreDevicePnpState(Target);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        TargetSetDevicePnpState(Target, SurpriseRemovePending);
        break;

    case IRP_MN_REMOVE_DEVICE:
        TargetD0ToD3(Target);
        TargetSetMissing(Target, DevicePnpStateName(Target->DevicePnpState));
        TargetSetDevicePnpState(Target, Deleted);
        AdapterTargetListChanged(TargetGetAdapter(Target));
        break;

    case IRP_MN_EJECT:
        TargetSetMissing(Target, "Ejected");
        TargetSetDevicePnpState(Target, Deleted);
        AdapterTargetListChanged(TargetGetAdapter(Target));
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        __TargetDeviceUsageNotification(Target, Irp);
        break;

    default:
        break;
    }

    return DriverDispatchPnp(DeviceObject, Irp);
}

static FORCEINLINE ULONG
__ParseVbd(
    IN  ULONG   DeviceId
    )
{    
    ASSERT3U((DeviceId & ~((1 << 29) - 1)), ==, 0);

    if (DeviceId & (1 << 28))
        return (DeviceId & ((1 << 20) - 1)) >> 8;       /* xvd    */

    switch (DeviceId >> 8) {
    case 202:   return (DeviceId & 0xF0) >> 4;          /* xvd    */
    case 8:     return (DeviceId & 0xF0) >> 4;          /* sd     */
    case 3:     return (DeviceId & 0xC0) >> 6;          /* hda..b */
    case 22:    return ((DeviceId & 0xC0) >> 6) + 2;    /* hdc..d */
    case 33:    return ((DeviceId & 0xC0) >> 6) + 4;    /* hde..f */
    case 34:    return ((DeviceId & 0xC0) >> 6) + 6;    /* hdg..h */
    case 56:    return ((DeviceId & 0xC0) >> 6) + 8;    /* hdi..j */
    case 57:    return ((DeviceId & 0xC0) >> 6) + 10;   /* hdk..l */
    case 88:    return ((DeviceId & 0xC0) >> 6) + 12;   /* hdm..n */
    case 89:    return ((DeviceId & 0xC0) >> 6) + 14;   /* hdo..p */
    default:    return 0xFFFFFFFF;                      /* ERROR  */
    }
}

NTSTATUS
TargetCreate(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PANSI_STRING    Device,
    OUT PXENVBD_TARGET* _Target
    )
{
    PXENVBD_TARGET      Target;
    ULONG               DeviceId;
    ULONG               TargetId;
    ULONG               Size;
    NTSTATUS            status;

    DeviceId = strtoul(Device->Buffer, NULL, 10);
    TargetId = __ParseVbd(DeviceId);
    if (TargetId >= XENVBD_MAX_TARGETS)
        return STATUS_RETRY;
    if (AdapterIsTargetEmulated(Adapter, TargetId))
        return STATUS_RETRY;

    Verbose("[%u] =====> %s\n", TargetId, Device->Buffer);

    status = STATUS_NO_MEMORY; 
    Target = __TargetAllocate(sizeof(XENVBD_TARGET));
    if (Target == NULL)
        goto fail1;

    Target->Adapter         = Adapter;
    Target->DeviceObject    = NULL; // filled in later
    Target->DevicePnpState  = Present;
    Target->DevicePowerState = PowerDeviceD3;
    Target->DeviceId        = DeviceId;
    Target->TargetId        = TargetId;
    Target->State           = XENVBD_INITIALIZED;
    Target->BackendId       = DOMID_INVALID;
    KeInitializeSpinLock(&Target->StateLock);
    KeInitializeSpinLock(&Target->QueueLock);

    AdapterGetDebugInterface(Adapter, &Target->DebugInterface);
    AdapterGetStoreInterface(Adapter, &Target->StoreInterface);
    AdapterGetSuspendInterface(Adapter, &Target->SuspendInterface);

    status = STATUS_NO_MEMORY;
    Size = sizeof("device/vbd/") + Device->Length + 1;
    Target->Path = __TargetAllocate(Size);
    if (Target->Path == NULL)
        goto fail2;

    status = RtlStringCbPrintfA(Target->Path,
                                Size,
                                "device/vbd/%s",
                                Device->Buffer);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = STATUS_NO_MEMORY;
    Size = sizeof("data/scsi/target/XXXX") + 1;
    Target->TargetPath = __TargetAllocate(Size);
    if (Target->TargetPath == NULL)
        goto fail4;

    status = RtlStringCbPrintfA(Target->TargetPath,
                                Size,
                                "data/scsi/target/%u",
                                TargetId);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = GranterCreate(Target, &Target->Granter);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = BlockRingCreate(Target, &Target->BlockRing);
    if (!NT_SUCCESS(status))
        goto fail7;

    status = ThreadCreate(TargetBackendThread,
                          Target,
                          &Target->BackendThread);
    if (!NT_SUCCESS(status))
        goto fail8;

    InitializeListHead(&Target->Fresh);
    InitializeListHead(&Target->Prepared);
    InitializeListHead(&Target->Submitted);
    InitializeListHead(&Target->Shutdown);

    ExInitializeNPagedLookasideList(&Target->RequestList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(XENVBD_REQUEST),
                                    REQUEST_POOL_TAG,
                                    0);
    ExInitializeNPagedLookasideList(&Target->SegmentList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(XENVBD_SEGMENT),
                                    SEGMENT_POOL_TAG,
                                    0);
    ExInitializeNPagedLookasideList(&Target->IndirectList,
                                    NULL,
                                    NULL,
                                    0,
                                    sizeof(XENVBD_INDIRECT),
                                    INDIRECT_POOL_TAG,
                                    0);

    status = TargetD3ToD0(Target);
    if (!NT_SUCCESS(status))
        goto fail9;

    Verbose("[%u] <=====\n", TargetId);
    *_Target = Target;
    return STATUS_SUCCESS;

fail9:
    Error("fail9\n");

    ExDeleteNPagedLookasideList(&Target->RequestList);
    ExDeleteNPagedLookasideList(&Target->SegmentList);
    ExDeleteNPagedLookasideList(&Target->IndirectList);

    RtlZeroMemory(&Target->Fresh, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Prepared, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Submitted, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Shutdown, sizeof(LIST_ENTRY));

    ThreadAlert(Target->BackendThread);
    ThreadJoin(Target->BackendThread);
    Target->BackendThread = NULL;
fail8:
    Error("fail8\n");
    BlockRingDestroy(Target->BlockRing);
    Target->BlockRing = NULL;
fail7:
    Error("fail7\n");
    GranterDestroy(Target->Granter);
    Target->Granter = NULL;
fail6:
    Error("fail6\n");
fail5:
    Error("fail5\n");
    __TargetFree(Target->TargetPath);
    Target->TargetPath = NULL;
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
    __TargetFree(Target->Path);
    Target->Path = NULL;
fail2:
    Error("fail2\n");
    RtlZeroMemory(&Target->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Target->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));
    RtlZeroMemory(&Target->SuspendInterface, sizeof(XENBUS_SUSPEND_INTERFACE));

    Target->Adapter         = NULL;
    Target->DeviceObject    = NULL; // filled in later
    Target->DevicePnpState  = 0;
    Target->DevicePowerState = 0;
    Target->DeviceId        = 0;
    Target->TargetId        = 0;
    Target->State           = 0;
    Target->BackendId       = 0;
    RtlZeroMemory(&Target->QueueLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->StateLock, sizeof(KSPIN_LOCK));

    ASSERT(IsZeroMemory(Target, sizeof(XENVBD_TARGET)));
    __TargetFree(Target);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

VOID
TargetDestroy(
    IN  PXENVBD_TARGET  Target
    )
{
    ASSERT(IsListEmpty(&Target->Fresh));
    ASSERT(IsListEmpty(&Target->Prepared));
    ASSERT(IsListEmpty(&Target->Submitted));
    ASSERT(IsListEmpty(&Target->Shutdown));

    ExDeleteNPagedLookasideList(&Target->RequestList);
    ExDeleteNPagedLookasideList(&Target->SegmentList);
    ExDeleteNPagedLookasideList(&Target->IndirectList);

    RtlZeroMemory(&Target->Fresh, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Prepared, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Submitted, sizeof(LIST_ENTRY));
    RtlZeroMemory(&Target->Shutdown, sizeof(LIST_ENTRY));

    ThreadAlert(Target->BackendThread);
    ThreadJoin(Target->BackendThread);
    Target->BackendThread = NULL;

    BlockRingDestroy(Target->BlockRing);
    Target->BlockRing = NULL;

    GranterDestroy(Target->Granter);
    Target->Granter = NULL;

    __TargetFree(Target->BackendPath);
    Target->BackendPath = NULL;

    __TargetFree(Target->TargetPath);
    Target->TargetPath = NULL;

    __TargetFree(Target->Path);
    Target->Path = NULL;

    RtlZeroMemory(&Target->DebugInterface, sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Target->StoreInterface, sizeof(XENBUS_STORE_INTERFACE));
    RtlZeroMemory(&Target->SuspendInterface, sizeof(XENBUS_SUSPEND_INTERFACE));

    Target->Adapter         = NULL;
    Target->DeviceObject    = NULL; // filled in later
    Target->DevicePnpState  = 0;
    Target->DevicePowerState = 0;
    Target->DeviceId        = 0;
    Target->TargetId        = 0;
    Target->State           = 0;
    Target->BackendId       = 0;
    RtlZeroMemory(&Target->QueueLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->StateLock, sizeof(KSPIN_LOCK));

    ASSERT(IsZeroMemory(Target, sizeof(XENVBD_TARGET)));
    __TargetFree(Target);
}
