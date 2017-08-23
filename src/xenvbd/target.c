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
#include <stdlib.h>
#include <ntstrsafe.h>

#include <xen.h>
#include <xencdb.h>
#include <names.h>
#include <store_interface.h>
#include <evtchn_interface.h>
#include <gnttab_interface.h>
#include <debug_interface.h>
#include <suspend_interface.h>

#include "target.h"
#include "driver.h"
#include "adapter.h"
#include "srbext.h"
#include "thread.h"
#include "base64.h"

#include "debug.h"
#include "assert.h"
#include "util.h"

#define GUID_LENGTH (sizeof("xxxxxxxx-xxxx-xxxx-xxxxxxxxxxxx"))

typedef enum _XENVBD_STATE {
    XENVBD_STATE_INVALID,
    XENVBD_INITIALIZED, // -> { CLOSED }
    XENVBD_CLOSING,     // -> { CLOSED }
    XENVBD_CLOSED,      // -> { PREPARED }
    XENVBD_PREPARED,    // -> { CLOSING, CONNECTED }
    XENVBD_CONNECTED,   // -> { ENABLED, CLOSING }
    XENVBD_ENABLED      // -> { CLOSING }
} XENVBD_STATE, *PXENVBD_STATE;

struct _XENVBD_TARGET {
    PXENVBD_ADAPTER             Adapter;
    PDEVICE_OBJECT              DeviceObject;
    DEVICE_PNP_STATE            DevicePnpState;
    DEVICE_PNP_STATE            PrevPnpState;
    DEVICE_POWER_STATE          DevicePowerState;
    BOOLEAN                     WrittenEjected;
    BOOLEAN                     EjectRequested;
    BOOLEAN                     EjectPending;
    BOOLEAN                     Missing;
    const CHAR*                 Reason;
    BOOLEAN                     Usage[4];
    XENVBD_STATE                State;
    KSPIN_LOCK                  Lock;

    PXENVBD_RING                Ring;
    ULONG                       TargetId;
    ULONG                       DeviceId;
    CHAR                        Path[sizeof("device/vbd/xxxxxxxx")];
    CHAR                        TargetPath[sizeof("data/scsi/target/xxxx")];
    PCHAR                       BackendPath;
    USHORT                      BackendId;

    ULONG64                     SectorCount;
    ULONG                       SectorSize;
    ULONG                       PhysicalSectorSize;
    ULONG                       DiskInfo;
    BOOLEAN                     FeatureRemovable;
    BOOLEAN                     FeatureFlushCache;
    BOOLEAN                     FeatureBarrier;
    BOOLEAN                     FeatureDiscard;
    BOOLEAN                     FeatureDiscardEnable;
    BOOLEAN                     FeatureDiscardSecure;
    ULONG                       FeatureDiscardAlignment;
    ULONG                       FeatureDiscardGranularity;
    ULONG                       FeatureMaxIndirectSegments;
    PVOID                       Page80;
    ULONG                       Page80Length;
    PVOID                       Page83;
    ULONG                       Page83Length;
    CHAR                        VdiUuid[GUID_LENGTH];

    LIST_ENTRY                  ShutdownSrbs;
    KSPIN_LOCK                  ShutdownLock;

    XENBUS_STORE_INTERFACE      StoreInterface;
    XENBUS_DEBUG_INTERFACE      DebugInterface;
    XENBUS_SUSPEND_INTERFACE    SuspendInterface;

    PXENVBD_THREAD              BackendThread;
    PXENBUS_STORE_WATCH         BackendWatch;
    PXENBUS_DEBUG_CALLBACK      DebugCallback;
    PXENBUS_SUSPEND_CALLBACK    SuspendCallback;
};

#define TARGET_POOL_TAG            'odPX'

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
    if (Buffer == NULL)
        return;
    ExFreePoolWithTag(Buffer, TARGET_POOL_TAG);
}

#define TARGET_GET_PROPERTY(_name, _type)       \
static FORCEINLINE _type                        \
__TargetGet ## _name ## (                       \
    IN  PXENVBD_TARGET  Target                  \
    )                                           \
{                                               \
    return Target-> ## _name ## ;               \
}                                               \
_type                                           \
TargetGet ## _name ## (                         \
    IN  PXENVBD_TARGET  Target                  \
    )                                           \
{                                               \
    return __TargetGet ## _name ## (Target);    \
}

TARGET_GET_PROPERTY(Adapter, PXENVBD_ADAPTER)
TARGET_GET_PROPERTY(Ring, PXENVBD_RING)
TARGET_GET_PROPERTY(DeviceObject, PDEVICE_OBJECT)
TARGET_GET_PROPERTY(DevicePnpState, DEVICE_PNP_STATE)
TARGET_GET_PROPERTY(TargetId, ULONG)
TARGET_GET_PROPERTY(DeviceId, ULONG)
TARGET_GET_PROPERTY(Path, PCHAR)
TARGET_GET_PROPERTY(TargetPath, PCHAR)
TARGET_GET_PROPERTY(BackendPath, PCHAR)
TARGET_GET_PROPERTY(BackendId, USHORT)
TARGET_GET_PROPERTY(Missing, BOOLEAN)
TARGET_GET_PROPERTY(SectorCount, ULONG64)
TARGET_GET_PROPERTY(SectorSize, ULONG)
TARGET_GET_PROPERTY(PhysicalSectorSize, ULONG)
TARGET_GET_PROPERTY(FeatureRemovable, BOOLEAN)
TARGET_GET_PROPERTY(FeatureFlushCache, BOOLEAN)
TARGET_GET_PROPERTY(FeatureBarrier, BOOLEAN)
TARGET_GET_PROPERTY(FeatureDiscardSecure, BOOLEAN)
TARGET_GET_PROPERTY(FeatureDiscardAlignment, ULONG)
TARGET_GET_PROPERTY(FeatureDiscardGranularity, ULONG)
TARGET_GET_PROPERTY(FeatureMaxIndirectSegments, ULONG)

//TARGET_GET_PROPERTY(FeatureDiscard, BOOLEAN)
static FORCEINLINE BOOLEAN
__TargetGetFeatureDiscard(
    IN  PXENVBD_TARGET  Target
    )
{
    return Target->FeatureDiscard && Target->FeatureDiscardEnable;
}
BOOLEAN
TargetGetFeatureDiscard(
    IN  PXENVBD_TARGET  Target
    )
{
    return __TargetGetFeatureDiscard(Target);
}

//TARGET_GET_PROPERTY(SurpriseRemovable, BOOLEAN)
static FORCEINLINE BOOLEAN
__TargetGetSurpriseRemovable(
    IN  PXENVBD_TARGET  Target
    )
{
    return (Target->DiskInfo & VDISK_REMOVABLE) ? TRUE : FALSE;
}
BOOLEAN
TargetGetSurpriseRemovable(
    IN  PXENVBD_TARGET  Target
    )
{
    return __TargetGetSurpriseRemovable(Target);
}

#undef TARGET_GET_PROPERTY

static FORCEINLINE PCHAR
__PnpStateName(
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
    default:                    return "UNKNOWN";
    }
}

static FORCEINLINE BOOLEAN
TargetSetDevicePowerState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_POWER_STATE  State
    )
{
    if (Target->DevicePowerState == State)
        return FALSE;

    Verbose("Target[%d] : POWER %s to %s\n",
            __TargetGetTargetId(Target),
            PowerDeviceStateName(Target->DevicePowerState),
            PowerDeviceStateName(State));
    Target->DevicePowerState = State;
    
    return TRUE;
}

VOID
TargetSetMissing(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR      *Reason
    )
{
    ASSERT3P(Reason, !=, NULL);

    if (Target->Missing) {
        Verbose("Target[%d] : Already MISSING (%s) when trying to set (%s)\n",
                __TargetGetTargetId(Target),
                Target->Reason,
                Reason);
    } else {
        Verbose("Target[%d] : MISSING %s\n",
                __TargetGetTargetId(Target),
                Reason);
        Target->Missing = TRUE;
        Target->Reason = Reason;
    }
}

VOID
TargetSetDevicePnpState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_PNP_STATE    State
    )
{
    Verbose("Target[%d] : PNP %s to %s\n",
            __TargetGetTargetId(Target),
            __PnpStateName(Target->DevicePnpState),
            __PnpStateName(State));

    if (Target->DevicePnpState == Deleted)
        return;

    Target->PrevPnpState = Target->DevicePnpState;
    Target->DevicePnpState = State;
}

static FORCEINLINE VOID
__TargetRestoreDevicePnpState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_PNP_STATE    State
    )
{
    if (Target->DevicePnpState != State)
        return;

    Verbose("Target[%d] : PNP %s to %s\n",
            __TargetGetTargetId(Target),
            __PnpStateName(Target->DevicePnpState),
            __PnpStateName(Target->PrevPnpState));
    Target->DevicePnpState = Target->PrevPnpState;
}

VOID
TargetSetDeviceObject(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject
    )
{
    Verbose("Target[%d] : Setting DeviceObject = 0x%p\n",
            __TargetGetTargetId(Target),
            DeviceObject);

    ASSERT3P(Target->DeviceObject, ==, NULL);
    Target->DeviceObject = DeviceObject;
}

VOID
TargetDisableFeature(
    IN  PXENVBD_TARGET  Target,
    IN  UCHAR           Operation
    )
{
    switch (Operation) {
    case BLKIF_OP_WRITE_BARRIER:
        Trace("BLKIF_OP_WRITE_BARRIER not supported\n");
        Target->FeatureBarrier = FALSE;
        break;
    case BLKIF_OP_FLUSH_DISKCACHE:
        Trace("BLKIF_OP_FLUSH_DISKCACHE not supported\n");
        Target->FeatureFlushCache = FALSE;
        break;
    case BLKIF_OP_DISCARD:
        Trace("BLKIF_OP_DISCARD not supported\n");
        Target->FeatureDiscard = FALSE;
        break;
    case BLKIF_OP_READ:
    case BLKIF_OP_WRITE:
        Trace("BLKIF_OP_INDIRECT nor supported\n");
        // BLKIF_OP_[READ|WRITE] cannot fail, this must be BLKIF_OP_INDIRECT
        Target->FeatureMaxIndirectSegments = 0;
        break;
    default:
        break;
    }
}

static FORCEINLINE BOOLEAN
__ValidateSectors(
    IN  ULONG64     SectorCount,
    IN  ULONG64     Start,
    IN  ULONG       Length
    )
{
    // Deal with overflow
    return (Start < SectorCount) && ((Start + Length) <= SectorCount);
}

static FORCEINLINE BOOLEAN
__ValidateSrbBuffer(
    IN  PCHAR               Caller,
    IN  PSCSI_REQUEST_BLOCK Srb,
    IN  ULONG               MinLength
    )
{
    if (Srb->DataBuffer == NULL) {
        Error("%s: Srb[0x%p].DataBuffer = NULL\n", Caller, Srb);
        return FALSE;
    }
    if (MinLength) {
        if (Srb->DataTransferLength < MinLength) {
            Error("%s: Srb[0x%p].DataTransferLength < %d\n", Caller, Srb, MinLength);
            return FALSE;
        }
    } else {
        if (Srb->DataTransferLength == 0) {
            Error("%s: Srb[0x%p].DataTransferLength = 0\n", Caller, Srb);
            return FALSE;
        }
    }

    return TRUE;
}

static FORCEINLINE BOOLEAN
TargetReadWrite(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__ValidateSectors(__TargetGetSectorCount(Target),
                           Cdb_LogicalBlock(Srb),
                           Cdb_TransferBlock(Srb))) {
        Srb->SrbStatus = SRB_STATUS_ERROR;
        return TRUE; // Complete now
    }

    RingQueue(__TargetGetRing(Target), SrbExt);
    return FALSE;
}

static FORCEINLINE BOOLEAN
TargetSyncCache(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__TargetGetFeatureFlushCache(Target) &&
        !__TargetGetFeatureBarrier(Target)) {
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    RingQueue(__TargetGetRing(Target), SrbExt);
    return FALSE;
}

static FORCEINLINE BOOLEAN
TargetUnmap(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__TargetGetFeatureDiscard(Target)) {
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        return TRUE;
    }

    RingQueue(__TargetGetRing(Target), SrbExt);
    return FALSE;
}

#define MODE_CACHING_PAGE_LENGTH 20
static DECLSPEC_NOINLINE VOID
TargetModeSense(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PMODE_PARAMETER_HEADER  Header  = Srb->DataBuffer;
    const UCHAR             PageCode = Cdb_PageCode(Srb);
    ULONG                   LengthLeft = Cdb_AllocationLength(Srb);
    PVOID                   CurrentPage = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    RtlZeroMemory(Srb->DataBuffer, Srb->DataTransferLength);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(struct _MODE_SENSE))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    // TODO : CDROM requires more ModePage entries
    // Header
    Header->ModeDataLength  = sizeof(MODE_PARAMETER_HEADER) - 1;
    Header->MediumType      = 0;
    Header->DeviceSpecificParameter = 0;
    Header->BlockDescriptorLength   = 0;
    LengthLeft -= sizeof(MODE_PARAMETER_HEADER);
    CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_HEADER));

    // Fill in Block Parameters (if Specified and space)
    // when the DBD (Disable Block Descriptor) is set, ignore the block page
    if (Cdb_Dbd(Srb) == 0 &&
        LengthLeft >= sizeof(MODE_PARAMETER_BLOCK)) {
        PMODE_PARAMETER_BLOCK Block = (PMODE_PARAMETER_BLOCK)CurrentPage;
        // Fill in BlockParams
        Block->DensityCode                  =   0;
        Block->NumberOfBlocks[0]            =   0;
        Block->NumberOfBlocks[1]            =   0;
        Block->NumberOfBlocks[2]            =   0;
        Block->BlockLength[0]               =   0;
        Block->BlockLength[1]               =   0;
        Block->BlockLength[2]               =   0;

        Header->BlockDescriptorLength = sizeof(MODE_PARAMETER_BLOCK);
        Header->ModeDataLength += sizeof(MODE_PARAMETER_BLOCK);
        LengthLeft -= sizeof(MODE_PARAMETER_BLOCK);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_PARAMETER_BLOCK));
    }

    // Fill in Cache Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_CACHING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= MODE_CACHING_PAGE_LENGTH) {
        PMODE_CACHING_PAGE Caching = (PMODE_CACHING_PAGE)CurrentPage;
        // Fill in CachingParams
        Caching->PageCode                   = MODE_PAGE_CACHING;
        Caching->PageSavable                = 0;
        Caching->PageLength                 = MODE_CACHING_PAGE_LENGTH;
        Caching->ReadDisableCache           = 0;
        Caching->MultiplicationFactor       = 0;
        Caching->WriteCacheEnable           = __TargetGetFeatureFlushCache(Target) ? 1 : 0;
        Caching->WriteRetensionPriority     = 0;
        Caching->ReadRetensionPriority      = 0;
        Caching->DisablePrefetchTransfer[0] = 0;
        Caching->DisablePrefetchTransfer[1] = 0;
        Caching->MinimumPrefetch[0]         = 0;
        Caching->MinimumPrefetch[1]         = 0;
        Caching->MaximumPrefetch[0]         = 0;
        Caching->MaximumPrefetch[1]         = 0;
        Caching->MaximumPrefetchCeiling[0]  = 0;
        Caching->MaximumPrefetchCeiling[1]  = 0;

        Header->ModeDataLength += MODE_CACHING_PAGE_LENGTH;
        LengthLeft -= MODE_CACHING_PAGE_LENGTH;
        CurrentPage = ((PUCHAR)CurrentPage + MODE_CACHING_PAGE_LENGTH);
    }

    // Fill in Informational Exception Parameters (if Specified and space)
    if ((PageCode == MODE_PAGE_FAULT_REPORTING || PageCode == MODE_SENSE_RETURN_ALL) &&
        LengthLeft >= sizeof(MODE_INFO_EXCEPTIONS)) {
        PMODE_INFO_EXCEPTIONS Exceptions = (PMODE_INFO_EXCEPTIONS)CurrentPage;
        // Fill in Exceptions
        Exceptions->PageCode                = MODE_PAGE_FAULT_REPORTING;
        Exceptions->PSBit                   = 0;
        Exceptions->PageLength              = sizeof(MODE_INFO_EXCEPTIONS);
        Exceptions->Flags                   = 0;
        Exceptions->Dexcpt                  = 1; // disabled
        Exceptions->ReportMethod            = 0;
        Exceptions->IntervalTimer[0]        = 0;
        Exceptions->IntervalTimer[1]        = 0;
        Exceptions->IntervalTimer[2]        = 0;
        Exceptions->IntervalTimer[3]        = 0;
        Exceptions->ReportCount[0]          = 0;
        Exceptions->ReportCount[1]          = 0;
        Exceptions->ReportCount[2]          = 0;
        Exceptions->ReportCount[3]          = 0;

        Header->ModeDataLength += sizeof(MODE_INFO_EXCEPTIONS);
        LengthLeft -= sizeof(MODE_INFO_EXCEPTIONS);
        CurrentPage = ((PUCHAR)CurrentPage + sizeof(MODE_INFO_EXCEPTIONS));
    }

    // Finish this SRB
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
    Srb->DataTransferLength = __min(Cdb_AllocationLength(Srb), (ULONG)(Header->ModeDataLength + 1));
}

static DECLSPEC_NOINLINE VOID
TargetRequestSense(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PSENSE_DATA         Sense = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, (ULONG)sizeof(SENSE_DATA))) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        return;
    }

    RtlZeroMemory(Sense, sizeof(SENSE_DATA));

    Sense->ErrorCode            = 0x70;
    Sense->Valid                = 1;
    Sense->AdditionalSenseCodeQualifier = 0;
    Sense->SenseKey             = SCSI_SENSE_NO_SENSE;
    Sense->AdditionalSenseCode  = SCSI_ADSENSE_NO_SENSE;
    Srb->DataTransferLength     = sizeof(SENSE_DATA);
    Srb->SrbStatus              = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
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

    if (!__ValidateSrbBuffer(__FUNCTION__, Srb, 8)) {
        Srb->ScsiStatus = 0x40;
        Srb->SrbStatus = SRB_STATUS_DATA_OVERRUN;
        Srb->DataTransferLength = 0;
        return;
    }

    RtlZeroMemory(Buffer, AllocLength);

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

static DECLSPEC_NOINLINE VOID
TargetReadCapacity(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PREAD_CAPACITY_DATA Capacity = Srb->DataBuffer;
    ULONG64             SectorCount;
    ULONG               SectorSize;
    ULONG               LastBlock;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = __TargetGetSectorCount(Target);
    SectorSize = __TargetGetSectorSize(Target);

    if (SectorCount == (ULONG)SectorCount)
        LastBlock = (ULONG)SectorCount - 1;
    else
        LastBlock = ~(ULONG)0;

    if (Capacity) {
        Capacity->LogicalBlockAddress = _byteswap_ulong(LastBlock);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetReadCapacity16(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PREAD_CAPACITY16_DATA   Capacity = Srb->DataBuffer;
    ULONG64                 SectorCount;
    ULONG                   SectorSize;
    ULONG                   PhysSectorSize;
    ULONG                   LogicalPerPhysical;
    ULONG                   LogicalPerPhysicalExponent;

    if (Cdb_PMI(Srb) == 0 && Cdb_LogicalBlock(Srb) != 0) {
        Srb->ScsiStatus = 0x02; // CHECK_CONDITION
        return;
    }

    SectorCount = __TargetGetSectorCount(Target);
    SectorSize = __TargetGetSectorSize(Target);
    PhysSectorSize = __TargetGetPhysicalSectorSize(Target);

    LogicalPerPhysical = PhysSectorSize / SectorSize;

    if (!_BitScanReverse(&LogicalPerPhysicalExponent, LogicalPerPhysical))
        LogicalPerPhysicalExponent = 0;

    if (Capacity) {
        Capacity->LogicalBlockAddress.QuadPart = _byteswap_uint64(SectorCount - 1);
        Capacity->BytesPerBlock = _byteswap_ulong(SectorSize);
        Capacity->LogicalPerPhysicalExponent = (UCHAR)LogicalPerPhysicalExponent;
    }

    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TargetInquiry00(
    IN  PXENVBD_TARGET          Target,
    IN  PXENVBD_SRBEXT          SrbExt
    )
{
    PSCSI_REQUEST_BLOCK         Srb = SrbExt->Srb;
    PVPD_SUPPORTED_PAGES_PAGE   Data = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (Srb->DataTransferLength < sizeof(VPD_SUPPORTED_PAGES_PAGE) - 1 + 3) {
        Srb->DataTransferLength = 0;
        Srb->SrbStatus = SRB_STATUS_ERROR;
        return;
    }

    RtlZeroMemory(Data, Srb->DataTransferLength);
    Data->PageCode = 0x00;
    Data->PageLength = 3;
    Data->SupportedPageList[0] = 0x00;
    Data->SupportedPageList[1] = 0x80;
    Data->SupportedPageList[2] = 0x83;

    Srb->DataTransferLength = sizeof(VPD_SUPPORTED_PAGES_PAGE) - 1 + 3;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TargetInquiry80(
    IN  PXENVBD_TARGET      Target,
    IN  PXENVBD_SRBEXT      SrbExt
    )
{
    PSCSI_REQUEST_BLOCK     Srb = SrbExt->Srb;
    PVPD_SERIAL_NUMBER_PAGE Data = Srb->DataBuffer;
    ULONG                   Length;

    RtlZeroMemory(Data, Srb->DataTransferLength);
    
    if (Target->Page80 && Target->Page80Length) {
        if (Srb->DataTransferLength < Target->Page80Length) {
            Srb->DataTransferLength = 0;
            Srb->SrbStatus = SRB_STATUS_ERROR;
            return;
        }

        RtlCopyMemory(Data,
                      Target->Page80,
                      Target->Page80Length);

        Length = Target->Page80Length;
    } else {
        Data->PageCode      = 0x80;
        Data->PageLength    = 4;
        RtlStringCbPrintfA((PCHAR)Data->SerialNumber,
                           4,
                           "%04u",
                           __TargetGetTargetId(Target));

        Length = sizeof(VPD_SERIAL_NUMBER_PAGE) + 4;
    }

    Srb->DataTransferLength = Length;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TargetInquiry83(
    IN  PXENVBD_TARGET          Target,
    IN  PXENVBD_SRBEXT          SrbExt
    )
{
    PSCSI_REQUEST_BLOCK         Srb = SrbExt->Srb;
    PVPD_IDENTIFICATION_PAGE    Data = Srb->DataBuffer;
    ULONG                       Length;
    PVPD_IDENTIFICATION_DESCRIPTOR  Descr;

    RtlZeroMemory(Data, Srb->DataTransferLength);

    if (Target->Page83 && Target->Page83Length) {
        if (Srb->DataTransferLength < Target->Page83Length) {
            Srb->DataTransferLength = 0;
            Srb->SrbStatus = SRB_STATUS_ERROR;
            return;
        }

        RtlCopyMemory(Data,
                      Target->Page83,
                      Target->Page83Length);

        Length = Target->Page83Length;
    } else {
        Data->PageCode          = 0x83;
        Data->PageLength        = 16;
        Descr = (PVPD_IDENTIFICATION_DESCRIPTOR)Data->Descriptors;
        Descr->CodeSet          = VpdCodeSetAscii;
        Descr->IdentifierType   = VpdIdentifierTypeVendorId;
        Descr->IdentifierLength = 16;
        RtlStringCbPrintfA((PCHAR)Descr->Identifier,
                           16,
                           "XENSRC  %08u",
                           __TargetGetTargetId(Target));

        Length = sizeof(VPD_IDENTIFICATION_PAGE) - 1 +
                 sizeof(VPD_IDENTIFICATION_DESCRIPTOR) - 1 +
                 16;
    }

    // Append vdi-uuid descriptor (if buffer is large enough)
    if (Srb->DataTransferLength >= Length + sizeof(VPD_IDENTIFICATION_DESCRIPTOR) - 1 + GUID_LENGTH) {
        Data->PageLength += sizeof(VPD_IDENTIFICATION_DESCRIPTOR) - 1 + GUID_LENGTH;

        Descr = (PVPD_IDENTIFICATION_DESCRIPTOR)((PUCHAR)Data + Length);
        Descr->CodeSet          = VpdCodeSetAscii;
        Descr->IdentifierType   = VpdIdentifierTypeVendorSpecific;
        Descr->IdentifierLength = GUID_LENGTH;
        RtlStringCbPrintfA((PCHAR)Descr->Identifier,
                           GUID_LENGTH,
                           "%s",
                           Target->VdiUuid);

        Length += sizeof(VPD_IDENTIFICATION_DESCRIPTOR) - 1 +
                  GUID_LENGTH;
    }

    Srb->DataTransferLength = Length;
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static FORCEINLINE VOID
__TargetInquiryStd(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    PINQUIRYDATA        Data = Srb->DataBuffer;

    UNREFERENCED_PARAMETER(Target);

    if (Srb->DataTransferLength < sizeof(INQUIRYDATA)) {
        Srb->DataTransferLength = 0;
        Srb->SrbStatus = SRB_STATUS_ERROR;
        return;
    }

    Data->DeviceType            = DIRECT_ACCESS_DEVICE;
    Data->DeviceTypeQualifier   = DEVICE_CONNECTED;
    Data->Versions              = 4;
    Data->ResponseDataFormat    = 2;
    Data->AdditionalLength      = 0;
    Data->CommandQueue          = 1;
    RtlStringCbPrintfA((PCHAR)Data->VendorId, 8, "XENSRC");
    RtlStringCbPrintfA((PCHAR)Data->ProductId, 16, "PVDISK");
    RtlStringCbPrintfA((PCHAR)Data->ProductRevisionLevel, 4, "3.0");

    Srb->DataTransferLength = sizeof(INQUIRYDATA);
    Srb->SrbStatus = SRB_STATUS_SUCCESS;
}

static DECLSPEC_NOINLINE VOID
TargetInquiry(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (Cdb_EVPD(Srb)) {
        switch (Cdb_PageCode(Srb)) {
        case 0x00:  __TargetInquiry00(Target, SrbExt);  break;
        case 0x80:  __TargetInquiry80(Target, SrbExt);  break;
        case 0x83:  __TargetInquiry83(Target, SrbExt);  break;
        default:    Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    } else {
        switch (Cdb_PageCode(Srb)) {
        case 0x00:  __TargetInquiryStd(Target, SrbExt); break;
        default:    Srb->SrbStatus = SRB_STATUS_ERROR;  break;
        }
    }
}

static FORCEINLINE BOOLEAN
__ValidateSrbForTarget(
    IN  PXENVBD_TARGET      Target,
    IN  PSCSI_REQUEST_BLOCK Srb
    )
{
    const UCHAR             Operation = Cdb_OperationEx(Srb);

    if (Srb->PathId != 0) {
        Error("Target[%d] : Invalid PathId(%d) (%02x:%s)\n",
              __TargetGetTargetId(Target),
              Srb->PathId,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_PATH_ID;
        return FALSE;
    }

    if (Srb->Lun != 0) {
        Error("Target[%d] : Invalid Lun(%d) (%02x:%s)\n",
              __TargetGetTargetId(Target),
              Srb->Lun,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_LUN;
        return FALSE;
    }

    if (__TargetGetMissing(Target)) {
        Error("Target[%d] : %s (%s) (%02x:%s)\n",
              __TargetGetTargetId(Target),
              Target->Missing ? "MISSING" : "NOT_MISSING",
              Target->Reason,
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_NO_DEVICE;
        return FALSE;
    }

    return TRUE;
}

VOID
TargetPrepareIo(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;

    if (!__ValidateSrbForTarget(Target, Srb))
        return;

    Srb->SrbStatus = SRB_STATUS_PENDING;
}

BOOLEAN
TargetStartIo(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    PSCSI_REQUEST_BLOCK Srb = SrbExt->Srb;
    const UCHAR         Operation = Cdb_OperationEx(Srb);
    BOOLEAN             WasQueued = FALSE;

    ASSERT(__ValidateSrbForTarget(Target, Srb));

    switch (Operation) {
    case SCSIOP_READ:
    case SCSIOP_WRITE:
        if (!TargetReadWrite(Target, SrbExt))
            WasQueued = TRUE;
        break;

    case SCSIOP_UNMAP:
        if (!TargetUnmap(Target, SrbExt))
            WasQueued = TRUE;
        break;

    case SCSIOP_SYNCHRONIZE_CACHE:
        if (!TargetSyncCache(Target, SrbExt))
            WasQueued = TRUE;
        break;

    case SCSIOP_INQUIRY:
        AdapterSetDeviceQueueDepth(__TargetGetAdapter(Target),
                                   __TargetGetTargetId(Target));
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
        Trace("Target[%d] : Unsupported CDB (%02x:%s)\n",
              TargetGetTargetId(Target),
              Operation,
              Cdb_OperationName(Operation));
        Srb->SrbStatus = SRB_STATUS_INVALID_REQUEST;
        break;
    }
    return WasQueued;
}

static DECLSPEC_NOINLINE NTSTATUS
TargetSetState(
    IN  PXENVBD_TARGET  Target,
    IN  XENVBD_STATE    State
    );

VOID
TargetReset(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;

    Verbose("[%u] =====>\n", __TargetGetTargetId(Target));

    status = TargetSetState(Target, XENVBD_CONNECTED);
    ASSERT(NT_SUCCESS(status));

    RingReset(Target->Ring);

    status = TargetSetState(Target, XENVBD_ENABLED);
    ASSERT(NT_SUCCESS(status));

    Verbose("[%u] <=====\n", __TargetGetTargetId(Target));
}

VOID
TargetFlush(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    Trace("[%u] =====> (0x%p)\n", __TargetGetTargetId(Target), SrbExt->Srb);
    ExInterlockedInsertTailList(&Target->ShutdownSrbs,
                                &SrbExt->ListEntry,
                                &Target->ShutdownLock);
    RingNotify(__TargetGetRing(Target));
    Trace("[%u] <=====\n", __TargetGetTargetId(Target));
}

VOID
TargetShutdown(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    )
{
    Trace("[%u] =====> (0x%p)\n", __TargetGetTargetId(Target), SrbExt->Srb);
    ExInterlockedInsertTailList(&Target->ShutdownSrbs,
                                &SrbExt->ListEntry,
                                &Target->ShutdownLock);
    RingNotify(__TargetGetRing(Target));
    Trace("[%u] <=====\n", __TargetGetTargetId(Target));
}

VOID
TargetCompleteShutdown(
    IN  PXENVBD_TARGET      Target
    )
{
    for (;;) {
        PLIST_ENTRY         ListEntry;
        PXENVBD_SRBEXT      SrbExt;
        PSCSI_REQUEST_BLOCK Srb;

        ListEntry = ExInterlockedRemoveHeadList(&Target->ShutdownSrbs,
                                                &Target->ShutdownLock);
        if (ListEntry == NULL)
            break;

        SrbExt = CONTAINING_RECORD(ListEntry, XENVBD_SRBEXT, ListEntry);
        Srb = SrbExt->Srb;

        Trace("[%u] =====> (0x%p)\n", __TargetGetTargetId(Target), SrbExt->Srb);
        Srb->SrbStatus = SRB_STATUS_SUCCESS;
        AdapterCompleteSrb(__TargetGetAdapter(Target), SrbExt);
        Trace("[%u] <=====\n", __TargetGetTargetId(Target));
    }
}

VOID
TargetIssueDeviceEject(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR      *Reason
    )
{
    BOOLEAN             DoEject = FALSE;

    if (Target->DeviceObject) {
        DoEject = TRUE;
        Target->EjectRequested = TRUE;
    } else {
        Target->EjectPending = TRUE;
    }

    Verbose("Target[%d] : Ejecting (%s - %s)\n",
            __TargetGetTargetId(Target),
            DoEject ? "Now" : "Next PnP IRP",
            Reason);
    if (!Target->WrittenEjected) {
        Target->WrittenEjected = TRUE;
        (VOID) XENBUS_STORE(Printf,
                            &Target->StoreInterface,
                            NULL,
                            __TargetGetPath(Target),
                            "ejected",
                            "1");
    }
    if (DoEject) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n",
                __TargetGetTargetId(Target),
                Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    } else {
        Verbose("Target[%d] : Triggering BusChangeDetected to detect device\n",
                __TargetGetTargetId(Target));
        AdapterTargetListChanged(TargetGetAdapter(Target));
    }
}

static FORCEINLINE PCHAR
__DeviceUsageName(
    IN  DEVICE_USAGE_NOTIFICATION_TYPE  Type
    )
{
    switch (Type) {
    case DeviceUsageTypePaging:         return "paging";
    case DeviceUsageTypeHibernation:    return "hibernation";
    case DeviceUsageTypeDumpFile:       return "dump";
    default:                            return NULL;
    }
}

static FORCEINLINE VOID
__TargetDeviceUsageNotification(
    IN  PXENVBD_TARGET              Target,
    IN  PIRP                        Irp
    )
{
    PIO_STACK_LOCATION              StackLocation;
    BOOLEAN                         Value;
    DEVICE_USAGE_NOTIFICATION_TYPE  Type;
    PCHAR                           Name;

    StackLocation = IoGetCurrentIrpStackLocation(Irp);
    Value = StackLocation->Parameters.UsageNotification.InPath;
    Type  = StackLocation->Parameters.UsageNotification.Type;

    Name = __DeviceUsageName(Type);
    if (Name == NULL)
        return;
    if (Target->Usage[Type] == Value)
        return;

    Target->Usage[Type] = Value;

    Verbose("[%u] %s = %s\n",
            __TargetGetTargetId(Target),
            Name,
            Value ? "TRUE" : "FALSE");
    (VOID) XENBUS_STORE(Printf,
                        &Target->StoreInterface,
                        NULL,
                        Target->TargetPath,
                        Name,
                        "%u",
                        Value ? 1 : 0);
}

static FORCEINLINE VOID
__TargetCheckEjectPending(
    IN  PXENVBD_TARGET  Target
    )
{
    BOOLEAN             EjectPending = FALSE;

    if (Target->EjectPending) {
        EjectPending = TRUE;
        Target->EjectPending = FALSE;
        Target->EjectRequested = TRUE;
    }

    if (EjectPending) {
        Verbose("Target[%d] : IoRequestDeviceEject(0x%p)\n",
                __TargetGetTargetId(Target),
                Target->DeviceObject);
        IoRequestDeviceEject(Target->DeviceObject);
    }
}

static FORCEINLINE VOID
__TargetCheckEjectFailed(
    IN  PXENVBD_TARGET  Target
    )
{
    BOOLEAN             EjectFailed = FALSE;

    if (Target->EjectRequested) {
        EjectFailed = TRUE;
        Target->EjectRequested = FALSE;
    }

    if (EjectFailed) {
        Error("Target[%d] : Unplug failed due to open handle(s)!\n",
              __TargetGetTargetId(Target));
        (VOID) XENBUS_STORE(Printf,
                            &Target->StoreInterface,
                            NULL,
                            __TargetGetPath(Target),
                            "error",
                            "Unplug failed due to open handle(s)!");
    }
}

static FORCEINLINE VOID
__TargetRemoveDevice(
    IN  PXENVBD_TARGET  Target
    )
{
    TargetD0ToD3(Target);

    switch (TargetGetDevicePnpState(Target)) {
    case SurpriseRemovePending:
        TargetSetMissing(Target, "Surprise Remove");
        break;

    default:
        TargetSetMissing(Target, "Removed");
        break;
    }

    TargetSetDevicePnpState(Target, Deleted);
    AdapterTargetListChanged(TargetGetAdapter(Target));
}

static FORCEINLINE VOID
__TargetEject(
    IN  PXENVBD_TARGET  Target
    )
{
    TargetSetMissing(Target, "Ejected");
    TargetSetDevicePnpState(Target, Deleted);
    AdapterTargetListChanged(TargetGetAdapter(Target));
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

    __TargetCheckEjectPending(Target);

    switch (StackLocation->MinorFunction) {
    case IRP_MN_START_DEVICE:
        (VOID) TargetD3ToD0(Target);
        TargetSetDevicePnpState(Target, Started);
        break;

    case IRP_MN_QUERY_STOP_DEVICE:
        TargetSetDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_CANCEL_STOP_DEVICE:
        __TargetRestoreDevicePnpState(Target, StopPending);
        break;

    case IRP_MN_STOP_DEVICE:
        TargetD0ToD3(Target);
        TargetSetDevicePnpState(Target, Stopped);
        break;

    case IRP_MN_QUERY_REMOVE_DEVICE:
        TargetSetDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        __TargetCheckEjectFailed(Target);
        __TargetRestoreDevicePnpState(Target, RemovePending);
        break;

    case IRP_MN_SURPRISE_REMOVAL:
        TargetSetDevicePnpState(Target, SurpriseRemovePending);
        break;

    case IRP_MN_REMOVE_DEVICE:
        __TargetRemoveDevice(Target);
        break;

    case IRP_MN_EJECT:
        __TargetEject(Target);
        break;

    case IRP_MN_DEVICE_USAGE_NOTIFICATION:
        __TargetDeviceUsageNotification(Target, Irp);
        break;

    default:
        break;
    }
    return DriverDispatchPnp(DeviceObject, Irp);
}

static FORCEINLINE NTSTATUS
TargetReadParameters(
    IN  PXENVBD_TARGET  Target
    )
{
    BOOLEAN             Changed = FALSE;
    PCHAR               Value;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "info",
                          &Value);
    if (NT_SUCCESS(status)) {
        ULONG   Temp = strtoul(Value, NULL, 10);
        if (Target->DiskInfo != Temp)
            Changed = TRUE;
        Target->DiskInfo = Temp;

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "sector-size",
                          &Value);
    if (NT_SUCCESS(status)) {
        ULONG   Temp = strtoul(Value, NULL, 10);
        if (Target->SectorSize != Temp)
            Changed = TRUE;
        Target->SectorSize = Temp;

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "physical-sector-size",
                          &Value);
    if (NT_SUCCESS(status)) {
        Target->PhysicalSectorSize = strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    } else {
        Target->PhysicalSectorSize = Target->SectorSize;
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "sectors",
                          &Value);
    if (NT_SUCCESS(status)) {
        ULONG64 Temp = strtoul(Value, NULL, 10);
        if (Target->SectorCount != Temp)
            Changed = TRUE;
        Target->SectorCount = Temp;

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    }

    if (__TargetGetSectorCount(Target) == 0)
        return STATUS_INVALID_PARAMETER;
    if (__TargetGetSectorSize(Target) != 512)
        return STATUS_INVALID_PARAMETER;

    if (Changed) {
        Verbose("[%u] sectors=%llu, sector-size=%u, physical-sector-size=%u\n",
                __TargetGetTargetId(Target),
                __TargetGetSectorCount(Target),
                __TargetGetSectorSize(Target),
                __TargetGetPhysicalSectorSize(Target));
    }
    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetZeroParameters(
    IN  PXENVBD_TARGET  Target
    )
{
    Target->DiskInfo = 0;
    Target->SectorSize = 0;
    Target->PhysicalSectorSize = 0;
    Target->SectorCount = 0;
}

static FORCEINLINE NTSTATUS
TargetReadFeatures(
    IN  PXENVBD_TARGET  Target
    )
{

#define READ_FEATURE(_type, _radix, _name)                                          \
    do {                                                                            \
        const CHAR      *Name;                                                      \
        ULONG           Override;                                                   \
        PCHAR           Value;                                                      \
        NTSTATUS        status;                                                     \
        Name = DriverGetFeatureName( ## _name ## );                                 \
        if (Name == NULL)                                                           \
            break;                                                                  \
        status = XENBUS_STORE(Read,                                                 \
                              &Target->StoreInterface,                              \
                              NULL,                                                 \
                              __TargetGetBackendPath(Target),                       \
                              (PCHAR)Name,                                          \
                              &Value);                                              \
        if (NT_SUCCESS(status)) {                                                   \
            Target-> ## _name ## = ( ## _type ## )strtoul(Value, NULL, _radix);     \
            XENBUS_STORE(Free,                                                      \
                         &Target->StoreInterface,                                   \
                         Value);                                                    \
        }                                                                           \
        if (DriverGetFeatureOverride( ## _name ## , &Override))                     \
            Target-> ## _name ## = ( ## _type ## )Override;                         \
    } while (FALSE);

    READ_FEATURE(BOOLEAN, 2, FeatureRemovable)
    READ_FEATURE(BOOLEAN, 2, FeatureFlushCache)
    READ_FEATURE(BOOLEAN, 2, FeatureBarrier)
    READ_FEATURE(BOOLEAN, 2, FeatureDiscard)
    READ_FEATURE(BOOLEAN, 2, FeatureDiscardEnable)
    READ_FEATURE(BOOLEAN, 2, FeatureDiscardSecure)
    READ_FEATURE(ULONG, 10, FeatureDiscardAlignment)
    READ_FEATURE(ULONG, 10, FeatureDiscardGranularity)
    READ_FEATURE(ULONG, 10, FeatureMaxIndirectSegments)

#undef READ_FEATURE

    Verbose("[%u] %s%s%s\n",
            __TargetGetTargetId(Target),
            __TargetGetFeatureRemovable(Target) ? "REMOVABLE " : "",
            __TargetGetFeatureFlushCache(Target) ? "FLUSH " : "",
            __TargetGetFeatureBarrier(Target) ? "BARRIER " : "");
    if (__TargetGetFeatureDiscard(Target))
        Verbose("[%u] DISCARD %u @ %u%s\n",
                __TargetGetTargetId(Target),
                __TargetGetFeatureDiscardGranularity(Target),
                __TargetGetFeatureDiscardAlignment(Target),
                __TargetGetFeatureDiscardSecure(Target) ? " SECURE" : "");
    if (__TargetGetFeatureMaxIndirectSegments(Target) > BLKIF_MAX_SEGMENTS_PER_REQUEST)
        Verbose("[%u] INDIRECT %u\n",
                __TargetGetTargetId(Target),
                __TargetGetFeatureMaxIndirectSegments(Target));

    return STATUS_SUCCESS;
}

static FORCEINLINE VOID
TargetZeroFeatures(
    IN  PXENVBD_TARGET  Target
    )
{
    Target->FeatureRemovable = FALSE;
    Target->FeatureFlushCache = FALSE;
    Target->FeatureBarrier = FALSE;
    Target->FeatureDiscard = FALSE;
    Target->FeatureDiscardEnable = FALSE;
    Target->FeatureDiscardSecure = FALSE;
    Target->FeatureDiscardAlignment = 0;
    Target->FeatureDiscardGranularity = 0;
    Target->FeatureMaxIndirectSegments = 0;
}

static FORCEINLINE VOID
TargetReadInquiryOverrides(
    IN  PXENVBD_TARGET  Target
    )
{
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "sm-data/scsi/0x12/0x80",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        (VOID) Base64Decode(Buffer,
                            &Target->Page80,
                            &Target->Page80Length);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "sm-data/scsi/0x12/0x83",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        (VOID) Base64Decode(Buffer,
                            &Target->Page83,
                            &Target->Page83Length);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }
}

static FORCEINLINE VOID
TargetZeroInquiryOverrides(
    IN  PXENVBD_TARGET  Target
    )
{
    Base64Free(Target->Page80);
    Target->Page80 = NULL;
    Target->Page80Length = 0;

    Base64Free(Target->Page83);
    Target->Page83 = NULL;
    Target->Page83Length = 0;
}

static FORCEINLINE VOID
TargetReadVdiUuid(
    IN  PXENVBD_TARGET  Target
    )
{
    PCHAR               Buffer;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "sm-data/vdi-uuid",
                          &Buffer);
    if (NT_SUCCESS(status)) {
        (VOID) RtlStringCchPrintfA(Target->VdiUuid,
                                   GUID_LENGTH,
                                   "%s",
                                   Buffer);

        Trace("VdiUuid = %s\n", Target->VdiUuid);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Buffer);
    }
}

static FORCEINLINE VOID
TargetZeroVdiUuid(
    IN  PXENVBD_TARGET  Target
    )
{
    RtlZeroMemory(Target->VdiUuid, sizeof(Target->VdiUuid));
}

static FORCEINLINE NTSTATUS
__TargetWriteTarget(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetTargetPath(Target),
                          "paging",
                          "%u",
                          Target->Usage[DeviceUsageTypePaging] ? 1 : 0);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetTargetPath(Target),
                          "hibernation",
                          "%u",
                          Target->Usage[DeviceUsageTypeHibernation] ? 1 : 0);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetTargetPath(Target),
                          "dump",
                          "%u",
                          Target->Usage[DeviceUsageTypeDumpFile] ? 1 : 0);
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetTargetPath(Target),
                          "frontend",
                          "%s",
                          __TargetGetPath(Target));
    if (!NT_SUCCESS(status))
        return status;

    status = XENBUS_STORE(Printf,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetTargetPath(Target),
                          "device",
                          "%u",
                          __TargetGetDeviceId(Target));
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

static FORCEINLINE NTSTATUS
__TargetReadBackend(
    IN  PXENVBD_TARGET  Target
    )
{
    PCHAR               Value;
    ULONG               Length;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetPath(Target),
                          "backend-id",
                          &Value);
    if (NT_SUCCESS(status)) {
        Target->BackendId = (USHORT)strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    } else {
        Target->BackendId = 0;
    }

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetPath(Target),
                          "backend",
                          &Value);
    if (!NT_SUCCESS(status))
        goto fail1;

    Length = (ULONG)strlen(Value);

    __TargetFree(Target->BackendPath);

    status = STATUS_NO_MEMORY;
    Target->BackendPath = __TargetAllocate(Length + 1);
    if (Target->BackendPath == NULL)
        goto fail2;

    RtlCopyMemory(Target->BackendPath,
                  Value,
                  Length);

    XENBUS_STORE(Free,
                 &Target->StoreInterface,
                 Value);

    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_STORE(Free,
                 &Target->StoreInterface,
                 Value);

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static FORCEINLINE NTSTATUS
__TargetSetState(
    IN  PXENVBD_TARGET  Target,
    IN  XenbusState     State
    )
{
    return XENBUS_STORE(Printf,
                        &Target->StoreInterface,
                        NULL,
                        __TargetGetPath(Target),
                        "state",
                        "%u",
                        (ULONG)State);
}

static FORCEINLINE NTSTATUS
__TargetWaitState(
    IN  PXENVBD_TARGET  Target,
    OUT XenbusState     *State
    )
{
    XenbusState         OldState = *State;
    PXENBUS_STORE_WATCH Watch;
    KEVENT              Event;
    LARGE_INTEGER       Timeout;
    PCHAR               Value;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "state",
                          &Value);
    if (NT_SUCCESS(status)) {
        *State = (XenbusState)strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);

        if (OldState != *State)
            goto done;
    }

    KeInitializeEvent(&Event, NotificationEvent, FALSE);
    Timeout.QuadPart = 0;

    status = XENBUS_STORE(WatchAdd,
                          &Target->StoreInterface,
                          __TargetGetBackendPath(Target),
                          "state",
                          &Event,
                          &Watch);
    if (!NT_SUCCESS(status))
        goto fail1;

    while (OldState == *State) {
        if (KeWaitForSingleObject(&Event,
                                  Executive,
                                  KernelMode,
                                  FALSE,
                                  &Timeout) == STATUS_TIMEOUT) {
            XENBUS_STORE(Poll,
                         &Target->StoreInterface);
            continue;
        }

        status = XENBUS_STORE(Read,
                              &Target->StoreInterface,
                              NULL,
                              __TargetGetBackendPath(Target),
                              "state",
                              &Value);
        if (!NT_SUCCESS(status))
            goto fail2;

        *State = (XenbusState)strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    }

    XENBUS_STORE(WatchRemove,
                 &Target->StoreInterface,
                 Watch);

done:
    return STATUS_SUCCESS;

fail2:
    Error("fail2\n");

    XENBUS_STORE(WatchRemove,
                 &Target->StoreInterface,
                 Watch);

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
TargetClose(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    if (Target->BackendWatch)
        XENBUS_STORE(WatchRemove,
                     &Target->StoreInterface,
                     Target->BackendWatch);
    Target->BackendWatch = NULL;

    status = __TargetReadBackend(Target);
    if (!NT_SUCCESS(status))
        goto fail1;

    State = XenbusStateUnknown;
    do {
        status = __TargetWaitState(Target, &State);
        if (!NT_SUCCESS(status))
            goto fail2;
    } while (State == XenbusStateInitialising);

    while (State != XenbusStateClosing &&
           State != XenbusStateClosed) {
        status = __TargetSetState(Target, XenbusStateClosing);
        if (!NT_SUCCESS(status))
            goto fail3;

        status = __TargetWaitState(Target, &State);
        if (!NT_SUCCESS(status))
            goto fail4;
    }

    while (State != XenbusStateClosed) {
        status = __TargetSetState(Target, XenbusStateClosed);
        if (!NT_SUCCESS(status))
            goto fail5;

        status = __TargetWaitState(Target, &State);
        if (!NT_SUCCESS(status))
            goto fail6;
    }

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;

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
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
TargetPrepare(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    status = __TargetReadBackend(Target);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_STORE(WatchAdd,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          ThreadGetEvent(Target->BackendThread),
                          &Target->BackendWatch);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = __TargetWriteTarget(Target);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = __TargetSetState(Target, XenbusStateInitialising);
    if (!NT_SUCCESS(status))
        goto fail4;

    State = XenbusStateUnknown;
    do {
        status = __TargetWaitState(Target, &State);
        if (!NT_SUCCESS(status))
            goto fail5;
    } while (State == XenbusStateClosed ||
             State == XenbusStateInitialising);

    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateInitWait)
        goto fail6;

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;

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
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
TargetConnect(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    NTSTATUS            status;

    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    status = RingConnect(Target->Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    for (;;) {
        PXENBUS_STORE_TRANSACTION   Transaction;

        status = XENBUS_STORE(TransactionStart,
                              &Target->StoreInterface,
                              &Transaction);
        if (!NT_SUCCESS(status))
            break;

        status = RingStoreWrite(Target->Ring, Transaction);
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(Printf,
                              &Target->StoreInterface,
                              Transaction,
                              __TargetGetPath(Target),
                              "target-id",
                              "%u",
                              __TargetGetTargetId(Target));
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(Printf,
                              &Target->StoreInterface,
                              Transaction,
                              __TargetGetPath(Target),
                              "feature-surprise-remove",
                              "%u",
                              1);
        if (!NT_SUCCESS(status))
            goto abort;

        status = XENBUS_STORE(Printf,
                              &Target->StoreInterface,
                              Transaction,
                              __TargetGetPath(Target),
                              "feature-online-resize",
                              "%u",
                              1);
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
        goto fail2;

    status = __TargetSetState(Target, XenbusStateInitialised);
    if (!NT_SUCCESS(status))
        goto fail3;

    State = XenbusStateUnknown;
    do {
        status = __TargetWaitState(Target, &State);
        if (!NT_SUCCESS(status))
            goto fail4;
    } while (State == XenbusStateInitWait ||
             State == XenbusStateInitialising ||
             State == XenbusStateInitialised);
    status = STATUS_UNSUCCESSFUL;
    if (State != XenbusStateConnected)
        goto fail5;

    status = TargetReadParameters(Target);
    if (!NT_SUCCESS(status))
        goto fail6;

    status = TargetReadFeatures(Target);
    if (!NT_SUCCESS(status))
        goto fail7;

    TargetReadInquiryOverrides(Target);
    TargetReadVdiUuid(Target);

    status = __TargetSetState(Target, XenbusStateConnected);
    if (!NT_SUCCESS(status))
        goto fail8;

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;

fail8:
    Error("fail8\n");
    TargetZeroVdiUuid(Target);
    TargetZeroInquiryOverrides(Target);
    TargetZeroFeatures(Target);
fail7:
    Error("fail7\n");
fail6:
    Error("fail6\n");
    TargetZeroParameters(Target);
fail5:
    Error("fail5\n");
fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
    RingDisconnect(Target->Ring);
fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE NTSTATUS
TargetEnable(
    IN  PXENVBD_TARGET  Target
    )
{
    NTSTATUS            status;

    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    status = RingEnable(Target->Ring);
    if (!NT_SUCCESS(status))
        goto fail1;

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;

fail1:
    Error("fail1 %08x\n", status);
    return status;
}

static DECLSPEC_NOINLINE VOID
TargetDisable(
    IN  PXENVBD_TARGET  Target
    )
{
    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    RingDisable(Target->Ring);

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));
}

static DECLSPEC_NOINLINE VOID
TargetDisconnect(
    IN  PXENVBD_TARGET  Target
    )
{
    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    TargetZeroVdiUuid(Target);
    TargetZeroInquiryOverrides(Target);
    TargetZeroFeatures(Target);
    TargetZeroParameters(Target);

    RingDisconnect(Target->Ring);

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));
}

static const PCHAR
__XenvbdStateName(
    IN  XENVBD_STATE    State
    )
{
    switch (State) {
    case XENVBD_STATE_INVALID:  return "STATE_INVALID";
    case XENVBD_INITIALIZED:    return "INITIALIZED";
    case XENVBD_CLOSING:        return "CLOSING";
    case XENVBD_CLOSED:         return "CLOSED";
    case XENVBD_PREPARED:       return "PREPARED";
    case XENVBD_CONNECTED:      return "CONNECTED";
    case XENVBD_ENABLED:        return "ENABLED";
    default:                    return "UNKNOWN";
    }
}

static DECLSPEC_NOINLINE NTSTATUS
TargetSetState(
    IN  PXENVBD_TARGET  Target,
    IN  XENVBD_STATE    State
    )
{
    NTSTATUS            status;

    ASSERT3U(KeGetCurrentIrql(), ==, DISPATCH_LEVEL);

    Verbose("[%u] =====> %s -> %s\n",
            __TargetGetTargetId(Target),
            __XenvbdStateName(Target->State),
            __XenvbdStateName(State));

    status = STATUS_SUCCESS;
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
                if (NT_SUCCESS(status)) {
                    Target->State = XENVBD_CLOSED;
                } else {
                    Target->State = XENVBD_STATE_INVALID;
                }
                break;
            default:
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            break;

        case XENVBD_CLOSED:
            switch (State) {
            case XENVBD_INITIALIZED:
                Target->State = XENVBD_INITIALIZED;
                break;
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                status = TargetPrepare(Target);
                if (NT_SUCCESS(status)) {
                    Target->State = XENVBD_PREPARED;
                } else {
                    (VOID) TargetClose(Target);
                    Target->State = XENVBD_STATE_INVALID;
                }
                break;
            default:
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            break;

        case XENVBD_PREPARED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
                status = TargetClose(Target);
                if (NT_SUCCESS(status))
                    Target->State = XENVBD_CLOSED;
                break;
            case XENVBD_CONNECTED:
            case XENVBD_ENABLED:
                status = TargetConnect(Target);
                if (NT_SUCCESS(status)) {
                    Target->State = XENVBD_CONNECTED;
                } else {
                    (VOID) TargetClose(Target);
                    Target->State = XENVBD_STATE_INVALID;
                }
                break;
            default:
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            break;

        case XENVBD_CONNECTED:
            switch (State) {
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
                status = TargetClose(Target);
                if (NT_SUCCESS(status))
                    Target->State = XENVBD_CLOSING;
                else
                    Target->State = XENVBD_STATE_INVALID;
                break;
            case XENVBD_ENABLED:
                status = TargetEnable(Target);
                if (NT_SUCCESS(status))
                    Target->State = XENVBD_ENABLED;
                else
                    Target->State = XENVBD_STATE_INVALID;
                break;
            default:
                status = STATUS_NOT_SUPPORTED;
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
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            break;

        case XENVBD_ENABLED:
            switch (State) {
            case XENVBD_CLOSING:
            case XENVBD_CLOSED:
            case XENVBD_PREPARED:
            case XENVBD_CONNECTED:
                TargetDisable(Target);
                Target->State = XENVBD_CONNECTED;
                break;
            default:
                status = STATUS_NOT_SUPPORTED;
                break;
            }
            break;

        default:
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        Trace("[%u] in state %s\n",
              __TargetGetTargetId(Target),
              __XenvbdStateName(Target->State));
    }

    Verbose("[%u] <===== %s\n",
            __TargetGetTargetId(Target),
            __XenvbdStateName(Target->State));

    return status;
}

static DECLSPEC_NOINLINE VOID
TargetDebugCallback(
    IN  PVOID       Argument,
    IN  BOOLEAN     Crashing
    )
{
    PXENVBD_TARGET  Target = Argument;

    UNREFERENCED_PARAMETER(Crashing);

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TargetId: %u\n",
                 __TargetGetTargetId(Target));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "DeviceId: %u\n",
                 __TargetGetDeviceId(Target));

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Path: %s\n",
                 __TargetGetPath(Target));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "TargetPath: %s\n",
                 __TargetGetTargetPath(Target));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "BackendPath: %s (%u)\n",
                 __TargetGetBackendPath(Target),
                 __TargetGetBackendId(Target));

    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Disk: %llu of %u (%u)\n",
                 __TargetGetSectorCount(Target),
                 __TargetGetSectorSize(Target),
                 __TargetGetPhysicalSectorSize(Target));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Features: \n",
                 __TargetGetFeatureFlushCache(Target) ? "FLUSH " : "",
                 __TargetGetFeatureBarrier(Target) ? "BARRIER " : "",
                 __TargetGetFeatureDiscard(Target) ? "DISCARD " : "",
                 __TargetGetFeatureMaxIndirectSegments(Target) > BLKIF_MAX_SEGMENTS_PER_REQUEST ? "INDIRECT " : "");
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "State: %s\n",
                 __XenvbdStateName(Target->State));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "Adapter: 0x%p\n",
                 Target->Adapter);
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "DeviceObject: 0x%p %s\n",
                 Target->DeviceObject,
                 Target->Missing ? Target->Reason : "");
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "DevicePnpState: %s (%s)\n",
                 __PnpStateName(Target->DevicePnpState),
                 __PnpStateName(Target->PrevPnpState));
    XENBUS_DEBUG(Printf,
                 &Target->DebugInterface,
                 "DevicePowerState: %s\n",
                 PowerDeviceStateName(Target->DevicePowerState));
}

static DECLSPEC_NOINLINE VOID
TargetSuspendCallback(
    IN  PVOID       Argument
    )
{
    PXENVBD_TARGET  Target = Argument;
    NTSTATUS        status;

    Verbose("[%u] %s (%s)\n",
            TargetGetTargetId(Target),
            Target->Missing ? "MISSING" : "NOT_MISSING",
            Target->Reason);
    Target->Missing = FALSE;
    Target->Reason = NULL;

    status = TargetSetState(Target, XENVBD_CLOSED);
    ASSERT(NT_SUCCESS(status));

    status = TargetSetState(Target, XENVBD_ENABLED);
    ASSERT(NT_SUCCESS(status));
}

static FORCEINLINE VOID
__TargetCheckForEject(
    IN  PXENVBD_TARGET  Target
    )
{
    XenbusState         State;
    BOOLEAN             Online;
    PCHAR               Value;
    NTSTATUS            status;

    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "state",
                          &Value);
    if (NT_SUCCESS(status)) {
        State = (XenbusState)strtoul(Value, NULL, 10);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    } else {
        State = XenbusStateUnknown;
    }
    status = XENBUS_STORE(Read,
                          &Target->StoreInterface,
                          NULL,
                          __TargetGetBackendPath(Target),
                          "online",
                          &Value);
    if (NT_SUCCESS(status)) {
        Online = (BOOLEAN)strtoul(Value, NULL, 2);

        XENBUS_STORE(Free,
                     &Target->StoreInterface,
                     Value);
    } else {
        Online = TRUE;
    }

    if (!Online && State == XenbusStateClosing) {
        TargetIssueDeviceEject(Target, "online = false");
    }
}

static DECLSPEC_NOINLINE NTSTATUS
TargetBackendThread(
    IN  PXENVBD_THREAD  Self,
    IN  PVOID           Context
    )
{
    PXENVBD_TARGET      Target = Context;
    PKEVENT             Event;
    
    Trace("[%u] =====>\n", __TargetGetTargetId(Target));

    Event = ThreadGetEvent(Self);

    for (;;) {
        KIRQL           Irql;

        (VOID) KeWaitForSingleObject(Event,
                                     KernelMode,
                                     Executive,
                                     FALSE,
                                     NULL);
        KeClearEvent(Event);

        if (ThreadIsAlerted(Self))
            break;

        KeAcquireSpinLock(&Target->Lock, &Irql);
        if (Target->State != XENVBD_ENABLED)
            goto loop;

        __TargetCheckForEject(Target);
        (VOID) TargetReadParameters(Target);

loop:
        KeReleaseSpinLock(&Target->Lock, Irql);

    }

    Trace("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;
}

NTSTATUS
TargetD3ToD0(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;
    NTSTATUS            status;

    if (!TargetSetDevicePowerState(Target, PowerDeviceD0))
        return STATUS_SUCCESS;

    Verbose("[%u] =====>\n", __TargetGetTargetId(Target));

    AdapterGetStoreInterface(__TargetGetAdapter(Target),
                             &Target->StoreInterface);
    AdapterGetDebugInterface(__TargetGetAdapter(Target),
                             &Target->DebugInterface);
    AdapterGetSuspendInterface(__TargetGetAdapter(Target),
                               &Target->SuspendInterface);

    status = XENBUS_STORE(Acquire, &Target->StoreInterface);
    if (!NT_SUCCESS(status))
        goto fail1;

    status = XENBUS_DEBUG(Acquire, &Target->DebugInterface);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = XENBUS_DEBUG(Register,
                          &Target->DebugInterface,
                          __MODULE__ "|TARGET",
                          TargetDebugCallback,
                          Target,
                          &Target->DebugCallback);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = XENBUS_SUSPEND(Acquire, &Target->SuspendInterface);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = XENBUS_SUSPEND(Register,
                            &Target->SuspendInterface,
                            SUSPEND_CALLBACK_LATE,
                            TargetSuspendCallback,
                            Target,
                            &Target->SuspendCallback);
    if (!NT_SUCCESS(status))
        goto fail5;

    KeAcquireSpinLock(&Target->Lock, &Irql);
    status = TargetSetState(Target, XENVBD_ENABLED);
    KeReleaseSpinLock(&Target->Lock, Irql);

    if (!NT_SUCCESS(status))
        goto fail6;

    Verbose("[%u] <=====\n", __TargetGetTargetId(Target));

    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

    XENBUS_SUSPEND(Deregister,
                   &Target->SuspendInterface,
                   Target->SuspendCallback);
    Target->SuspendCallback = NULL;

fail5:
    Error("fail5\n");
    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);

fail4:
    Error("fail4\n");
    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

fail3:
    Error("fail3\n");
    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

fail2:
    Error("fail2\n");
    XENBUS_STORE(Release,
                 &Target->StoreInterface);
fail1:
    Error("1ail1 (%08x)\n", status);

    RtlZeroMemory(&Target->SuspendInterface,
                  sizeof(XENBUS_SUSPEND_INTERFACE));
    RtlZeroMemory(&Target->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Target->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));
    Target->DevicePowerState = PowerDeviceD3;

    return status;
}

VOID
TargetD0ToD3(
    IN  PXENVBD_TARGET  Target
    )
{
    KIRQL               Irql;

    if (!TargetSetDevicePowerState(Target, PowerDeviceD3))
        return;

    Verbose("[%u] =====>\n", __TargetGetTargetId(Target));

    KeAcquireSpinLock(&Target->Lock, &Irql);
    (VOID) TargetSetState(Target, XENVBD_CLOSED);
    KeReleaseSpinLock(&Target->Lock, Irql);

    // ensure backend path is freed
    __TargetFree(Target->BackendPath);
    Target->BackendPath = NULL;

    XENBUS_SUSPEND(Deregister,
                   &Target->SuspendInterface,
                   Target->SuspendCallback);
    Target->SuspendCallback = NULL;

    XENBUS_SUSPEND(Release,
                   &Target->SuspendInterface);

    XENBUS_DEBUG(Deregister,
                 &Target->DebugInterface,
                 Target->DebugCallback);
    Target->DebugCallback = NULL;

    XENBUS_DEBUG(Release,
                 &Target->DebugInterface);

    XENBUS_STORE(Release,
                 &Target->StoreInterface);

    RtlZeroMemory(&Target->SuspendInterface,
                  sizeof(XENBUS_SUSPEND_INTERFACE));
    RtlZeroMemory(&Target->DebugInterface,
                  sizeof(XENBUS_DEBUG_INTERFACE));
    RtlZeroMemory(&Target->StoreInterface,
                  sizeof(XENBUS_STORE_INTERFACE));

    Verbose("[%u] <=====\n", __TargetGetTargetId(Target));
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
    IN  PCHAR           Device,
    OUT PXENVBD_TARGET* _Target
    )
{
    NTSTATUS            status;
    PXENVBD_TARGET      Target;
    ULONG               TargetId;
    ULONG               DeviceId;

    DeviceId = strtoul(Device, NULL, 10);
    TargetId = __ParseVbd(DeviceId);
    if (TargetId >= XENVBD_MAX_TARGETS)
        return STATUS_RETRY;

    if (AdapterIsTargetEmulated(Adapter, TargetId))
        return STATUS_RETRY;

    status = STATUS_INSUFFICIENT_RESOURCES;
#pragma warning(suppress: 6014)
    Target = __TargetAllocate(sizeof(XENVBD_TARGET));
    if (Target == NULL)
        goto fail1;

    Verbose("Target[%d] : Creating\n", TargetId);
    Target->Adapter = Adapter;
    Target->DeviceObject = NULL; // filled in later
    Target->DevicePnpState = Present;
    Target->DevicePowerState = PowerDeviceD3;
    Target->TargetId = TargetId;
    Target->DeviceId = DeviceId;
    Target->State = XENVBD_INITIALIZED;
    Target->BackendId = DOMID_INVALID;
    KeInitializeSpinLock(&Target->Lock);
    KeInitializeSpinLock(&Target->ShutdownLock);
    InitializeListHead(&Target->ShutdownSrbs);

    status = RtlStringCbPrintfA(Target->Path,
                                sizeof(Target->Path),
                                "device/vbd/%u",
                                DeviceId);
    if (!NT_SUCCESS(status))
        goto fail2;

    status = RtlStringCbPrintfA(Target->TargetPath,
                                sizeof(Target->TargetPath),
                                "data/scsi/target/%u",
                                TargetId);
    if (!NT_SUCCESS(status))
        goto fail3;

    status = RingCreate(Target, &Target->Ring);
    if (!NT_SUCCESS(status))
        goto fail4;

    status = ThreadCreate(TargetBackendThread,
                          Target,
                          &Target->BackendThread);
    if (!NT_SUCCESS(status))
        goto fail5;

    status = TargetD3ToD0(Target);
    if (!NT_SUCCESS(status))
        goto fail6;

    *_Target = Target;

    Verbose("Target[%d] : Created\n", TargetId);
    return STATUS_SUCCESS;

fail6:
    Error("fail6\n");

    ThreadAlert(Target->BackendThread);
    ThreadJoin(Target->BackendThread);
    Target->BackendThread = NULL;

fail5:
    Error("fail5\n");

    RingDestroy(Target->Ring);
    Target->Ring = NULL;

fail4:
    Error("fail4\n");

    RtlZeroMemory(Target->TargetPath, sizeof(Target->TargetPath));

fail3:
    Error("fail3\n");

    RtlZeroMemory(Target->Path, sizeof(Target->Path));

fail2:
    Error("fail2\n");

    Target->Adapter = NULL;
    Target->DeviceObject = NULL;
    Target->DevicePnpState = 0;
    Target->DevicePowerState = 0;
    Target->TargetId = 0;
    Target->DeviceId = 0;
    Target->State = 0;
    Target->BackendId = 0;
    RtlZeroMemory(&Target->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->ShutdownLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->ShutdownSrbs, sizeof(LIST_ENTRY));

    ASSERT(IsZeroMemory(Target, sizeof(XENVBD_TARGET)));
    __TargetFree(Target);

fail1:
    Error("Fail1 (%08x)\n", status);
    return status;
}

VOID
TargetDestroy(
    IN  PXENVBD_TARGET  Target
    )
{
    const ULONG         TargetId = __TargetGetTargetId(Target);

    Verbose("Target[%d] : Destroying\n", TargetId);

    TargetD0ToD3(Target);

    ASSERT3U(TargetGetDevicePnpState(Target), ==, Deleted);

    ThreadAlert(Target->BackendThread);
    ThreadJoin(Target->BackendThread);
    Target->BackendThread = NULL;

    RingDestroy(Target->Ring);
    Target->Ring = NULL;

    RtlZeroMemory(Target->TargetPath, sizeof(Target->TargetPath));

    RtlZeroMemory(Target->Path, sizeof(Target->Path));

    Target->Adapter = NULL;
    Target->DeviceObject = NULL;
    Target->DevicePnpState = 0;
    Target->DevicePowerState = 0;
    Target->TargetId = 0;
    Target->DeviceId = 0;
    Target->State = 0;
    Target->BackendId = 0;
    RtlZeroMemory(&Target->Lock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->ShutdownLock, sizeof(KSPIN_LOCK));
    RtlZeroMemory(&Target->ShutdownSrbs, sizeof(LIST_ENTRY));

    ASSERT(IsZeroMemory(Target, sizeof(XENVBD_TARGET)));
    __TargetFree(Target);

    Verbose("Target[%d] : Destroyed\n", TargetId);
}
