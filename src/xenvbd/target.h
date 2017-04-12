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

#ifndef _XENVBD_TARGET_H
#define _XENVBD_TARGET_H

#include <ntddk.h>

typedef struct _XENVBD_TARGET XENVBD_TARGET, *PXENVBD_TARGET;

#include "types.h"
#include "srbext.h"
#include "adapter.h"
#include "granter.h"

#define TARGET_GET_PROPERTY(_name, _type)       \
extern _type                                    \
TargetGet ## _name ## (                         \
    IN  PXENVBD_TARGET  Target                  \
    );

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

extern VOID
TargetSetDevicePnpState(
    IN  PXENVBD_TARGET      Target,
    IN  DEVICE_PNP_STATE    State
    );

extern VOID
TargetSetDeviceObject(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject
    );

extern VOID
TargetSetMissing(
    IN  PXENVBD_TARGET  Target,
    IN  const CHAR*     Reason
    );

extern NTSTATUS
TargetCreate(
    IN  PXENVBD_ADAPTER Adapter,
    IN  PANSI_STRING    Device,
    OUT PXENVBD_TARGET* _Target
    );

extern VOID
TargetDestroy(
    IN  PXENVBD_TARGET  Target
    );

extern NTSTATUS
TargetD3ToD0(
    IN  PXENVBD_TARGET  Target
    );

extern VOID
TargetD0ToD3(
    IN  PXENVBD_TARGET  Target
    );

extern NTSTATUS
TargetDispatchPnp(
    IN  PXENVBD_TARGET  Target,
    IN  PDEVICE_OBJECT  DeviceObject,
    IN  PIRP            Irp
    );

extern VOID
TargetReset(
    IN  PXENVBD_TARGET  Target
    );

extern VOID
TargetFlush(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
TargetShutdown(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
TargetPrepareSrb(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
TargetStartSrb(
    IN  PXENVBD_TARGET  Target,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
TargetSubmitRequests(
    IN  PXENVBD_TARGET  Target
    );

extern VOID
TargetCompleteResponse(
    IN  PXENVBD_TARGET  Target,
    IN  ULONG64         Id,
    IN  SHORT           Status
    );

#endif // _XENVBD_TARGET_H
