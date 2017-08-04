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

#ifndef _XENVBD_RING_H
#define _XENVBD_RING_H

#include <ntddk.h>

typedef struct _XENVBD_RING XENVBD_RING, *PXENVBD_RING;

#include "target.h"
#include "srbext.h"

extern NTSTATUS
RingCreate(
    IN  PXENVBD_TARGET  Target,
    OUT PXENVBD_RING    *Ring
    );

extern VOID
RingDestroy(
    IN  PXENVBD_RING    Ring
    );

extern NTSTATUS
RingConnect(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingDisconnect(
    IN  PXENVBD_RING    Ring
    );

extern NTSTATUS
RingEnable(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingDisable(
    IN  PXENVBD_RING    Ring
    );

extern NTSTATUS
RingStoreWrite(
    IN  PXENVBD_RING    Ring,
    IN  PVOID           Transaction
    );

extern VOID
RingQueue(
    IN  PXENVBD_RING    Ring,
    IN  PXENVBD_SRBEXT  SrbExt
    );

extern VOID
RingNotify(
    IN  PXENVBD_RING    Ring
    );

extern VOID
RingReset(
    IN  PXENVBD_RING    Ring
    );

#endif // _XENVBD_RING_H
