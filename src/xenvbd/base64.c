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

#include "base64.h"

#include "debug.h"
#include "assert.h"
#include "util.h"

#define BASE64_POOL_TAG            '46BX'

static FORCEINLINE PVOID
__Base64Allocate(
    IN  ULONG   Size
    )
{
    PVOID       Buffer;

    Buffer = ExAllocatePoolWithTag(NonPagedPool,
                                   Size,
                                   BASE64_POOL_TAG);
    if (Buffer)
        RtlZeroMemory(Buffer, Size);

    return Buffer;
}

VOID
Base64Free(
    IN  PVOID   Buffer
    )
{
    if (Buffer == NULL)
        return;
    ExFreePoolWithTag(Buffer, BASE64_POOL_TAG);
}

static FORCEINLINE UCHAR
__Base64DecodeChar(
    IN  CHAR        Char
    )
{
    if (Char >= 'A' && Char <= 'Z') return Char - 'A';
    if (Char >= 'a' && Char <= 'z') return Char - 'a' + 26;
    if (Char >= '0' && Char <= '9') return Char - '0' + 52;
    if (Char == '+')                return 62;
    if (Char == '/')                return 63;
    if (Char == '=')                return 0;
    return 0xFF; // failure code
}

static FORCEINLINE UCHAR
__Base64Decode(
    IN  PUCHAR      Dst,
    IN  PCHAR       Src,
    IN  ULONG       Left
    )
{
    UCHAR           Values[4];

    if (Left < 4)
        goto fail1;
    if (Src[0] == '=' || Src[1] == '=')
        goto fail2;
    if (Src[2] == '=' && Src[3] != '=')
        goto fail3;

    Values[0] = __Base64DecodeChar(Src[0]);
    Values[1] = __Base64DecodeChar(Src[1]);
    Values[2] = __Base64DecodeChar(Src[2]);
    Values[3] = __Base64DecodeChar(Src[3]);

    if (Values[0] == 0xFF || Values[1] == 0xFF ||
        Values[2] == 0xFF || Values[3] == 0xFF)
        goto fail4;

    Dst[0] = (Values[1] >> 4) | (Values[0] << 2);
    if (Src[2] == '=')
        return 2;
    Dst[1] = (Values[2] >> 2) | (Values[1] << 4);
    if (Src[3] == '=')
        return 1;
    Dst[2] = (Values[3]     ) | (Values[2] << 6);
    return 0;

fail4:
    Error("fail4\n");
fail3:
    Error("fail3\n");
fail2:
    Error("fail2\n");
fail1:
    Error("fail1\n");
    return 0xFF; // failure code
}

NTSTATUS
Base64Decode(
    IN  PCHAR       Input,
    OUT PVOID       *Output,
    OUT PULONG      OutputLength
    )
{
    ULONG           InputLength;
    ULONG           Blocks;
    ULONG           Index;
    UCHAR           Pad = 0;
    NTSTATUS        status;

    Trace("=====> \"%s\"\n", Input);

    InputLength = (ULONG)strlen(Input);
    Blocks = InputLength / 4;

    status = STATUS_NO_MEMORY;
    *Output = __Base64Allocate(Blocks * 3);
    if (*Output == NULL)
        goto fail1;

    status = STATUS_INVALID_PARAMETER;
    for (Index = 0; Index < Blocks; ++Index) {
        if (Pad)
            goto fail2;
        Pad = __Base64Decode((PUCHAR)*Output + (Index * 3),
                             Input + (Index * 4),
                             InputLength - (Index * 4));
        if (Pad > 2)
            goto fail3;
    }

    *OutputLength = (Blocks * 3) - Pad;

    Trace("<=====\n");

    return STATUS_SUCCESS;

fail3:
    Error("fail3\n");

fail2:
    Error("fail2\n");

    *OutputLength = 0;

    Base64Free(*Output);
    *Output = NULL;

fail1:
    Error("fail1 %08x\n", status);

    return status;
}

