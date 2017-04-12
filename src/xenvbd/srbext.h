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

#ifndef _XENVBD_SRBEXT_H
#define _XENVBD_SRBEXT_H

#include <ntddk.h>
#include <xenvbd-storport.h>
#include <xen.h>
#include "assert.h"

typedef struct _XENVBD_SRBEXT {
    PSCSI_REQUEST_BLOCK     Srb;
    LIST_ENTRY              ListEntry;
    LONG                    RequestCount;
    // ScatterGather
    PVOID                   SGList;
    ULONG                   SGIndex;
    ULONG                   SGOffset;
} XENVBD_SRBEXT, *PXENVBD_SRBEXT;

typedef struct _XENVBD_REQUEST {
    PXENVBD_SRBEXT          SrbExt;
    LIST_ENTRY              ListEntry;
    ULONG64                 Id; // = (ULONG64)(ULONG_PTR)this

    UCHAR                   Operation;  // BLKIF_OP_{READ/WRITE/BARRIER/DISCARD}
    UCHAR                   Flags;      // BLKIF_OP_DISCARD only
    USHORT                  NrSegments; // BLKIF_OP_{READ/WRITE} only, 0-11 (direct) or 11-4096 (indirect)
    LIST_ENTRY              Segments;   // BLKIF_OP_{READ/WRITE} only

    ULONG64                 FirstSector;
    ULONG64                 NrSectors;  // BLKIF_OP_DISCARD only
    LIST_ENTRY              Indirects;  // BLKIF_OP_{READ/WRITE} with NrSegments > 11 only
} XENVBD_REQUEST, *PXENVBD_REQUEST;

#pragma pack(push, 1)
typedef struct _BLKIF_SEGMENT {
    ULONG                   GrantRef;
    UCHAR                   First;
    UCHAR                   Last;
    USHORT                  __Padding;
} BLKIF_SEGMENT, *PBLKIF_SEGMENT;
#pragma pack(pop)

#define XENVBD_MAX_SEGMENTS_PER_PAGE        (PAGE_SIZE / sizeof(BLKIF_SEGMENT))
#define XENVBD_MAX_SEGMENTS_PER_INDIRECT    (XENVBD_MAX_SEGMENTS_PER_PAGE * 2) // limited Indirecting

typedef struct _XENVBD_INDIRECT {
    LIST_ENTRY              ListEntry;
    PBLKIF_SEGMENT          Page;
    PVOID                   Grant;
    PMDL                    Mdl;
} XENVBD_INDIRECT, *PXENVBD_INDIRECT;

typedef struct _XENVBD_SEGMENT {
    LIST_ENTRY              ListEntry;
    PVOID                   Grant;
    UCHAR                   FirstSector;
    UCHAR                   LastSector;
    ULONG                   Length;
    PVOID                   BufferId;
    PVOID                   Buffer; // VirtAddr mapped to PhysAddr(s)
    MDL                     Mdl;
    PFN_NUMBER              Pfn[2];
} XENVBD_SEGMENT, *PXENVBD_SEGMENT;

#endif // _XENVBD_SRBEXT_H
