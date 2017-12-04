// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#ifndef _MEM_H
#define _MEM_H

#include <ntddk.h>

#define P_PRESENT        0x01
#define P_WRITABLE	 0x02
#define P_USERMODE	 0x04
#define P_WRITETHROUGH	 0x08
#define P_CACHE_DISABLED 0x10
#define P_ACCESSED	 0x20
#define P_DIRTY		 0x40
#define P_LARGE		 0x80
#define P_GLOBAL	 0x100

//#define PML4_BASE 0xfffff6fb7dbed000ULL
//#define PDP_BASE 0xfffff6fb7da00000ULL
//#define PD_BASE 0xfffff6fb40000000ULL
//#define PT_BASE 0xfffff68000000000ULL

#define VIRTDBG_POOLTAG 0xbad0bad0

PVOID AllocateMemory(ULONG32 Size);
VOID UnAllocateMemory(PVOID pMem);
PVOID AllocateContiguousMemory(ULONG size);
NTSTATUS IsPagePresent(ULONG64 PageVA);
PVOID NTAPI MmAllocatePages(
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA
	);
PVOID NTAPI MmAllocateContiguousPages(//分配的范围内连续的，非分页物理存储器，并将其映射到系统地址空间。
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA
	);
PVOID NTAPI MmAllocateContiguousPagesSpecifyCache(//分配的范围内连续的，非分页物理存储器，并将其映射到系统地址空间。
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA,
	ULONG CacheType
	);

#endif
