// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


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

#define PML4_BASE 0xfffff6fb7dbed000ULL
#define PDP_BASE 0xfffff6fb7da00000ULL
#define PD_BASE 0xfffff6fb40000000ULL
#define PT_BASE 0xfffff68000000000ULL
#define ITL_TAG 'sxpp'
#define VIRTDBG_POOLTAG 0xbad0bad0
PVOID AllocateMemory(ULONG32 Size)
{
    PVOID pMem = NULL;
    pMem = ExAllocatePoolWithTag(NonPagedPool, Size, VIRTDBG_POOLTAG);
    if (pMem == NULL)
        return NULL;

    RtlZeroMemory(pMem, Size);
    return pMem;
}

VOID UnAllocateMemory(PVOID pMem)
{
    ExFreePoolWithTag(pMem, VIRTDBG_POOLTAG);
}


PVOID AllocateContiguousMemory(ULONG size)
{
    PVOID Address;
    PHYSICAL_ADDRESS l1, l2, l3;

    l1.QuadPart = 0;
    l2.QuadPart = -1;
    l3.QuadPart = 0x200000;
    
    Address = MmAllocateContiguousMemorySpecifyCache(size, l1, l2, l3, MmCached);

    if (Address == NULL)
    {
        return NULL;
    }

    RtlZeroMemory(Address, size);
    return Address;
}

NTSTATUS IsPagePresent(ULONG64 PageVA)
{
    ULONG64 Pml4e, Pdpe, Pde, Pte;

    Pml4e = *(PULONG64)(((PageVA >> 36) & 0xff8) + PML4_BASE);

    if (!(Pml4e & P_PRESENT))
        return STATUS_NO_MEMORY;

    Pdpe = *(PULONG64)(((PageVA >> 27) & 0x1ffff8) + PDP_BASE);

    if (!(Pdpe & P_PRESENT))
        return STATUS_NO_MEMORY;

    Pde = *(PULONG64)(((PageVA >> 18) & 0x3ffffff8) + PD_BASE);

    if (!(Pde & P_PRESENT))
        return STATUS_NO_MEMORY;

    if ((Pde & P_LARGE) == P_LARGE)
        return STATUS_SUCCESS;

    Pte = *(PULONG64)(((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

    if (!(Pte & P_PRESENT))
        return STATUS_NO_MEMORY;

    return STATUS_SUCCESS;

}
PVOID NTAPI MmAllocatePages(
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA
	)
{
	PVOID PageVA;
	//  PHYSICAL_ADDRESS PagePA;

	if (!uNumberOfPages)
		return NULL;

	PageVA = ExAllocatePoolWithTag(NonPagedPool, uNumberOfPages * PAGE_SIZE, ITL_TAG);
	if (!PageVA)
		return NULL;
	RtlZeroMemory(PageVA, uNumberOfPages * PAGE_SIZE);

	if (pFirstPagePA)
		*pFirstPagePA = MmGetPhysicalAddress(PageVA);

	//  DbgPrint("申请的虚拟地址 %p %p\n",PageVA,MmGetVirtualForPhysical(*pFirstPagePA));
	return PageVA;
}

PVOID NTAPI MmAllocateContiguousPagesSpecifyCache(//分配的范围内连续的，非分页物理存储器，并将其映射到系统地址空间。
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA,
	ULONG CacheType
	)
{
	PVOID PageVA;
	PHYSICAL_ADDRESS PagePA, l1, l2, l3;

	if (!uNumberOfPages)
		return NULL;

	l1.QuadPart = 0;
	l2.QuadPart = -1;
	l3.QuadPart = 0x20000;

	PageVA = MmAllocateContiguousMemorySpecifyCache(uNumberOfPages * PAGE_SIZE, l1, l2, l3, CacheType);
	if (!PageVA)
		return NULL;

	RtlZeroMemory(PageVA, uNumberOfPages * PAGE_SIZE);

	PagePA = MmGetPhysicalAddress(PageVA);
	if (pFirstPagePA)
		*pFirstPagePA = PagePA;

	return PageVA;
}
PVOID NTAPI MmAllocateContiguousPages(//分配的范围内连续的，非分页物理存储器，并将其映射到系统地址空间。
	ULONG uNumberOfPages,
	PPHYSICAL_ADDRESS pFirstPagePA
	)
{
	//	NumberOfBytes [中]

	//	大小，以字节为单位，连续的内存块的分配。 欲了解更多信息，请参见备注。 
	//		HighestAcceptableAddress [中]

	//最有效的物理地址调用者可以使用。 例如，如果一个设备能解决在第一个16兆字节的处理器的物理存储器地址范围仅位置，驱动此设备应该设置HighestAcceptableAddress到0x0000000000FFFFFF。 
	return MmAllocateContiguousPagesSpecifyCache(uNumberOfPages, pFirstPagePA, MmCached);
}

ULONG64 GetPagePresent(ULONG64 PageVA)
{
	ULONG64 Pml4e, Pdpe, Pde, Pte;

	Pml4e = *(PULONG64)(((PageVA >> 36) & 0xff8) + PML4_BASE);

	if (!(Pml4e & P_PRESENT))
		return 0;
	
	Pdpe = *(PULONG64)(((PageVA >> 27) & 0x1ffff8) + PDP_BASE);

	if (!(Pdpe & P_PRESENT))
		return 0;

	Pde = *(PULONG64)(((PageVA >> 18) & 0x3ffffff8) + PD_BASE);

	if (!(Pde & P_PRESENT))
		return 0;

	if ((Pde & P_LARGE) == P_LARGE)
		return Pde;

	Pte = *(PULONG64)(((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);

	if (!(Pte & P_PRESENT))
		return 0;

	return Pte;

}