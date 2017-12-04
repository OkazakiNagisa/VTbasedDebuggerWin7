#include "ntddk.h"
#include "Arch\Intel\VMX.h"
#include "Arch\Intel\EPT.h"
#include "dbgtool.h"
typedef struct _R3EPT_HOOK{
	ULONG64 Code_PAGE_VA;
	ULONG64 Code_PAGE_PFN;
	ULONG64 Data_PAGE_VA;
	ULONG64 Data_PAGE_PFN;
	ULONG64 OriginalPtr;
	PEPROCESS TargetProcess;
	ULONG64 TargetCr3;
	BOOLEAN IsHook;
	PMDL mdl;
	ULONG RefCount;
	LIST_ENTRY PageList;
}R3EPT_HOOK, *PR3EPT_HOOK;
extern p_save_handlentry PmainList;
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	union {
		UCHAR InProgressFlags;
		struct {
			BOOLEAN KernelApcInProgress : 1;
			BOOLEAN SpecialApcInProgress : 1;
		};
	};

	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
#define PFN(addr)                   (ULONG64)((addr) >> PAGE_SHIFT)


#ifndef  ___EPT_FUNC__
#define ___EPT_FUNC__
#define PT_BASE 0xFFFFF68000000000
NTKERNELAPI
VOID
KeStackAttachProcess(
__inout PEPROCESS PROCESS,
__out PKAPC_STATE ApcState
);

NTKERNELAPI
VOID
KeUnstackDetachProcess(
__in PKAPC_STATE ApcState
);
NTKERNELAPI _IRQL_requires_max_(APC_LEVEL) _IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_same_ VOID KeGenericCallDpc(_In_ PKDEFERRED_ROUTINE Routine, _In_opt_ PVOID Context);
VOID PHpHookCallbackDPC(IN PRKDPC Dpc, IN PVOID Context, IN PVOID SystemArgument1, IN PVOID SystemArgument2);
#endif 


#ifndef __EPT_STRUCT
#define  __EPT_STRUCT
static LIST_ENTRY R3pageList;
static KSPIN_LOCK R3PageLock;

typedef struct _HOOK_CONTEXT
{
	BOOLEAN Hook;           // TRUE to hook page, FALSE to unhook
	ULONG64 DataPagePFN;    // Physical data page PFN
	ULONG64 CodePagePFN;    // Physical code page PFN
} HOOK_CONTEXT, *PHOOK_CONTEXT;

#endif // !__EPT_STRUCT
//初始化
VOID InitialzeR3EPTHOOK(){

	KeInitializeSpinLock(&R3PageLock);
	InitializeListHead(&R3pageList);


}
//移除HOOK链表和释放HOOK数据结构内存
VOID NTAPI Page_ExFreeItem(PR3EPT_HOOK Item)
{
	KIRQL OldIrql;
	KeAcquireSpinLock(&R3PageLock, &OldIrql);
	RemoveEntryList(&Item->PageList);
	KeReleaseSpinLock(&R3PageLock, OldIrql);
	ExFreePool(Item);
	return;


}
//获取挂钩地址HOOK数据
PR3EPT_HOOK Page_IsVald(ULONG64 Address,ULONG64 EProcess){

	KIRQL OldIrql;
	ULONG64 Page = NULL;
	if (Address!=NULL)
	{
		Page = PAGE_ALIGN(Address);//Get page
	}
	
	PLIST_ENTRY Entry;
	R3EPT_HOOK *TempItem = NULL;
	R3EPT_HOOK* DFind = NULL;
	KeAcquireSpinLock(&R3PageLock, &OldIrql);
	Entry = R3pageList.Flink;
	while (Entry != &R3pageList)
	{
		TempItem = CONTAINING_RECORD(Entry, R3EPT_HOOK, PageList);
		Entry = Entry->Flink;
		if (Address != NULL)
		{

			if (TempItem->Data_PAGE_VA == Page && TempItem->TargetProcess == EProcess)
			{
				DFind = TempItem;
				break;
			}
		}

	
	}
	KeReleaseSpinLock(&R3PageLock, OldIrql);
	return DFind;

}
//获取指定GVA的HOOK数据
PR3EPT_HOOK Page_FindStructByGvaBase(ULONG64 GVA){

	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	ULONG64 GVAbase = PAGE_ALIGN(GVA);
	R3EPT_HOOK *TempItem = NULL;
	R3EPT_HOOK* DFind = NULL;
	KeAcquireSpinLock(&R3PageLock, &OldIrql);
	Entry = R3pageList.Flink;
	while (Entry != &R3pageList)
	{
		TempItem = CONTAINING_RECORD(Entry, R3EPT_HOOK, PageList);
		Entry = Entry->Flink;
		if (GVA != NULL)
		{

			if (TempItem->Data_PAGE_VA == GVAbase)
			{
				DFind = TempItem;
				break;
			}
		}


	}
	KeReleaseSpinLock(&R3PageLock, OldIrql);
	return DFind;


}
//获取指定pfn的HOOK数据
PR3EPT_HOOK Page_FindStructByGpaPfn(ULONG64 GpaPfn){

	KIRQL OldIrql;
	PLIST_ENTRY Entry;
	R3EPT_HOOK *TempItem = NULL;
	R3EPT_HOOK* DFind = NULL;
	KeAcquireSpinLock(&R3PageLock, &OldIrql);
	Entry = R3pageList.Flink;
	while (Entry != &R3pageList)
	{
		TempItem = CONTAINING_RECORD(Entry, R3EPT_HOOK, PageList);
		Entry = Entry->Flink;
		if (GpaPfn != NULL)
		{

			if (TempItem->Data_PAGE_PFN == GpaPfn)
			{
				DFind = TempItem;
				break;
			}
		}


	}
	KeReleaseSpinLock(&R3PageLock, OldIrql);
	return DFind;


}
//添加HOOK数据到链表
BOOLEAN Page_Add(PR3EPT_HOOK phook){
	PR3EPT_HOOK Temp = NULL;
	Temp = (PR3EPT_HOOK)ExAllocatePoolWithTag(NonPagedPool, sizeof(R3EPT_HOOK), 'xrrp');
	if (!Temp)
	{
		return FALSE;
	}
	RtlZeroMemory(Temp, sizeof(R3EPT_HOOK));
	Temp->Code_PAGE_PFN = phook->Code_PAGE_PFN;
	Temp->Code_PAGE_VA = phook->Code_PAGE_VA;
	Temp->Data_PAGE_PFN = phook->Data_PAGE_PFN;
	Temp->Data_PAGE_VA = phook->Data_PAGE_VA;
	Temp->IsHook = phook->IsHook;
	Temp->OriginalPtr = phook->OriginalPtr;
	Temp->TargetCr3 = phook->TargetCr3;
	Temp->mdl = phook->mdl;
	Temp->RefCount = phook->RefCount;
	Temp->TargetProcess = phook->TargetProcess;
	ExInterlockedInsertTailList(&R3pageList,&Temp->PageList,&R3PageLock);
	return TRUE;

}
//获取R3下GPA
static ULONG64 NTAPI GetGuestPA(PVOID GuestVA)
{

	ULONG64 GuestAddr;
	ULONG64 PageVA = (ULONG64)GuestVA;
	ULONG64 GuestPA = (((PageVA >> 9) & 0x7ffffffff8) + PT_BASE);// MiGetPteAddress(GuestVA);
	if (!MmIsAddressValid((PVOID)GuestPA))
	{
		
		return FALSE;
	}
	GuestPA = *(PULONG64)GuestPA & 0xfffffff000;
	GuestAddr = PageVA & 0xfff;
	GuestPA = GuestPA + GuestAddr;
	return (ULONG64)GuestPA;
}
//处理R3的EPT异常
BOOLEAN R3_HideMEM_Violation(IN PGUEST_STATE GuestState){
	PEPT_DATA pEPT = &GuestState->Vcpu->EPT;
	ULONG64 pfn = PFN(GuestState->PhysicalAddress.QuadPart );
	PR3EPT_HOOK Phook = NULL;
	p_save_handlentry Padd = NULL;
	PEPT_VIOLATION_DATA pViolationData = (PEPT_VIOLATION_DATA)&GuestState->ExitQualification;
	ULONG64 gva =  GuestState->LinearAddress;
	Phook = Page_FindStructByGvaBase(gva);

	if (Phook)
	{
	//uanc	DbgPrint("R3 EPT触发 \n");


		ULONG64 TargetPFN = Phook->Data_PAGE_PFN;
		EPT_ACCESS TargetAccess = EPT_ACCESS_ALL;

		// Executable page for writing
		if (pViolationData->Fields.Read)
		{
			
			Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
			if (Padd != NULL)
			{
				//DbgPrint("R3 EPT 调试器read触发 \n");
				TargetPFN = Phook->Code_PAGE_PFN;//调试工具访问内存给代码页
			}
			else
			{

				TargetPFN = Phook->Data_PAGE_PFN;

			}

			TargetAccess = EPT_ACCESS_RW;
		}
		else if (pViolationData->Fields.Write)
		{
			
		//	DbgPrint("R3 EPT Write触发 \n");
			TargetPFN = Phook->Code_PAGE_PFN;


			TargetAccess = EPT_ACCESS_RW;
		}
		else if (pViolationData->Fields.Execute)
		{
			//DbgPrint("R3 EPT Execute触发 \n");

			TargetPFN = Phook->Code_PAGE_PFN;


			TargetAccess = EPT_ACCESS_EXEC;
		}
		else
		{
			/* DPRINT(
			"HyperBone: CPU %d: %s: Impossible page 0x%p access 0x%X\n", CPU_IDX, __FUNCTION__,
			GuestState->PhysicalAddress.QuadPart, pViolationData->All
			);*/
		}


		EptUpdateTableRecursive(pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL, pfn, TargetAccess, TargetPFN, 1);
		EPT_CTX ctx = { 0 };
		__invept(INV_ALL_CONTEXTS, &ctx);
		GuestState->Vcpu->HookDispatch.pEntry = Phook;
		GuestState->Vcpu->HookDispatch.Rip = GuestState->GuestRip;
		ToggleMTF(TRUE);
		return TRUE;
	}
	else{

		
	//	EptUpdateTableRecursive(pEPT, pEPT->PML4Ptr, EPT_TOP_LEVEL, pfn, EPT_ACCESS_ALL, pfn, 1);
		return FALSE;

	}



}
//添加R3指定内存的XXOO
BOOLEAN R3_HideMem(PEPROCESS Process,ULONG64 Address,PVOID Code,ULONG Size){
	KAPC_STATE apc = { 0 };
	BOOLEAN IsAdd = FALSE;
	PR3EPT_HOOK IsVald = NULL;
	PR3EPT_HOOK Phook = NULL;
	ULONG_PTR ofsset = NULL;
	PHYSICAL_ADDRESS phys = { 0 };
	PUCHAR CodePage=NULL;
	BOOLEAN CreatePage = FALSE;
	phys.QuadPart = MAXULONG64;

	if (!g_Data->Features.EPT || !g_Data->Features.ExecOnlyEPT)
		return STATUS_NOT_SUPPORTED;

	if (!MmIsAddressValid(Process)){ return FALSE; }
	KeStackAttachProcess(Process, &apc);
	IsVald = Page_IsVald(Address,Process);

	if (IsVald!=NULL)
	{
		IsVald->RefCount++;
		KeUnstackDetachProcess(&apc);
		return FALSE;
	}
	else{
		CodePage = MmAllocateContiguousMemory(PAGE_SIZE, phys);
		CreatePage = TRUE;
	}



	if (!CodePage)
	{
		KeUnstackDetachProcess(&apc);
		return FALSE;
	}
	
		Phook = (PR3EPT_HOOK)ExAllocatePoolWithTag(NonPagedPool, sizeof(R3EPT_HOOK), "xrrp");
	
	
	if (Phook==NULL)
	{
		KeUnstackDetachProcess(&apc);
		return FALSE;
	}
	RtlZeroMemory(Phook, sizeof(R3EPT_HOOK));


	ofsset = (ULONG_PTR)Address - (ULONG_PTR)PAGE_ALIGN(Address);

	Phook->mdl= IoAllocateMdl(PAGE_ALIGN(Address),PAGE_SIZE,NULL,NULL,NULL);
	MmProbeAndLockPages(Phook->mdl, UserMode, IoWriteAccess);//锁定内存，page_out
	RtlCopyMemory(CodePage, PAGE_ALIGN(Address),PAGE_SIZE);
	//memcpy(CodePage + ofsset, Code, Size);//
	Phook->RefCount=1;//页面引用计数初始化为1
	Phook->Code_PAGE_VA = CodePage;
	Phook->Code_PAGE_PFN = PFN(MmGetPhysicalAddress(CodePage).QuadPart);
	Phook->Data_PAGE_PFN = PFN(GetGuestPA(PAGE_ALIGN(Address)));
	Phook->Data_PAGE_VA = PAGE_ALIGN(Address);
	Phook->OriginalPtr = Address;
	Phook->IsHook = TRUE;
	Phook->TargetCr3 = __readcr3();
	Phook->TargetProcess = Process;
	IsAdd=Page_Add(Phook);
	KeUnstackDetachProcess(&apc);
	DbgPrint("Gpa:=%p CODEPA:=%p \n", GetGuestPA(Address), MmGetPhysicalAddress(CodePage).QuadPart);
	//
	if (IsAdd)
	{
		if (CreatePage){

			HOOK_CONTEXT ctx = { 0 };
			ctx.Hook = TRUE;
			ctx.DataPagePFN = Phook->Data_PAGE_PFN;
			ctx.CodePagePFN = Phook->Code_PAGE_PFN;

			KeGenericCallDpc(PHpHookCallbackDPC, &ctx);//修改EPT表项 
		}

		////
	}
	return TRUE;
}
//移除R3指定内存的XXOO
BOOLEAN R3_UnHideMem(ULONG64 Address,ULONG64 Eprocess){
	PR3EPT_HOOK IsVald = NULL;
	
	if (!g_Data->Features.EPT || !g_Data->Features.ExecOnlyEPT)
		return STATUS_NOT_SUPPORTED;

	IsVald = Page_IsVald(Address, Eprocess);
	if (IsVald!=NULL ) 
	{
		if (IsVald->RefCount == 1)
		{
			HOOK_CONTEXT ctx = { 0 };
			ctx.Hook = FALSE;
			ctx.DataPagePFN = IsVald->Data_PAGE_PFN;
			ctx.CodePagePFN = IsVald->Code_PAGE_PFN;;

			KeGenericCallDpc(PHpHookCallbackDPC, &ctx);


			MmFreeContiguousMemory(IsVald->Code_PAGE_VA);//释放CODE_PAGE
			MmUnlockPages(IsVald->mdl);//解锁内存
			IoFreeMdl(IsVald->mdl);//移除MDL
			Page_ExFreeItem(IsVald);//移除链表数据释放内存

		}
		else
		{
			IsVald->RefCount--;
		}

		
	}
	

	////FIXME
	return TRUE;
}
 
