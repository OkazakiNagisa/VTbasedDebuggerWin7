// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#include "driver.h"
#include "gobalConter.h"
#include "vstruct.h"
#include "LDE64x6412.h"
#include "ntddk.h"
#include "VMProtectDDK.h"
#include "dbgtool.h"
#include "Core/HVM.h"
#include "Include/CPU.h"
#include "Include/Common.h"
#include "Util/Utils.h"
#include "Test/Tests.h"
#include <intrin.h>
#include "R3EptHideMem.h"
UCHAR int3 = { 0xCC };
PDEVICE_OBJECT pDevObj;
BOOLEAN OpenVtMode = FALSE;//LOAD VT MODE
BOOLEAN VtMode = FALSE;
BOOLEAN MainVtMode = FALSE;
VOID TestPageHook();
VOID RemoveDbgtoolMsg(BOOLEAN  isload);
VOID DbgNoVtHookMyDbgKr(BOOLEAN IsH);
VOID SetDbgMsgNotify(BOOLEAN IsLoad);
VOID EPTUNHOOK_SwapContext();
VOID EPT_InitialzeMiNiHook();
VOID EPT_UnInitialzeMiNiHook();
VOID EPT_UnLoadSsdtInlineHook();
VOID EPT_InitIalzeSsdtInlineHook();
VOID EPTHOOK_SwapContext();
VOID EPTUNHOOK_SwapContext();
VOID InitialzeDbgprocessList();
void InitIalzeSsdtInlineHook();
void unloadSsdtInlineHook();
void InitializeHookSwapContext();
VOID HOOKSwapContext();
VOID UnHookSwapContext();
NTSTATUS ObProtectProcess(BOOLEAN Enable);
p_save_handlentry PmainList;
VOID UnLoadProtectWindow();
VOID LoadProtectWindow();

VOID LoadImageNotifyRoutine
(
__in_opt PUNICODE_STRING  FullImageName,
__in HANDLE  ProcessId,
__in PIMAGE_INFO  ImageInfo
);
NTSTATUS HvmSwallowBluepill();
BOOLEAN VmxIsImplemented();
NTSTATUS NTAPI MmInitEptPageTable();
NTSTATUS NTAPI MmFreeEptPageTable();
DbgkpMarkProcessPeb(IN PEPROCESS Process);
VOID InitDisablePatchGuard();
VOID installMiniHOOK();
VOID  unMiniHook();
VOID DbgInitItem();
VOID UnLoadSysHook();
VOID BpInitItem();
VOID HOOKEPT(ULONG64 VA, BOOLEAN hook);
VOID UnLoadDisablePatchGuard();
typedef int(*LDE_DISASM)(void *p, int dw);
LDE_DISASM LDE;

void LDE_init()
{
	LDE = ExAllocatePool(NonPagedPool, 12800);
	memcpy(LDE, szShellCode, 12800);
}

HANDLE ProcessId = NULL;
ULONG64 ProcessAddr = NULL;
BOOLEAN ISHOOK = FALSE;
BOOLEAN inunHOOK = TRUE;
PEPROCESS process;
BOOLEAN DriverEnable = FALSE;
HANDLE hThread = NULL;
ULONG64 proxyidt;
extern _fastcall PageFaultHandlerHook;
void HookMemoryPage(PEPROCESS Process, ULONG64 Address);
void UnHookMemoryPage(ULONG32 Address);
VOID inithook();
VOID initdata();
VOID bglol();
VOID DbgUnlol();
NTSTATUS NTAPI initDbgk();
NTSTATUS HOOKIDT(ULONG IDTID, PVOID NewfcuncAddress,__in BOOLEAN userDPL, __out  PVOID * oldTRAP1);
PGLOBAL_DATA g_Data = NULL;

/// <summary>
/// Allocate global data
/// </summary>
/// <returns>Allocated data or NULL</returns>
PGLOBAL_DATA AllocGlobalData()
{
	PHYSICAL_ADDRESS low = { 0 }, high = { 0 };
	high.QuadPart = MAXULONG64;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	ULONG_PTR size = FIELD_OFFSET(GLOBAL_DATA, cpu_data) + cpu_count * sizeof(VCPU);
	PGLOBAL_DATA pData = (PGLOBAL_DATA)ExAllocatePoolWithTag(NonPagedPoolNx, size, HB_POOL_TAG);
	if (pData == NULL)
		return NULL;

	RtlZeroMemory(pData, size);

	pData->MSRBitmap = ExAllocatePoolWithTag(NonPagedPoolNx, PAGE_SIZE, HB_POOL_TAG);
	if (pData->MSRBitmap == NULL)
	{
		ExFreePoolWithTag(pData, HB_POOL_TAG);
		return NULL;
	}

	RtlZeroMemory(pData->MSRBitmap, PAGE_SIZE);

	pData->CPUVendor = UtilCPUVendor();

	for (ULONG i = 0; i < cpu_count; i++)
	{
		PVCPU Vcpu = &pData->cpu_data[i];

		InitializeListHead(&Vcpu->EPT.PageList);

		for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
		{
			Vcpu->EPT.Pages[j] = MmAllocateContiguousMemorySpecifyCache(PAGE_SIZE, low, high, low, MmNonCached);
			if (Vcpu->EPT.Pages[j] != NULL)
			{
				UtilProtectNonpagedMemory(Vcpu->EPT.Pages[j], PAGE_SIZE, PAGE_READWRITE);
				RtlZeroMemory(Vcpu->EPT.Pages[j], PAGE_SIZE);
			}
		}
	}

	return pData;
}

/// <summary>
/// Free global data
/// </summary>
/// <param name="pData">Data pointer</param>
VOID FreeGlobalData(IN PGLOBAL_DATA pData)
{
	if (pData == NULL)
		return;

	ULONG cpu_count = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (ULONG i = 0; i < cpu_count; i++)
	{
		PVCPU Vcpu = &pData->cpu_data[i];
		if (Vcpu->VMXON)
			MmFreeContiguousMemory(Vcpu->VMXON);
		if (Vcpu->VMCS)
			MmFreeContiguousMemory(Vcpu->VMCS);
		if (Vcpu->VMMStack)
			MmFreeContiguousMemory(Vcpu->VMMStack);

		for (ULONG j = 0; j < EPT_PREALLOC_PAGES; j++)
			if (Vcpu->EPT.Pages[j] != NULL)
				MmFreeContiguousMemory(Vcpu->EPT.Pages[j]);
	}

	if (pData->Memory)
		ExFreePoolWithTag(pData->Memory, HB_POOL_TAG);
	if (pData->MSRBitmap)
		ExFreePoolWithTag(pData->MSRBitmap, HB_POOL_TAG);

	ExFreePoolWithTag(pData, HB_POOL_TAG);
}
NTSTATUS UnloadHV(){

	TestPrintResults();
	//TestStop();

	NTSTATUS status = StopHV();
	MainVtMode = FALSE;
	FreeGlobalData(g_Data);
}
NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObj)
{

	UNREFERENCED_PARAMETER(pDriverObj);
    CCHAR i;
    KIRQL OldIrql;
    KAFFINITY OldAffinity;
	UNICODE_STRING strLink;

	//删除符号连接和设备
	RtlInitUnicodeString(&strLink, LINK_NAME);
	IoDeleteSymbolicLink(&strLink);
	IoDeleteDevice(pDriverObj->DeviceObject);
	/**
    for (i=0; i<KeNumberProcessors; i++)
    {
        OldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1<<i));
        OldIrql = KeRaiseIrqlToDpcLevel();
        _StopVirtualization();
        KeLowerIrql(OldIrql);
        KeRevertToUserAffinityThreadEx(OldAffinity);
    }


HvmSpitOutBluepill ();
*/
	
	if (DriverEnable)
	{
		//MmFreeEptPageTable(); 
		ObProtectProcess(FALSE);
		//UnLoadSysHook();
		//DbgUnlol();
		//TestStop();
		DbgNoVtHookMyDbgKr(FALSE);
		//UnHookSwapContext();
		UnLoadProtectWindow();
		//UnLoadDisablePatchGuard();
	}
	
	
	if (MainVtMode)
	{
		UnloadHV();
	}

    return STATUS_SUCCESS;
}
VOID Dbglol(){
	if (VtMode)
	{
		//EPTHOOK_SwapContext();
		EPT_InitialzeMiNiHook();
		EPT_InitIalzeSsdtInlineHook();
	}
	else{
		InitDisablePatchGuard();// 动态PASS W7 PG
	//	HOOKSwapContext();
		InitIalzeSsdtInlineHook();
		installMiniHOOK();//加载dbgk-krnl函数钩子
	}
	
}

VOID DbgUnlol(){

	if (VtMode)
	{
		//EPTUNHOOK_SwapContext();
		EPT_UnInitialzeMiNiHook();
		EPT_UnLoadSsdtInlineHook();
		//SetDbgMsgNotify(FALSE);
	}
	else
	{
		UnLoadDisablePatchGuard();
	//	UnHookSwapContext();
		unloadSsdtInlineHook();
		//SetDbgMsgNotify(FALSE);
		unMiniHook();
	}



}

VOID DbgNoVtHookMyDbgKr(BOOLEAN IsH){
	if (IsH)
	{
		InitDisablePatchGuard();// 动态PASS W7 PG
		//	HOOKSwapContext();
		InitIalzeSsdtInlineHook();
		installMiniHOOK();//加载dbgk-krnl函数钩子
		RemoveDbgtoolMsg(TRUE);
	}
	else
	{
		UnLoadDisablePatchGuard();
		//	UnHookSwapContext();
		unloadSsdtInlineHook();
		//SetDbgMsgNotify(FALSE);
		RemoveDbgtoolMsg(FALSE);
		unMiniHook();
	}



}
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
int __cdecl mystrcmp(const char *src, const char *dst)
{
	int ret = 0;
	while (!(ret = *(unsigned char *)src - *(unsigned char *)dst) && *dst)
		++src, ++dst;
	if (ret < 0)
		ret = -1;
	else if (ret > 0)
		ret = 1;
	return(ret);
}
BOOLEAN CheckIOCTLData(){
	if (KiRetireDpcList == NULL || ObDuplicateObject == NULL || KiSaveDebugRegisterState == NULL || KiUmsCallEntry == NULL || KiSystemServiceExit == NULL || KeGdiFlushUserBatch == NULL || KiSystemServiceRepeat == NULL || PspSystemDlls==NULL)
	{
		return FALSE;
	}

	if (KeServiceDescriptorTable == NULL || KeServiceDescriptorTableShadow == NULL || KiSystemServiceCopyEnd == NULL || DbgkDebugObjectType==NULL){
		return FALSE;
	}
	if (DbgkCopyProcessDebugPort == NULL || KiDispatchException == NULL || DbgkForwardException == NULL || LpcRequestWaitReplyPortEx==NULL){
	
		return FALSE;
	}
	if (KiDispatchException==NULL || MmGetFileNameForSection == NULL || PsGetNextProcess == NULL || PsTerminateProcess == NULL || DbgkOpenProcessDebugPort == NULL || DbgkUnMapViewOfSection == NULL || DbgkMapViewOfSection == NULL){
		return FALSE;
	}
	if (ExGetCallBackBlockRoutine == NULL || ObpCallPreOperationCallbacks == NULL || DbgkExitProcess == NULL || DbgkExitThread == NULL || DbgkpSendApiMessage == NULL || DbgkpQueueMessage == NULL || MmGetFileNameForAddress==NULL)
	{
		return FALSE;
	}
	if (NtQueryInformationThread == NULL || ExCompareExchangeCallBack == NULL || RtlpCopyLegacyContextX86==NULL)
	{
		return FALSE;
	}

	if (NtReadVirtualMemory == NULL || NtWriteVirtualMemory == NULL || XNtOpenProcess == NULL || KiAttachProcess==NULL)
	{
		return FALSE;
	}

	if (SwapContext_PatchXRstor == NULL || SwapContext==NULL)
	{
		return FALSE;
	}
	return TRUE;
}
void BypassCheckSign(PDRIVER_OBJECT pDriverObj)
{
	//STRUCT FOR WIN64
	typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
	{
		struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
		struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
		VOID*        DllBase;
		VOID*        EntryPoint;
		ULONG32      SizeOfImage;
		UINT8        _PADDING0_[0x4];
		struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
		struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
		ULONG32      Flags;
	}LDR_DATA, *PLDR_DATA;
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)(pDriverObj->DriverSection);
	ldr->Flags |= 0x20;
}

VOID InitEptPageStruct();
VOID RemoveListEntry(PLIST_ENTRY ListEntry);
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//VMProtectBegin("DispatchIoctl");

	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInSize;
	ULONG uOutSize;

	//获得IRP里的关键数据
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	//这个就是传说中的控制码
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	//输入和输出的缓冲区（DeviceIoControl的InBuffer和OutBuffer都是它）
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	//EXE发送传入数据的BUFFER长度（DeviceIoControl的nInBufferSize）
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	//EXE接收传出数据的BUFFER长度（DeviceIoControl的nOutBufferSize）
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;
	switch (uIoControlCode)
	{
	case IOCTL_notiyenable:{
		if (!DriverEnable)
		{
			if (strlen(keycode) != 0 && strlen(keycheck) != 0)
			{

				if (mystrcmp(keycode, "") != 0 && mystrcmp(keycheck, "") != 0)
				{
					if (mystrcmp(keycode, keycheck) == 0)//验证key是否存在
					{
						
						if (CheckIOCTLData){//验证所有调试数据是否可用
							InitializeHookSwapContext();
							ObProtectProcess(TRUE);
							
							DriverEnable = TRUE;
							initdata(); //初始化数据
							
							initDbgk();//初始化dbgkrnl系统数据
						//	TestPageHook();
							DbgNoVtHookMyDbgKr(TRUE);
							VtMode = FALSE;
					//	Dbglol();//支持VT则启用VT模式 不支持则启动普通模式
					     	LoadProtectWindow();
						}
					}


				}
			}
		}
		status = STATUS_SUCCESS;
		break;
	}
		

	case  IOCTL_dbgProcessId:{
		DbgPrint(" ADD DBG TOOL PROCESS");
		insertlist(PsGetCurrentProcessId(), PsGetCurrentProcess(), PmainList);//加入DBG进程
		if (VtMode)
		{
			///暂时没处理这个位置
		}
		else{
		ULONG64 process = PsGetCurrentProcess();
			RemoveListEntry(process + 0x188);

		}
		


		break;
	}

		
	case Hookpage:
	{
					// inunHOOK = TRUE;
					 ////// HOOK R3 
		if (process != NULL){
			if (ISHOOK == TRUE){

				// HookEptMemoryPage(process, ProcessAddr);
				R3_HideMem(process, ProcessAddr, &int3, 1);
			
				DbgPrint("挂钩成功EPROCESS:%p \n", process);
				DbgPrint("挂钩成功地址:%p  \n", ProcessAddr);
				process = NULL;
				ProcessAddr = NULL;
			}
		}

						 status = STATUS_SUCCESS;
					 break;
	}
	case Unhookpage:
	{
					 
					  // inunHOOK = FALSE;
					   //// UNHOOK R3

		// UnHookEptPage( ProcessAddr);
		if (ProcessAddr != NULL){
			if (ISHOOK == TRUE){
				R3_UnHideMem(ProcessAddr,process);
			
				process = NULL;
				ProcessAddr = NULL;

			}
		}

						 status = STATUS_SUCCESS;
					 break;
	}
	case TargetHookAddress:
	{
							///// ADDRESS R3
								
								 
									
								      RtlZeroMemory(&ProcessId, 8);
									  memcpy(&ProcessAddr, pIoBuffer, sizeof(ProcessAddr));

								
							 
					 status = STATUS_SUCCESS;
					 break;
	}
	case TargetProcessId:
	{

						
							


							
							
								
								RtlZeroMemory(&ProcessId,8);
								memcpy(&ProcessId, pIoBuffer, sizeof(ProcessId));
								DbgPrint(" IS TRUE ! PROCESS %d \n", ProcessId);
								if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &process))){
									ISHOOK = TRUE;
									DbgPrint(" IS TRUE ! EPROCESS %p \n",process);

								}
								else{

									ISHOOK = FALSE;
								
								}

							

							  status = STATUS_SUCCESS;
							  break;
	}
		
	case IOCTL_ObDuplicateObject:
	{
		RtlZeroMemory(&ObDuplicateObject, 8);
		memcpy(&ObDuplicateObject, pIoBuffer, sizeof(ObDuplicateObject));
		
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_RtlpCopyLegacyContextX86:
	{
		RtlZeroMemory(&RtlpCopyLegacyContextX86, 8);
		memcpy(&RtlpCopyLegacyContextX86, pIoBuffer, sizeof(RtlpCopyLegacyContextX86));

		status = STATUS_SUCCESS;
		break;
	}
		////

	case IOCTL_keycode:
	{
		RtlZeroMemory(&keycode, 1024);
		memcpy(&keycode, pIoBuffer, 1024);

		status = STATUS_SUCCESS;
		break;
	}
		

	case IOCTL_keycheck:
	{
		RtlZeroMemory(&keycheck, 1024);
		memcpy(&keycheck, pIoBuffer, 1024);

		status = STATUS_SUCCESS;
		break;
	}

		////
		

	case IOCTL_DbgLol:{

		if (DbgConter==FALSE){
			Dbglol();
			DbgConter = TRUE;
		}
		else
		{
			DbgConter = FALSE;
			DbgUnlol();
		}
		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_KiAttachProcess:
		{
		RtlZeroMemory(&KiAttachProcess, 8);
		memcpy(&KiAttachProcess, pIoBuffer, sizeof(KiAttachProcess));

			status = STATUS_SUCCESS;
			break;
		}
	case IOCTL_DbgkpWakeTarget:
	{
		RtlZeroMemory(&DbgkpWakeTarget_2, 8);
		memcpy(&DbgkpWakeTarget_2, pIoBuffer, sizeof(DbgkpWakeTarget_2));

		status = STATUS_SUCCESS;
		break;
	}

		////////////////////////////////////////////
		
	case IOCTL_NtCreateDebugObject:
		{
		RtlZeroMemory(&NtCreateDebugObject, 8);
		memcpy(&NtCreateDebugObject, pIoBuffer, sizeof(NtCreateDebugObject));

			status = STATUS_SUCCESS;
			break;
		}


		


	case IOCTL_NtWaitForDebugEvent:
		{
		RtlZeroMemory(&NtWaitForDebugEvent, 8);
		memcpy(&NtWaitForDebugEvent, pIoBuffer, sizeof(NtWaitForDebugEvent));

			status = STATUS_SUCCESS;
			break;
		}

		
	case IOCTL_SwapContext:
		{
		RtlZeroMemory(&SwapContext, 8);
		memcpy(&SwapContext, pIoBuffer, sizeof(SwapContext));

			status = STATUS_SUCCESS;
			break;
		}
	case IOCTL_SwapContext_PatchXRstor:
	{
		RtlZeroMemory(&SwapContext_PatchXRstor, 8);
		memcpy(&SwapContext_PatchXRstor, pIoBuffer, sizeof(SwapContext_PatchXRstor));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_NtDebugContinue:
	{
		RtlZeroMemory(&NtDebugContinue, 8);
		memcpy(&NtDebugContinue, pIoBuffer, sizeof(NtDebugContinue));

		status = STATUS_SUCCESS;
		break;
	}


		

	case IOCTL_NtDebugActiveProcess:
		{
		RtlZeroMemory(&NtDebugActiveProcess, 8);
		memcpy(&NtDebugActiveProcess, pIoBuffer, sizeof(NtDebugActiveProcess));

			status = STATUS_SUCCESS;
			break;
		}


		

	case IOCTL_NtRemoveProcessDebug:
		{
		RtlZeroMemory(&myNtRemoveProcessDebug, 8);
		memcpy(&myNtRemoveProcessDebug, pIoBuffer, sizeof(myNtRemoveProcessDebug));

			status = STATUS_SUCCESS;
			break;
		}

		//////////////////////////////////////////////////////////////////////////
	case IOCTL_NtReadVirtualMemory:
	{
		RtlZeroMemory(&NtReadVirtualMemory, 8);
		memcpy(&NtReadVirtualMemory, pIoBuffer, sizeof(NtReadVirtualMemory));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_NtWriteVirtualMemory:
	{
		RtlZeroMemory(&NtWriteVirtualMemory, 8);
		memcpy(&NtWriteVirtualMemory, pIoBuffer, sizeof(NtWriteVirtualMemory));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_NtOpenProcess:
	{
		RtlZeroMemory(&XNtOpenProcess, 8);
		memcpy(&XNtOpenProcess, pIoBuffer, sizeof(XNtOpenProcess));

		status = STATUS_SUCCESS;
		break;
	}
		//////////////////////////////////////////////////////////////////////////
	case IOCTL_DbgkpPostFakeProcessCreateMessages:
	{
		RtlZeroMemory(&DbgkpPostFakeProcessCreateMessages, 8);
		memcpy(&DbgkpPostFakeProcessCreateMessages, pIoBuffer, sizeof(DbgkpPostFakeProcessCreateMessages));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkpSetProcessDebugObject:
	{
		RtlZeroMemory(&DbgkpSetProcessDebugObject, 8);
		memcpy(&DbgkpSetProcessDebugObject, pIoBuffer, sizeof(DbgkpSetProcessDebugObject));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_ExCompareExchangeCallBack:
	{
		RtlZeroMemory(&ExCompareExchangeCallBack, 8);
		memcpy(&ExCompareExchangeCallBack, pIoBuffer, sizeof(ExCompareExchangeCallBack));

		status = STATUS_SUCCESS;
		break;
	}

		
	case IOCTL_NtQueryInformationThread:
	{
		RtlZeroMemory(&NtQueryInformationThread, 8);
		memcpy(&NtQueryInformationThread, pIoBuffer, sizeof(NtQueryInformationThread));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PspSystemDlls:
	{
		RtlZeroMemory(&PspSystemDlls, 8);
		memcpy(&PspSystemDlls, pIoBuffer, sizeof(PspSystemDlls));

		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_ObpCallPreOperationCallbacks:
	{
		RtlZeroMemory(&ObpCallPreOperationCallbacks, 8);
		memcpy(&ObpCallPreOperationCallbacks, pIoBuffer, sizeof(ObpCallPreOperationCallbacks));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_MmGetFileNameForAddress:
	{
		RtlZeroMemory(&MmGetFileNameForAddress, 8);
		memcpy(&MmGetFileNameForAddress, pIoBuffer, sizeof(MmGetFileNameForAddress));

		status = STATUS_SUCCESS;
		break;
	}


		
	case IOCTL_DbgkpQueueMessage:
	{
		RtlZeroMemory(&DbgkpQueueMessage, 8);
		memcpy(&DbgkpQueueMessage, pIoBuffer, sizeof(DbgkpQueueMessage));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkpSendApiMessage:
	{
		RtlZeroMemory(&DbgkpSendApiMessage, 8);
		memcpy(&DbgkpSendApiMessage, pIoBuffer, sizeof(DbgkpSendApiMessage));

		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_ExGetCallBackBlockRoutine:
	{
		RtlZeroMemory(&ExGetCallBackBlockRoutine, 8);
		memcpy(&ExGetCallBackBlockRoutine, pIoBuffer, sizeof(ExGetCallBackBlockRoutine));

		status = STATUS_SUCCESS;
		break;
	}
		

	case IOCTL_PsTerminateProcess:
		{
		RtlZeroMemory(&PsTerminateProcess, 8);
		memcpy(&PsTerminateProcess, pIoBuffer, sizeof(PsTerminateProcess));

			status = STATUS_SUCCESS;
			break;
		}

		////

	case IOCTL_DbgkExitProcess:
	{
		RtlZeroMemory(&DbgkExitProcess, 8);
		memcpy(&DbgkExitProcess, pIoBuffer, sizeof(DbgkExitProcess));

		status = STATUS_SUCCESS;
		break;
	}


	case IOCTL_DbgkExitThread:
	{
		RtlZeroMemory(&DbgkExitThread, 8);
		memcpy(&DbgkExitThread, pIoBuffer, sizeof(DbgkExitThread));

		status = STATUS_SUCCESS;
		break;
	}


		////

	case IOCTL_ObTypeIndexTable:
	{
		RtlZeroMemory(&ObTypeIndexTable, 8);
		memcpy(&ObTypeIndexTable, pIoBuffer, sizeof(ObTypeIndexTable));

		DbgPrint(("RECV ObTypeIndexTable \n"));
		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_DbgkOpenProcessDebugPort:
	{
		RtlZeroMemory(&DbgkOpenProcessDebugPort, 8);
		memcpy(&DbgkOpenProcessDebugPort, pIoBuffer, sizeof(DbgkOpenProcessDebugPort));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkUnMapViewOfSection:
	{
		RtlZeroMemory(&DbgkUnMapViewOfSection, 8);
		memcpy(&DbgkUnMapViewOfSection, pIoBuffer, sizeof(DbgkUnMapViewOfSection));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkMapViewOfSection:
	{
		RtlZeroMemory(&DbgkMapViewOfSection, 8);
		memcpy(&DbgkMapViewOfSection, pIoBuffer, sizeof(DbgkMapViewOfSection));

		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_KiDispatchException:
	{
		RtlZeroMemory(&KiDispatchException, 8);
		memcpy(&KiDispatchException, pIoBuffer, sizeof(KiDispatchException));
		DbgPrint(("RECV ObTypeIndexTable \n"));
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkForwardException:
	{
		RtlZeroMemory(&DbgkForwardException, 8);
		memcpy(&DbgkForwardException, pIoBuffer, sizeof(DbgkForwardException));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_MmGetFileNameForSection:
	{
		RtlZeroMemory(&MmGetFileNameForSection, 8);
		memcpy(&MmGetFileNameForSection, pIoBuffer, sizeof(MmGetFileNameForSection));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PsGetNextProcess:
	{
		RtlZeroMemory(&PsGetNextProcess, 8);
		memcpy(&PsGetNextProcess, pIoBuffer, sizeof(PsGetNextProcess));

		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_DbgkpProcessDebugPortMutex:
	{
		RtlZeroMemory(&DbgkpProcessDebugPortMutex, 8);
		memcpy(&DbgkpProcessDebugPortMutex, pIoBuffer, sizeof(DbgkpProcessDebugPortMutex));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkCopyProcessDebugPort:
	{
		RtlZeroMemory(&DbgkCopyProcessDebugPort, 8);
		memcpy(&DbgkCopyProcessDebugPort, pIoBuffer, sizeof(DbgkCopyProcessDebugPort));

		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_DbgkDebugObjectType:
	{
		RtlZeroMemory(&DbgkDebugObjectType, 8);
		memcpy(&DbgkDebugObjectType, pIoBuffer, sizeof(DbgkDebugObjectType));

		status = STATUS_SUCCESS;
		break;
	}
		
		//////////////////////////////////////////////////////////////////////////
	case IOCTL_KiSaveDebugRegisterState:
	{
		RtlZeroMemory(&KiSaveDebugRegisterState, 8);
		memcpy(&KiSaveDebugRegisterState, pIoBuffer, sizeof(KiSaveDebugRegisterState));

		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_KiRestoreDebugRegisterState:
	{
		RtlZeroMemory(&KiRestoreDebugRegisterState, 8);
		memcpy(&KiRestoreDebugRegisterState, pIoBuffer, sizeof(KiRestoreDebugRegisterState));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KiUmsCallEntry:
	{
		RtlZeroMemory(&KiUmsCallEntry, 8);
		memcpy(&KiUmsCallEntry, pIoBuffer, sizeof(KiUmsCallEntry));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KiSystemServiceExit:
	{
		RtlZeroMemory(&KiSystemServiceExit, 8);
		memcpy(&KiSystemServiceExit, pIoBuffer, sizeof(KiSystemServiceExit));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KeGdiFlushUserBatch:
	{
		RtlZeroMemory(&KeGdiFlushUserBatch, 8);
		memcpy(&KeGdiFlushUserBatch, pIoBuffer, sizeof(KeGdiFlushUserBatch));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KiConvertToGuiThread:
	{
		RtlZeroMemory(&KiConvertToGuiThread, 8);
		memcpy(&KiConvertToGuiThread, pIoBuffer, sizeof(KiConvertToGuiThread));

		status = STATUS_SUCCESS;
		break;
	}

	case IOCTL_KiSystemServiceRepeat:
	{
		RtlZeroMemory(&KiSystemServiceRepeat, 8);
		memcpy(&KiSystemServiceRepeat, pIoBuffer, sizeof(KiSystemServiceRepeat));
		KiSystemServiceRepeat = KiSystemServiceRepeat + 0x3C;
		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KiSystemServiceCopyEnd:
	{
		RtlZeroMemory(&KiSystemServiceCopyEnd, 8);
		memcpy(&KiSystemServiceCopyEnd, pIoBuffer, sizeof(KiSystemServiceCopyEnd));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KeServiceDescriptorTable:
	{
		RtlZeroMemory(&KeServiceDescriptorTable, 8);
		memcpy(&KeServiceDescriptorTable, pIoBuffer, sizeof(KeServiceDescriptorTable));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_DbgkpPostFakeThreadMessages:
	{
		RtlZeroMemory(&DbgkpPostFakeThreadMessages, 8);
		memcpy(&DbgkpPostFakeThreadMessages, pIoBuffer, sizeof(DbgkpPostFakeThreadMessages));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PsSuspendThread:
	{
		RtlZeroMemory(&PsSuspendThread, 8);
		memcpy(&PsSuspendThread, pIoBuffer, sizeof(PsSuspendThread));

		status = STATUS_SUCCESS;
		break;
	}
		

	case IOCTL_KeFreezeAllThreads:
		{
		RtlZeroMemory(&KeFreezeAllThreads, 8);
		memcpy(&KeFreezeAllThreads, pIoBuffer, sizeof(KeFreezeAllThreads));

			status = STATUS_SUCCESS;
			break;
		}
	case IOCTL_PsResumeThread:
	{
		RtlZeroMemory(&PsResumeThread, 8);
		memcpy(&PsResumeThread, pIoBuffer, sizeof(PsResumeThread));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KeThawAllThreads:
	{
		RtlZeroMemory(&KeThawAllThreads, 8);
		memcpy(&KeThawAllThreads, pIoBuffer, sizeof(KeThawAllThreads));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PsGetNextProcessThread:
	{
		RtlZeroMemory(&PsGetNextProcessThread, 8);
		memcpy(&PsGetNextProcessThread, pIoBuffer, sizeof(PsGetNextProcessThread));

		status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_KiRetireDpcList:
	{
		RtlZeroMemory(&KiRetireDpcList, 8);
		memcpy(&KiRetireDpcList, pIoBuffer, sizeof(KiRetireDpcList));

		status = STATUS_SUCCESS;
		break;
	}

		

	case IOCTL_DbgkpPostModuleMessages:
	{
		RtlZeroMemory(&DbgkpPostModuleMessages, 8);
		memcpy(&DbgkpPostModuleMessages, pIoBuffer, sizeof(DbgkpPostModuleMessages));

		status = STATUS_SUCCESS;
		break;
	}
		
	case IOCTL_KeServiceDescriptorTableShadow:
	{
		RtlZeroMemory(&KeServiceDescriptorTableShadow, 8);
		memcpy(&KeServiceDescriptorTableShadow, pIoBuffer, sizeof(KeServiceDescriptorTableShadow));

		status = STATUS_SUCCESS;
		break;
	}
		//////////////////////////////////////////////////////////////////////////
/**	case ISrecv:
	{


				

							status = STATUS_SUCCESS;
							break;
	}*/
	}
	//这里设定DeviceIoControl的*lpBytesReturned的值（如果通信失败则返回0长度）
	if (status == STATUS_SUCCESS)
		pIrp->IoStatus.Information = uOutSize;
	else
		pIrp->IoStatus.Information = 0;
	//这里设定DeviceIoControl的返回值是成功还是失败
	pIrp->IoStatus.Status = status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	
	return status;
	//VMProtectEnd();
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{




	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
VOID NTAPI RegSetCr3(
	PVOID NewCr3
	)
{
	__writecr3((ULONG64)NewCr3);

}
//切入客户机进程空间
ULONG64 NTAPI AttachGuestProcess(ULONG64 GuestCr3)
{
	ULONG64 OldCr3 = GuestCr3;
	RegSetCr3(GuestCr3);//切换到用户进程空间
	return OldCr3;
}

//切出到原来的进程空间
VOID NTAPI DetachTargetProcess(ULONG64 OldCR3)
{
	RegSetCr3(OldCR3);//切换到用户进程空间


}
/*
BOOLEAN


PageFaultHandler(
PStackFrame StrackFrame
)
{
	UINT64         *PageTable;
	UINT64         PFAddress;

	ULONG64 CR3X;
	PFAddress = _Cr2();

	if (oldGuestRip == TargetAddress && IoGetCurrentProcess() == TargetProcess){
		CR3X=AttachGuestProcess(oldCr3);
		
		
		DetachTargetProcess(CR3X);
		return TRUE;
	}
	
	//__debugbreak();
	return FALSE;
}
*/

NTSTATUS LoadHV(){


	// Check hardware support
	if (!HvmIsHVSupported())
	{
		DPRINT("HyperBone: CPU %d: %s: VMX/AMD-V is not supported, aborting\n", CPU_IDX, __FUNCTION__);
		return STATUS_HV_FEATURE_UNAVAILABLE;
	}

	// Initialize internal structures
	if (UtilSSDTEntry(0) == 0)
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to Get SSDT/Kernel base, can't continue\n", CPU_IDX, __FUNCTION__);
		return STATUS_UNSUCCESSFUL;
	}

	g_Data = AllocGlobalData();
	if (g_Data == NULL)
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to allocate global data\n", CPU_IDX, __FUNCTION__);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Get physical memory regions
	if (!NT_SUCCESS(UtilQueryPhysicalMemory()))
	{
		DPRINT("HyperBone: CPU %d: %s: Failed to query physical memory ranges\n", CPU_IDX, __FUNCTION__);
		FreeGlobalData(g_Data);
		return STATUS_UNSUCCESSFUL;
	}

	// Fill available CPU features
	HvmCheckFeatures();

	DPRINT("HyperBone: CPU %d: %s: Subverting started...\n", CPU_IDX, __FUNCTION__);
	if (!NT_SUCCESS(StartHV()))
	{
		DPRINT("HyperBone: CPU %d: %s: StartHV() failed\n", CPU_IDX, __FUNCTION__);
		FreeGlobalData(g_Data);
		return STATUS_UNSUCCESSFUL;
	}


	MainVtMode = TRUE;
	DPRINT("HyperBone: CPU %d: %s: Subverting finished\n", CPU_IDX, __FUNCTION__);

//	TestStart(FALSE, FALSE, TRUE);

}
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING RegistryPath)
{

	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName;
	UNICODE_STRING ustrDevName;
	
	NTSTATUS Status;
	

	//设置分发函数和卸载例程
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	//创建一个设备
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);
	if (!NT_SUCCESS(status))	return status;
	//判断支持的WDM版本，其实这个已经不需要了，纯属WIN9X和WINNT并存时代的残留物
	if (IoIsWdmVersionAvailable(1, 0x10))
		RtlInitUnicodeString(&ustrLinkName, LINK_GLOBAL_NAME);
	else
		RtlInitUnicodeString(&ustrLinkName, LINK_NAME);
	//创建符号连接
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(pDevObj);
		return status;
	}

	DbgPrint("VV-DBG \n");
	PmainList = createlist();//创建记录DBG工具的链表

	LDE_init();
	BypassCheckSign(pDriverObj);
	InitialzeDbgprocessList();//初始化调试信息链表
	if (OpenVtMode)
	{
		InitialzeR3EPTHOOK();//初始化R3内存欺骗
		LoadHV();//加载VT模式
	}

	


//	PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)LoadImageNotifyRoutine);
    return STATUS_SUCCESS;
}


