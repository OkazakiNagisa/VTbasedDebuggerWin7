#include "ntddk.h"
#include "dbgtool.h"
#include "DRRWE.h"
#include "KernelStruct.h "
#include "intrin.h"
#include <ntimage.h>
#include "VMProtectDDK.h"
#include "./Hooks/PageHook.h"
typedef struct _ReadWriteR3MemData{

	HANDLE ProcessHandle;
	PVOID BaseAddress;
	PVOID Buffer;
	ULONG BufferLength;
	PULONG ReturnLength;
	BOOLEAN IsReadOrWrite;
	NTSTATUS Status;

}ReadWriteR3MemData, *PReadWriteR3MemData;
extern PDEVICE_OBJECT pDevObj;
static KSPIN_LOCK KrwLock = NULL;
KEVENT KwaitForReadOrWrite;


ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 funcstr);
extern BOOLEAN VtMode;
//////////////

/////////////

NTKERNELAPI char* PsGetProcessImageFileName(PEPROCESS Process);
typedef ULONG(__fastcall *pfNtOpenProcess)(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK AccessMask,
	__in PVOID ObjectAttributes,
	__in PCLIENT_ID ClientId);
typedef signed __int64(__fastcall *pfNtReadVirtualMemory)(PHANDLE ProcessHandle, unsigned __int64 AccessMode, __int64 a3, __int64 a4, unsigned __int64 a5);
typedef signed __int64(__fastcall *pfNtWriteVirtualMemory)(PHANDLE ProcessHandle, __int64 a2, unsigned __int64 AccessMode, __int64 a4, unsigned __int64 a5);
pfNtWriteVirtualMemory PwriteMem = NULL;
pfNtReadVirtualMemory PreadMem = NULL;
extern pfNtOpenProcess XNtOpenProcess;
extern pfNtWriteVirtualMemory NtWriteVirtualMemory;
extern pfNtReadVirtualMemory NtReadVirtualMemory;

#define WOW64_MAXIMUM_SUPPORTED_EXTENSION     512
#define WOW64_SIZE_OF_80387_REGISTERS      80
typedef  LONG DWORD;
typedef  INT16 WORD;
typedef char BYTE;
extern p_save_handlentry PmainList;
static KSPIN_LOCK local_lock;
ULONG64 KiRestoreDebugRegisterState;
extern ULONG64 KiSaveDebugRegisterState;
ULONG64 KiAttachProcess;
typedef NTSTATUS (__fastcall* pfKiAttachProcess)(
	IN PKTHREAD Thread,
	IN PKPROCESS Process,
	IN PKLOCK_QUEUE_HANDLE ApcLock,
	IN PRKAPC_STATE SavedApcState);

typedef struct _WOW64_FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	char    RegisterArea[WOW64_SIZE_OF_80387_REGISTERS];
	DWORD   Cr0NpxState;
} WOW64_FLOATING_SAVE_AREA;

typedef WOW64_FLOATING_SAVE_AREA *PWOW64_FLOATING_SAVE_AREA;
typedef struct _WOW64_CONTEXT {

	//
	// The flags values within this flag control the contents of
	// a CONTEXT record.
	//
	// If the context record is used as an input parameter, then
	// for each portion of the context record controlled by a flag
	// whose value is set, it is assumed that that portion of the
	// context record contains valid context. If the context record
	// is being used to modify a threads context, then only that
	// portion of the threads context will be modified.
	//
	// If the context record is used as an IN OUT parameter to capture
	// the context of a thread, then only those portions of the thread's
	// context corresponding to set flags will be returned.
	//
	// The context record is never used as an OUT only parameter.
	//

	DWORD ContextFlags;

	//
	// This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
	// set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
	// included in CONTEXT_FULL.
	//

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
	//

	WOW64_FLOATING_SAVE_AREA FloatSave;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_SEGMENTS.
	//

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_INTEGER.
	//

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	//
	// This section is specified/returned if the
	// ContextFlags word contians the flag CONTEXT_CONTROL.
	//

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;              // MUST BE SANITIZED
	DWORD   EFlags;             // MUST BE SANITIZED
	DWORD   Esp;
	DWORD   SegSs;

	//
	// This section is specified/returned if the ContextFlags word
	// contains the flag CONTEXT_EXTENDED_REGISTERS.
	// The format and contexts are processor specific
	//

char    ExtendedRegisters[WOW64_MAXIMUM_SUPPORTED_EXTENSION];

} WOW64_CONTEXT;

typedef WOW64_CONTEXT *PWOW64_CONTEXT;
/*
typedef struct DECLSPEC_ALIGN(16) _M128A{
	ULONGLONG Low;
	LONGLONG High;
} M128A, *PM128A;
*/

// 
// Format of data for 32-bit fxsave/fxrstor instructions. 
// 

typedef struct _XMM_SAVE_AREA321 {
	WORD   ControlWord;
	WORD   StatusWord;
	BYTE  TagWord;
	BYTE  Reserved1;
	WORD   ErrorOpcode;
	DWORD ErrorOffset;
	WORD   ErrorSelector;
	WORD   Reserved2;
	DWORD DataOffset;
	WORD   DataSelector;
	WORD   Reserved3;
	DWORD MxCsr;
	DWORD MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[16];
	BYTE  Reserved4[96];
} XMM_SAVE_AREA321, *PXMM_SAVE_AREA321;

#define LEGACY_SAVE_AREA_LENGTH sizeof(XMM_SAVE_AREA32) 



typedef struct DECLSPEC_ALIGN(16) _myCONTEXT{

	

	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;



	DWORD ContextFlags;
	DWORD MxCsr;


	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;


	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;


	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;

	

	DWORD64 Rip;

	
	union {
		XMM_SAVE_AREA321 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		};
	};

	

	M128A VectorRegister[26];
	DWORD64 VectorControl;

	// 
	// Special debug control registers. 
	// 

	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} myCONTEXT, *PmyCONTEXT;
void GetKernelModuleBase(char* lpModuleName, ULONG64 *ByRefBase, ULONG *ByRefSize);
typedef struct _HOOK_64BIT{
	PVOID orgcode;

	PVOID orgcodenumber;
	PVOID FreeSpacebyte;

}HOOK_64BIT, *PHOOK_64BIT;
extern p_save_handlentry PmainList;
ULONG RtlWalkFrameChain(OUT PVOID *Callers, IN ULONG Count, IN ULONG Flags);
PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID *Original_ApiAddress, OUT ULONG *PatchSize);
VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);
NTKERNELAPI PEPROCESS IoThreadToProcess(IN PETHREAD Thread);
PVOID HookKernelApi4_6bit(IN ULONG64 ApiAddress, IN PVOID Proxy_ApiAddress, PHOOK_64BIT structb);
VOID UnHookKernelApi4_6bit(IN ULONG64 ApiAddress, PHOOK_64BIT structb);
ULONG64 ExCompareExchangeCallBack;
ULONG64 ObpCallPreOperationCallbacks;
ULONG64 ExGetCallBackBlockRoutine;
ULONG64 NtQueryInformationThread;
typedef __int64(__fastcall *pfObpCallPreOperationCallbacks)(__int64 a1, __int64 a2, __int64 a3);
typedef __int64(__fastcall *pfExGetCallBackBlockRoutine)(__int64 a1);
typedef BOOLEAN(__fastcall *pfExCompareExchangeCallBack)(ULONG64 a1,ULONG64 a2,ULONG64 a3);
typedef NTSTATUS(__fastcall *pfNtQueryInformationThread)(IN   HANDLE   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT   PVOID   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT   PULONG   ReturnLength   OPTIONAL
	);
NTSTATUS PsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process);
NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD *Thread);
pfNtQueryInformationThread orgNtQueryInformationThread;
typedef (__fastcall *pfnNtReadVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef (__fastcall *pfnNtWriteVirtualMemory)(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	);
typedef NTSTATUS(__fastcall*pfNtSetInformationThread)(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);

ULONG pslp_patch_size9 = 0;		//ObpCallPreOperationCallbacks被修改了N字节
PUCHAR pslp_head_n_byte9 = NULL;	//ObpCallPreOperationCallbacks的前N字节数组
PVOID ori_pslp9 = NULL;			//ObpCallPreOperationCallbacks的原函数

ULONG pslp_patch_size10 = 0;		//ExGetCallBackBlockRoutine被修改了N字节
PUCHAR pslp_head_n_byte10 = NULL;	//ExGetCallBackBlockRoutine的前N字节数组
PVOID ori_pslp10 = NULL;			//ExGetCallBackBlockRoutine的原函数

ULONG pslp_patch_size19 = 0;		//NtQueryInformationThread被修改了N字节
PUCHAR pslp_head_n_byte19 = NULL;	//NtQueryInformationThread的前N字节数组
PVOID ori_pslp19 = NULL;			//NtQueryInformationThread的原函数


ULONG pslp_patch_size20 = 0;		//ExCompareExchangeCallBack被修改了N字节
PUCHAR pslp_head_n_byte20 = NULL;	//ExCompareExchangeCallBack的前N字节数组
PVOID ori_pslp20 = NULL;			//ExCompareExchangeCallBack的原函数


ULONG pslp_patch_size21 = 0;		//proxyPsLookupThreadByThreadId被修改了N字节
PUCHAR pslp_head_n_byte21 = NULL;	//proxyPsLookupThreadByThreadId的前N字节数组
PVOID ori_pslp21 = NULL;			//proxyPsLookupThreadByThreadId的原函数


ULONG pslp_patch_size22 = 0;		//proxyPsLookupProcessByProcessId被修改了N字节
PUCHAR pslp_head_n_byte22 = NULL;	//proxyPsLookupProcessByProcessId的前N字节数组
PVOID ori_pslp22 = NULL;			//proxyPsLookupProcessByProcessId的原函数


ULONG pslp_patch_size23 = 0;		//KiRestoreDebugRegisterState被修改了N字节
PUCHAR pslp_head_n_byte23 = NULL;	//KiRestoreDebugRegisterState的前N字节数组
PVOID ori_pslp23 = NULL;			//KiRestoreDebugRegisterState的原函数


ULONG pslp_patch_size24= 0;		//KiSaveDebugRegisterState被修改了N字节
PUCHAR pslp_head_n_byte24 = NULL;	//KiSaveDebugRegisterState的前N字节数组
PVOID ori_pslp24 = NULL;			//KiSaveDebugRegisterState的原函数


ULONG pslp_patch_size25 = 0;		//RtlpCopyLegacyContextX86被修改了N字节
PUCHAR pslp_head_n_byte25 = NULL;	//RtlpCopyLegacyContextX86的前N字节数组
PVOID ori_pslp25 = NULL;			//RtlpCopyLegacyContextX86的原函数

ULONG pslp_patch_size26 = 0;		//pfKiAttachProcess被修改了N字节
PUCHAR pslp_head_n_byte26 = NULL;	//pfKiAttachProcess的前N字节数组
pfKiAttachProcess ori_pslp26 = NULL;			//pfKiAttachProcess的原函数

ULONG pslp_patch_size27 = 0;		//ReadProcessMemory被修改了N字节
PUCHAR pslp_head_n_byte27 = NULL;	//ReadProcessMemory的前N字节数组
pfnNtReadVirtualMemory ori_pslp27 = NULL;			//ReadProcessMemory的原函数

ULONG pslp_patch_size28 = 0;		//WriteProcessMemory被修改了N字节
PUCHAR pslp_head_n_byte28 = NULL;	//WriteProcessMemory的前N字节数组
pfnNtWriteVirtualMemory ori_pslp28 = NULL;			//WriteProcessMemory的原函数


ULONG64 RtlpCopyLegacyContextX86 = NULL;
ULONG64	KrnlBase = 0;
ULONG	KrnlSize = 0;
HOOK_64BIT orgcode;
typedef NTSTATUS(__fastcall *pfPsLookupProcessByProcessId)(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process);
typedef  NTSTATUS(__fastcall *pfPsLookupThreadByThreadId)(_In_ HANDLE ThreadId, _Outptr_ PETHREAD *Thread);
extern __fastcall myKiSaveDebugRegisterState();
extern __fastcall myKiRestoreDebugRegisterState();
ULONG64 _Search64Process(char *szProcessName, ULONG64 callBackFUNC);
NTSTATUS
NTAPI
NtSetInformationThread(
_In_ HANDLE ThreadHandle,
_In_ THREADINFOCLASS ThreadInformationClass,
_In_reads_bytes_(ThreadInformationLength) PVOID ThreadInformation,
_In_ ULONG ThreadInformationLength
);

__int64   __fastcall proxyKiAttachProcess(
	IN PKTHREAD Thread,
	IN PKPROCESS Process,
	IN PKLOCK_QUEUE_HANDLE ApcLock,
	IN PRKAPC_STATE SavedApcState)
{
	PEPROCESS g_Guiprocess = NULL;
	char *CallProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
	if (strstr(CallProcessName,"System")!=NULL || PsGetCurrentProcessId()==4)
	{
		return ori_pslp26(Thread, Process, ApcLock, SavedApcState);
	}
	p_save_handlentry Padd = NULL;
	
	Padd = querylist(PmainList, NULL, Process);

	if (Padd != NULL)
	{
		Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
		if (Padd!=NULL)
	{
			return ori_pslp26(Thread, Process, ApcLock, SavedApcState);
	}
		g_Guiprocess = _Search64Process("csrss", 0);

		DbgPrint(" myProcessName:%s \n", PsGetProcessImageFileName(PsGetCurrentProcess()));
		return ori_pslp26(Thread, g_Guiprocess, ApcLock, SavedApcState);;
	}
	return ori_pslp26(Thread, Process, ApcLock, SavedApcState);
}


__int64 __fastcall proxyObpCallPreOperationCallbacks(__int64 a1, __int64 a2, __int64 a3){
	if (VtMode)
	{
		PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(ObpCallPreOperationCallbacks);
		ori_pslp9 = pEntry->OriginalData;
	}
	
	p_save_handlentry Padd;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL){
	
		return ((pfObpCallPreOperationCallbacks)ori_pslp9)(a1, a2, a3);//不是我们的进程操作进程对象就调用原来函数

	
	}
	else{
		return 0;//放行
	}

	
	

	return ((pfObpCallPreOperationCallbacks)ori_pslp9)(a1, a2, a3);//不是我们的进程操作进程对象就调用原来函数return 0;//放行
}
VOID proxyListFunc(_In_ HANDLE ParentId, _In_ HANDLE ProcessId, _In_ BOOLEAN Create){
	
	return ;

}


/*

NTSTATUS myNtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength){
	PEPROCESS_S Process = NULL;
	PETHREAD Thread = NULL;
	p_save_handlentry Padd = NULL;
	NTSTATUS Sstatus;
	NTSTATUS status=STATUS_SUCCESS;
	PPROCESS_List PlIST = NULL;;
	PTHREAD_dr_List TList = NULL;
	THREAD_dr_List t = {0};
	PKTRAP_FRAME pframe = NULL;
	PWOW64_CONTEXT contex = threadInformation;
	WOW64_CONTEXT mycontex = { 0 };
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
		status = NtSetInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength);

		return status;

	}
	Sstatus = ObReferenceObjectByHandle(threadHandle,
		THREAD_ALL_ACCESS,
		*PsThreadType,
		KernelMode,
		(PVOID*)&Thread,
		NULL);
	if (!NT_SUCCESS(Sstatus)){
		return Sstatus;

	}
	ObDereferenceObject(Thread);
	Process = IoThreadToProcess(Thread);
	if (Process!=NULL)
	{
		Padd = querylist(PmainList, 0x10086, Process);
		if (Padd != NULL)
		{
			status = NtSetInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength);

			return status;

		}

	}

	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd != NULL)
	{
		if (threadInformationClass == ThreadWow64Context && threadInformationLength == 0x2CC && threadInformation != NULL && threadHandle != NULL)//ThreadWow64Context 
		{
			Sstatus = ObReferenceObjectByHandle(threadHandle,
				THREAD_ALL_ACCESS,
				*PsThreadType,
				KernelMode,
				(PVOID*)&Thread,
				NULL);
			if (!NT_SUCCESS(Sstatus)){

				return STATUS_SUCCESS;

			}


			BOOLEAN lock = FALSE;
			lock = ExAcquireRundownProtection(&Thread->RundownProtect);
			if (MmIsAddressValid(Thread) != TRUE || lock != TRUE)
			{
				return;

			}
			pframe = Thread->Tcb.TrapFrame;
			if ((pframe != NULL) && MmIsAddressValid(&pframe->Dr0) && MmIsAddressValid(&pframe->Dr1) && MmIsAddressValid(&pframe->Dr2) && MmIsAddressValid(&pframe->Dr3) && MmIsAddressValid(&pframe->Dr6) && MmIsAddressValid(&pframe->Dr7))
			{
				if (contex->Dr7 != NULL)
				{
					*(UCHAR*)(Thread + 0x3) = 0x40;

				}

				mycontex.Dr0 = contex->Dr0;
				mycontex.Dr1 = contex->Dr1;
				mycontex.Dr2 = contex->Dr2;
				mycontex.Dr3 = contex->Dr3;
				mycontex.Dr6 = contex->Dr6;
				mycontex.Dr7 = contex->Dr7;
				mycontex.EFlags = contex->EFlags;
				contex->Dr0 = ((PLARGE_INTEGER)(&pframe->Dr0))->LowPart;
				contex->Dr1 = ((PLARGE_INTEGER)(&pframe->Dr1))->LowPart;
				contex->Dr2 = ((PLARGE_INTEGER)(&pframe->Dr2))->LowPart;
				contex->Dr3 = ((PLARGE_INTEGER)(&pframe->Dr3))->LowPart;
				contex->Dr6 = ((PLARGE_INTEGER)(&pframe->Dr6))->LowPart;
			//	contex->Dr7 = ((PLARGE_INTEGER)(&pframe->Dr7))->LowPart;
			//	contex->EFlags = pframe->EFlags;




			}

			ExReleaseRundownProtection(&Thread->RundownProtect);
			//DbgPrint("thread: %p", Thread);
			//OD设置线程上下文的时候DR我们设置成线程自己的
			status = NtSetInformationThread(threadHandle, threadInformationClass, threadInformation, threadInformationLength);
			contex->Dr0=mycontex.Dr0;
			contex->Dr1 = mycontex.Dr1;
			contex->Dr2 = mycontex.Dr2;
			contex->Dr3 = mycontex.Dr3;
			contex->Dr6 = mycontex.Dr6;
			contex->Dr7 = mycontex.Dr7;
		

			DbgPrint("SET thread: %p dr0: %d dr1 :%d dr2 :%d dr3 :%d dr6:%d dr7:%d", Thread, contex->Dr0, contex->Dr1, contex->Dr2, contex->Dr3, contex->Dr6, contex->Dr7);

			ObDereferenceObject(Thread);


		}



	}



	if (threadInformationClass == ThreadWow64Context && threadInformationLength == 0x2CC && threadInformation != NULL && threadHandle != NULL)//ThreadWow64Context 
	{
		Sstatus = ObReferenceObjectByHandle(threadHandle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			(PVOID*)&Thread,
			NULL);
		if (!NT_SUCCESS(Sstatus)){

			return STATUS_SUCCESS;

		}

		ObDereferenceObject(Thread);

		if (NT_SUCCESS(Sstatus)){

			Process = IoThreadToProcess(Thread);
			if (Process==NULL)
			{
				return STATUS_SUCCESS;
			}

			PlIST = Dr_FindProcessList(Process);
			if (PlIST != NULL){
			
				///////////
				TList = Dr_FindThreadContextByThreadList(PlIST, Thread);
				if (TList != NULL)
				{
					t.Dr0 = mycontex.Dr0;
					t.Dr1 = mycontex.Dr1;
					t.Dr2 = mycontex.Dr2;
					t.Dr3 = mycontex.Dr3;
					t.Dr6 = mycontex.Dr6;
					t.Dr7 = mycontex.Dr7;
					t.eflag = mycontex.EFlags;
					t.Thread = Thread;
					Dr_UpdataThreadContextByThreadList(PlIST, Thread, &t);
				}
				else
				{

					t.Dr0 = mycontex.Dr0;
					t.Dr1 = mycontex.Dr1;
					t.Dr2 = mycontex.Dr2;
					t.Dr3 = mycontex.Dr3;
					t.Dr6 = mycontex.Dr6;
					t.Dr7 = mycontex.Dr7;
					t.eflag = mycontex.EFlags;
					t.Thread = Thread;

					Dr_AddThreadStructToList(PlIST, &t);

				}

			
			}
			else
			{

				PlIST = Dr_AddProcessToList(Process);
				if (PlIST==NULL)
				{
					return STATUS_SUCCESS;
				}

			
				

				t.Dr0 = mycontex.Dr0;
				t.Dr1 = mycontex.Dr1;
				t.Dr2 = mycontex.Dr2;
				t.Dr3 = mycontex.Dr3;
				t.Dr6 = mycontex.Dr6;
				t.Dr7 = mycontex.Dr7;
				t.eflag = mycontex.EFlags;
					t.Thread = Thread;

					Dr_AddThreadStructToList(PlIST, &t);
				
			

				////////////


			}
			



		}
	}

	

	return STATUS_SUCCESS;
}
*/

/*
NTSTATUS __fastcall myNtQueryInformationThread(IN   HANDLE   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT   PVOID   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT   PULONG   ReturnLength   OPTIONAL
	){

	PEPROCESS_S Process = NULL;
	PETHREAD Thread = NULL;
	PPROCESS_List PlIST = NULL;;
	PTHREAD_dr_List TList = NULL;
	p_save_handlentry Padd = NULL;
	NTSTATUS Sstatus=STATUS_SUCCESS;
	PKTRAP_FRAME pframe = NULL;
	PWOW64_CONTEXT contex = ThreadInformation;
	NTSTATUS status = STATUS_SUCCESS;
	//orgNtQueryInformationThread = ori_pslp19;
	orgNtQueryInformationThread = NtQueryInformationThread;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd == NULL)
	{
		status = orgNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

		return status;

	}
	Sstatus = ObReferenceObjectByHandle(ThreadHandle,
		THREAD_ALL_ACCESS,
		*PsThreadType,
		KernelMode,
		(PVOID*)&Thread,
		NULL);
	if (!NT_SUCCESS(Sstatus)){
		return Sstatus;

	}
	ObDereferenceObject(Thread);
	Process = IoThreadToProcess(Thread);
	if (Process != NULL)
	{
		Padd = querylist(PmainList, 0x10086, Process);
		if (Padd != NULL)
		{
			status = orgNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

			return status;

		}

	}

	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd != NULL)
	{
		if (ThreadInformationClass == ThreadWow64Context && ThreadInformationLength == 0x2CC && ThreadInformation != NULL && ThreadHandle != NULL)//ThreadWow64Context 
		{
			Sstatus = ObReferenceObjectByHandle(ThreadHandle,
				THREAD_ALL_ACCESS,
				*PsThreadType,
				KernelMode,
				(PVOID*)&Thread,
				NULL);
			if (!NT_SUCCESS(Sstatus)){

				return STATUS_SUCCESS;

			}


			BOOLEAN lock = FALSE;
			lock = ExAcquireRundownProtection(&Thread->RundownProtect);
			if (MmIsAddressValid(Thread) != TRUE || lock != TRUE)
			{
				return;

			}
			pframe = Thread->Tcb.TrapFrame;
			if ((pframe != NULL) && MmIsAddressValid(&pframe->Dr0) && MmIsAddressValid(&pframe->Dr1) && MmIsAddressValid(&pframe->Dr2) && MmIsAddressValid(&pframe->Dr3) && MmIsAddressValid(&pframe->Dr6) && MmIsAddressValid(&pframe->Dr7))
			{



				/ *	contex->Dr0 = ((PLARGE_INTEGER)(&pframe->Dr0))->LowPart;
				contex->Dr1 = ((PLARGE_INTEGER)(&pframe->Dr1))->LowPart;
				contex->Dr2 = ((PLARGE_INTEGER)(&pframe->Dr2))->LowPart;
				contex->Dr3 = ((PLARGE_INTEGER)(&pframe->Dr3))->LowPart;
				contex->Dr6 = ((PLARGE_INTEGER)(&pframe->Dr6))->LowPart;
				contex->Dr7 = ((PLARGE_INTEGER)(&pframe->Dr7))->LowPart;
				contex->EFlags = pframe->EFlags;* /

				

			}

			ExReleaseRundownProtection(&Thread->RundownProtect);
			//DbgPrint("thread: %p", Thread);
			//OD设置线程上下文的时候DR我们设置成线程自己的
			status = orgNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);

			

			ObDereferenceObject(Thread);


		}

		
	}


	if (ThreadInformationClass == ThreadWow64Context && ThreadInformationLength == 0x2CC && ThreadInformation != NULL && ThreadHandle != NULL)//ThreadWow64Context 
	{
		Sstatus = ObReferenceObjectByHandle(ThreadHandle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			(PVOID*)&Thread,
			NULL);
		if (!NT_SUCCESS(Sstatus)){

			return status;

		}

		ObDereferenceObject(Thread);

		if (NT_SUCCESS(Sstatus)){


			Process = IoThreadToProcess(Thread);
			if (Process != NULL){

				PlIST = Dr_FindProcessList(Process);
				if (PlIST != NULL)
				{

					TList = Dr_FindThreadContextByThreadList(PlIST, Thread);
					if (TList != NULL)
					{
						contex->Dr0 = TList->Dr0;
						contex->Dr1 = TList->Dr1;
						contex->Dr2 = TList->Dr2;
						contex->Dr3 = TList->Dr3;
						contex->Dr6 = TList->Dr6;
						contex->Dr7 = TList->Dr7;
						contex->EFlags = TList->eflag;

						DbgPrint(" QUERY thread: %p dr0: %d dr1 :%d dr2 :%d dr3 :%d dr6:%d dr7:%d", Thread, contex->Dr0, contex->Dr1, contex->Dr2, contex->Dr3, contex->Dr6, contex->Dr7);



					}


				}





			}

		}


		return status;
	}

	return status;


	//PspWow64GetContextThreadOnAmd64_0 ETHREAD/ MODE/ THREADINFORMATION


}*/


NTSTATUS __fastcall myNtQueryInformationThread(IN   HANDLE   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT   PVOID   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT   PULONG   ReturnLength   OPTIONAL
	){
	//VMProtectBegin("myNtQueryInformationThread");

	if (VtMode)
	{
		PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(NtQueryInformationThread);
		ori_pslp19 = pEntry->OriginalData;
	}
	PEPROCESS_S Process=NULL;
	PETHREAD Thread = NULL;
	PPROCESS_List PlIST = NULL;;
	PTHREAD_dr_List TList = NULL;
	p_save_handlentry Padd = NULL;
	NTSTATUS Sstatus;
	PWOW64_CONTEXT contex = ThreadInformation;
	NTSTATUS status;
	orgNtQueryInformationThread = ori_pslp19;
	//orgNtQueryInformationThread = NtQueryInformationThread;

	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	status=orgNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
	if (Padd!=NULL)
	{
		return status;

	}
	
	
	if (ThreadInformationClass == ThreadWow64Context && ThreadInformationLength == 0x2CC && ThreadInformation != NULL && ThreadHandle!=NULL)//ThreadWow64Context 
	{
		Sstatus = ObReferenceObjectByHandle(ThreadHandle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			(PVOID*)&Thread,
			NULL);
		if (!NT_SUCCESS(Sstatus)){

			return status;
			
		}

		ObDereferenceObject(Thread);
		
		if (NT_SUCCESS(Sstatus)){
		
		
			Process = IoThreadToProcess(Thread);
			if (Process != NULL){
		
				PlIST = Dr_FindProcessList(Process);
				if (PlIST!=NULL)
				{

					TList = Dr_FindThreadContextByThreadList(PlIST, Thread);
					if (TList!=NULL)
					{
						contex->Dr0 = TList->Dr0;
						contex->Dr1 = TList->Dr1;
						contex->Dr2 = TList->Dr2;
						contex->Dr3 = TList->Dr3;
						contex->Dr6 = TList->Dr6;
						contex->Dr7 = TList->Dr7;
						contex->EFlags = TList->eflag;




					}
					else
					{
						contex->Dr0 = NULL;
						contex->Dr1 = NULL;
						contex->Dr2 = NULL;
						contex->Dr3 = NULL;
						contex->Dr6 = NULL;
						contex->Dr7 = NULL;
						contex->EFlags &= ~0x100;
					}


				}
			
			
			
			
			
			}

		}

		
		return status;
	} 
	return status;
	
//	VMProtectEnd();
	//PspWow64GetContextThreadOnAmd64_0 ETHREAD/ MODE/ THREADINFORMATION


}

void *__fastcall myRtlpCopyLegacyContextX86(BOOLEAN islegacy, PWOW64_CONTEXT destcontex, ULONG nouse_falg, PWOW64_CONTEXT srccontext)
{
//VMProtectBegin("myRtlpCopyLegacyContextX86");
	void *result = 0x10020;;
	PETHREAD Thread = NULL;
	PEPROCESS Process = NULL;
	PPROCESS_List PlIST = NULL;
	PTHREAD_dr_List TList = NULL;
	Thread = PsGetCurrentThread();
	if (islegacy)
	{
		destcontex->ContextFlags = srccontext->ContextFlags;


		//dr
		////// 



		//////////////////////////////////



	
			
			

		if (Thread!=NULL){


				Process = IoThreadToProcess(Thread);
				if (Process != NULL){

					PlIST = Dr_FindProcessList(Process);
					if (PlIST != NULL)
					{

						TList = Dr_FindThreadContextByThreadList(PlIST, Thread);
						if (TList != NULL)
						{
							destcontex->Dr0 = TList->Dr0;
							destcontex->Dr1 = TList->Dr1;
							destcontex->Dr2 = TList->Dr2;
							destcontex->Dr3 = TList->Dr3;
							destcontex->Dr6 = TList->Dr6;
							destcontex->Dr7 = TList->Dr7;
							destcontex->EFlags = TList->eflag;




						}
						else
						{
							//////////////////////////////////////////////////////////////////////////

							destcontex->Dr0 = NULL;
							destcontex->Dr1 = NULL;
							destcontex->Dr2 = NULL;
							destcontex->Dr3 = NULL;
							destcontex->Dr6 = NULL;
							destcontex->Dr7 = NULL;
							destcontex->EFlags &= ~0x100;
							//////////////////////////////////////////////////////////////////////////
						}


					}
					else
					{
						destcontex->Dr0 = srccontext->Dr0;
						destcontex->Dr1 = srccontext->Dr1;
						destcontex->Dr2 = srccontext->Dr2;
						destcontex->Dr3 = srccontext->Dr3;
						destcontex->Dr6 = srccontext->Dr6;
						destcontex->Dr7 = srccontext->Dr7;
					}





				}

		}
		else{

			destcontex->Dr0 = srccontext->Dr0;
			destcontex->Dr1 = srccontext->Dr1;
			destcontex->Dr2 = srccontext->Dr2;
			destcontex->Dr3 = srccontext->Dr3;
			destcontex->Dr6 = srccontext->Dr6;
			destcontex->Dr7 = srccontext->Dr7;

		}


		



		///////////////////////////////////


		

		///////


		destcontex->Eax = srccontext->Eax;
		destcontex->Ebp = srccontext->Ebp;
		destcontex->Ebx = srccontext->Ebx;
		destcontex->Ecx = srccontext->Ecx;
		destcontex->Edi = srccontext->Edi;
		destcontex->Edx = srccontext->Edx;
		destcontex->EFlags = srccontext->EFlags;
		destcontex->Eip = srccontext->Eip;
		destcontex->Esi = srccontext->Esi;
		destcontex->Esp = srccontext->Esp;
		destcontex->SegCs = srccontext->SegCs;

		destcontex->SegDs = srccontext->SegDs;
		destcontex->SegEs = srccontext->SegEs;
		destcontex->SegFs = srccontext->SegFs;
		destcontex->SegGs = srccontext->SegGs;
		destcontex->SegSs = srccontext->SegSs;
		
		result = memmove(&destcontex->ExtendedRegisters, &srccontext->ExtendedRegisters, 0x200ui64);

		destcontex->FloatSave = srccontext->FloatSave;





	}
	return result;
//	VMProtectEnd();
}

VOID myKeContextFromKframes(PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame, PCONTEXT ContextFrame){





}
VOID __fastcall myKeContextToKframes(PKTRAP_FRAME TrapFrame, IN PKEXCEPTION_FRAME ExceptionFrame, PCONTEXT ContextFrame, ULONG CONTEXTFALG, KPROCESSOR_MODE  rMODE){





}
///////////



BOOLEAN IsProtectedProcess(PEPROCESS eprocess)
{
	UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
	p_save_handlentry Padd = NULL;
	Padd = querylist(PmainList, NULL, eprocess);
	
	/*
	char *processName = PsGetProcessImageFileName(PsGetCurrentProcess());
	char *processName2 = PsGetProcessImageFileName(eprocess);*/
	/*if (strstr(processName, "BlackCipher") != NULL && strstr(processName2, "cstrike-on") != NULL)///NGS Cant Read and Write Process MEmory!
	{
		
		return TRUE;
	}*/
	if (Padd != NULL ){
		if (eprocess==PsGetCurrentProcess())
{
			return FALSE;

		}
		else
		{
			return TRUE;
		}
	
	}
	return FALSE;
}

PVOID obHandle = NULL, obHandle2 = NULL;

OB_PREOP_CALLBACK_STATUS preCall(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
#define PROCESS_TERMINATE 0x1

	HANDLE pid;
	if (pOperationInformation->ObjectType != *PsProcessType)
		goto exit_sub;
	pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	//DbgPrint("[OBCALLBACK][Process]PID=%ld\n", pid);
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (IsProtectedProcess((PEPROCESS)pOperationInformation->Object))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;

			}
		}
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			//pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_CREATE_THREAD;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~PROCESS_QUERY_LIMITED_INFORMATION;
			}
		}
	}
exit_sub:
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS preCall2(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
#define THREAD_TERMINATE2 0x1
	PEPROCESS ep;
	PETHREAD et;
	HANDLE pid;
	if (pOperationInformation->ObjectType != *PsThreadType)
		goto exit_sub;
	et = (PETHREAD)pOperationInformation->Object;
	ep = IoThreadToProcess(et);
	pid = PsGetProcessId(ep);
	//DbgPrint("[OBCALLBACK][Thread]PID=%ld; TID=%ld\n", pid, PsGetThreadId(et));
	UNREFERENCED_PARAMETER(RegistrationContext);
	if (IsProtectedProcess(ep))
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			//pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			//pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess=0;
			if ((pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess & THREAD_TERMINATE2) == THREAD_TERMINATE2)
			{
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_TERMINATE2;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SUSPEND_RESUME;
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}
	}
exit_sub:
	return OB_PREOP_SUCCESS;
}

NTSTATUS ObProtectProcess(BOOLEAN Enable)
{
	if (Enable == TRUE)
	{
		NTSTATUS obst1 = 0, obst2 = 0;
		OB_CALLBACK_REGISTRATION obReg, obReg2;
		OB_OPERATION_REGISTRATION opReg, opReg2;
		//reg ob callback 1
		memset(&obReg, 0, sizeof(obReg));
		obReg.Version = ObGetFilterVersion();
		obReg.OperationRegistrationCount = 1;
		obReg.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg.Altitude, L"321124xz");
		obReg.OperationRegistration = &opReg;
		memset(&opReg, 0, sizeof(opReg));
		opReg.ObjectType = PsProcessType;
		opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall;
		obst1 = ObRegisterCallbacks(&obReg, &obHandle);
		//reg ob callback 2
		memset(&obReg2, 0, sizeof(obReg2));
		obReg2.Version = ObGetFilterVersion();
		obReg2.OperationRegistrationCount = 1;
		obReg2.RegistrationContext = NULL;
		RtlInitUnicodeString(&obReg2.Altitude, L"321125xz");
		obReg2.OperationRegistration = &opReg2;
		memset(&opReg2, 0, sizeof(opReg2));
		opReg2.ObjectType = PsThreadType;
		opReg2.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		opReg2.PreOperation = (POB_PRE_OPERATION_CALLBACK)&preCall2;
		obst1 = ObRegisterCallbacks(&obReg2, &obHandle2);
		return NT_SUCCESS(obst1) & NT_SUCCESS(obst2);
	}
	else
	{
		if (obHandle != NULL)
			ObUnRegisterCallbacks(obHandle);
		if (obHandle2 != NULL)
			ObUnRegisterCallbacks(obHandle2);
		return TRUE;
	}
}


//////////////


VOID RwWorkItem(
	_In_     PDEVICE_OBJECT DeviceObject,
	_In_opt_ PReadWriteR3MemData Data
	)
{
	DbgPrint("Address:%p IsRead:%d", Data->BaseAddress, Data->IsReadOrWrite);
	/*KPROCESSOR_MODE OldPreviousMode;
	OldPreviousMode = ExGetPreviousMode();
	((PETHREAD)PsGetCurrentThread())->Tcb.PreviousMode = UserMode;
	if (Data->IsReadOrWrite)
	{

		//读
		Data->Status = PreadMem(Data->ProcessHandle, Data->BaseAddress, Data->Buffer, Data->BufferLength, Data->ReturnLength);
	}
	else
	{

		//写

		Data->Status = PwriteMem(Data->ProcessHandle, Data->BaseAddress, Data->Buffer, Data->BufferLength, Data->ReturnLength);
	}
	((PETHREAD)PsGetCurrentThread())->Tcb.PreviousMode = OldPreviousMode;*/


	KeSetEvent(&KwaitForReadOrWrite, 0, TRUE);
	

}
VOID RW(PReadWriteR3MemData Data)
{
	DbgPrint("Address:%p IsRead:%d", Data->BaseAddress, Data->IsReadOrWrite);
	KPROCESSOR_MODE OldPreviousMode;
	OldPreviousMode = ExGetPreviousMode();
	//((PETHREAD)PsGetCurrentThread())->Tcb.PreviousMode = UserMode;
	if (Data->IsReadOrWrite)
	{

	//读
	//Data->Status = PreadMem(Data->ProcessHandle, Data->BaseAddress, Data->Buffer, Data->BufferLength, Data->ReturnLength);
	}
	else
	{

	//写

	//Data->Status = PwriteMem(Data->ProcessHandle, Data->BaseAddress, Data->Buffer, Data->BufferLength, Data->ReturnLength);
	}
	//((PETHREAD)PsGetCurrentThread())->Tcb.PreviousMode = OldPreviousMode;



	KeSetEvent(&KwaitForReadOrWrite, 0, TRUE);
	PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID ReadOrWriteR3Mem(PReadWriteR3MemData Data){
	KIRQL OldIrql;
	HANDLE     hThread;
	NTSTATUS status;
	//PIO_WORKITEM pIoWorkItem;
	//KeAcquireSpinLockAtDpcLevel(&KrwLock);
	//KeAcquireSpinLock(&KrwLock, &OldIrql);
	KeInitializeEvent(&KwaitForReadOrWrite, SynchronizationEvent, FALSE);
	

	status = PsCreateSystemThread(&hThread, 0, NULL, NULL, NULL, RW, Data);

/*
	pIoWorkItem = IoAllocateWorkItem(pDevObj);
	if (pIoWorkItem)
	{
		IoQueueWorkItem(pIoWorkItem, (PIO_WORKITEM_ROUTINE)RwWorkItem, DelayedWorkQueue, Data);
	}*/


	if (NT_SUCCESS(status))
	{
		ZwClose(hThread);
	
		KeWaitForSingleObject(&KwaitForReadOrWrite, Executive, KernelMode, FALSE, NULL);
	}


KeWaitForSingleObject(&KwaitForReadOrWrite, Executive, KernelMode, FALSE, NULL);
//IoFreeWorkItem(pIoWorkItem);
KeClearEvent(&KwaitForReadOrWrite);
	//KeReleaseSpinLockFromDpcLevel(&KrwLock);
	//KeReleaseSpinLock(&KrwLock, OldIrql);
}


NTSTATUS __fastcall MyNtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	
	if (VtMode)
	{
		PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(NtReadVirtualMemory);
		PreadMem = pEntry->OriginalData;
	}
	NTSTATUS Status;
	PEPROCESS Process;
	


	return ori_pslp27(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	/*PReadWriteR3MemData Pdata=NULL;
	p_save_handlentry Padd = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		ExGetPreviousMode(),
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	Pdata = ExAllocatePool(NonPagedPool, sizeof(ReadWriteR3MemData));





	
	if (Pdata==NULL)
	{
		return  PreadMem(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
		
	} else{
	
	Pdata->ProcessHandle = ProcessHandle;
		Pdata->BaseAddress = BaseAddress;
		Pdata->Buffer = Buffer;
		Pdata->BufferLength = BufferLength;
		Pdata->ReturnLength = ReturnLength;
		Pdata->IsReadOrWrite = TRUE;
		Pdata->Status = STATUS_ACCESS_DENIED;
		ReadOrWriteR3Mem(Pdata);
		ExFreePool(Pdata);
		return Pdata->Status;
	
	}*/
	/*ObDereferenceObject(Process);
	if (Process != NULL){
	Padd = querylist(PmainList, NULL, Process);
	if (Padd != NULL)
	{
	if (PsGetCurrentProcess() == Process){
	return NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	//yes
	}
	else{
	//no
	return STATUS_ACCESS_DENIED;
	}


	}

	}
	*/





	
}
NTSTATUS __fastcall MyNtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG BufferLength,
	OUT PULONG ReturnLength OPTIONAL
	)
{
	if (VtMode)
	{
		PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(NtWriteVirtualMemory);
		PwriteMem = pEntry->OriginalData;
	}
	NTSTATUS Status;
	PEPROCESS Process;

	return ori_pslp28(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
/*
	PReadWriteR3MemData Pdata = NULL;
	p_save_handlentry Padd = NULL;
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		ExGetPreviousMode(),
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	Pdata = ExAllocatePool(NonPagedPool, sizeof(ReadWriteR3MemData));

	
	if (Pdata == NULL)
	{
		return  PwriteMem(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
	}
	else{

		Pdata->ProcessHandle = ProcessHandle;
		Pdata->BaseAddress = BaseAddress;
		Pdata->Buffer = Buffer;
		Pdata->BufferLength = BufferLength;
		Pdata->ReturnLength = ReturnLength;
		Pdata->IsReadOrWrite = FALSE;
		Pdata->Status = STATUS_ACCESS_DENIED;
		ReadOrWriteR3Mem(Pdata);
		ExFreePool(Pdata);
		return Pdata->Status;

	}
*/

	/*	
	ObDereferenceObject(Process);

	if (Process!=NULL){
		Padd = querylist(PmainList, NULL, Process);
		if (Padd!=NULL)
		{
			if (PsGetCurrentProcess() == Process){
				return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
				//yes
			} else{
			//no
				return STATUS_ACCESS_DENIED;
			}


		}

	}
*/


	 	//return NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
}

BOOLEAN IsSystemProcessCall(){
	UCHAR* PsGetProcessImageFileName(IN PEPROCESS Process);
	PEPROCESS Process = PsGetCurrentProcess();
	if (Process!=NULL)
	{
		char *processName = PsGetProcessImageFileName(PsGetCurrentProcess());

		if (MmIsAddressValid(processName)==TRUE)
		{
			if (strstr(processName, "csrss") != NULL || strstr(processName, "explorer") != NULL || strstr(processName, "svchost") != NULL)
			{

				return TRUE;
			}
			


		}
	}
	

	return FALSE;
}

ULONG __fastcall MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK AccessMask,
	__in PVOID ObjectAttributes,
	__in PCLIENT_ID ClientId){
	p_save_handlentry Padd = NULL;
	HANDLE pid;

	if (IsSystemProcessCall())
	{
		return  XNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);//调用原函数

	}

	if (ClientId->UniqueProcess!=NULL)
	{
		pid = ClientId->UniqueProcess;

		Padd = querylist(PmainList, pid, NULL);
		if (Padd!=NULL)
		{
			if (pid==PsGetCurrentProcessId())
			{
				return  XNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);//调用原函数
			}
			else{

				return STATUS_ACCESS_DENIED;
				//no
			}
		}

	}
	

	return  XNtOpenProcess(ProcessHandle, AccessMask, ObjectAttributes, ClientId);//调用原函数

}

VOID init(){

	KeInitializeSpinLock(&local_lock);
	GetKernelModuleBase("ntoskrnl.exe", &KrnlBase, &KrnlSize);
}


NTSTATUS __fastcall 	proxyPsSetContextThread(__in PETHREAD Thread, __in PCONTEXT ThreadContext, __in KPROCESSOR_MODE PreviousMode){



}

NTSTATUS __fastcall proxyPspGetContextThreadInternal(
	__in PETHREAD Ethread,
	__in PCONTEXT ThreadContext, 
	__in KPROCESSOR_MODE PreviousMode,
	__in BOOLEAN isSystemThread,
	__in BOOLEAN dwOne){




}
NTSTATUS __fastcall  proxyPspSetContextThreadInternal(
	__in PETHREAD Ethread,
	__in PCONTEXT ThreadContext,
	__in KPROCESSOR_MODE PreviousMode,
	__in BOOLEAN isSystemThread,
	__in BOOLEAN dwOne){


}



 NTSTATUS  __fastcall proxyPsLookupThreadByThreadId(_In_ HANDLE ThreadId, _Outptr_ PETHREAD *Thread){

	 p_save_handlentry Padd = NULL;
	
	 PEPROCESS Process = NULL;
	 NTSTATUS st;
	 st = ((pfPsLookupThreadByThreadId)ori_pslp21)(ThreadId, Thread);
	 if (NT_SUCCESS(st))
	 {
		 Process = IoThreadToProcess(*Thread);

		 Padd = querylist(PmainList, NULL, Process);
		 if (Padd != NULL)
		 {

			 Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
			 if (Padd != NULL)
			 {

				 return  st;

			 }
			 else
			 {
				 if (MmIsAddressValid(Thread))
				 {
					 *Thread = NULL;
				 }
				 return STATUS_ACCESS_DENIED;
			 }

		 }
	 }
	
	

	 return  st;
}
 NTSTATUS __fastcall proxyPsLookupProcessByProcessId(_In_ HANDLE ProcessId, _Out_ PEPROCESS *Process){
	 if (VtMode)
	 {
		 PPAGE_HOOK_ENTRY pEntry = PHGetHookEntry(fc_DbgkGetAdrress(L"PsLookupProcessByProcessId"));
		 ori_pslp22 = pEntry->OriginalData;
	 }
	 p_save_handlentry Padd = NULL;
	 Padd = querylist(PmainList, ProcessId, NULL);
	 NTSTATUS status = NULL;
	 status=((pfPsLookupProcessByProcessId)ori_pslp22)(ProcessId, Process);

	 if (NT_SUCCESS(status))
	 {
		 if (Padd != NULL){
			 Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
			 if (Padd != NULL)
			 {

				 return  status;

			 }
			 else
			 {
				 if (MmIsAddressValid(Process))
				 {
					 *Process = NULL;
				 }
				 return STATUS_ACCESS_DENIED;
			 }
			
			 
		 }
		 
	 }
	 return status;
 }




ULONG64 __fastcall proxyExGetCallBackBlockRoutine(ULONG64 a1){
	KIRQL oldirql = 0;
	KeAcquireSpinLock(&local_lock, &oldirql);//加锁 不加会有些无良驱动来回注册 会蓝的很难看

	ULONG64 result = *(ULONG64 *)(a1 + 8);

	if (result>KrnlBase && result <(KrnlBase+KrnlSize))
	{
		DbgPrint("系统调用跳过！");//有时候会有系统的回调
		KeReleaseSpinLock(&local_lock, oldirql);
		return result;
	}

	p_save_handlentry Padd;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd!=NULL)
	{
		KeReleaseSpinLock(&local_lock, oldirql);
		return proxyListFunc;//我们的程序在调用 返回伪回调

		//return *(ULONG64 *)(a1 + 8); //这里是返回正确的回调函数~ 
	}
	if (!MmIsAddressValid(result))
	{
		KeReleaseSpinLock(&local_lock, oldirql);
		return proxyListFunc;//免得无良驱动忘了卸载回调 返回伪回调

	}
	KeReleaseSpinLock(&local_lock, oldirql);
	return result; //这里是返回正确的回调函数~ 


}

ULONG64 __fastcall proxyExCompareExchangeCallBack(ULONG64 a1, ULONG64 a2, ULONG64 a3){
	p_save_handlentry Padd;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), PsGetCurrentProcess());
	if (Padd != NULL)
	{

		return FALSE;
	}
	return TRUE;
}

VOID RemoveListEntry(PLIST_ENTRY ListEntry)
{
	KIRQL OldIrql;
	OldIrql = KeRaiseIrqlToDpcLevel();
	if (ListEntry->Flink != ListEntry &&
		ListEntry->Blink != ListEntry &&
		ListEntry->Blink->Flink == ListEntry &&
		ListEntry->Flink->Blink == ListEntry)
	{
		ListEntry->Flink->Blink = ListEntry->Blink;
		ListEntry->Blink->Flink = ListEntry->Flink;
		ListEntry->Flink = ListEntry;
		ListEntry->Blink = ListEntry;
	}
	KeLowerIrql(OldIrql);
}


VOID  T_KiSaveDebugRegisterState(){



	return 0;
}

VOID T_KiRestoreDebugRegisterState(){

	PEPROCESS Process=NULL;
	PETHREAD Thread=NULL;
	PPROCESS_List PlIST = NULL;;
	PTHREAD_dr_List TList = NULL;
	ULONG64 UDR = NULL;
	PLARGE_INTEGER PDR = &UDR;
	
	Thread = PsGetCurrentThread();
	if (Thread!=NULL)
	{
		Process = IoThreadToProcess(Thread);



		if (Process != NULL){

			PlIST = Dr_FindProcessList(Process);
			if (PlIST != NULL)
			{

				TList = Dr_FindThreadContextByThreadList(PlIST, Thread);
				if (TList != NULL)
				{
					PDR->LowPart = TList->Dr0;
					PDR->HighPart = 0x00000000;
					__writedr(0, UDR);
					 
					PDR->LowPart = TList->Dr1;
					PDR->HighPart = 0x00000000;
					__writedr(1, UDR);
					 
					PDR->LowPart = TList->Dr2;
					PDR->HighPart = 0x00000000;
					__writedr(2, UDR);

					PDR->LowPart = TList->Dr3;
					PDR->HighPart = 0x00000000;
					__writedr(3, UDR);

					PDR->LowPart = TList->Dr6;
					PDR->HighPart = 0x00000000;
					__writedr(6, UDR);

					PDR->LowPart = TList->Dr7;
					PDR->HighPart = 0x00000000;
					__writedr(7, UDR);
				}


			}

				}


	}




	
	return 0;
}
ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 funcstr);
VOID initANti(){
	init();
	KeInitializeSpinLock(&KrwLock);
	InitListAndLock();
	pslp_head_n_byte9 = HookKernelApi(ObpCallPreOperationCallbacks,
		(PVOID)proxyObpCallPreOperationCallbacks,
		&ori_pslp9,
		&pslp_patch_size9);


	pslp_head_n_byte25 = HookKernelApi(RtlpCopyLegacyContextX86,
		(PVOID)myRtlpCopyLegacyContextX86,
		&ori_pslp25,
		&pslp_patch_size25);

	pslp_head_n_byte27 = HookKernelApi(NtReadVirtualMemory,
		(PVOID)MyNtReadVirtualMemory,
		&ori_pslp27,
		&pslp_patch_size27);
	pslp_head_n_byte28 = HookKernelApi(NtWriteVirtualMemory,
		(PVOID)MyNtWriteVirtualMemory,
		&ori_pslp28,
		&pslp_patch_size28);
	/*pslp_head_n_byte26 = HookKernelApi(KiAttachProcess,
		(PVOID)proxyKiAttachProcess,
		&ori_pslp26,
		&pslp_patch_size26);*/

	
/*
	pslp_head_n_byte23 = HookKernelApi(KiRestoreDebugRegisterState,
		(PVOID)T_KiRestoreDebugRegisterState,
		&ori_pslp23,
		&pslp_patch_size23);
	pslp_head_n_byte24 = HookKernelApi(KiSaveDebugRegisterState,
		(PVOID)T_KiSaveDebugRegisterState,
		&ori_pslp24,
		&pslp_patch_size24);
*/



/*
	pslp_head_n_byte21 = HookKernelApi(fc_DbgkGetAdrress(L"PsLookupThreadByThreadId") ,
		(PVOID)proxyPsLookupThreadByThreadId,
		&ori_pslp21,
		&pslp_patch_size21);
		*/
	pslp_head_n_byte22 = HookKernelApi(fc_DbgkGetAdrress(L"PsLookupProcessByProcessId") ,
		(PVOID)proxyPsLookupProcessByProcessId,
		&ori_pslp22,
		&pslp_patch_size22);
	pslp_head_n_byte19 = HookKernelApi(NtQueryInformationThread,
		(PVOID)myNtQueryInformationThread,
		&ori_pslp19,
		&pslp_patch_size19);

/*
	pslp_head_n_byte20 = HookKernelApi(ExCompareExchangeCallBack,
		(PVOID)proxyExCompareExchangeCallBack,
		&ori_pslp20,
		&pslp_patch_size20);


	*/
/*
	pslp_head_n_byte19 = HookKernelApi(NtQueryInformationThread,
		(PVOID)myNtQueryInformationThread,
		&ori_pslp19,
		&pslp_patch_size19);
	*/
//	pslp_head_n_byte10 = HookKernelApi(ExGetCallBackBlockRoutine,
	//	(PVOID)proxyExGetCallBackBlockRoutine,
		//&ori_pslp10,
		//&pslp_patch_size10);
	//HookKernelApi4_6bit(ExGetCallBackBlockRoutine,
		//	(PVOID)proxyExGetCallBackBlockRoutine);
/*

	HookKernelApi4_6bit(ExGetCallBackBlockRoutine,
		(PVOID)proxyExGetCallBackBlockRoutine, &orgcode);
*/


}
VOID unload(){

	UnhookKernelApi(ObpCallPreOperationCallbacks, pslp_head_n_byte9, pslp_patch_size9);
	UnhookKernelApi(NtQueryInformationThread, pslp_head_n_byte19, pslp_patch_size19); 
	UnhookKernelApi(RtlpCopyLegacyContextX86, pslp_head_n_byte25, pslp_patch_size25);
//	UnhookKernelApi(KiAttachProcess, pslp_head_n_byte26, pslp_patch_size26);
	UnhookKernelApi(fc_DbgkGetAdrress(L"PsLookupProcessByProcessId"), pslp_head_n_byte22, pslp_patch_size22);
	UnhookKernelApi(NtReadVirtualMemory, pslp_head_n_byte27, pslp_patch_size27);
	UnhookKernelApi(NtWriteVirtualMemory, pslp_head_n_byte28, pslp_patch_size28);
	/*
	/*

/*
	UnhookKernelApi(KiSaveDebugRegisterState, pslp_head_n_byte24, pslp_patch_size24);
	UnhookKernelApi(KiRestoreDebugRegisterState, pslp_head_n_byte23, pslp_patch_size23);*/
/*
	UnhookKernelApi(ExCompareExchangeCallBack, pslp_head_n_byte20, pslp_patch_size20);
*/
	
/*
	UnhookKernelApi(fc_DbgkGetAdrress(L"PsLookupThreadByThreadId"), pslp_head_n_byte21, pslp_patch_size21);
	*/
	
//	UnhookKernelApi(ExGetCallBackBlockRoutine, pslp_head_n_byte10, pslp_patch_size10);
	
/*	UnhookKernelApi(NtQueryInformationThread, pslp_head_n_byte19, pslp_patch_size19);*/
	/*UnHookKernelApi4_6bit(ExGetCallBackBlockRoutine, &orgcode);

*/



}

VOID EPT_InitAnti(){
	init();
	KeInitializeSpinLock(&KrwLock);
	InitListAndLock();
	PHHook(RtlpCopyLegacyContextX86, myRtlpCopyLegacyContextX86);
	PHHook(ObpCallPreOperationCallbacks, proxyObpCallPreOperationCallbacks);
	PHHook(fc_DbgkGetAdrress(L"PsLookupProcessByProcessId"), proxyPsLookupProcessByProcessId);
	PHHook(NtQueryInformationThread, myNtQueryInformationThread);
	//PHHook(NtReadVirtualMemory, MyNtReadVirtualMemory);
	//PHHook(NtWriteVirtualMemory, MyNtWriteVirtualMemory);
}
VOID EPT_UnLoadAnti(){
	PHRestore(RtlpCopyLegacyContextX86);
	PHRestore(ObpCallPreOperationCallbacks);
	PHRestore(fc_DbgkGetAdrress(L"PsLookupProcessByProcessId"));
	PHRestore(NtQueryInformationThread);
	//PHRestore(NtReadVirtualMemory);
	//PHRestore(NtWriteVirtualMemory);
}
BOOLEAN VxkCopyMemory(PVOID pDestination, PVOID pSourceAddress, SIZE_T SizeOfCopy)
{
	PMDL pMdl = NULL;
	PVOID pSafeAddress = NULL;
	pMdl = IoAllocateMdl(pSourceAddress, (ULONG)SizeOfCopy, FALSE, FALSE, NULL);
	if (!pMdl) return FALSE;
	__try
	{
		MmProbeAndLockPages(pMdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMdl);
		return FALSE;
	}
	pSafeAddress = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (!pSafeAddress) return FALSE;
	RtlCopyMemory(pDestination, pSafeAddress, SizeOfCopy);
	MmUnlockPages(pMdl);
	IoFreeMdl(pMdl);
	return TRUE;
}

VOID UnicodeToChar(PUNICODE_STRING dst, char *src)
{
	ANSI_STRING string;
	RtlUnicodeStringToAnsiString(&string, dst, TRUE);
	strcpy(src, string.Buffer);
	RtlFreeAnsiString(&string);
}

void DenyLoadDriver(PVOID DriverEntry)
{
	UCHAR fuck[] = "\xB8\x22\x00\x00\xC0\xC3";
	VxkCopyMemory(DriverEntry, fuck, sizeof(fuck));
}

PVOID GetDriverEntryByImageBase(PVOID ImageBase)
{
	PIMAGE_DOS_HEADER pDOSHeader;
	PIMAGE_NT_HEADERS64 pNTHeader;
	PVOID pEntryPoint;
	pDOSHeader = (PIMAGE_DOS_HEADER)ImageBase;
	pNTHeader = (PIMAGE_NT_HEADERS64)((ULONG64)ImageBase + pDOSHeader->e_lfanew);
	pEntryPoint = (PVOID)((ULONG64)ImageBase + pNTHeader->OptionalHeader.AddressOfEntryPoint);
	return pEntryPoint;
}

VOID LoadImageNotifyRoutine
(
__in_opt PUNICODE_STRING  FullImageName,
__in HANDLE  ProcessId,
__in PIMAGE_INFO  ImageInfo
)
{
	PVOID pDrvEntry;
	char szFullImageName[260] = { 0 };
	if (FullImageName != NULL && MmIsAddressValid(FullImageName))
	{
		if (ProcessId == 0)
		{
			
			pDrvEntry = GetDriverEntryByImageBase(ImageInfo->ImageBase);
			DbgPrint("[LoadImageNotifyX64]DriverEntry: %p\n", pDrvEntry);
			UnicodeToChar(FullImageName, szFullImageName);
			if (strstr(_strlwr(szFullImageName), "TesMon.sys"))
			{
				DbgPrint("[LoadImageNotifyX64]%wZ\n", FullImageName);
			
				DenyLoadDriver(pDrvEntry);
			}
		}
	}
}