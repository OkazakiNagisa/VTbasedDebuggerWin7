#include "ntddk.h"
#include "amd64.h"



typedef ULONG64(__fastcall *NTUSERQUERYWINDOW)
(
IN HANDLE		WindowHandle,
IN ULONG64	TypeInformation
);
typedef struct _LARGE_STRING
{
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PVOID Buffer;
} LARGE_STRING, *PLARGE_STRING;

NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	);
NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
IN PCLIENT_ID AppClientId,
IN NTSTATUS ContinueStatus);
NTSTATUS
__fastcall
proxyNtWaitForDebugEvent(IN HANDLE DebugHandle,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL,
OUT ULONG64 StateChange);
NTSTATUS
__fastcall
proxyNtDebugActiveProcess(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle);
NTSTATUS
NTAPI
NtRemoveProcessDebug(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle);
NTSTATUS __fastcall myNtQueryInformationThread(IN   HANDLE   ThreadHandle,
	IN   THREADINFOCLASS   ThreadInformationClass,
	OUT   PVOID   ThreadInformation,
	IN   ULONG   ThreadInformationLength,
	OUT   PULONG   ReturnLength   OPTIONAL
	);
signed __int64 __fastcall MyNtWriteVirtualMemory(PHANDLE ProcessHandle, __int64 a2, unsigned __int64 AccessMode, __int64 a4, unsigned __int64 a5);
ULONG __fastcall MyNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK AccessMask,
	__in PVOID ObjectAttributes,
	__in PCLIENT_ID ClientId);
signed __int64 __fastcall MyNtReadVirtualMemory(PHANDLE ProcessHandle, unsigned __int64 AccessMode, __int64 a3, __int64 a4, unsigned __int64 a5);

NTSTATUS myNtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
typedef NTSTATUS(__fastcall*CALLFUNC)();
	ULONG64 NtSyscallHandler;
	ULONG64 GuestSyscallHandler;
	ULONG64 NtSyscallHandler32;
	ULONG64 NtKernelsyscallBase;
	ULONG64 NtKernelSSDT;
	ULONG64 KeGdiFlushUserBatch;
	ULONG64 KiSaveDebugRegisterState;
	ULONG64 KiUmsCallEntry;
	ULONG64 KiSystemServiceRepeat;
	ULONG64 MmUserProbeAddress_Address;
	ULONG64 KiSystemServiceCopyEnd;
	CHAR SyscallHookEnabled[4096];
	CHAR SyscallParamTable[4096];
	PVOID SyscallPointerTable[4096];
	ULONG64 KeServiceDescriptorTable;
	ULONG64 KeServiceDescriptorTableShadow;
	ULONG64 KiSystemServiceExit;
	VOID SyscallEntryPoint();
	extern ULONG KiSystemServiceRepeat_Emulate();






	NTSTATUS AddServiceCallHook(ULONG Index, UCHAR ParameterCount, PVOID Function)
	{
		if (Index >= ARRAYSIZE(SyscallHookEnabled))
			return STATUS_INVALID_PARAMETER_1;

		if (ParameterCount > 15)
			return STATUS_INVALID_PARAMETER_2;

		//
		// Ensure this function isn't interrupted
		//
		KIRQL irql = KeGetCurrentIrql();

		if (irql < DISPATCH_LEVEL)
			irql = KeRaiseIrqlToDpcLevel();

		//
		// If the syscall hook is enabled, disable it immediately
		//
		InterlockedExchange8(&SyscallHookEnabled[Index], FALSE);

		SyscallParamTable[Index] = ParameterCount;
		SyscallPointerTable[Index] = Function;

		//
		// If the function is valid, re-enable it
		//
		if (Function)
			InterlockedExchange8(&SyscallHookEnabled[Index], TRUE);

		//
		// Reset IRQL
		//

		if (KeGetCurrentIrql() > irql)
			KeLowerIrql(irql);
		return STATUS_SUCCESS;
	}
	NTSTATUS RemoveServiceCallHook(ULONG Index)
	{
		return AddServiceCallHook(Index, 0, NULL);
	}
	VOID EnbaleHookSysCALL(){
		__writemsr(MSR_LSTAR, GuestSyscallHandler);


	}
	VOID DisableHookSysCALL(){

		__writemsr(MSR_LSTAR, NtSyscallHandler);
	}

	VOID  HookMsr(CALLFUNC func)
	{
		NTSTATUS  status;
		KMUTEX mutex;
		KeInitializeMutex(&mutex, 0);
		KeWaitForSingleObject(&mutex, Executive, KernelMode, FALSE, NULL);

		for (LONG i = 0; i < KeQueryActiveProcessorCount(NULL); i++)
		{
			KAFFINITY oldAffinity = KeSetSystemAffinityThreadEx((KAFFINITY)(1 << i));
			KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
			func();
			KeLowerIrql(oldIrql);
			KeRevertToUserAffinityThreadEx(oldAffinity);
		}
		KeReleaseMutex(&mutex, FALSE);
	}
	VOID UnLoadSysHook(){
		HookMsr(&DisableHookSysCALL);//Disable hook
	}
VOID initdata(){
	

		NtKernelsyscallBase = (ULONG64)__readmsr(MSR_LSTAR);//kisystemcall64 entry point

		NtSyscallHandler = (ULONG64)__readmsr(MSR_LSTAR);

		NtSyscallHandler32 = (ULONG64)__readmsr(MSR_CSTAR);

		GuestSyscallHandler = (ULONG64)&SyscallEntryPoint;

	//	proxyNtQueryWindow = ssdt_GetSSDTShaDowFuncX64(16);
		
	}


VOID inithook(){

	// init data
	RtlSecureZeroMemory(SyscallHookEnabled, sizeof(SyscallHookEnabled));
	RtlSecureZeroMemory(SyscallParamTable, sizeof(SyscallParamTable));
	RtlSecureZeroMemory(SyscallPointerTable, sizeof(SyscallPointerTable));


	AddServiceCallHook(144, 4, (PVOID)&proxyNtCreateDebugObject);
	AddServiceCallHook(395, 4, (PVOID)&proxyNtWaitForDebugEvent);
	AddServiceCallHook(174, 3, (PVOID)&proxyNtDebugContinue);
   AddServiceCallHook(173,2, (PVOID)&proxyNtDebugActiveProcess);
   AddServiceCallHook(314, 2, (PVOID)&NtRemoveProcessDebug);
   AddServiceCallHook(34, 5, (PVOID)&myNtQueryInformationThread);



  // AddServiceCallHook(10, 4, (PVOID)&myNtSetInformationThread);
  // AddServiceCallHook(55, 5, (PVOID)&MyNtWriteVirtualMemory);
   //AddServiceCallHook(60, 5, (PVOID)&MyNtReadVirtualMemory);
  // AddServiceCallHook(35, 4, (PVOID)&MyNtOpenProcess);
   
   
	HookMsr(&EnbaleHookSysCALL);//ENABLE hook
}



