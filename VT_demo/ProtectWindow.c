#include "ntddk.h"
#include "dbgtool.h"
#include "windef.h"
/////////

extern p_save_handlentry PmainList;
typedef NTSTATUS(__fastcall *pfNtUserFindWindowEx)(HWND a1, HWND a2, PUNICODE_STRING a3, PUNICODE_STRING a4, ULONG a5);
typedef HANDLE(__fastcall *pfNTUSERGETFOREGROUNDWINDOW)(VOID);
typedef NTSTATUS(__fastcall* pfNtUserBuildHwndList)(IN HDESK hdesk, IN HWND hwndNext, IN ULONG fEnumChildren, IN DWORD idThread, IN UINT cHwndMax, OUT HWND *phwndFirst, OUT ULONG* pcHwndNeeded);
typedef HWND(__fastcall* pfNtUserWindowFromPoint)(__int64 a1);
typedef __int64 (__fastcall*pfNTGDIGETPIXEL)(HDC hDC, int XPos, int YPos);

typedef __int64(__fastcall* pfNtUserCallOneParam)(__int64 a1, unsigned int a2);

typedef __int64(__fastcall *pfNtUserChildWindowFromPointEx)(
	_In_ HWND  hwndParent,
	_In_ POINT pt,
	_In_ UINT  uFlags
	);
typedef __int64(__fastcall *pfNtUserRealChildWindowFromPoint)(_In_ HWND  hwndParent,
_In_ POINT ptParentClientCoords
);
typedef __int64(__fastcall *pfNtUserWindowFromPhysicalPoint)(__int64 a1);
typedef __int64 (__fastcall *pfNtUserMessageCall)(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, int a6);
typedef __int64(__fastcall* pfNtUserGetClassName)(HWND hWnd, LPTSTR IpClassName, int nMaxCount);
pfNtUserChildWindowFromPointEx orgNtUserChildWindowFromPointEx = NULL;
pfNtUserRealChildWindowFromPoint orgNtUserRealChildWindowFromPoint = NULL;
pfNtUserWindowFromPhysicalPoint orgNtUserWindowFromPhysicalPoint = NULL;
///////
pfNtUserMessageCall orgNtUserMessageCall;
pfNtUserCallOneParam	 RealNtUserCallOneParam = NULL;
pfNTGDIGETPIXEL NTGDIGETPIXEL = NULL;
//用于搜索进程 编码仅限于win7X64
typedef struct _KSERVICE_TABLE_DESCRIPTOR{
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;
NTSTATUS KeStackAttachProcess(PEPROCESS process, PKAPC_STATE APC);
NTSTATUS KeUnstackDetachProcess(PKAPC_STATE APC);


extern ULONG64 KeServiceDescriptorTableShadow;
#define kmalloc(_s)	ExAllocatePoolWithTag(NonPagedPool, _s, 'SYSQ')
#define kfree(_p)	ExFreePool(_p)
typedef struct _LARGE_STRING
{
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PVOID Buffer;
} LARGE_STRING, *PLARGE_STRING;
typedef HANDLE(__fastcall *NTUSERQUERYWINDOW)
(
IN HWND		WindowHandle,
IN ULONG	TypeInformation
);

typedef ULONG64(__fastcall *NTUSERPOSTMESSAGE)
(
ULONG64 	hWnd,
INT 	Msg,
ULONG32 	wParam,
ULONG32 	lParam
);
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation
(
IN ULONG	SystemInformationClass,
OUT PVOID	SystemInformation,
IN ULONG	Length,
OUT PULONG	ReturnLength
);

void GetKernelModuleBase(char* lpModuleName, ULONG64 *ByRefBase, ULONG *ByRefSize)
{
	typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
	{
		ULONG Unknow1;
		ULONG Unknow2;
		ULONG Unknow3;
		ULONG Unknow4;
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT NameLength;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		char ImageName[256];
	} SYSTEM_MODULE_INFORMATION_ENTRY, *PSYSTEM_MODULE_INFORMATION_ENTRY;
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG Count;//内核中以加载的模块的个数
		SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
	} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY64 InLoadOrderLinks;
		ULONG64 __Undefined1;
		ULONG64 __Undefined2;
		ULONG64 __Undefined3;
		ULONG64 NonPagedDebugInfo;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG   Flags;
		USHORT  LoadCount;
		USHORT  __Undefined5;
		ULONG64 __Undefined6;
		ULONG   CheckSum;
		ULONG   __padding1;
		ULONG   TimeDateStamp;
		ULONG   __padding2;
	}KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
	ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
	PVOID pBuffer = NULL;
	PCHAR pDrvName = NULL;
	NTSTATUS Result;
	PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
	do
	{
		//分配内存
		pBuffer = kmalloc(BufferSize);
		if (pBuffer == NULL)
			return;
		//查询模块信息
		Result = ZwQuerySystemInformation(11, pBuffer, BufferSize, &NeedSize);
		if (Result == STATUS_INFO_LENGTH_MISMATCH)
		{
			kfree(pBuffer);
			BufferSize *= 2;
		}
		else if (!NT_SUCCESS(Result))
		{
			//查询失败则退出
			kfree(pBuffer);
			return;
		}
	} while (Result == STATUS_INFO_LENGTH_MISMATCH);
	pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
	//获得模块的总数量
	ModuleCount = pSystemModuleInformation->Count;
	//遍历所有的模块
	for (i = 0; i < ModuleCount; i++)
	{
		if ((ULONG64)(pSystemModuleInformation->Module[i].Base) > (ULONG64)0x8000000000000000)
		{
			pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset;
			if (_stricmp(pDrvName, lpModuleName) == 0)
			{
				*ByRefBase = (ULONG64)pSystemModuleInformation->Module[i].Base;
				*ByRefSize = pSystemModuleInformation->Module[i].Size;
				goto exit_sub;
			}
		}
	}
exit_sub:
	kfree(pBuffer);
}

ULONG64 _Search64Process(char *szProcessName, ULONG64 callBackFUNC)
{
	ULONG64 pEprocess, LastProcess;
	ULONG64 Current_Pid;
	ULONG64 Start_Pid;
	int	  index;
	PLIST_ENTRY64 pList_Active_Process;

	if (!MmIsAddressValid(szProcessName))
		return 0;

	index = 0;

	pEprocess = (ULONG64)PsGetCurrentProcess();
	Start_Pid = *(ULONG64*)(pEprocess + 0x180);
	Current_Pid = Start_Pid;

	while (TRUE)
	{
		LastProcess = pEprocess;
		pList_Active_Process = (PLIST_ENTRY)(pEprocess + 0x188);
		pEprocess = (ULONG64)pList_Active_Process->Flink;
		pEprocess = pEprocess - 0x188;
		Current_Pid = *(ULONG64*)(pEprocess + 0x180);
		if (MmIsAddressValid(callBackFUNC) && callBackFUNC != 0){
			//((ENUMPROCESSCALLBACK)callBackFUNC)(LastProcess);


		}
		if ((Current_Pid == Start_Pid) && index > 0)
		{
			return 0;
		}
		else if (strstr((char*)LastProcess + 0x2e0, szProcessName) != 0)
		{



			return LastProcess;
		}
		index++;
	}
	return 0;
}


ULONG64 ssdt_GetSSDTShaDowFuncX64(ULONG serviceID){
	PKSERVICE_TABLE_DESCRIPTOR SSDTShadow;
	PULONG         W32pServiceTable;
	KAPC_STATE     ApcState;
	PULONG g_Guiprocess;
	ULONG64 funcAddress;
	BOOLEAN ERRORX=FALSE;
	SSDTShadow = (PKSERVICE_TABLE_DESCRIPTOR)KeServiceDescriptorTableShadow;
	serviceID &= 0x0FFF;
	if (!SSDTShadow)
	{
		return 0;
	}


	g_Guiprocess = _Search64Process("csrss", 0);
	if (g_Guiprocess==NULL)
	{
		ERRORX = TRUE;
		return NULL;
	}

	KeStackAttachProcess(g_Guiprocess, &ApcState);
	W32pServiceTable = SSDTShadow[1].ServiceTableBase;
	
	funcAddress = (LONGLONG)(W32pServiceTable[serviceID] >> 4)
		+ (ULONGLONG)W32pServiceTable;

	KeUnstackDetachProcess(&ApcState);
	funcAddress &= 0xfffffff000ffffff;
	return funcAddress;



}

ULONG64	ul64W32pServiceTable = 0;
ULONG64	IndexOfNtUserPostMessage = 0x100f;	//<---这是你要修改的ID(查表可知)
ULONG64	IndexOfNtUserQueryWindow = 0x1010;
ULONG64 IndexOfNtUserCreateWindowEx = 0x1076;
HWND LastForegroundWindow=NULL;
NTUSERQUERYWINDOW orgNtUserQueryWindow = NULL;	//<---则是原始函数的地址
NTUSERPOSTMESSAGE orgNtUserPostMessage = NULL;
pfNtUserFindWindowEx orgNtUserFindWindowEx = NULL;
pfNTUSERGETFOREGROUNDWINDOW orgNtUserGetforegroundwindow = NULL;
pfNtUserBuildHwndList orgNtUserBuildHwndList = NULL;
pfNtUserWindowFromPoint orgNtUserWindowFromPoint = NULL;

pfNtUserGetClassName orgNtUserGetClassName = NULL;
ULONG64	Win32kBase = 0;
ULONG	Win32kSize = 0;

KIRQL WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

void SafeMemcpy(PVOID dst, PVOID src, ULONG32 length)
{
	KIRQL irql;
	irql = WPOFFx64();
	memcpy(dst, src, length);
	WPONx64(irql);
}

ULONGLONG GetKeServiceDescriptorTableShadow64()
{
	PUCHAR StartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR EndSearchAddress = StartSearchAddress + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONG templong = 0;
	ULONGLONG addr = 0;
	for (i = StartSearchAddress; i < EndSearchAddress; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *i;
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x1d) //4c8d1d
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				return addr;
			}
		}
	}
	return 0;
}

ULONGLONG GetSSSDTFuncCurAddr64(ULONG64 Index)
{
	ULONGLONG				W32pServiceTable = 0, qwTemp = 0;
	LONG 					dwTemp = 0;
	PKSERVICE_TABLE_DESCRIPTOR	pWin32k;
	pWin32k = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG64)KeServiceDescriptorTableShadow + sizeof(KSERVICE_TABLE_DESCRIPTOR));
	W32pServiceTable = (ULONGLONG)(pWin32k->ServiceTableBase);
	ul64W32pServiceTable = W32pServiceTable;
	qwTemp = W32pServiceTable + 4 * (Index - 0x1000);	//这里是获得偏移地址的位置，要HOOK的话修改这里即可
	dwTemp = *(PLONG)qwTemp;
	dwTemp = dwTemp >> 4;
	qwTemp = W32pServiceTable + (LONG64)dwTemp;
	return qwTemp;
}

#define SETBIT(x,y) x|=(1<<y) //将X的第Y位置1
#define CLRBIT(x,y) x&=~(1<<y) //将X的第Y位清0
#define GETBIT(x,y) (x & (1 << y)) //取X的第Y位，返回0或非0

VOID ModifySSSDT(ULONG64 Index, ULONG64 Address, CHAR ParamCount)
{
	CHAR b = 0, bits[4] = { 0 };
	LONG i;

	ULONGLONG				W32pServiceTable = 0, qwTemp = 0;
	LONG 					dwTemp = 0;
	PKSERVICE_TABLE_DESCRIPTOR	pWin32k;
	KIRQL					irql;
	pWin32k = (PKSERVICE_TABLE_DESCRIPTOR)((ULONG64)KeServiceDescriptorTableShadow + sizeof(KSERVICE_TABLE_DESCRIPTOR));	//4*8
	W32pServiceTable = (ULONGLONG)(pWin32k->ServiceTableBase);
	qwTemp = W32pServiceTable + 4 * (Index - 0x1000);
	dwTemp = (LONG)(Address - W32pServiceTable);
	dwTemp = dwTemp << 4;	//DbgPrint("*(PLONG)qwTemp: %x, dwTemp: %x",*(PLONG)qwTemp,dwTemp);

	//处理参数
	if (ParamCount > 4)
		ParamCount = ParamCount - 4;
	else
		ParamCount = 0;
	//获得dwtmp的第一个字节
	memcpy(&b, &dwTemp, 1);
	//处理低四位，填写参数个数
	for (i = 0; i < 4; i++)
	{
		bits[i] = GETBIT(ParamCount, i);
		if (bits[i])
			SETBIT(b, i);
		else
			CLRBIT(b, i);
	}
	//把数据复制回去
	memcpy(&dwTemp, &b, 1);

	irql = WPOFFx64();
	*(PLONG)qwTemp = dwTemp;
	WPONx64(irql);
}

ULONG64 FindFreeSpace(ULONG64 StartAddress, ULONG64 Length)
{
	UCHAR 	c = 0;
	ULONG64 i = 0, qw = 0;
	for (i = StartAddress; i < StartAddress + Length; i++)
	{
		if (*(PUCHAR)i == 0xC3)
		{
			RtlMoveMemory(&qw, (PVOID)(i + 1), 8);
			if (qw == 0x9090909090909090)
			{
				return i + 1;
			}
		}
	}
	return 0;
}

VOID HOOK_SSSDT(ULONG64 FunctionId, ULONG64 ProxyFunctionAddress, CHAR ParamCount)	//return OriFunctionAddress
{
	ULONG64 FreeSpace = 0, OriFunctionAddress = 0;
	LONG lng = 0;
	UCHAR jmp_code[] = "\xFF\x25\x00\x00\x00\x00";
	DbgPrint("ProxyFunctionAddress: %p", ProxyFunctionAddress);
	GetKernelModuleBase("win32k.sys", &Win32kBase, &Win32kSize);
	DbgPrint("Win32kBase: %p", Win32kBase);
	DbgPrint("Win32kBase: %ld", Win32kSize);
	if (Win32kBase == 0 || Win32kSize == 0)
		return;
	FreeSpace = FindFreeSpace(Win32kBase, Win32kSize);
	DbgPrint("FreeSpace: %p", FreeSpace);
	if (FreeSpace == 0)
		return;
	SafeMemcpy((PVOID)FreeSpace, &ProxyFunctionAddress, 8);
	OriFunctionAddress = GetSSSDTFuncCurAddr64(FunctionId);
	DbgPrint("OriFunctionAddress: %p", OriFunctionAddress);
	lng = (LONG)(FreeSpace - (OriFunctionAddress - 6) - 6);
	memcpy(&jmp_code[2], &lng, 4);
	SafeMemcpy((PVOID)(OriFunctionAddress - 6), jmp_code, 6);
	ModifySSSDT(FunctionId, OriFunctionAddress - 6, ParamCount);
	DbgPrint("HOOK_SSSDT OK!");
}

VOID UNHOOK_SSSDT(ULONG64 FunctionId, ULONG64 OriFunctionAddress, CHAR ParamCount)
{
	ModifySSSDT(FunctionId, (ULONG64)OriFunctionAddress, ParamCount);
	DbgPrint("UNHOOK_SSSDT OK!");
}




NTSTATUS __fastcall MyNtUserFindWindowEx(HWND a1, HWND a2, PUNICODE_STRING a3, PUNICODE_STRING a4, ULONG a5){
	p_save_handlentry Padd=NULL;
	HWND result;
	result = orgNtUserFindWindowEx(a1, a2, a3, a4, a5);
	if (result==NULL)
	{
		return 0;
	}
	Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
	if (Padd == NULL){
	
		ULONG ProcessID;

		ProcessID = orgNtUserQueryWindow(result, 0);
		Padd = querylist(PmainList, ProcessID, NULL);
		if (Padd != NULL){
			DbgPrint(" MyNtUserFindWindowEx Protect Process~!");
			return 0;
		}
	
	}
	DbgPrint(" MyNtUserFindWindowEx NO Protect Process~!");
	return result;
	
}
HANDLE __fastcall MyNtUserQueryWindow(IN HWND WindowHandle, IN ULONG TypeInformation)
{
	p_save_handlentry Padd=NULL;
	HANDLE WindowHandleProcessID;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
	if (Padd==NULL)
	{
		WindowHandleProcessID = orgNtUserQueryWindow(WindowHandle, 0);
		Padd = querylist(PmainList, WindowHandleProcessID, NULL);
		if (Padd !=NULL)
			return 0;
	}
	return orgNtUserQueryWindow(WindowHandle, TypeInformation);
}

ULONG __fastcall MyNtUserGetForegroundWindow(VOID)
{
	ULONG result;
	p_save_handlentry Padd = NULL;
	
	
	result = orgNtUserGetforegroundwindow();
	Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
	if (Padd==NULL)
	{
		ULONG ProcessID;

		ProcessID = orgNtUserQueryWindow(result, 0);
		 Padd = querylist(PmainList, ProcessID, NULL);
		 if (Padd!=NULL)
			result = LastForegroundWindow;
		else
			LastForegroundWindow = result;
	}
	return result;
}




__int64 myNtUserGetClassName(HWND hWnd, LPTSTR IpClassName, int nMaxCount){

	p_save_handlentry Padd = NULL;
	HANDLE WindowHandleProcessID;
	Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
	if (Padd == NULL)
	{
		WindowHandleProcessID = orgNtUserQueryWindow(hWnd, 0);
		Padd = querylist(PmainList, WindowHandleProcessID, NULL);
		if (Padd != NULL)
			return 0;
	}

	return orgNtUserGetClassName(hWnd, IpClassName, nMaxCount);

}

HWND NtUserGetWindowFromDC(HDC hdc)
{
	

	
	return (HWND)(RealNtUserCallOneParam((ULONG)hdc, 0x03));
}

	NTSTATUS __fastcall MyNtUserBuildHwndList(IN HDESK hdesk, IN HWND hwndNext, IN ULONG fEnumChildren, IN DWORD idThread, IN UINT cHwndMax, OUT HWND *phwndFirst, OUT ULONG* pcHwndNeeded)
{
	NTSTATUS result;
	p_save_handlentry Padd = NULL;

	Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
	if (Padd==NULL)
	{
		ULONG ProcessID;

		if (fEnumChildren == 1)
		{
			ProcessID = orgNtUserQueryWindow((ULONG)hwndNext, 0);
			Padd = querylist(PmainList, ProcessID, PsGetCurrentProcess());
			if (Padd!=NULL)
				return STATUS_UNSUCCESSFUL;
		}
		result = orgNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);

		if (result == STATUS_SUCCESS)
		{
			ULONG i = 0;
			ULONG j;

			while (i < *pcHwndNeeded)
			{
				ProcessID = orgNtUserQueryWindow((HWND)phwndFirst[i], 0);
				Padd = querylist(PmainList, ProcessID, PsGetCurrentProcess());
				if (Padd!=NULL)
				{
					for (j = i; j < (*pcHwndNeeded) - 1; j++)
						phwndFirst[j] = phwndFirst[j + 1];
					LastForegroundWindow = (HWND)phwndFirst[i];
					phwndFirst[*pcHwndNeeded - 1] = 0;

					(*pcHwndNeeded)--;
					continue;
				}
				i++;
			}

		}
		return result;
	}
	return orgNtUserBuildHwndList(hdesk, hwndNext, fEnumChildren, idThread, cHwndMax, phwndFirst, pcHwndNeeded);
}

/*
	NTSTATUS New_NtUserBuildHwndList(
		IN HDESK hdesk,
		IN HWND hwndNext,
		IN ULONG fEnumChildren,
		IN DWORD idThread,
		IN UINT cHwndMax,
		OUT HWND *phwndFirst,
		OUT ULONG* pcHwndNeeded)
	{
		NTSTATUS status;
		ULONG i, ProcessId;
		if (fEnumChildren == 1)
		{
			ProcessId = orgNtUserQueryWindow((ULONG)hwndNext, 0);


			if (GetDebugInfoByPid(ProcessId))
			{
				if (!FindDebugInfoByEprocess(IoGetCurrentProcess())
					return STATUS_UNSUCCESSFUL;
			}


		}

		status = Org_NtUserBuildHwndList(hdesk,
			hwndNext,
			fEnumChildren,
			idThread,
			cHwndMax,
			phwndFirst,
			pcHwndNeeded);

		if (status == STATUS_SUCCESS)
		{
			if (IS_HOOK == 1 && !FindDebugInfoByEprocess(IoGetCurrentProcess()))
			{
				i = 0;
				while (i < *pcHwndNeeded)
				{
					// 获取句柄所属的进程ID
					ProcessId = Org_NtUserQueryWindow((ULONG)phwndFirst[i], 0);
					// 判断句柄是否属于OD
					if (GetDebugInfoByPid(ProcessId))
					{
						// 将此后的句柄信息前移，覆盖掉OD的句柄信息
						RtlCopyMemory(&phwndFirst[i + 1], &phwndFirst[i], *pcHwndNeeded - i);
						// 最后一项清0
						phwndFirst[*pcHwndNeeded - 1] = 0;
						// 总数减1
						(*pcHwndNeeded)--;
						continue;
					}
					i++;
				}
			}
		}

		return status;
	}

*/

	HWND __fastcall MyNtUserWindowFromPoint(__int64 a1)
	{
		HWND h = orgNtUserWindowFromPoint(a1);
	
		p_save_handlentry Padd = NULL;
		Padd = querylist(PmainList, PsGetCurrentProcessId(), NULL);
		if (Padd==NULL){
		
		
		HANDLE ProcessId = NULL;
		ProcessId = orgNtUserQueryWindow(h, 0);
		if (ProcessId == NULL){
			return 0;
		}
		Padd = querylist(PmainList, ProcessId, PsGetCurrentProcess());
		if (Padd!=NULL)
		{
			return NULL;

		}
		}




		return h;
	
	
	
	}
	__int64 NTAPI OnNTGDIGETPIXEL(HDC hDC, int XPos, int YPos)
	{
		HWND hd;
		ULONG processId;
		p_save_handlentry Padd = NULL;
		
		hd = NtUserGetWindowFromDC(hDC);
	
	
		processId = orgNtUserQueryWindow((HWND)hd, 0);
		Padd = querylist(PmainList, processId, NULL);
		if (Padd!=NULL)
		{
			return 0;
		}
		return NTGDIGETPIXEL(hDC, XPos, YPos);
	}

	__int64 __fastcall MyNtUserChildWindowFromPointEx(_In_ HWND  hwndParent,
		_In_ POINT pt,
		_In_ UINT  uFlags
		)
	{
		HWND hd;
		ULONG processId;
		p_save_handlentry Padd = NULL;

		processId = orgNtUserQueryWindow((HWND)hwndParent, 0);
		Padd = querylist(PmainList, processId, NULL);
		if (Padd != NULL)
		{
			return 0;
		}

		hd = orgNtUserChildWindowFromPointEx(hwndParent, pt, uFlags);
		processId = orgNtUserQueryWindow((HWND)hd, 0);
		Padd = querylist(PmainList, processId, NULL);
		if (Padd != NULL)
		{
			return 0;
		}
		return hd;
	}
	__int64 __fastcall MyNtUserWindowFromPhysicalPoint(__int64 a1)
	{
		HWND hd;
		ULONG processId;
		p_save_handlentry Padd = NULL;
		if (a1==NULL)
		{
			return 0;

		}
		hd = orgNtUserWindowFromPhysicalPoint(a1);
		if (hd==NULL)
		{
			return 0;
		}
		processId = orgNtUserQueryWindow((HWND)hd, 0);
		Padd = querylist(PmainList, processId, NULL);
		if (Padd != NULL)
		{
			return 0;
		}
		return hd;
	}
	__int64 __fastcall MyNtUserRealChildWindowFromPoint(HWND a1, POINT a2)
	{
		HWND hd;
		ULONG processId;
		p_save_handlentry Padd = NULL;
		
		hd = orgNtUserRealChildWindowFromPoint(a1, a2);
		if (hd==NULL)
		{
			return NULL;
		}
		processId = orgNtUserQueryWindow((HWND)hd, 0);
		Padd = querylist(PmainList, processId, NULL);
		if (Padd != NULL)
		{
			return 0;
		}
		return hd;
	}

	__int64 __fastcall MyNtUserMessageCall(__int64 a1, unsigned int a2, __int64 a3, __int64 a4, __int64 a5, int a6)
	{
		return orgNtUserMessageCall(a1, a2, a3, a4, a5, a6);
	}
VOID LoadProtectWindow(){
	KAPC_STATE pkapc_state ={0};
	ULONG64 g_Guiprocess = NULL;
	orgNtUserQueryWindow = ssdt_GetSSDTShaDowFuncX64(16);
	orgNtUserFindWindowEx = ssdt_GetSSDTShaDowFuncX64(110);
	orgNtUserGetforegroundwindow = ssdt_GetSSDTShaDowFuncX64(60);
	orgNtUserBuildHwndList = ssdt_GetSSDTShaDowFuncX64(28);
	orgNtUserWindowFromPoint = ssdt_GetSSDTShaDowFuncX64(20);
	orgNtUserGetClassName = ssdt_GetSSDTShaDowFuncX64(123);
	RealNtUserCallOneParam = ssdt_GetSSDTShaDowFuncX64(2);
	NTGDIGETPIXEL = ssdt_GetSSDTShaDowFuncX64(191);

	orgNtUserChildWindowFromPointEx = ssdt_GetSSDTShaDowFuncX64(653);
	orgNtUserWindowFromPhysicalPoint = ssdt_GetSSDTShaDowFuncX64(823);
	orgNtUserRealChildWindowFromPoint = ssdt_GetSSDTShaDowFuncX64(752);
	orgNtUserMessageCall = ssdt_GetSSDTShaDowFuncX64(7);
	DbgPrint("orgNtUserQueryWindow :%p", orgNtUserQueryWindow);

	g_Guiprocess = _Search64Process("csrss", 0);
	if (g_Guiprocess==NULL)
	{
		return NULL;
	}
	KeStackAttachProcess(g_Guiprocess, &pkapc_state);

	HOOK_SSSDT(0x106E, MyNtUserFindWindowEx, 5);
	HOOK_SSSDT(0x1010, MyNtUserQueryWindow, 2);
	HOOK_SSSDT(0x103C, MyNtUserGetForegroundWindow, 0);
	HOOK_SSSDT(0x101C, MyNtUserBuildHwndList, 7);
	HOOK_SSSDT(0x1014, MyNtUserWindowFromPoint, 1);
	HOOK_SSSDT(0x107b, myNtUserGetClassName, 3);
	HOOK_SSSDT(0x10BF, OnNTGDIGETPIXEL, 3);

	HOOK_SSSDT(0x128D, MyNtUserChildWindowFromPointEx, 3);
	HOOK_SSSDT(0x1337, MyNtUserWindowFromPhysicalPoint, 1);
	//HOOK_SSSDT(0x12F0, MyNtUserRealChildWindowFromPoint, 2);
//	HOOK_SSSDT(0x1007, MyNtUserMessageCall, 6);

	
	KeUnstackDetachProcess(&pkapc_state);


}
VOID UnLoadProtectWindow(){
	KAPC_STATE pkapc_state = { 0 };
	ULONG64 g_Guiprocess = NULL;


	g_Guiprocess = _Search64Process("csrss", 0);
	if (g_Guiprocess == NULL)
	{
		return NULL;
	}
	KeStackAttachProcess(g_Guiprocess, &pkapc_state);


	UNHOOK_SSSDT(0x106E, orgNtUserFindWindowEx,5);
	UNHOOK_SSSDT(0x1010, orgNtUserQueryWindow, 2);
	UNHOOK_SSSDT(0x103C, orgNtUserGetforegroundwindow, 0);
	UNHOOK_SSSDT(0x101C, orgNtUserBuildHwndList, 7);
	UNHOOK_SSSDT(0x1014, orgNtUserWindowFromPoint, 1);
	UNHOOK_SSSDT(0x107b, orgNtUserGetClassName, 3);
	UNHOOK_SSSDT(0x10BF, NTGDIGETPIXEL, 3);
	UNHOOK_SSSDT(0x128D, orgNtUserChildWindowFromPointEx, 3);
	UNHOOK_SSSDT(0x1337, orgNtUserWindowFromPhysicalPoint, 1);
	//UNHOOK_SSSDT(0x12F0, orgNtUserRealChildWindowFromPoint, 2);
//	UNHOOK_SSSDT(0x1007, orgNtUserMessageCall, 6);

	KeUnstackDetachProcess(&pkapc_state);

}