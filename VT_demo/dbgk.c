

#include "ntddk.h"
ULONG64 fc_DbgkGetAdrress(PUNICODE_STRING64 funcstr){
	UNICODE_STRING64 usFuncName;
	RtlInitUnicodeString(&usFuncName, funcstr);
	return MmGetSystemRoutineAddress(&usFuncName);

}
/**
#include "KernelStruct.h"
#include "ntimage.h"
void ZwFlushInstructionCache();
VOID NTAPI DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent);
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

typedef VOID (__fastcall* KiCheckForKernelApcDelivery1)();

#define ProbeForWriteGenericType(Ptr, Type)                                    \
	do {                                                                       \
	if ((ULONG_PTR)(Ptr) + sizeof(Type) - 1 < (ULONG_PTR)(Ptr) ||          \
	(ULONG_PTR)(Ptr) + sizeof(Type) - 1 >= (ULONG_PTR)MmUserProbeAddress) { \
	ExRaiseAccessViolation();                                          \
						}                                                                      \
		*(volatile Type *)(Ptr) = *(volatile Type *)(Ptr);                     \
					} while (0)

#define ProbeForWriteHandle(Ptr) ProbeForWriteGenericType(Ptr, HANDLE)
#define PspSetProcessFlag(Flags, Flag) \
	RtlInterlockedSetBitsDiscardReturn (Flags, Flag)
extern ProbeWrite(ULONG64 PTR);
typedef LONG(*EXSYSTEMEXCEPTIONFILTER)(VOID);
VOID ExfReleasePushLockShared(PEX_PUSH_LOCK PushLock);
VOID ExfAcquirePushLockShared(PEX_PUSH_LOCK PushLock);


NTSTATUS
NTAPI
DbgkpSendApiMessage(IN OUT PDBGKM_MSG ApiMsg,
IN ULONG SuspendProcess);


typedef NTSTATUS
(__fastcall*
proxyDbgkpSendApiMessage)(IN OUT PDBGKM_MSG ApiMsg,
IN ULONG SuspendProcess);

NTSTATUS
SeLocateProcessImageName(
_Inout_ PEPROCESS Process,
_Outptr_ PUNICODE_STRING *pImageFileName
);
#define EX_PUSH_LOCK_SHARE_INC       ((ULONG_PTR)0x10)
#define EX_PUSH_LOCK_PTR_BITS        ((ULONG_PTR)0xf)
#define EX_PUSH_LOCK_LOCK            ((ULONG_PTR)0x1)
#define DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(hdrs,field) \
	((hdrs)->OptionalHeader.##field)
PVOID
ObFastReferenceObjectLocked(
IN PEX_FAST_REF FastRef
);
VOID
ObFastDereferenceObject(
IN PEX_FAST_REF FastRef,
IN PVOID Object
);
NTSTATUS
PsReferenceProcessFilePointer(
IN PEPROCESS Process,
OUT PVOID *OutFileObject
);
VOID
ExAcquirePushLockShared(
IN PEX_PUSH_LOCK PushLock
)
{

	if (InterlockedCompareExchangePointer(&PushLock->Ptr,
		(PVOID)(EX_PUSH_LOCK_SHARE_INC | EX_PUSH_LOCK_LOCK),
		NULL) != NULL) {
		ExfAcquirePushLockShared(PushLock);
	}
}

VOID
ExReleasePushLockShared(
IN PEX_PUSH_LOCK PushLock
)
{
	EX_PUSH_LOCK OldValue, NewValue;

	OldValue.Value = EX_PUSH_LOCK_SHARE_INC | EX_PUSH_LOCK_LOCK;
	NewValue.Value = 0;

	if (InterlockedCompareExchangePointer(&PushLock->Ptr,
		NewValue.Ptr,
		OldValue.Ptr) != OldValue.Ptr) {
		ExfReleasePushLockShared(PushLock);
	}
}


VOID
KeEnterCriticalRegionThread(
PKTHREAD Thread
)
{
	Thread->KernelApcDisable -= 1;
	return;
}

typedef NTSTATUS
(*OBINSERTOBJECT)(
__in PVOID Object,
__inout_opt PACCESS_STATE PassedAccessState,
__in_opt ACCESS_MASK DesiredAccess,
__in ULONG ObjectPointerBias,
__out_opt PVOID *NewObject,
__out_opt PHANDLE Handle
);

typedef NTSTATUS(__stdcall *OBCREATEOBJECT)(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID *Object
	);
typedef NTSTATUS
(*OBOPENOBJECTBYPOINTER)(
__in PVOID Object,
__in ULONG HandleAttributes,
__in_opt PACCESS_STATE PassedAccessState,
__in ACCESS_MASK DesiredAccess,
__in_opt POBJECT_TYPE ObjectType,
__in KPROCESSOR_MODE AccessMode,
__out PHANDLE Handle
);


typedef NTSTATUS
(*ObDuplicateObject1)(
IN PEPROCESS_S SourceProcess,
IN HANDLE SourceHandle,
IN PEPROCESS_S TargetProcess OPTIONAL,
OUT PHANDLE TargetHandle OPTIONAL,
IN ACCESS_MASK DesiredAccess,
IN ULONG HandleAttributes,
IN ULONG Options,
IN KPROCESSOR_MODE PreviousMode
);
typedef NTSTATUS(__fastcall *PsGetNextProcessThreadx)(PEPROCESS_S process,PKTHREAD THREAD);
typedef NTSTATUS(__fastcall *DbgkpPostModuleMessagesx)(PEPROCESS_S process, PKTHREAD THREAD,PDEBUG_OBJECT debug);
typedef NTSTATUS(__fastcall *KeThawAllThreadsx)();
typedef NTSTATUS(__fastcall *PsResumeThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(__fastcall *PsSuspendThreadx)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
typedef NTSTATUS(__fastcall *MmGetFileNameForSectionx)(IN PVOID Thread, OUT POBJECT_NAME_INFORMATION FileName OPTIONAL);
typedef NTSTATUS(__fastcall *PsTerminateProcessx)(IN PEPROCESS_S Process, NTSTATUS STATUS);

//proxyDbgkpSendApiMessage DbgkpSendApiMessage;

typedef NTSTATUS(__fastcall *PsGetNextProcessx)(POBJECT_TYPE object);


typedef NTSTATUS(__fastcall *LpcRequestWaitReplyPortExx)(PVOID64 port, PPORT_MESSAGE Message, PPORT_MESSAGE Buffer);
typedef
NTSTATUS
(__fastcall* DbgkpPostFakeThreadMessagesx)(IN PEPROCESS_S Process,
IN ULONG64 DebugObject,
IN PETHREAD StartThread,
OUT PETHREAD *FirstThread,
OUT PETHREAD *LastThread);
typedef NTSTATUS(__fastcall *KeFreezeAllThreadsx)();
ULONG64 __fastcall RtlImageNtHeader(PVOID64 ad);

LpcRequestWaitReplyPortExx LpcRequestWaitReplyPortEx;
PsGetNextProcessx PsGetNextProcess;
PsTerminateProcessx PsTerminateProcess;
MmGetFileNameForSectionx MmGetFileNameForSection;
KeThawAllThreadsx KeThawAllThreads;
PsGetNextProcessThreadx PsGetNextProcessThread;
DbgkpPostModuleMessagesx DbgkpPostModuleMessages;
EXSYSTEMEXCEPTIONFILTER  ExSystemExceptionFilter;
OBINSERTOBJECT ObInsertObject;
OBCREATEOBJECT ObCreateObject;
OBOPENOBJECTBYPOINTER ObOpenObjectByPointer;
PsResumeThreadx PsResumeThread;
PsSuspendThreadx PsSuspendThread;
FAST_MUTEX DbgkFastMutex;
ULONG64 DbgkpProcessDebugPortMutex;
ObDuplicateObject1 ObDuplicateObject;
KiCheckForKernelApcDelivery1 KiCheckForKernelApcDelivery12;
POBJECT_TYPE_S DbgkDebugObjectType;
POBJECT_TYPE_S NewDbgObject;
POBJECT_TYPE_S *ObTypeIndexTable = 0;
ULONG64 *PspSystemDlls;
ULONG64 PspNotifyEnableMask;
DbgkpPostFakeThreadMessagesx DbgkpPostFakeThreadMessages;
KeFreezeAllThreadsx KeFreezeAllThreads;


VOID
NTAPI
DbgkpDeleteObject(IN PVOID DebugObject)
{
	PAGED_CODE();


	ASSERT(IsListEmpty(&((PDEBUG_OBJECT)DebugObject)->EventList));
}

VOID
__fastcall
DbgkpCloseObject(IN PEPROCESS OwnerProcess OPTIONAL,
IN PVOID ObjectBody,
IN ACCESS_MASK GrantedAccess,
IN ULONG HandleCount,
IN ULONG SystemHandleCount)
{
	PDEBUG_OBJECT DebugObject = ObjectBody;
	PEPROCESS_S Process = NULL;
	BOOLEAN DebugPortCleared = FALSE;
	PLIST_ENTRY DebugEventList;
	PDEBUG_EVENT DebugEvent;
	PAGED_CODE();



	if (SystemHandleCount > 1) return;


	ExAcquireFastMutex(&DebugObject->Mutex);


	DebugObject->DebuggerInactive = TRUE;


	DebugEventList = DebugObject->EventList.Flink;
	InitializeListHead(&DebugObject->EventList);


	ExReleaseFastMutex(&DebugObject->Mutex);

	KeSetEvent(&DebugObject->EventsPresent, IO_NO_INCREMENT, FALSE);


	while ((Process = PsGetNextProcess(Process)))
	{

		if (Process->Pcb.newdbgport == DebugObject)
		{

			ExAcquireFastMutex(&DbgkFastMutex);


			if (Process->Pcb.newdbgport == DebugObject)
			{

				Process->Pcb.newdbgport = NULL;
				DebugPortCleared = TRUE;
			}


			ExReleaseFastMutex(&DbgkFastMutex);


			if (DebugPortCleared)
			{

				//DbgkpMarkProcessPeb(Process);


				if (DebugObject->KillProcessOnExit)
				{

					PsTerminateProcess(Process, STATUS_DEBUGGER_INACTIVE);
				}


				ObDereferenceObject(DebugObject);
			}
		}
	}


	while (DebugEventList != &DebugObject->EventList)
	{

		DebugEvent = CONTAINING_RECORD(DebugEventList, DEBUG_EVENT, EventList);


		DebugEventList = DebugEventList->Flink;


		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}
}

POBJECT_TYPE CreateNewObjectType(POBJECT_TYPE_S *OrigDebugObjectType)
{
	NTSTATUS					status;
	POBJECT_TYPE_S				NewObjectType;

	UNICODE_STRING				usObjectTypeName, usFuncName;
	OBCREATEOBJECTTYPE			ObCreateObjectType;
	OBJECT_TYPE_INITIALIZER_S	Object_Type_Init = {0};

	NewObjectType = NULL;

	if (OrigDebugObjectType == NULL || *OrigDebugObjectType == NULL || ObTypeIndexTable==NULL)
	{
		return NULL;
	}


	RtlInitUnicodeString(&usObjectTypeName, L"VV-DBG");
	RtlInitUnicodeString(&usFuncName, L"ObCreateObjectType");
	ObCreateObjectType = (OBCREATEOBJECTTYPE)MmGetSystemRoutineAddress(&usFuncName);
	if (ObCreateObjectType == NULL)
	{
		return NULL;
	}
	
	memset(&Object_Type_Init, 0x00, sizeof(OBJECT_TYPE_INITIALIZER_S));
	memcpy(&Object_Type_Init, &(*OrigDebugObjectType)->TypeInfo, sizeof(OBJECT_TYPE_INITIALIZER_S));
	Object_Type_Init.DeleteProcedure = &DbgkpDeleteObject;
	Object_Type_Init.CloseProcedure = &DbgkpCloseObject;

	status = ObCreateObjectType(&usObjectTypeName, &Object_Type_Init, NULL, &NewObjectType);
	if (status == STATUS_OBJECT_NAME_COLLISION)
	{
		ULONG Index = 2;
		while (ObTypeIndexTable[Index])
		{
			if (RtlCompareUnicodeString(&ObTypeIndexTable[Index]->Name, &usObjectTypeName, FALSE) == 0)
			{
				return (POBJECT_TYPE)ObTypeIndexTable[Index];
			}
			Index++;
		}
	}

	return (POBJECT_TYPE)NewObjectType;
}



VOID
KeLeaveCriticalRegionThread(
IN PKTHREAD Thread
)
{
	if ((Thread->KernelApcDisable += 1) == 0) {
		if (Thread->ApcState.ApcListHead[KernelMode].Flink !=
			&Thread->ApcState.ApcListHead[KernelMode]) {

			if (Thread->SpecialApcDisable == 0) {
				KiCheckForKernelApcDelivery12();
			}
		}
	}
	return;
}

NTSTATUS __fastcall proxyNtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags
	)
{
	NTSTATUS status;
	HANDLE Handle;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE        PreviousMode;

	PreviousMode = ExGetPreviousMode();

	DbgPrint("HOOK NTCREATEDEBUGOBJECT");
	try {
		if (PreviousMode != KernelMode) {
			ProbeForWriteHandle(DebugObjectHandle);
		
			*DebugObjectHandle = *DebugObjectHandle;
		}
		*DebugObjectHandle = NULL;

	} except(ExSystemExceptionFilter()) {
		return GetExceptionCode();
	}

	if (Flags & ~DEBUG_KILL_ON_CLOSE) {
		return STATUS_INVALID_PARAMETER;
	}
	
	//创建调试对象
	status = ObCreateObject(
		PreviousMode,
		NewDbgObject,        
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);
		
	/ *	status = ObCreateObject(
		PreviousMode,
		*(ULONG64*)DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);* /
	if (!NT_SUCCESS(status)) {
		DbgPrint("创建出错");
		return status;
	}
	//初始化调试对象
	ExInitializeFastMutex(&DebugObject->Mutex);
	InitializeListHead(&DebugObject->EventList);
	KeInitializeEvent(&DebugObject->EventsPresent, NotificationEvent, FALSE);

	if (Flags & DEBUG_KILL_ON_CLOSE) {
		DebugObject->Flags = DEBUG_OBJECT_KILL_ON_CLOSE;
	}
	else {
		DebugObject->Flags = 0;
	}

	
	status = ObInsertObject(
		DebugObject,
		NULL,
		DesiredAccess,
		0,
		NULL,
		&Handle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("插入出错");
		return status;
	}

	try {
		*DebugObjectHandle = Handle;
	} except(ExSystemExceptionFilter()) {
		status = GetExceptionCode();
	}

	return status;
}

HANDLE
NTAPI
DbgkpSectionToFileHandle(IN PVOID Section)
{
	NTSTATUS Status;
	POBJECT_NAME_INFORMATION FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	HANDLE Handle;
	PAGED_CODE();

	
	Status = MmGetFileNameForSection(Section, &FileName);
	if (!NT_SUCCESS(Status)) return NULL;

	InitializeObjectAttributes(&ObjectAttributes,
		&FileName->Name,
		OBJ_CASE_INSENSITIVE |
		OBJ_FORCE_ACCESS_CHECK |
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);


	Status = ZwOpenFile(&Handle,
		GENERIC_READ | SYNCHRONIZE,
		&ObjectAttributes,
		&IoStatusBlock,
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_SYNCHRONOUS_IO_NONALERT);


	ExFreePool(FileName);
	if (!NT_SUCCESS(Status)) return NULL;
	return Handle;
}


BOOLEAN
NTAPI
DbgkpSuspendProcess(VOID)
{
	PAGED_CODE();


	if (!((PEPROCESS_S)PsGetCurrentProcess())->ProcessDelete)
	{
	
		KeFreezeAllThreads();
		return TRUE;
	}
	else
	{
	
		return FALSE;
	}
}


VOID
NTAPI
DbgkpResumeProcess(VOID)
{
	PAGED_CODE();

	
	KeThawAllThreads();
}


PVOID PsQuerySystemDllInfo(
	ULONG index)		
{
	PVOID64	DllInfo;

	DllInfo = (PVOID64)PspSystemDlls[index];	
	if (DllInfo != NULL &&
		*(PVOID*)((char*)DllInfo + 0x28) != 0)
	{
		return (PVOID)((ULONG64)DllInfo + 0x10);
	}

	return NULL;
}
/ **
VOID DbgkSendSystemDllMessages(
	PETHREAD		Thread,
	PDEBUG_OBJECT	DebugObject,
	PDBGKM_MSG	ApiMsg
	)
{
	NTSTATUS	status;

	HANDLE		FileHandle;

	ULONG		index;
	PTEB64		Teb;
	PEPROCESS_S	Process;
	PETHREAD	CurrentThread;
	PMODULE_INFO	DllInfo;
	BOOLEAN		bSource;
	KAPC_STATE ApcState;
	PIMAGE_NT_HEADERS NtHeaders;

	IO_STATUS_BLOCK	IoStackBlock;
	OBJECT_ATTRIBUTES	ObjectAttr;

	if (Thread)
	{
		Process = (PEPROCESS_S)Thread->Tcb.Process;
	}
	else{
		Process = (PEPROCESS_S)PsGetCurrentProcess();
	}

	CurrentThread = (PETHREAD)PsGetCurrentThread();
	index = 0;
	do
	{
		if (index >= 2)
		{
			break;
		}
		DllInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
		if (DllInfo != NULL)
		{
			ApiMsg->LoadDll.DebugInfoFileOffset = 0;
			ApiMsg->LoadDll.DebugInfoSize = 0;
			ApiMsg->LoadDll.FileHandle = NULL;

			Teb = NULL;

			ApiMsg->LoadDll.BaseOfDll = DllInfo->BaseOfDll;

			if (Thread && index != 0)
			{
				bSource = TRUE;
				KeStackAttachProcess((PEPROCESS)Process, &ApcState);
			}
			else{
				bSource = FALSE;
			}

			NtHeaders = RtlImageNtHeader(DllInfo->BaseOfDll);
			if (NtHeaders != NULL)
			{
				ApiMsg->LoadDll.DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				ApiMsg->LoadDll.DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}

			if (Thread == 0)
			{
				if (!IS_SYSTEM_THREAD(CurrentThread) &&
					CurrentThread->Tcb.ApcStateIndex != 1)
				{
					Teb = (PTEB64)CurrentThread->Tcb.Teb;
				}

				if (Teb)
				{
					
					RtlStringCbCopyW(Teb->StaticUnicodeBuffer, 261 * sizeof(wchar_t), DllInfo->Buffer);

					Teb->NtTib.ArbitraryUserPointer = Teb->StaticUnicodeBuffer;
					ApiMsg->LoadDll.NamePointer = (PVOID)&Teb->NtTib.ArbitraryUserPointer;
				}
			}

			if (bSource == TRUE)
			{
				KeUnstackDetachProcess(&ApcState);
			}

			InitializeObjectAttributes(
				&ObjectAttr,
				&DllInfo->FileName,
				OBJ_CASE_INSENSITIVE | OBJ_FORCE_ACCESS_CHECK | OBJ_KERNEL_HANDLE,
				NULL,
				NULL);

			status = ZwOpenFile(
				&FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&ObjectAttr,
				&IoStackBlock,
				FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
				FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(status))
			{
				FileHandle = NULL;
			}

			
			ApiMsg->h.u1.Length = sizeof(DBGKM_MSG) << 16 |
				(8 + sizeof(DBGKM_LOAD_DLL));
			ApiMsg->h.u2.ZeroInit = 0;
			ApiMsg->h.u2.s2.Type = LPC_DEBUG_EVENT;
			ApiMsg->ApiNumber = DbgKmLoadDllApi;

			if (Thread == NULL)
			{
				DbgkpSendApiMessage(ApiMsg, 0x3);
				if (FileHandle != NULL)
				{
					ObCloseHandle(FileHandle, KernelMode);
				}
				if (Teb != NULL)
				{
					Teb->NtTib.ArbitraryUserPointer = NULL;

				}
			}
			else{
				status = DbgkpQueueMessage(
					Process,
					Thread,
					ApiMsg,
					DEBUG_EVENT_NOWAIT,
					DebugObject);
				if (!NT_SUCCESS(status))
				{
					if (FileHandle != NULL)
					{
						ObCloseHandle(FileHandle, KernelMode);
					}
				}
			}
		}
		index++;
	} while (TRUE);
}
* /
/ **
VOID __fastcall
DbgkCreateThread(
PETHREAD Thread
)
{
	DBGKM_MSG m;
	PDBGKM_CREATE_THREAD CreateThreadArgs;
	PDBGKM_CREATE_PROCESS CreateProcessArgs;
	PEPROCESS_S Process;
	PDBGKM_LOAD_DLL LoadDllArgs;
	NTSTATUS status;
	PIMAGE_NT_HEADERS NtHeaders;
	ULONG OldFlags;

	ULONG	index;
	PMODULE_INFO ModuleInfo;
	PDEBUG_OBJECT DebugObject;
	PSYSTEM_DLL	SystemDll;
	PVOID	Object;
	PFILE_OBJECT FileObject;
	PKTHREAD	CurrentThread;

	Process = (PEPROCESS_S)Thread->Tcb.Process;

	OldFlags = PspSetProcessFlag(&Process->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED | PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE);

	if ((OldFlags&PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE) == 0 &&
		(*(ULONG64*)PspNotifyEnableMask & 0x1))
	{

		IMAGE_INFO_EX ImageInfoEx;
		PUNICODE_STRING ImageName;
		POBJECT_NAME_INFORMATION FileNameInfo;

		//
		// notification of main .exe
		//

		ImageInfoEx.ImageInfo.Properties = 0;
		ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
		ImageInfoEx.ImageInfo.ImageBase = Process->SectionBaseAddress;
		ImageInfoEx.ImageInfo.ImageSize = 0;

		try {
			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);

			if (NtHeaders) {
				ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			ImageInfoEx.ImageInfo.ImageSize = 0;
		}
		ImageInfoEx.ImageInfo.ImageSelector = 0;
		ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

		PsReferenceProcessFilePointer((PEPROCESS)Process, &FileObject);
		status = SeLocateProcessImageName((PEPROCESS)Process, &ImageName);
		if (!NT_SUCCESS(status))
		{
			ImageName = NULL;
		}

		PsCallImageNotifyRoutines(
			ImageName,
			Process->UniqueProcessId,
			FileObject,
			&ImageInfoEx);

		if (ImageName)
		{
			//因为在SeLocateProcessImageName中为ImageName申请了内存，所以要在此处释放掉
			ExFreePoolWithTag(ImageName, 0);
		}

		//PsReferenceProcessFilePointer增加了引用计数
		ObfDereferenceObject(FileObject);

		index = 0;
		while (index < 2)
		{
			ModuleInfo = (PMODULE_INFO)PsQuerySystemDllInfo(index);
			if (ModuleInfo != NULL)
			{
				ImageInfoEx.ImageInfo.Properties = 0;
				ImageInfoEx.ImageInfo.ImageAddressingMode = IMAGE_ADDRESSING_MODE_32BIT;
				ImageInfoEx.ImageInfo.ImageBase = ModuleInfo->BaseOfDll;
				ImageInfoEx.ImageInfo.ImageSize = 0;

				try{
					NtHeaders = RtlImageNtHeader(ModuleInfo->BaseOfDll);
					if (NtHeaders)
					{
						ImageInfoEx.ImageInfo.ImageSize = DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, SizeOfImage);
					}
				}except(EXCEPTION_EXECUTE_HANDLER) {
					ImageInfoEx.ImageInfo.ImageSize = 0;
				}

				ImageInfoEx.ImageInfo.ImageSelector = 0;
				ImageInfoEx.ImageInfo.ImageSectionNumber = 0;

				//实际就是PspSystemDlls
				SystemDll = (PSYSTEM_DLL)((ULONG)ModuleInfo - 0x8);
				Object = ObFastReferenceObject(&SystemDll->FastRef);
				if (Object == NULL)
				{
					CurrentThread = (PKTHREAD)PsGetCurrentThread();
					KeEnterCriticalRegionThread(CurrentThread);

					ExAcquirePushLockShared(&SystemDll->Lock);

					//由于系统模块不可能得不到，所以逆向发现win7没做判断
					Object = ObFastReferenceObjectLocked(&SystemDll->FastRef);

					ExReleasePushLockShared(&SystemDll->Lock);

					KeLeaveCriticalRegionThread(CurrentThread);

				}

				FileObject = MmGetFileObjectForSection(Object);

				if (Object != NULL)
				{
					ObFastDereferenceObject(
						&SystemDll->FastRef,
						Object);
				}

				PsCallImageNotifyRoutines(
					&SystemDll->ModuleInfo.FileName,
					Process->UniqueProcessId,
					FileObject,
					&ImageInfoEx);

				ObfDereferenceObject(FileObject);
			}

			index++;
		}
	}

	DebugObject = (PDEBUG_OBJECT)Process->DebugPort;

	if (DebugObject == NULL) {
		return;
	}

	if ((OldFlags&PS_PROCESS_FLAGS_CREATE_REPORTED) == 0)
	{

		CreateThreadArgs = &m.u.CreateProcessInfo.InitialThread;
		CreateThreadArgs->SubSystemKey = 0;

		CreateProcessArgs = &m.u.CreateProcessInfo;
		CreateProcessArgs->SubSystemKey = 0;
		CreateProcessArgs->FileHandle = DbgkpSectionToFileHandle(
			Process->SectionObject
			);
		CreateProcessArgs->BaseOfImage = Process->SectionBaseAddress;
		CreateThreadArgs->StartAddress = NULL;
		CreateProcessArgs->DebugInfoFileOffset = 0;
		CreateProcessArgs->DebugInfoSize = 0;

		try {

			NtHeaders = RtlImageNtHeader(Process->SectionBaseAddress);

			if (NtHeaders) {

				CreateThreadArgs->StartAddress = (PVOID)(DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, ImageBase) +
					DBGKP_FIELD_FROM_IMAGE_OPTIONAL_HEADER(NtHeaders, AddressOfEntryPoint));

				CreateProcessArgs->DebugInfoFileOffset = NtHeaders->FileHeader.PointerToSymbolTable;
				CreateProcessArgs->DebugInfoSize = NtHeaders->FileHeader.NumberOfSymbols;
			}
		} except(EXCEPTION_EXECUTE_HANDLER) {
			CreateThreadArgs->StartAddress = NULL;
			CreateProcessArgs->DebugInfoFileOffset = 0;
			CreateProcessArgs->DebugInfoSize = 0;
		}

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateProcessApi, sizeof(*CreateProcessArgs));

		DbgkpSendApiMessage(&m, FALSE);

		if (CreateProcessArgs->FileHandle != NULL) {
			ObCloseHandle(CreateProcessArgs->FileHandle, KernelMode);
		}

		DbgkSendSystemDllMessages(
			NULL,
			NULL,
			&m);
	}
	else{

		CreateThreadArgs = &m.u.CreateThread;
		CreateThreadArgs->SubSystemKey = 0;
		CreateThreadArgs->StartAddress = Thread->Win32StartAddress;

		DBGKM_FORMAT_API_MSG(m, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));

		DbgkpSendApiMessage(&m, TRUE);
	}

	if (Thread->ClonedThread == TRUE)
	{
		DbgkpPostModuleMessages(
			Process,
			Thread,
			NULL);
	}
}

* /

VOID
NTAPI
proxyDbgkExitProcess(IN NTSTATUS ExitStatus)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_EXIT_PROCESS ExitProcess = &ApiMessage.u.ExitProcess;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();
	PAGED_CODE();

	/ **
	if (PsGetCurrentThread()->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
		return;
	}
	else {
	
	}
	* /
	if (!Process->Pcb.newdbgport) {
		return;
	}

	if (PsGetCurrentThread()->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_DEADTHREAD) {
		return;
	}

	
	ExitProcess->ExitStatus = ExitStatus;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXIT_PROCESS));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExitProcessApi;





	KeQuerySystemTime(&Process->ExitTime);


	DbgkpSendApiMessage(&ApiMessage, FALSE);
}


VOID
NTAPI
proxyDbgkExitThread(IN NTSTATUS ExitStatus)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_EXIT_THREAD ExitThread = &ApiMessage.u.ExitThread;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();
	BOOLEAN Suspended;
	PAGED_CODE();

	/ **
	if (PsGetCurrentThread()->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_HIDEFROMDBG) {
		return;
	}
	else {

	}
	* /
	if (!Process->Pcb.newdbgport) {
		return;
	}

	if (PsGetCurrentThread()->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_DEADTHREAD) {
		return;
	}

	
	ExitThread->ExitStatus = ExitStatus;

	
	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXIT_THREAD));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmExitThreadApi;

	
	Suspended = DbgkpSuspendProcess();


	DbgkpSendApiMessage(&ApiMessage, FALSE);

	if (Suspended) DbgkpResumeProcess();
}


VOID
__fastcall
proxyDbgkMapViewOfSection(IN PVOID Section,
IN PVOID BaseAddress,
IN ULONG SectionOffset,
IN ULONG_PTR ViewSize)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_LOAD_DLL LoadDll = &ApiMessage.u.LoadDll;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();
	PIMAGE_NT_HEADERS NtHeader;
	PTEB64 TEB = (PTEB64)Thread->Tcb.Teb;
	PAGED_CODE();

	
	if ((ExGetPreviousMode() == KernelMode) ||
		
		!(Process->Pcb.newdbgport))
	{
		
		return;
	}

	LoadDll->FileHandle = DbgkpSectionToFileHandle(Section);
	LoadDll->BaseOfDll = BaseAddress;
	LoadDll->DebugInfoFileOffset = 0;
	LoadDll->DebugInfoSize = 0;
	LoadDll->NamePointer = &TEB->NtTib.ArbitraryUserPointer;
	

	NtHeader = RtlImageNtHeader(BaseAddress);
	if (NtHeader)
	{
	
		LoadDll->DebugInfoFileOffset = NtHeader->FileHeader.
			PointerToSymbolTable;
		LoadDll->DebugInfoSize = NtHeader->FileHeader.NumberOfSymbols;
	}

	
	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_LOAD_DLL));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmLoadDllApi;

	
	DbgkpSendApiMessage(&ApiMessage, TRUE);

	
	ObCloseHandle(LoadDll->FileHandle, KernelMode);
}

BOOLEAN DbgkpSuppressDbgMsg(
	IN PTEB64 Teb)
{
	BOOLEAN bSuppress;
	try{
		bSuppress = (BOOLEAN)Teb->SuppressDebugMsg;
	}except(EXCEPTION_EXECUTE_HANDLER){
		bSuppress = FALSE;
	}
	return bSuppress;
}
VOID
__fastcall
proxyDbgkUnMapViewOfSection( IN PEPROCESS_S PROCESS,IN PVOID BaseAddress)
{
	DBGKM_MSG ApiMessage;
	PDBGKM_UNLOAD_DLL UnloadDll = &ApiMessage.u.UnloadDll;
	PEPROCESS_S Process = PsGetCurrentProcess();
	PETHREAD Thread = PsGetCurrentThread();

	PTEB64	Teb;
	PAGED_CODE();

	
	if ((ExGetPreviousMode() == KernelMode) ||
		
		!(Process->Pcb.newdbgport))
	{
		
		return;
	}
	if (Thread->SystemThread != TRUE &&
		Thread->Tcb.ApcStateIndex != 0x1)
	{
		Teb = (PTEB64)Thread->Tcb.Teb;
	}
	else{
		Teb = NULL;
	}

	if (Teb != NULL && Process == Process)
	{
		if (!DbgkpSuppressDbgMsg(Teb))
		{
			//
		}
		else{
			//暂停调试消息的话就退出
			return;
		}
	}


	UnloadDll->BaseAddress = BaseAddress;

	 
	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_UNLOAD_DLL));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmUnloadDllApi;

	
	DbgkpSendApiMessage(&ApiMessage, TRUE);
}



NTSTATUS
NTAPI
DbgkpQueueMessage(IN PEPROCESS_S Process,
IN PETHREAD Thread,
IN PDBGKM_MSG Message,
IN ULONG Flags,
IN PDEBUG_OBJECT TargetObject OPTIONAL)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT LocalDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	BOOLEAN NewEvent;
	PAGED_CODE();


	/ * Check if we have to allocate a debug event * /
	NewEvent = (Flags & DEBUG_EVENT_NOWAIT) ? TRUE : FALSE;
	if (NewEvent)
	{
		/ * Allocate it * /
		DebugEvent = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(DEBUG_EVENT),
			'EgbD');
		if (!DebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

		/ * Set flags * /
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;

		/ * Reference the thread and process * /
		ObReferenceObject(Thread);
		ObReferenceObject(Process);

		/ * Set the current thread * /
		DebugEvent->BackoutThread = PsGetCurrentThread();

		/ * Set the debug object * /
		DebugObject = TargetObject;
	}
	else
	{
		/ * Use the debug event on the stack * /
		DebugEvent = &LocalDebugEvent;
		DebugEvent->Flags = Flags;

		/ * Acquire the port lock * /
		ExAcquireFastMutex(&DbgkFastMutex);

		/ * Get the debug object * /
		DebugObject = Process->Pcb.newdbgport;

		/ * Check what kind of API message this is * /
		switch (Message->ApiNumber)
		{
			/ * Process or thread creation * /
		case DbgKmCreateThreadApi:
		case DbgKmCreateProcessApi:

			/ * Make sure we're not skipping creation messages * /
			if (Thread->SkipCreationMsg) DebugObject = NULL;
			break;

			/ * Process or thread exit * /
		case DbgKmExitThreadApi:
		case DbgKmExitProcessApi:

			/ * Make sure we're not skipping exit messages * /
			if (Thread->SkipTerminationMsg) DebugObject = NULL;

			/ * No special handling for other messages * /
		default:
			break;
		}
	}

	/ * Setup the Debug Event * /
	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *Message;
	DebugEvent->ClientId = Thread->Cid;

	/ * Check if we have a port object * /
	if (!DebugObject)
	{
		/ * Fail * /
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		/ * Acquire the debug object mutex * /
		ExAcquireFastMutex(&DebugObject->Mutex);

		/ * Check if a debugger is active * /
		if (!DebugObject->DebuggerInactive)
		{
			/ * Add the event into the object's list * /
	
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);

			/ * Check if we have to signal it * /
			if (!NewEvent)
			{
				/ * Signal it * /
				KeSetEvent(&DebugObject->EventsPresent,
					IO_NO_INCREMENT,
					FALSE);
			}

			/ * Set success * /
			Status = STATUS_SUCCESS;
		}
		else
		{
			/ * No debugger * /
			Status = STATUS_DEBUGGER_INACTIVE;
		}

		/ * Release the object lock * /
		ExReleaseFastMutex(&DebugObject->Mutex);
	}

	/ * Check if we had acquired the port lock * /
	if (!NewEvent)
	{
		/ * Release it * /
		ExReleaseFastMutex(&DbgkFastMutex);

		/ * Check if we got here through success * /
		if (NT_SUCCESS(Status))
		{
			/ * Wait on the continue event * /
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			/ * Copy API Message back * /
			*Message = DebugEvent->ApiMsg;

			/ * Set return status * /
			Status = DebugEvent->Status;
		}
	}
	else
	{
		/ * Check if we failed * /
		if (!NT_SUCCESS(Status))
		{
			/ * Dereference the process and thread * /
			ObDereferenceObject(Thread);
			ObDereferenceObject(Process);

			/ * Free the debug event * /
			ExFreePoolWithTag(DebugEvent, 'EgbD');
		}
	}

	/ * Return status * /

	return Status;
}

/ *
NTSTATUS
NTAPI
DbgkpQueueMessage(IN PEPROCESS_S Process,
IN PETHREAD Thread,
IN PDBGKM_MSG Message,
IN ULONG Flags,
IN PDEBUG_OBJECT TargetObject OPTIONAL)
{
	PDEBUG_EVENT DebugEvent;
	DEBUG_EVENT LocalDebugEvent;
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	BOOLEAN NewEvent;
	PAGED_CODE();
	

	
	NewEvent = (Flags & DEBUG_EVENT_NOWAIT) ? TRUE : FALSE;
	if (NewEvent)
	{
		
		DebugEvent = ExAllocatePoolWithTag(NonPagedPool,
			sizeof(DEBUG_EVENT),
			'EgbD');
		if (!DebugEvent) return STATUS_INSUFFICIENT_RESOURCES;

		
		DebugEvent->Flags = Flags | DEBUG_EVENT_INACTIVE;

		
		ObReferenceObject(Thread);
		ObReferenceObject(Process);

		
		DebugEvent->BackoutThread = PsGetCurrentThread();

		
		DebugObject = TargetObject;
	}
	else
	{
		
		DebugEvent = &LocalDebugEvent;
		DebugEvent->Flags = Flags;

		
		ExAcquireFastMutex(&DbgkFastMutex);

	
	//	DebugObject = Process->Pcb.newdbgport;

		DebugObject = Process->DebugPort;
		switch (Message->ApiNumber)
		{
		
		case DbgKmCreateThreadApi:
		case DbgKmCreateProcessApi:

		
			//if (Thread->SkipCreationMsg) DebugObject = NULL;
			break;

			
		case DbgKmExitThreadApi:
		case DbgKmExitProcessApi:

			
		//	if (Thread->SkipTerminationMsg) DebugObject = NULL;

			
		default:
			break;
		}
	}

	
	KeInitializeEvent(&DebugEvent->ContinueEvent, SynchronizationEvent, FALSE);
	DebugEvent->Process = Process;
	DebugEvent->Thread = Thread;
	DebugEvent->ApiMsg = *Message;
	DebugEvent->ClientId = Thread->Cid;

	
	if (!DebugObject)
	{
		
		Status = STATUS_PORT_NOT_SET;
	}
	else
	{
		
		ExAcquireFastMutex(&DebugObject->Mutex);

		
		if (!DebugObject->DebuggerInactive)
		{
			
			
			InsertTailList(&DebugObject->EventList, &DebugEvent->EventList);

		
			if (!NewEvent)
			{
				
				KeSetEvent(&DebugObject->EventsPresent,
					IO_NO_INCREMENT,
					FALSE);
			}

			
			Status = STATUS_SUCCESS;
		}
		else
		{
			
			Status = STATUS_DEBUGGER_INACTIVE;
		}

	
		ExReleaseFastMutex(&DebugObject->Mutex);
	}

	
	if (!NewEvent)
	{
		
		ExReleaseFastMutex(&DbgkFastMutex);

		
		if (NT_SUCCESS(Status))
		{
			
			KeWaitForSingleObject(&DebugEvent->ContinueEvent,
				Executive,
				KernelMode,
				FALSE,
				NULL);

			
			*Message = DebugEvent->ApiMsg;

			
			Status = DebugEvent->Status;
		}
	}
	else
	{
		
		if (!NT_SUCCESS(Status))
		{
			
			ObDereferenceObject(Thread);
			ObDereferenceObject(Process);

			
			ExFreePoolWithTag(DebugEvent, 'EgbD');
		}
	}

	

	return Status;
}
* /


NTSTATUS
NTAPI
DbgkpSendApiMessageLpc(IN OUT PDBGKM_MSG Message,
IN PVOID Port,
IN BOOLEAN SuspendProcess)
{
	NTSTATUS Status;
	UCHAR Buffer[PORT_MAXIMUM_MESSAGE_LENGTH];
	BOOLEAN Suspended = FALSE;
	PAGED_CODE();


	if (SuspendProcess) Suspended = DbgkpSuspendProcess();

	
	Message->ReturnedStatus = STATUS_PENDING;

	
	PspSetProcessFlag(&((PEPROCESS_S)PsGetCurrentProcess())->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED);

	
	Status = LpcRequestWaitReplyPortEx(Port,
		(PPORT_MESSAGE)Message,
		(PPORT_MESSAGE)&Buffer[0]);

	
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);

	
	if (NT_SUCCESS(Status)) RtlCopyMemory(Message, Buffer, sizeof(DBGKM_MSG));


	if (Suspended) DbgkpResumeProcess();
	return Status;
}



NTSTATUS
NTAPI
DbgkpSendApiMessage(IN OUT PDBGKM_MSG ApiMsg,
IN ULONG SuspendProcess)
{
	NTSTATUS Status;
	BOOLEAN Suspended = FALSE;
	PAGED_CODE();

	
	if (SuspendProcess &0x1) Suspended = DbgkpSuspendProcess();

	
	ApiMsg->ReturnedStatus = STATUS_PENDING;

	
	//PspSetProcessFlag(&((PEPROCESS_S)PsGetCurrentProcess())->Flags, PS_PROCESS_FLAGS_CREATE_REPORTED);

	
	Status = DbgkpQueueMessage(PsGetCurrentProcess(),
		PsGetCurrentThread(),
		ApiMsg,
		((SuspendProcess & 0x2) << 0x5),
		NULL);

	
	ZwFlushInstructionCache(NtCurrentProcess(), NULL, 0);

	
	if (Suspended) DbgkpResumeProcess();
	return Status;
}


VOID
proxyDbgkCopyProcessDebugPort(
IN PEPROCESS_S TargetProcess,
IN PEPROCESS_S SourceProcess
)
/ *++

Routine Description:

Copies a debug port from one process to another.

Arguments:

TargetProcess - Process to move port to
sourceProcess - Process to move port from

Return Value:

None

--* /
{
	PDEBUG_OBJECT DebugObject;

	PAGED_CODE();

	TargetProcess->Pcb.newdbgport = NULL; // New process. Needs no locks.

	if (SourceProcess->Pcb.newdbgport != NULL) {
		ExAcquireFastMutex(&DbgkFastMutex);
		DebugObject = SourceProcess->Pcb.newdbgport;
		if (DebugObject != NULL && (SourceProcess->Flags&PS_PROCESS_FLAGS_NO_DEBUG_INHERIT) == 0) {
			//
			// We must not propagate a debug port thats got no handles left.
			//
			ExAcquireFastMutex(&DebugObject->Mutex);

			//
			// If the object is delete pending then don't propagate this object.
			//
			if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
				ObReferenceObject(DebugObject);
				TargetProcess->Pcb.newdbgport = DebugObject;
			}

			ExReleaseFastMutex(&DebugObject->Mutex);
		}
		ExReleaseFastMutex(&DbgkFastMutex);
	}
}



/ **
VOID
__fastcall
proxyDbgkCopyProcessDebugPort(IN PEPROCESS_S Process,
IN PEPROCESS_S Parent)
{
	PDEBUG_OBJECT DebugObject;
	PAGED_CODE();
	

	Process->Pcb.newdbgport = NULL;

	
	if (Parent->Pcb.newdbgport) return;

	
	ExAcquireFastMutex(&DbgkFastMutex);

	DebugObject = Parent->Pcb.newdbgport;
	if ((DebugObject) && !(Process->NoDebugInherit))
	{
		
		ExAcquireFastMutex(&DebugObject->Mutex);

		
		if (!DebugObject->DebuggerInactive)
		{
			
			ObReferenceObject(DebugObject);
			Process->Pcb.newdbgport = DebugObject;
		}

	
		ExReleaseFastMutex(&DebugObject->Mutex);
	}

	
	ExReleaseFastMutex(&DbgkFastMutex);
}
* /
PVOID PsCaptureExceptionPort(
	IN PEPROCESS_S Process)
{
	
	PVOID		ExceptionPort;
	PETHREAD Thread;
	Thread = (PETHREAD)PsGetCurrentThread();
	ExceptionPort = Process->ExceptionPortData;
	if (ExceptionPort != NULL)
	{
		KeEnterCriticalRegionThread(Thread);
		
		ExAcquirePushLockShared(&Process->ProcessLock);
		ExceptionPort = (PVOID64)((ULONG64)ExceptionPort & 0x0FFFFFFFFFFFFFFF8);
		ObfReferenceObject(ExceptionPort);
		ExReleasePushLockShared(&Process->ProcessLock);
		KeLeaveCriticalRegionThread(Thread);
		
	}

	return ExceptionPort;
}


VOID SendForWarExcept_Thread(){

	DBGKM_MSG ApiMessage = {0};
	PDBGKM_CREATE_THREAD CreateThreadArgs;


	ApiMessage.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_CREATE_THREAD));
	ApiMessage.h.u2.ZeroInit = 0;
	ApiMessage.h.u2.s2.Type = LPC_DEBUG_EVENT;
	ApiMessage.ApiNumber = DbgKmCreateThreadApi;
	ApiMessage.u.CreateThread.StartAddress = 0x10086;
	//DBGKM_FORMAT_API_MSG(ApiMessage, DbgKmCreateThreadApi, sizeof(*CreateThreadArgs));


	DbgkpSendApiMessage(&ApiMessage, FALSE);

}

BOOLEAN __fastcall MarkDbgProcess(){
	PEPROCESS_S Process=PsGetCurrentProcess();

	if (Process->Pcb.Unused3 == NULL && Process->Pcb.newdbgport!=NULL)
	{
		//InterlockedExchange8(&Process->Pcb.markdbg, TRUE);
		Process->Pcb.Unused3 = TRUE;
		SendForWarExcept_Thread(); //SendCreateThreadMsg
		
		return TRUE;

	}
	else{


		return FALSE;
	}





}



BOOLEAN
__fastcall
proxyDbgkForwardException(
IN PEXCEPTION_RECORD ExceptionRecord,
IN BOOLEAN DebugException,
IN BOOLEAN SecondChance
)
{
	NTSTATUS		st;

	PEPROCESS_S		Process;
	PVOID			ExceptionPort;
	PDEBUG_OBJECT	DebugObject;
	BOOLEAN			bLpcPort;

	DBGKM_MSG m;
	PDBGKM_EXCEPTION args;

	DebugObject = NULL;
	ExceptionPort = NULL;
	bLpcPort = FALSE;

	args = &m.u.Exception;

	m.h.u1.Length = sizeof(DBGKM_MSG) << 16 |
		(8 + sizeof(DBGKM_EXCEPTION));
	m.h.u2.ZeroInit = 0;
	m.h.u2.s2.Type = LPC_DEBUG_EVENT;
	m.ApiNumber = DbgKmExceptionApi;
//	DBGKM_FORMAT_API_MSG(m, DbgKmExceptionApi, sizeof(*args));

	Process = (PEPROCESS_S)PsGetCurrentProcess();

	if (DebugException == TRUE)
	{

			DebugObject = (PDEBUG_OBJECT)Process->Pcb.newdbgport;

	}
	else{
	//	ExceptionPort = PsCaptureExceptionPort(Process);
	//	m.h.u2.ZeroInit = LPC_EXCEPTION;
		bLpcPort = TRUE;
	}

	if ((ExceptionPort == NULL && DebugObject == NULL) &&
		DebugException == TRUE)
	{
		return FALSE;
	}
	MarkDbgProcess();
	args->ExceptionRecord = *ExceptionRecord;
	args->FirstChance = !SecondChance;

	if (bLpcPort == FALSE)
	{
		st = DbgkpSendApiMessage(&m, DebugException);
	}
	else if (ExceptionPort){

	//	st = DbgkpSendApiMessageLpc(&m, ExceptionPort, DebugException);
	//	ObfDereferenceObject(ExceptionPort);
	}
	else{
		m.ReturnedStatus = DBG_EXCEPTION_NOT_HANDLED;
		st = STATUS_SUCCESS;
	}

	if (NT_SUCCESS(st))
	{
		//根据汇编感觉这样写才恰当....
		st = m.ReturnedStatus;

		if (m.ReturnedStatus == DBG_EXCEPTION_NOT_HANDLED)
		{
			if (DebugException == TRUE)
			{
				return FALSE;
			}

			
		}


	}

	return NT_SUCCESS(st);
}


VOID
NTAPI
DbgkpFreeDebugEvent(IN PDEBUG_EVENT DebugEvent)
{
	PHANDLE Handle = NULL;
	PAGED_CODE();

	
	switch (DebugEvent->ApiMsg.ApiNumber)
	{
		
	case DbgKmCreateProcessApi:

	
		Handle = &DebugEvent->ApiMsg.u.CreateProcess.FileHandle;
		break;

	
	case DbgKmLoadDllApi:

	
		Handle = &DebugEvent->ApiMsg.u.LoadDll.FileHandle;

	default:
		break;
	}

	if ((Handle) && (*Handle)) ObCloseHandle(*Handle, KernelMode);

	
	ObDereferenceObject(DebugEvent->Process);
	ObDereferenceObject(DebugEvent->Thread);
	ExFreePoolWithTag(DebugEvent, 'EgbD');
}

VOID
NTAPI
DbgkpWakeTarget(IN PDEBUG_EVENT DebugEvent)
{
	PETHREAD Thread = DebugEvent->Thread;
	PAGED_CODE();

	
	if (DebugEvent->Flags & DEBUG_EVENT_SUSPEND) PsResumeThread(Thread, NULL);

	
	if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
	{
	
		ExReleaseRundownProtection(&Thread->RundownProtect);
	}

	
	if (DebugEvent->Flags & DEBUG_EVENT_NOWAIT)
	{
	
		DbgkpFreeDebugEvent(DebugEvent);
	}
	else
	{
		
		KeSetEvent(&DebugEvent->ContinueEvent, IO_NO_INCREMENT, FALSE);
	}
}

/ *
NTSTATUS
NTAPI
DbgkpPostFakeModuleMessages(IN PEPROCESS_S Process,
IN PETHREAD Thread,
IN PDEBUG_OBJECT DebugObject)
{
	PPEB Peb = Process->Peb;
	PPEB_LDR_DATA LdrData;
	PLDR_DATA_TABLE_ENTRY LdrEntry;
	PLIST_ENTRY ListHead, NextEntry;
	DBGKM_MSG ApiMessage;
	PDBGKM_LOAD_DLL LoadDll = &ApiMessage.LoadDll;
	ULONG i;
	PIMAGE_NT_HEADERS NtHeader;
	UNICODE_STRING ModuleName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS Status;
	PAGED_CODE();


	
	if (!Peb) return STATUS_SUCCESS;

	
	LdrData = Peb->Ldr;
	ListHead = &LdrData->InLoadOrderModuleList;
	NextEntry = ListHead->Flink;

	i = 0;
	while ((NextEntry != ListHead) && (i < 500))
	{
		
		if (!i)
		{
			
			NextEntry = NextEntry->Flink;
			i++;
			continue;
		}

		
		LdrEntry = CONTAINING_RECORD(NextEntry,
			LDR_DATA_TABLE_ENTRY,
			InLoadOrderLinks);

		
		RtlZeroMemory(&ApiMessage, sizeof(DBGKM_MSG));
		ApiMessage.ApiNumber = DbgKmLoadDllApi;

		
		LoadDll->BaseOfDll = LdrEntry->DllBase;
		LoadDll->NamePointer = NULL;

		NtHeader = RtlImageNtHeader(LoadDll->BaseOfDll);
		if (NtHeader)
		{
			
			LoadDll->DebugInfoFileOffset = NtHeader->FileHeader.
				PointerToSymbolTable;
			LoadDll->DebugInfoSize = NtHeader->FileHeader.NumberOfSymbols;
		}

	
		
		//Status = MmGetFileNameForAddress(NtHeader, &ModuleName);
		if (NT_SUCCESS(Status))
		{
			
			InitializeObjectAttributes(&ObjectAttributes,
				&ModuleName,
				OBJ_FORCE_ACCESS_CHECK |
				OBJ_KERNEL_HANDLE |
				OBJ_CASE_INSENSITIVE,
				NULL,
				NULL);

			
			Status = ZwOpenFile(&LoadDll->FileHandle,
				GENERIC_READ | SYNCHRONIZE,
				&ObjectAttributes,
				&IoStatusBlock,
				FILE_SHARE_READ |
				FILE_SHARE_WRITE |
				FILE_SHARE_DELETE,
				FILE_SYNCHRONOUS_IO_NONALERT);
			if (!NT_SUCCESS(Status)) LoadDll->FileHandle = NULL;

			
			ExFreePool(ModuleName.Buffer);
		}

		
		
		if (DebugObject==NULL
			)
		{

			DbgkpSendApiMessage(&ApiMessage, 0x3);
		}

		else{
			Status = DbgkpQueueMessage(Process,
				Thread,
				&ApiMessage,
				DEBUG_EVENT_NOWAIT,
				DebugObject);
		
		}
		if (!NT_SUCCESS(Status))
		{
			
			if (LoadDll->FileHandle) ObCloseHandle(LoadDll->FileHandle,
				KernelMode);
		}

		
		NextEntry = NextEntry->Flink;
		i++;
	}

	
	return STATUS_SUCCESS;
}
* /
/ **
NTSTATUS
NTAPI
DbgkpPostFakeThreadMessages(IN PEPROCESS_S Process,
IN PDEBUG_OBJECT DebugObject,
IN PETHREAD StartThread,
OUT PETHREAD *FirstThread,
OUT PETHREAD *LastThread)
{
	PETHREAD pFirstThread = NULL, ThisThread, OldThread = NULL, pLastThread;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOLEAN IsFirstThread;
	ULONG Flags;
	DBGKM_MSG ApiMessage;
	PDBGKM_CREATE_THREAD CreateThread = &ApiMessage.CreateThread;
	PDBGKM_CREATE_PROCESS CreateProcess = &ApiMessage.CreateProcess;
	BOOLEAN First;
	PIMAGE_NT_HEADERS NtHeader;
	PAGED_CODE();
	

	
	if (StartThread)
	{
		
		IsFirstThread = FALSE;
		pFirstThread = StartThread;
		ThisThread = StartThread;

		
		ObReferenceObject(StartThread);
	}
	else
	{
		
		ThisThread = PsGetNextProcessThread(Process, NULL);
		IsFirstThread = TRUE;
	}

	
	do
	{
		
		if (OldThread) ObDereferenceObject(OldThread);

		
		pLastThread = ThisThread;
		ObReferenceObject(ThisThread);
		if (ExAcquireRundownProtection(&ThisThread->RundownProtect))
		{
		
			Flags = DEBUG_EVENT_RELEASE | DEBUG_EVENT_NOWAIT;

			
			if (!ThisThread->SystemThread)
			{
				
				if (NT_SUCCESS(PsSuspendThread(ThisThread, NULL)))
				{
					
					Flags |= DEBUG_EVENT_SUSPEND;
				}
			}
		}
		else
		{
			
			Flags = DEBUG_EVENT_PROTECT_FAILED | DEBUG_EVENT_NOWAIT;
		}

		
		RtlZeroMemory(&ApiMessage, sizeof(ApiMessage));

		
		if ((IsFirstThread) &&
			!(Flags & DEBUG_EVENT_PROTECT_FAILED) &&
			!(ThisThread->SystemThread) )
		{
			
			First = TRUE;
		}
		else
		{
			
			First = FALSE;
		}

		
		if (First)
		{
			
			ApiMessage.ApiNumber = DbgKmCreateProcessApi;

			
			if (Process->SectionObject)
			{
				
				CreateProcess->FileHandle =
					DbgkpSectionToFileHandle(Process->SectionObject);
			}
			else
			{
			
				CreateProcess->FileHandle = NULL;
			}

			
			CreateProcess->BaseOfImage = Process->SectionBaseAddress;

			
			NtHeader = RtlImageNtHeader(Process->SectionBaseAddress);
			if (NtHeader)
			{
				
				CreateProcess->DebugInfoFileOffset = NtHeader->FileHeader.
					PointerToSymbolTable;
				CreateProcess->DebugInfoSize = NtHeader->FileHeader.
					NumberOfSymbols;
			}
		}
		else
		{
			
			ApiMessage.ApiNumber = DbgKmCreateThreadApi;
			CreateThread->StartAddress = ThisThread->StartAddress;
		}

	
		
		Status = DbgkpQueueMessage(Process,
			ThisThread,
			&ApiMessage,
			Flags,
			DebugObject);
		if (!NT_SUCCESS(Status))
		{
			
			if (Flags & DEBUG_EVENT_SUSPEND) PsResumeThread(ThisThread, NULL);

			
			if (Flags & DEBUG_EVENT_RELEASE)
			{
				
				ExReleaseRundownProtection(&ThisThread->RundownProtect);
			}

			
			if ((ApiMessage.ApiNumber == DbgKmCreateProcessApi) &&
				(CreateProcess->FileHandle))
			{
				
				ObCloseHandle(CreateProcess->FileHandle, KernelMode);
			}

			
			ObDereferenceObject(ThisThread);
			break;
		}

		
		if (First)
		{
		
			IsFirstThread = FALSE;

			
			ObReferenceObject(ThisThread);
			pFirstThread = ThisThread;
		}

		
		ThisThread = PsGetNextProcessThread(Process, ThisThread);
		OldThread = pLastThread;
	} while (ThisThread);

	
	if (!NT_SUCCESS(Status))
	{
		
		if (pFirstThread) ObDereferenceObject(pFirstThread);
		if (pLastThread) ObDereferenceObject(pLastThread);
		return Status;
	}

	
	if (!pFirstThread) return STATUS_UNSUCCESSFUL;


	*FirstThread = pFirstThread;
	*LastThread = pLastThread;
	return Status;
}

* /
NTSTATUS
NTAPI
DbgkpPostFakeProcessCreateMessages(IN PEPROCESS_S Process,
IN PDEBUG_OBJECT DebugObject,
OUT PETHREAD *LastThread)
{
	KAPC_STATE ApcState;
	PETHREAD FirstThread, FinalThread;
	PETHREAD ReturnThread = NULL;
	NTSTATUS Status;
	PAGED_CODE();
	

	
	KeStackAttachProcess(&Process->Pcb, &ApcState);


	Status = DbgkpPostFakeThreadMessages(Process,
		DebugObject,
		NULL,
		&FirstThread,
		&FinalThread);
	if (NT_SUCCESS(Status))
	{
		DbgkpPostModuleMessages(Process,
			FirstThread,
			DebugObject);
	//	Status = DbgkpPostFakeModuleMessages(Process,
			//FirstThread,
	//	DebugObject);
		if (!NT_SUCCESS(Status))
		{
			
			ObDereferenceObject(FinalThread);
		}
		else
		{
			
			ReturnThread = FinalThread;
		}

		
		ObDereferenceObject(FirstThread);
	}

	KeUnstackDetachProcess(&ApcState);

	
	*LastThread = ReturnThread;
	return Status;
}

VOID
NTAPI
DbgkpConvertKernelToUserStateChange(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
IN PDEBUG_EVENT DebugEvent)
{
	

	WaitStateChange->AppClientId = DebugEvent->ClientId;

	
	switch (DebugEvent->ApiMsg.ApiNumber)
	{
		
	case DbgKmCreateProcessApi:

		
		WaitStateChange->NewState = DbgCreateProcessStateChange;

		
		WaitStateChange->StateInfo.CreateProcessInfo.NewProcess =
			DebugEvent->ApiMsg.u.CreateProcess;

		
		DebugEvent->ApiMsg.u.CreateProcess.FileHandle = NULL;
		break;

		
	case DbgKmCreateThreadApi:

		
		WaitStateChange->NewState = DbgCreateThreadStateChange;

		
		WaitStateChange->StateInfo.CreateThread.NewThread.StartAddress =
			DebugEvent->ApiMsg.u.CreateThread.StartAddress;
		WaitStateChange->StateInfo.CreateThread.NewThread.SubSystemKey =
			DebugEvent->ApiMsg.u.CreateThread.SubSystemKey;
		break;

		
	case DbgKmExceptionApi:

		
		if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_BREAKPOINT)
		{
			
			WaitStateChange->NewState = DbgBreakpointStateChange;
		}
		else if ((NTSTATUS)DebugEvent->ApiMsg.u.Exception.ExceptionRecord.ExceptionCode ==
			STATUS_SINGLE_STEP)
		{
			
			WaitStateChange->NewState = DbgSingleStepStateChange;
		}
		else
		{
			
			WaitStateChange->NewState = DbgExceptionStateChange;
		}

		
		WaitStateChange->StateInfo.Exception.ExceptionRecord =
			DebugEvent->ApiMsg.u.Exception.ExceptionRecord;
	
		WaitStateChange->StateInfo.Exception.FirstChance =
			DebugEvent->ApiMsg.u.Exception.FirstChance;
		break;

		
	case DbgKmExitProcessApi:

		WaitStateChange->NewState = DbgExitProcessStateChange;
		WaitStateChange->StateInfo.ExitProcess.ExitStatus =
			DebugEvent->ApiMsg.u.ExitProcess.ExitStatus;
		break;

		
	case DbgKmExitThreadApi:

		
		WaitStateChange->NewState = DbgExitThreadStateChange;
		WaitStateChange->StateInfo.ExitThread.ExitStatus =
			DebugEvent->ApiMsg.u.ExitThread.ExitStatus;
		break;

		
	case DbgKmLoadDllApi:

	
		WaitStateChange->NewState = DbgLoadDllStateChange;
		
		
		WaitStateChange->StateInfo.LoadDll = DebugEvent->ApiMsg.u.LoadDll;

	
		DebugEvent->ApiMsg.u.LoadDll.FileHandle = NULL;
		break;

	
	case DbgKmUnloadDllApi:

		
		WaitStateChange->NewState = DbgUnloadDllStateChange;
		WaitStateChange->StateInfo.UnloadDll.BaseAddress =
			DebugEvent->ApiMsg.u.UnloadDll.BaseAddress;
		break;

	default:

		
		ASSERT(FALSE);
	}
}

VOID
NTAPI
DbgkpMarkProcessPeb(IN PEPROCESS_S Process)
{
	KAPC_STATE ApcState;
	PAGED_CODE();

	
	if (!ExAcquireRundownProtection(&Process->RundownProtect)) return;

	
	if (Process->Peb)
	{
	
		KeStackAttachProcess(&Process->Pcb, &ApcState);

		
		ExAcquireFastMutex(&DbgkFastMutex);

		Process->Peb->BeingDebugged = (Process->DebugPort) ? TRUE : FALSE;

		
		ExReleaseFastMutex(&DbgkFastMutex);

		
		KeUnstackDetachProcess(&ApcState);
	}

	
	ExReleaseRundownProtection(&Process->RundownProtect);
}

VOID
NTAPI
DbgkpOpenHandles(IN PDBGUI_WAIT_STATE_CHANGE WaitStateChange,
IN PEPROCESS Process,
IN PETHREAD Thread)
{
	NTSTATUS Status;
	HANDLE Handle;
	PHANDLE DupHandle;
	PAGED_CODE();
	

	
	switch (WaitStateChange->NewState)
	{
	
	case DbgCreateThreadStateChange:

		
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{
			
			WaitStateChange->
				StateInfo.CreateThread.HandleToThread = Handle;
		}
		return;

		
	case DbgCreateProcessStateChange:

		
		Status = ObOpenObjectByPointer(Thread,
			0,
			NULL,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{
			
			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToThread = Handle;
		}

		Status = ObOpenObjectByPointer(Process,
			0,
			NULL,
			PROCESS_ALL_ACCESS,
			*PsProcessType,
			KernelMode,
			&Handle);
		if (NT_SUCCESS(Status))
		{
			
			WaitStateChange->
				StateInfo.CreateProcessInfo.HandleToProcess = Handle;
		}

		
		DupHandle = &WaitStateChange->
			StateInfo.CreateProcessInfo.NewProcess.FileHandle;
		break;

	case DbgLoadDllStateChange:

	
		DupHandle = &WaitStateChange->StateInfo.LoadDll.FileHandle;
		break;

	
	default:
		return;
	}

	
	Handle = *DupHandle;
	if (Handle)
	{
		
		Status = ObDuplicateObject(PsGetCurrentProcess(),
			Handle,
			PsGetCurrentProcess(),
			DupHandle,
			0,
			0,
			DUPLICATE_SAME_ACCESS,
			KernelMode);
		if (!NT_SUCCESS(Status)) *DupHandle = NULL;

	
		ObCloseHandle(Handle, KernelMode);
	}
}



/ *
NTSTATUS
NTAPI
DbgkpSetProcessDebugObject(IN PEPROCESS_S Process,
IN PDEBUG_OBJECT DebugObject,
IN NTSTATUS MsgStatus,
IN PETHREAD LastThread)
{
	NTSTATUS Status;
	LIST_ENTRY TempList;
	BOOLEAN GlobalHeld = FALSE, DoSetEvent = TRUE;
	PETHREAD ThisThread, FirstThread;
	PLIST_ENTRY NextEntry;
	PDEBUG_EVENT DebugEvent;
	PETHREAD EventThread;
	PAGED_CODE();



	InitializeListHead(&TempList);

	
	if (NT_SUCCESS(MsgStatus))
	{
		
		Status = STATUS_SUCCESS;
	}
	else
	{
	
		LastThread = NULL;
		Status = MsgStatus;
	}


	if (NT_SUCCESS(Status))
	{
		
	ThreadScan:
		GlobalHeld = TRUE;
		ExAcquireFastMutex(&DbgkFastMutex);

		
		if (Process->Pcb.newdbgport)
	//	if (Process->DebugPort)
		{
			
			Status = STATUS_PORT_ALREADY_SET;
		}
		else
		{
			
			Process->Pcb.newdbgport = DebugObject;
		//	Process->DebugPort = DebugObject;
			
			ObReferenceObject(LastThread);

			
			ThisThread = PsGetNextProcessThread(Process, LastThread);
			if (ThisThread)
			{
				
				Process->Pcb.newdbgport = NULL;
				//Process->DebugPort = NULL;
				ExReleaseFastMutex(&DbgkFastMutex);
				GlobalHeld = FALSE;

				
				ObDereferenceObject(LastThread);

				
				Status = DbgkpPostFakeThreadMessages(Process,
					DebugObject,
					ThisThread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status))
				{
					
					LastThread = NULL;
				}
				else
				{
					
					ObDereferenceObject(FirstThread);
					goto ThreadScan;
				}
			}
		}
	}

	
	ExAcquireFastMutex(&DebugObject->Mutex);

	
	if (NT_SUCCESS(Status))
	{
		
		if (DebugObject->DebuggerInactive)
		{
			Process->Pcb.newdbgport = NULL;
		//	Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{
			
			PspSetProcessFlag(&Process->Flags,
				PS_PROCESS_FLAGS_NO_DEBUG_INHERIT |
				PS_PROCESS_FLAGS_CREATE_REPORTED);

			
			ObReferenceObject(DebugObject);
		}
	}

	
	NextEntry = DebugObject->EventList.Flink;
	while (NextEntry != &DebugObject->EventList)
	{
		
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
		NextEntry = NextEntry->Flink;
	

		
		if ((DebugEvent->Flags & DEBUG_EVENT_INACTIVE) &&
			(DebugEvent->BackoutThread == PsGetCurrentThread()))
		{
			
			EventThread = DebugEvent->Thread;
	

			
			if ((MsgStatus == STATUS_SUCCESS) &&
			
				(!EventThread->SystemThread))
			{
				
				if (DebugEvent->Flags & DEBUG_EVENT_PROTECT_FAILED)
				{
					
					PspSetProcessFlag(&EventThread->CrossThreadFlags  , PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

					
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else
				{
					
					if (DoSetEvent)
					{
						
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent,
							IO_NO_INCREMENT,
							FALSE);
						DoSetEvent = FALSE;
					}

					
					DebugEvent->BackoutThread = NULL;

					
					PspSetProcessFlag(&EventThread->CrossThreadFlags, PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);
				}
			}
			else
			{
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			
			if (DebugEvent->Flags & DEBUG_EVENT_RELEASE)
			{
			
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
			//	ExReleaseRundownProtection(&EventThread->RundownProtect);
			}
		}
	}

	
	ExReleaseFastMutex(&DebugObject->Mutex);

	
	if (GlobalHeld) ExReleaseFastMutex(&DbgkFastMutex);

	
	if (LastThread) ObDereferenceObject(LastThread);

	
	while (!IsListEmpty(&TempList))
	{
		
		NextEntry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);

		DbgkpWakeTarget(DebugEvent);
	}

	
	//if (NT_SUCCESS(Status)) DbgkpMarkProcessPeb(Process);
	return Status;
}* /



NTSTATUS
DbgkpSetProcessDebugObject(
IN PEPROCESS_S Process,
IN PDEBUG_OBJECT DebugObject,
IN NTSTATUS MsgStatus,
IN PETHREAD LastThread
)

{
	NTSTATUS Status;
	PETHREAD ThisThread;
	LIST_ENTRY TempList;
	PLIST_ENTRY Entry;
	PDEBUG_EVENT DebugEvent;
	BOOLEAN First;
	PETHREAD Thread;
	BOOLEAN GlobalHeld;
	PETHREAD FirstThread;

	PAGED_CODE();

	ThisThread = PsGetCurrentThread();

	InitializeListHead(&TempList);

	First = TRUE;
	GlobalHeld = FALSE;

	if (!NT_SUCCESS(MsgStatus)) {
		LastThread = NULL;
		Status = MsgStatus;
	}
	else {
		Status = STATUS_SUCCESS;
	}

	//
	// Pick up any threads we missed
	//
	if (NT_SUCCESS(Status)) {

		while (1) {
			//
			// Acquire the debug port mutex so we know that any new threads will
			// have to wait to behind us.
			//
			GlobalHeld = TRUE;

			ExAcquireFastMutex(&DbgkFastMutex);

			//
			// If the port has been set then exit now.
			//
			if (Process->Pcb.newdbgport != NULL)
			//if (Process->DebugPort != NULL)
			{
				Status = STATUS_PORT_ALREADY_SET;
				break;
			}
			//
			// Assign the debug port to the process to pick up any new threads
			//

		//	Process->DebugPort = DebugObject;

			Process->Pcb.newdbgport = DebugObject;
			//
			// Reference the last thread so we can deref outside the lock
			//
			ObReferenceObject(LastThread);

			//
			// Search forward for new threads
			//
			Thread = PsGetNextProcessThread(Process, LastThread);
			if (Thread != NULL) {

				//
				// Remove the debug port from the process as we are
				// about to drop the lock
				//
				Process->Pcb.newdbgport = NULL;
				//Process->DebugPort = NULL;
				ExReleaseFastMutex(&DbgkFastMutex);

				GlobalHeld = FALSE;

				ObDereferenceObject(LastThread);

				//
				// Queue any new thread messages and repeat.
				//

				Status = DbgkpPostFakeThreadMessages(Process,
					DebugObject,
					Thread,
					&FirstThread,
					&LastThread);
				if (!NT_SUCCESS(Status)) {
					LastThread = NULL;
					break;
				}
				ObDereferenceObject(FirstThread);
			}
			else {
				break;
			}
		}
	}

	//
	// Lock the debug object so we can check its deleted status
	//
	ExAcquireFastMutex(&DebugObject->Mutex);

	//
	// We must not propagate a debug port thats got no handles left.
	//

	if (NT_SUCCESS(Status)) {
		if ((DebugObject->Flags&DEBUG_OBJECT_DELETE_PENDING) == 0) {
			PspSetProcessFlag(&Process->Flags, PS_PROCESS_FLAGS_NO_DEBUG_INHERIT | PS_PROCESS_FLAGS_CREATE_REPORTED);
			ObReferenceObject(DebugObject);
		}
		else {
			Process->Pcb.newdbgport = NULL;
			//Process->DebugPort = NULL;
			Status = STATUS_DEBUGGER_INACTIVE;
		}
	}

	for (Entry = DebugObject->EventList.Flink;
		Entry != &DebugObject->EventList;
		) {

		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		Entry = Entry->Flink;

		if ((DebugEvent->Flags&DEBUG_EVENT_INACTIVE) != 0 && DebugEvent->BackoutThread == ThisThread) {
			Thread = DebugEvent->Thread;

			//
			// If the thread has not been inserted by CreateThread yet then don't
			// create a handle. We skip system threads here also
			//
			if (NT_SUCCESS(Status) && (!Thread->SystemThread)) {
				//
				// If we could not acquire rundown protection on this
				// thread then we need to suppress its exit message.
				//
				if ((DebugEvent->Flags&DEBUG_EVENT_PROTECT_FAILED) != 0) {
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG);
					RemoveEntryList(&DebugEvent->EventList);
					InsertTailList(&TempList, &DebugEvent->EventList);
				}
				else {
					if (First) {
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent, 0, FALSE);
						First = FALSE;
					}
					DebugEvent->BackoutThread = NULL;
					PspSetProcessFlag(&Thread->CrossThreadFlags,
						PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG);

				}
			}
			else {
				RemoveEntryList(&DebugEvent->EventList);
				InsertTailList(&TempList, &DebugEvent->EventList);
			}

			if (DebugEvent->Flags&DEBUG_EVENT_RELEASE) {
				DebugEvent->Flags &= ~DEBUG_EVENT_RELEASE;
				ExReleaseRundownProtection(&Thread->RundownProtect);
			}

		}
	}

	ExReleaseFastMutex(&DebugObject->Mutex);

	if (GlobalHeld) {
		ExReleaseFastMutex(&DbgkFastMutex);
	}

	if (LastThread != NULL) {
		ObDereferenceObject(LastThread);
	}

	while (!IsListEmpty(&TempList)) {
		Entry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(Entry, DEBUG_EVENT, EventList);
		DbgkpWakeTarget(DebugEvent);
	}

//	if (NT_SUCCESS(Status)) {
	//	DbgkpMarkProcessPeb(Process);
	//}

	return Status;
}


NTSTATUS
NTAPI
DbgkClearProcessDebugObject(IN PEPROCESS_S Process,
IN PDEBUG_OBJECT SourceDebugObject OPTIONAL)
{
	PDEBUG_OBJECT DebugObject;
	PDEBUG_EVENT DebugEvent;
	LIST_ENTRY TempList;
	PLIST_ENTRY NextEntry;
	PAGED_CODE();
	

	
	ExAcquireFastMutex(&DbgkFastMutex);

	
	DebugObject = Process->Pcb.newdbgport;

	
	if ((DebugObject) &&
		((DebugObject == SourceDebugObject) ||
		(SourceDebugObject == NULL)))
	{
	
		Process->Pcb.newdbgport = NULL;

		ExReleaseFastMutex(&DbgkFastMutex);
		//DbgkpMarkProcessPeb(Process);
	}
	else
	{
		
		ExReleaseFastMutex(&DbgkFastMutex);
		return STATUS_PORT_NOT_SET;
	}

	InitializeListHead(&TempList);

	
	ExAcquireFastMutex(&DebugObject->Mutex);

	NextEntry = DebugObject->EventList.Flink;
	while (NextEntry != &DebugObject->EventList)
	{
	
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);
		NextEntry = NextEntry->Flink;

		
		if (DebugEvent->Process == Process)
		{
			
			RemoveEntryList(&DebugEvent->EventList);
			InsertTailList(&TempList, &DebugEvent->EventList);
		}
	}

	
	ExReleaseFastMutex(&DebugObject->Mutex);

	
	ObDereferenceObject(DebugObject);

	while (!IsListEmpty(&TempList))
	{
		
		NextEntry = RemoveHeadList(&TempList);
		DebugEvent = CONTAINING_RECORD(NextEntry, DEBUG_EVENT, EventList);

		
		DebugEvent->Status = STATUS_DEBUGGER_INACTIVE;
		DbgkpWakeTarget(DebugEvent);
	}

	
	return STATUS_SUCCESS;
}


NTSTATUS
__fastcall
proxyDbgkOpenProcessDebugPort(IN PEPROCESS_S Process,
IN KPROCESSOR_MODE PreviousMode,
OUT HANDLE *DebugHandle)
{
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	PAGED_CODE();


	if (!Process->Pcb.newdbgport) return STATUS_PORT_NOT_SET;

	
	ExAcquireFastMutex(&DbgkFastMutex);

	
	DebugObject = Process->Pcb.newdbgport;
	if (DebugObject) ObReferenceObject(DebugObject);

	
	ExReleaseFastMutex(&DbgkFastMutex);

	
	if (!DebugObject) return STATUS_PORT_NOT_SET;

	
	Status = ObOpenObjectByPointer(DebugObject,
		0,
		NULL,
		MAXIMUM_ALLOWED,
		NewDbgObject,
		PreviousMode,
		DebugHandle);
	if (!NT_SUCCESS(Status)) ObDereferenceObject(DebugObject);

	
	return Status;
}

/ **
NTSTATUS
NTAPI
NtCreateDebugObject(OUT PHANDLE DebugHandle,
IN ACCESS_MASK DesiredAccess,
IN POBJECT_ATTRIBUTES ObjectAttributes,
IN ULONG Flags)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PDEBUG_OBJECT DebugObject;
	HANDLE hDebug;
	NTSTATUS Status;
	PAGED_CODE();

	
	if (PreviousMode != KernelMode)
	{
		
		try
		{
			
			ProbeForWriteHandle(DebugHandle);
		}
			except(EXCEPTION_EXECUTE_HANDLER)
		{
			
				return GetExceptionCode();
		} 
	}

	
	if (Flags & ~DBGK_ALL_FLAGS) return STATUS_INVALID_PARAMETER;

	
	Status = ObCreateObject(PreviousMode,
		DbgkDebugObjectType,
		ObjectAttributes,
		PreviousMode,
		NULL,
		sizeof(DEBUG_OBJECT),
		0,
		0,
		(PVOID*)&DebugObject);
	if (NT_SUCCESS(Status))
	{
		
		ExInitializeFastMutex(&DebugObject->Mutex);

	
		InitializeListHead(&DebugObject->EventList);

		
		KeInitializeEvent(&DebugObject->EventsPresent,
			NotificationEvent,
			FALSE);

		
		DebugObject->Flags = 0;
		if (Flags & DBGK_KILL_PROCESS_ON_EXIT)
		{
			DebugObject->KillProcessOnExit = TRUE;
		}

	
		Status = ObInsertObject((PVOID)DebugObject,
			NULL,
			DesiredAccess,
			0,
			NULL,
			&hDebug);
		if (NT_SUCCESS(Status))
		{
			
			try
			{
				
				*DebugHandle = hDebug;
			}
				except(ExSystemExceptionFilter())
			{
			
				Status = GetExceptionCode();
			} ;
		}
	}

	
	return Status;
}

* /

NTSTATUS
NTAPI
proxyNtDebugContinue(IN HANDLE DebugHandle,
IN PCLIENT_ID AppClientId,
IN NTSTATUS ContinueStatus)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PDEBUG_OBJECT DebugObject;
	NTSTATUS Status;
	PDEBUG_EVENT DebugEvent = NULL, DebugEventToWake = NULL;
	PLIST_ENTRY ListHead, NextEntry;
	BOOLEAN NeedsWake = FALSE;
	CLIENT_ID ClientId;
	PAGED_CODE();
	

	
	if (PreviousMode != KernelMode)
	{
	
		try
		{
			
			ProbeForRead(AppClientId, sizeof(CLIENT_ID), sizeof(ULONG));
			ClientId = *AppClientId;
			AppClientId = &ClientId;
		}
			except(EXCEPTION_EXECUTE_HANDLER)
		{
			
				return GetExceptionCode();
		}
	}

	
	if ((ContinueStatus != DBG_CONTINUE) &&
		(ContinueStatus != DBG_EXCEPTION_HANDLED) &&
		(ContinueStatus != DBG_EXCEPTION_NOT_HANDLED) &&
		(ContinueStatus != DBG_TERMINATE_THREAD) &&
		(ContinueStatus != DBG_TERMINATE_PROCESS))
	{
		
		Status = STATUS_INVALID_PARAMETER;
	}
	else
	{
		
		Status = ObReferenceObjectByHandle(DebugHandle,
			DEBUG_OBJECT_WAIT_STATE_CHANGE,
			NewDbgObject,
			PreviousMode,
			(PVOID*)&DebugObject,
			NULL);
		/ *	Status = ObReferenceObjectByHandle(DebugHandle,
			DEBUG_OBJECT_WAIT_STATE_CHANGE,
			*(ULONG64*)DbgkDebugObjectType,
			PreviousMode,
			(PVOID*)&DebugObject,
			NULL);* /
		if (NT_SUCCESS(Status))
		{
			
			ExAcquireFastMutex(&DebugObject->Mutex);

			ListHead = &DebugObject->EventList;
			NextEntry = ListHead->Flink;
			while (ListHead != NextEntry)
			{
				
				DebugEvent = CONTAINING_RECORD(NextEntry,
					DEBUG_EVENT,
					EventList);

				
				if (DebugEvent->ClientId.UniqueProcess ==
					AppClientId->UniqueProcess)
				{
					
					if (NeedsWake)
					{
						
						DebugEvent->Flags &= ~DEBUG_EVENT_INACTIVE;
						KeSetEvent(&DebugObject->EventsPresent,
							IO_NO_INCREMENT,
							FALSE);
						break;
					}

					
					if ((DebugEvent->ClientId.UniqueThread ==
						AppClientId->UniqueThread) && (DebugEvent->Flags & DEBUG_EVENT_READ))
					{
						
						RemoveEntryList(NextEntry);

						
						NeedsWake = TRUE;
						DebugEventToWake = DebugEvent;
					}
				}

				
				NextEntry = NextEntry->Flink;
			}

			
			ExReleaseFastMutex(&DebugObject->Mutex);

			
			ObDereferenceObject(DebugObject);

			
			if (NeedsWake)
			{
				
				DebugEventToWake->ApiMsg.ReturnedStatus = ContinueStatus;
				DebugEventToWake->Status = STATUS_SUCCESS;

				
				DbgkpWakeTarget(DebugEventToWake);
			}
			else
			{
				
				Status = STATUS_INVALID_PARAMETER;
			}
		}
	}

	
	return Status;
}


/ **
NTSTATUS
NTAPI
NtDebugActiveProcess(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle)
{
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PETHREAD LastThread;
	NTSTATUS Status;
	PAGED_CODE();
	

	
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	
	if ((Process == PsGetCurrentProcess()) ||
		(Process == PsInitialSystemProcess))
	{
	
		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	
	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	if (!NT_SUCCESS(Status))
	{

		ObDereferenceObject(Process);
		return Status;
	}


	if (!ExAcquireRundownProtection(&Process->RundownProtect))
	{
	
		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);
		return STATUS_PROCESS_IS_TERMINATING;
	}

	
	Status = DbgkpPostFakeProcessCreateMessages(Process,
		DebugObject,
		&LastThread);
	Status = DbgkpSetProcessDebugObject(Process,
		DebugObject,
		Status,
		LastThread);


	ExReleaseRundownProtection(&Process->RundownProtect);


	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}
* /
/ *
* @implemented
* /

NTSTATUS
NTAPI
NtRemoveProcessDebug(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle)
{
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	NTSTATUS Status;
	PAGED_CODE();


	
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	

	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	/ *Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		*(ULONG64*)DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);* /
	if (!NT_SUCCESS(Status))
	{
		
		ObDereferenceObject(Process);
		return Status;
	}

	
	Status = DbgkClearProcessDebugObject(Process, DebugObject);

	
	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}

/ **
NTSTATUS
NTAPI
NtSetInformationDebugObject(IN HANDLE DebugHandle,
IN DEBUGOBJECTINFOCLASS DebugObjectInformationClass,
IN PVOID DebugInformation,
IN ULONG DebugInformationLength,
OUT PULONG ReturnLength OPTIONAL)
{
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	NTSTATUS Status;
	PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION DebugInfo = DebugInformation;
	PAGED_CODE();

	
	Status = DefaultSetInfoBufferCheck(DebugObjectInformationClass,
		DbgkpDebugObjectInfoClass,
		sizeof(DbgkpDebugObjectInfoClass) /
		sizeof(DbgkpDebugObjectInfoClass[0]),
		DebugInformation,
		DebugInformationLength,
		PreviousMode);
	if (!NT_SUCCESS(Status)) return Status;


	if (ReturnLength)
	{
		
		try
		{
			
			ProbeForWriteUlong(ReturnLength);
			*ReturnLength = sizeof(*DebugInfo);
		}
			except(ExSystemExceptionFilter())
		{
			
				return GetExceptionCode();
		}
	
	}

	
	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_WAIT_STATE_CHANGE,
		DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	if (NT_SUCCESS(Status))
	{
	
		ExAcquireFastMutex(&DebugObject->Mutex);

		
		if (DebugInfo->KillProcessOnExit)
		{
			
			DebugObject->KillProcessOnExit = TRUE;
		}
		else
		{
			
			DebugObject->KillProcessOnExit = FALSE;
		}

	
		ExReleaseFastMutex(&DebugObject->Mutex);

		
		ObDereferenceObject(DebugObject);
	}

	
	return Status;
}
* /

NTSTATUS
__fastcall
proxyNtWaitForDebugEvent(IN HANDLE DebugHandle,
IN BOOLEAN Alertable,
IN PLARGE_INTEGER Timeout OPTIONAL,
OUT PDBGUI_WAIT_STATE_CHANGE StateChange)
{
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	LARGE_INTEGER LocalTimeOut;
	PEPROCESS Process;
	LARGE_INTEGER StartTime;
	PETHREAD Thread;
	BOOLEAN GotEvent;
	LARGE_INTEGER NewTime;
	PDEBUG_OBJECT DebugObject;
	DBGUI_WAIT_STATE_CHANGE WaitStateChange;
	NTSTATUS Status;
	PDEBUG_EVENT DebugEvent = NULL, DebugEvent2;
	PLIST_ENTRY ListHead, NextEntry, NextEntry2;
	PAGED_CODE();

	
	RtlZeroMemory(&WaitStateChange, sizeof(WaitStateChange));
	LocalTimeOut.QuadPart = 0;


	if (PreviousMode != KernelMode)
	{
		
		try
		{
			
			if (Timeout)
			{
			
				//ProbeForReadLargeInteger(Timeout);

			
				LocalTimeOut = *Timeout;
				Timeout = &LocalTimeOut;
			}

		
			ProbeForWrite(StateChange, sizeof(*StateChange), sizeof(ULONG));
		}
			except(EXCEPTION_EXECUTE_HANDLER)
		{
		
				return GetExceptionCode();
		}
		
	}
	else
	{
	
		if (Timeout) LocalTimeOut = *Timeout;
	}


	if (Timeout) KeQuerySystemTime(&StartTime);

	
	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_WAIT_STATE_CHANGE,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
/ *
	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_WAIT_STATE_CHANGE,
		*(ULONG64*)DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);* /
	if (!NT_SUCCESS(Status)) return Status;

	
	Process = NULL;
	Thread = NULL;

	
	while (TRUE)
	{
		Status = KeWaitForSingleObject(&DebugObject->EventsPresent,
			Executive,
			PreviousMode,
			Alertable,
			Timeout);
		if (!NT_SUCCESS(Status) ||
			(Status == STATUS_TIMEOUT) ||
			(Status == STATUS_ALERTED) ||
			(Status == STATUS_USER_APC))
		{
		
			break;
		}

	
		GotEvent = FALSE;
		ExAcquireFastMutex(&DebugObject->Mutex);

	
		if (DebugObject->DebuggerInactive)
		{
			
			Status = STATUS_DEBUGGER_INACTIVE;
		}
		else
		{
		
			ListHead = &DebugObject->EventList;
			NextEntry = ListHead->Flink;
			while (ListHead != NextEntry)
			{
			
				DebugEvent = CONTAINING_RECORD(NextEntry,
					DEBUG_EVENT,
					EventList);
			

			
				if (!(DebugEvent->Flags & (DEBUG_EVENT_INACTIVE | DEBUG_EVENT_READ)))
				{
				
					GotEvent = TRUE;

				
					NextEntry2 = DebugObject->EventList.Flink;
					while (NextEntry2 != NextEntry)
					{
						
						DebugEvent2 = CONTAINING_RECORD(NextEntry2,
							DEBUG_EVENT,
							EventList);

						if (DebugEvent2->ClientId.UniqueProcess ==
							DebugEvent->ClientId.UniqueProcess)
						{
							
							DebugEvent->Flags |= DEBUG_EVENT_INACTIVE;
							DebugEvent->BackoutThread = NULL;
							GotEvent = FALSE;
							break;
						}

					
						NextEntry2 = NextEntry2->Flink;
					}

				
					if (GotEvent) break;
				}

			
				NextEntry = NextEntry->Flink;
			}

		
			if (GotEvent)
			{
				
				Process = DebugEvent->Process;
				Thread = DebugEvent->Thread;
				ObReferenceObject(Process);
				ObReferenceObject(Thread);

				
				DbgkpConvertKernelToUserStateChange(&WaitStateChange,
					DebugEvent);

		
				DebugEvent->Flags |= DEBUG_EVENT_READ;
			}
			else
			{
				
				KeClearEvent(&DebugObject->EventsPresent);
			}

		
			Status = STATUS_SUCCESS;
		}

	
		ExReleaseFastMutex(&DebugObject->Mutex);
		if (!NT_SUCCESS(Status)) break;

	
		if (!GotEvent)
		{
			
			if (LocalTimeOut.QuadPart < 0)
			{
			
				KeQuerySystemTime(&NewTime);

				
				LocalTimeOut.QuadPart += (NewTime.QuadPart - StartTime.QuadPart);
				StartTime = NewTime;

				
				if (LocalTimeOut.QuadPart >= 0)
				{
					
					Status = STATUS_TIMEOUT;
					break;
				}
			}
		}
		else
		{
			
			DbgkpOpenHandles(&WaitStateChange, Process, Thread);
			ObDereferenceObject(Process);
			ObDereferenceObject(Thread);
			break;
		}
	}

	
	ObDereferenceObject(DebugObject);

	
	try
	{
	
		*StateChange = WaitStateChange;
	}
		except(ExSystemExceptionFilter())
	{
		
		Status = GetExceptionCode();
	}
	

	return Status;
}


NTSTATUS
__fastcall
proxyNtDebugActiveProcess(IN HANDLE ProcessHandle,
IN HANDLE DebugHandle)
{
	PEPROCESS_S Process;
	PDEBUG_OBJECT DebugObject;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();
	PETHREAD LastThread;
	NTSTATUS Status;
	PAGED_CODE();
	
	
	Status = ObReferenceObjectByHandle(ProcessHandle,
		PROCESS_SUSPEND_RESUME,
		*PsProcessType,
		PreviousMode,
		(PVOID*)&Process,
		NULL);
	if (!NT_SUCCESS(Status)) return Status;

	if ((Process == PsGetCurrentProcess()) ||
		(Process == PsInitialSystemProcess))
	{
		
		ObDereferenceObject(Process);
		return STATUS_ACCESS_DENIED;
	}

	

	Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		NewDbgObject,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);
	/ *Status = ObReferenceObjectByHandle(DebugHandle,
		DEBUG_OBJECT_ADD_REMOVE_PROCESS,
		*(ULONG64*)DbgkDebugObjectType,
		PreviousMode,
		(PVOID*)&DebugObject,
		NULL);* /
	if (!NT_SUCCESS(Status))
	{
		
		ObDereferenceObject(Process);
		return Status;
	}

	
	if (!ExAcquireRundownProtection(&Process->RundownProtect))
	{
	
		ObDereferenceObject(Process);
		ObDereferenceObject(DebugObject);
		return STATUS_PROCESS_IS_TERMINATING;
	}

	
	Status = DbgkpPostFakeProcessCreateMessages(Process,
		DebugObject,
		&LastThread);
	Status = DbgkpSetProcessDebugObject(Process,
		DebugObject,
		Status,
		LastThread);

	
	ExReleaseRundownProtection(&Process->RundownProtect);

	ObDereferenceObject(Process);
	ObDereferenceObject(DebugObject);
	return Status;
}


NTSTATUS NTAPI initDbgk(){

	ExSystemExceptionFilter = fc_DbgkGetAdrress(L"ExSystemExceptionFilter");
	ObInsertObject = fc_DbgkGetAdrress(L"ObInsertObject");
	ObCreateObject = fc_DbgkGetAdrress(L"ObCreateObject");
	ObOpenObjectByPointer = fc_DbgkGetAdrress(L"ObOpenObjectByPointer");
	KiCheckForKernelApcDelivery12 = fc_DbgkGetAdrress(L"KiCheckForKernelApcDelivery");
	ExInitializeFastMutex(&DbgkFastMutex);
	//DbgkFastMutex = (PFAST_MUTEX)DbgkpProcessDebugPortMutex;

	
/ *
	NewDbgObject = 
		*(ULONG64*)DbgkDebugObjectType;* /
	NewDbgObject =CreateNewObjectType(DbgkDebugObjectType);

	if (NewDbgObject==NULL){
	
		DbgPrint("NewDbgObject is NULL");
	}
	

}*/