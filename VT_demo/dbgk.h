/*
#include "ntddk.h"

typedef enum _DBGKM_APINUMBER
{
	DbgKmExceptionApi = 0,
	DbgKmCreateThreadApi = 1,
	DbgKmCreateProcessApi = 2,
	DbgKmExitThreadApi = 3,
	DbgKmExitProcessApi = 4,
	DbgKmLoadDllApi = 5,
	DbgKmUnloadDllApi = 6,
	DbgKmErrorReportApi = 7,
	DbgKmMaxApiNumber = 8,
} DBGKM_APINUMBER;

typedef struct _DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION
{
	ULONG KillProcessOnExit;
} DEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION, *PDEBUG_OBJECT_KILL_PROCESS_ON_EXIT_INFORMATION;

typedef struct _DEBUG_OBJECT
{
	KEVENT EventsPresent;
	FAST_MUTEX Mutex;
	LIST_ENTRY EventList;
	union
	{
		ULONG Flags;
		struct
		{
			UCHAR DebuggerInactive : 1;
			UCHAR KillProcessOnExit : 1;
		};
	};
} DEBUG_OBJECT, *PDEBUG_OBJECT;
typedef enum _DBG_STATE
{
	DbgIdle,
	DbgReplyPending,
	DbgCreateThreadStateChange,
	DbgCreateProcessStateChange,
	DbgExitThreadStateChange,
	DbgExitProcessStateChange,
	DbgExceptionStateChange,
	DbgBreakpointStateChange,
	DbgSingleStepStateChange,
	DbgLoadDllStateChange,
	DbgUnloadDllStateChange
} DBG_STATE, *PDBG_STATE;
typedef struct _DBGKM_EXCEPTION
{
	EXCEPTION_RECORD ExceptionRecord;
	ULONG FirstChance;
} DBGKM_EXCEPTION, *PDBGKM_EXCEPTION;

typedef struct _DBGKM_CREATE_THREAD
{
	ULONG SubSystemKey;
	PVOID StartAddress;
} DBGKM_CREATE_THREAD, *PDBGKM_CREATE_THREAD;

typedef struct _DBGKM_CREATE_PROCESS
{
	ULONG SubSystemKey;
	HANDLE FileHandle;
	PVOID BaseOfImage;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	DBGKM_CREATE_THREAD InitialThread;
} DBGKM_CREATE_PROCESS, *PDBGKM_CREATE_PROCESS;

typedef struct _DBGKM_EXIT_THREAD
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_THREAD, *PDBGKM_EXIT_THREAD;

typedef struct _DBGKM_EXIT_PROCESS
{
	NTSTATUS ExitStatus;
} DBGKM_EXIT_PROCESS, *PDBGKM_EXIT_PROCESS;

typedef struct _DBGKM_LOAD_DLL
{
	HANDLE FileHandle;
	PVOID BaseOfDll;
	ULONG DebugInfoFileOffset;
	ULONG DebugInfoSize;
	PVOID NamePointer;
} DBGKM_LOAD_DLL, *PDBGKM_LOAD_DLL;

typedef struct _DBGKM_UNLOAD_DLL
{
	PVOID BaseAddress;
} DBGKM_UNLOAD_DLL, *PDBGKM_UNLOAD_DLL;

//
// User-Mode Debug State Change Structure
//
typedef struct _DBGUI_WAIT_STATE_CHANGE
{
	DBG_STATE NewState;
	CLIENT_ID AppClientId;
	union
	{
		struct
		{
			HANDLE HandleToThread;
			DBGKM_CREATE_THREAD NewThread;
		} CreateThread;
		struct
		{
			HANDLE HandleToProcess;
			HANDLE HandleToThread;
			DBGKM_CREATE_PROCESS NewProcess;
		} CreateProcessInfo;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_EXCEPTION Exception;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	} StateInfo;
} DBGUI_WAIT_STATE_CHANGE, *PDBGUI_WAIT_STATE_CHANGE;

//
// LPC Debug Message
//



//
// Kernel Exported Object Types
//
extern POBJECT_TYPE NTSYSAPI LpcPortObjectType;



//
// Internal helper macro
//
#define N_ROUND_UP(x,s) \
    (((ULONG)(x)+(s)-1) & ~((ULONG)(s)-1))

//
// Port Object Access Masks
//
#define PORT_CONNECT                    0x1
#define PORT_ALL_ACCESS                 (STANDARD_RIGHTS_REQUIRED | \
                                         SYNCHRONIZE | \
                                         PORT_CONNECT)

typedef enum _LPC_TYPE
{
	LPC_NEW_MESSAGE,
	LPC_REQUEST,
	LPC_REPLY,
	LPC_DATAGRAM,
	LPC_LOST_REPLY,
	LPC_PORT_CLOSED,
	LPC_CLIENT_DIED,
	LPC_EXCEPTION,
	LPC_DEBUG_EVENT,
	LPC_ERROR_EVENT,
	LPC_CONNECTION_REQUEST,
	LPC_CONNECTION_REFUSED,
	LPC_MAXIMUM
} LPC_TYPE;
#define DEBUG_OBJECT_WAIT_STATE_CHANGE      0x0001
#define DEBUG_OBJECT_ADD_REMOVE_PROCESS     0x0002
#define DEBUG_OBJECT_SET_INFORMATION        0x0004
#define DEBUG_OBJECT_ALL_ACCESS             (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x0F)
GENERIC_MAPPING DbgkDebugObjectMapping =
{
	STANDARD_RIGHTS_READ | DEBUG_OBJECT_WAIT_STATE_CHANGE,
	STANDARD_RIGHTS_WRITE | DEBUG_OBJECT_ADD_REMOVE_PROCESS,
	STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE,
	DEBUG_OBJECT_ALL_ACCESS
};


//
// Port Object Flags
//
#define LPCP_CONNECTION_PORT            0x00000001
#define LPCP_UNCONNECTED_PORT           0x00000002
#define LPCP_COMMUNICATION_PORT         0x00000003
#define LPCP_CLIENT_PORT                0x00000004
#define LPCP_PORT_TYPE_MASK             0x0000000F
#define LPCP_PORT_DELETED               0x10000000
#define LPCP_WAITABLE_PORT              0x20000000
#define LPCP_NAME_DELETED               0x40000000
#define LPCP_SECURITY_DYNAMIC           0x80000000

//
// LPC Message Types
//


//
// Information Classes for NtQueryInformationPort
//
typedef enum _PORT_INFORMATION_CLASS
{
	PortNoInformation
} PORT_INFORMATION_CLASS;



//
// Maximum message size that can be sent through an LPC Port without a section
//
#ifdef _WIN64
#define PORT_MAXIMUM_MESSAGE_LENGTH 512
#else
#define PORT_MAXIMUM_MESSAGE_LENGTH 256
#endif

//
// Portable LPC Types for 32/64-bit compatibility
//
#ifdef USE_LPC6432
#define LPC_CLIENT_ID CLIENT_ID64
#define LPC_SIZE_T ULONGLONG
#define LPC_PVOID ULONGLONG
#define LPC_HANDLE ULONGLONG
#else
#define LPC_CLIENT_ID CLIENT_ID
#define LPC_SIZE_T SIZE_T
#define LPC_PVOID PVOID
#define LPC_HANDLE HANDLE
#endif
#define DEBUG_OBJECT_DELETE_PENDING			(0x1) // Debug object is delete pending.
#define DEBUG_OBJECT_KILL_ON_CLOSE			(0x2) // Kill all debugged processes on close

#define DEBUG_KILL_ON_CLOSE					(0x01)

#define DEBUG_EVENT_READ					(0x01)  // Event had been seen by win32 app
#define DEBUG_EVENT_NOWAIT					(0x02)  // No waiter one this. Just free the pool
#define DEBUG_EVENT_INACTIVE				(0x04)  // The message is in inactive. It may be activated or deleted later
#define DEBUG_EVENT_RELEASE					(0x08)  // Release rundown protection on this thread
#define DEBUG_EVENT_PROTECT_FAILED			(0x10)  // Rundown protection failed to be acquired on this thread
#define DEBUG_EVENT_SUSPEND					(0x20)  // Resume thread on continue

//
// Define debug object access types. No security is present on this object.
//
#define DEBUG_READ_EVENT        (0x0001)
#define DEBUG_PROCESS_ASSIGN    (0x0002)
#define DEBUG_SET_INFORMATION   (0x0004)
#define DEBUG_QUERY_INFORMATION (0x0008)
#define DEBUG_ALL_ACCESS     (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|DEBUG_READ_EVENT|DEBUG_PROCESS_ASSIGN|\
	DEBUG_SET_INFORMATION|DEBUG_QUERY_INFORMATION)

//一些内核其他定义声明

//
// Used to signify that the delete APC has been queued or the
// thread has called PspExitThread itself.
//
#define PS_CROSS_THREAD_FLAGS_TERMINATED           0x00000001UL
//
// Thread create failed
//
#define PS_CROSS_THREAD_FLAGS_DEADTHREAD           0x00000002UL
//
// Debugger isn't shown this thread
//
#define PS_CROSS_THREAD_FLAGS_HIDEFROMDBG          0x00000004UL
//
// Thread is impersonating
//
#define PS_CROSS_THREAD_FLAGS_IMPERSONATING        0x00000008UL
//
// This is a system thread
//
#define PS_CROSS_THREAD_FLAGS_SYSTEM               0x00000010UL
//
// Hard errors are disabled for this thread
//
#define PS_CROSS_THREAD_FLAGS_HARD_ERRORS_DISABLED 0x00000020UL
//
// We should break in when this thread is terminated
//
#define PS_CROSS_THREAD_FLAGS_BREAK_ON_TERMINATION 0x00000040UL
//
// This thread should skip sending its create thread message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_CREATION_MSG    0x00000080UL
//
// This thread should skip sending its final thread termination message
//
#define PS_CROSS_THREAD_FLAGS_SKIP_TERMINATION_MSG 0x00000100UL

#define IS_SYSTEM_THREAD(Thread)  (((Thread)->CrossThreadFlags&PS_CROSS_THREAD_FLAGS_SYSTEM) != 0)


#define PS_PROCESS_FLAGS_CREATE_REPORTED        0x00000001UL // Create process debug call has occurred
#define PS_PROCESS_FLAGS_NO_DEBUG_INHERIT       0x00000002UL // Don't inherit debug port
#define PS_PROCESS_FLAGS_PROCESS_EXITING        0x00000004UL // PspExitProcess entered
#define PS_PROCESS_FLAGS_PROCESS_DELETE         0x00000008UL // Delete process has been issued
#define PS_PROCESS_FLAGS_WOW64_SPLIT_PAGES      0x00000010UL // Wow64 split pages
#define PS_PROCESS_FLAGS_VM_DELETED             0x00000020UL // VM is deleted
#define PS_PROCESS_FLAGS_OUTSWAP_ENABLED        0x00000040UL // Outswap enabled
#define PS_PROCESS_FLAGS_OUTSWAPPED             0x00000080UL // Outswapped
#define PS_PROCESS_FLAGS_FORK_FAILED            0x00000100UL // Fork status
#define PS_PROCESS_FLAGS_WOW64_4GB_VA_SPACE     0x00000200UL // Wow64 process with 4gb virtual address space
#define PS_PROCESS_FLAGS_ADDRESS_SPACE1         0x00000400UL // Addr space state1
#define PS_PROCESS_FLAGS_ADDRESS_SPACE2         0x00000800UL // Addr space state2
#define PS_PROCESS_FLAGS_SET_TIMER_RESOLUTION   0x00001000UL // SetTimerResolution has been called
#define PS_PROCESS_FLAGS_BREAK_ON_TERMINATION   0x00002000UL // Break on process termination
#define PS_PROCESS_FLAGS_CREATING_SESSION       0x00004000UL // Process is creating a session
#define PS_PROCESS_FLAGS_USING_WRITE_WATCH      0x00008000UL // Process is using the write watch APIs
#define PS_PROCESS_FLAGS_IN_SESSION             0x00010000UL // Process is in a session
#define PS_PROCESS_FLAGS_OVERRIDE_ADDRESS_SPACE 0x00020000UL // Process must use native address space (Win64 only)
#define PS_PROCESS_FLAGS_HAS_ADDRESS_SPACE      0x00040000UL // This process has an address space
#define PS_PROCESS_FLAGS_LAUNCH_PREFETCHED      0x00080000UL // Process launch was prefetched
#define PS_PROCESS_INJECT_INPAGE_ERRORS         0x00100000UL // Process should be given inpage errors - hardcoded in trap.asm too
#define PS_PROCESS_FLAGS_VM_TOP_DOWN            0x00200000UL // Process memory allocations default to top-down
#define PS_PROCESS_FLAGS_IMAGE_NOTIFY_DONE      0x00400000UL // We have sent a message for this image
#define PS_PROCESS_FLAGS_PDE_UPDATE_NEEDED      0x00800000UL // The system PDEs need updating for this process (NT32 only)
#define PS_PROCESS_FLAGS_VDM_ALLOWED            0x01000000UL // Process allowed to invoke NTVDM support
#define PS_PROCESS_FLAGS_SMAP_ALLOWED           0x02000000UL // Process allowed to invoke SMAP support
#define PS_PROCESS_FLAGS_CREATE_FAILED          0x04000000UL // Process create failed

#define PS_PROCESS_FLAGS_DEFAULT_IO_PRIORITY    0x38000000UL // The default I/O priority for created threads. (3 bits)

#define PS_PROCESS_FLAGS_PRIORITY_SHIFT         27

#define PS_PROCESS_FLAGS_EXECUTE_SPARE1         0x40000000UL //
#define PS_PROCESS_FLAGS_EXECUTE_SPARE2         0x80000000UL //


#define THREAD_TERMINATE						(0x0001)  
#define THREAD_SUSPEND_RESUME					(0x0002)  
#define THREAD_GET_CONTEXT						(0x0008)  
#define THREAD_SET_CONTEXT						(0x0010)  
#define THREAD_QUERY_INFORMATION				(0x0040)  
#define THREAD_SET_INFORMATION					(0x0020)  
#define THREAD_SET_THREAD_TOKEN					(0x0080)
#define THREAD_IMPERSONATE						(0x0100)
#define THREAD_DIRECT_IMPERSONATION				(0x0200)

#define PROCESS_TERMINATE						(0x0001)  
#define PROCESS_CREATE_THREAD					(0x0002)  
#define PROCESS_SET_SESSIONID					(0x0004)  
#define PROCESS_VM_OPERATION					(0x0008)  
#define PROCESS_VM_READ							(0x0010)  
#define PROCESS_VM_WRITE						(0x0020)  
#define PROCESS_DUP_HANDLE						(0x0040)  
#define PROCESS_CREATE_PROCESS					(0x0080)  
#define PROCESS_SET_QUOTA						(0x0100)  
#define PROCESS_SET_INFORMATION					(0x0200)  
#define PROCESS_QUERY_INFORMATION				(0x0400)  
#define PROCESS_SUSPEND_RESUME					(0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION		(0x1000)  


#define LPC_REQUEST								1
#define LPC_REPLY								2
#define LPC_DATAGRAM							3
#define LPC_LOST_REPLY							4
#define LPC_PORT_CLOSED							5
#define LPC_CLIENT_DIED							6
#define LPC_EXCEPTION							7
#define LPC_DEBUG_EVENT							8
#define LPC_ERROR_EVENT							9
#define LPC_CONNECTION_REQUEST					10
#define DBGK_KILL_PROCESS_ON_EXIT         (0x1)
#define DBGK_ALL_FLAGS                    (DBGK_KILL_PROCESS_ON_EXIT)
typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectUnusedInformation,
	DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;
//
// LPC Port Message
//
typedef struct _PORT_MESSAGE
{
	union
	{
		struct
		{
			CSHORT DataLength;
			CSHORT TotalLength;
		} s1;
		ULONG Length;
	} u1;
	union
	{
		struct
		{
			CSHORT Type;
			CSHORT DataInfoOffset;
		} s2;
		ULONG ZeroInit;
	} u2;
	union
	{
		LPC_CLIENT_ID ClientId;
		double DoNotUseThisField;
	};
	ULONG MessageId;
	union
	{
		LPC_SIZE_T ClientViewSize;
		ULONG CallbackId;
	};
} PORT_MESSAGE, *PPORT_MESSAGE;


typedef struct _DBGKM_MSG
{
	PORT_MESSAGE h;
	DBGKM_APINUMBER ApiNumber;
	NTSTATUS ReturnedStatus;
	union
	{
		DBGKM_EXCEPTION Exception;
		DBGKM_CREATE_THREAD CreateThread;
		DBGKM_CREATE_PROCESS CreateProcess;
		DBGKM_EXIT_THREAD ExitThread;
		DBGKM_EXIT_PROCESS ExitProcess;
		DBGKM_LOAD_DLL LoadDll;
		DBGKM_UNLOAD_DLL UnloadDll;
	};
} DBGKM_MSG, *PDBGKM_MSG;



//
// Debug Event
//
typedef struct _DEBUG_EVENT
{
	LIST_ENTRY EventList;
	KEVENT ContinueEvent;
	CLIENT_ID ClientId;
	PEPROCESS Process;
	PETHREAD Thread;
	NTSTATUS Status;
	ULONG Flags;
	PETHREAD BackoutThread;
	DBGKM_MSG ApiMsg;
} DEBUG_EVENT, *PDEBUG_EVENT;


typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                      // 25 elements, 0x70 bytes (sizeof)
{
	/ *0x000* /     UINT16       Length;
	union                                                                                                                                                                       // 2 elements, 0x1 bytes (sizeof)
	{
		/ *0x002* /         UINT8        ObjectTypeFlags;
		struct                                                                                                                                                                  // 7 elements, 0x1 bytes (sizeof)
		{
			/ *0x002* /             UINT8        CaseInsensitive : 1;                                                                                                                                   // 0 BitPosition
			/ *0x002* /             UINT8        UnnamedObjectsOnly : 1;                                                                                                                                // 1 BitPosition
			/ *0x002* /             UINT8        UseDefaultObject : 1;                                                                                                                                  // 2 BitPosition
			/ *0x002* /             UINT8        SecurityRequired : 1;                                                                                                                                  // 3 BitPosition
			/ *0x002* /             UINT8        MaintainHandleCount : 1;                                                                                                                               // 4 BitPosition
			/ *0x002* /             UINT8        MaintainTypeList : 1;                                                                                                                                  // 5 BitPosition
			/ *0x002* /             UINT8        SupportsObjectCallbacks : 1;                                                                                                                           // 6 BitPosition
		};
	};
	/ *0x004* /     ULONG32      ObjectTypeCode;
	/ *0x008* /     ULONG32      InvalidAttributes;
	/ *0x00C* /     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     // 4 elements, 0x10 bytes (sizeof)
	/ *0x01C* /     ULONG32      ValidAccessMask;
	/ *0x020* /     ULONG32      RetainAccess;
	/ *0x024* /     enum _POOL_TYPE PoolType;
	/ *0x028* /     ULONG32      DefaultPagedPoolCharge;
	/ *0x02C* /     ULONG32      DefaultNonPagedPoolCharge;
	/ *0x030* /     PVOID DumpProcedure;
	/ *0x038* /     PVOID OpenProcedure;
	/ *0x040* /     PVOID CloseProcedure;
	/ *0x048* /     PVOID DeleteProcedure;
	/ *0x050* /     PVOID ParseProcedure;
	/ *0x058* /     PVOID SecurityProcedure;
	/ *0x060* /     PVOID QueryNameProcedure;
	/ *0x068* /     PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER_S, *POBJECT_TYPE_INITIALIZER;
typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)
{
	union                                    // 3 elements, 0x8 bytes (sizeof)
	{
		struct                               // 5 elements, 0x8 bytes (sizeof)
		{
			/ *0x000* /             UINT64       Locked : 1;         // 0 BitPosition
			/ *0x000* /             UINT64       Waiting : 1;        // 1 BitPosition
			/ *0x000* /             UINT64       Waking : 1;         // 2 BitPosition
			/ *0x000* /             UINT64       MultipleShared : 1; // 3 BitPosition
			/ *0x000* /             UINT64       Shared : 60;        // 4 BitPosition
		};
		/ *0x000* /         UINT64       Value;
		/ *0x000* /         VOID*        Ptr;
	};
}EX_PUSH_LOCK, *PEX_PUSH_LOCK;
typedef struct _OBJECT_TYPE_S                   // 12 elements, 0xD0 bytes (sizeof)
{
	/ *0x000* /     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
	/ *0x010* /     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
	/ *0x020* /     VOID*        DefaultObject;
	/ *0x028* /     UINT8        Index;
	/ *0x029* /     UINT8        _PADDING0_[0x3];
	/ *0x02C* /     ULONG32      TotalNumberOfObjects;
	/ *0x030* /     ULONG32      TotalNumberOfHandles;
	/ *0x034* /     ULONG32      HighWaterNumberOfObjects;
	/ *0x038* /     ULONG32      HighWaterNumberOfHandles;
	/ *0x03C* /     UINT8        _PADDING1_[0x4];
	/ *0x040* /     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 25 elements, 0x70 bytes (sizeof)
	/ *0x0B0* /     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)
	/ *0x0B8* /     ULONG32      Key;
	/ *0x0BC* /     UINT8        _PADDING2_[0x4];
	/ *0x0C0* /     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)
}OBJECT_TYPE_S, *POBJECT_TYPE_S;
typedef struct _MODULE_INFO
{
	ULONG64			UnKown1;
	UNICODE_STRING	FileName;		//+0x4
	PVOID			BaseOfDll;		//+0xC
	wchar_t*		Buffer;			//+0x10
	//...
}MODULE_INFO, *PMODULE_INFO;

typedef struct _SYSTEM_DLL
{
	EX_FAST_REF		FastRef;
	EX_PUSH_LOCK	Lock;
	MODULE_INFO		ModuleInfo;
}SYSTEM_DLL, *PSYSTEM_DLL;
typedef NTSTATUS
(*OBCREATEOBJECTTYPE)(
PUNICODE_STRING usTypeName,
POBJECT_TYPE_INITIALIZER ObjectTypeInit,
PVOID	Reserved,
POBJECT_TYPE *ObjectType);
*/
