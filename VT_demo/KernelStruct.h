#include "ntddk.h"
typedef struct _KERNEL_STACK_SEGMENT // 5 elements, 0x28 bytes (sizeof)
{
	/*0x000*/     UINT64       StackBase;
	/*0x008*/     UINT64       StackLimit;
	/*0x010*/     UINT64       KernelStack;
	/*0x018*/     UINT64       InitialStack;
	/*0x020*/     UINT64       ActualLimit;
}KERNEL_STACK_SEGMENT, *PKERNEL_STACK_SEGMENT;
typedef struct _KERNEL_STACK_CONTROL       // 2 elements, 0x50 bytes (sizeof)
{
	/*0x000*/     struct _KERNEL_STACK_SEGMENT Current;  // 5 elements, 0x28 bytes (sizeof)
	/*0x028*/     struct _KERNEL_STACK_SEGMENT Previous; // 5 elements, 0x28 bytes (sizeof)
}KERNEL_STACK_CONTROL, *PKERNEL_STACK_CONTROL;

typedef struct _EX_FAST_REF      // 3 elements, 0x8 bytes (sizeof)
{
	union                        // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         VOID*        Object;
		/*0x000*/         UINT64       RefCnt : 4; // 0 BitPosition
		/*0x000*/         UINT64       Value;
	};
}EX_FAST_REF, *PEX_FAST_REF;
/*

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
#endif*/



/*
typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectUnusedInformation,
	DebugObjectKillProcessOnExitInformation
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;
//
// LPC Port Message
//

typedef struct _PORT_MESSAGE             // 7 elements, 0x28 bytes (sizeof)
{
	union                                // 2 elements, 0x4 bytes (sizeof)
	{
		struct                           // 2 elements, 0x4 bytes (sizeof)
		{
			INT16        DataLength;
			INT16        TotalLength;
		}s1;
		ULONG32      Length;
	}u1;
	union                                // 2 elements, 0x4 bytes (sizeof)
	{
		struct                           // 2 elements, 0x4 bytes (sizeof)
		{
			INT16        Type;
			INT16        DataInfoOffset;
		}s2;
		ULONG32      ZeroInit;
	}u2;
	union                                // 2 elements, 0x10 bytes (sizeof)
	{
		struct _CLIENT_ID ClientId;      // 2 elements, 0x10 bytes (sizeof)
		float      DoNotUseThisField;
	};
	ULONG32      MessageId;
	UINT8        _PADDING0_[0x4];
	union                                // 2 elements, 0x8 bytes (sizeof)
	{
		UINT64       ClientViewSize;
		ULONG32      CallbackId;
	};
}PORT_MESSAGE, *PPORT_MESSAGE;



#pragma pack(push) //保存对齐状态
#pragma pack(1)//设定为4字节对齐
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
	}u;
	UCHAR unknow[0x40];
} DBGKM_MSG, *PDBGKM_MSG;
#pragma pop(pop)//设定为4字节对齐* /


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

#pragma pack(push) //保存对齐状态
#pragma pack(4)//设定为4字节对齐*/


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

typedef struct _OBJECT_TYPE_INITIALIZER                                                                                                                                      // 25 elements, 0x70 bytes (sizeof)
{
	/*0x000*/     UINT16       Length;
	union                                                                                                                                                                       // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x002*/         UINT8        ObjectTypeFlags;
		struct                                                                                                                                                                  // 7 elements, 0x1 bytes (sizeof)
		{
			/*0x002*/             UINT8        CaseInsensitive : 1;                                                                                                                                   // 0 BitPosition
			/*0x002*/             UINT8        UnnamedObjectsOnly : 1;                                                                                                                                // 1 BitPosition
			/*0x002*/             UINT8        UseDefaultObject : 1;                                                                                                                                  // 2 BitPosition
			/*0x002*/             UINT8        SecurityRequired : 1;                                                                                                                                  // 3 BitPosition
			/*0x002*/             UINT8        MaintainHandleCount : 1;                                                                                                                               // 4 BitPosition
			/*0x002*/             UINT8        MaintainTypeList : 1;                                                                                                                                  // 5 BitPosition
			/*0x002*/             UINT8        SupportsObjectCallbacks : 1;                                                                                                                           // 6 BitPosition
		};
	};
	/*0x004*/     ULONG32      ObjectTypeCode;
	/*0x008*/     ULONG32      InvalidAttributes;
	/*0x00C*/     struct _GENERIC_MAPPING GenericMapping;                                                                                                                                     // 4 elements, 0x10 bytes (sizeof)
	/*0x01C*/     ULONG32      ValidAccessMask;
	/*0x020*/     ULONG32      RetainAccess;
	/*0x024*/     enum _POOL_TYPE PoolType;
	/*0x028*/     ULONG32      DefaultPagedPoolCharge;
	/*0x02C*/     ULONG32      DefaultNonPagedPoolCharge;
	/*0x030*/     PVOID DumpProcedure;
	/*0x038*/     PVOID OpenProcedure;
	/*0x040*/     PVOID CloseProcedure;
	/*0x048*/     PVOID DeleteProcedure;
	/*0x050*/     PVOID ParseProcedure;
	/*0x058*/     PVOID SecurityProcedure;
	/*0x060*/     PVOID QueryNameProcedure;
	/*0x068*/     PVOID OkayToCloseProcedure;
}OBJECT_TYPE_INITIALIZER_S, *POBJECT_TYPE_INITIALIZER;

#pragma pop(pop)//设定为4字节对齐

typedef struct _EX_PUSH_LOCK                 // 7 elements, 0x8 bytes (sizeof)
{
	union                                    // 3 elements, 0x8 bytes (sizeof)
	{
		struct                               // 5 elements, 0x8 bytes (sizeof)
		{
			/*0x000*/             UINT64       Locked : 1;         // 0 BitPosition
			/*0x000*/             UINT64       Waiting : 1;        // 1 BitPosition
			/*0x000*/             UINT64       Waking : 1;         // 2 BitPosition
			/*0x000*/             UINT64       MultipleShared : 1; // 3 BitPosition
			/*0x000*/             UINT64       Shared : 60;        // 4 BitPosition
		};
		/*0x000*/         UINT64       Value;
		/*0x000*/         VOID*        Ptr;
	};
}EX_PUSH_LOCK, *PEX_PUSH_LOCK;
typedef struct _OBJECT_TYPE_S                   // 12 elements, 0xD0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY TypeList;              // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _UNICODE_STRING Name;              // 3 elements, 0x10 bytes (sizeof)
	/*0x020*/     VOID*        DefaultObject;
	/*0x028*/     UINT8        Index;
	/*0x029*/     UINT8        _PADDING0_[0x3];
	/*0x02C*/     ULONG32      TotalNumberOfObjects;
	/*0x030*/     ULONG32      TotalNumberOfHandles;
	/*0x034*/     ULONG32      HighWaterNumberOfObjects;
	/*0x038*/     ULONG32      HighWaterNumberOfHandles;
	/*0x03C*/     UINT8        _PADDING1_[0x4];
	/*0x040*/     struct _OBJECT_TYPE_INITIALIZER TypeInfo; // 25 elements, 0x70 bytes (sizeof)
	/*0x0B0*/     struct _EX_PUSH_LOCK TypeLock;            // 7 elements, 0x8 bytes (sizeof)
	/*0x0B8*/     ULONG32      Key;
	/*0x0BC*/     UINT8        _PADDING2_[0x4];
	/*0x0C0*/     struct _LIST_ENTRY CallbackList;          // 2 elements, 0x10 bytes (sizeof)
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


typedef struct _KAFFINITY_EX // 4 elements, 0x28 bytes (sizeof)
{
	/*0x000*/     UINT16       Count;
	/*0x002*/     UINT16       Size;
	/*0x004*/     ULONG32      Reserved;
	/*0x008*/     UINT64       Bitmap[4];
}KAFFINITY_EX, *PKAFFINITY_EX;
typedef struct _KGUARDED_MUTEX64              // 7 elements, 0x38 bytes (sizeof)
{
	/*0x000*/     LONG32       Count;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     ULONG64 Owner;
	/*0x010*/     ULONG32      Contention;
	/*0x014*/     UINT8        _PADDING1_[0x4];
	/*0x018*/     struct _KGATE Gate;                     // 1 elements, 0x18 bytes (sizeof)
	union                                   // 2 elements, 0x8 bytes (sizeof)
	{
		struct                              // 2 elements, 0x8 bytes (sizeof)
		{
			/*0x030*/             INT16        KernelApcDisable;
			/*0x032*/             INT16        SpecialApcDisable;
			/*0x034*/             UINT8        _PADDING2_[0x4];
		};
		/*0x030*/         ULONG32      CombinedApcDisable;
	};
}KGUARDED_MUTEX64, *PKGUARDED_MUTEX64;
typedef union _KGDTENTRY64 {
	struct {
		USHORT  LimitLow;
		USHORT  BaseLow;
		union {
			struct {
				UCHAR   BaseMiddle;
				UCHAR   Flags1;
				UCHAR   Flags2;
				UCHAR   BaseHigh;
			} Bytes;

			struct {
				ULONG   BaseMiddle : 8;
				ULONG   Type : 5;//把S位包含进去了，也就是是否为系统段描述符的位。
				ULONG   Dpl : 2;
				ULONG   Present : 1;
				ULONG   LimitHigh : 4;
				ULONG   System : 1;//即AVL，系统软件自定义的。
				ULONG   LongMode : 1;
				ULONG   DefaultBig : 1;//即INTEL的D/B (default operation size/default stack pointer size and/or upper bound) flag。
				ULONG   Granularity : 1;
				ULONG   BaseHigh : 8;
			} Bits;
		};

		ULONG BaseUpper;
		ULONG MustBeZero;
	};

	ULONG64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;


typedef struct _PS_PER_CPU_QUOTA_CACHE_AWARE // 5 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY SortedListEntry;      // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY IdleOnlyListHead;     // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     UINT64       CycleBaseAllowance;
	/*0x028*/     INT64        CyclesRemaining;
	/*0x030*/     ULONG32      CurrentGeneration;
	/*0x034*/     UINT8        _PADDING0_[0xC];
}PS_PER_CPU_QUOTA_CACHE_AWARE, *PPS_PER_CPU_QUOTA_CACHE_AWARE;

typedef struct _MMADDRESS_NODE          // 5 elements, 0x28 bytes (sizeof)
{
	union                               // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         INT64        Balance : 2;       // 0 BitPosition
		/*0x000*/         struct _MMADDRESS_NODE* Parent;
	}u1;
	/*0x008*/     struct _MMADDRESS_NODE* LeftChild;
	/*0x010*/     struct _MMADDRESS_NODE* RightChild;
	/*0x018*/     UINT64       StartingVpn;
	/*0x020*/     UINT64       EndingVpn;
}MMADDRESS_NODE, *PMMADDRESS_NODE;

typedef struct _MM_AVL_TABLE                          // 6 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _MMADDRESS_NODE BalancedRoot;              // 5 elements, 0x28 bytes (sizeof)
	struct                                            // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x028*/         UINT64       DepthOfTree : 5;                 // 0 BitPosition
		/*0x028*/         UINT64       Unused : 3;                      // 5 BitPosition
		/*0x028*/         UINT64       NumberGenericTableElements : 56; // 8 BitPosition
	};
	/*0x030*/     VOID*        NodeHint;
	/*0x038*/     VOID*        NodeFreeHint;
}MM_AVL_TABLE, *PMM_AVL_TABLE;




typedef struct _PS_CPU_QUOTA_BLOCK                                        // 14 elements, 0x4080 bytes (sizeof)
{
	union                                                                 // 2 elements, 0x40 bytes (sizeof)
	{
		struct                                                            // 5 elements, 0x40 bytes (sizeof)
		{
			/*0x000*/             struct _LIST_ENTRY ListEntry;                                 // 2 elements, 0x10 bytes (sizeof)
			/*0x010*/             ULONG32      SessionId;
			/*0x014*/             ULONG32      CpuShareWeight;
			/*0x018*/             CHAR CapturedWeightData[0x8]; // 3 elements, 0x8 bytes (sizeof)
			union                                                         // 2 elements, 0x4 bytes (sizeof)
			{
				struct                                                    // 2 elements, 0x4 bytes (sizeof)
				{
					/*0x020*/                     ULONG32      DuplicateInputMarker : 1;                // 0 BitPosition
					/*0x020*/                     ULONG32      Reserved : 31;                           // 1 BitPosition
				};
				/*0x020*/                 LONG32       MiscFlags;
			};
		};
		struct                                                            // 2 elements, 0x40 bytes (sizeof)
		{
			/*0x000*/             UINT64       BlockCurrentGenerationLock;
			/*0x008*/             UINT64       CyclesAccumulated;
			/*0x010*/             UINT8        _PADDING0_[0x30];
		};
	};
	/*0x040*/     UINT64       CycleCredit;
	/*0x048*/     ULONG32      BlockCurrentGeneration;
	/*0x04C*/     ULONG32      CpuCyclePercent;
	/*0x050*/     UINT8        CyclesFinishedForCurrentGeneration;
	/*0x051*/     UINT8        _PADDING1_[0x2F];
	/*0x080*/     struct _PS_PER_CPU_QUOTA_CACHE_AWARE Cpu[256];
}PS_CPU_QUOTA_BLOCK, *PPS_CPU_QUOTA_BLOCK;




typedef struct _EJOB                                // 42 elements, 0x1C8 bytes (sizeof)
{
	/*0x000*/     struct _KEVENT Event;                           // 1 elements, 0x18 bytes (sizeof)
	/*0x018*/     struct _LIST_ENTRY JobLinks;                    // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     struct _LIST_ENTRY ProcessListHead;             // 2 elements, 0x10 bytes (sizeof)
	/*0x038*/     struct _ERESOURCE JobLock;                      // 15 elements, 0x68 bytes (sizeof)
	/*0x0A0*/     union _LARGE_INTEGER TotalUserTime;             // 4 elements, 0x8 bytes (sizeof)
	/*0x0A8*/     union _LARGE_INTEGER TotalKernelTime;           // 4 elements, 0x8 bytes (sizeof)
	/*0x0B0*/     union _LARGE_INTEGER ThisPeriodTotalUserTime;   // 4 elements, 0x8 bytes (sizeof)
	/*0x0B8*/     union _LARGE_INTEGER ThisPeriodTotalKernelTime; // 4 elements, 0x8 bytes (sizeof)
	/*0x0C0*/     ULONG32      TotalPageFaultCount;
	/*0x0C4*/     ULONG32      TotalProcesses;
	/*0x0C8*/     ULONG32      ActiveProcesses;
	/*0x0CC*/     ULONG32      TotalTerminatedProcesses;
	/*0x0D0*/     union _LARGE_INTEGER PerProcessUserTimeLimit;   // 4 elements, 0x8 bytes (sizeof)
	/*0x0D8*/     union _LARGE_INTEGER PerJobUserTimeLimit;       // 4 elements, 0x8 bytes (sizeof)
	/*0x0E0*/     UINT64       MinimumWorkingSetSize;
	/*0x0E8*/     UINT64       MaximumWorkingSetSize;
	/*0x0F0*/     ULONG32      LimitFlags;
	/*0x0F4*/     ULONG32      ActiveProcessLimit;
	/*0x0F8*/     struct _KAFFINITY_EX Affinity;                  // 4 elements, 0x28 bytes (sizeof)
	/*0x120*/     UINT8        PriorityClass;
	/*0x121*/     UINT8        _PADDING0_[0x7];
	/*0x128*/     ULONG64 AccessState;
	/*0x130*/     ULONG32      UIRestrictionsClass;
	/*0x134*/     ULONG32      EndOfJobTimeAction;
	/*0x138*/     VOID*        CompletionPort;
	/*0x140*/     VOID*        CompletionKey;
	/*0x148*/     ULONG32      SessionId;
	/*0x14C*/     ULONG32      SchedulingClass;
	/*0x150*/     UINT64       ReadOperationCount;
	/*0x158*/     UINT64       WriteOperationCount;
	/*0x160*/     UINT64       OtherOperationCount;
	/*0x168*/     UINT64       ReadTransferCount;
	/*0x170*/     UINT64       WriteTransferCount;
	/*0x178*/     UINT64       OtherTransferCount;
	/*0x180*/     UINT64       ProcessMemoryLimit;
	/*0x188*/     UINT64       JobMemoryLimit;
	/*0x190*/     UINT64       PeakProcessMemoryUsed;
	/*0x198*/     UINT64       PeakJobMemoryUsed;
	/*0x1A0*/     UINT64       CurrentJobMemoryUsed;
	/*0x1A8*/     struct _EX_PUSH_LOCK MemoryLimitsLock;          // 7 elements, 0x8 bytes (sizeof)
	/*0x1B0*/     struct _LIST_ENTRY JobSetLinks;                 // 2 elements, 0x10 bytes (sizeof)
	/*0x1C0*/     ULONG32      MemberLevel;
	/*0x1C4*/     ULONG32      JobFlags;
}EJOB, *PEJOB;

typedef struct _HARDWARE_PTE
{
	ULONG64 Valid : 1;
	ULONG64 Write : 1;
	ULONG64 Owner : 1;
	ULONG64 WriteThrough : 1;
	ULONG64 CacheDisable : 1;
	ULONG64 Accessed : 1;
	ULONG64 Dirty : 1;
	ULONG64 LargePage : 1;
	ULONG64 Global : 1;
	ULONG64 CopyOnWrite : 1;
	ULONG64 Prototype : 1;
	ULONG64 reserved0 : 1;
	ULONG64 PageFrameNumber : 28;
	ULONG64 reserved1 : 12;
	ULONG64 SoftwareWsIndex : 11;
	ULONG64 NoExecute : 1;
} HARDWARE_PTE, *PHARDWARE_PTE;
typedef struct _MMWSLE_NONDIRECT_HASH // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     VOID*        Key;
	/*0x008*/     ULONG32      Index;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
}MMWSLE_NONDIRECT_HASH, *PMMWSLE_NONDIRECT_HASH;

typedef struct _MMWSLENTRY               // 7 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       Valid : 1;              // 0 BitPosition
	/*0x000*/     UINT64       Spare : 1;              // 1 BitPosition
	/*0x000*/     UINT64       Hashed : 1;             // 2 BitPosition
	/*0x000*/     UINT64       Direct : 1;             // 3 BitPosition
	/*0x000*/     UINT64       Protection : 5;         // 4 BitPosition
	/*0x000*/     UINT64       Age : 3;                // 9 BitPosition
	/*0x000*/     UINT64       VirtualPageNumber : 52; // 12 BitPosition
}MMWSLENTRY, *PMMWSLENTRY;
typedef struct _MMWSLE_FREE_ENTRY   // 3 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     UINT64       MustBeZero : 1;    // 0 BitPosition
	/*0x000*/     UINT64       PreviousFree : 31; // 1 BitPosition
	/*0x000*/     UINT64       NextFree : 32;     // 32 BitPosition
}MMWSLE_FREE_ENTRY, *PMMWSLE_FREE_ENTRY;
typedef struct _MMWSLE                // 1 elements, 0x8 bytes (sizeof)
{
	union                             // 4 elements, 0x8 bytes (sizeof)
	{
		/*0x000*/         VOID*        VirtualAddress;
		/*0x000*/         UINT64       Long;
		/*0x000*/         struct _MMWSLENTRY e1;        // 7 elements, 0x8 bytes (sizeof)
		/*0x000*/         struct _MMWSLE_FREE_ENTRY e2; // 3 elements, 0x8 bytes (sizeof)
	}u1;
}MMWSLE, *PMMWSLE;
typedef struct _MMWSLE_HASH // 1 elements, 0x4 bytes (sizeof)
{
	/*0x000*/     ULONG32      Index;
}MMWSLE_HASH, *PMMWSLE_HASH;
typedef struct _MMWSL                                   // 25 elements, 0x488 bytes (sizeof)
{
	/*0x000*/     ULONG32      FirstFree;
	/*0x004*/     ULONG32      FirstDynamic;
	/*0x008*/     ULONG32      LastEntry;
	/*0x00C*/     ULONG32      NextSlot;
	/*0x010*/     struct _MMWSLE* Wsle;
	/*0x018*/     VOID*        LowestPagableAddress;
	/*0x020*/     ULONG32      LastInitializedWsle;
	/*0x024*/     ULONG32      NextAgingSlot;
	/*0x028*/     ULONG32      NumberOfCommittedPageTables;
	/*0x02C*/     ULONG32      VadBitMapHint;
	/*0x030*/     ULONG32      NonDirectCount;
	/*0x034*/     ULONG32      LastVadBit;
	/*0x038*/     ULONG32      MaximumLastVadBit;
	/*0x03C*/     ULONG32      LastAllocationSizeHint;
	/*0x040*/     ULONG32      LastAllocationSize;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _MMWSLE_NONDIRECT_HASH* NonDirectHash;
	/*0x050*/     struct _MMWSLE_HASH* HashTableStart;
	/*0x058*/     struct _MMWSLE_HASH* HighestPermittedHashAddress;
	/*0x060*/     ULONG32      MaximumUserPageTablePages;
	/*0x064*/     ULONG32      MaximumUserPageDirectoryPages;
	/*0x068*/     ULONG32*     CommittedPageTables;
	/*0x070*/     ULONG32      NumberOfCommittedPageDirectories;
	/*0x074*/     UINT8        _PADDING1_[0x4];
	/*0x078*/     UINT64       CommittedPageDirectories[128];
	/*0x478*/     ULONG32      NumberOfCommittedPageDirectoryParents;
	/*0x47C*/     UINT8        _PADDING2_[0x4];
	/*0x480*/     UINT64       CommittedPageDirectoryParents[1];
}MMWSL, *PMMWSL;
typedef struct _MMSUPPORT_FLAGS                 // 15 elements, 0x4 bytes (sizeof)
{
	struct                                      // 6 elements, 0x1 bytes (sizeof)
	{
		/*0x000*/         UINT8        WorkingSetType : 3;        // 0 BitPosition
		/*0x000*/         UINT8        ModwriterAttached : 1;     // 3 BitPosition
		/*0x000*/         UINT8        TrimHard : 1;              // 4 BitPosition
		/*0x000*/         UINT8        MaximumWorkingSetHard : 1; // 5 BitPosition
		/*0x000*/         UINT8        ForceTrim : 1;             // 6 BitPosition
		/*0x000*/         UINT8        MinimumWorkingSetHard : 1; // 7 BitPosition
	};
	struct                                      // 4 elements, 0x1 bytes (sizeof)
	{
		/*0x001*/         UINT8        SessionMaster : 1;         // 0 BitPosition
		/*0x001*/         UINT8        TrimmerState : 2;          // 1 BitPosition
		/*0x001*/         UINT8        Reserved : 1;              // 3 BitPosition
		/*0x001*/         UINT8        PageStealers : 4;          // 4 BitPosition
	};
	/*0x002*/     UINT8        MemoryPriority : 8;            // 0 BitPosition
	struct                                      // 4 elements, 0x1 bytes (sizeof)
	{
		/*0x003*/         UINT8        WsleDeleted : 1;           // 0 BitPosition
		/*0x003*/         UINT8        VmExiting : 1;             // 1 BitPosition
		/*0x003*/         UINT8        ExpansionFailed : 1;       // 2 BitPosition
		/*0x003*/         UINT8        Available : 5;             // 3 BitPosition
	};
}MMSUPPORT_FLAGS, *PMMSUPPORT_FLAGS;
typedef struct _MMSUPPORT                        // 21 elements, 0x88 bytes (sizeof)
{
	/*0x000*/     struct _EX_PUSH_LOCK WorkingSetMutex;        // 7 elements, 0x8 bytes (sizeof)
	/*0x008*/     struct _KGATE* ExitGate;
	/*0x010*/     VOID*        AccessLog;
	/*0x018*/     struct _LIST_ENTRY WorkingSetExpansionLinks; // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     ULONG32      AgeDistribution[7];
	/*0x044*/     ULONG32      MinimumWorkingSetSize;
	/*0x048*/     ULONG32      WorkingSetSize;
	/*0x04C*/     ULONG32      WorkingSetPrivateSize;
	/*0x050*/     ULONG32      MaximumWorkingSetSize;
	/*0x054*/     ULONG32      ChargedWslePages;
	/*0x058*/     ULONG32      ActualWslePages;
	/*0x05C*/     ULONG32      WorkingSetSizeOverhead;
	/*0x060*/     ULONG32      PeakWorkingSetSize;
	/*0x064*/     ULONG32      HardFaultCount;
	/*0x068*/     struct _MMWSL* VmWorkingSetList;
	/*0x070*/     UINT16       NextPageColor;
	/*0x072*/     UINT16       LastTrimStamp;
	/*0x074*/     ULONG32      PageFaultCount;
	/*0x078*/     ULONG32      RepurposeCount;
	/*0x07C*/     ULONG32      Spare[2];
	/*0x084*/     struct _MMSUPPORT_FLAGS Flags;               // 15 elements, 0x4 bytes (sizeof)
}MMSUPPORT, *PMMSUPPORT;
typedef struct _SE_AUDIT_PROCESS_CREATION_INFO      // 1 elements, 0x8 bytes (sizeof)
{
	/*0x000*/     struct _OBJECT_NAME_INFORMATION* ImageFileName;
}SE_AUDIT_PROCESS_CREATION_INFO, *PSE_AUDIT_PROCESS_CREATION_INFO;

typedef struct _ALPC_PROCESS_CONTEXT  // 3 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     struct _EX_PUSH_LOCK Lock;        // 7 elements, 0x8 bytes (sizeof)
	/*0x008*/     struct _LIST_ENTRY ViewListHead;  // 2 elements, 0x10 bytes (sizeof)
	/*0x018*/     UINT64       PagedPoolQuotaCache;
}ALPC_PROCESS_CONTEXT, *PALPC_PROCESS_CONTEXT;
typedef struct _PO_DIAG_STACK_RECORD // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     ULONG32      StackDepth;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     VOID*        Stack[1];
}PO_DIAG_STACK_RECORD, *PPO_DIAG_STACK_RECORD;

typedef union _KEXECUTE_OPTIONS                           // 9 elements, 0x1 bytes (sizeof) 
{
	struct                                                // 8 elements, 0x1 bytes (sizeof) 
	{
		/*0x000*/         UINT8        ExecuteDisable : 1;                  // 0 BitPosition                  
		/*0x000*/         UINT8        ExecuteEnable : 1;                   // 1 BitPosition                  
		/*0x000*/         UINT8        DisableThunkEmulation : 1;           // 2 BitPosition                  
		/*0x000*/         UINT8        Permanent : 1;                       // 3 BitPosition                  
		/*0x000*/         UINT8        ExecuteDispatchEnable : 1;           // 4 BitPosition                  
		/*0x000*/         UINT8        ImageDispatchEnable : 1;             // 5 BitPosition                  
		/*0x000*/         UINT8        DisableExceptionChainValidation : 1; // 6 BitPosition                  
		/*0x000*/         UINT8        Spare : 1;                           // 7 BitPosition                  
	};
	/*0x000*/     UINT8        ExecuteOptions;
}KEXECUTE_OPTIONS, *PKEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT           // 3 elements, 0x4 bytes (sizeof) 
{
	/*0x000*/     LONG32       Value;
	struct                            // 2 elements, 0x4 bytes (sizeof) 
	{
		/*0x000*/         ULONG32      State : 3;       // 0 BitPosition                  
		/*0x000*/         ULONG32      StackCount : 29; // 3 BitPosition                  
	};
}KSTACK_COUNT, *PKSTACK_COUNT;

#pragma pack(push) //保存对齐状态
#pragma pack(1)//设定为4字节对齐
typedef struct _KPROCESS                       // 37 elements, 0x160 bytes (sizeof)
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;          // 29 elements, 0x18 bytes (sizeof)
	/*0x018*/     struct _LIST_ENTRY ProfileListHead;        // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     UINT64       DirectoryTableBase;
	/*0x030*/     struct _LIST_ENTRY ThreadListHead;         // 2 elements, 0x10 bytes (sizeof)
	/*0x040*/     UINT64       ProcessLock;
	/*0x048*/     struct _KAFFINITY_EX Affinity;             // 4 elements, 0x28 bytes (sizeof)
	/*0x070*/     struct _LIST_ENTRY ReadyListHead;          // 2 elements, 0x10 bytes (sizeof)
	/*0x080*/     struct _SINGLE_LIST_ENTRY SwapListEntry;   // 1 elements, 0x8 bytes (sizeof)
	/*0x088*/     struct _KAFFINITY_EX ActiveProcessors;     // 4 elements, 0x28 bytes (sizeof)
	union                                      // 2 elements, 0x4 bytes (sizeof)
	{
		struct                                 // 5 elements, 0x4 bytes (sizeof)
		{
			/*0x0B0*/             LONG32       AutoAlignment : 1;    // 0 BitPosition
			/*0x0B0*/             LONG32       DisableBoost : 1;     // 1 BitPosition
			/*0x0B0*/             LONG32       DisableQuantum : 1;   // 2 BitPosition
			/*0x0B0*/             ULONG32      ActiveGroupsMask : 4; // 3 BitPosition
			/*0x0B0*/             LONG32       ReservedFlags : 25;   // 7 BitPosition
		};
		/*0x0B0*/         LONG32       ProcessFlags;
	};
	/*0x0B4*/     CHAR         BasePriority;
	/*0x0B5*/     CHAR         QuantumReset;
	/*0x0B6*/     UINT8        Visited;
	/*0x0B7*/     UINT8        Unused3;
	/*0x0B8*/     ULONG32      ThreadSeed[4];
	/*0x0C8*/     UINT16       IdealNode[4];
	/*0x0D0*/     UINT16       IdealGlobalNode;
	/*0x0D2*/       union _KEXECUTE_OPTIONS Flags;       // 9 elements, 0x1 bytes (sizeof)

	/*0x0D3*/     UINT8        markdbg;
	/*0x0D4  */  ULONG64      newdbgport;
	/*0x0D8*/    //ULONG32      dbg2;

	/*0x0DC*/    union _KSTACK_COUNT StackCount;             // 3 elements, 0x4 bytes (sizeof)
	/*0x0E0*/     struct _LIST_ENTRY ProcessListEntry;       // 2 elements, 0x10 bytes (sizeof)
	/*0x0F0*/     UINT64       CycleTime;
	/*0x0F8*/     ULONG32      KernelTime;
	/*0x0FC*/     ULONG32      UserTime;
	/*0x100*/     ULONG64*        InstrumentationCallback;
	/*0x108*/     union _KGDTENTRY64 LdtSystemDescriptor;    // 7 elements, 0x10 bytes (sizeof)
	/*0x118*/     ULONG64*        LdtBaseAddress;

	/*0x120*/     struct _KGUARDED_MUTEX64 LdtProcessLock;     // 7 elements, 0x38 bytes (sizeof)
	/*0x158*/     UINT16       LdtFreeSelectorHint;
	/*0x15A*/     UINT16       LdtTableLength;
	/*0x4C4*/     UINT8        _PADDING0_[0x4];
	

	
}KPROCESS, *PKPROCESS;
#pragma pack(pop)//恢复对齐状态
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;



typedef struct _KQUEUE                 // 5 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;  // 29 elements, 0x18 bytes (sizeof)
	/*0x018*/     struct _LIST_ENTRY EntryListHead;  // 2 elements, 0x10 bytes (sizeof)
	/*0x028*/     ULONG32      CurrentCount;
	/*0x02C*/     ULONG32      MaximumCount;
	/*0x030*/     struct _LIST_ENTRY ThreadListHead; // 2 elements, 0x10 bytes (sizeof)
}KQUEUE, *PKQUEUE;

typedef struct _RTL_UMS_CONTEXT                       // 28 elements, 0x540 bytes (sizeof)
{
	/*0x000*/     struct _SINGLE_LIST_ENTRY Link;                   // 1 elements, 0x8 bytes (sizeof)
	/*0x008*/     UINT8        _PADDING0_[0x8];
	/*0x010*/     struct _CONTEXT Context;                          // 64 elements, 0x4D0 bytes (sizeof)
	/*0x4E0*/     VOID*        Teb;
	/*0x4E8*/     VOID*        UserContext;
	union                                             // 2 elements, 0x8 bytes (sizeof)
	{
		struct                                        // 11 elements, 0x4 bytes (sizeof)
		{
			/*0x4F0*/             ULONG32      ScheduledThread : 1;         // 0 BitPosition
			/*0x4F0*/             ULONG32      HasQuantumReq : 1;           // 1 BitPosition
			/*0x4F0*/             ULONG32      HasAffinityReq : 1;          // 2 BitPosition
			/*0x4F0*/             ULONG32      HasPriorityReq : 1;          // 3 BitPosition
			/*0x4F0*/             ULONG32      Suspended : 1;               // 4 BitPosition
			/*0x4F0*/             ULONG32      VolatileContext : 1;         // 5 BitPosition
			/*0x4F0*/             ULONG32      Terminated : 1;              // 6 BitPosition
			/*0x4F0*/             ULONG32      DebugActive : 1;             // 7 BitPosition
			/*0x4F0*/             ULONG32      RunningOnSelfThread : 1;     // 8 BitPosition
			/*0x4F0*/             ULONG32      DenyRunningOnSelfThread : 1; // 9 BitPosition
			/*0x4F0*/             ULONG32      ReservedFlags : 22;          // 10 BitPosition
		};
		/*0x4F0*/         LONG32       Flags;
	};
	union                                             // 2 elements, 0x8 bytes (sizeof)
	{
		struct                                        // 3 elements, 0x8 bytes (sizeof)
		{
			/*0x4F8*/             UINT64       KernelUpdateLock : 1;        // 0 BitPosition
			/*0x4F8*/             UINT64       Reserved : 1;                // 1 BitPosition
			/*0x4F8*/             UINT64       PrimaryClientID : 62;        // 2 BitPosition
		};
		/*0x4F8*/         UINT64       ContextLock;
	};
	/*0x500*/     UINT64       QuantumValue;
	/*0x508*/     struct _GROUP_AFFINITY AffinityMask;              // 3 elements, 0x10 bytes (sizeof)
	/*0x518*/     LONG32       Priority;
	/*0x51C*/     UINT8        _PADDING1_[0x4];
	/*0x520*/     struct _RTL_UMS_CONTEXT* PrimaryUmsContext;
	/*0x528*/     ULONG32      SwitchCount;
	/*0x52C*/     ULONG32      KernelYieldCount;
	/*0x530*/     ULONG32      MixedYieldCount;
	/*0x534*/     ULONG32      YieldCount;
	/*0x538*/     UINT8        _PADDING2_[0x8];
}RTL_UMS_CONTEXT, *PRTL_UMS_CONTEXT;
typedef struct _UMS_CONTROL_BLOCK                                // 22 elements, 0x98 bytes (sizeof)
{
	/*0x000*/     struct _RTL_UMS_CONTEXT* UmsContext;
	/*0x008*/     struct _SINGLE_LIST_ENTRY* CompletionListEntry;
	/*0x010*/     struct _KEVENT* CompletionListEvent;
	/*0x018*/     ULONG32      ServiceSequenceNumber;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
	union                                                        // 2 elements, 0x6C bytes (sizeof)
	{
		struct                                                   // 6 elements, 0x6C bytes (sizeof)
		{
			/*0x020*/             struct _KQUEUE UmsQueue;                             // 5 elements, 0x40 bytes (sizeof)
			/*0x060*/             struct _LIST_ENTRY QueueEntry;                       // 2 elements, 0x10 bytes (sizeof)
			/*0x070*/             struct _RTL_UMS_CONTEXT* YieldingUmsContext;
			/*0x078*/             VOID*        YieldingParam;
			/*0x080*/             VOID*        UmsTeb;
			union                                                // 2 elements, 0x4 bytes (sizeof)
			{
				/*0x088*/                 ULONG32      PrimaryFlags;
				/*0x088*/                 ULONG32      UmsContextHeaderReady : 1;          // 0 BitPosition
			};
		};
		struct                                                   // 6 elements, 0x6C bytes (sizeof)
		{
			/*0x020*/             struct _KQUEUE* UmsAssociatedQueue;
			/*0x028*/             struct _LIST_ENTRY* UmsQueueListEntry;
			/*0x030*/             struct _KUMS_CONTEXT_HEADER* UmsContextHeader;
			/*0x038*/             struct _KGATE UmsWaitGate;                           // 1 elements, 0x18 bytes (sizeof)
			/*0x050*/             VOID*        StagingArea;
			union                                                // 2 elements, 0x4 bytes (sizeof)
			{
				/*0x058*/                 LONG32       Flags;
				struct                                           // 4 elements, 0x4 bytes (sizeof)
				{
					/*0x058*/                     ULONG32      UmsForceQueueTermination : 1;   // 0 BitPosition
					/*0x058*/                     ULONG32      UmsAssociatedQueueUsed : 1;     // 1 BitPosition
					/*0x058*/                     ULONG32      UmsThreadParked : 1;            // 2 BitPosition
					/*0x058*/                     ULONG32      UmsPrimaryDeliveredContext : 1; // 3 BitPosition
				};
			};
		};
	};
	/*0x090*/     UINT16       TebSelector;
	/*0x092*/     UINT8        _PADDING1_[0x6];
}UMS_CONTROL_BLOCK, *PUMS_CONTROL_BLOCK;
typedef struct _KDESCRIPTOR // 3 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT16       Pad[3];
	/*0x006*/     UINT16       Limit;
	/*0x008*/     VOID*        Base;
}KDESCRIPTOR, *PKDESCRIPTOR;
typedef struct _KSPECIAL_REGISTERS     // 27 elements, 0xD8 bytes (sizeof)
{
	/*0x000*/     UINT64       Cr0;
	/*0x008*/     UINT64       Cr2;
	/*0x010*/     UINT64       Cr3;
	/*0x018*/     UINT64       Cr4;
	/*0x020*/     UINT64       KernelDr0;
	/*0x028*/     UINT64       KernelDr1;
	/*0x030*/     UINT64       KernelDr2;
	/*0x038*/     UINT64       KernelDr3;
	/*0x040*/     UINT64       KernelDr6;
	/*0x048*/     UINT64       KernelDr7;
	/*0x050*/     struct _KDESCRIPTOR Gdtr;          // 3 elements, 0x10 bytes (sizeof)
	/*0x060*/     struct _KDESCRIPTOR Idtr;          // 3 elements, 0x10 bytes (sizeof)
	/*0x070*/     UINT16       Tr;
	/*0x072*/     UINT16       Ldtr;
	/*0x074*/     ULONG32      MxCsr;
	/*0x078*/     UINT64       DebugControl;
	/*0x080*/     UINT64       LastBranchToRip;
	/*0x088*/     UINT64       LastBranchFromRip;
	/*0x090*/     UINT64       LastExceptionToRip;
	/*0x098*/     UINT64       LastExceptionFromRip;
	/*0x0A0*/     UINT64       Cr8;
	/*0x0A8*/     UINT64       MsrGsBase;
	/*0x0B0*/     UINT64       MsrGsSwap;
	/*0x0B8*/     UINT64       MsrStar;
	/*0x0C0*/     UINT64       MsrLStar;
	/*0x0C8*/     UINT64       MsrCStar;
	/*0x0D0*/     UINT64       MsrSyscallMask;
}KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;
typedef struct _KPROCESSOR_STATE                 // 2 elements, 0x5B0 bytes (sizeof)
{
	/*0x000*/     struct _KSPECIAL_REGISTERS SpecialRegisters; // 27 elements, 0xD8 bytes (sizeof)
	/*0x0D8*/     UINT8        _PADDING0_[0x8];
	/*0x0E0*/     struct _CONTEXT ContextFrame;                // 64 elements, 0x4D0 bytes (sizeof)
}KPROCESSOR_STATE, *PKPROCESSOR_STATE;


typedef struct _PP_LOOKASIDE_LIST // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     struct _GENERAL_LOOKASIDE* P;
	/*0x008*/     struct _GENERAL_LOOKASIDE* L;
}PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;
typedef struct _KDPC_DATA           // 4 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY DpcListHead; // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     UINT64       DpcLock;
	/*0x018*/     LONG32       DpcQueueDepth;
	/*0x01C*/     ULONG32      DpcCount;
}KDPC_DATA, *PKDPC_DATA;
typedef struct _KTIMER_TABLE_ENTRY // 3 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT64       Lock;
	/*0x008*/     struct _LIST_ENTRY Entry;      // 2 elements, 0x10 bytes (sizeof)
	/*0x018*/     union _ULARGE_INTEGER Time;    // 4 elements, 0x8 bytes (sizeof)
}KTIMER_TABLE_ENTRY, *PKTIMER_TABLE_ENTRY;
typedef struct _KTIMER_TABLE                      // 2 elements, 0x2200 bytes (sizeof)
{
	/*0x000*/     struct _KTIMER* TimerExpiry[64];
	/*0x200*/     struct _KTIMER_TABLE_ENTRY TimerEntries[256];
}KTIMER_TABLE, *PKTIMER_TABLE;
typedef struct _flags                      // 5 elements, 0x1 bytes (sizeof)
{
	/*0x000*/     UINT8        Removable : 1;            // 0 BitPosition
	/*0x000*/     UINT8        GroupAssigned : 1;        // 1 BitPosition
	/*0x000*/     UINT8        GroupCommitted : 1;       // 2 BitPosition
	/*0x000*/     UINT8        GroupAssignmentFixed : 1; // 3 BitPosition
	/*0x000*/     UINT8        Fill : 4;                 // 4 BitPosition
}flags, *Pflags;
typedef struct _CACHED_KSTACK_LIST // 5 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     union _SLIST_HEADER SListHead; // 5 elements, 0x10 bytes (sizeof)
	/*0x010*/     LONG32       MinimumFree;
	/*0x014*/     ULONG32      Misses;
	/*0x018*/     ULONG32      MissesLast;
	/*0x01C*/     ULONG32      Pad0;
}CACHED_KSTACK_LIST, *PCACHED_KSTACK_LIST;
typedef struct _KNODE                              // 18 elements, 0xC0 bytes (sizeof)
{
	/*0x000*/     union _SLIST_HEADER PagedPoolSListHead;        // 5 elements, 0x10 bytes (sizeof)
	/*0x010*/     union _SLIST_HEADER NonPagedPoolSListHead[3];
	/*0x040*/     struct _GROUP_AFFINITY Affinity;               // 3 elements, 0x10 bytes (sizeof)
	/*0x050*/     ULONG32      ProximityId;
	/*0x054*/     UINT16       NodeNumber;
	/*0x056*/     UINT16       PrimaryNodeNumber;
	/*0x058*/     UINT8        MaximumProcessors;
	/*0x059*/     UINT8        Color;
	/*0x05A*/     struct _flags Flags;                           // 5 elements, 0x1 bytes (sizeof)
	/*0x05B*/     UINT8        NodePad0;
	/*0x05C*/     ULONG32      Seed;
	/*0x060*/     ULONG32      MmShiftedColor;
	/*0x064*/     UINT8        _PADDING0_[0x4];
	/*0x068*/     UINT64       FreeCount[2];
	/*0x078*/     ULONG32      Right;
	/*0x07C*/     ULONG32      Left;
	/*0x080*/     struct _CACHED_KSTACK_LIST CachedKernelStacks; // 5 elements, 0x20 bytes (sizeof)
	/*0x0A0*/     LONG32       ParkLock;
	/*0x0A4*/     ULONG32      NodePad1;
	/*0x0A8*/     UINT8        _PADDING1_[0x18];
}KNODE, *PKNODE;
typedef struct _PPM_IDLE_STATE                                                                                                                                              // 14 elements, 0x60 bytes (sizeof)
{
	/*0x000*/     struct _KAFFINITY_EX DomainMembers;                                                                                                                                     // 4 elements, 0x28 bytes (sizeof)
	/*0x028*/     PVOID IdleCheck;
	/*0x030*/     PVOID IdleHandler;
	/*0x038*/     UINT64       HvConfig;
	/*0x040*/     VOID*        Context;
	/*0x048*/     ULONG32      Latency;
	/*0x04C*/     ULONG32      Power;
	/*0x050*/     ULONG32      TimeCheck;
	/*0x054*/     ULONG32      StateFlags;
	/*0x058*/     UINT8        PromotePercent;
	/*0x059*/     UINT8        DemotePercent;
	/*0x05A*/     UINT8        PromotePercentBase;
	/*0x05B*/     UINT8        DemotePercentBase;
	/*0x05C*/     UINT8        StateType;
	/*0x05D*/     UINT8        _PADDING0_[0x3];
}PPM_IDLE_STATE, *PPPM_IDLE_STATE;
typedef struct _PPM_IDLE_STATES            // 8 elements, 0xA0 bytes (sizeof)
{
	/*0x000*/     ULONG32      Count;
	union                                  // 5 elements, 0x4 bytes (sizeof)
	{
		/*0x004*/         ULONG32      AsULONG;
		struct                             // 4 elements, 0x4 bytes (sizeof)
		{
			/*0x004*/             ULONG32      AllowScaling : 1; // 0 BitPosition
			/*0x004*/             ULONG32      Disabled : 1;     // 1 BitPosition
			/*0x004*/             ULONG32      HvMaxCState : 4;  // 2 BitPosition
			/*0x004*/             ULONG32      Reserved : 26;    // 6 BitPosition
		};
	}Flags;
	/*0x008*/     ULONG32      TargetState;
	/*0x00C*/     ULONG32      ActualState;
	/*0x010*/     ULONG32      OldState;
	/*0x014*/     UINT8        NewlyUnparked;
	/*0x015*/     UINT8        _PADDING0_[0x3];
	/*0x018*/     struct _KAFFINITY_EX TargetProcessors; // 4 elements, 0x28 bytes (sizeof)
	/*0x040*/     struct _PPM_IDLE_STATE State[1];
}PPM_IDLE_STATES, *PPPM_IDLE_STATES;
typedef struct _PROC_IDLE_STATE_BUCKET // 4 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     UINT64       MinTime;
	/*0x010*/     UINT64       MaxTime;
	/*0x018*/     ULONG32      Count;
	/*0x01C*/     UINT8        _PADDING0_[0x4];
}PROC_IDLE_STATE_BUCKET, *PPROC_IDLE_STATE_BUCKET;
typedef struct _PROC_IDLE_STATE_ACCOUNTING              // 7 elements, 0x228 bytes (sizeof)
{
	/*0x000*/     UINT64       TotalTime;
	/*0x008*/     ULONG32      IdleTransitions;
	/*0x00C*/     ULONG32      FailedTransitions;
	/*0x010*/     ULONG32      InvalidBucketIndex;
	/*0x014*/     UINT8        _PADDING0_[0x4];
	/*0x018*/     UINT64       MinTime;
	/*0x020*/     UINT64       MaxTime;
	/*0x028*/     struct _PROC_IDLE_STATE_BUCKET IdleTimeBuckets[16];
}PROC_IDLE_STATE_ACCOUNTING, *PPROC_IDLE_STATE_ACCOUNTING;
typedef struct _PROC_IDLE_ACCOUNTING             // 6 elements, 0x2C0 bytes (sizeof)
{
	/*0x000*/     ULONG32      StateCount;
	/*0x004*/     ULONG32      TotalTransitions;
	/*0x008*/     ULONG32      ResetCount;
	/*0x00C*/     UINT8        _PADDING0_[0x4];
	/*0x010*/     UINT64       StartTime;
	/*0x018*/     UINT64       BucketLimits[16];
	/*0x098*/     struct _PROC_IDLE_STATE_ACCOUNTING State[1];
}PROC_IDLE_ACCOUNTING, *PPROC_IDLE_ACCOUNTING;
typedef enum _PROC_HYPERVISOR_STATE  // 3 elements, 0x4 bytes
{
	ProcHypervisorNone = 0 /*0x0*/,
	ProcHypervisorPresent = 1 /*0x1*/,
	ProcHypervisorPower = 2 /*0x2*/
}PROC_HYPERVISOR_STATE, *PPROC_HYPERVISOR_STATE;
typedef struct _PPM_FFH_THROTTLE_STATE_INFO // 5 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     UINT8        EnableLogging;
	/*0x001*/     UINT8        _PADDING0_[0x3];
	/*0x004*/     ULONG32      MismatchCount;
	/*0x008*/     UINT8        Initialized;
	/*0x009*/     UINT8        _PADDING1_[0x7];
	/*0x010*/     UINT64       LastValue;
	/*0x018*/     union _LARGE_INTEGER LastLogTickCount;  // 4 elements, 0x8 bytes (sizeof)
}PPM_FFH_THROTTLE_STATE_INFO, *PPPM_FFH_THROTTLE_STATE_INFO;

typedef struct _PROC_IDLE_SNAP // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       Time;
	/*0x008*/     UINT64       Idle;
}PROC_IDLE_SNAP, *PPROC_IDLE_SNAP;
typedef struct _PROC_PERF_CONSTRAINT      // 9 elements, 0x30 bytes (sizeof)
{
	/*0x000*/     struct _KPRCB* Prcb;
	/*0x008*/     UINT64       PerfContext;
	/*0x010*/     ULONG32      PercentageCap;
	/*0x014*/     ULONG32      ThermalCap;
	/*0x018*/     ULONG32      TargetFrequency;
	/*0x01C*/     ULONG32      AcumulatedFullFrequency;
	/*0x020*/     ULONG32      AcumulatedZeroFrequency;
	/*0x024*/     ULONG32      FrequencyHistoryTotal;
	/*0x028*/     ULONG32      AverageFrequency;
	/*0x02C*/     UINT8        _PADDING0_[0x4];
}PROC_PERF_CONSTRAINT, *PPROC_PERF_CONSTRAINT;

typedef struct _PROC_PERF_DOMAIN                                         // 26 elements, 0xB8 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY Link;                                             // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _KPRCB* Master;
	/*0x018*/     struct _KAFFINITY_EX Members;                                        // 4 elements, 0x28 bytes (sizeof)
	/*0x040*/     PVOID FeedbackHandler;
	/*0x048*/     PVOID GetFFHThrottleState;
	/*0x050*/     PVOID BoostPolicyHandler;
	/*0x058*/     PVOID PerfSelectionHandler;
	/*0x060*/     PVOID PerfHandler;
	/*0x068*/     struct _PROC_PERF_CONSTRAINT* Processors;
	/*0x070*/     UINT64       PerfChangeTime;
	/*0x078*/     ULONG32      ProcessorCount;
	/*0x07C*/     ULONG32      PreviousFrequencyMhz;
	/*0x080*/     ULONG32      CurrentFrequencyMhz;
	/*0x084*/     ULONG32      PreviousFrequency;
	/*0x088*/     ULONG32      CurrentFrequency;
	/*0x08C*/     ULONG32      CurrentPerfContext;
	/*0x090*/     ULONG32      DesiredFrequency;
	/*0x094*/     ULONG32      MaxFrequency;
	/*0x098*/     ULONG32      MinPerfPercent;
	/*0x09C*/     ULONG32      MinThrottlePercent;
	/*0x0A0*/     ULONG32      MaxPercent;
	/*0x0A4*/     ULONG32      MinPercent;
	/*0x0A8*/     ULONG32      ConstrainedMaxPercent;
	/*0x0AC*/     ULONG32      ConstrainedMinPercent;
	/*0x0B0*/     UINT8        Coordination;
	/*0x0B1*/     UINT8        _PADDING0_[0x3];
	/*0x0B4*/     LONG32       PerfChangeIntervalCount;
}PROC_PERF_DOMAIN, *PPROC_PERF_DOMAIN;
typedef struct _PROC_PERF_LOAD        // 2 elements, 0x2 bytes (sizeof)
{
	/*0x000*/     UINT8        BusyPercentage;
	/*0x001*/     UINT8        FrequencyPercentage;
}PROC_PERF_LOAD, *PPROC_PERF_LOAD;
typedef struct _PROC_HISTORY_ENTRY // 3 elements, 0x4 bytes (sizeof)
{
	/*0x000*/     UINT16       Utility;
	/*0x002*/     UINT8        Frequency;
	/*0x003*/     UINT8        Reserved;
}PROC_HISTORY_ENTRY, *PPROC_HISTORY_ENTRY;
typedef struct _PROCESSOR_POWER_STATE                         // 27 elements, 0x100 bytes (sizeof)
{
	/*0x000*/     struct _PPM_IDLE_STATES* IdleStates;
	/*0x008*/     UINT64       IdleTimeLast;
	/*0x010*/     UINT64       IdleTimeTotal;
	/*0x018*/     UINT64       IdleTimeEntry;
	/*0x020*/     struct _PROC_IDLE_ACCOUNTING* IdleAccounting;
	/*0x028*/     enum _PROC_HYPERVISOR_STATE Hypervisor;
	/*0x02C*/     ULONG32      PerfHistoryTotal;
	/*0x030*/     UINT8        ThermalConstraint;
	/*0x031*/     UINT8        PerfHistoryCount;
	/*0x032*/     UINT8        PerfHistorySlot;
	/*0x033*/     UINT8        Reserved;
	/*0x034*/     ULONG32      LastSysTime;
	/*0x038*/     UINT64       WmiDispatchPtr;
	/*0x040*/     LONG32       WmiInterfaceEnabled;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _PPM_FFH_THROTTLE_STATE_INFO FFHThrottleStateInfo; // 5 elements, 0x20 bytes (sizeof)
	/*0x068*/     struct _KDPC PerfActionDpc;                               // 9 elements, 0x40 bytes (sizeof)
	/*0x0A8*/     LONG32       PerfActionMask;
	/*0x0AC*/     UINT8        _PADDING1_[0x4];
	/*0x0B0*/     struct _PROC_IDLE_SNAP IdleCheck;                         // 2 elements, 0x10 bytes (sizeof)
	/*0x0C0*/     struct _PROC_IDLE_SNAP PerfCheck;                         // 2 elements, 0x10 bytes (sizeof)
	/*0x0D0*/     struct _PROC_PERF_DOMAIN* Domain;
	/*0x0D8*/     struct _PROC_PERF_CONSTRAINT* PerfConstraint;
	/*0x0E0*/     struct _PROC_PERF_LOAD* Load;
	/*0x0E8*/     struct _PROC_HISTORY_ENTRY* PerfHistory;
	/*0x0F0*/     ULONG32      Utility;
	/*0x0F4*/     ULONG32      OverUtilizedHistory;
	/*0x0F8*/     ULONG32      AffinityCount;
	/*0x0FC*/     ULONG32      AffinityHistory;
}PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;
typedef struct _KREQUEST_PACKET                   // 2 elements, 0x20 bytes (sizeof)
{
	/*0x000*/     VOID*        CurrentPacket[3];
	/*0x018*/     PVOID WorkerRoutine;
}KREQUEST_PACKET, *PKREQUEST_PACKET;
typedef struct _REQUEST_MAILBOX            // 3 elements, 0x40 bytes (sizeof)
{
	/*0x000*/     struct _REQUEST_MAILBOX* Next;
	/*0x008*/     INT64        RequestSummary;
	/*0x010*/     struct _KREQUEST_PACKET RequestPacket; // 2 elements, 0x20 bytes (sizeof)
	/*0x030*/     UINT8        _PADDING0_[0x10];
}REQUEST_MAILBOX, *PREQUEST_MAILBOX;

typedef struct _KPRCB                                                   // 242 elements, 0x4D00 bytes (sizeof)
{
	/*0x000*/      ULONG32      MxCsr;
	/*0x004*/      UINT8        LegacyNumber;
	/*0x005*/      UINT8        ReservedMustBeZero;
	/*0x006*/      UINT8        InterruptRequest;
	/*0x007*/      UINT8        IdleHalt;
	/*0x008*/      struct _KTHREAD* CurrentThread;
	/*0x010*/      struct _KTHREAD* NextThread;
	/*0x018*/      struct _KTHREAD* IdleThread;
	/*0x020*/      UINT8        NestingLevel;
	/*0x021*/      UINT8        PrcbPad00[3];
	/*0x024*/      ULONG32      Number;
	/*0x028*/      UINT64       RspBase;
	/*0x030*/      UINT64       PrcbLock;
	/*0x038*/      UINT64       PrcbPad01;
	/*0x040*/      struct _KPROCESSOR_STATE ProcessorState;                            // 2 elements, 0x5B0 bytes (sizeof)
	/*0x5F0*/      CHAR         CpuType;
	/*0x5F1*/      CHAR         CpuID;
	union                                                               // 2 elements, 0x2 bytes (sizeof)
	{
		/*0x5F2*/          UINT16       CpuStep;
		struct                                                          // 2 elements, 0x2 bytes (sizeof)
		{
			/*0x5F2*/              UINT8        CpuStepping;
			/*0x5F3*/              UINT8        CpuModel;
		};
	};
	/*0x5F4*/      ULONG32      MHz;
	/*0x5F8*/      UINT64       HalReserved[8];
	/*0x638*/      UINT16       MinorVersion;
	/*0x63A*/      UINT16       MajorVersion;
	/*0x63C*/      UINT8        BuildType;
	/*0x63D*/      UINT8        CpuVendor;
	/*0x63E*/      UINT8        CoresPerPhysicalProcessor;
	/*0x63F*/      UINT8        LogicalProcessorsPerCore;
	/*0x640*/      ULONG32      ApicMask;
	/*0x644*/      ULONG32      CFlushSize;
	/*0x648*/      VOID*        AcpiReserved;
	/*0x650*/      ULONG32      InitialApicId;
	/*0x654*/      ULONG32      Stride;
	/*0x658*/      UINT16       Group;
	/*0x65A*/      UINT8        _PADDING0_[0x6];
	/*0x660*/      UINT64       GroupSetMember;
	/*0x668*/      UINT8        GroupIndex;
	/*0x669*/      UINT8        _PADDING1_[0x7];
	/*0x670*/      struct _KSPIN_LOCK_QUEUE LockQueue[17];
	/*0x780*/      struct _PP_LOOKASIDE_LIST PPLookasideList[16];
	/*0x880*/      struct _GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
	/*0x1480*/     struct _GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
	/*0x2080*/     LONG32       PacketBarrier;
	/*0x2084*/     UINT8        _PADDING2_[0x4];
	/*0x2088*/     struct _SINGLE_LIST_ENTRY DeferredReadyListHead;                    // 1 elements, 0x8 bytes (sizeof)
	/*0x2090*/     LONG32       MmPageFaultCount;
	/*0x2094*/     LONG32       MmCopyOnWriteCount;
	/*0x2098*/     LONG32       MmTransitionCount;
	/*0x209C*/     LONG32       MmDemandZeroCount;
	/*0x20A0*/     LONG32       MmPageReadCount;
	/*0x20A4*/     LONG32       MmPageReadIoCount;
	/*0x20A8*/     LONG32       MmDirtyPagesWriteCount;
	/*0x20AC*/     LONG32       MmDirtyWriteIoCount;
	/*0x20B0*/     LONG32       MmMappedPagesWriteCount;
	/*0x20B4*/     LONG32       MmMappedWriteIoCount;
	/*0x20B8*/     ULONG32      KeSystemCalls;
	/*0x20BC*/     ULONG32      KeContextSwitches;
	/*0x20C0*/     ULONG32      CcFastReadNoWait;
	/*0x20C4*/     ULONG32      CcFastReadWait;
	/*0x20C8*/     ULONG32      CcFastReadNotPossible;
	/*0x20CC*/     ULONG32      CcCopyReadNoWait;
	/*0x20D0*/     ULONG32      CcCopyReadWait;
	/*0x20D4*/     ULONG32      CcCopyReadNoWaitMiss;
	/*0x20D8*/     LONG32       LookasideIrpFloat;
	/*0x20DC*/     LONG32       IoReadOperationCount;
	/*0x20E0*/     LONG32       IoWriteOperationCount;
	/*0x20E4*/     LONG32       IoOtherOperationCount;
	/*0x20E8*/     union _LARGE_INTEGER IoReadTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
	/*0x20F0*/     union _LARGE_INTEGER IoWriteTransferCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x20F8*/     union _LARGE_INTEGER IoOtherTransferCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x2100*/     LONG32       TargetCount;
	/*0x2104*/     ULONG32      IpiFrozen;
	/*0x2108*/     UINT8        _PADDING3_[0x78];
	/*0x2180*/     struct _KDPC_DATA DpcData[2];
	/*0x21C0*/     VOID*        DpcStack;
	/*0x21C8*/     LONG32       MaximumDpcQueueDepth;
	/*0x21CC*/     ULONG32      DpcRequestRate;
	/*0x21D0*/     ULONG32      MinimumDpcRate;
	/*0x21D4*/     ULONG32      DpcLastCount;
	/*0x21D8*/     UINT8        ThreadDpcEnable;
	/*0x21D9*/     UINT8        QuantumEnd;
	/*0x21DA*/     UINT8        DpcRoutineActive;
	/*0x21DB*/     UINT8        IdleSchedule;
	union                                                               // 3 elements, 0x4 bytes (sizeof)
	{
		/*0x21DC*/         LONG32       DpcRequestSummary;
		/*0x21DC*/         INT16        DpcRequestSlot[2];
		struct                                                          // 2 elements, 0x4 bytes (sizeof)
		{
			/*0x21DC*/             INT16        NormalDpcState;
			union                                                       // 2 elements, 0x2 bytes (sizeof)
			{
				/*0x21DE*/                 UINT16       DpcThreadActive : 1;                       // 0 BitPosition
				/*0x21DE*/                 INT16        ThreadDpcState;
			};
		};
	};
	/*0x21E0*/     ULONG32      TimerHand;
	/*0x21E4*/     LONG32       MasterOffset;
	/*0x21E8*/     ULONG32      LastTick;
	/*0x21EC*/     ULONG32      UnusedPad;
	/*0x21F0*/     UINT64       PrcbPad50[2];
	/*0x2200*/     struct _KTIMER_TABLE TimerTable;                                    // 2 elements, 0x2200 bytes (sizeof)
	/*0x4400*/     struct _KGATE DpcGate;                                              // 1 elements, 0x18 bytes (sizeof)
	/*0x4418*/     VOID*        PrcbPad52;
	/*0x4420*/     struct _KDPC CallDpc;                                               // 9 elements, 0x40 bytes (sizeof)
	/*0x4460*/     LONG32       ClockKeepAlive;
	/*0x4464*/     UINT8        ClockCheckSlot;
	/*0x4465*/     UINT8        ClockPollCycle;
	/*0x4466*/     UINT16       NmiActive;
	/*0x4468*/     LONG32       DpcWatchdogPeriod;
	/*0x446C*/     LONG32       DpcWatchdogCount;
	/*0x4470*/     UINT64       TickOffset;
	/*0x4478*/     LONG32       KeSpinLockOrdering;
	/*0x447C*/     ULONG32      PrcbPad70;
	/*0x4480*/     struct _LIST_ENTRY WaitListHead;                                    // 2 elements, 0x10 bytes (sizeof)
	/*0x4490*/     UINT64       WaitLock;
	/*0x4498*/     ULONG32      ReadySummary;
	/*0x449C*/     ULONG32      QueueIndex;
	/*0x44A0*/     struct _KDPC TimerExpirationDpc;                                    // 9 elements, 0x40 bytes (sizeof)
	/*0x44E0*/     UINT64       PrcbPad72[4];
	/*0x4500*/     struct _LIST_ENTRY DispatcherReadyListHead[32];
	/*0x4700*/     ULONG32      InterruptCount;
	/*0x4704*/     ULONG32      KernelTime;
	/*0x4708*/     ULONG32      UserTime;
	/*0x470C*/     ULONG32      DpcTime;
	/*0x4710*/     ULONG32      InterruptTime;
	/*0x4714*/     ULONG32      AdjustDpcThreshold;
	/*0x4718*/     UINT8        DebuggerSavedIRQL;
	/*0x4719*/     UINT8        PrcbPad80[7];
	/*0x4720*/     ULONG32      DpcTimeCount;
	/*0x4724*/     ULONG32      DpcTimeLimit;
	/*0x4728*/     ULONG32      PeriodicCount;
	/*0x472C*/     ULONG32      PeriodicBias;
	/*0x4730*/     ULONG32      AvailableTime;
	/*0x4734*/     ULONG32      KeExceptionDispatchCount;
	/*0x4738*/     struct _KNODE* ParentNode;
	/*0x4740*/     UINT64       StartCycles;
	/*0x4748*/     UINT64       PrcbPad82[3];
	/*0x4760*/     LONG32       MmSpinLockOrdering;
	/*0x4764*/     ULONG32      PageColor;
	/*0x4768*/     ULONG32      NodeColor;
	/*0x476C*/     ULONG32      NodeShiftedColor;
	/*0x4770*/     ULONG32      SecondaryColorMask;
	/*0x4774*/     ULONG32      PrcbPad83;
	/*0x4778*/     UINT64       CycleTime;
	/*0x4780*/     ULONG32      CcFastMdlReadNoWait;
	/*0x4784*/     ULONG32      CcFastMdlReadWait;
	/*0x4788*/     ULONG32      CcFastMdlReadNotPossible;
	/*0x478C*/     ULONG32      CcMapDataNoWait;
	/*0x4790*/     ULONG32      CcMapDataWait;
	/*0x4794*/     ULONG32      CcPinMappedDataCount;
	/*0x4798*/     ULONG32      CcPinReadNoWait;
	/*0x479C*/     ULONG32      CcPinReadWait;
	/*0x47A0*/     ULONG32      CcMdlReadNoWait;
	/*0x47A4*/     ULONG32      CcMdlReadWait;
	/*0x47A8*/     ULONG32      CcLazyWriteHotSpots;
	/*0x47AC*/     ULONG32      CcLazyWriteIos;
	/*0x47B0*/     ULONG32      CcLazyWritePages;
	/*0x47B4*/     ULONG32      CcDataFlushes;
	/*0x47B8*/     ULONG32      CcDataPages;
	/*0x47BC*/     ULONG32      CcLostDelayedWrites;
	/*0x47C0*/     ULONG32      CcFastReadResourceMiss;
	/*0x47C4*/     ULONG32      CcCopyReadWaitMiss;
	/*0x47C8*/     ULONG32      CcFastMdlReadResourceMiss;
	/*0x47CC*/     ULONG32      CcMapDataNoWaitMiss;
	/*0x47D0*/     ULONG32      CcMapDataWaitMiss;
	/*0x47D4*/     ULONG32      CcPinReadNoWaitMiss;
	/*0x47D8*/     ULONG32      CcPinReadWaitMiss;
	/*0x47DC*/     ULONG32      CcMdlReadNoWaitMiss;
	/*0x47E0*/     ULONG32      CcMdlReadWaitMiss;
	/*0x47E4*/     ULONG32      CcReadAheadIos;
	/*0x47E8*/     LONG32       MmCacheTransitionCount;
	/*0x47EC*/     LONG32       MmCacheReadCount;
	/*0x47F0*/     LONG32       MmCacheIoCount;
	/*0x47F4*/     ULONG32      PrcbPad91[1];
	/*0x47F8*/     UINT64       RuntimeAccumulation;
	/*0x4800*/     struct _PROCESSOR_POWER_STATE PowerState;                           // 27 elements, 0x100 bytes (sizeof)
	/*0x4900*/     UINT8        PrcbPad92[16];
	/*0x4910*/     ULONG32      KeAlignmentFixupCount;
	/*0x4914*/     UINT8        _PADDING4_[0x4];
	/*0x4918*/     struct _KDPC DpcWatchdogDpc;                                        // 9 elements, 0x40 bytes (sizeof)
	/*0x4958*/     struct _KTIMER DpcWatchdogTimer;                                    // 6 elements, 0x40 bytes (sizeof)
	/*0x4998*/     struct _CACHE_DESCRIPTOR Cache[5];
	/*0x49D4*/     ULONG32      CacheCount;
	/*0x49D8*/     ULONG32      CachedCommit;
	/*0x49DC*/     ULONG32      CachedResidentAvailable;
	/*0x49E0*/     VOID*        HyperPte;
	/*0x49E8*/     VOID*        WheaInfo;
	/*0x49F0*/     VOID*        EtwSupport;
	/*0x49F8*/     UINT8        _PADDING5_[0x8];
	/*0x4A00*/     union _SLIST_HEADER InterruptObjectPool;                            // 5 elements, 0x10 bytes (sizeof)
	/*0x4A10*/     union _SLIST_HEADER HypercallPageList;                              // 5 elements, 0x10 bytes (sizeof)
	/*0x4A20*/     VOID*        HypercallPageVirtual;
	/*0x4A28*/     VOID*        VirtualApicAssist;
	/*0x4A30*/     UINT64*      StatisticsPage;
	/*0x4A38*/     VOID*        RateControl;
	/*0x4A40*/     UINT64       CacheProcessorMask[5];
	/*0x4A68*/     struct _KAFFINITY_EX PackageProcessorSet;                           // 4 elements, 0x28 bytes (sizeof)
	/*0x4A90*/     UINT64       CoreProcessorSet;
	/*0x4A98*/     VOID*        PebsIndexAddress;
	/*0x4AA0*/     UINT64       PrcbPad93[12];
	/*0x4B00*/     ULONG32      SpinLockAcquireCount;
	/*0x4B04*/     ULONG32      SpinLockContentionCount;
	/*0x4B08*/     ULONG32      SpinLockSpinCount;
	/*0x4B0C*/     ULONG32      IpiSendRequestBroadcastCount;
	/*0x4B10*/     ULONG32      IpiSendRequestRoutineCount;
	/*0x4B14*/     ULONG32      IpiSendSoftwareInterruptCount;
	/*0x4B18*/     ULONG32      ExInitializeResourceCount;
	/*0x4B1C*/     ULONG32      ExReInitializeResourceCount;
	/*0x4B20*/     ULONG32      ExDeleteResourceCount;
	/*0x4B24*/     ULONG32      ExecutiveResourceAcquiresCount;
	/*0x4B28*/     ULONG32      ExecutiveResourceContentionsCount;
	/*0x4B2C*/     ULONG32      ExecutiveResourceReleaseExclusiveCount;
	/*0x4B30*/     ULONG32      ExecutiveResourceReleaseSharedCount;
	/*0x4B34*/     ULONG32      ExecutiveResourceConvertsCount;
	/*0x4B38*/     ULONG32      ExAcqResExclusiveAttempts;
	/*0x4B3C*/     ULONG32      ExAcqResExclusiveAcquiresExclusive;
	/*0x4B40*/     ULONG32      ExAcqResExclusiveAcquiresExclusiveRecursive;
	/*0x4B44*/     ULONG32      ExAcqResExclusiveWaits;
	/*0x4B48*/     ULONG32      ExAcqResExclusiveNotAcquires;
	/*0x4B4C*/     ULONG32      ExAcqResSharedAttempts;
	/*0x4B50*/     ULONG32      ExAcqResSharedAcquiresExclusive;
	/*0x4B54*/     ULONG32      ExAcqResSharedAcquiresShared;
	/*0x4B58*/     ULONG32      ExAcqResSharedAcquiresSharedRecursive;
	/*0x4B5C*/     ULONG32      ExAcqResSharedWaits;
	/*0x4B60*/     ULONG32      ExAcqResSharedNotAcquires;
	/*0x4B64*/     ULONG32      ExAcqResSharedStarveExclusiveAttempts;
	/*0x4B68*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresExclusive;
	/*0x4B6C*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresShared;
	/*0x4B70*/     ULONG32      ExAcqResSharedStarveExclusiveAcquiresSharedRecursive;
	/*0x4B74*/     ULONG32      ExAcqResSharedStarveExclusiveWaits;
	/*0x4B78*/     ULONG32      ExAcqResSharedStarveExclusiveNotAcquires;
	/*0x4B7C*/     ULONG32      ExAcqResSharedWaitForExclusiveAttempts;
	/*0x4B80*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresExclusive;
	/*0x4B84*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresShared;
	/*0x4B88*/     ULONG32      ExAcqResSharedWaitForExclusiveAcquiresSharedRecursive;
	/*0x4B8C*/     ULONG32      ExAcqResSharedWaitForExclusiveWaits;
	/*0x4B90*/     ULONG32      ExAcqResSharedWaitForExclusiveNotAcquires;
	/*0x4B94*/     ULONG32      ExSetResOwnerPointerExclusive;
	/*0x4B98*/     ULONG32      ExSetResOwnerPointerSharedNew;
	/*0x4B9C*/     ULONG32      ExSetResOwnerPointerSharedOld;
	/*0x4BA0*/     ULONG32      ExTryToAcqExclusiveAttempts;
	/*0x4BA4*/     ULONG32      ExTryToAcqExclusiveAcquires;
	/*0x4BA8*/     ULONG32      ExBoostExclusiveOwner;
	/*0x4BAC*/     ULONG32      ExBoostSharedOwners;
	/*0x4BB0*/     ULONG32      ExEtwSynchTrackingNotificationsCount;
	/*0x4BB4*/     ULONG32      ExEtwSynchTrackingNotificationsAccountedCount;
	/*0x4BB8*/     UINT8        VendorString[13];
	/*0x4BC5*/     UINT8        PrcbPad10[3];
	/*0x4BC8*/     ULONG32      FeatureBits;
	/*0x4BCC*/     UINT8        _PADDING6_[0x4];
	/*0x4BD0*/     union _LARGE_INTEGER UpdateSignature;                               // 4 elements, 0x8 bytes (sizeof)
	/*0x4BD8*/     struct _CONTEXT* Context;
	/*0x4BE0*/     ULONG32      ContextFlags;
	/*0x4BE4*/     UINT8        _PADDING7_[0x4];
	/*0x4BE8*/     struct _XSAVE_AREA* ExtendedState;
	/*0x4BF0*/     UINT8        _PADDING8_[0x10];
	/*0x4C00*/     struct _REQUEST_MAILBOX* Mailbox;
	/*0x4C08*/     UINT8        _PADDING9_[0x78];
	/*0x4C80*/     struct _REQUEST_MAILBOX RequestMailbox[1];
	/*0x4CC0*/     UINT8        _PADDING10_[0x40];
}KPRCB, *PKPRCB;
typedef struct _COUNTER_READING       // 4 elements, 0x18 bytes (sizeof)
{
	/*0x000*/     enum _HARDWARE_COUNTER_TYPE Type;
	/*0x004*/     ULONG32      Index;
	/*0x008*/     UINT64       Start;
	/*0x010*/     UINT64       Total;
}COUNTER_READING, *PCOUNTER_READING;
typedef struct _THREAD_PERFORMANCE_DATA       // 10 elements, 0x1C0 bytes (sizeof)
{
	/*0x000*/     UINT16       Size;
	/*0x002*/     UINT16       Version;
	/*0x004*/     struct _PROCESSOR_NUMBER ProcessorNumber; // 3 elements, 0x4 bytes (sizeof)
	/*0x008*/     ULONG32      ContextSwitches;
	/*0x00C*/     ULONG32      HwCountersCount;
	/*0x010*/     UINT64       UpdateCount;
	/*0x018*/     UINT64       WaitReasonBitMap;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     struct _COUNTER_READING CycleTime;        // 4 elements, 0x18 bytes (sizeof)
	/*0x040*/     struct _COUNTER_READING HwCounters[16];
}THREAD_PERFORMANCE_DATA, *PTHREAD_PERFORMANCE_DATA;
typedef struct _KTHREAD_COUNTERS               // 7 elements, 0x1A8 bytes (sizeof)
{
	/*0x000*/     UINT64       WaitReasonBitMap;
	/*0x008*/     struct _THREAD_PERFORMANCE_DATA* UserData;
	/*0x010*/     ULONG32      Flags;
	/*0x014*/     ULONG32      ContextSwitches;
	/*0x018*/     UINT64       CycleTimeBias;
	/*0x020*/     UINT64       HardwareCounters;
	/*0x028*/     struct _COUNTER_READING HwCounter[16];
}KTHREAD_COUNTERS, *PKTHREAD_COUNTERS;


/*
typedef struct __XSAVE_FORMAT{
	WORD	 ControlWord;//     : Uint2B
	WORD	 StatusWord;// : Uint2B
	UCHAR	 TagWord;// : UChar
	UCHAR Reserved1; //: UChar
	WORD ErrorOpcode;// : Uint2B
	DWORD ErrorOffset;// : Uint4B
	WORD ErrorSelector;// : Uint2B
	WORD Reserved2;// : Uint2B
	DWORD DataOffset;// : Uint4B
	WORD DataSelector;// : Uint2B
	WORD	 Reserved3;// : Uint2B
	DWORD	MxCsr;// : Uint4B
	DWORD MxCsr_Mask;// : Uint4B
	M128A FloatRegisters[8];// : [8] _M128A
	M128A	 XmmRegisters[16];// _M128A
	UCHAR Reserved4[96];// UChar



}KXSAVE_FORMAT, *KPXSAVE_FORMAT;*/
typedef struct _KTHREAD                                 // 126 elements, 0x360 bytes (sizeof)
{
	/*0x000*/     struct _DISPATCHER_HEADER Header;                   // 29 elements, 0x18 bytes (sizeof)
	/*0x018*/     UINT64       CycleTime;
	/*0x020*/     UINT64       QuantumTarget;
	/*0x028*/     VOID*        InitialStack;
	/*0x030*/     VOID*        StackLimit;
	/*0x038*/     VOID*        KernelStack;
	/*0x040*/     UINT64       ThreadLock;
	/*0x048*/     CHAR WaitRegister;          // 8 elements, 0x1 bytes (sizeof)
	/*0x049*/     UINT8        Running;
	/*0x04A*/     UINT8        Alerted[2];
	union                                               // 2 elements, 0x4 bytes (sizeof)
	{
		struct                                          // 14 elements, 0x4 bytes (sizeof)
		{
			/*0x04C*/             ULONG32      KernelStackResident : 1;       // 0 BitPosition
			/*0x04C*/             ULONG32      ReadyTransition : 1;           // 1 BitPosition
			/*0x04C*/             ULONG32      ProcessReadyQueue : 1;         // 2 BitPosition
			/*0x04C*/             ULONG32      WaitNext : 1;                  // 3 BitPosition
			/*0x04C*/             ULONG32      SystemAffinityActive : 1;      // 4 BitPosition
			/*0x04C*/             ULONG32      Alertable : 1;                 // 5 BitPosition
			/*0x04C*/             ULONG32      GdiFlushActive : 1;            // 6 BitPosition
			/*0x04C*/             ULONG32      UserStackWalkActive : 1;       // 7 BitPosition
			/*0x04C*/             ULONG32      ApcInterruptRequest : 1;       // 8 BitPosition
			/*0x04C*/             ULONG32      ForceDeferSchedule : 1;        // 9 BitPosition
			/*0x04C*/             ULONG32      QuantumEndMigrate : 1;         // 10 BitPosition
			/*0x04C*/             ULONG32      UmsDirectedSwitchEnable : 1;   // 11 BitPosition
			/*0x04C*/             ULONG32      TimerActive : 1;               // 12 BitPosition
			/*0x04C*/             ULONG32      Reserved : 19;                 // 13 BitPosition
		};
		/*0x04C*/         LONG32       MiscFlags;
	};
	union                                               // 2 elements, 0x30 bytes (sizeof)
	{
		/*0x050*/         struct _KAPC_STATE ApcState;                    // 5 elements, 0x30 bytes (sizeof)
		struct                                          // 3 elements, 0x30 bytes (sizeof)
		{
			/*0x050*/             UINT8        ApcStateFill[43];
			/*0x07B*/             CHAR         Priority;
			/*0x07C*/             ULONG32      NextProcessor;
		};
	};
	/*0x080*/     ULONG32      DeferredProcessor;
	/*0x084*/     UINT8        _PADDING0_[0x4];
	/*0x088*/     UINT64       ApcQueueLock;
	/*0x090*/     INT64        WaitStatus;
	/*0x098*/     struct _KWAIT_BLOCK* WaitBlockList;
	union                                               // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x0A0*/         struct _LIST_ENTRY WaitListEntry;               // 2 elements, 0x10 bytes (sizeof)
		/*0x0A0*/         struct _SINGLE_LIST_ENTRY SwapListEntry;        // 1 elements, 0x8 bytes (sizeof)
	};
	/*0x0B0*/     struct _KQUEUE* Queue;
	/*0x0B8*/     VOID*        Teb;
	/*0x0C0*/     struct _KTIMER Timer;                               // 6 elements, 0x40 bytes (sizeof)
	union                                               // 2 elements, 0x4 bytes (sizeof)
	{
		struct                                          // 10 elements, 0x4 bytes (sizeof)
		{
			/*0x100*/             ULONG32      AutoAlignment : 1;             // 0 BitPosition
			/*0x100*/             ULONG32      DisableBoost : 1;              // 1 BitPosition
			/*0x100*/             ULONG32      EtwStackTraceApc1Inserted : 1; // 2 BitPosition
			/*0x100*/             ULONG32      EtwStackTraceApc2Inserted : 1; // 3 BitPosition
			/*0x100*/             ULONG32      CalloutActive : 1;             // 4 BitPosition
			/*0x100*/             ULONG32      ApcQueueable : 1;              // 5 BitPosition
			/*0x100*/             ULONG32      EnableStackSwap : 1;           // 6 BitPosition
			/*0x100*/             ULONG32      GuiThread : 1;                 // 7 BitPosition
			/*0x100*/             ULONG32      UmsPerformingSyscall : 1;      // 8 BitPosition
			/*0x100*/             ULONG32      ReservedFlags : 23;            // 9 BitPosition
		};
		/*0x100*/         LONG32       ThreadFlags;
	};
	/*0x104*/     ULONG32      Spare0;
	union                                               // 6 elements, 0xC0 bytes (sizeof)
	{
		/*0x108*/         struct _KWAIT_BLOCK WaitBlock[4];
		struct                                          // 2 elements, 0xC0 bytes (sizeof)
		{
			/*0x108*/             UINT8        WaitBlockFill4[44];
			/*0x134*/             ULONG32      ContextSwitches;
			/*0x138*/             UINT8        _PADDING1_[0x90];
		};
		struct                                          // 5 elements, 0xC0 bytes (sizeof)
		{
			/*0x108*/             UINT8        WaitBlockFill5[92];
			/*0x164*/             UINT8        State;
			/*0x165*/             CHAR         NpxState;
			/*0x166*/             UINT8        WaitIrql;
			/*0x167*/             CHAR         WaitMode;
			/*0x168*/             UINT8        _PADDING2_[0x60];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)
		{
			/*0x108*/             UINT8        WaitBlockFill6[140];
			/*0x194*/             ULONG32      WaitTime;
			/*0x198*/             UINT8        _PADDING3_[0x30];
		};
		struct                                          // 3 elements, 0xC0 bytes (sizeof)
		{
			/*0x108*/             UINT8        WaitBlockFill7[168];
			/*0x1B0*/             VOID*        TebMappedLowVa;
			/*0x1B8*/             struct _UMS_CONTROL_BLOCK* Ucb;
			/*0x1C0*/             UINT8        _PADDING4_[0x8];
		};
		struct                                          // 2 elements, 0xC0 bytes (sizeof)
		{
			/*0x108*/             UINT8        WaitBlockFill8[188];
			union                                       // 2 elements, 0x4 bytes (sizeof)
			{
				struct                                  // 2 elements, 0x4 bytes (sizeof)
				{
					/*0x1C4*/                     INT16        KernelApcDisable;
					/*0x1C6*/                     INT16        SpecialApcDisable;
				};
				/*0x1C4*/                 ULONG32      CombinedApcDisable;
			};
		};
	};
	/*0x1C8*/     struct _LIST_ENTRY QueueListEntry;                  // 2 elements, 0x10 bytes (sizeof)
	/*0x1D8*/     struct _KTRAP_FRAME* TrapFrame;
	/*0x1E0*/     VOID*        FirstArgument;
	union                                               // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x1E8*/         VOID*        CallbackStack;
		/*0x1E8*/         UINT64       CallbackDepth;
	};
	/*0x1F0*/     UINT8        ApcStateIndex;
	/*0x1F1*/     CHAR         BasePriority;
	union                                               // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x1F2*/         CHAR         PriorityDecrement;
		struct                                          // 2 elements, 0x1 bytes (sizeof)
		{
			/*0x1F2*/             UINT8        ForegroundBoost : 4;           // 0 BitPosition
			/*0x1F2*/             UINT8        UnusualBoost : 4;              // 4 BitPosition
		};
	};
	/*0x1F3*/     UINT8        Preempted;
	/*0x1F4*/     UINT8        AdjustReason;
	/*0x1F5*/     CHAR         AdjustIncrement;
	/*0x1F6*/     CHAR         PreviousMode;
	/*0x1F7*/     CHAR         Saturation;
	/*0x1F8*/     ULONG32      SystemCallNumber;
	/*0x1FC*/     ULONG32      FreezeCount;
	/*0x200*/     struct _GROUP_AFFINITY UserAffinity;                // 3 elements, 0x10 bytes (sizeof)
	/*0x210*/     struct _KPROCESS* Process;
	/*0x218*/     struct _GROUP_AFFINITY Affinity;                    // 3 elements, 0x10 bytes (sizeof)
	/*0x228*/     ULONG32      IdealProcessor;
	/*0x22C*/     ULONG32      UserIdealProcessor;
	/*0x230*/     struct _KAPC_STATE* ApcStatePointer[2];
	union                                               // 2 elements, 0x30 bytes (sizeof)
	{
		/*0x240*/         struct _KAPC_STATE SavedApcState;               // 5 elements, 0x30 bytes (sizeof)
		struct                                          // 5 elements, 0x30 bytes (sizeof)
		{
			/*0x240*/             UINT8        SavedApcStateFill[43];
			/*0x26B*/             UINT8        WaitReason;
			/*0x26C*/             CHAR         SuspendCount;
			/*0x26D*/             CHAR         Spare1;
			/*0x26E*/             UINT8        CodePatchInProgress;
			/*0x26F*/             UINT8        _PADDING5_[0x1];
		};
	};
	/*0x270*/     VOID*        Win32Thread;
	/*0x278*/     VOID*        StackBase;
	union                                               // 7 elements, 0x58 bytes (sizeof)
	{
		/*0x280*/         struct _KAPC SuspendApc;                        // 16 elements, 0x58 bytes (sizeof)
		struct                                          // 2 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill0[1];
			/*0x281*/             UINT8        ResourceIndex;
			/*0x282*/             UINT8        _PADDING6_[0x56];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill1[3];
			/*0x283*/             UINT8        QuantumReset;
			/*0x284*/             UINT8        _PADDING7_[0x54];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill2[4];
			/*0x284*/             ULONG32      KernelTime;
			/*0x288*/             UINT8        _PADDING8_[0x50];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill3[64];
			/*0x2C0*/             struct _KPRCB* WaitPrcb;
			/*0x2C8*/             UINT8        _PADDING9_[0x10];
		};
		struct                                          // 2 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill4[72];
			/*0x2C8*/             VOID*        LegoData;
			/*0x2D0*/             UINT8        _PADDING10_[0x8];
		};
		struct                                          // 3 elements, 0x58 bytes (sizeof)
		{
			/*0x280*/             UINT8        SuspendApcFill5[83];
			/*0x2D3*/             UINT8        LargeStack;
			/*0x2D4*/             ULONG32      UserTime;
		};
	};
	union                                               // 2 elements, 0x20 bytes (sizeof)
	{
		/*0x2D8*/         struct _KSEMAPHORE SuspendSemaphore;            // 2 elements, 0x20 bytes (sizeof)
		struct                                          // 2 elements, 0x20 bytes (sizeof)
		{
			/*0x2D8*/             UINT8        SuspendSemaphorefill[28];
			/*0x2F4*/             ULONG32      SListFaultCount;
		};
	};
	/*0x2F8*/     struct _LIST_ENTRY ThreadListEntry;                 // 2 elements, 0x10 bytes (sizeof)
	/*0x308*/     struct _LIST_ENTRY MutantListHead;                  // 2 elements, 0x10 bytes (sizeof)
	/*0x318*/     VOID*        SListFaultAddress;
	/*0x320*/     INT64        ReadOperationCount;
	/*0x328*/     INT64        WriteOperationCount;
	/*0x330*/     INT64        OtherOperationCount;
	/*0x338*/     INT64        ReadTransferCount;
	/*0x340*/     INT64        WriteTransferCount;
	/*0x348*/     INT64        OtherTransferCount;
	/*0x350*/     struct _KTHREAD_COUNTERS* ThreadCounters;
	/*0x358*/          struct _XSAVE_FORMAT* StateSaveArea;
	/*0x360*/     struct _XSTATE_SAVE* XStateSave;
}KTHREAD, *PKTHREAD;
typedef struct _TERMINATION_PORT    // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     struct _TERMINATION_PORT* Next;
	/*0x008*/     VOID*        Port;
}TERMINATION_PORT, *PTERMINATION_PORT;
typedef struct _ETHREAD                                              // 88 elements, 0x498 bytes (sizeof)
{
	/*0x000*/     struct _KTHREAD Tcb;                                             // 126 elements, 0x360 bytes (sizeof)
	/*0x360*/     union _LARGE_INTEGER CreateTime;                                 // 4 elements, 0x8 bytes (sizeof)
	union                                                            // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x368*/         union _LARGE_INTEGER ExitTime;                               // 4 elements, 0x8 bytes (sizeof)
		/*0x368*/         struct _LIST_ENTRY KeyedWaitChain;                           // 2 elements, 0x10 bytes (sizeof)
	};
	/*0x378*/     LONG32       ExitStatus;
	/*0x37C*/     UINT8        _PADDING0_[0x4];
	union                                                            // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x380*/         struct _LIST_ENTRY PostBlockList;                            // 2 elements, 0x10 bytes (sizeof)
		struct                                                       // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x380*/             VOID*        ForwardLinkShadow;
			/*0x388*/             VOID*        StartAddress;
		};
	};
	union                                                            // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x390*/         struct _TERMINATION_PORT* TerminationPort;
		/*0x390*/         struct _ETHREAD* ReaperLink;
		/*0x390*/         VOID*        KeyedWaitValue;
	};
	/*0x398*/     UINT64       ActiveTimerListLock;
	/*0x3A0*/     struct _LIST_ENTRY ActiveTimerListHead;                          // 2 elements, 0x10 bytes (sizeof)
	//ULONG64 unknow;
	/*0x3B0*/     struct _CLIENT_ID Cid;                                           // 2 elements, 0x10 bytes (sizeof)
	union                                                            // 2 elements, 0x20 bytes (sizeof)
	{
		/*0x3C0*/         struct _KSEMAPHORE KeyedWaitSemaphore;                       // 2 elements, 0x20 bytes (sizeof)
		/*0x3C0*/         struct _KSEMAPHORE AlpcWaitSemaphore;                        // 2 elements, 0x20 bytes (sizeof)
	};
	/*0x3E0*/     ULONG64 ClientSecurity;                // 4 elements, 0x8 bytes (sizeof)
	/*0x3E8*/     struct _LIST_ENTRY IrpList;                                      // 2 elements, 0x10 bytes (sizeof)
	/*0x3F8*/     UINT64       TopLevelIrp;
	/*0x400*/     struct _DEVICE_OBJECT* DeviceToVerify;
	/*0x408*/     ULONG64 CpuQuotaApc;
	/*0x410*/     VOID*        Win32StartAddress;
	/*0x418*/     VOID*        LegacyPowerObject;
	/*0x420*/     struct _LIST_ENTRY ThreadListEntry;                              // 2 elements, 0x10 bytes (sizeof)
	/*0x430*/     struct _EX_RUNDOWN_REF RundownProtect;                           // 2 elements, 0x8 bytes (sizeof)
	/*0x438*/     struct _EX_PUSH_LOCK ThreadLock;                                 // 7 elements, 0x8 bytes (sizeof)
	/*0x440*/     ULONG32      ReadClusterSize;
	/*0x444*/     LONG32       MmLockOrdering;
	
	union                                                            // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x448*/         ULONG32      CrossThreadFlags;
		struct                                                       // 14 elements, 0x4 bytes (sizeof)
		{
			/*0x448*/             ULONG32      Terminated : 1;                             // 0 BitPosition
			/*0x448*/             ULONG32      ThreadInserted : 1;                         // 1 BitPosition
			/*0x448*/             ULONG32      HideFromDebugger : 1;                       // 2 BitPosition
			/*0x448*/             ULONG32      ActiveImpersonationInfo : 1;                // 3 BitPosition
			/*0x448*/             ULONG32      SystemThread : 1;                           // 4 BitPosition
			/*0x448*/             ULONG32      HardErrorsAreDisabled : 1;                  // 5 BitPosition
			/*0x448*/             ULONG32      BreakOnTermination : 1;                     // 6 BitPosition
			/*0x448*/             ULONG32      SkipCreationMsg : 1;                        // 7 BitPosition
			/*0x448*/             ULONG32      SkipTerminationMsg : 1;                     // 8 BitPosition
			/*0x448*/             ULONG32      CopyTokenOnOpen : 1;                        // 9 BitPosition
			/*0x448*/             ULONG32      ThreadIoPriority : 3;                       // 10 BitPosition
			/*0x448*/             ULONG32      ThreadPagePriority : 3;                     // 13 BitPosition
			/*0x448*/             ULONG32      RundownFail : 1;                            // 16 BitPosition
			/*0x448*/             ULONG32      NeedsWorkingSetAging : 1;                   // 17 BitPosition
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x44C*/         ULONG32      SameThreadPassiveFlags;
		struct                                                       // 7 elements, 0x4 bytes (sizeof)
		{
			/*0x44C*/             ULONG32      ActiveExWorker : 1;                         // 0 BitPosition
			/*0x44C*/             ULONG32      ExWorkerCanWaitUser : 1;                    // 1 BitPosition
			/*0x44C*/             ULONG32      MemoryMaker : 1;                            // 2 BitPosition
			/*0x44C*/             ULONG32      ClonedThread : 1;                           // 3 BitPosition
			/*0x44C*/             ULONG32      KeyedEventInUse : 1;                        // 4 BitPosition
			/*0x44C*/             ULONG32      RateApcState : 2;                           // 5 BitPosition
			/*0x44C*/             ULONG32      SelfTerminate : 1;                          // 7 BitPosition
		};
	};
	union                                                            // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x450*/         ULONG32      SameThreadApcFlags;
		struct                                                       // 4 elements, 0x4 bytes (sizeof)
		{
			struct                                                   // 8 elements, 0x1 bytes (sizeof)
			{
				/*0x450*/                 UINT8        Spare : 1;                              // 0 BitPosition
				/*0x450*/                 UINT8        StartAddressInvalid : 1;                // 1 BitPosition
				/*0x450*/                 UINT8        EtwPageFaultCalloutActive : 1;          // 2 BitPosition
				/*0x450*/                 UINT8        OwnsProcessWorkingSetExclusive : 1;     // 3 BitPosition
				/*0x450*/                 UINT8        OwnsProcessWorkingSetShared : 1;        // 4 BitPosition
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetExclusive : 1; // 5 BitPosition
				/*0x450*/                 UINT8        OwnsSystemCacheWorkingSetShared : 1;    // 6 BitPosition
				/*0x450*/                 UINT8        OwnsSessionWorkingSetExclusive : 1;     // 7 BitPosition
			};
			struct                                                   // 8 elements, 0x1 bytes (sizeof)
			{
				/*0x451*/                 UINT8        OwnsSessionWorkingSetShared : 1;        // 0 BitPosition
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceExclusive : 1;   // 1 BitPosition
				/*0x451*/                 UINT8        OwnsProcessAddressSpaceShared : 1;      // 2 BitPosition
				/*0x451*/                 UINT8        SuppressSymbolLoad : 1;                 // 3 BitPosition
				/*0x451*/                 UINT8        Prefetching : 1;                        // 4 BitPosition
				/*0x451*/                 UINT8        OwnsDynamicMemoryShared : 1;            // 5 BitPosition
				/*0x451*/                 UINT8        OwnsChangeControlAreaExclusive : 1;     // 6 BitPosition
				/*0x451*/                 UINT8        OwnsChangeControlAreaShared : 1;        // 7 BitPosition
			};
			struct                                                   // 6 elements, 0x1 bytes (sizeof)
			{
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetExclusive : 1;   // 0 BitPosition
				/*0x452*/                 UINT8        OwnsPagedPoolWorkingSetShared : 1;      // 1 BitPosition
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetExclusive : 1;  // 2 BitPosition
				/*0x452*/                 UINT8        OwnsSystemPtesWorkingSetShared : 1;     // 3 BitPosition
				/*0x452*/                 UINT8        TrimTrigger : 2;                        // 4 BitPosition
				/*0x452*/                 UINT8        Spare1 : 2;                             // 6 BitPosition
			};
			/*0x453*/             UINT8        PriorityRegionActive;
		};
	};
	/*0x454*/     UINT8        CacheManagerActive;
	/*0x455*/     UINT8        DisablePageFaultClustering;
	/*0x456*/     UINT8        ActiveFaultCount;
	/*0x457*/     UINT8        LockOrderState;
	/*0x458*/     UINT64       AlpcMessageId;
	union                                                            // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x460*/         VOID*        AlpcMessage;
		/*0x460*/         ULONG32      AlpcReceiveAttributeSet;
	};
	/*0x468*/     struct _LIST_ENTRY AlpcWaitListEntry;                            // 2 elements, 0x10 bytes (sizeof)
	/*0x478*/     ULONG32      CacheManagerCount;
	/*0x47C*/     ULONG32      IoBoostCount;
	/*0x480*/     UINT64       IrpListLock;
	/*0x488*/     VOID*        ReservedForSynchTracking;
	/*0x490*/     struct _SINGLE_LIST_ENTRY CmCallbackListHead;                    // 1 elements, 0x8 bytes (sizeof)
	
}ETHREAD, *PETHREAD;

typedef struct _LIST_ENTRY64_S // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       Flink;
	/*0x008*/     UINT64       Blink;
}LIST_ENTRY64_S, *PLIST_ENTRY64_S;

typedef struct _PEB                                      // 91 elements, 0x380 bytes (sizeof)
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                  // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x003*/         UINT8        BitField;
		struct                                             // 6 elements, 0x1 bytes (sizeof)
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;              // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                    // 5 BitPosition
		};
	};
	/*0x008*/     UINT64       Mutant;
	/*0x010*/     UINT64       ImageBaseAddress;
	/*0x018*/     UINT64       Ldr;
	/*0x020*/     UINT64       ProcessParameters;
	/*0x028*/     UINT64       SubSystemData;
	/*0x030*/     UINT64       ProcessHeap;
	/*0x038*/     UINT64       FastPebLock;
	/*0x040*/     UINT64       AtlThunkSListPtr;
	/*0x048*/     UINT64       IFEOKey;
	union                                                  // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct                                             // 6 elements, 0x4 bytes (sizeof)
		{
			/*0x050*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition
			/*0x050*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition
			/*0x050*/             ULONG32      ReservedBits0 : 27;               // 5 BitPosition
		};
	};
	union                                                  // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x058*/         UINT64       KernelCallbackTable;
		/*0x058*/         UINT64       UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved[1];
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     UINT64       ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        _PADDING0_[0x4];
	/*0x078*/     UINT64       TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     UINT64       ReadOnlySharedMemoryBase;
	/*0x090*/     UINT64       HotpatchInformation;
	/*0x098*/     UINT64       ReadOnlyStaticServerData;
	/*0x0A0*/     UINT64       AnsiCodePageData;
	/*0x0A8*/     UINT64       OemCodePageData;
	/*0x0B0*/     UINT64       UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     UINT64       ProcessHeaps;
	/*0x0F8*/     UINT64       GdiSharedHandleTable;
	/*0x100*/     UINT64       ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        _PADDING1_[0x4];
	/*0x110*/     UINT64       LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        _PADDING2_[0x4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     UINT64       PostProcessInitRoutine;
	/*0x238*/     UINT64       TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        _PADDING3_[0x4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)
	/*0x2D8*/     UINT64       pShimData;
	/*0x2E0*/     UINT64       AppCompatInfo;
	/*0x2E8*/     struct _STRING64 CSDVersion;                           // 3 elements, 0x10 bytes (sizeof)
	/*0x2F8*/     UINT64       ActivationContextData;
	/*0x300*/     UINT64       ProcessAssemblyStorageMap;
	/*0x308*/     UINT64       SystemDefaultActivationContextData;
	/*0x310*/     UINT64       SystemAssemblyStorageMap;
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     UINT64       FlsCallback;
	/*0x328*/     struct _LIST_ENTRY64_S FlsListHead;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x338*/     UINT64       FlsBitmap;
	/*0x340*/     ULONG32      FlsBitmapBits[4];
	/*0x350*/     ULONG32      FlsHighIndex;
	/*0x354*/     UINT8        _PADDING4_[0x4];
	/*0x358*/     UINT64       WerRegistrationData;
	/*0x360*/     UINT64       WerShipAssertPtr;
	/*0x368*/     UINT64       pContextData;
	/*0x370*/     UINT64       pImageHeaderHash;
	union                                                  // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x378*/         ULONG32      TracingFlags;
		struct                                             // 3 elements, 0x4 bytes (sizeof)
		{
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition
			/*0x378*/             ULONG32      SpareTracingBits : 30;            // 2 BitPosition
		};
	};
}PEB, *PPEB;
typedef struct _EPROCESS_S                                               // 135 elements, 0x4D0 bytes (sizeof)
{
	/*0x000*/     struct _KPROCESS Pcb;                                              // 37 elements, 0x160 bytes (sizeof)
	/*0x160*/     struct _EX_PUSH_LOCK ProcessLock;                                  // 7 elements, 0x8 bytes (sizeof)
	/*0x168*/     union _LARGE_INTEGER CreateTime;                                   // 4 elements, 0x8 bytes (sizeof)
	/*0x170*/     union _LARGE_INTEGER ExitTime;                                     // 4 elements, 0x8 bytes (sizeof)
	/*0x178*/     struct _EX_RUNDOWN_REF RundownProtect;                             // 2 elements, 0x8 bytes (sizeof)
	/*0x180*/     VOID*        UniqueProcessId;
	/*0x188*/     struct _LIST_ENTRY ActiveProcessLinks;                             // 2 elements, 0x10 bytes (sizeof)
	/*0x198*/     UINT64       ProcessQuotaUsage[2];
	/*0x1A8*/     UINT64       ProcessQuotaPeak[2];
	/*0x1B8*/     UINT64       CommitCharge;
	/*0x1C0*/     ULONG64 QuotaBlock;
	/*0x1C8*/     struct _PS_CPU_QUOTA_BLOCK* CpuQuotaBlock;
	/*0x1D0*/     UINT64       PeakVirtualSize;
	/*0x1D8*/     UINT64       VirtualSize;
	/*0x1E0*/     struct _LIST_ENTRY SessionProcessLinks;                            // 2 elements, 0x10 bytes (sizeof)
	/*0x1F0*/     VOID*        DebugPort;
	union                                                              // 3 elements, 0x8 bytes (sizeof)
	{
		/*0x1F8*/         VOID*        ExceptionPortData;
		/*0x1F8*/         UINT64       ExceptionPortValue;
		/*0x1F8*/         UINT64       ExceptionPortState : 3;                           // 0 BitPosition
	};
	/*0x200*/    ULONG64 ObjectTable;
	/*0x208*/     struct _EX_FAST_REF Token;                                         // 3 elements, 0x8 bytes (sizeof)
	/*0x210*/     UINT64       WorkingSetPage;
	/*0x218*/     struct _EX_PUSH_LOCK AddressCreationLock;                          // 7 elements, 0x8 bytes (sizeof)
	/*0x220*/     struct _ETHREAD* RotateInProgress;
	/*0x228*/     struct _ETHREAD* ForkInProgress;
	/*0x230*/     UINT64       HardwareTrigger;
	/*0x238*/     struct _MM_AVL_TABLE* PhysicalVadRoot;
	/*0x240*/     VOID*        CloneRoot;
	/*0x248*/     UINT64       NumberOfPrivatePages;
	/*0x250*/     UINT64       NumberOfLockedPages;
	/*0x258*/     VOID*        Win32Process;
	/*0x260*/     struct _EJOB* Job;
	/*0x268*/     VOID*        SectionObject;
	/*0x270*/     VOID*        SectionBaseAddress;
	/*0x278*/     ULONG32      Cookie;
	/*0x27C*/     ULONG32      UmsScheduledThreads;
	/*0x280*/    ULONG64 WorkingSetWatch;
	/*0x288*/     VOID*        Win32WindowStation;
	/*0x290*/     VOID*        InheritedFromUniqueProcessId;
	/*0x298*/     VOID*        LdtInformation;
	/*0x2A0*/     VOID*        Spare;
	/*0x2A8*/     UINT64       ConsoleHostProcess;
	/*0x2B0*/     VOID*        DeviceMap;
	/*0x2B8*/     VOID*        EtwDataSource;
	/*0x2C0*/     VOID*        FreeTebHint;
	
	union                                                              // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x2D0*/         struct _HARDWARE_PTE PageDirectoryPte;                         // 16 elements, 0x8 bytes (sizeof)
		/*0x2D0*/         UINT64       Filler;
	};

	ULONG32 unknow;
	ULONG32 unknow1;
	/*0x2D8*/     VOID*        Session;
	/*0x2E0*/     UINT8        ImageFileName[15];
	/*0x2EF*/     UINT8        PriorityClass;
	/*0x2F0*/     struct _LIST_ENTRY JobLinks;                                       // 2 elements, 0x10 bytes (sizeof)
	/*0x300*/     VOID*        LockedPagesList;
	/*0x308*/     struct _LIST_ENTRY ThreadListHead;                                 // 2 elements, 0x10 bytes (sizeof)
	/*0x318*/     VOID*        SecurityPort;
	/*0x320*/     VOID*        Wow64Process;
	/*0x328*/     ULONG32      ActiveThreads;
	/*0x32C*/     ULONG32      ImagePathHash;
	/*0x330*/     ULONG32      DefaultHardErrorProcessing;
	/*0x334*/     LONG32       LastThreadExitStatus;
	/*0x338*/     struct _PEB* Peb;
	/*0x340*/     struct _EX_FAST_REF PrefetchTrace;                                 // 3 elements, 0x8 bytes (sizeof)
	/*0x348*/     union _LARGE_INTEGER ReadOperationCount;                           // 4 elements, 0x8 bytes (sizeof)
	/*0x350*/     union _LARGE_INTEGER WriteOperationCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x358*/     union _LARGE_INTEGER OtherOperationCount;                          // 4 elements, 0x8 bytes (sizeof)
	/*0x360*/     union _LARGE_INTEGER ReadTransferCount;                            // 4 elements, 0x8 bytes (sizeof)
	/*0x368*/     union _LARGE_INTEGER WriteTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
	/*0x370*/     union _LARGE_INTEGER OtherTransferCount;                           // 4 elements, 0x8 bytes (sizeof)
	/*0x378*/     UINT64       CommitChargeLimit;
	/*0x380*/     UINT64       CommitChargePeak;
	/*0x388*/     VOID*        AweInfo;
	/*0x390*/     struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo; // 1 elements, 0x8 bytes (sizeof)
	/*0x398*/     struct _MMSUPPORT Vm;                                              // 21 elements, 0x88 bytes (sizeof)
	/*0x420*/     struct _LIST_ENTRY MmProcessLinks;                                 // 2 elements, 0x10 bytes (sizeof)
	/*0x430*/     VOID*        HighestUserAddress;
	/*0x438*/     ULONG32      ModifiedPageCount;
	
	union                                                              // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x43C*/         ULONG32      Flags2;
		struct                                                         // 20 elements, 0x4 bytes (sizeof)
		{
			/*0x43C*/             ULONG32      JobNotReallyActive : 1;                       // 0 BitPosition
			/*0x43C*/             ULONG32      AccountingFolded : 1;                         // 1 BitPosition
			/*0x43C*/             ULONG32      NewProcessReported : 1;                       // 2 BitPosition
			/*0x43C*/             ULONG32      ExitProcessReported : 1;                      // 3 BitPosition
			/*0x43C*/             ULONG32      ReportCommitChanges : 1;                      // 4 BitPosition
			/*0x43C*/             ULONG32      LastReportMemory : 1;                         // 5 BitPosition
			/*0x43C*/             ULONG32      ReportPhysicalPageChanges : 1;                // 6 BitPosition
			/*0x43C*/             ULONG32      HandleTableRundown : 1;                       // 7 BitPosition
			/*0x43C*/             ULONG32      NeedsHandleRundown : 1;                       // 8 BitPosition
			/*0x43C*/             ULONG32      RefTraceEnabled : 1;                          // 9 BitPosition
			/*0x43C*/             ULONG32      NumaAware : 1;                                // 10 BitPosition
			/*0x43C*/             ULONG32      ProtectedProcess : 1;                         // 11 BitPosition
			/*0x43C*/             ULONG32      DefaultPagePriority : 3;                      // 12 BitPosition
			/*0x43C*/             ULONG32      PrimaryTokenFrozen : 1;                       // 15 BitPosition
			/*0x43C*/             ULONG32      ProcessVerifierTarget : 1;                    // 16 BitPosition
			/*0x43C*/             ULONG32      StackRandomizationDisabled : 1;               // 17 BitPosition
			/*0x43C*/             ULONG32      AffinityPermanent : 1;                        // 18 BitPosition
			/*0x43C*/             ULONG32      AffinityUpdateEnable : 1;                     // 19 BitPosition
			/*0x43C*/             ULONG32      PropagateNode : 1;                            // 20 BitPosition
			/*0x43C*/             ULONG32      ExplicitAffinity : 1;                         // 21 BitPosition
		};
	};
	union                                                              // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x440*/         ULONG32      Flags;
		struct                                                         // 29 elements, 0x4 bytes (sizeof)
		{
			/*0x440*/             ULONG32      CreateReported : 1;                           // 0 BitPosition
			/*0x440*/             ULONG32      NoDebugInherit : 1;                           // 1 BitPosition
			/*0x440*/             ULONG32      ProcessExiting : 1;                           // 2 BitPosition
			/*0x440*/             ULONG32      ProcessDelete : 1;                            // 3 BitPosition
			/*0x440*/             ULONG32      Wow64SplitPages : 1;                          // 4 BitPosition
			/*0x440*/             ULONG32      VmDeleted : 1;                                // 5 BitPosition
			/*0x440*/             ULONG32      OutswapEnabled : 1;                           // 6 BitPosition
			/*0x440*/             ULONG32      Outswapped : 1;                               // 7 BitPosition
			/*0x440*/             ULONG32      ForkFailed : 1;                               // 8 BitPosition
			/*0x440*/             ULONG32      Wow64VaSpace4Gb : 1;                          // 9 BitPosition
			/*0x440*/             ULONG32      AddressSpaceInitialized : 2;                  // 10 BitPosition
			/*0x440*/             ULONG32      SetTimerResolution : 1;                       // 12 BitPosition
			/*0x440*/             ULONG32      BreakOnTermination : 1;                       // 13 BitPosition
			/*0x440*/             ULONG32      DeprioritizeViews : 1;                        // 14 BitPosition
			/*0x440*/             ULONG32      WriteWatch : 1;                               // 15 BitPosition
			/*0x440*/             ULONG32      ProcessInSession : 1;                         // 16 BitPosition
			/*0x440*/             ULONG32      OverrideAddressSpace : 1;                     // 17 BitPosition
			/*0x440*/             ULONG32      HasAddressSpace : 1;                          // 18 BitPosition
			/*0x440*/             ULONG32      LaunchPrefetched : 1;                         // 19 BitPosition
			/*0x440*/             ULONG32      InjectInpageErrors : 1;                       // 20 BitPosition
			/*0x440*/             ULONG32      VmTopDown : 1;                                // 21 BitPosition
			/*0x440*/             ULONG32      ImageNotifyDone : 1;                          // 22 BitPosition
			/*0x440*/             ULONG32      PdeUpdateNeeded : 1;                          // 23 BitPosition
			/*0x440*/             ULONG32      VdmAllowed : 1;                               // 24 BitPosition
			/*0x440*/             ULONG32      CrossSessionCreate : 1;                       // 25 BitPosition
			/*0x440*/             ULONG32      ProcessInserted : 1;                          // 26 BitPosition
			/*0x440*/             ULONG32      DefaultIoPriority : 3;                        // 27 BitPosition
			/*0x440*/             ULONG32      ProcessSelfDelete : 1;                        // 30 BitPosition
			/*0x440*/             ULONG32      SetTimerResolutionLink : 1;                   // 31 BitPosition
		};
	};
	/*0x444*/     LONG32       ExitStatus;
	/*0x448*/     struct _MM_AVL_TABLE VadRoot;                                      // 6 elements, 0x40 bytes (sizeof)
	/*0x488*/     struct _ALPC_PROCESS_CONTEXT AlpcContext;                          // 3 elements, 0x20 bytes (sizeof)
	/*0x4A8*/     struct _LIST_ENTRY TimerResolutionLink;                            // 2 elements, 0x10 bytes (sizeof)
	/*0x4B8*/     ULONG32      RequestedTimerResolution;
	/*0x4BC*/     ULONG32      ActiveThreadsHighWatermark;
	/*0x4C0*/     ULONG32      SmallestTimerResolution;

	/*0x4C8*/     struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;
}EPROCESS_S, *PEPROCESS_S;
typedef struct _PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof)
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID*        SsHandle;
	/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof)
	/*0x040*/     VOID*        EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID*        ShutdownThreadId;
}PEB_LDR_DATA, *PPEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY                         // 24 elements, 0xE0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     VOID*        DllBase;
	/*0x038*/     VOID*        EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
		struct                                               // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x070*/             VOID*        SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union                                                    // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID*        LoadedImports;
	};
	/*0x088*/     ULONG64 EntryPointActivationContext;
	/*0x090*/     VOID*        PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
	/*0x0C8*/     VOID*        ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _CLIENT_ID64     // 2 elements, 0x10 bytes (sizeof)
{
	/*0x000*/     UINT64       UniqueProcess;
	/*0x008*/     UINT64       UniqueThread;
}CLIENT_ID64, *PCLIENT_ID64;
typedef struct _GDI_TEB_BATCH64   // 3 elements, 0x4E8 bytes (sizeof)
{
	/*0x000*/     ULONG32      Offset;
	/*0x004*/     UINT8        _PADDING0_[0x4];
	/*0x008*/     UINT64       HDC;
	/*0x010*/     ULONG32      Buffer[310];
}GDI_TEB_BATCH64, *PGDI_TEB_BATCH64;
typedef struct _TEB64                                   // 101 elements, 0x1818 bytes (sizeof)
{
	/*0x000*/      struct _NT_TIB64 NtTib;                             // 8 elements, 0x38 bytes (sizeof)
	/*0x038*/      UINT64       EnvironmentPointer;
	/*0x040*/      struct _CLIENT_ID64 ClientId;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x050*/      UINT64       ActiveRpcHandle;
	/*0x058*/      UINT64       ThreadLocalStoragePointer;
	/*0x060*/      UINT64       ProcessEnvironmentBlock;
	/*0x068*/      ULONG32      LastErrorValue;
	/*0x06C*/      ULONG32      CountOfOwnedCriticalSections;
	/*0x070*/      UINT64       CsrClientThread;
	/*0x078*/      UINT64       Win32ThreadInfo;
	/*0x080*/      ULONG32      User32Reserved[26];
	/*0x0E8*/      ULONG32      UserReserved[5];
	/*0x0FC*/      UINT8        _PADDING0_[0x4];
	/*0x100*/      UINT64       WOW32Reserved;
	/*0x108*/      ULONG32      CurrentLocale;
	/*0x10C*/      ULONG32      FpSoftwareStatusRegister;
	/*0x110*/      UINT64       SystemReserved1[54];
	/*0x2C0*/      LONG32       ExceptionCode;
	/*0x2C4*/      UINT8        _PADDING1_[0x4];
	/*0x2C8*/      UINT64       ActivationContextStackPointer;
	/*0x2D0*/      UINT8        SpareBytes[24];
	/*0x2E8*/      ULONG32      TxFsContext;
	/*0x2EC*/      UINT8        _PADDING2_[0x4];
	/*0x2F0*/      struct _GDI_TEB_BATCH64 GdiTebBatch;                // 3 elements, 0x4E8 bytes (sizeof)
	/*0x7D8*/      struct _CLIENT_ID64 RealClientId;                   // 2 elements, 0x10 bytes (sizeof)
	/*0x7E8*/      UINT64       GdiCachedProcessHandle;
	/*0x7F0*/      ULONG32      GdiClientPID;
	/*0x7F4*/      ULONG32      GdiClientTID;
	/*0x7F8*/      UINT64       GdiThreadLocalInfo;
	/*0x800*/      UINT64       Win32ClientInfo[62];
	/*0x9F0*/      UINT64       glDispatchTable[233];
	/*0x1138*/     UINT64       glReserved1[29];
	/*0x1220*/     UINT64       glReserved2;
	/*0x1228*/     UINT64       glSectionInfo;
	/*0x1230*/     UINT64       glSection;
	/*0x1238*/     UINT64       glTable;
	/*0x1240*/     UINT64       glCurrentRC;
	/*0x1248*/     UINT64       glContext;
	/*0x1250*/     ULONG32      LastStatusValue;
	/*0x1254*/     UINT8        _PADDING3_[0x4];
	/*0x1258*/     struct _STRING64 StaticUnicodeString;               // 3 elements, 0x10 bytes (sizeof)
	/*0x1268*/     WCHAR        StaticUnicodeBuffer[261];
	/*0x1472*/     UINT8        _PADDING4_[0x6];
	/*0x1478*/     UINT64       DeallocationStack;
	/*0x1480*/     UINT64       TlsSlots[64];
	/*0x1680*/     struct _LIST_ENTRY TlsLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x1690*/     UINT64       Vdm;
	/*0x1698*/     UINT64       ReservedForNtRpc;
	/*0x16A0*/     UINT64       DbgSsReserved[2];
	/*0x16B0*/     ULONG32      HardErrorMode;
	/*0x16B4*/     UINT8        _PADDING5_[0x4];
	/*0x16B8*/     UINT64       Instrumentation[11];
	/*0x1710*/     struct _GUID ActivityId;                            // 4 elements, 0x10 bytes (sizeof)
	/*0x1720*/     UINT64       SubProcessTag;
	/*0x1728*/     UINT64       EtwLocalData;
	/*0x1730*/     UINT64       EtwTraceData;
	/*0x1738*/     UINT64       WinSockData;
	/*0x1740*/     ULONG32      GdiBatchCount;
	union                                               // 3 elements, 0x4 bytes (sizeof)
	{
		/*0x1744*/         struct _PROCESSOR_NUMBER CurrentIdealProcessor; // 3 elements, 0x4 bytes (sizeof)
		/*0x1744*/         ULONG32      IdealProcessorValue;
		struct                                          // 4 elements, 0x4 bytes (sizeof)
		{
			/*0x1744*/             UINT8        ReservedPad0;
			/*0x1745*/             UINT8        ReservedPad1;
			/*0x1746*/             UINT8        ReservedPad2;
			/*0x1747*/             UINT8        IdealProcessor;
		};
	};
	/*0x1748*/     ULONG32      GuaranteedStackBytes;
	/*0x174C*/     UINT8        _PADDING6_[0x4];
	/*0x1750*/     UINT64       ReservedForPerf;
	/*0x1758*/     UINT64       ReservedForOle;
	/*0x1760*/     ULONG32      WaitingOnLoaderLock;
	/*0x1764*/     UINT8        _PADDING7_[0x4];
	/*0x1768*/     UINT64       SavedPriorityState;
	/*0x1770*/     UINT64       SoftPatchPtr1;
	/*0x1778*/     UINT64       ThreadPoolData;
	/*0x1780*/     UINT64       TlsExpansionSlots;
	/*0x1788*/     UINT64       DeallocationBStore;
	/*0x1790*/     UINT64       BStoreLimit;
	/*0x1798*/     ULONG32      MuiGeneration;
	/*0x179C*/     ULONG32      IsImpersonating;
	/*0x17A0*/     UINT64       NlsCache;
	/*0x17A8*/     UINT64       pShimData;
	/*0x17B0*/     ULONG32      HeapVirtualAffinity;
	/*0x17B4*/     UINT8        _PADDING8_[0x4];
	/*0x17B8*/     UINT64       CurrentTransactionHandle;
	/*0x17C0*/     UINT64       ActiveFrame;
	/*0x17C8*/     UINT64       FlsData;
	/*0x17D0*/     UINT64       PreferredLanguages;
	/*0x17D8*/     UINT64       UserPrefLanguages;
	/*0x17E0*/     UINT64       MergedPrefLanguages;
	/*0x17E8*/     ULONG32      MuiImpersonation;
	union                                               // 2 elements, 0x2 bytes (sizeof)
	{
		/*0x17EC*/         UINT16       CrossTebFlags;
		/*0x17EC*/         UINT16       SpareCrossTebBits : 16;            // 0 BitPosition
	};
	union                                               // 2 elements, 0x2 bytes (sizeof)
	{
		/*0x17EE*/         UINT16       SameTebFlags;
		struct                                          // 12 elements, 0x2 bytes (sizeof)
		{
			/*0x17EE*/             UINT16       SafeThunkCall : 1;             // 0 BitPosition
			/*0x17EE*/             UINT16       InDebugPrint : 1;              // 1 BitPosition
			/*0x17EE*/             UINT16       HasFiberData : 1;              // 2 BitPosition
			/*0x17EE*/             UINT16       SkipThreadAttach : 1;          // 3 BitPosition
			/*0x17EE*/             UINT16       WerInShipAssertCode : 1;       // 4 BitPosition
			/*0x17EE*/             UINT16       RanProcessInit : 1;            // 5 BitPosition
			/*0x17EE*/             UINT16       ClonedThread : 1;              // 6 BitPosition
			/*0x17EE*/             UINT16       SuppressDebugMsg : 1;          // 7 BitPosition
			/*0x17EE*/             UINT16       DisableUserStackWalk : 1;      // 8 BitPosition
			/*0x17EE*/             UINT16       RtlExceptionAttached : 1;      // 9 BitPosition
			/*0x17EE*/             UINT16       InitialThread : 1;             // 10 BitPosition
			/*0x17EE*/             UINT16       SpareSameTebBits : 5;          // 11 BitPosition
		};
	};
	/*0x17F0*/     UINT64       TxnScopeEnterCallback;
	/*0x17F8*/     UINT64       TxnScopeExitCallback;
	/*0x1800*/     UINT64       TxnScopeContext;
	/*0x1808*/     ULONG32      LockCount;
	/*0x180C*/     ULONG32      SpareUlong0;
	/*0x1810*/     UINT64       ResourceRetValue;
}TEB64, *PTEB64;








