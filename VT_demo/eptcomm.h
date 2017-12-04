#include "ntddk.h"
#define _HARDWARE_PTE_WORKING_SET_BITS  11
typedef struct _MMPTE {
	ULONGLONG Valid : 1;
	ULONGLONG Writable : 1;        // changed for MP version
	ULONGLONG Owner : 1;
	ULONGLONG WriteThrough : 1;
	ULONGLONG CacheDisable : 1;
	ULONGLONG Accessed : 1;
	ULONGLONG Dirty : 1;
	ULONGLONG LargePage : 1;
	ULONGLONG Global : 1;
	ULONGLONG CopyOnWrite : 1; // software field
	ULONGLONG Prototype : 1;   // software field
	ULONGLONG Write : 1;       // software field - MP change
	ULONGLONG PageFrameNumber : 28;
	ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
	ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
	ULONG64 NoExecute : 1;
} MMPTE, *PMMPTE;
#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)

#define PTE_BASE          0xFFFFF68000000000UI64
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_SHIFT 3
#define PDE_SHIFT 2

#define MiGetPteAddress(va)  ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))
//#define MiGetPteAddress(va) ((PULONG64)(((((ULONG64)(va)&0x0000FFFFFFFFF000) >> 12))*8 + PTE_BASE))
#define MiGetPdeAddress(va) ((PULONG64)(((((ULONG64)(va)&0x0000FFFFFFFFF000) >> 21))*8 + PDE_BASE))
#define MiGetPpeAddress(va) ((PULONG64)(((((ULONG64)(va)&0x0000FFFFFFFFF000) >> 30))*8 + PPE_BASE))
#define MiGetPxeAddress(va) ((PULONG64)(((((ULONG64)(va)&0x0000FFFFFFFFF000) >>39))*8 + PXE_BASE))
#define   GUEST_INTERRUPTIBILITY_INFO  0x00004824

#define TRAP_MTF						0
#define TRAP_DEBUG						1
#define TRAP_INT3						3
#define TRAP_INTO						4
#define TRAP_GP					    13
#define TRAP_PAGE_FAULT					14
#define TRAP_INVALID_OP					6

#define DIVIDE_ERROR_EXCEPTION 0
#define DEBUG_EXCEPTION 1
#define NMI_INTERRUPT 2
#define BREAKPOINT_EXCEPTION 3
#define OVERFLOW_EXCEPTION 4
#define BOUND_EXCEPTION 5
#define INVALID_OPCODE_EXCEPTION 6
#define DEVICE_NOT_AVAILABLE_EXCEPTION 7
#define DOUBLE_FAULT_EXCEPTION 8
#define COPROCESSOR_SEGMENT_OVERRUN 9
#define INVALID_TSS_EXCEPTION 10
#define SEGMENT_NOT_PRESENT 11
#define STACK_FAULT_EXCEPTION 12
#define GENERAL_PROTECTION_EXCEPTION 13
#define PAGE_FAULT_EXCEPTION 14
#define X87_FLOATING_POINT_ERROR 16
#define ALIGNMENT_CHECK_EXCEPTION 17
//#define MACHINE_CHECK_EXCEPTION 18
#define SIMD_FLOATING_POINT_EXCEPTION 19

#define EXTERNAL_INTERRUPT 0
#define HARDWARE_EXCEPTION 3
#define SOFTWARE_INTERRUPT 4
#define PRIVILEGED_SOFTWARE_EXCEPTION 5
#define SOFTWARE_EXCEPTION 6
#define OTHER_EVENT 7

#define HVM_DELIVER_NO_ERROR_CODE (-1)

#pragma pack (push, 1)
typedef struct _DBG_ESP
{
	ULONG64   Esp0;
	ULONG64   Esp1;
	ULONG64   Esp2;
	ULONG64   Esp3;
	ULONG64   Esp4;
	ULONG64   Esp5;
} DBG_ESP, *PDBG_ESP;

typedef struct _DEBG_ESP
{
	LIST_ENTRY  ListEntry;
	HANDLE      Threaid;
	DBG_ESP  Stack;
	PDBG_ESP PStack;
	ULONG64  GuestPA;
} DEBG_ESP, *PDEBG_ESP;

typedef struct _DEBUG_BP_
{
	LIST_ENTRY        ListEntry;
	PEPROCESS         Proces;
	ULONG64           Cr3;
	ULONG64           PT;
	ULONG64           EPTPTEVA;
	PHYSICAL_ADDRESS  EPTPTEPA;
	ULONG64           OldEPTPDEPA;
	ULONG64           EPTPDEPA;
	ULONG64           EPTPDEVA;
	PHYSICAL_ADDRESS  NewEPTPDEPA;
	ULONG64           NewEPTPDEVA;
	PHYSICAL_ADDRESS  NewEPTPtePA;
	ULONG64           NewEPTPteVA;
	ULONG64           BPVA;
	ULONG64           BPPA;
	BOOLEAN           BPHOOK;
	BOOLEAN           BPUNHOOK;
	PHYSICAL_ADDRESS  GuestPA;
	ULONG64           OldEPTPtePA;

	ULONG64           OldRip;
	ULONG64           NewRip;
} DEB_BP, *PDEB_BP;
#pragma pack (pop)
#pragma pack (push, 1)
typedef struct _DEBUG_ESP
{
	ULONG64   Esp0;
	ULONG64   Esp1;
	ULONG64   Esp2;
	ULONG64   Esp3;
	ULONG64   Esp4;
	ULONG64   Esp5;
} DEBUG_ESP, *PDEBUG_ESP;
#pragma pack (pop)
typedef struct tagItem
{
	LIST_ENTRY  ListEntry;
	PEPROCESS   Proces;
	HANDLE      ThreadId;
	ULONG64     Cr3;
	ULONG64      Page;
	ULONG64		 Flags;
	PDEBUG_ESP   PDEsp;
	DEBUG_ESP    DEsp;
	ULONG64      BpIndex;
	ULONG64       GuestRip;
} VT_ITEM, *PVT_ITEM;
typedef struct _KAPC_STATE {
	LIST_ENTRY ApcListHead[MaximumMode];
	struct _KPROCESS *Process;
	BOOLEAN KernelApcInProgress;
	BOOLEAN KernelApcPending;
	BOOLEAN UserApcPending;
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;



typedef struct _DEBUG_BP
{
	PEPROCESS         Proces;
	ULONG64           PteOffset;
	ULONG64           Pte;
	PHYSICAL_ADDRESS  Ptephy;
	PHYSICAL_ADDRESS  GuestPA;
	ULONG64           OldPtePA;
	ULONG64           NewPtePA;
	ULONG64           OldRip;
	ULONG64           NewRip;
	ULONG64           NEWPdeVA;
	ULONG64           Cr3;
	ULONG64           Addr;
	BOOLEAN           Addrhook;
} DEBUG_BP, *PDEBUG_BP;


typedef struct Buffer_Lock
{
	PMDL mdl;
	PVOID *lpData;
} BUFFER_LOCK;
typedef struct _MMPTE_HARDWARE_PAE {

	ULONGLONG Valid : 1;			//0 映射状态 该页当前没有映射物理内存=0 该页当前映射了物理内存=1
	ULONGLONG Write : 1;			// 1读写属性 只读=0 可读可写=1 (本位属性只对用户级代码有效 内核态将被忽略 即总可以读/写)
	ULONGLONG Owner : 1;			//2 访问模式 只有内核模式可以访问=0 内核与用户模式均可访问=1
	ULONGLONG WriteThrough : 1;		//3 写入模式 回写模式(写入操作不同步)=0 直写模式(写入操作同步)=1
	ULONGLONG CacheDisable : 1;		//4 缓存模式 允许缓存=0 禁用缓存=1
	ULONGLONG Accessed : 1;			//5 访问状态 该页未被读/写过=0 该页已被读/写过=1
	ULONGLONG Dirty : 1;			//6 脏页状态 该页未被改动过=0 该页已被改动过=1
	ULONGLONG LargePage : 1;		//7 分页大小 本位只对PDE有效 PAE模式分为4K和2M两种页 4K分页=0 2M分页=1
	ULONGLONG Global : 1;			//8 全局页面 该PTE对应到所有进程空间=1 该PTE对应当前进程空间=0
	ULONGLONG CopyOnWrite : 1; 		//9 写时复制
	ULONGLONG Prototype : 1;		//10 内存共享 用于R3多进程共享内存
	ULONGLONG reserved0 : 1;		//11 保留位 未使用11
	ULONGLONG PageFrameNumber : 28;	// PFN物理页的页帧号 对于PTE将该域和0xfffffffffffff000做与运算 可得到该页物理内存基址
	ULONGLONG reserved1 : 23;		// 保留位 未使用
	ULONGLONG Execute : 1;			// 是否执行 不可执行=1 可执行=0

} MMPTE_HARDWARE_PAE, *PMMPTE_HARDWARE_PAE;
