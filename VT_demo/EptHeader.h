#include "ntddk.h"

typedef struct _EPTP_ {
	ULONGLONG MEMORYTYPE : 3;//2
	ULONGLONG WalkLength : 3;//5
	ULONGLONG D : 1;//6
	ULONGLONG reserved : 5;//11
	ULONGLONG PML4T : 28;//39
	ULONGLONG reserved2 : 24;//63
} TEPTPPML4T, *PTEPTPPML4T;
typedef struct _EPTPPDE_ {
	ULONG64 PML4E;
	PHYSICAL_ADDRESS PML4EPHY;
	ULONG64 PDPTE;
	PHYSICAL_ADDRESS PDPTEPHY;
	ULONG64 PDE;
	PHYSICAL_ADDRESS PDEPHY;
	ULONG64 PTE;
	PHYSICAL_ADDRESS PTEPHY;
	ULONG64 vPTE[5];
} _TEPTPPML4T, *P_TEPTPPML4T;
typedef struct _EPTPTE_HARDWARE_2MPAE {
	ULONGLONG Read : 1;      //读0
	ULONGLONG Write : 1;     //写1
	ULONGLONG Execute : 1;  //执行2
	ULONGLONG MemoryType : 3; //内存类型5
	ULONGLONG IPAT : 1;   //6
	//
	ULONGLONG LargePage : 1;//7页面尺寸位
	ULONGLONG Accessed : 1;//// 8访问状态 该页未被读/写过=0 该页已被读/写过=1

	ULONGLONG Dirty : 1;//// 9脏页状态 该页未被改动过=0 该页已被改动过=1

	ULONGLONG reserved2 : 2;//11
	ULONGLONG reserved6 : 9;//20
	ULONGLONG PageFrame : 19;//物理地址
	ULONGLONG reserved3 : 13;
	ULONGLONG reserved4 : 11;
} EPT_PDE_2MPAGE, *PEPT_PDE_2MPAGE;
typedef struct _EPT2MPAGE_ {
	ULONGLONG Offset : 21;
	ULONGLONG PDEindex : 9;
	ULONGLONG PDPTEindex : 9;
	ULONGLONG PML4Eindex : 9;
	ULONGLONG Sign : 15;
} EPTP2MTABLE_ENTRY, *PEPT2MPTABLE_ENTRY;
typedef struct _EPT_ATTRIBUTE_PAE {
	ULONGLONG Read : 1;      //0读
	ULONGLONG Write : 1;     //1写
	ULONGLONG Execute : 1;  //2执行
	ULONGLONG ReadAble : 1; //3为1时表表示GPA可读
	ULONGLONG WriteAble : 1;   //4为1时表表示GPA可写
	ULONGLONG ExecuteAble : 1;//5为1时表表示GPA可执行
	ULONGLONG reserved : 1;//// 6保留
	ULONGLONG Valid : 1;//为1时 7表明存在一个线性地址
	ULONGLONG TranSlation : 1;////8为1时表面EPT VIOLATION发生在GPA转HPA 为0表明发生在对guest paging-stucture表现访问环节
	ULONGLONG reserved2 : 1;//9保留 为0
	ULONGLONG NMIunblocking : 1;//10为1表明执行啦IRET指令，并且NMI阻塞已经解除
	ULONGLONG reserved3 : 1;//11
	ULONGLONG reserved4 : 13;//23:11
	ULONGLONG GET_PTE : 1;//24
	ULONGLONG GET_PAGE_FRAME : 1;//25
	ULONGLONG FIX_ACCESS : 1;//26为1时 进行access ringht修复工作
	ULONGLONG FIX_MISCONF : 1;//27为1时 进行misconfiguration修复工作
	ULONGLONG FIX_FIXING : 1;//28为1时 修复 为0映射
	ULONGLONG EPT_FORCE : 1;//29为1时 强制进行映射
	ULONGLONG reserved5 : 1;
} EPT_ATTRIBUTE_PAGE, *PEPT_ATTRIBUTE_PAGE;
typedef struct _EPTPAGE_ {
	ULONGLONG Offset : 12;
	ULONGLONG PTEindex : 9;
	ULONGLONG PDEindex : 9;
	ULONGLONG PDPTEindex : 9;
	ULONGLONG PML4Eindex : 9;
	ULONGLONG Sign : 15;
} EPTP4KTABLE_ENTRY, *PEPTP4KTABLE_ENTRY;

typedef struct _EPTPINV_ {
	ULONGLONG VPID : 16;//16
	ULONGLONG reserved : 47;//63
	ULONGLONG GuestVA : 64;//39
} INVTABLE, *PINVTABLE;
typedef struct _EPTPTE_HARDWARE_PAE {
	ULONGLONG Read : 1;      //读0
	ULONGLONG Write : 1;     //写1
	ULONGLONG Execute : 1;  //执行2
	ULONGLONG MemoryType : 3; //内存类型5
	ULONGLONG IPAT : 1;   //6
	//
	ULONGLONG LargePage : 1;//7页面尺寸位
	ULONGLONG Accessed : 1;//// 8访问状态 该页未被读/写过=0 该页已被读/写过=1

	ULONGLONG Dirty : 1;//// 9脏页状态 该页未被改动过=0 该页已被改动过=1

	ULONGLONG reserved2 : 2;//11
	ULONGLONG PageFrame : 28;//物理地址
	ULONGLONG reserved3 : 13;
	ULONGLONG reserved4 : 11;
} EPT_PAE_4KPAGE, *PEPT_PAE_4KPAGE;
#define P_PRESENT			0x01
#define P_WRITABLE			0x02
#define P_USERMODE			0x04
#define P_WRITETHROUGH		0x08
#define P_CACHE_DISABLED	0x10
#define P_ACCESSED			0x20
#define P_DIRTY				0x40
#define P_LARGE				0x80
#define P_GLOBAL			0x100

#define MEM_TYPE_UC                                     0
#define MEM_TYPE_WB                                     6
#define MEM_TYPE_WT                                     4
#define MEM_TYPE_WP                                     5
#define MEM_TYPE_WC                                     1

//	;;
//;; EPT 页结构内存类型
//	;;
#define EPT_MEM_WB                                      (MEM_TYPE_WB << 3)
#define EPT_MEM_UC                                      (MEM_TYPE_UC << 3)
#define EPT_MEM_WT                                      (MEM_TYPE_WT << 3)
#define EPT_MEM_WP                                      (MEM_TYPE_WP << 3)
#define EPT_MEM_WC                                      (MEM_TYPE_WC << 3)
#define EPT_READ		0x01
#define EPT_WRIT		0x02
#define EPT_EXECUTE		0x04