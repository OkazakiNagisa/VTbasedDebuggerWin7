/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "vmcs.h"
#include "hvm.h"

/*
 * VMX Exit Reasons
 */
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000
#define CPU_BASED_CR3_LOAD_EXITING		        0x00008000
#define CPU_BASED_CR3_STORE_EXITING		       0x00010000
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

#define TRAP_MTF						0
#define TRAP_DEBUG						1
#define TRAP_INT3						3
#define TRAP_INTO						4
#define TRAP_GP					    13
#define TRAP_PAGE_FAULT					14
#define TRAP_INVALID_OP					6


#define EXIT_REASON_EXCEPTION_NMI 0

#define GUEST_PHYSICAL_ADDRESS  0x00002400
#define EXIT_REASON_EPT_VIOLATION 48
#define EXIT_REASON_MTF_TRAP_FLAG 37
#define EXIT_REASON_EPT_MISONFIGURATION 49
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_INTERRUPT   7

#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32

#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34

#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40

#define EXIT_REASON_MACHINE_CHECK       41

#define EXIT_REASON_TPR_BELOW_THRESHOLD 43

#define VMX_MAX_GUEST_VMEXIT	EXIT_REASON_TPR_BELOW_THRESHOLD

enum SEGREGS
{
  ES = 0,
  CS,
  SS,
  DS,
  FS,
  GS,
  LDTR,
  TR
};

/*
 * Exit Qualifications for MOV for Control Register Access
 */
#define CONTROL_REG_ACCESS_NUM          0xf     /* 3:0, number of control register */
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose register */
#define LMSW_SOURCE_DATA                (0xFFFF << 16)  /* 16:31 lmsw source */

/* XXX these are really VMX specific */
#define TYPE_MOV_TO_DR          (0 << 4)
#define TYPE_MOV_FROM_DR        (1 << 4)
#define TYPE_MOV_TO_CR          (0 << 4)
#define TYPE_MOV_FROM_CR        (1 << 4)
#define TYPE_CLTS               (2 << 4)
#define TYPE_LMSW               (3 << 4)

/*
 * Intel CPU features in CR4
 */
#define X86_CR4_VMXE		0x2000  /* enable VMX */

/*
 * Intel CPU  MSR
 */
#define BTS64(b)					(1i64 << b)
#define FEATURE_CONTROL_LOCKED        BTS64(0)
#define FEATURE_CONTROL_VMXON_ENABLED BTS64(2)

/* MSRs & bits used for VMX enabling */
#define MSR_IA32_FEATURE_CONTROL 	0x03a
#define MSR_IA32_VMX_BASIC   		0x480
#define MSR_IA32_VMX_PINBASED_CTLS	0x481
#define MSR_IA32_VMX_PROCBASED_CTLS	0x482
#define MSR_IA32_VMX_EXIT_CTLS		0x483
#define MSR_IA32_VMX_ENTRY_CTLS		0x484
#define MSR_IA32_VMX_PROCBASED_CTLS2 0x48B
#define MSR_IA32_SYSENTER_CS		0x174
#define MSR_IA32_SYSENTER_ESP		0x175
#define MSR_IA32_SYSENTER_EIP		0x176
#define MSR_IA32_DEBUGCTL			0x1d9

#define MSR_LSTAR           0xC0000082

#define MSR_FS_BASE         0xc0000100        /* 64bit FS base */
#define MSR_GS_BASE         0xc0000101        /* 64bit GS base */
#define MSR_SHADOW_GS_BASE  0xc0000102        /* SwapGS GS shadow */ 
#define MSR_EFER 0xc0000080 
typedef struct _DEBUG_DR6_
{

	unsigned B0 : 1;//Dr0断点访问
	unsigned B1 : 1;//Dr1断点访问
	unsigned B2 : 1;//Dr2断点访问
	unsigned B3 : 1;//Dr3断点访问
	unsigned Reverted : 9;
	unsigned BD : 1;//有DEBUG寄存器访问引发的#DB异常
	unsigned BS : 1;//有单步引发的#DB异常
	unsigned BT : 1;//有TASK switch 任务切换引发的#DB异常
	unsigned Reverted2 : 16;

}DEBUG_DR6, *PDEBUG_DR6;
typedef struct _INTERRUPT_INFO_FIELD {
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned ErrorCodeValid : 1;
	unsigned NMIUnblocking : 1;
	unsigned Reserved : 18;
	unsigned Valid : 1;
} INTERRUPT_INFO_FIELD, *PINTERRUPT_INFO_FIELD;
typedef struct _INTERRUPT_INJECT_INFO_FIELD{
	unsigned Vector : 8;
	unsigned InterruptionType : 3;
	unsigned DeliverErrorCode : 1;
	unsigned Reserved : 19;
	unsigned Valid : 1;
} INTERRUPT_INJECT_INFO_FIELD, *PINTERRUPT_INJECT_INFO_FIELD;
typedef struct _DEBUG_DR7_
{

	unsigned L0 : 1; //0 DR0断点#DB
	unsigned G0 : 1; //1
	unsigned L1 : 1; //2 DR1断点#DB
	unsigned G1 : 1; //3
	unsigned L2 : 1; //4 DR2断点#DB
	unsigned G2 : 1; //5
	unsigned L3 : 1; //6 DR3断点#DB
	unsigned G3 : 1; //7
	unsigned LE : 1; //8
	unsigned GE : 1; //9
	unsigned reserved : 3; //001  //10-11-12
	unsigned GD : 1; //13...允许对DEBUG寄存器访问产生#DB异常
	unsigned reserved2 : 2; //00
	unsigned RW0 : 2;//设置DR0访问类型 00B执行断点 01B写断点 10B IO读/写断点11B 读/写断点
	unsigned LEN0 : 2;//设置DR0字节长度 00B一个字节 01B WORD 10B QWORD 11B DWORD 
	unsigned RW1 : 2;//设置DR1访问类型
	unsigned LEN1 : 2;//设置DR1字节长度
	unsigned RW2 : 2;//设置DR2访问类型
	unsigned LEN2 : 2;//设置DR2字节长度
	unsigned RW3 : 2;//设置DR3访问类型
	unsigned LEN3 : 2;//设置DR3字节长度

}DEBUG_DR7, *PDEBUG_DR7;


VOID set_in_cr4 (
  ULONG32 mask
);

VOID clear_in_cr4 (
  ULONG32 mask
);

//Implemented in vmx-asm.asm
VOID  VmxVmCall (
  ULONG32 HypercallNumber
);

ULONG64  VmxRead (
  ULONG64 field
);

VOID  VmxVmexitHandler ();

VOID  VmxDumpVmcs ();

BOOLEAN  VmxIsImplemented ();

NTSTATUS VmxSetupVMCS (
                       ULONG_PTR VMM_Stack,
                       PVOID GuestRip,
                       PVOID GuestRsp
                       );

NTSTATUS  VmxShutdown (
  PGUEST_REGS GuestRegs
);

NTSTATUS  VmxFillGuestSelectorData (
  PVOID GdtBase,
  ULONG Segreg,
  USHORT Selector
);

