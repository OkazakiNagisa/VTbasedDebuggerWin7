/* 
 * Copyright holder: Invisible Things Lab
 */

#include "vmx.h"

VOID VmxDumpVmcs ()
{
  ULONG32 addr;

  KdPrint (("\n/*****16-bit Guest-State Fields*****/\n"));
  KdPrint (("GUEST_ES_SELECTOR 0x%X: 0x%llx\n", GUEST_ES_SELECTOR, VmxRead (GUEST_ES_SELECTOR)));
  KdPrint (("GUEST_CS_SELECTOR 0x%X: 0x%llx\n", GUEST_CS_SELECTOR, VmxRead (GUEST_CS_SELECTOR)));
  KdPrint (("GUEST_SS_SELECTOR 0x%X: 0x%llx\n", GUEST_SS_SELECTOR, VmxRead (GUEST_SS_SELECTOR)));
  KdPrint (("GUEST_DS_SELECTOR 0x%X: 0x%llx\n", GUEST_DS_SELECTOR, VmxRead (GUEST_DS_SELECTOR)));
  KdPrint (("GUEST_FS_SELECTOR 0x%X: 0x%llx\n", GUEST_FS_SELECTOR, VmxRead (GUEST_FS_SELECTOR)));
  KdPrint (("GUEST_GS_SELECTOR 0x%X: 0x%llx\n", GUEST_GS_SELECTOR, VmxRead (GUEST_GS_SELECTOR)));
  KdPrint (("GUEST_LDTR_SELECTOR 0x%X: 0x%llx\n", GUEST_LDTR_SELECTOR, VmxRead (GUEST_LDTR_SELECTOR)));
  KdPrint (("GUEST_TR_SELECTOR 0x%X: 0x%llx\n", GUEST_TR_SELECTOR, VmxRead (GUEST_TR_SELECTOR)));

  KdPrint (("\n/*****16-bit Host-State Fields*****/\n"));
  KdPrint (("HOST_ES_SELECTOR 0x%X: 0x%llx\n", HOST_ES_SELECTOR, VmxRead (HOST_ES_SELECTOR)));
  KdPrint (("HOST_CS_SELECTOR 0x%X: 0x%llx\n", HOST_CS_SELECTOR, VmxRead (HOST_CS_SELECTOR)));
  KdPrint (("HOST_SS_SELECTOR 0x%X: 0x%llx\n", HOST_SS_SELECTOR, VmxRead (HOST_SS_SELECTOR)));
  KdPrint (("HOST_DS_SELECTOR 0x%X: 0x%llx\n", HOST_DS_SELECTOR, VmxRead (HOST_DS_SELECTOR)));
  KdPrint (("HOST_FS_SELECTOR 0x%X: 0x%llx\n", HOST_FS_SELECTOR, VmxRead (HOST_FS_SELECTOR)));
  KdPrint (("HOST_GS_SELECTOR 0x%X: 0x%llx\n", HOST_GS_SELECTOR, VmxRead (HOST_GS_SELECTOR)));
  KdPrint (("HOST_TR_SELECTOR 0x%X: 0x%llx\n", HOST_TR_SELECTOR, VmxRead (HOST_TR_SELECTOR)));

  KdPrint (("\n/*****64-bit Control Fields*****/\n"));
  KdPrint (("IO_BITMAP_A 0x%X: 0x%llx\n",      IO_BITMAP_A,      VmxRead (IO_BITMAP_A)));
  KdPrint (("IO_BITMAP_A_HIGH 0x%X: 0x%llx\n", IO_BITMAP_A_HIGH, VmxRead (IO_BITMAP_A_HIGH)));
  KdPrint (("IO_BITMAP_B 0x%X: 0x%llx\n",      IO_BITMAP_B,      VmxRead (IO_BITMAP_B)));
  KdPrint (("IO_BITMAP_B_HIGH 0x%X: 0x%llx\n", IO_BITMAP_B_HIGH, VmxRead (IO_BITMAP_B_HIGH)));
  //
  KdPrint (("MSR_BITMAP 0x%X: 0x%llx\n",      MSR_BITMAP,      VmxRead (MSR_BITMAP)));
  KdPrint (("MSR_BITMAP_HIGH 0x%X: 0x%llx\n", MSR_BITMAP_HIGH, VmxRead (MSR_BITMAP_HIGH)));
  //
  KdPrint (("VM_EXIT_MSR_STORE_ADDR 0x%X: 0x%llx\n",      VM_EXIT_MSR_STORE_ADDR,      VmxRead (VM_EXIT_MSR_STORE_ADDR)));
  KdPrint (("VM_EXIT_MSR_STORE_ADDR_HIGH 0x%X: 0x%llx\n", VM_EXIT_MSR_STORE_ADDR_HIGH, VmxRead (VM_EXIT_MSR_STORE_ADDR_HIGH)));
  KdPrint (("VM_EXIT_MSR_LOAD_ADDR 0x%X: 0x%llx\n",       VM_EXIT_MSR_LOAD_ADDR,       VmxRead (VM_EXIT_MSR_LOAD_ADDR)));
  KdPrint (("VM_EXIT_MSR_LOAD_ADDR_HIGH 0x%X: 0x%llx\n",  VM_EXIT_MSR_LOAD_ADDR_HIGH,  VmxRead (VM_EXIT_MSR_LOAD_ADDR_HIGH)));
  KdPrint (("VM_ENTRY_MSR_LOAD_ADDR 0x%X: 0x%llx\n",      VM_ENTRY_MSR_LOAD_ADDR,      VmxRead (VM_ENTRY_MSR_LOAD_ADDR)));
  KdPrint (("VM_ENTRY_MSR_LOAD_ADDR_HIGH 0x%X: 0x%llx\n", VM_ENTRY_MSR_LOAD_ADDR_HIGH, VmxRead (VM_ENTRY_MSR_LOAD_ADDR_HIGH)));
  //
  KdPrint (("TSC_OFFSET 0x%X: 0x%llx\n",      TSC_OFFSET,      VmxRead (TSC_OFFSET)));
  KdPrint (("TSC_OFFSET_HIGH 0x%X: 0x%llx\n", TSC_OFFSET_HIGH, VmxRead (TSC_OFFSET_HIGH)));
  //
  KdPrint (("VIRTUAL_APIC_PAGE_ADDR 0x%X: 0x%llx\n",      VIRTUAL_APIC_PAGE_ADDR,      VmxRead (VIRTUAL_APIC_PAGE_ADDR)));
  KdPrint (("VIRTUAL_APIC_PAGE_ADDR_HIGH 0x%X: 0x%llx\n", VIRTUAL_APIC_PAGE_ADDR_HIGH, VmxRead (VIRTUAL_APIC_PAGE_ADDR_HIGH)));

  KdPrint (("\n/*****64-bit Guest-State Fields*****/\n"));
  KdPrint (("VMCS_LINK_POINTER 0x%X: 0x%llx\n",      VMCS_LINK_POINTER,      VmxRead (VMCS_LINK_POINTER)));
  KdPrint (("VMCS_LINK_POINTER_HIGH 0x%X: 0x%llx\n", VMCS_LINK_POINTER_HIGH, VmxRead (VMCS_LINK_POINTER_HIGH)));
  KdPrint (("GUEST_IA32_DEBUGCTL 0x%X: 0x%llx\n",      GUEST_IA32_DEBUGCTL,      VmxRead (GUEST_IA32_DEBUGCTL)));
  KdPrint (("GUEST_IA32_DEBUGCTL_HIGH 0x%X: 0x%llx\n", GUEST_IA32_DEBUGCTL_HIGH, VmxRead (GUEST_IA32_DEBUGCTL_HIGH)));

  KdPrint (("\n/*****32-bit Control Fields*****/\n"));
  KdPrint (("PIN_BASED_VM_EXEC_CONTROL 0x%X: 0x%llx\n", PIN_BASED_VM_EXEC_CONTROL, VmxRead (PIN_BASED_VM_EXEC_CONTROL)));
  addr = CPU_BASED_VM_EXEC_CONTROL;
  KdPrint (("CPU_BASED_VM_EXEC_CONTROL 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = EXCEPTION_BITMAP;
  KdPrint (("EXCEPTION_BITMAP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = PAGE_FAULT_ERROR_CODE_MASK;
  KdPrint (("PAGE_FAULT_ERROR_CODE_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = PAGE_FAULT_ERROR_CODE_MATCH;
  KdPrint (("PAGE_FAULT_ERROR_CODE_MATCH 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_COUNT;
  KdPrint (("CR3_TARGET_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_CONTROLS;
  KdPrint (("VM_EXIT_CONTROLS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_STORE_COUNT;
  KdPrint (("VM_EXIT_MSR_STORE_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_MSR_LOAD_COUNT;
  KdPrint (("VM_EXIT_MSR_LOAD_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_CONTROLS;
  KdPrint (("VM_ENTRY_CONTROLS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_MSR_LOAD_COUNT;
  KdPrint (("VM_ENTRY_MSR_LOAD_COUNT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_INTR_INFO_FIELD;
  KdPrint (("VM_ENTRY_INTR_INFO_FIELD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_EXCEPTION_ERROR_CODE;
  KdPrint (("VM_ENTRY_EXCEPTION_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_ENTRY_INSTRUCTION_LEN;
  KdPrint (("VM_ENTRY_INSTRUCTION_LEN 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = TPR_THRESHOLD;
  KdPrint (("TPR_THRESHOLD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = SECONDARY_VM_EXEC_CONTROL;
  KdPrint (("SECONDARY_VM_EXEC_CONTROL 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****32-bit RO Data Fields*****/\n"));
  addr = VM_INSTRUCTION_ERROR;
  KdPrint (("VM_INSTRUCTION_ERROR 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_REASON;
  KdPrint (("VM_EXIT_REASON 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INTR_INFO;
  KdPrint (("VM_EXIT_INTR_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INTR_ERROR_CODE;
  KdPrint (("VM_EXIT_INTR_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IDT_VECTORING_INFO_FIELD;
  KdPrint (("IDT_VECTORING_INFO_FIELD 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = IDT_VECTORING_ERROR_CODE;
  KdPrint (("IDT_VECTORING_ERROR_CODE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VM_EXIT_INSTRUCTION_LEN;
  KdPrint (("VM_EXIT_INSTRUCTION_LEN 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = VMX_INSTRUCTION_INFO;
  KdPrint (("VMX_INSTRUCTION_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****32-bit Guest-State Fields*****/\n"));
  addr = GUEST_ES_LIMIT;
  KdPrint (("GUEST_ES_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_LIMIT;
  KdPrint (("GUEST_CS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_LIMIT;
  KdPrint (("GUEST_SS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_LIMIT;
  KdPrint (("GUEST_DS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_LIMIT;
  KdPrint (("GUEST_FS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_LIMIT;
  KdPrint (("GUEST_GS_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_LIMIT;
  KdPrint (("GUEST_LDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_LIMIT;
  KdPrint (("GUEST_TR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GDTR_LIMIT;
  KdPrint (("GUEST_GDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IDTR_LIMIT;
  KdPrint (("GUEST_IDTR_LIMIT 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ES_AR_BYTES;
  KdPrint (("GUEST_ES_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_AR_BYTES;
  KdPrint (("GUEST_CS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_AR_BYTES;
  KdPrint (("GUEST_SS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_AR_BYTES;
  KdPrint (("GUEST_DS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_AR_BYTES;
  KdPrint (("GUEST_FS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_AR_BYTES;
  KdPrint (("GUEST_GS_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_AR_BYTES;
  KdPrint (("GUEST_LDTR_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_AR_BYTES;
  KdPrint (("GUEST_TR_AR_BYTES 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_INTERRUPTIBILITY_STATE;
  KdPrint (("GUEST_INTERRUPTIBILITY_INFO 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ACTIVITY_STATE;
  KdPrint (("GUEST_ACTIVITY_STATE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SM_BASE;
  KdPrint (("GUEST_SM_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_CS;
  KdPrint (("GUEST_SYSENTER_CS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****32-bit Host-State Fields*****/\n"));
  addr = HOST_IA32_SYSENTER_CS;
  KdPrint (("HOST_IA32_SYSENTER_CS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****Natural 64-bit Control Fields*****/\n"));
  addr = CR0_GUEST_HOST_MASK;
  KdPrint (("CR0_GUEST_HOST_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR4_GUEST_HOST_MASK;
  KdPrint (("CR4_GUEST_HOST_MASK 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR0_READ_SHADOW;
  KdPrint (("CR0_READ_SHADOW 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR4_READ_SHADOW;
  KdPrint (("CR4_READ_SHADOW 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE0;
  KdPrint (("CR3_TARGET_VALUE0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE1;
  KdPrint (("CR3_TARGET_VALUE1 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE2;
  KdPrint (("CR3_TARGET_VALUE2 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = CR3_TARGET_VALUE3;
  KdPrint (("CR3_TARGET_VALUE3 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****Natural 64-bit RO Data Fields*****/\n"));
  addr = EXIT_QUALIFICATION;
  KdPrint (("EXIT_QUALIFICATION 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LINEAR_ADDRESS;
  KdPrint (("GUEST_LINEAR_ADDRESS 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****Natural 64-bit Guest-State Fields*****/\n"));
  addr = GUEST_CR0;
  KdPrint (("GUEST_CR0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CR3;
  KdPrint (("GUEST_CR3 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CR4;
  KdPrint (("GUEST_CR4 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_ES_BASE;
  KdPrint (("GUEST_ES_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_CS_BASE;
  KdPrint (("GUEST_CS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SS_BASE;
  KdPrint (("GUEST_SS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DS_BASE;
  KdPrint (("GUEST_DS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_FS_BASE;
  KdPrint (("GUEST_FS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GS_BASE;
  KdPrint (("GUEST_GS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_LDTR_BASE;
  KdPrint (("GUEST_LDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_TR_BASE;
  KdPrint (("GUEST_TR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_GDTR_BASE;
  KdPrint (("GUEST_GDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_IDTR_BASE;
  KdPrint (("GUEST_IDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_DR7;
  KdPrint (("GUEST_DR7 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_RSP;
  KdPrint (("GUEST_RSP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_RIP;
  KdPrint (("GUEST_RIP 0x%X: 0x%llX\n", addr, VmxRead (addr)));
  addr = GUEST_RFLAGS;
  KdPrint (("GUEST_RFLAGS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_PENDING_DBG_EXCEPTIONS;
  KdPrint (("GUEST_PENDING_DBG_EXCEPTIONS 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_ESP;
  KdPrint (("GUEST_SYSENTER_ESP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = GUEST_SYSENTER_EIP;
  KdPrint (("GUEST_SYSENTER_EIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));

  KdPrint (("\n\n\n/*****Natural 64-bit Host-State Fields*****/\n"));
  addr = HOST_CR0;
  KdPrint (("HOST_CR0 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_CR3;
  KdPrint (("HOST_CR3 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_CR4;
  KdPrint (("HOST_CR4 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_FS_BASE;
  KdPrint (("HOST_FS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_GS_BASE;
  KdPrint (("HOST_GS_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_TR_BASE;
  KdPrint (("HOST_TR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_GDTR_BASE;
  KdPrint (("HOST_GDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IDTR_BASE;
  KdPrint (("HOST_IDTR_BASE 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IA32_SYSENTER_ESP;
  KdPrint (("HOST_IA32_SYSENTER_ESP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_IA32_SYSENTER_EIP;
  KdPrint (("HOST_IA32_SYSENTER_EIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_RSP;
  KdPrint (("HOST_RSP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
  addr = HOST_RIP;
  KdPrint (("HOST_RIP 0x%X: 0x%llx\n", addr, VmxRead (addr)));
}
