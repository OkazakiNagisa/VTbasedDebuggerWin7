/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>
#include "common.h"
#include "vmx.h"
#include "regs.h"

// ntamd64_x.h
#define KGDT64_NULL      (0 * 16)       // NULL descriptor
#define KGDT64_R0_CODE   (1 * 16)       // kernel mode 64-bit code
#define KGDT64_R0_DATA   (1 * 16) + 8   // kernel mode 64-bit data (stack)
#define KGDT64_R3_CMCODE (2 * 16)       // user mode 32-bit code
#define KGDT64_R3_DATA   (2 * 16) + 8   // user mode 32-bit data
#define KGDT64_R3_CODE   (3 * 16)       // user mode 64-bit code
#define KGDT64_SYS_TSS   (4 * 16)       // kernel mode system task state
#define KGDT64_R3_CMTEB  (5 * 16)       // user mode 32-bit TEB
#define KGDT64_R0_CMCODE (6 * 16)       // kernel mode 32-bit code

// this must be synchronized with CmSetBluepillSelectors() (common-asm.asm)
#define	BP_GDT64_CODE		KGDT64_R0_CODE  // cs
#define BP_GDT64_DATA		KGDT64_R0_DATA  // ds, es, ss
#define BP_GDT64_SYS_TSS	KGDT64_SYS_TSS  // tr
#define BP_GDT64_PCR		KGDT64_R0_DATA  // gs

NTSTATUS HvmSwallowBluepill ();

NTSTATUS HvmSpitOutBluepill ();
