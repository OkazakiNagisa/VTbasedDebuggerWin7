/* 
 * Copyright holder: Invisible Things Lab
 */

#pragma once

#include <ntddk.h>

// ----------------------------------------  

#define MEM_TAG	'DeDf'

#define NBP_MAGIC ((ULONG32)'!LTI')
#define NBP_HYPERCALL_UNLOAD			0x1

# define BP_KNOCK_EAX	0xbabecafe


#pragma pack (push, 1)

/* 
* Attribute for segment selector.
*/
typedef struct
{
    USHORT type:4;              /* 0;  Bit 40-43 */
    USHORT s:1;                 /* 4;  Bit 44 */
    USHORT dpl:2;               /* 5;  Bit 45-46 */
    USHORT p:1;                 /* 7;  Bit 47 */
    // gap!       
    USHORT avl:1;               /* 8;  Bit 52 */
    USHORT l:1;                 /* 9;  Bit 53 */
    USHORT db:1;                /* 10; Bit 54 */
    USHORT g:1;                 /* 11; Bit 55 */
    USHORT Gap:4;
} SEGMENT_ATTRIBUTES;

typedef struct
{
  USHORT sel;
  USHORT attributes;
  ULONG32 limit;
  ULONG64 base;
} SEGMENT_SELECTOR;

typedef struct
{
  USHORT LimitLow;
  USHORT BaseLow;
  UCHAR BaseMid;
  UCHAR AttributesLow;
  struct
  {
      UCHAR LimitHigh      : 4;
      UCHAR AttributesHigh : 4;
  };
  UCHAR BaseHigh;
} SEGMENT_DESCRIPTOR, *PSEGMENT_DESCRIPTOR;

#pragma pack (pop)

#define LA_STANDARD		0x10

#define REG_MASK			0x07
#define REG_GP				0x08
#define REG_GP_ADDITIONAL	0x10
#define REG_CONTROL			0x20
#define REG_DEBUG			0x40
#define REG_RFLAGS			0x80

#define	REG_RAX	REG_GP | 0
#define REG_RCX	REG_GP | 1
#define REG_RDX	REG_GP | 2
#define REG_RBX	REG_GP | 3
#define REG_RSP	REG_GP | 4
#define REG_RBP	REG_GP | 5
#define REG_RSI	REG_GP | 6
#define REG_RDI	REG_GP | 7

#define	REG_R8	REG_GP_ADDITIONAL | 0
#define	REG_R9	REG_GP_ADDITIONAL | 1
#define	REG_R10	REG_GP_ADDITIONAL | 2
#define	REG_R11	REG_GP_ADDITIONAL | 3
#define	REG_R12	REG_GP_ADDITIONAL | 4
#define	REG_R13	REG_GP_ADDITIONAL | 5
#define	REG_R14	REG_GP_ADDITIONAL | 6
#define	REG_R15	REG_GP_ADDITIONAL | 7

#define REG_CR0	REG_CONTROL | 0
#define REG_CR2	REG_CONTROL | 2
#define REG_CR3	REG_CONTROL | 3
#define REG_CR4	REG_CONTROL | 4
#define REG_CR8	REG_CONTROL | 8

typedef struct _CPU
{
    PVOID OriginalVmcs;    // VMCS结构，每个guest OS 一个
    PVOID OriginaVmxonR;   // Vmxon结构，每个CPU核心一个
    PVOID VMM_Stack;       // VMM栈

} CPU, *PCPU;

typedef struct _GUEST_REGS
{
  ULONG64 rax;                  // 0x00         // NOT VALID FOR SVM
  ULONG64 rcx;
  ULONG64 rdx;                  // 0x10
  ULONG64 rbx;
  ULONG64 rsp;                  // 0x20         // rsp is not stored here on SVM
  ULONG64 rbp;
  ULONG64 rsi;                  // 0x30
  ULONG64 rdi;
  ULONG64 r8;                   // 0x40
  ULONG64 r9;
  ULONG64 r10;                  // 0x50
  ULONG64 r11;
  ULONG64 r12;                  // 0x60
  ULONG64 r13;
  ULONG64 r14;                  // 0x70
  ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;

NTSTATUS  CmSubvert (
  PVOID
);

NTSTATUS  CmGuestEip (
  PVOID
);

NTSTATUS  CmInitializeSegmentSelector (
  SEGMENT_SELECTOR * SegmentSelector,
  USHORT Selector,
  PUCHAR GdtBase
);

NTSTATUS  CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
);

NTSTATUS  CmGeneratePushReg (
                             PUCHAR pCode,
                             PULONG pGeneratedCodeLength,
                             ULONG Register
                             );

NTSTATUS  CmGenerateIretq (
                           PUCHAR pCode,
                           PULONG pGeneratedCodeLength
                           );

VOID GetCpuIdInfo (
                   ULONG32 fn,
                   OUT PULONG32 ret_eax,
                   OUT PULONG32 ret_ebx,
                   OUT PULONG32 ret_ecx,
                   OUT PULONG32 ret_edx
                   );


