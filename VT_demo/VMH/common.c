/* 
 * Copyright holder: Invisible Things Lab
 */

#include "common.h"
#include "hvm.h"

NTSTATUS  CmInitializeSegmentSelector (
  SEGMENT_SELECTOR * SegmentSelector,
  USHORT Selector,
  PUCHAR GdtBase
)
{
  PSEGMENT_DESCRIPTOR SegDesc;

  if (!SegmentSelector)
    return STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    KdPrint (("CmInitializeSegmentSelector(): Given selector (0x%X) points to LDT\n", Selector));
    return STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR) ((PUCHAR) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel   = Selector;
  SegmentSelector->base  = SegDesc->BaseLow | SegDesc->BaseMid << 16 | SegDesc->BaseHigh << 24;
  SegmentSelector->limit = SegDesc->LimitLow | SegDesc->LimitHigh << 16;
  SegmentSelector->attributes = SegDesc->AttributesLow | SegDesc->AttributesHigh << 8;

  if (!(SegDesc->AttributesLow & LA_STANDARD)) {
    // this is a TSS or callgate etc, save the base high part
    SegmentSelector->base |= (*(PULONG64) ((PUCHAR) SegDesc + 8)) << 32;
  }

#define IS_GRANULARITY_4KB  (1 << 0xB)

  if ( SegmentSelector->attributes & IS_GRANULARITY_4KB ) {
    // 4096-bit granularity is enabled for this segment, scale the limit
    SegmentSelector->limit = (SegmentSelector->limit << 12) | 0xfff;
  }

  return STATUS_SUCCESS;
}


NTSTATUS  CmGenerateMovReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register,
  ULONG64 Value
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0x48;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x49;
    pCode[1] = 0xb8 | (UCHAR) (Register & REG_MASK);
    memcpy (&pCode[2], &Value, 8);
    uCodeLength = 10;
    break;

  case REG_CONTROL:
    uCodeLength = *pGeneratedCodeLength;
    CmGenerateMovReg (pCode, pGeneratedCodeLength, REG_RAX, Value);
    // calc the size of the "mov rax, value"
    uCodeLength = *pGeneratedCodeLength - uCodeLength;
    pCode += uCodeLength;

    uCodeLength = 0;

    if (Register == (REG_CR8)) {
      // build 0x44 0x0f 0x22 0xc0
      pCode[0] = 0x44;
      uCodeLength = 1;
      pCode++;
      Register = 0;
    }
    // mov crX, rax

    pCode[0] = 0x0f;
    pCode[1] = 0x22;
    pCode[2] = 0xc0 | (UCHAR) ((Register & REG_MASK) << 3);

    // *pGeneratedCodeLength has already been adjusted to the length of the "mov rax"
    uCodeLength += 3;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}


NTSTATUS  CmGenerateCallReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  ULONG uCodeLength;

  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  switch (Register & ~REG_MASK) {
  case REG_GP:
    pCode[0] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 2;
    break;

  case REG_GP_ADDITIONAL:
    pCode[0] = 0x41;
    pCode[1] = 0xff;
    pCode[1] = 0xd0 | (UCHAR) (Register & REG_MASK);
    uCodeLength = 3;
    break;
  }

  if (pGeneratedCodeLength)
    *pGeneratedCodeLength += uCodeLength;

  return STATUS_SUCCESS;
}

NTSTATUS  CmGeneratePushReg (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength,
  ULONG Register
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  if ((Register & ~REG_MASK) != REG_GP)
    return STATUS_NOT_SUPPORTED;

  pCode[0] = 0x50 | (UCHAR) (Register & REG_MASK);
  *pGeneratedCodeLength += 1;

  return STATUS_SUCCESS;
}


NTSTATUS  CmGenerateIretq (
  PUCHAR pCode,
  PULONG pGeneratedCodeLength
)
{
  if (!pCode || !pGeneratedCodeLength)
    return STATUS_INVALID_PARAMETER;

  pCode[0] = 0x48;
  pCode[1] = 0xcf;
  *pGeneratedCodeLength += 2;

  return STATUS_SUCCESS;
}
