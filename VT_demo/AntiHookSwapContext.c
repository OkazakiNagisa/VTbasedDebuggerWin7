#include "ntddk.h"
#include "./Hooks/PageHook.h"
#include "KernelStruct.h"

 ULONG64 SwapContext_PatchXRstor;
 ULONG64 SwapContext;
 ULONG64 jmp_SwapContextTp;
 ULONG64 jmp_SwapContext_PatchXRstor;
 ULONG64 jmp_SwapContext;
 PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID *Original_ApiAddress, OUT ULONG *PatchSize);
 VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);
 NTKERNELAPI
	 BOOLEAN
	 PsIsSystemThread(
	 _In_ PETHREAD Thread
	 );
 ULONG pslp_patch_size30 = 0;		//SwapContext被修改了N字节
 PUCHAR pslp_head_n_byte30 = NULL;	//SwapContext的前N字节数组
 PVOID ori_pslp30 = NULL;			//pfKiAttachProcess的原函数
 extern __fastcall MySwapContext();
 BOOLEAN __fastcall  IstThreadStub(PETHREAD OldThread, PETHREAD NewThread){

	 if ((PsIsSystemThread(OldThread) == TRUE)&& (PsIsSystemThread(NewThread)==TRUE))
	 {
		 return TRUE;
	 }

	 return FALSE;
 
 
 }
 void InitializeHookSwapContext(){
 
	 jmp_SwapContext_PatchXRstor = SwapContext_PatchXRstor + 0x121;

	 jmp_SwapContext = SwapContext + 0x29;
	 jmp_SwapContextTp = SwapContext + 0x1B;

 }
 VOID EPTHOOK_SwapContext(){
 
	 PHHook(SwapContext,MySwapContext);
 
 }

 VOID EPTUNHOOK_SwapContext(){


	 PHRestore(SwapContext);

 }
 VOID HOOKSwapContext(){
	 pslp_head_n_byte30 = HookKernelApi(SwapContext,
		 (PVOID)&MySwapContext,
		 &ori_pslp30,
		 &pslp_patch_size30);
 }
 VOID UnHookSwapContext(){
	 UnhookKernelApi(SwapContext, pslp_head_n_byte30, pslp_patch_size30);


 }