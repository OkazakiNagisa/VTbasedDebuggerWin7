#include "ntddk.h"
#include "./Hooks/PageHook.h"
VOID EPT_InitAnti();
VOID EPT_UnLoadAnti();
PVOID HookKernelApi(IN PVOID ApiAddress, IN PVOID Proxy_ApiAddress, OUT PVOID *Original_ApiAddress, OUT ULONG *PatchSize);
VOID UnhookKernelApi(IN PVOID ApiAddress, IN PVOID OriCode, IN ULONG PatchSize);
VOID
__fastcall
proxyDbgkUnMapViewOfSection(IN PEPROCESS PROCESS, IN PVOID BaseAddress);
VOID
__fastcall
proxyDbgkMapViewOfSection(IN PVOID Section,
IN PVOID BaseAddress,
IN ULONG SectionOffset,
IN ULONG_PTR ViewSize);

NTSTATUS
__fastcall
proxyDbgkOpenProcessDebugPort(IN PEPROCESS Process,
IN KPROCESSOR_MODE PreviousMode,
OUT HANDLE *DebugHandle);
////
VOID
__fastcall
proxyDbgkCopyProcessDebugPort(IN PEPROCESS Process,
IN PEPROCESS Parent);
BOOLEAN
__fastcall
proxyDbgkForwardException(IN PEXCEPTION_RECORD ExceptionRecord,
IN BOOLEAN DebugPort,
IN BOOLEAN SecondChance);
NTSTATUS
DbgkpSetProcessDebugObject_2(//反汇编OK
IN PEPROCESS Process,
IN ULONG64 DebugObject,
IN NTSTATUS MsgStatus,
IN PETHREAD LastThread
);
VOID
NTAPI
proxyDbgkExitProcess(IN NTSTATUS ExitStatus);
VOID
NTAPI
proxyDbgkExitThread(IN NTSTATUS ExitStatus);
NTSTATUS __fastcall
DbgkpQueueMessage_2(
IN PEPROCESS Process,
IN PETHREAD Thread,
IN OUT ULONG64 ApiMsg,
IN ULONG Flags,
IN ULONG64 TargetDebugObject
);
KIRQL WPOFFx64();
void WPONx64(KIRQL irql);
VOID initANti();
VOID unload();
////
extern ULONG64 DbgkpSetProcessDebugObject;
extern ULONG64 DbgkpQueueMessage;
 ULONG64 DbgkExitProcess;
 ULONG64 DbgkExitThread;
ULONG64 DbgkUnMapViewOfSection;
ULONG64 DbgkMapViewOfSection;
ULONG64 DbgkOpenProcessDebugPort;
ULONG64 KiDispatchException;
UINT16 orgfunc=0;
ULONG64 DbgkCopyProcessDebugPort;
ULONG64 DbgkForwardException;
ULONG pslp_patch_size2 = 0;		//DbgkCopyProcessDebugPort被修改了N字节
PUCHAR pslp_head_n_byte2 = NULL;	//DbgkCopyProcessDebugPort的前N字节数组
PVOID ori_pslp2 = NULL;			//DbgkCopyProcessDebugPort的原函数

ULONG pslp_patch_size3 = 0;		//DbgkForwardException被修改了N字节
PUCHAR pslp_head_n_byte3 = NULL;	//DbgkForwardException的前N字节数组
PVOID ori_pslp3 = NULL;			//DbgkForwardException的原函数

ULONG pslp_patch_size4= 0;		//DbgkOpenProcessDebugPort被修改了N字节
PUCHAR pslp_head_n_byte4= NULL;	//DbgkOpenProcessDebugPort的前N字节数组
PVOID ori_pslp4= NULL;			//DbgkOpenProcessDebugPort的原函数

ULONG pslp_patch_size5= 0;		//DbgkUnMapViewOfSection被修改了N字节
PUCHAR pslp_head_n_byte5= NULL;	//DbgkUnMapViewOfSection的前N字节数组
PVOID ori_pslp5= NULL;			//DbgkUnMapViewOfSection的原函数

ULONG pslp_patch_size6= 0;		//DbgkMapViewOfSection被修改了N字节
PUCHAR pslp_head_n_byte6= NULL;	//DbgkMapViewOfSection的前N字节数组
PVOID ori_pslp6= NULL;			//DbgkMapViewOfSection的原函数


ULONG pslp_patch_size7 = 0;		//DbgkExitThread被修改了N字节
PUCHAR pslp_head_n_byte7 = NULL;	//DbgkExitThread的前N字节数组
PVOID ori_pslp7 = NULL;			//DbgkExitThread的原函数

ULONG pslp_patch_size8 = 0;		//DbgkExitProcess被修改了N字节
PUCHAR pslp_head_n_byte8 = NULL;	//DbgkExitProcess的前N字节数组
PVOID ori_pslp8 = NULL;			//DbgkExitProcess的原函数

ULONG pslp_patch_size11 = 0;		//DbgkExitProcess被修改了N字节
PUCHAR pslp_head_n_byte11 = NULL;	//DbgkExitProcess的前N字节数组
PVOID ori_pslp11 = NULL;			//DbgkExitProcess的原函数

ULONG pslp_patch_size12 = 0;		//DbgkpSetProcessDebugObject_2被修改了N字节
PUCHAR pslp_head_n_byte12 = NULL;	//DbgkpSetProcessDebugObject_2的前N字节数组
PVOID ori_pslp12 = NULL;			//DbgkpSetProcessDebugObject_2的原函数


UCHAR Irgcode[2] = {  0x0f,0x85 };
UCHAR orgcode[2] = { 0x90,0xE9 };

VOID installMiniHOOK(){
	KIRQL irq;


	pslp_head_n_byte3 = HookKernelApi(DbgkForwardException,
		(PVOID)proxyDbgkForwardException,
		&ori_pslp3,
		&pslp_patch_size3);

	/*pslp_head_n_byte12 = HookKernelApi(DbgkpSetProcessDebugObject,
		(PVOID)DbgkpSetProcessDebugObject_2,
		&ori_pslp12,
		&pslp_patch_size12);*/


pslp_head_n_byte2 = HookKernelApi(DbgkCopyProcessDebugPort,
	(PVOID)proxyDbgkCopyProcessDebugPort,
		&ori_pslp2,
		&pslp_patch_size2);


	
	pslp_head_n_byte4 = HookKernelApi(DbgkOpenProcessDebugPort,
		(PVOID)proxyDbgkOpenProcessDebugPort,
		&ori_pslp4,
		&pslp_patch_size4);

/*
	pslp_head_n_byte5 = HookKernelApi(DbgkUnMapViewOfSection,
		(PVOID)proxyDbgkUnMapViewOfSection,
		&ori_pslp5,
		&pslp_patch_size5);

	pslp_head_n_byte6 = HookKernelApi(DbgkMapViewOfSection,
		(PVOID)proxyDbgkMapViewOfSection,
		&ori_pslp6,
		&pslp_patch_size6);*/




	/*pslp_head_n_byte7 = HookKernelApi(DbgkExitThread,
		(PVOID)proxyDbgkExitThread,
		&ori_pslp7,
		&pslp_patch_size7);

	pslp_head_n_byte8 = HookKernelApi(DbgkExitProcess,
		(PVOID)proxyDbgkExitProcess,
		&ori_pslp8,
		&pslp_patch_size8);
*/

	pslp_head_n_byte11 = HookKernelApi(DbgkpQueueMessage,
		(PVOID)DbgkpQueueMessage_2,
		&ori_pslp11,
		&pslp_patch_size11);
/*

	irq=WPOFFx64();
memcpy(KiDispatchException + 0x241, orgcode, 2);
	//_InterlockedExchange16(KiDispatchException + 0x241, 0x90E9);
	WPONx64(irq);*/
	initANti();
}
VOID EPT_InitialzeMiNiHook(){
	EPT_InitAnti();
	PHHook(DbgkForwardException, proxyDbgkForwardException);
	PHHook(DbgkCopyProcessDebugPort, proxyDbgkCopyProcessDebugPort);
	PHHook(DbgkOpenProcessDebugPort, proxyDbgkOpenProcessDebugPort);
	//PHHook(DbgkUnMapViewOfSection, proxyDbgkUnMapViewOfSection);
	//PHHook(DbgkMapViewOfSection, proxyDbgkMapViewOfSection);
	PHHook(DbgkpQueueMessage, DbgkpQueueMessage_2);
//	PHHOOK2(KiDispatchException + 0x241, orgcode, 2);
}

VOID EPT_UnInitialzeMiNiHook(){
	EPT_UnLoadAnti();
	PHRestore(DbgkForwardException);
	PHRestore(DbgkCopyProcessDebugPort);
	PHRestore(DbgkOpenProcessDebugPort);
//	PHRestore(DbgkUnMapViewOfSection);
	//PHRestore(DbgkMapViewOfSection);
	PHRestore(DbgkpQueueMessage);
	//PHRestore(KiDispatchException + 0x241);
}
VOID  unMiniHook(){
	KIRQL irq;

	UnhookKernelApi(DbgkForwardException, pslp_head_n_byte3, pslp_patch_size3);
/*
	UnhookKernelApi(DbgkpSetProcessDebugObject, pslp_head_n_byte12, pslp_patch_size12);
*/

	UnhookKernelApi(DbgkCopyProcessDebugPort, pslp_head_n_byte2, pslp_patch_size2);



	UnhookKernelApi(DbgkOpenProcessDebugPort, pslp_head_n_byte4, pslp_patch_size4);

/*
	UnhookKernelApi(DbgkUnMapViewOfSection, pslp_head_n_byte5, pslp_patch_size5);

	UnhookKernelApi(DbgkMapViewOfSection, pslp_head_n_byte6, pslp_patch_size6);*/

/*
	UnhookKernelApi(DbgkExitThread, pslp_head_n_byte7, pslp_patch_size7);
	UnhookKernelApi(DbgkExitProcess, pslp_head_n_byte8, pslp_patch_size8);*/
	UnhookKernelApi(DbgkpQueueMessage, pslp_head_n_byte11, pslp_patch_size11);

	/*irq = WPOFFx64();
	memcpy(KiDispatchException + 0x241, Irgcode, 2);
	//_InterlockedExchange16(KiDispatchException + 0x241, 0x850f);
	WPONx64(irq);*/
	unload();
}