#include "ntddk.h"
typedef struct _StackFrame{
	ULONG64 ERRORCODE;
	ULONG64 rip;
	ULONG64 cs;
	ULONG64 rflags;
	ULONG64 rsp;
	ULONG64 ss;

}StackFrame, *PStackFrame;