#include "ntddk.h"
BOOLEAN R3_HideMem(PEPROCESS Process, ULONG64 Address, PVOID Code, ULONG Size);
BOOLEAN R3_UnHideMem(ULONG64 Address,ULONG64 Eprocess);
VOID InitialzeR3EPTHOOK();
