#include "ntddk.h"

typedef struct{

	struct  ProcessList * up;
	HANDLE processID;
	
	struct  ProcessList * dw;

}ProcessList, *PProcessList;