#pragma once
#include "ntddk.h"
#define EPT_READ		0x01
#define EPT_WRIT		0x02
#define EPT_EXECUTE		0x04

typedef struct _MemoryType{
	unsigned	bit0 : 1;
	unsigned	bit1 : 1;
	unsigned	bit2 : 1;
	unsigned	bit3 : 1;
	unsigned	bit4 : 1;
	unsigned	bit5 : 1;
	unsigned	bit6 : 1;
	unsigned	bit7 : 1;
	unsigned	bit8 : 1;
	unsigned	bit9 : 1;
	unsigned	bit10 : 1;
	unsigned	bit11 : 1;
	unsigned	bit12 : 1;
	unsigned	bit13 : 1;
	unsigned	bit14 : 1;
	unsigned	bit15 : 1;
	unsigned	bit16 : 1;
	unsigned	bit17 : 1;
	unsigned	bit18 : 1;
	unsigned	bit19 : 1;
	unsigned	bit20 : 1;
	unsigned	bit21 : 1;
	unsigned	bit22 : 1;
	unsigned	bit23 : 1;
	unsigned	bit24 : 1;
	unsigned	bit25 : 1;
	unsigned	bit26 : 1;
	unsigned	bit27 : 1;
	unsigned	bit28 : 1;
	unsigned	bit29 : 1;
	unsigned	bit30 : 1;
	unsigned	bit31 : 1;
	unsigned	bit32 : 1;
	unsigned	bit33 : 1;
	unsigned	bit34 : 1;
	unsigned	bit35 : 1;
	unsigned	bit36 : 1;
	unsigned	bit37 : 1;
	unsigned	bit38 : 1;
	unsigned	bit39 : 1;
	unsigned	bit40 : 1;
	unsigned	bit41 : 1;
	unsigned	bit42 : 1;
	unsigned	bit43 : 1;
	unsigned	bit44 : 1;
	unsigned	bit45 : 1;
	unsigned	bit46 : 1;
	unsigned	bit47 : 1;
	unsigned	bit48 : 1;
	unsigned	bit49 : 1;
	unsigned	bit50 : 1;
	unsigned	bit51 : 1;
	unsigned	bit52 : 1;
	unsigned	bit53 : 1;
	unsigned	bit54 : 1;
	unsigned	bit55 : 1;
	unsigned	bit56 : 1;
	unsigned	bit57 : 1;
	unsigned	bit58 : 1;
	unsigned	bit59 : 1;
	unsigned	bit60 : 1;
	unsigned	bit61 : 1;
	unsigned	bit62 : 1;
	unsigned	bit63 : 1;

}MemoryType, *pMemoryType;

typedef struct _InveptDescriptor{
	ULONG64		EPTP;
	ULONG64 	Reserve;
}InveptDescriptor, *pInveptDescriptor;

typedef struct _EPTP{
	union{
		struct{
			unsigned	MemType : 3;		// bit0-bit2	
			unsigned	PageWalk : 3;		// bit3-bit5
			unsigned	dirty : 1;		// bit6
			unsigned	reserved : 5;		// bit7-bit11
			unsigned	pml4Pa : 28;	// bit12-bit39
			unsigned	reserved1 : 24;	// bit40-bit63	
		};
		ULONG64	Value;
	};
}EPTP, *P_EPTP;

typedef struct _EPTPML4E{
	union{
		struct{
			unsigned	R : 1;			// bit0
			unsigned	W : 1;			// bit1
			unsigned	E : 1;			// bit2
			unsigned	Reserved : 5;			// bit3-bit7
			unsigned	AccessedFlag : 1;			// bit8
			unsigned	Ignored : 3;			// bit9-bit11
			unsigned	PAGE_PA_39_12 : 28;			// bit12-bit39
			unsigned	Reserved1 : 12;			// bit40-bit51
			unsigned	Ignored1 : 12;			// bit52-bit63
		};
		ULONG64 Value;
	};
}EPTPML4E, *P_EPTPML4E;

typedef struct _EPTPDPTE{
	union{
		struct{
			unsigned	R : 1;			// bit0
			unsigned	W : 1;			// bit1
			unsigned	E : 1;			// bit2
			unsigned	Reserved : 5;			// bit3-bit7
			unsigned	AccessedFlag : 1;			// bit8
			unsigned	Ignored : 3;			// bit9-bit11
			unsigned	PAGE_PA_39_12 : 28;			// bit12-bit39
			unsigned	Reserved1 : 12;			// bit40-bit51
			unsigned	Ignored1 : 12;			// bit52-bit63
		};
		ULONG64 Value;
	};
}EPTPDPTE, *P_EPTPDPTE;

typedef struct _EPTPDE_2MB{
	union{
		struct{
			unsigned	R : 1;				// bit0
			unsigned	W : 1;				// bit1
			unsigned	E : 1;				// bit2
			unsigned	MemType : 3;		// bit3-bit5
			unsigned	IgnorePatMemType : 1;	// bit6
			unsigned	PS : 1;		// bit7
			unsigned	AccesedFlag : 1;		// bit8
			unsigned	DirtyFlag : 1;		// bit9
			unsigned	Ignored : 2;		// bit10-bit11
			unsigned	Reserved : 9;		// bit12-bit20
			unsigned	PAGE_PA_39_21 : 19;	// bit21-bit39
			unsigned	Reserved1 : 12;	// bit40-bit51
			unsigned	Ignored1 : 11;	// bit52-bit62
			unsigned	SuppressVE : 1;		// bit63
		};
		ULONG64 Value;
	};

}EPTPDE_2MB, *P_EPTPDE_2MB;

typedef	struct _EPT_VIOLATION{
	union{
		struct{
			unsigned	R : 1;				// bit0
			unsigned	W : 1;				// bit1
			unsigned	E : 1;				// bit2
			unsigned	PageRead : 1;		// bit3
			unsigned	PageWrite : 1;		// bit4
			unsigned	PageExecute : 1;		// bit5
			unsigned	Reserved : 1;		// bit6
			unsigned	LinearAddrValid : 1;	// bit7
			unsigned	IfBit7 : 1;		// bit8
			unsigned	Reserved1 : 3;		// bit9-bit11
			unsigned	NmiUnblocking : 1;	// bit12
			unsigned	Reserved2 : 19;	//bit13-bit31
		};
		ULONG64	Value;
	};

}EPT_VIOLATION, *P_EPT_VIOLATION;

typedef struct _GUEST_PAGE{
	union{
		struct{
			unsigned	PageOffset : 21;	// 2M	bit0-bit20
			unsigned	PDIndex : 9;		// 		bit21-bit29
			unsigned	PDPTIndex : 9;		// 		bit30-bit38
			unsigned	PML4Index : 9;		//		bit39-bit47
			unsigned	Reserved : 16;
		};
		ULONG64	Value;
	};
}GUEST_PAGE, *P_GUEST_PAGE;

typedef struct _EPT_INFO{
	EPTP				Eptps;
	PHYSICAL_ADDRESS	pPml4PA;
	PVOID			pPml4s;
	PHYSICAL_ADDRESS	pPdptPA;
	PVOID			pPDPTs;
	PHYSICAL_ADDRESS	pPdPA;
	PVOID			pPDs;
}EPT_INFO, *P_EPT_INFO;


