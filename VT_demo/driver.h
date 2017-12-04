// This file is part of Virtdbg
// Copyright (C) 2010-2011 Damien AUMAITRE

//  Licence is GPLv3, see LICENCE.txt in the top-level directory


#include <ntddk.h>



NTSTATUS PsLookupProcessByProcessId(
	_In_ HANDLE ProcessId,
	_Out_ PEPROCESS *Process);




