#pragma once
#include <windows.h>

typedef struct _DARKMODULE {
    BOOL      bSuccess;
	LPWSTR	  ErrorMsg;
	PBYTE	  pbDllData;
	DWORD	  dwDllDataLen;
	LPWSTR    LocalDLLName;
	PWCHAR 	  CrackedDLLName;
    ULONG_PTR ModuleBase;
} DARKMODULE, *PDARKMODULE;
