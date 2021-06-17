#include <stdio.h>
#include <windows.h>

#define LOAD_LOCAL_FILE  0x00000001
#define LOAD_REMOTE_FILE 0x00000002
#define LOAD_MEMORY		 0x00000003

#pragma once
typedef struct _DARKMODULE {
    BOOL      bSuccess;
	LPWSTR	  ErrorMsg;
	PBYTE	  pbDllData;
	DWORD	  dwDllDataLen;
	LPWSTR    LocalDLLName;
	PWCHAR 	  CrackedDLLName;
    ULONG_PTR ModuleBase;
} DARKMODULE, *PDARKMODULE;

DARKMODULE DarkLoadLibrary(
	DWORD  dwFlags,
	LPCWSTR lpwBuffer,
	DWORD  dwLen,
	LPCWSTR lpwName
);