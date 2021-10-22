#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "Shlwapi.lib")

#define LOAD_LOCAL_FILE  0x00000001
#define LOAD_REMOTE_FILE 0x00000002
#define LOAD_MEMORY		 0x00000003
#define NO_LINK			 0x00010000

typedef LPVOID(WINAPI* HEAPALLOC)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef HANDLE(WINAPI* GETPROCESSHEAP)(VOID);
typedef HANDLE(WINAPI* CREATEFILEW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef DWORD(WINAPI* GETFILESIZE)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef BOOL(WINAPI* READFILE)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
typedef BOOL(WINAPI* CLOSEHANDLE)(HANDLE hObject);
typedef BOOL(WINAPI* HEAPFREE)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
typedef LPCWSTR(WINAPI *PATHFINDFILENAMEW)(LPCWSTR pszPath);
typedef int(__cdecl *WSPRINTFW)(LPWSTR, LPCWSTR, ...);

#pragma once
typedef struct _DARKMODULE {
    BOOL      bSuccess;
	LPWSTR	  ErrorMsg;
	PBYTE	  pbDllData;
	DWORD	  dwDllDataLen;
	LPWSTR    LocalDLLName;
	PWCHAR CrackedDLLName;
    ULONG_PTR ModuleBase;
	BOOL		bLinkedToPeb;
} DARKMODULE, *PDARKMODULE;

PDARKMODULE DarkLoadLibrary(
	DWORD   dwFlags,
	LPCWSTR lpwBuffer,
	LPVOID	lpFileBuffer,
	DWORD   dwLen,
	LPCWSTR lpwName
);

SIZE_T WideStringLength(LPWSTR str);
BOOL WideStringCompare(LPWSTR lpwStr1, LPWSTR lpwStr2, SIZE_T cbMaxCount);