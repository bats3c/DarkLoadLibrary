#include <stdio.h>
#include <windows.h>

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
typedef void(__cdecl* _WSPLITPATH)(const wchar_t* _FullPath, wchar_t* _Drive, wchar_t* _Dir, wchar_t* _Filename, wchar_t* _Ext);
typedef wchar_t*(_cdecl* WCSCPY)(wchar_t* Dest, const wchar_t* _Source);
typedef wchar_t* (__cdecl* WCSCAT)(wchar_t* _dst, const wchar_t* __src);

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