#include <stdio.h>
#include <windows.h>

#include "pebutils.h"
#include "darkloadlibrary.h"

typedef DWORD (WINAPI * _ThisIsAFunction) (LPCWSTR);

VOID main()
{
	GETPROCESSHEAP pGetProcessHeap = (GETPROCESSHEAP)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetProcessHeap");
	HEAPFREE pHeapFree = (HEAPFREE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapFree");

	PDARKMODULE DarkModule = DarkLoadLibrary(
		LOAD_LOCAL_FILE,
		L".\\amsi.dll",
		NULL,
		0,
		NULL
	);

	if (!DarkModule->bSuccess)
	{
		printf("load failed: %S\n", DarkModule->ErrorMsg);
		pHeapFree(pGetProcessHeap(), 0, DarkModule->ErrorMsg);
		pHeapFree(pGetProcessHeap(), 0, DarkModule);
		return;
	}

	_ThisIsAFunction ThisIsAFunction = (_ThisIsAFunction)GetFunctionAddress(
		(HMODULE)DarkModule->ModuleBase,
		"CallThisFunction"
	);
	pHeapFree(pGetProcessHeap(), 0, DarkModule);

	if (!ThisIsAFunction)
	{
		printf("failed to find it\n");
		return;
	}

    ThisIsAFunction(L"this is working!!!");

	return;
}