#include <stdio.h>
#include <windows.h>

#include "pebutils.h"
#include "darkloadlibrary.h"

typedef DWORD (WINAPI * _ThisIsAFunction) (LPCWSTR);

VOID main()
{
	PDARKMODULE DarkModule = DarkLoadLibrary(
		LOAD_LOCAL_FILE,
		L"TestDLL.dll",
		NULL,
		0,
		NULL
	);

	if (!DarkModule->bSuccess)
	{
		printf("load failed: %S\n", DarkModule->ErrorMsg);
		HeapFree(GetProcessHeap(), 0, DarkModule->ErrorMsg);
		HeapFree(GetProcessHeap(), 0, DarkModule);
		return;
	}

	_ThisIsAFunction ThisIsAFunction = (_ThisIsAFunction)GetFunctionAddress(
		(HMODULE)DarkModule->ModuleBase,
		"CallThisFunction"
	);
	HeapFree(GetProcessHeap(), 0, DarkModule);

	if (!ThisIsAFunction)
	{
		printf("failed to find it\n");
		return;
	}

    ThisIsAFunction(L"this is working!!!");

	return;
}