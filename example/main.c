#include <stdio.h>
#include <windows.h>

#include "darkloadlibrary.h"

typedef DWORD (WINAPI * _ThisIsAFunction) (LPCWSTR);

VOID main()
{
	DARKMODULE dModule = DarkLoadLibrary(
		LOAD_LOCAL_FILE,
		L"P:\\HideUrCLR\\TestDLL\\x64\\Release\\TestDLL.dll",
		0,
		NULL
	);

	if (!dModule.bSuccess)
	{
		printf("load failed: %S\n", dModule.ErrorMsg);
		return;
	}

	printf("Loaded: %S (%d bytes)\n", dModule.CrackedDLLName, dModule.dwDllDataLen);

	_ThisIsAFunction ThisIsAFunction = GetProcAddress(
		dModule.ModuleBase,
		"CallThisFunction"
	);

	if (!ThisIsAFunction)
	{
		printf("failed to find it\n");
		return;
	}

    ThisIsAFunction(L"this is working!!!");

	return;
}