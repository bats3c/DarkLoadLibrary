#include "darkloadlibrary.h"

BOOL ParseFileName(
	PDARKMODULE pdModule,
	LPWSTR lpwFileName
)
{
	if (lpwFileName == NULL)
	{
		pdModule->ErrorMsg = L"Invalid filename";
		return FALSE;
	}

	pdModule->LocalDLLName = lpwFileName;

	HANDLE hHeap = GetProcessHeap();
	if (!hHeap)
	{
		pdModule->ErrorMsg = L"Failed to find valid heap";
		return FALSE;
	}

	pdModule->CrackedDLLName = (PWCHAR)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH * 2
	);

	PWCHAR lpwExt = (PWCHAR)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH
	);

	PWCHAR lpwFilename = (PWCHAR)HeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH
	);

	if (!pdModule->CrackedDLLName || !lpwExt || !lpwFilename)
	{
		pdModule->ErrorMsg = L"Failed to allocate memory";
		return FALSE;
	}

	_wsplitpath(
        lpwFileName,
        NULL,
        NULL,
        lpwFilename,
        lpwExt
    );

	if (lpwFilename == NULL || lpwExt == NULL)
	{
		pdModule->ErrorMsg = L"Failed to crack filename";
		return FALSE;
	}

	PCHAR lpCpy = wcscpy(
		pdModule->CrackedDLLName,
		lpwFilename
	);
    
	PCHAR lpCat = wcscat(
		pdModule->CrackedDLLName,
		lpwExt
	);

	if (!lpCpy || !lpCat)
	{
		pdModule->ErrorMsg = L"Failed to format cracked path";
		return FALSE;
	}

	return TRUE;
}

BOOL ReadFileToBuffer(
	PDARKMODULE pdModule
)
{
	HANDLE hFile = CreateFileW(
        pdModule->LocalDLLName,
        GENERIC_READ, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        NULL, 
        OPEN_EXISTING, 
        0, 
        NULL
    );

	if (hFile == INVALID_HANDLE_VALUE)
    {
        pdModule->ErrorMsg = L"Failed to open local DLL file";
		return FALSE;
    }

	DWORD dwSize = GetFileSize(
		hFile,
		NULL
	);

	if (dwSize == INVALID_FILE_SIZE)
    {
        pdModule->ErrorMsg = L"Failed to get DLL file size";
		return FALSE;
    }

	pdModule->pbDllData = VirtualAlloc(
        NULL, 
        dwSize, 
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_READWRITE
    );

	if (pdModule->pbDllData == NULL)
	{
		pdModule->ErrorMsg = L"Failed to allocate memory for DLL data";
		return FALSE;
	}

	if (!ReadFile(
        hFile, 
        pdModule->pbDllData, 
        dwSize, 
        &pdModule->dwDllDataLen, 
        NULL))
    {
        pdModule->ErrorMsg = L"Failed to read data from DLL file";
		return FALSE;
    }

	if (!CloseHandle(hFile))
    {
        pdModule->ErrorMsg = L"Failed to close handle on DLL file";
		return FALSE;
    }

	return TRUE;
}

DARKMODULE DarkLoadLibrary(
	DWORD   dwFlags,
	LPCWSTR lpwBuffer,
	DWORD   dwLen,
	LPCWSTR lpwName
)
{
	DARKMODULE dModule;

	dModule.bSuccess = FALSE;

	// get the DLL data into memory, whatever the format it's in
	switch (dwFlags)
	{
	case LOAD_LOCAL_FILE:
		if (!ParseFileName(&dModule, lpwBuffer) || !ReadFileToBuffer(&dModule))
		{
			goto Cleanup;
		}
		break;

	case LOAD_MEMORY:
		dModule.ErrorMsg = L"Not implemented yet, sorry";
		goto Cleanup;
		break;

	case NO_LINK:
		dModule.ErrorMsg = L"Not implemented yet, sorry";
		goto Cleanup;
		break;

	default:
		break;
	}

	// is there a module with the same name already loaded
	if (lpwName == NULL)
	{
		lpwName = dModule.CrackedDLLName;
	}

	HMODULE hModule = IsModulePresent(
		lpwName
	);

	if (hModule != NULL)
	{
		dModule.ModuleBase = hModule;
		dModule.bSuccess = TRUE;

		goto Cleanup;
	}

	// make sure the PE we are about to load is valid
	if (!IsValidPE(dModule.pbDllData))
	{
		dModule.ErrorMsg = L"Data is an invalid PE";
		goto Cleanup;
	}

	// map the sections into memory
	if (!MapSections(&dModule))
	{
		dModule.ErrorMsg = L"Failed to map sections";
		goto Cleanup;
	}

	// handle the import tables
	if (!ResolveImports(&dModule))
	{
		dModule.ErrorMsg = L"Failed to resolve imports";
		goto Cleanup;
	}

	// link the module to the PEB
	if (!LinkModuleToPEB(&dModule))
	{
		dModule.ErrorMsg = L"Failed to link module to PEB";
		goto Cleanup;
	}

	// trigger tls callbacks, set permissions and call the entry point
	if (!BeginExecution(&dModule))
	{
		dModule.ErrorMsg = L"Failed to execute";
		goto Cleanup;
	}

	dModule.bSuccess = TRUE;

	goto Cleanup;

	Cleanup:
		return dModule;
}

BOOL ConcealLibrary(
	PDARKMODULE pdModule,
	BOOL bConceal
)
{
	// TODO: implement this function

	pdModule->ErrorMsg = L"Not implemented yet, sorry";

	return FALSE;
}

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