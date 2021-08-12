#include "darkloadlibrary.h"
#include "ldrutils.h"

BOOL ParseFileName(
	PDARKMODULE pdModule,
	LPWSTR lpwFileName
)
{
	HEAPALLOC pHeapAlloc = (HEAPALLOC)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapAlloc");
	GETPROCESSHEAP pGetProcessHeap = (GETPROCESSHEAP)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetProcessHeap");
	_WSPLITPATH p_wsplitpath = (_WSPLITPATH)GetFunctionAddress(IsModulePresent(L"ucrtbased.dll"), "_wsplitpath");
	WCSCPY pwcscpy = (WCSCPY)GetFunctionAddress(IsModulePresent(L"ucrtbased.dll"), "wcscpy");
	WCSCAT pwcscat = (WCSCAT)GetFunctionAddress(IsModulePresent(L"ucrtbased.dll"), "wcscat");

	if (lpwFileName == NULL)
	{
		pdModule->ErrorMsg = L"Invalid filename";
		return FALSE;
	}

	pdModule->LocalDLLName = lpwFileName;

	HANDLE hHeap = pGetProcessHeap();
	if (!hHeap)
	{
		pdModule->ErrorMsg = L"Failed to find valid heap";
		return FALSE;
	}

	pdModule->CrackedDLLName = (PWCHAR)pHeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH * 2
	);

	PWCHAR lpwExt = (PWCHAR)pHeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH
	);

	PWCHAR lpwFilename = (PWCHAR)pHeapAlloc(
		hHeap,
		HEAP_ZERO_MEMORY,
		MAX_PATH
	);

	if (!pdModule->CrackedDLLName || !lpwExt || !lpwFilename)
	{
		pdModule->ErrorMsg = L"Failed to allocate memory";
		return FALSE;
	}

	p_wsplitpath(
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

	PCHAR lpCpy = (PCHAR)pwcscpy(
		pdModule->CrackedDLLName,
		lpwFilename
	);
    
	PCHAR lpCat = (PCHAR)pwcscat(
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
	HEAPALLOC pHeapAlloc = (HEAPALLOC)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapAlloc");
	CREATEFILEW pCreateFileW = (CREATEFILEW)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "CreateFileW");
	VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "VirtualAlloc");
	GETFILESIZE pGetFileSize = (GETFILESIZE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetFileSize");
	READFILE pReadFile = (READFILE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "ReadFile");
	CLOSEHANDLE pCloseHandle = (CLOSEHANDLE)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "CloseHandle");

	HANDLE hFile = pCreateFileW(
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

	DWORD dwSize = pGetFileSize(
		hFile,
		NULL
	);

	if (dwSize == INVALID_FILE_SIZE)
    {
        pdModule->ErrorMsg = L"Failed to get DLL file size";
		return FALSE;
    }

	pdModule->pbDllData = pVirtualAlloc(
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

	if (!pReadFile(
        hFile, 
        pdModule->pbDllData, 
        dwSize, 
        &pdModule->dwDllDataLen, 
        NULL))
    {
        pdModule->ErrorMsg = L"Failed to read data from DLL file";
		return FALSE;
    }

	if (!pCloseHandle(hFile))
    {
        pdModule->ErrorMsg = L"Failed to close handle on DLL file";
		return FALSE;
    }

	return TRUE;
}

PDARKMODULE DarkLoadLibrary(
	DWORD   dwFlags,
	LPCWSTR lpwBuffer,
	LPVOID	lpFileBuffer,
	DWORD   dwLen,
	LPCWSTR lpwName
)
{
	HEAPALLOC pHeapAlloc = (HEAPALLOC)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "HeapAlloc");
	GETPROCESSHEAP pGetProcessHeap = (GETPROCESSHEAP)GetFunctionAddress(IsModulePresent(L"Kernel32.dll"), "GetProcessHeap");
	WCSCAT pwcscat = (WCSCAT)GetFunctionAddress(IsModulePresent(L"ucrtbased.dll"), "wcscat");

	PDARKMODULE dModule = (DARKMODULE*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DARKMODULE));
	if (!dModule)
		return NULL;

	dModule->bSuccess = FALSE;
	dModule->bLinkedToPeb = TRUE;

	// get the DLL data into memory, whatever the format it's in
	switch (LOWORD(dwFlags))
	{
	case LOAD_LOCAL_FILE:
		if (!ParseFileName(dModule, lpwBuffer) || !ReadFileToBuffer(dModule))
		{
			goto Cleanup;
		}
		break;

	case LOAD_MEMORY:
		dModule->dwDllDataLen = dwLen;
		dModule->pbDllData = lpFileBuffer;

		/*
			This is probably a hack for the greater scheme but lol
		*/
		dModule->CrackedDLLName = lpwName;
		dModule->LocalDLLName = lpwName;

		if (lpwName == NULL)
			goto Cleanup;

		break;

	default:
		break;
	}

	if (dwFlags & NO_LINK)
		dModule->bLinkedToPeb = FALSE;

	// is there a module with the same name already loaded
	if (lpwName == NULL)
	{
		lpwName = dModule->CrackedDLLName;
	}

	HMODULE hModule = IsModulePresent(
		lpwName
	);

	if (hModule != NULL)
	{
		dModule->ModuleBase = (ULONG_PTR)hModule;
		dModule->bSuccess = TRUE;

		goto Cleanup;
	}

	// make sure the PE we are about to load is valid
	if (!IsValidPE(dModule->pbDllData))
	{
		dModule->ErrorMsg = (wchar_t*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 500);
		if (!dModule->ErrorMsg)
			goto Cleanup;

		pwcscat(dModule->ErrorMsg, L"Data is an invalid PE: ");
		pwcscat(dModule->ErrorMsg, lpwName);
		goto Cleanup;
	}

	// map the sections into memory
	if (!MapSections(dModule))
	{
		dModule->ErrorMsg = (wchar_t*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 500);
		if (!dModule->ErrorMsg)
			goto Cleanup;

		pwcscat(dModule->ErrorMsg, L"Failed to map sections: ");
		pwcscat(dModule->ErrorMsg, lpwName);
		goto Cleanup;
	}

	// handle the import tables
	if (!ResolveImports(dModule))
	{
		dModule->ErrorMsg = (wchar_t*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 500);
		if (!dModule->ErrorMsg)
			goto Cleanup;

		pwcscat(dModule->ErrorMsg, L"Failed to resolve imports: ");
		pwcscat(dModule->ErrorMsg, lpwName);
		goto Cleanup;
	}

	// link the module to the PEB
	if (dModule->bLinkedToPeb)
	{
		if (!LinkModuleToPEB(dModule))
		{
			dModule->ErrorMsg = (wchar_t*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 500);
			if (!dModule->ErrorMsg)
				goto Cleanup;
			
			pwcscat(dModule->ErrorMsg, L"Failed to link module to PEB: ");
			pwcscat(dModule->ErrorMsg, lpwName);
			goto Cleanup;
		}
	}

	// trigger tls callbacks, set permissions and call the entry point
	if (!BeginExecution(dModule))
	{
		dModule->ErrorMsg = (wchar_t*)pHeapAlloc(pGetProcessHeap(), HEAP_ZERO_MEMORY, 500);
		if (!dModule->ErrorMsg)
			goto Cleanup;

		pwcscat(dModule->ErrorMsg, L"Failed to execute: ");
		pwcscat(dModule->ErrorMsg, lpwName);
		goto Cleanup;
	}

	dModule->bSuccess = TRUE;

	goto Cleanup;

	Cleanup:
		return dModule;
}

BOOL ConcealLibrary(
	PDARKMODULE pdModule,
	BOOL bConceal
)
{
	// TODO: reimplement this function, so it is better

	pdModule->ErrorMsg = L"Not implemented yet, sorry";

	return FALSE;
}