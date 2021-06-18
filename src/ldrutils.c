#include "ldrutils.h"

BOOL IsValidPE(
    PBYTE pbData
)
{
    PIMAGE_NT_HEADERS pNtHeaders;

    pNtHeaders = RVA(
        PIMAGE_NT_HEADERS, 
        pbData, 
        ((PIMAGE_DOS_HEADER)pbData)->e_lfanew
    );

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    return TRUE;
}

BOOL MapSections(
    PDARKMODULE pdModule
)
{
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_BASE_RELOCATION pRelocation;
    PIMAGE_SECTION_HEADER pSectionHeader;

    pNtHeaders = RVA(
        PIMAGE_NT_HEADERS, 
        pdModule->pbDllData, 
        ((PIMAGE_DOS_HEADER)pdModule->pbDllData)->e_lfanew
    );

    // try get prefered address
    pdModule->ModuleBase = (ULONG_PTR)VirtualAlloc(
        (LPVOID)(pNtHeaders->OptionalHeader.ImageBase),
        (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!pdModule->ModuleBase)
    {
        pdModule->ModuleBase = (ULONG_PTR)VirtualAlloc(
            0,
            (SIZE_T)pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
    }

    if (!pdModule->ModuleBase)
    {
        return FALSE;
    }

    // copy across the headers
    for (INT i = 0; i < pNtHeaders->OptionalHeader.SizeOfHeaders; i++)
    {
        ((PBYTE)pdModule->ModuleBase)[i] = ((PBYTE)pdModule->pbDllData)[i];
    }

    // copy across the sections
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (INT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
    {
        for (INT j = 0; j < pSectionHeader->SizeOfRawData; j++)
        {
            ((PBYTE)(pdModule->ModuleBase + pSectionHeader->VirtualAddress))[j] = ((PBYTE)(pdModule->pbDllData + pSectionHeader->PointerToRawData))[j];
        }
    }

    // if we havent got our prefered base address, relocate
    ULONG_PTR pulBaseOffset = pdModule->ModuleBase - pNtHeaders->OptionalHeader.ImageBase;
    pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if ((pdModule->ModuleBase - pNtHeaders->OptionalHeader.ImageBase) && pDataDir)
    {
        pRelocation = RVA(
            PIMAGE_BASE_RELOCATION, 
            pdModule->ModuleBase, 
            pDataDir->VirtualAddress
        );

        do
        {
            PIMAGE_RELOC pRelocList = (PIMAGE_RELOC)(pRelocation + 1);

            do
            {
                if (pRelocList->type == IMAGE_REL_BASED_DIR64)
                {
                    *(PULONG_PTR)((PBYTE)pdModule->ModuleBase + pRelocation->VirtualAddress + pRelocList->offset) += pulBaseOffset;
                }
                else if (pRelocList->type == IMAGE_REL_BASED_HIGHLOW)
                {
                    *(PULONG_PTR)((PBYTE)pdModule->ModuleBase + pRelocation->VirtualAddress + pRelocList->offset) += (DWORD)pulBaseOffset;
                }
                else if (pRelocList->type == IMAGE_REL_BASED_HIGH)
                {
                    *(PULONG_PTR)((PBYTE)pdModule->ModuleBase + pRelocation->VirtualAddress + pRelocList->offset) += HIWORD(pulBaseOffset);
                }
                else if (pRelocList->type == IMAGE_REL_BASED_LOW)
                {
                    *(PULONG_PTR)((PBYTE)pdModule->ModuleBase + pRelocation->VirtualAddress + pRelocList->offset) += LOWORD(pulBaseOffset);
                }

                pRelocList++;

            } while ((PBYTE)pRelocList != (PBYTE)pRelocation + pRelocation->SizeOfBlock);

            pRelocation = (PIMAGE_BASE_RELOCATION)pRelocList;

        } while (pRelocation->VirtualAddress);
    }

    return TRUE;
}

BOOL ResolveImports(
    PDARKMODULE pdModule
)
{
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_DELAYLOAD_DESCRIPTOR pDelayDesc;
    PIMAGE_THUNK_DATA pFirstThunk, pOrigFirstThunk;

    STRING aString = { 0 };
    LDRGETPROCADDRESS pLdrGetProcAddress = NULL;

    pNtHeaders = RVA(
        PIMAGE_NT_HEADERS, 
        pdModule->pbDllData, 
        ((PIMAGE_DOS_HEADER)pdModule->pbDllData)->e_lfanew
    );

    pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    pLdrGetProcAddress = (LDRGETPROCADDRESS)GetProcAddress(
        IsModulePresent(L"ntdll.dll"),
        "LdrGetProcedureAddress"
    );

    if (!pLdrGetProcAddress)
    {
        return FALSE;
    }

    // handle the import table
    if (pDataDir->Size)
    {
        pImportDesc = RVA(
            PIMAGE_IMPORT_DESCRIPTOR, 
            pdModule->ModuleBase, 
            pDataDir->VirtualAddress
        );

        DWORD dwImportCount = 0;

        for (; pImportDesc->Name; pImportDesc++)
        {
            dwImportCount++;
        }

        pImportDesc = RVA(
            PIMAGE_IMPORT_DESCRIPTOR,
            pdModule->ModuleBase, 
            pDataDir->VirtualAddress
        );

        for (; pImportDesc->Name; pImportDesc++)
        {
            // use LoadLibraryA for the time being.
            // make this recursive in the future.
            HMODULE hLibrary = LoadLibraryA(
                (LPSTR)(pdModule->ModuleBase + pImportDesc->Name)
            );

            pFirstThunk = RVA(
                PIMAGE_THUNK_DATA, 
                pdModule->ModuleBase, 
                pImportDesc->FirstThunk
            );
            
            pOrigFirstThunk = RVA(
                PIMAGE_THUNK_DATA, 
                pdModule->ModuleBase, 
                pImportDesc->OriginalFirstThunk
            );

            for (; pOrigFirstThunk->u1.Function; pFirstThunk++, pOrigFirstThunk++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigFirstThunk->u1.Ordinal))
                {
                    pLdrGetProcAddress(
                        hLibrary, 
                        NULL, 
                        (WORD)pOrigFirstThunk->u1.Ordinal, 
                        (PVOID *)&(pFirstThunk->u1.Function)
                    );
                }
                else
                {
                    pImportByName = RVA(
                        PIMAGE_IMPORT_BY_NAME, 
                        pdModule->ModuleBase, 
                        pOrigFirstThunk->u1.AddressOfData
                    );
                    
                    FILL_STRING(
                        aString, 
                        pImportByName->Name
                    );

                    pLdrGetProcAddress(
                        hLibrary, 
                        &aString, 
                        0, 
                        (PVOID *)&(pFirstThunk->u1.Function)
                    );
                }
            }
        }
    }

    // handle the delayed import table
    pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    if (pDataDir->Size)
    {
        pDelayDesc = RVA(
            PIMAGE_DELAYLOAD_DESCRIPTOR, 
            pdModule->ModuleBase, 
            pDataDir->VirtualAddress
        );

        for (; pDelayDesc->DllNameRVA; pDelayDesc++)
        {
            // use LoadLibraryA for the time being.
            // make this recursive in the future.
            HMODULE hLibrary = LoadLibraryA((LPSTR)(pdModule->ModuleBase + pDelayDesc->DllNameRVA));

            pFirstThunk = RVA(
                PIMAGE_THUNK_DATA, 
                pdModule->ModuleBase, 
                pDelayDesc->ImportAddressTableRVA
            );
            
            pOrigFirstThunk = RVA(
                PIMAGE_THUNK_DATA, 
                pdModule->ModuleBase, 
                pDelayDesc->ImportNameTableRVA
            );

            for (; pOrigFirstThunk->u1.Function; pFirstThunk++, pOrigFirstThunk++)
            {
                if (IMAGE_SNAP_BY_ORDINAL(pOrigFirstThunk->u1.Ordinal))
                {
                    pLdrGetProcAddress(
                        hLibrary, 
                        NULL, 
                        (WORD)pOrigFirstThunk->u1.Ordinal, 
                        (PVOID *)&(pFirstThunk->u1.Function)
                    );
                }
                else
                {
                    pImportByName = RVA(
                        PIMAGE_IMPORT_BY_NAME, 
                        pdModule->ModuleBase, 
                        pOrigFirstThunk->u1.AddressOfData
                    );
                    
                    FILL_STRING(
                        aString, 
                        pImportByName->Name
                    );

                    pLdrGetProcAddress(
                        hLibrary, 
                        &aString, 
                        0, 
                        (PVOID *)&(pFirstThunk->u1.Function)
                    );
                }
            }
        }
    }

    return TRUE;
}

BOOL BeginExecution(
    PDARKMODULE pdModule
)
{
    DWORD dwProtect;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_TLS_DIRECTORY pTlsDir;
    PIMAGE_DATA_DIRECTORY pDataDir;
    PIMAGE_TLS_CALLBACK* ppCallback;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pFuncEntry;

    DLLMAIN DllMain = NULL;

    pNtHeaders = RVA(
        PIMAGE_NT_HEADERS, 
        pdModule->pbDllData, 
        ((PIMAGE_DOS_HEADER)pdModule->pbDllData)->e_lfanew
    );

    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (INT i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
    {
        if (pSectionHeader->SizeOfRawData)
        {
            // what protections should it have
            DWORD dwExecutable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            DWORD dwReadable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            DWORD dwWriteable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            if (!dwExecutable && !dwReadable && !dwWriteable) { dwProtect = PAGE_NOACCESS; }
            else if (!dwExecutable && !dwReadable && dwWriteable) { dwProtect = PAGE_WRITECOPY; }
            else if (!dwExecutable && dwReadable && !dwWriteable) { dwProtect = PAGE_READONLY; }
            else if (!dwExecutable && dwReadable && dwWriteable) { dwProtect = PAGE_READWRITE; }
            else if (dwExecutable && !dwReadable && !dwWriteable) { dwProtect = PAGE_EXECUTE; }
            else if (dwExecutable && !dwReadable && dwWriteable) { dwProtect = PAGE_EXECUTE_WRITECOPY; }
            else if (dwExecutable && dwReadable && !dwWriteable) { dwProtect = PAGE_EXECUTE_READ; }
            else if (dwExecutable && dwReadable && dwWriteable) { dwProtect = PAGE_EXECUTE_READWRITE; }

            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
            {
                dwProtect |= PAGE_NOCACHE;
            }

            VirtualProtect(
                (LPVOID)(pdModule->ModuleBase + pSectionHeader->VirtualAddress),
                pSectionHeader->SizeOfRawData,
                dwProtect,
                &dwProtect
            );
        }
    }

    // flush the instruction cache
    FlushInstructionCache((HANDLE)-1, NULL, 0);

    // execute the TLS callbacks
    pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (pDataDir->Size)
    {
        pTlsDir = RVA(
            PIMAGE_TLS_DIRECTORY, 
            pdModule->ModuleBase, 
            pDataDir->VirtualAddress
        );

        ppCallback = (PIMAGE_TLS_CALLBACK *)(pTlsDir->AddressOfCallBacks);

        for (; *ppCallback; ppCallback++)
        {
            (*ppCallback)((LPVOID)pdModule->ModuleBase, DLL_PROCESS_ATTACH, NULL);
        }
    }

    // on x64 register the exception handlers
    // #ifdef _WIN64
    //     pDataDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    //     if (pDataDir->Size)
    //     {
    //         pFuncEntry = RVA(
    //             PIMAGE_RUNTIME_FUNCTION_ENTRY, 
    //             pdModule->ModuleBase, 
    //             pDataDir->VirtualAddress
    //         );

    //         RtlAddFunctionTable(
    //             (PRUNTIME_FUNCTION)pFuncEntry,
    //             (pDataDir->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)) - 1,
    //             pdModule->ModuleBase
    //         );
    //     }
    // #endif

    // call the image entry point
    DllMain = RVA(
        DLLMAIN,
        pdModule->ModuleBase,
        pNtHeaders->OptionalHeader.AddressOfEntryPoint
    );

    DllMain(
        (HINSTANCE)pdModule->ModuleBase,
        DLL_PROCESS_ATTACH,
        (LPVOID)NULL
    );

    return TRUE;
}