#include <windows.h>

#include "pebutils.h"
#include "darkloadlibrary.h"

#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)

typedef BOOL(WINAPI * DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);

BOOL IsValidPE(PBYTE pbData);
BOOL MapSections(PDARKMODULE pdModule);
BOOL ResolveImports(PDARKMODULE pdModule);
BOOL LinkModuleToPEB(PDARKMODULE pdModule);
BOOL BeginExecution(PDARKMODULE pdModule);
wchar_t* FindDLLPath(wchar_t* path, wchar_t* libname_w);