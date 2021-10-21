#include <windows.h>
#include <malloc.h>

#include "pebstructs.h"
#include "darkloadlibrary.h"

#define FILL_STRING(string, buffer) \
    string.Length = (USHORT)strlen(buffer); \
    string.MaximumLength = string.Length; \
    string.Buffer = buffer

typedef NTSTATUS(WINAPI* LDRGETPROCADDRESS)(HMODULE, PANSI_STRING, WORD, PVOID*);
typedef VOID(WINAPI* RTLRBINSERTNODEEX)(_In_ PRTL_RB_TREE Tree, _In_opt_ PRTL_BALANCED_NODE Parent, _In_ BOOLEAN Right, _Out_ PRTL_BALANCED_NODE Node);
typedef VOID(NTAPI* RTLINITUNICODESTRING)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef NTSTATUS(NTAPI* NTQUERYSYSTEMTIME)(PLARGE_INTEGER SystemTime);
typedef NTSTATUS(NTAPI* RTLHASHUNICODESTRING)(UNICODE_STRING* String, BOOLEAN CaseInSensitive, ULONG HashAlgorithm, ULONG* HashValue);
typedef SIZE_T(NTAPI* RTLCOMPAREMEMORY)(const VOID* Source1, const VOID* Source2, SIZE_T Length);
typedef int(__cdecl* _WCSNICMP)(const wchar_t* _Str1, const wchar_t* _Str2, size_t _MaxCount);
typedef int(__cdecl* STRCMP)(const char* _Str1, const char* _Str2);
typedef int(WINAPI *MULTIBYTETOWIDECHAR)(
    UINT   CodePage,
    DWORD  dwFlags,
    LPCCH  lpMultiByteStr,
    int    cbMultiByte,
    LPWSTR lpWideCharStr,
    int    cchWideChar
);
typedef int(__cdecl* _WCSICMP)(const wchar_t* _Str1, const wchar_t* _Str2);

#ifdef _WIN64
    #define PEB_OFFSET 0x60
    #define READ_MEMLOC __readgsqword 
#else
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword 
#endif

#pragma once
#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
#define RtlInitializeListEntry(entry) ((entry)->Blink = (entry)->Flink = (entry))

#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

#define LDR_HASH_TABLE_ENTRIES 32

NTSYSAPI NTSTATUS NTAPI RtlHashUnicodeString(__in PCUNICODE_STRING String, __in BOOLEAN CaseInSensitive, __in ULONG HashAlgorithm, __out PULONG HashValue);
NTSYSAPI VOID NTAPI RtlRbInsertNodeEx(_In_ PRTL_RB_TREE Tree, _In_opt_ PRTL_BALANCED_NODE Parent, _In_ BOOLEAN Right, _Out_ PRTL_BALANCED_NODE Node);

HMODULE IsModulePresent(LPCWSTR lpwName);
HMODULE IsModulePresentA(char* Name);
BOOL LinkModuleToPEB(PDARKMODULE pdModule);
PVOID GetFunctionAddress(HMODULE hModule, char*  ProcName);
BOOL LocalLdrGetProcedureAddress(HMODULE hLibrary, PANSI_STRING ProcName, WORD Ordinal, PVOID* FunctionAddress);
BOOL _LocalLdrGetProcedureAddress(HMODULE hLibrary, PANSI_STRING ProcName, WORD Ordinal, PVOID* FunctionAddress);