#pragma once
#include <windows.h>
#include <stddef.h>
#include "pebstructs.h"
#include "darkmodule.h"
#include "darkloadlibrary.h"

#ifdef _WIN32
    #define PEB_OFFSET 0x30
    #define READ_MEMLOC __readfsdword 
#endif

#ifdef _WIN64
    #define PEB_OFFSET 0x60
    #define READ_MEMLOC __readgsqword 
#endif

#pragma once
#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
#define RtlInitializeListEntry(entry) ((entry)->Blink = (entry)->Flink = (entry))

#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

#define LDR_HASH_TABLE_ENTRIES 32

HMODULE IsModulePresent(LPCWSTR lpwName);
BOOL LinkModuleToPEB(PDARKMODULE pdModule);
ULONG LdrHashEntry(UNICODE_STRING UniName, BOOL XorHash);
PLDR_DATA_TABLE_ENTRY2 FindLdrTableEntry(
	PCWSTR BaseName
);
PRTL_RB_TREE FindModuleBaseAddressIndex();
BOOL AddBaseAddressEntry(
	PLDR_DATA_TABLE_ENTRY2 pLdrEntry,
	PVOID lpBaseAddr
);
PLIST_ENTRY FindHashTable();
VOID InsertTailList(
	PLIST_ENTRY ListHead,
	PLIST_ENTRY Entry
);
BOOL AddHashTableEntry(
	PLDR_DATA_TABLE_ENTRY2 pLdrEntry
);

NTSTATUS RtlHashUnicodeString(
  PCUNICODE_STRING String,
  BOOLEAN          CaseInSensitive,
  ULONG            HashAlgorithm,
  PULONG           HashValue
);

void RtlRbInsertNodeEx(
    RTL_RB_TREE *Tree, 
    RTL_BALANCED_NODE *Parent, 
    BOOLEAN Right, 
    RTL_BALANCED_NODE *Node
);
