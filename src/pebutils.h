#include <windows.h>

#include "../include/darkloadlibrary"
#include "pebstructs.h"

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

NTSTATUS RtlHashUnicodeString(
  PCUNICODE_STRING String,
  BOOLEAN          CaseInSensitive,
  ULONG            HashAlgorithm,
  PULONG           HashValue
);

VOID RtlRbInsertNodeEx (
    RTL_RB_TREE *Tree, 
    RTL_BALANCED_NODE *Parent, 
    BOOLEAN Right, 
    RTL_BALANCED_NODE *Node);

#define LDRP_IMAGE_DLL 0x00000004
#define LDRP_ENTRY_INSERTED 0x00008000
#define LDRP_ENTRY_PROCESSED 0x00004000
#define LDRP_PROCESS_ATTACH_CALLED 0x00080000

#define LDR_HASH_TABLE_ENTRIES 32

HMODULE IsModulePresent(LPCWSTR lpwName);
BOOL LinkModuleToPEB(PDARKMODULE pdModule);