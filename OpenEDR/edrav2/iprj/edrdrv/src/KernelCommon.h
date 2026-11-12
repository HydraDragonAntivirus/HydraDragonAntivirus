#pragma once

#include <fltKernel.h>

#include "SharedDefs.h"
#include "PoolTags.h"

//#define DEBUG_IRP
#ifdef DEBUG_IRP
    #define IS_DEBUG_IRP 1
#else
    #define IS_DEBUG_IRP 0
#endif  // DEBUG_IRP

// PID_ENTRY - for each process in the system we record, we get its pid and image file, those are stord in thi struct
// the struct is meant to be used in blist (LIST_ENTRY)
typedef struct _PID_ENTRY {
    LIST_ENTRY entry;
    PUNICODE_STRING Path;
    ULONG Pid;
    BOOLEAN IsAcgEnabled;
    _PID_ENTRY() {
        Pid = 0;
        Path = nullptr;
        IsAcgEnabled = FALSE;
        entry.Flink = nullptr;
        entry.Blink = nullptr;
    }

    void* operator new(size_t size) {
        void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, OWLY_POOL_TAG_PID_ENTRY);
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void* ptr) {
        ExFreePoolWithTag(ptr, OWLY_POOL_TAG_PID_ENTRY);
    }

    //fixme needs new and delete operator, dtor
} PID_ENTRY, *PPID_ENTRY;

typedef struct _DIRECTORY_ENTRY {
    LIST_ENTRY entry;
    WCHAR path[MAX_FILE_NAME_LENGTH];
    _DIRECTORY_ENTRY() {
        InitializeListHead(&entry);
        path[0] = L'\0';
    }

    void* operator new(size_t size) {
        void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, OWLY_POOL_TAG_DIRECTORY_ENTRY);
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void* ptr) {
        ExFreePoolWithTag(ptr, OWLY_POOL_TAG_DIRECTORY_ENTRY);
    }

} DIRECTORY_ENTRY, *PDIRECTORY_ENTRY;

typedef struct _IRP_ENTRY {
    LIST_ENTRY entry;
    DRIVER_MESSAGE data;
    UNICODE_STRING
        filePath;  // keep path to unicode string related to the object, we copy it later to user
    WCHAR Buffer[MAX_FILE_NAME_LENGTH];  // unicode string buffer for file name

    _IRP_ENTRY() {
        InitializeListHead(&entry);
        filePath.Length = 0;
        filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        filePath.Buffer = Buffer;
        RtlZeroBytes(Buffer, MAX_FILE_NAME_SIZE);
        data.next = nullptr;
        data.IRP_OP = IRP_NONE;
        data.MemSizeUsed = 0;
        data.isEntropyCalc = FALSE;
        data.FileChange = FILE_CHANGE_NOT_SET;
        data.FileLocationInfo = FILE_NOT_PROTECTED;
    }

    void* operator new(size_t size) {
        void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, OWLY_POOL_TAG_IRP_ENTRY);
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void* ptr) {
        ExFreePoolWithTag(ptr, OWLY_POOL_TAG_IRP_ENTRY);
    }

} IRP_ENTRY, *PIRP_ENTRY;

void* __cdecl operator new(size_t size);

void __cdecl operator delete(void* data, size_t size);

void __cdecl operator delete(void* data);

NTSTATUS CopyWString(LPWSTR dest, LPCWSTR source, size_t size);

WCHAR* stristr(const WCHAR* String, const WCHAR* Pattern);

BOOLEAN startsWith(PUNICODE_STRING String, PWCHAR Pattern);

// GID_ENTRY - for each gid in the system we record, holds pids entries (PID_ENTRY)
// the struct is meant to be used in blist (LIST_ENTRY)
struct GID_ENTRY {
    LIST_ENTRY GidListEntry;
    ULONGLONG gid;
    ULONGLONG pidsSize;
    LIST_ENTRY HeadListPids;
    BOOLEAN IsMalicious;

    // gid as input
    GID_ENTRY(ULONGLONG Gid) {
        gid = Gid;
        InitializeListHead(&HeadListPids);
        InitializeListHead(&GidListEntry);
        pidsSize = 0;
        IsMalicious = FALSE;
    }

    //copy
    GID_ENTRY(const GID_ENTRY& a) {
        HeadListPids.Flink = a.HeadListPids.Flink;
        HeadListPids.Blink = a.HeadListPids.Blink;
        GidListEntry.Flink = a.GidListEntry.Flink;
        GidListEntry.Blink = a.GidListEntry.Blink;
        gid = a.gid;
        pidsSize = a.pidsSize;
        IsMalicious = a.IsMalicious;
    }

    const GID_ENTRY& operator=(const GID_ENTRY& a) {
        HeadListPids.Flink = a.HeadListPids.Flink;
        HeadListPids.Blink = a.HeadListPids.Blink;
        GidListEntry.Flink = a.GidListEntry.Flink;
        GidListEntry.Blink = a.GidListEntry.Blink;
        gid = a.gid;
        pidsSize = a.pidsSize;
        IsMalicious = a.IsMalicious;
        return *this;
    }

    void* operator new(size_t size) {
        void* ptr = ExAllocatePoolWithTag(NonPagedPool, size, OWLY_POOL_TAG_GID_ENTRY);
        if (size && ptr != nullptr)
            memset(ptr, 0, size);
        return ptr;
    }

    void operator delete(void* ptr) {
        ExFreePoolWithTag(ptr, OWLY_POOL_TAG_GID_ENTRY);
    }
};

typedef GID_ENTRY* PGID_ENTRY;

// A registry value as it was before a user-mode process set or deleted it
// (regmon.cpp, pre-operation callbacks), so the process's changes can be
// reverted when it is killed as ransomware (MESSAGE_REVERT_REGISTRY_CHANGES).
// One allocation: the key path, value name and data follow the struct.
// Allocated and freed by DriverData (AllocRegistryBackup / FreeRegistryBackup).
typedef struct _REGISTRY_BACKUP_ENTRY
{
    LIST_ENTRY list;
    ULONG Pid;                 // process that changed the value
    ULONG Ancestors[8];        // its creator chain then, nearest first: the revert
    ULONG AncestorCount;       // of a killed process includes its descendants
    ULONGLONG NameHash;        // of key path + value name, case-insensitive
    BOOLEAN ValueExisted;      // FALSE: the process created it, revert deletes it
    BOOLEAN IsKeyDelete;       // the whole key was deleted: Data holds its values
                               // as REGISTRY_KEY_VALUE_RECORDs, ValueName is empty
    ULONG Type;
    ULONG DataSize;
    UNICODE_STRING KeyPath;    // \REGISTRY\..., NUL-terminated
    UNICODE_STRING ValueName;  // NUL-terminated, empty for the default value
    PUCHAR Data;
} REGISTRY_BACKUP_ENTRY, * PREGISTRY_BACKUP_ENTRY;

// One value of a deleted key in REGISTRY_BACKUP_ENTRY::Data (IsKeyDelete),
// followed by NameBytes of name and DataSize of data. Unaligned: copy it out.
typedef struct _REGISTRY_KEY_VALUE_RECORD
{
    USHORT NameBytes;
    ULONG Type;
    ULONG DataSize;
} REGISTRY_KEY_VALUE_RECORD;
