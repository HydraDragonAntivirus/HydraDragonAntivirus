#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>

#define REG_TAG 'gkER'

// Paths to protect (kept for reference; active protection is in regmon.cpp rules)
#define REG_PROTECT_SUBPATH L"\\SOFTWARE\\Owlyshield"
#define REG_PROTECT_OWLY L"\\Services\\owlyshield_ransom"
#define REG_PROTECT_SANCTUM L"\\Services\\sanctum_ppl_runner"
#define REG_PROTECT_MBRFILTER L"\\Services\\MBRFilter"

// Lifecycle
// RegeditDriverEntry: initializes backup spin lock only.
// CmRegisterCallback is NOT called — regmon.cpp owns the registry callback.
NTSTATUS RegeditDriverEntry();
NTSTATUS RegeditUnloadDriver();

// Deferred registry value backup (for fidye-yazilimi rollback via
// driverData->RevertRegistryChangesForGid).
// Can be called from regmon.cpp's notifyOnRegistryActions to snapshot
// values before delete/overwrite operations.
VOID QueueRegistryBackupPublic(
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_ ULONGLONG Gid,
    _In_ BOOLEAN IsDeletion);
