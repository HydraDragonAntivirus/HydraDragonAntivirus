#include "Regedit.h"
#include "DriverData.h"
#include "KernelCommon.h"
#include <ntstrsafe.h>

// FIX (Bug #1): ZwOpenKey / ZwQueryValueKey must NEVER be called directly
// inside a CmRegisterCallback pre-notification. Doing so causes the registry
// subsystem to fire another RegNtPreOpenKey / RegNtPreQueryValueKey callback
// on the same thread, re-entering this function while the registry lock is
// still held. In checked/debug Windows builds CmQueryValueKey validates the
// caller-supplied UNICODE_STRING against internal state and fires
// DbgBreakPointWithStatus(STATUS_INVALID_VALUE) when it finds the re-entrant
// call's UNICODE_STRING inconsistent — producing the 80000003 int 3 break.
//
// Fix: queue the backup work to a system worker thread via IoQueueWorkItem.
// Worker threads run outside the CmCallback context, so ZwOpenKey and
// ZwQueryValueKey are safe there.
//
// Requirement: g_DeviceObject must be set to your DEVICE_OBJECT* during
// DriverEntry before CmRegisterCallback is called.
extern PDEVICE_OBJECT g_DeviceObject;

typedef struct _REG_BACKUP_WORK_CTX {
    PIO_WORKITEM  WorkItem;
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    ULONGLONG      Gid;
    BOOLEAN        IsDeletion;
    WCHAR          KeyPathBuffer[MAX_FILE_NAME_LENGTH];
    WCHAR          ValueNameBuffer[MAX_FILE_NAME_LENGTH];
} REG_BACKUP_WORK_CTX, *PREG_BACKUP_WORK_CTX;

static VOID RegMarkBackupThread(VOID);
static VOID RegUnmarkBackupThread(VOID);
static BOOLEAN RegIsBackupThread(VOID);

static IO_WORKITEM_ROUTINE RegBackupWorkRoutine;
static VOID RegBackupWorkRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PREG_BACKUP_WORK_CTX ctx = (PREG_BACKUP_WORK_CTX)Context;
    if (!ctx) return;

    if (!driverData)
    {
        IoFreeWorkItem(ctx->WorkItem);
        ExFreePoolWithTag(ctx, REG_TAG);
        return;
    }

    // Safe to call ZwOpenKey / ZwQueryValueKey here — we are NOT inside a
    // CmCallback, so no recursive callback re-entry can occur.
    //
    // Mark this thread so RegistryCallback knows to skip processing any
    // callbacks our Zw* calls trigger (prevents ObQueryNameString being called
    // on transient KCB state → STATUS_INVALID_VALUE in debug kernels).
    RegMarkBackupThread();

    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &ctx->KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    NTSTATUS openStatus = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &objAttr);
    if (NT_SUCCESS(openStatus))
    {
        ULONG resultLength = 0;
        const ULONG kDataMax = 1024;
        PKEY_VALUE_PARTIAL_INFORMATION pValueInfo =
            (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                sizeof(KEY_VALUE_PARTIAL_INFORMATION) + kDataMax,
                REG_TAG);
        if (pValueInfo)
        {
            NTSTATUS queryStatus = ZwQueryValueKey(
                hKey, &ctx->ValueName, KeyValuePartialInformation,
                pValueInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + kDataMax, &resultLength);
            if (NT_SUCCESS(queryStatus) && pValueInfo->DataLength <= kDataMax)
            {
                PREGISTRY_BACKUP_ENTRY backup = new REGISTRY_BACKUP_ENTRY();
                if (backup)
                {
                    backup->Gid        = ctx->Gid;
                    backup->IsDeletion = ctx->IsDeletion;
                    backup->Type       = pValueInfo->Type;
                    backup->DataSize   = pValueInfo->DataLength;
                    RtlCopyMemory(backup->RegistryData, pValueInfo->Data, pValueInfo->DataLength);
                    RtlStringCbCopyW(backup->KeyPath, sizeof(backup->KeyPath), ctx->KeyPath.Buffer);

                    USHORT valNameLen = 0;
                    if (ctx->ValueName.Buffer && ctx->ValueName.Length > 0)
                    {
                        valNameLen = (USHORT)min(ctx->ValueName.Length,
                                                 sizeof(backup->ValueName) - sizeof(WCHAR));
                        RtlCopyMemory(backup->ValueName, ctx->ValueName.Buffer, valNameLen);
                    }
                    backup->ValueName[valNameLen / sizeof(WCHAR)] = L'\0';
                    driverData->AddRegistryBackup(backup);
                }
            }
            ExFreePoolWithTag(pValueInfo, REG_TAG);
        }
        ZwClose(hKey);
    }

    IoFreeWorkItem(ctx->WorkItem);
    RegUnmarkBackupThread();
    ExFreePoolWithTag(ctx, REG_TAG);
}

// Helper: allocate and queue a deferred registry-backup work item.
// KeyPath and ValueName are deep-copied into the context so the caller's
// buffers can be freed immediately after this returns.
static VOID QueueRegistryBackup(
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_ ULONGLONG Gid,
    _In_ BOOLEAN IsDeletion)
{
    if (!g_DeviceObject) return;

    PREG_BACKUP_WORK_CTX ctx = (PREG_BACKUP_WORK_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(REG_BACKUP_WORK_CTX), REG_TAG);
    if (!ctx) return;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Gid        = Gid;
    ctx->IsDeletion = IsDeletion;

    // Deep-copy KeyPath
    SIZE_T pathChars = min(KeyPath->Length / sizeof(WCHAR), (SIZE_T)(MAX_FILE_NAME_LENGTH - 1));
    RtlCopyMemory(ctx->KeyPathBuffer, KeyPath->Buffer, pathChars * sizeof(WCHAR));
    ctx->KeyPathBuffer[pathChars] = L'\0';
    ctx->KeyPath.Buffer        = ctx->KeyPathBuffer;
    ctx->KeyPath.Length        = (USHORT)(pathChars * sizeof(WCHAR));
    ctx->KeyPath.MaximumLength = (USHORT)((pathChars + 1) * sizeof(WCHAR));

    // Deep-copy ValueName (optional)
    if (ValueName && ValueName->Buffer && ValueName->Length > 0)
    {
        SIZE_T valChars = min(ValueName->Length / sizeof(WCHAR), (SIZE_T)(MAX_FILE_NAME_LENGTH - 1));
        RtlCopyMemory(ctx->ValueNameBuffer, ValueName->Buffer, valChars * sizeof(WCHAR));
        ctx->ValueNameBuffer[valChars] = L'\0';
        ctx->ValueName.Buffer        = ctx->ValueNameBuffer;
        ctx->ValueName.Length        = (USHORT)(valChars * sizeof(WCHAR));
        ctx->ValueName.MaximumLength = (USHORT)((valChars + 1) * sizeof(WCHAR));
    }
    else
    {
        RtlInitUnicodeString(&ctx->ValueName, L"");
    }

    ctx->WorkItem = IoAllocateWorkItem(g_DeviceObject);
    if (!ctx->WorkItem)
    {
        ExFreePoolWithTag(ctx, REG_TAG);
        return;
    }

    IoQueueWorkItem(ctx->WorkItem, RegBackupWorkRoutine, DelayedWorkQueue, ctx);
}

// =============================================================================
// SELF-CALL GUARD
//
// When RegBackupWorkRoutine calls ZwOpenKey / ZwQueryValueKey, RegistryCallback
// fires again on the same worker thread. The inner RegNtPreQueryValueKey case
// calls GetNameForRegistryObject → ObQueryNameString on the key object. On
// checked / debug kernels, ObQueryNameString → CmObQueryNameInfo can call
// DbgBreakPointWithStatus(STATUS_INVALID_VALUE) if the KCB is in a transient
// state during the ongoing Zw* call (e.g. NameLength == 0 on the root KCB path).
//
// Fix: track each backup work-item thread by its PETHREAD pointer. At the top of
// RegistryCallback, bail out immediately if the current thread is one of ours.
// This also eliminates the redundant 64 KB non-paged pool alloc + ObQueryNameString
// that would otherwise run for every Zw* call the work item makes.
// =============================================================================

#define REG_MAX_BACKUP_THREADS 8

static PETHREAD  g_BackupWorkThreads[REG_MAX_BACKUP_THREADS];
static KSPIN_LOCK g_BackupWorkLock;
// Initialized to 0 by the BSS linker segment; KeInitializeSpinLock writes 0 too,
// so calling it in RegeditDriverEntry() is sufficient.

static VOID RegMarkBackupThread(VOID)
{
    KIRQL irql;
    PETHREAD current = PsGetCurrentThread();
    KeAcquireSpinLock(&g_BackupWorkLock, &irql);
    for (int i = 0; i < REG_MAX_BACKUP_THREADS; ++i)
    {
        if (g_BackupWorkThreads[i] == NULL)
        {
            g_BackupWorkThreads[i] = current;
            break;
        }
    }
    KeReleaseSpinLock(&g_BackupWorkLock, irql);
}

static VOID RegUnmarkBackupThread(VOID)
{
    KIRQL irql;
    PETHREAD current = PsGetCurrentThread();
    KeAcquireSpinLock(&g_BackupWorkLock, &irql);
    for (int i = 0; i < REG_MAX_BACKUP_THREADS; ++i)
    {
        if (g_BackupWorkThreads[i] == current)
        {
            g_BackupWorkThreads[i] = NULL;
            break;
        }
    }
    KeReleaseSpinLock(&g_BackupWorkLock, irql);
}

static BOOLEAN RegIsBackupThread(VOID)
{
    KIRQL irql;
    BOOLEAN found = FALSE;
    PETHREAD current = PsGetCurrentThread();
    KeAcquireSpinLock(&g_BackupWorkLock, &irql);
    for (int i = 0; i < REG_MAX_BACKUP_THREADS; ++i)
    {
        if (g_BackupWorkThreads[i] == current)
        {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_BackupWorkLock, irql);
    return found;
}

static BOOLEAN UnicodeContainsString(
    _In_ PUNICODE_STRING SourceUp,
    _In_ PCWSTR PatternUp
)
{
    if (!SourceUp || !SourceUp->Buffer || SourceUp->Length == 0 || !PatternUp)
        return FALSE;

    ULONG srcChars = SourceUp->Length / sizeof(WCHAR);
    ULONG patChars = (ULONG)wcslen(PatternUp);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = SourceUp->Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], PatternUp, patChars * sizeof(WCHAR)))
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOLEAN IsRegistryPathProtected(PUNICODE_STRING RegPath)
{
    if (!RegPath || !RegPath->Buffer || RegPath->Length == 0)
        return FALSE;

    UNICODE_STRING pathUp;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&pathUp, RegPath, TRUE)))
        return FALSE;

    BOOLEAN protectedPath = FALSE;

    if (UnicodeContainsString(&pathUp, L"\\SERVICES\\OWLYSHIELD_RANSOM") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\REDDBG") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\HYPERDBG") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\HYPERHV") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\SANCTUM_PPL_RUNNER") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\MBRFILTER") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\FS_MINIFILTER") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\SANCTUM") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\EDRDRV") ||
        UnicodeContainsString(&pathUp, L"\\SERVICES\\EDRSVC") ||
        UnicodeContainsString(&pathUp, L"\\SOFTWARE\\OWLYSHIELD"))
    {
        protectedPath = TRUE;
    }

    RtlFreeUnicodeString(&pathUp);
    return protectedPath;
}

typedef struct _REGISTRY_HIVE_MAP_ENTRY {
    PCWSTR UserPrefix;
    SIZE_T UserPrefixLen;
    PCWSTR KernelPrefix;
} REGISTRY_HIVE_MAP_ENTRY;

static const REGISTRY_HIVE_MAP_ENTRY kRegistryHiveMap[] = {
    { L"HKLM\\", 5, L"\\REGISTRY\\MACHINE\\" },
    { L"HKCU\\", 5, L"\\REGISTRY\\USER\\" },
    { L"HKCR\\", 5, L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES\\" },
    { L"HKCC\\", 5, L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT\\" },
    { L"HKU\\", 4, L"\\REGISTRY\\USER\\" },
};

// Global
LARGE_INTEGER Cookie;

#ifndef REGEDIT_MONITOR_VERBOSE_NOTIFICATIONS
#define REGEDIT_MONITOR_VERBOSE_NOTIFICATIONS 0
#endif

static BOOLEAN ShouldMonitorVerboseRegistryNotifications()
{
    return (REGEDIT_MONITOR_VERBOSE_NOTIFICATIONS != 0);
}

static BOOLEAN AppendRegistryPathComponent(
    _Inout_ PUNICODE_STRING RegistryPath,
    _In_opt_ PUNICODE_STRING Component)
{
    if (RegistryPath == NULL || RegistryPath->Buffer == NULL)
    {
        return FALSE;
    }

    if (Component == NULL || Component->Buffer == NULL || Component->Length == 0)
    {
        return TRUE;
    }

    if (RegistryPath->Length > 0 &&
        RegistryPath->Buffer[(RegistryPath->Length / sizeof(WCHAR)) - 1] != L'\\')
    {
        if (!NT_SUCCESS(RtlAppendUnicodeToString(RegistryPath, L"\\")))
        {
            return FALSE;
        }
    }

    return NT_SUCCESS(RtlAppendUnicodeStringToString(RegistryPath, Component));
}

// Helper functions (Internal)
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

    pRegistryPath->Length = 0;

    if (!pRegistryObject)
        return FALSE;

    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    ULONG ReturnLen = 0;
    POBJECT_NAME_INFORMATION NameInfo = NULL;
    BOOLEAN success = FALSE;

    __try
    {
        // First call to get required length.
        Status = ObQueryNameString(pRegistryObject, NULL, 0, &ReturnLen);
        if (Status != STATUS_INFO_LENGTH_MISMATCH || ReturnLen == 0)
        {
            __leave;
        }

        NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, ReturnLen, REG_TAG);
        if (!NameInfo)
        {
            __leave;
        }

        RtlZeroMemory(NameInfo, ReturnLen);

        Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
        if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
        {
            __leave;
        }

        if (NameInfo->Name.Length >= pRegistryPath->MaximumLength)
        {
            __leave;
        }

        RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);
        pRegistryPath->Buffer[pRegistryPath->Length / sizeof(WCHAR)] = L'\0';
        success = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        success = FALSE;
    }

    if (NameInfo)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
    }

    return success;
}

BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || Source->Length == 0 || !Pattern)
        return FALSE;

    UNICODE_STRING srcUp = { 0 }, patUp = { 0 };
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, Pattern);

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, Source, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &pat, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcChars = srcUp.Length / sizeof(WCHAR);
    ULONG patChars = patUp.Length / sizeof(WCHAR);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patChars * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

_Success_(return != FALSE) static BOOLEAN
 NormalizeRegistryAlertPath(_In_ PUNICODE_STRING SourcePath, _Out_writes_(OutBufferChars) PWCHAR OutBuffer,
                               _In_ SIZE_T OutBufferChars, _Out_ PUSHORT OutLength)
{
    if (OutBuffer == NULL || OutBufferChars == 0 || OutLength == NULL)
    {
        return FALSE;
    }

    OutBuffer[0] = L'\0';
    *OutLength = 0;

    if (SourcePath == NULL || SourcePath->Buffer == NULL || SourcePath->Length == 0)
    {
        return FALSE;
    }

    // RtlStringCchCopyNW is fully SAL-annotated — the analyzer understands
    // its bounds contract and will not fire C6386 on it.
    NTSTATUS st = RtlStringCchCopyNW(OutBuffer, OutBufferChars, SourcePath->Buffer, SourcePath->Length / sizeof(WCHAR));
    if (!NT_SUCCESS(st) && st != STATUS_BUFFER_OVERFLOW)
        return FALSE;
    // STATUS_BUFFER_OVERFLOW is acceptable: RtlStringCchCopyNW still null-terminates
    // the output and copies as many characters as fit — truncation is intentional here.

    // Fix up forward slashes in-place on the already-bounded, null-terminated buffer.
    for (PWCHAR p = OutBuffer; *p != L'\0'; ++p)
    {
        if (*p == L'/')
            *p = L'\\';
    }

    // ObQueryNameString returns kernel-namespace paths (\REGISTRY\MACHINE\...).
    // Convert to user-friendly form (HKLM\...) so the usermode consumer can
    // display and match them without knowing kernel prefixes.
    // Walk the map longest-KernelPrefix first to prefer the more specific
    // HKCR / HKCC entries over the bare HKLM match.
    for (ULONG i = 0; i < RTL_NUMBER_OF(kRegistryHiveMap); ++i)
    {
        SIZE_T kernelPrefixLen = wcslen(kRegistryHiveMap[i].KernelPrefix);
        if (_wcsnicmp(OutBuffer, kRegistryHiveMap[i].KernelPrefix, kernelPrefixLen) == 0)
        {
            WCHAR friendlyBuffer[MAX_FILE_NAME_LENGTH] = {0};
            PCWSTR subpath = OutBuffer + kernelPrefixLen;
            NTSTATUS status = RtlStringCchCopyW(friendlyBuffer, RTL_NUMBER_OF(friendlyBuffer),
                                                kRegistryHiveMap[i].UserPrefix);
            if (!NT_SUCCESS(status))
            {
                return FALSE;
            }

            status = RtlStringCchCatW(friendlyBuffer, RTL_NUMBER_OF(friendlyBuffer), subpath);
            if (!NT_SUCCESS(status))
            {
                return FALSE;
            }

            status = RtlStringCchCopyW(OutBuffer, OutBufferChars, friendlyBuffer);
            if (!NT_SUCCESS(status))
            {
                return FALSE;
            }
            break;
        }
    }

    *OutLength = (USHORT)(wcsnlen(OutBuffer, OutBufferChars) * sizeof(WCHAR));
    return TRUE;
}

static BOOLEAN BuildRegistryOpenPath(_Inout_ PUNICODE_STRING RegistryPath,
                                     _In_opt_ PVOID RootObject,
                                     _In_opt_ PUNICODE_STRING CompleteName)
{
    if (RegistryPath == NULL || RegistryPath->Buffer == NULL || RegistryPath->MaximumLength == 0)
    {
        return FALSE;
    }

    RegistryPath->Length = 0;

    if (CompleteName == NULL || CompleteName->Buffer == NULL || CompleteName->Length == 0)
    {
        return FALSE;
    }

    BOOLEAN hasRootPath = FALSE;
    if (RootObject != NULL)
    {
        hasRootPath = GetNameForRegistryObject(RegistryPath, RootObject);
    }

    if (!hasRootPath || CompleteName->Buffer[0] == L'\\')
    {
        if (CompleteName->Length > RegistryPath->MaximumLength)
        {
            return FALSE;
        }

        RtlCopyUnicodeString(RegistryPath, CompleteName);
        return TRUE;
    }

    if (RegistryPath->Length > 0 &&
        RegistryPath->Buffer[(RegistryPath->Length / sizeof(WCHAR)) - 1] != L'\\')
    {
        if (RegistryPath->Length + sizeof(WCHAR) > RegistryPath->MaximumLength)
        {
            return FALSE;
        }

        if (!NT_SUCCESS(RtlAppendUnicodeToString(RegistryPath, L"\\")))
        {
            return FALSE;
        }
    }

    if (RegistryPath->Length + CompleteName->Length > RegistryPath->MaximumLength)
    {
        return FALSE;
    }

    return NT_SUCCESS(RtlAppendUnicodeStringToString(RegistryPath, CompleteName));
}

VOID SendRegistryAlert(PUNICODE_STRING RegPath, PCWSTR Operation, HANDLE Pid, UCHAR RegOp)
{
    if (!driverData) return;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (!newEntry) return;

    // Set PID
    newEntry->data.PID = (ULONG)(ULONG_PTR)Pid;

    // Look up GID
    BOOLEAN isGidFound = FALSE;
    ULONGLONG gid = driverData->GetProcessGid(newEntry->data.PID, &isGidFound);
    if (gid != 0 && isGidFound) {
        newEntry->data.Gid = gid;
    }

    // Set Code
    newEntry->data.IRP_OP = IRP_REGISTRY;
    newEntry->data.FileChange = RegOp;

    // Check if the registry path is protected under self-defense/anti-tamper rules
    if (IsRegistryPathProtected(RegPath)) {
        newEntry->data.FileLocationInfo = FILE_PROTECTED;
    } else {
        newEntry->data.FileLocationInfo = FILE_NOT_PROTECTED;
    }

    // Copy Path
    if (RegPath && RegPath->Buffer) {
        if (NormalizeRegistryAlertPath(RegPath, newEntry->Buffer, RTL_NUMBER_OF(newEntry->Buffer),
                                       &newEntry->filePath.Length))
        {
            // FIX (Bug B): filePath.Buffer was never set. A UNICODE_STRING with
            // Length > 0 and Buffer == NULL is invalid: any downstream code that
            // calls RtlCopyUnicodeString or validates the string will crash or
            // fire an assertion. filePath must point to the same Buffer array
            // that NormalizeRegistryAlertPath wrote into.
            newEntry->filePath.Buffer = newEntry->Buffer;
            newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
        }
    }

    // Copy Operation to Extension
    RtlStringCbCopyW(newEntry->data.Extension, sizeof(newEntry->data.Extension), Operation);

    // Add to the driver queue; if enqueue ever fails, free the entry to avoid a leak.
    if (!driverData->AddIrpMessage(newEntry)) {
        
#if IS_DEBUG_IRP
DbgPrint("!!! Regedit: Failed to enqueue registry event for PID %lu\n",
                 newEntry->data.PID);
#endif

        delete newEntry;
    }
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    // Allocate local buffer on stack or pool? Regedit.c used Pool.
    // Creating temp buffer on new operator is cleaner for C++ or ExAllocatePool.
    // Use ExAllocatePool for safety.
    //
    // FIX (Bug #3): The original 1024-WCHAR buffer is too small for long registry
    // paths. After GetNameForRegistryObject fills the buffer with a long key path,
    // appending L"\\" + ValueName can overflow it.
    //
    // UNICODE_STRING.MaximumLength is a USHORT, so 65536 bytes (32768 WCHARs) does
    // not fit. The largest safe even size is 65534 bytes, i.e. 32767 WCHARs.
    constexpr USHORT REGPATH_MAX_BYTES = 0xFFFE;  // 65534 bytes, fits in USHORT

    RegPath.MaximumLength = REGPATH_MAX_BYTES;
    RegPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, REGPATH_MAX_BYTES, REG_TAG);
    
    if (!RegPath.Buffer) return Status;
    RegPath.Length = 0;

    // Self-call guard: if the current thread is our own backup work item thread,
    // skip all processing. Our Zw* calls would otherwise trigger RegNtPreOpenKey /
    // RegNtPreQueryValueKey, causing GetNameForRegistryObject → ObQueryNameString
    // on a KCB that is mid-operation, which fires STATUS_INVALID_VALUE in debug kernels.
    if (RegIsBackupThread())
    {
        ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
        return STATUS_SUCCESS;
    }

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Get current PID
    HANDLE hPid = PsGetCurrentProcessId();

    __try
    {
        switch (NotifyClass)
        {
        case RegNtPreDeleteValueKey:
        {
            PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object && pInfo->ValueName)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    // FIX (Bug #1): Calling ZwOpenKey / ZwQueryValueKey directly here
                    // caused recursive CmCallback re-entry → STATUS_INVALID_VALUE int 3.
                    // Defer the backup to a system worker thread via QueueRegistryBackup.
                    if (driverData)
                    {
                        BOOLEAN isGidFound = FALSE;
                        ULONGLONG gid = driverData->GetProcessGid((ULONG)(ULONG_PTR)hPid, &isGidFound);
                        if (isGidFound)
                        {
                            PUNICODE_STRING safeValueName =
                                (pInfo->ValueName && pInfo->ValueName->Buffer) ? pInfo->ValueName : NULL;
                            QueueRegistryBackup(&RegPath, safeValueName, gid, TRUE /*IsDeletion*/);
                        }
                    }


                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        if (!NT_SUCCESS(RtlAppendUnicodeToString(&RegPath, L"\\")) ||
                            !NT_SUCCESS(RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName)))
                        {
                            
#if IS_DEBUG_IRP
DbgPrint("RegPath append failed: buffer too small\n");
#endif

                            break;
                        }
                    }

                    if (TRUE) // Monitor all registry deletions
                    {
                        SendRegistryAlert(&RegPath, L"DELETE_VALUE", hPid, REG_DELETE_VALUE);               
                    }
                }
            }
            break;
        }
        case RegNtPreDeleteKey:
        {
            PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"DELETE_KEY", hPid, REG_DELETE_KEY); // FIX (Bug #2): was REG_DELETE_VALUE
                    }
                }
            }
            break;
        }
        case RegNtPreSetValueKey:
        {
             PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object && pInfo->ValueName)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    // FIX (Bug #1): Same recursive re-entry hazard as in RegNtPreDeleteValueKey.
                    // Defer backup to a worker thread.
                    if (driverData)
                    {
                        BOOLEAN isGidFound = FALSE;
                        ULONGLONG gid = driverData->GetProcessGid((ULONG)(ULONG_PTR)hPid, &isGidFound);
                        if (isGidFound)
                        {
                            PUNICODE_STRING safeValueName =
                                (pInfo->ValueName && pInfo->ValueName->Buffer) ? pInfo->ValueName : NULL;
                            QueueRegistryBackup(&RegPath, safeValueName, gid, FALSE /*IsDeletion*/);
                        }
                    }

                    if (!AppendRegistryPathComponent(&RegPath, pInfo->ValueName))
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("RegPath append failed: buffer too small\n");
#endif

                        break;
                    }

                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"SET_VALUE", hPid, REG_SET_VALUE);
                    }
                }
            }
            break;
        }
        case RegNtPreRenameKey:
        {
            PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"RENAME_KEY", hPid, REG_RENAME_KEY);
                    }
                }
            }
            break;
        }
        case RegNtPreOpenKey:
        {
            PREG_OPEN_KEY_INFORMATION pInfo = (PREG_OPEN_KEY_INFORMATION)Argument2;
            if (pInfo && BuildRegistryOpenPath(&RegPath, pInfo->RootObject, pInfo->CompleteName))
            {
                if (ShouldMonitorVerboseRegistryNotifications())
                {
                    SendRegistryAlert(&RegPath, L"OPEN_KEY", hPid, REG_OPEN_KEY); // FIX (Bug #2): was REG_QUERY_VALUE
                }
            }
            break;
        }
        case RegNtPreOpenKeyEx:
        {
            PREG_OPEN_KEY_INFORMATION_V1 pInfo = (PREG_OPEN_KEY_INFORMATION_V1)Argument2;
            if (pInfo && BuildRegistryOpenPath(&RegPath, pInfo->RootObject, pInfo->CompleteName))
            {
                if (ShouldMonitorVerboseRegistryNotifications())
                {
                    SendRegistryAlert(&RegPath, L"OPEN_KEY_EX", hPid, REG_OPEN_KEY); // FIX (Bug #2): was REG_QUERY_VALUE
                }
            }
            break;
        }
        case RegNtPreQueryValueKey:
        {
            PREG_QUERY_VALUE_KEY_INFORMATION pInfo = (PREG_QUERY_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (!AppendRegistryPathComponent(&RegPath, pInfo->ValueName))
                    {
                        
#if IS_DEBUG_IRP
DbgPrint("RegPath append failed: buffer too small\n");
#endif

                        break;
                    }

                    if (ShouldMonitorVerboseRegistryNotifications())
                    {
                        SendRegistryAlert(&RegPath, L"QUERY_VALUE", hPid, REG_QUERY_VALUE);
                    }
                }
            }
            break;
        }
        case RegNtPreQueryKey:
        {
            PREG_QUERY_KEY_INFORMATION pInfo = (PREG_QUERY_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (ShouldMonitorVerboseRegistryNotifications())
                    {
                        SendRegistryAlert(&RegPath, L"QUERY_KEY", hPid, REG_QUERY_KEY); // FIX (Bug #2): was REG_QUERY_VALUE
                    }
                }
            }
            break;
        }
        case RegNtPreEnumerateKey:
        {
            PREG_ENUMERATE_KEY_INFORMATION pInfo = (PREG_ENUMERATE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (ShouldMonitorVerboseRegistryNotifications())
                    {
                        SendRegistryAlert(&RegPath, L"ENUM_KEY", hPid, REG_ENUM_KEY); // FIX (Bug #2): was REG_QUERY_VALUE
                    }
                }
            }
            break;
        }
        case RegNtPreEnumerateValueKey:
        {
            PREG_ENUMERATE_VALUE_KEY_INFORMATION pInfo = (PREG_ENUMERATE_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (ShouldMonitorVerboseRegistryNotifications())
                    {
                        SendRegistryAlert(&RegPath, L"ENUM_VALUE", hPid, REG_ENUM_VALUE); // FIX (Bug #2): was REG_QUERY_VALUE
                    }
                }
            }
            break;
        }
        case RegNtPreSetKeySecurity:
        {
            PREG_SET_KEY_SECURITY_INFORMATION pInfo = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (ShouldMonitorVerboseRegistryNotifications())
                    {
                        SendRegistryAlert(&RegPath, L"SET_SECURITY", hPid, REG_SET_VALUE);
                    }
                }
            }
            break;
        }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        
#if IS_DEBUG_IRP
DbgPrint("!!! Regedit: exception in RegistryCallback (class=%d, PID=%lu)\n",
                 (int)(ULONG_PTR)Argument1, (ULONG)(ULONG_PTR)hPid);
#endif

    }

    if (RegPath.Buffer) ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}

NTSTATUS RegeditDriverEntry()
{
    KeInitializeSpinLock(&g_BackupWorkLock);

    NTSTATUS status = CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    if (NT_SUCCESS(status))
    {
        
#if IS_DEBUG_IRP
DbgPrint("[Registry-Protection] Initialized successfully\r\n");
#endif

    }
    return status;
}

NTSTATUS RegeditUnloadDriver()
{
    if (Cookie.QuadPart != 0)
    {
        CmUnRegisterCallback(Cookie);
        Cookie.QuadPart = 0;
    }
    return STATUS_SUCCESS;
}
