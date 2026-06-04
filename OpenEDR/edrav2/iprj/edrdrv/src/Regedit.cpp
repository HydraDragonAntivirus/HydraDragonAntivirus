#include "Regedit.h"
#include "DriverData.h"
#include "common.h"
#include <ntstrsafe.h>

// Registry telemetry (CmRegisterCallback / RegistryCallback) has been removed.
// OpenEDR's regmon.cpp already registers its own CmCallback and emits all
// registry events via the native LBVS fltport path.  Duplicating that callback
// here caused double-reporting and unnecessary overhead.
//
// What remains:
//   - QueueRegistryBackup / RegBackupWorkRoutine  – deferred value snapshot
//     used by driverData->AddRegistryBackup() for fidye-yazılımı rollback.
//   - RegeditDriverEntry / RegeditUnloadDriver   – stubs kept for link compat.
//
// Requirement: g_DeviceObject must be set before RegeditDriverEntry() is called.
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
            (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool,
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

static VOID QueueRegistryBackup(
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_ ULONGLONG Gid,
    _In_ BOOLEAN IsDeletion)
{
    if (!g_DeviceObject) return;

    PREG_BACKUP_WORK_CTX ctx = (PREG_BACKUP_WORK_CTX)ExAllocatePoolWithTag(NonPagedPool, sizeof(REG_BACKUP_WORK_CTX), REG_TAG);
    if (!ctx) return;

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Gid        = Gid;
    ctx->IsDeletion = IsDeletion;

    SIZE_T pathChars = min(KeyPath->Length / sizeof(WCHAR), (SIZE_T)(MAX_FILE_NAME_LENGTH - 1));
    RtlCopyMemory(ctx->KeyPathBuffer, KeyPath->Buffer, pathChars * sizeof(WCHAR));
    ctx->KeyPathBuffer[pathChars] = L'\0';
    ctx->KeyPath.Buffer        = ctx->KeyPathBuffer;
    ctx->KeyPath.Length        = (USHORT)(pathChars * sizeof(WCHAR));
    ctx->KeyPath.MaximumLength = (USHORT)((pathChars + 1) * sizeof(WCHAR));

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

// Exported for potential use by other modules (e.g. regmon.cpp integration)
VOID QueueRegistryBackupPublic(
    _In_ PUNICODE_STRING KeyPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_ ULONGLONG Gid,
    _In_ BOOLEAN IsDeletion)
{
    QueueRegistryBackup(KeyPath, ValueName, Gid, IsDeletion);
}

#define REG_MAX_BACKUP_THREADS 8

static PETHREAD   g_BackupWorkThreads[REG_MAX_BACKUP_THREADS];
static KSPIN_LOCK g_BackupWorkLock;

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

// RegeditDriverEntry: initialize spin lock only.
// CmRegisterCallback is intentionally NOT called here — regmon.cpp owns
// the registry callback for telemetry.
NTSTATUS RegeditDriverEntry()
{
    KeInitializeSpinLock(&g_BackupWorkLock);
    return STATUS_SUCCESS;
}

// RegeditUnloadDriver: nothing to unregister (no CmRegisterCallback was called).
NTSTATUS RegeditUnloadDriver()
{
    return STATUS_SUCCESS;
}
