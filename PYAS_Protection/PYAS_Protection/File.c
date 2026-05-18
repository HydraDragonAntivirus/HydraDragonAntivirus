// File.c - Self-Defense Protection with User-Mode Alerting (uses CXX_FileProtectX64.h
#include "Driver.h"
#include "Driver_File.h"
#include "Driver_Common.h" // Include common helpers
#include "Driver_Process.h"
#include "ProtectionRules.h"

// globals
PVOID g_CallBackHandle = NULL;
#define ALERT_POOL_TAG 'tlrA'

typedef struct _ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING ProtectedFile;
    UNICODE_STRING AttackingProcessPath;
    HANDLE AttackingPid;
    WCHAR AttackType[64];
} ALERT_WORK_ITEM, * PALERT_WORK_ITEM;

// forward declarations
NTSTATUS ProtectFileByObRegisterCallbacks(VOID);
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
);
VOID SendAlertWorker(PVOID Context);

#define FILE_SELF_DEFENSE_WRITE_MASK (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | \
                                      FILE_DELETE_CHILD | FILE_WRITE_ATTRIBUTES | DELETE | \
                                      WRITE_DAC | WRITE_OWNER)

#define FILE_SELF_DEFENSE_SAFE_ACCESS (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | \
                                       READ_CONTROL | SYNCHRONIZE)

static ACCESS_MASK ExpandFileDesiredAccess(_In_ ACCESS_MASK DesiredAccess)
{
    RtlMapGenericMask(&DesiredAccess, IoGetFileObjectGenericMapping());
    return DesiredAccess;
}

static BOOLEAN HasProtectedFileWriteAccess(_In_ ACCESS_MASK DesiredAccess)
{
    if (DesiredAccess & MAXIMUM_ALLOWED)
        return TRUE;

    ACCESS_MASK expandedAccess = ExpandFileDesiredAccess(DesiredAccess);
    return (expandedAccess & FILE_SELF_DEFENSE_WRITE_MASK) != 0;
}

static ACCESS_MASK RestrictProtectedFileAccess(_In_ ACCESS_MASK DesiredAccess)
{
    if (DesiredAccess & MAXIMUM_ALLOWED)
        return FILE_SELF_DEFENSE_SAFE_ACCESS;

    ACCESS_MASK expandedAccess = ExpandFileDesiredAccess(DesiredAccess);
    if ((expandedAccess & FILE_SELF_DEFENSE_WRITE_MASK) == 0)
        return DesiredAccess;

    ACCESS_MASK restrictedAccess = expandedAccess & ~FILE_SELF_DEFENSE_WRITE_MASK;
    if (restrictedAccess == 0)
        restrictedAccess = FILE_SELF_DEFENSE_SAFE_ACCESS;

    return restrictedAccess;
}

static BOOLEAN IsCurrentProductProcess(VOID)
{
    HANDLE pid = PsGetCurrentProcessId();

    if (IsProcessTrusted(pid) || IsProtectedProcessByPid(pid))
        return TRUE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;

    return IsProtectedProcessByPath(PsGetCurrentProcess());
}

// entry/unload (call from your DriverEntry/DriverUnload)
NTSTATUS FileDriverEntry()
{
    // Do NOT load rule files here. Dynamic rules are pushed later by the
    // user-mode service through IOCTL_HYDRADRAGON_SET_RULES.
    //
    // Also do not patch IoFileObjectType internals. If this OS build does not
    // support file object callbacks, file self-defense must be implemented in
    // the minifilter path instead of forcing undocumented object-type flags.
    NTSTATUS status = ProtectFileByObRegisterCallbacks();

    if (NT_SUCCESS(status)) {
        DbgPrint("[Self-Defense] File object callback initialized\n");
        return STATUS_SUCCESS;
    }

    DbgPrint("[Self-Defense] File object callback unavailable: 0x%X. "
             "Continue without undocumented IoFileObjectType patch; use minifilter for file rules.\n",
             status);

    return STATUS_SUCCESS;
}


VOID FileUnloadDriver()
{
    if (g_CallBackHandle != NULL) {
        ObUnRegisterCallbacks(g_CallBackHandle);
        g_CallBackHandle = NULL;
    }

    CleanupProtectionRules();
    DbgPrint("[Self-Defense] FileDriver Unloaded\n");
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION callBackReg;
    OB_OPERATION_REGISTRATION operationReg;
    NTSTATUS status;

    RtlZeroMemory(&callBackReg, sizeof(callBackReg));
    RtlZeroMemory(&operationReg, sizeof(operationReg));

    callBackReg.Version = ObGetFilterVersion();
    callBackReg.OperationRegistrationCount = 1;
    callBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callBackReg.Altitude, L"321001");

    operationReg.ObjectType = IoFileObjectType;
    operationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)PreCallBack;
    operationReg.PostOperation = NULL;

    callBackReg.OperationRegistration = &operationReg;

    status = ObRegisterCallbacks(&callBackReg, &g_CallBackHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Self-Defense] ObRegisterCallbacks failed: 0x%X\n", status);
    }
    else {
        DbgPrint("[Self-Defense] ObRegisterCallbacks succeeded\n");
    }

    return status;
}

// Helper: get file dos name; returns allocated POBJECT_NAME_INFORMATION in OutNameInfo (must ExFreePool by caller)
BOOLEAN GetFileDosName(PFILE_OBJECT FileObject, POBJECT_NAME_INFORMATION* OutNameInfo)
{
    POBJECT_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS st;

    if (!FileObject || !OutNameInfo) return FALSE;

    // BUGFIX: Avoid STATUS_OBJECT_NAME_NOT_FOUND by filtering out non-disk file objects
    // Check if this is a special file object type (pipe, mailslot, device) that doesn't have a DOS device name
    // These objects don't need protection checks since protected files are disk-based
    if (FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN)) {
        // This is a named pipe or mailslot - skip protection (not a disk file)
        *OutNameInfo = NULL;
        return FALSE;
    }

    // Check if the file object has a valid device object and FileName
    // Objects without proper device/file associations can't be protected files
    if (!FileObject->DeviceObject || !FileObject->FileName.Buffer || FileObject->FileName.Length == 0) {
        *OutNameInfo = NULL;
        return FALSE;
    }

    st = IoQueryFileDosDeviceName(FileObject, &nameInfo);
    if (!NT_SUCCESS(st) || !nameInfo || !nameInfo->Name.Buffer || nameInfo->Name.Length == 0) {
        if (nameInfo) ExFreePool(nameInfo);
        *OutNameInfo = NULL;
        return FALSE;
    }

    *OutNameInfo = nameInfo;
    return TRUE;
}

OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *IoFileObjectType) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PFILE_OBJECT fileObj = (PFILE_OBJECT)OperationInformation->Object;
    if (!fileObj) return OB_PREOP_SUCCESS;

    POBJECT_NAME_INFORMATION nameInfo = NULL;
    if (!GetFileDosName(fileObj, &nameInfo)) {
        return OB_PREOP_SUCCESS;
    }

    UNICODE_STRING fileName = nameInfo->Name;

    // Normalize path to ensure consistency with rules
    NormalizeDevicePathToDos(&fileName);

    BOOLEAN isProtected = IsPathProtectedByType(fileName.Buffer, RuleTypeFile);

    if (isProtected) {
        if (IsCurrentProductProcess())
        {
            ExFreePool(nameInfo);
            return OB_PREOP_SUCCESS;
        }

        PACCESS_MASK desiredAccess = NULL;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            desiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            desiredAccess = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (desiredAccess && HasProtectedFileWriteAccess(*desiredAccess)) {
            HANDLE currentPid = PsGetCurrentProcessId();
            PUNICODE_STRING attackerPath = NULL;
            (VOID)SeLocateProcessImageName(PsGetCurrentProcess(), &attackerPath);

            ACCESS_MASK originalAccess = *desiredAccess;
            ACCESS_MASK restrictedAccess = RestrictProtectedFileAccess(originalAccess);

            if (restrictedAccess != originalAccess)
            {
                *desiredAccess = restrictedAccess;

                if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                    DbgPrint("[SELF-DEFENSE] Stripped CREATE access to: %wZ by PID: %p\n", &fileName, currentPid);
                    QueueAlertToUserMode(&fileName, attackerPath, currentPid, L"FILE_TAMPERING_BLOCKED");
                }
                else {
                    DbgPrint("[SELF-DEFENSE] Stripped DUP access to: %wZ by PID: %p\n", &fileName, currentPid);
                    QueueAlertToUserMode(&fileName, attackerPath, currentPid, L"HANDLE_HIJACK_BLOCKED");
                }
            }

            if (attackerPath) {
                ExFreePool(attackerPath);
                attackerPath = NULL;
            }
        }
    }

    if (nameInfo) {
        ExFreePool(nameInfo);
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS QueueAlertToUserMode(
    PUNICODE_STRING ProtectedFile,
    PUNICODE_STRING AttackingProcessPath,
    HANDLE AttackingPid,
    PCWSTR AttackType
)
{
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ALERT_WORK_ITEM), ALERT_POOL_TAG);
    if (!workItem) {
        DbgPrint("[SELF-DEFENSE] QueueAlert: allocation failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0) {
        USHORT needed = (USHORT)(ProtectedFile->Length + sizeof(WCHAR));
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, ALERT_POOL_TAG);
        if (workItem->ProtectedFile.Buffer) {
            workItem->ProtectedFile.Length = 0;
            workItem->ProtectedFile.MaximumLength = needed;
            RtlCopyUnicodeString(&workItem->ProtectedFile, ProtectedFile);
        }
    }

    if (AttackingProcessPath && AttackingProcessPath->Buffer && AttackingProcessPath->Length > 0) {
        USHORT needed = (USHORT)(AttackingProcessPath->Length + sizeof(WCHAR));
        workItem->AttackingProcessPath.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, ALERT_POOL_TAG);
        if (workItem->AttackingProcessPath.Buffer) {
            workItem->AttackingProcessPath.Length = 0;
            workItem->AttackingProcessPath.MaximumLength = needed;
            RtlCopyUnicodeString(&workItem->AttackingProcessPath, AttackingProcessPath);

            // Normalize path for user-mode reporting
            NormalizeDevicePathToDos(&workItem->AttackingProcessPath);
        }
    }

    workItem->AttackingPid = AttackingPid;
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType ? AttackType : L"UNKNOWN");

#pragma warning(suppress: 4996)
    ExInitializeWorkItem(&workItem->WorkItem, SendAlertWorker, workItem);
#pragma warning(suppress: 4996)
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}

VOID SendAlertWorker(PVOID Context)
{
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)Context;
    if (!workItem) return;

    WCHAR messageBuffer[2048];
    WCHAR escapedProtected[512];
    WCHAR escapedAttacker[512];

    PCWSTR protectedName = (workItem->ProtectedFile.Buffer) ? workItem->ProtectedFile.Buffer : L"Unknown";
    PCWSTR attackerPath = (workItem->AttackingProcessPath.Buffer) ? workItem->AttackingProcessPath.Buffer : L"Unknown";

    // Escape for JSON
    if (!EscapeJsonString(escapedProtected, sizeof(escapedProtected), protectedName)) {
        RtlStringCbCopyW(escapedProtected, sizeof(escapedProtected), L"ErrorEscapingPath");
    }
    if (!EscapeJsonString(escapedAttacker, sizeof(escapedAttacker), attackerPath)) {
        RtlStringCbCopyW(escapedAttacker, sizeof(escapedAttacker), L"ErrorEscapingPath");
    }

    NTSTATUS status = RtlStringCchPrintfW(messageBuffer, RTL_NUMBER_OF(messageBuffer),
        L"{\"source\":\"simplepyas\",\"category\":\"file\",\"action\":\"blocked\",\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%llu,\"attack_type\":\"%ws\"}",
        escapedProtected,
        escapedAttacker,
        (ULONGLONG)(ULONG_PTR)workItem->AttackingPid,
        workItem->AttackType);

    if (NT_SUCCESS(status))
    {
        SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);
        status = SendAlertToPipe(messageBuffer, messageLength);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("[SELF-DEFENSE] Failed to send alert: 0x%X\n", status);
        }
    }
    else
    {
        DbgPrint("[SELF-DEFENSE] Failed to format alert: 0x%X\n", status);
    }

    if (workItem->ProtectedFile.Buffer)
    {
        ExFreePoolWithTag(workItem->ProtectedFile.Buffer, ALERT_POOL_TAG);
    }
    if (workItem->AttackingProcessPath.Buffer)
    {
        ExFreePoolWithTag(workItem->AttackingProcessPath.Buffer, ALERT_POOL_TAG);
    }

    ExFreePoolWithTag(workItem, ALERT_POOL_TAG);
}
