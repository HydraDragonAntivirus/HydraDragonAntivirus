// File.c - Self-Defense Protection with User-Mode Alerting (uses CXX_FileProtectX64.h
#include "Driver.h"
#include "Driver_File.h"   // your header with OBJECT_TYPE_TEMP and related typedefs
#include "Driver_Common.h" // Include common helpers

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
VOID EnableObType(POBJECT_TYPE ObjectType);
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

// entry/unload (call from your DriverEntry/DriverUnload)
NTSTATUS FileDriverEntry()
{
    NTSTATUS status = ProtectFileByObRegisterCallbacks();
    if (NT_SUCCESS(status)) {
        DbgPrint("[Self-Defense] File protection initialized\n");
    }
    else {
        DbgPrint("[Self-Defense] ProtectFileByObRegisterCallbacks failed: 0x%X\n", status);
    }
    return status;
}

VOID FileUnloadDriver()
{
    if (g_CallBackHandle != NULL) {
        ObUnRegisterCallbacks(g_CallBackHandle);
        g_CallBackHandle = NULL;
    }
    DbgPrint("[Self-Defense] FileDriver Unloaded\n");
}

// --- EnableObType: use the provided OBJECT_TYPE_TEMP layout to set SupportsObjectCallbacks ---
// WARNING: This manipulates undocumented internals. Risk of incompatibility on some Windows builds.
VOID EnableObType(POBJECT_TYPE ObjectType)
{
    if (!ObjectType) {
        DbgPrint("[Self-Defense] EnableObType: NULL ObjectType\n");
        return;
    }

    //
    // Validate that the pointer looks sane by attempting to read a few offsets safely.
    // We avoid structured exceptions here; instead we perform basic pointer checks.
    //
    __try {
        // Cast to your provided temp struct which contains TypeInfo
        POBJECT_TYPE_TEMP pTemp = (POBJECT_TYPE_TEMP)ObjectType;

        // Basic validation: ensure the Name.Buffer pointer is reasonably aligned/non-NULL or not completely bogus.
        // This isn't perfect but can reduce chance of arbitrarily writing to bad memory.
        // This check is conservative: if both are NULL we still proceed but log a warning.
        if (pTemp->Name.Buffer == NULL && pTemp->DefaultObject == NULL) {
            DbgPrint("[Self-Defense] EnableObType: object type fields appear NULL (continuing with caution)\n");
        }

        // Now set the SupportsObjectCallbacks bit in TypeInfo.
        // The union with bitfield exists in OBJECT_TYPE_INITIALIZER in your header.
        // Set the bit safely:
        pTemp->TypeInfo.SupportsObjectCallbacks = 1;

        DbgPrint("[Self-Defense] EnableObType: Set SupportsObjectCallbacks=1 for object type at %p\n", ObjectType);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[Self-Defense] EnableObType: exception while attempting to set SupportsObjectCallbacks\n");
        // If an exception occurs, do not propagate; leave as-is.
    }
}

NTSTATUS ProtectFileByObRegisterCallbacks()
{
    OB_CALLBACK_REGISTRATION callBackReg;
    OB_OPERATION_REGISTRATION operationReg;
    NTSTATUS status;

    // Try to enable callbacks on IoFileObjectType (best-effort; may be unnecessary on some OS builds)
    EnableObType(*IoFileObjectType);

    RtlZeroMemory(&callBackReg, sizeof(callBackReg));
    RtlZeroMemory(&operationReg, sizeof(operationReg));

    callBackReg.Version = ObGetFilterVersion();
    callBackReg.OperationRegistrationCount = 1;
    callBackReg.RegistrationContext = NULL;
    RtlInitUnicodeString(&callBackReg.Altitude, L"321000");

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
    if (FileObject->Flags & (FO_NAMED_PIPE | FO_MAILSLOT)) {
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
    BOOLEAN isProtected = FALSE;

    // Folder-based protection patterns
    // Using ContainsSubstringInsensitive to match substring anywhere in the DOS Path
    static const PCWSTR protectedFolders[] = {
        L"\\Program Files\\HydraDragonAntivirus", 
        L"\\Desktop\\Sanctum",
        L"\\AppData\\Roaming\\Sanctum"
    };
    
    for (ULONG i = 0; i < ARRAYSIZE(protectedFolders); ++i) {
        if (ContainsSubstringInsensitive(fileName.Buffer, protectedFolders[i])) {
            isProtected = TRUE;
            break;
        }
    }

    if (isProtected) {
        ACCESS_MASK desiredAccess = 0;
        if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
            desiredAccess = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        }
        else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
            desiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        }

        if (desiredAccess & (DELETE | FILE_WRITE_DATA | GENERIC_WRITE)) {
            HANDLE currentPid = PsGetCurrentProcessId();
            PUNICODE_STRING attackerPath = NULL;
            NTSTATUS st = SeLocateProcessImageName(PsGetCurrentProcess(), &attackerPath);

            // Strip dangerous access rights
            if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
                OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~(DELETE | FILE_WRITE_DATA | GENERIC_WRITE);
                DbgPrint("[SELF-DEFENSE] Stripped CREATE access to: %wZ by PID: %p\n", &fileName, currentPid);
                QueueAlertToUserMode(&fileName, attackerPath, currentPid, L"FILE_TAMPERING_BLOCKED");
            }
            else {
                OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~(DELETE | FILE_WRITE_DATA | GENERIC_WRITE);
                DbgPrint("[SELF-DEFENSE] Stripped DUP access to: %wZ by PID: %p\n", &fileName, currentPid);
                QueueAlertToUserMode(&fileName, attackerPath, currentPid, L"HANDLE_HIJACK_BLOCKED");
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
    PALERT_WORK_ITEM workItem = (PALERT_WORK_ITEM)ExAllocatePoolWithTag(NonPagedPool, sizeof(ALERT_WORK_ITEM), ALERT_POOL_TAG);
    if (!workItem) {
        DbgPrint("[SELF-DEFENSE] QueueAlert: allocation failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workItem, sizeof(ALERT_WORK_ITEM));

    if (ProtectedFile && ProtectedFile->Buffer && ProtectedFile->Length > 0) {
        USHORT needed = (USHORT)(ProtectedFile->Length + sizeof(WCHAR));
        workItem->ProtectedFile.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, needed, ALERT_POOL_TAG);
        if (workItem->ProtectedFile.Buffer) {
            workItem->ProtectedFile.Length = 0;
            workItem->ProtectedFile.MaximumLength = needed;
            RtlCopyUnicodeString(&workItem->ProtectedFile, ProtectedFile);
        }
    }

    if (AttackingProcessPath && AttackingProcessPath->Buffer && AttackingProcessPath->Length > 0) {
        USHORT needed = (USHORT)(AttackingProcessPath->Length + sizeof(WCHAR));
        workItem->AttackingProcessPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPool, needed, ALERT_POOL_TAG);
        if (workItem->AttackingProcessPath.Buffer) {
            workItem->AttackingProcessPath.Length = 0;
            workItem->AttackingProcessPath.MaximumLength = needed;
            RtlCopyUnicodeString(&workItem->AttackingProcessPath, AttackingProcessPath);
        }
    }

    workItem->AttackingPid = AttackingPid;
    RtlStringCbCopyW(workItem->AttackType, sizeof(workItem->AttackType), AttackType ? AttackType : L"UNKNOWN");

    ExInitializeWorkItem(&workItem->WorkItem, SendAlertWorker, workItem);
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
        L"{\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%p,\"attack_type\":\"%ws\"}",
        escapedProtected, escapedAttacker, workItem->AttackingPid, workItem->AttackType);

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
