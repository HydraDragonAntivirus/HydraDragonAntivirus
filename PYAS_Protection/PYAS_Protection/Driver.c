#include "Driver.h"
#include "ProtectionRules.h"

// Runtime process-protection level values.
// SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT maps to:
//   Type   = PsProtectedTypeProtectedLight (1)
//   Signer = PsProtectedSignerAntimalware  (3)
// We resolve PsGetProcessProtection dynamically to avoid depending on private
// EPROCESS offsets or fragile structure layouts.
#define PS_PROTECTED_TYPE_PROTECTED_LIGHT 1
#define PS_PROTECTED_SIGNER_ANTIMALWARE   3

typedef UCHAR (*PFN_PS_GET_PROCESS_PROTECTION)(
    _In_ PEPROCESS Process
    );

static PFN_PS_GET_PROCESS_PROTECTION g_PsGetProcessProtection = NULL;

static UCHAR GetProcessProtectionLevel(_In_ PEPROCESS Process)
{
    if (!Process)
        return 0;

    if (!g_PsGetProcessProtection)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetProcessProtection");
        g_PsGetProcessProtection =
            (PFN_PS_GET_PROCESS_PROTECTION)MmGetSystemRoutineAddress(&routineName);
    }

    if (!g_PsGetProcessProtection)
    {
        DbgPrint("[SimplePYAS] PsGetProcessProtection is unavailable; denying rule-control caller\n");
        return 0;
    }

    return g_PsGetProcessProtection(Process);
}

static BOOLEAN IsAntimalwareProtectedLightProcess(_In_ PEPROCESS Process)
{
    UCHAR level = GetProcessProtectionLevel(Process);
    UCHAR type = level & 0x07;
    UCHAR signer = (level >> 4) & 0x0F;

    return (type == PS_PROTECTED_TYPE_PROTECTED_LIGHT &&
            signer == PS_PROTECTED_SIGNER_ANTIMALWARE);
}

#define SELF_DEFENSE_PIPE_NAME L"\\Device\\NamedPipe\\Global\\self_defense_alerts"

// Track if pipe is available (to avoid log spam)
static BOOLEAN g_PipeAvailable = FALSE;
static BOOLEAN g_PipeUnavailableLogged = FALSE;

static PDEVICE_OBJECT g_ControlDeviceObject = NULL;
static UNICODE_STRING g_ControlSymbolicLink;
static BOOLEAN g_ControlSymbolicLinkCreated = FALSE;

static VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);
static NTSTATUS CreateControlDevice(_In_ PDRIVER_OBJECT DriverObject);
static VOID DeleteControlDevice(VOID);

static NTSTATUS CompleteIrp(_Inout_ PIRP Irp, _In_ NTSTATUS Status, _In_ ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}


#define SANCTUM_RULE_LOADER_PATH \
    L"\\??\\C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\Sanctum\\AppData\\sanctum_ppl_runner.exe"

static BOOLEAN IsTrustedRuleIoctlCaller(VOID)
{
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrint("[SimplePYAS] Rule-control caller rejected: wrong IRQL %u\n",
            (ULONG)KeGetCurrentIrql());
        return FALSE;
    }

    PEPROCESS process = NULL;
    HANDLE pid = PsGetCurrentProcessId();
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status) || process == NULL)
    {
        DbgPrint("[SimplePYAS] Rule-control caller rejected: PsLookupProcessByProcessId(%p) failed 0x%X\n",
            pid,
            status);
        return FALSE;
    }

    if (!IsAntimalwareProtectedLightProcess(process))
    {
        DbgPrint("[SimplePYAS] Rule-control caller rejected: pid=%p is not SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT\n",
            pid);
        ObDereferenceObject(process);
        return FALSE;
    }

    PUNICODE_STRING imagePath = NULL;
    status = SeLocateProcessImageName(process, &imagePath);

    BOOLEAN trusted = FALSE;
    if (NT_SUCCESS(status) && imagePath && imagePath->Buffer && imagePath->Length > 0)
    {
        static const WCHAR runnerSuffix[] = L"sanctum_ppl_runner.exe";
        SIZE_T suffixChars = (sizeof(runnerSuffix) / sizeof(WCHAR)) - 1;
        SIZE_T pathChars = imagePath->Length / sizeof(WCHAR);

        if (pathChars >= suffixChars)
        {
            PCWSTR pathEnd = &imagePath->Buffer[pathChars - suffixChars];
            trusted = (_wcsicmp(pathEnd, runnerSuffix) == 0);
        }

        if (!trusted)
        {
            DbgPrint("[SimplePYAS] Rule-control caller rejected: pid=%p image=%wZ\n",
                pid,
                imagePath);
        }
    }
    else
    {
        DbgPrint("[SimplePYAS] Rule-control caller rejected: SeLocateProcessImageName(%p) failed 0x%X\n",
            pid,
            status);
    }

    if (imagePath)
        ExFreePool(imagePath);

    ObDereferenceObject(process);
    return trusted;
}

static NTSTATUS CreateControlDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName;
    NTSTATUS status;

    RtlInitUnicodeString(&deviceName, HYDRADRAGON_DEVICE_NAME);
    RtlInitUnicodeString(&g_ControlSymbolicLink, HYDRADRAGON_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_ControlDeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        g_ControlDeviceObject = NULL;
        DbgPrint("[SimplePYAS] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    g_ControlDeviceObject->Flags |= DO_BUFFERED_IO;

    // Remove a stale link from a previous test crash, then recreate it.
    IoDeleteSymbolicLink(&g_ControlSymbolicLink);

    status = IoCreateSymbolicLink(&g_ControlSymbolicLink, &deviceName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[SimplePYAS] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
        return status;
    }

    g_ControlSymbolicLinkCreated = TRUE;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HydraDragonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HydraDragonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = HydraDragonCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HydraDragonDeviceControl;

    g_ControlDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    DbgPrint("[SimplePYAS] Rule-control device created: %ws\n", HYDRADRAGON_DOS_DEVICE_NAME);
    return STATUS_SUCCESS;
}

static VOID DeleteControlDevice(VOID)
{
    if (g_ControlSymbolicLinkCreated)
    {
        IoDeleteSymbolicLink(&g_ControlSymbolicLink);
        g_ControlSymbolicLinkCreated = FALSE;
    }

    if (g_ControlDeviceObject)
    {
        IoDeleteDevice(g_ControlDeviceObject);
        g_ControlDeviceObject = NULL;
    }
}

NTSTATUS HydraDragonCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack && stack->MajorFunction == IRP_MJ_CREATE)
    {
        if (!IsTrustedRuleIoctlCaller())
        {
            return CompleteIrp(Irp, STATUS_ACCESS_DENIED, 0);
        }
    }

    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS HydraDragonDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status;

    switch (controlCode)
    {
    case IOCTL_HYDRADRAGON_SET_RULES:
        if (!IsTrustedRuleIoctlCaller())
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (systemBuffer == NULL || inputLength < sizeof(HYDRADRAGON_RULE_BLOB))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = SetProtectionRulesFromUserBuffer(systemBuffer, inputLength);
        if (NT_SUCCESS(status))
        {
            DbgPrint("[SimplePYAS] Protection rules updated from user-mode IOCTL\n");
        }
        else
        {
            DbgPrint("[SimplePYAS] Rule update IOCTL failed: 0x%X\n", status);
        }
        break;

    case IOCTL_HYDRADRAGON_CLEAR_RULES:
        if (!IsTrustedRuleIoctlCaller())
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        CleanupProtectionRules();
        DbgPrint("[SimplePYAS] Protection rules cleared by trusted Sanctum PPL runner IOCTL\n");
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return CompleteIrp(Irp, status, 0);
}

static BOOLEAN IsValidPipeServerProcess(HANDLE PipeHandle)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    FILE_PROCESS_IDS_USING_FILE_INFORMATION procIds = { 0 };
    BOOLEAN isValid = FALSE;
    HANDLE serverProcHandle = NULL;
    ULONG returnLength = 0;
    PUNICODE_STRING imagePath = NULL;

    // 1. Get process IDs using the pipe (should just be the server and us)
    status = ZwQueryInformationFile(
        PipeHandle,
        &ioStatus,
        &procIds,
        sizeof(procIds),
        FileProcessIdsUsingFileInformation
    );

    // Only proceed if exactly one other process (the server) has it open, or we can get list
    if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
        return FALSE; // Can't verify, deny by default
    }

    ULONG listSize = sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) +
        (sizeof(ULONG_PTR) * 16);
    PFILE_PROCESS_IDS_USING_FILE_INFORMATION pProcIds =
        (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, listSize, 'pPiM');

    if (!pProcIds) return FALSE;

    status = ZwQueryInformationFile(PipeHandle, &ioStatus, pProcIds, listSize, FileProcessIdsUsingFileInformation);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(pProcIds, 'pPiM');
        return FALSE;
    }

    // Find a PID that is not our own (the system process)
    ULONG_PTR serverPid = 0;
    ULONG_PTR currentPid = (ULONG_PTR)PsGetCurrentProcessId();
    for (ULONG i = 0; i < pProcIds->NumberOfProcessIdsInList; i++) {
        if (pProcIds->ProcessIdList[i] != currentPid && pProcIds->ProcessIdList[i] != 0) {
            serverPid = pProcIds->ProcessIdList[i];
            break;
        }
    }

    ExFreePoolWithTag(pProcIds, 'pPiM');

    if (serverPid == 0) return FALSE; // Server not found

    // 2. Open the server process
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)serverPid;
    clientId.UniqueThread = NULL;

    status = ZwOpenProcess(&serverProcHandle, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) return FALSE;

    // 3. Query the image path
    status = ZwQueryInformationProcess(serverProcHandle, ProcessImageFileName, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        ZwClose(serverProcHandle);
        return FALSE;
    }

    imagePath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, 'pPiM');
    if (!imagePath) {
        ZwClose(serverProcHandle);
        return FALSE;
    }

    status = ZwQueryInformationProcess(serverProcHandle, ProcessImageFileName, imagePath, returnLength, &returnLength);
    ZwClose(serverProcHandle);

    if (NT_SUCCESS(status) && imagePath->Buffer != NULL && imagePath->Length > 0) {
        UNICODE_STRING dosName;
        OBJECT_ATTRIBUTES linkObjAttr;
        HANDLE linkHandle;
        UNICODE_STRING driveCDeviceName = { 0 };

        RtlInitUnicodeString(&dosName, L"\\??\\C:");
        InitializeObjectAttributes(&linkObjAttr, &dosName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        if (NT_SUCCESS(ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &linkObjAttr)))
        {
            driveCDeviceName.MaximumLength = 256 * sizeof(WCHAR);
            driveCDeviceName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, driveCDeviceName.MaximumLength, 'pPiM');

            if (driveCDeviceName.Buffer)
            {
                if (NT_SUCCESS(ZwQuerySymbolicLinkObject(linkHandle, &driveCDeviceName, NULL)))
                {
                    if (RtlPrefixUnicodeString(&driveCDeviceName, imagePath, TRUE))
                    {
                        UNICODE_STRING remainingPart;
                        remainingPart.Buffer = (PWCH)((PUCHAR)imagePath->Buffer + driveCDeviceName.Length);
                        remainingPart.Length = imagePath->Length - driveCDeviceName.Length;
                        remainingPart.MaximumLength = remainingPart.Length;

                        // Normalize by trimming trailing spaces
                        while (remainingPart.Length >= sizeof(WCHAR) &&
                            remainingPart.Buffer[(remainingPart.Length / sizeof(WCHAR)) - 1] == L' ') {
                            remainingPart.Length -= sizeof(WCHAR);
                        }

                        UNICODE_STRING expectedRemaining;
                        RtlInitUnicodeString(
                            &expectedRemaining,
                            L"\\Program Files\\HydraDragonAntivirus\\hydradragon\\Owlyshield\\Owlyshield Service\\owlyshield_ransom.exe"
                        );

                        if (RtlCompareUnicodeString(&remainingPart, &expectedRemaining, TRUE) == 0)
                        {
                            isValid = TRUE;
                        }
                    }
                }
                ExFreePoolWithTag(driveCDeviceName.Buffer, 'pPiM');
            }
            ZwClose(linkHandle);
        }
    }

    ExFreePoolWithTag(imagePath, 'pPiM');
    return isValid;
}

NTSTATUS SendAlertToPipe(_In_ PCWSTR Message, _In_ SIZE_T MessageLength)
{
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    NTSTATUS status;

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    //
    // Do not wait/retry here. Alert workers must never stall boot or block a
    // callback path just because the user-mode listener is not available yet.
    // A single best-effort write is enough; user mode can reconnect later.
    //
    status = ZwCreateFile(
        &pipeHandle,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );

    if (!NT_SUCCESS(status))
    {
        if (!g_PipeUnavailableLogged)
        {
            DbgPrint("[SendAlertToPipe] User-mode listener unavailable: 0x%X; dropping alert\n", status);
            g_PipeUnavailableLogged = TRUE;
            g_PipeAvailable = FALSE;
        }

        return STATUS_SUCCESS;
    }

    if (!IsValidPipeServerProcess(pipeHandle))
    {
        DbgPrint("[SendAlertToPipe] Pipe connected but server process validation failed; alert dropped\n");
        ZwClose(pipeHandle);
        return STATUS_ACCESS_DENIED;
    }

    if (!g_PipeAvailable)
    {
        DbgPrint("[SendAlertToPipe] Pipe connection established and verified\n");
        g_PipeAvailable = TRUE;
        g_PipeUnavailableLogged = FALSE;
    }

    status = ZwWriteFile(
        pipeHandle,
        NULL,
        NULL,
        NULL,
        &ioStatusBlock,
        (PVOID)Message,
        (ULONG)MessageLength,
        NULL,
        NULL
    );

    ZwClose(pipeHandle);
    return status;
}

// DriverEntry
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT pDriverObj,
    _In_ PUNICODE_STRING pRegistryString
)
{
    UNREFERENCED_PARAMETER(pRegistryString);

#if DBG
    pDriverObj->DriverUnload = DriverUnload;
#else
    pDriverObj->DriverUnload = NULL;
#endif

    //
    // Do not patch loader/signature fields here. Production drivers should be
    // signed correctly instead of mutating undocumented loader state.
    //

    NTSTATUS status = CreateControlDevice(pDriverObj);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ProcessDriverEntry();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[SimplePYAS] ProcessDriverEntry failed: 0x%X\n", status);
        DeleteControlDevice();
        return status;
    }

    status = FileDriverEntry();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[SimplePYAS] FileDriverEntry failed: 0x%X\n", status);
        ProcessDriverUnload();
        DeleteControlDevice();
        return status;
    }

    status = RegeditDriverEntry();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[SimplePYAS] RegeditDriverEntry failed: 0x%X\n", status);
        FileUnloadDriver();
        ProcessDriverUnload();
        DeleteControlDevice();
        return status;
    }

    //
    // No delayed rule loader, no boot-time C: file I/O.
    // Rules must be sent by the HydraDragon user-mode service through
    // IOCTL_HYDRADRAGON_SET_RULES after it has read and validated the files.
    //
    DbgPrint("[SimplePYAS] DriverEntry complete - waiting for user-mode rule IOCTL\n");

    return STATUS_SUCCESS;
}

// DriverUnload
static VOID DriverUnload(_In_ PDRIVER_OBJECT pDriverObj)
{
    UNREFERENCED_PARAMETER(pDriverObj);

    DbgPrint("[SimplePYAS] DriverUnload started\n");

    RegeditUnloadDriver();
    FileUnloadDriver();
    ProcessDriverUnload();

    CleanupProtectionRules();
    DeleteControlDevice();

    DbgPrint("[SimplePYAS] DriverUnload complete\n");
}
