#include "Driver.h"
#include "ProtectionRules.h"

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
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    return CompleteIrp(Irp, status, 0);
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

    // Initialize protection rules (hardcoded defaults for boot-time protection)
    InitializeProtectionRules();

    DbgPrint("[SimplePYAS] DriverEntry complete - boot protection active\n");

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
