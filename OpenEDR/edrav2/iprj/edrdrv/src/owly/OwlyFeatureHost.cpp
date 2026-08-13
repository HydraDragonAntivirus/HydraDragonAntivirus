#include "OwlyFeatureHost.h"

#include "common.h"
#include "DriverData.h"
#include "Communication.h"
#include "ProcessProtection.h"
#include "RootkitDetector.h"
#include "UserModeHookEngine.h"
#include "AmsiProtection.h"
#include "Regedit.h"
#include <ntstrsafe.h>

// Regedit.cpp expects this symbol for IoAllocateWorkItem(). In the old
// Owlyshield driver it was created by FSfilter.cpp. In the integrated build we
// create a small control device only for work-item ownership.
extern PDEVICE_OBJECT g_DeviceObject;

namespace cmd {
namespace owly {

static PDEVICE_OBJECT g_OwlyWorkItemDeviceObject = nullptr;
static bool g_AmsiInitialized = false;
static bool g_ProcessProtectionInitialized = false;
static bool g_UserHookInitialized = false;
static bool g_RootkitInitialized = false;
static bool g_HookDeviceInitialized = false;
#if OWLY_HYPERVISOR_SUPPORT
static bool g_VmmInitialized = false;
#endif
static bool g_RegeditInitialized = false;

static NTSTATUS CreateWorkItemDevice(_In_ PDRIVER_OBJECT DriverObject)
{
    if (g_OwlyWorkItemDeviceObject != nullptr)
        return STATUS_SUCCESS;

    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\OwlyOpenEdrWorkItem");

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_OwlyWorkItemDeviceObject);

    if (!NT_SUCCESS(status))
        return status;

    g_DeviceObject = g_OwlyWorkItemDeviceObject;
    return STATUS_SUCCESS;
}

static VOID DeleteWorkItemDevice()
{
    if (g_DeviceObject == g_OwlyWorkItemDeviceObject)
        g_DeviceObject = nullptr;

    if (g_OwlyWorkItemDeviceObject != nullptr)
    {
        IoDeleteDevice(g_OwlyWorkItemDeviceObject);
        g_OwlyWorkItemDeviceObject = nullptr;
    }
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS InitializeFeatureHost(_In_ PDRIVER_OBJECT DriverObject)
{
    if (DriverObject == nullptr)
        return STATUS_INVALID_PARAMETER;

    NTSTATUS status = CreateWorkItemDevice(DriverObject);
    if (!NT_SUCCESS(status))
        return status;

    if (driverData == nullptr)
    {
        driverData = new (NonPagedPool) DriverData(DriverObject);
        if (driverData == nullptr)
            return STATUS_NO_MEMORY;

        // Attach DriverData to edrdrv's existing minifilter object. This is the
        // critical line that prevents Owlyshield from registering a second
        // minifilter while still allowing legacy Owly modules to query a filter.
        *driverData->getFilterAdd() = g_pCommonData->pFilter;
        driverData->setFilterStart();
    }

    // Do NOT call InitCommData(): it creates the legacy \\RWFilter port. The
    // integrated build emits via OpenEDR fltport only.

    status = AmsiInitialize();
    if (NT_SUCCESS(status)) g_AmsiInitialized = true;

    status = InitHookNotifyDevice(DriverObject);
    if (NT_SUCCESS(status)) g_HookDeviceInitialized = true;

#if OWLY_HYPERVISOR_SUPPORT
    status = InitVmmCommunication();
    if (NT_SUCCESS(status)) g_VmmInitialized = true;
#endif

    status = RegeditDriverEntry();
    if (NT_SUCCESS(status)) g_RegeditInitialized = true;

    status = InitProcessProtection();
    if (NT_SUCCESS(status)) g_ProcessProtectionInitialized = true;

    status = UserModeHookEngineInitialize();
    if (NT_SUCCESS(status)) g_UserHookInitialized = true;

    status = RootkitDetectorInitialize();
    if (NT_SUCCESS(status))
    {
        RootkitDetectorSetDeviceObject(g_OwlyWorkItemDeviceObject);
        g_RootkitInitialized = true;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID FinalizeFeatureHost()
{
    if (g_RootkitInitialized)
    {
        RootkitDetectorCleanup();
        g_RootkitInitialized = false;
    }

    if (g_UserHookInitialized)
    {
        UserModeHookEngineCleanup();
        g_UserHookInitialized = false;
    }

    if (g_ProcessProtectionInitialized)
    {
        UninitProcessProtection();
        g_ProcessProtectionInitialized = false;
    }

#if OWLY_HYPERVISOR_SUPPORT
    if (g_VmmInitialized)
    {
        CleanupVmmCommunication();
        g_VmmInitialized = false;
    }
#endif

    if (g_HookDeviceInitialized)
    {
        CleanupHookNotifyDevice();
        g_HookDeviceInitialized = false;
    }

    if (g_AmsiInitialized)
    {
        AmsiCleanup();
        g_AmsiInitialized = false;
    }

    if (driverData != nullptr)
    {
        driverData->setFilterStop();
        delete driverData;
        driverData = nullptr;
    }

    DeleteWorkItemDevice();
    g_RegeditInitialized = false;
}

} // namespace owly
} // namespace cmd
