/*++

Module Name:

    RootkitDetector.cpp

Abstract:

    Event-driven rootkit detection engine.
    No timer - detection triggered via RootkitDetectorOnDriverEvent().

    Called by FSfilter.cpp on relevant IRP events:
        IRP_PROCESS_CREATE   -> RK_TRIGGER_FULL   (new process, full scan)
        IRP_KERNEL_* events  -> RK_TRIGGER_FULL   (injection activity, full scan)
        ImageLoadCallback    -> RK_TRIGGER_DRIVER  (new image/driver loaded)
        All others           -> RK_TRIGGER_LIGHT   (cheap SSDT+hook scan only)

    Debounce: FULL scans are gated by ROOTKIT_DEBOUNCE_MS to prevent overhead
    on hot event paths. LIGHT and DRIVER scans are not debounced.

Environment:

    Kernel mode only.

--*/

#include "RootkitDetector.h"
#include "common.h"
#include "osutils.h"   // cmd::getTickCount64
#include "fltport.h"
#include <ntimage.h>
#include <ntstrsafe.h>

using EvFld    = cmd::edrdrv::EventField;
using SysmonEv = cmd::edrdrv::SysmonEvent;

// ---------------------------------------------------------------------------
// Dynamic imports
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *PZW_QUERY_SYSTEM_INFORMATION)(
    _In_      ULONG  SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI *PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    _In_  HANDLE     ProcessId,
    _Out_ PEPROCESS *Process);

typedef UCHAR *(NTAPI *PPS_GET_PROCESS_IMAGE_FILE_NAME)(
    _In_ PEPROCESS Process);

typedef NTSTATUS (NTAPI *PZW_QUERY_DIRECTORY_OBJECT)(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_opt_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI *POB_REFERENCE_OBJECT_BY_NAME)(
    _In_ PUNICODE_STRING ObjectPath,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID *Object
    );

static PZW_QUERY_SYSTEM_INFORMATION     fnZwQuerySystemInformation    = NULL;
static PPS_LOOKUP_PROCESS_BY_PROCESS_ID fnPsLookupProcessByProcessId  = NULL;
static PPS_GET_PROCESS_IMAGE_FILE_NAME  fnPsGetProcessImageFileName   = NULL;
static PZW_QUERY_DIRECTORY_OBJECT       fnZwQueryDirectoryObject      = NULL;
static POB_REFERENCE_OBJECT_BY_NAME     fnObReferenceObjectByName     = NULL;
static POBJECT_TYPE                    *g_IoFileObjectType            = NULL;

// ---------------------------------------------------------------------------
// SystemModuleInformation structures (not in public WDK headers)
// ---------------------------------------------------------------------------
#pragma pack(push,1)
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
#pragma pack(pop)

typedef struct _RK_OBJECT_TYPE_INITIALIZER {
    USHORT          Length;
    UCHAR           ObjectTypeFlags;
    UCHAR           Reserved0;
    ULONG           ObjectTypeCode;
    ULONG           InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG           ValidAccessMask;
    ULONG           RetainAccess;
    POOL_TYPE       PoolType;
    ULONG           DefaultPagedPoolCharge;
    ULONG           DefaultNonPagedPoolCharge;
    PVOID           DumpProcedure;
    PVOID           OpenProcedure;
    PVOID           CloseProcedure;
    PVOID           DeleteProcedure;
    PVOID           ParseProcedure;
    PVOID           SecurityProcedure;
    PVOID           QueryNameProcedure;
    PVOID           OkayToCloseProcedure;
} RK_OBJECT_TYPE_INITIALIZER, *PRK_OBJECT_TYPE_INITIALIZER;

typedef struct _RK_OBJECT_TYPE_LAYOUT {
    LIST_ENTRY                 TypeList;
    UNICODE_STRING             Name;
    PVOID                      DefaultObject;
    UCHAR                      Index;
    UCHAR                      Reserved0[3];
    ULONG                      TotalNumberOfObjects;
    ULONG                      TotalNumberOfHandles;
    ULONG                      HighWaterNumberOfObjects;
    ULONG                      HighWaterNumberOfHandles;
    UCHAR                      Reserved1[4];
    RK_OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONGLONG                  TypeLock;
    ULONG                      Key;
    UCHAR                      Reserved2[4];
    LIST_ENTRY                 CallbackList;
} RK_OBJECT_TYPE_LAYOUT, *PRK_OBJECT_TYPE_LAYOUT;

#define RK_OBJECT_TYPE_FLAG_SUPPORTS_CALLBACKS 0x40U
#define RK_OBJECT_CALLBACK_STATE_ENABLED       0x1UL
#define RK_OBJECT_CALLBACK_STATE_ACTIVE        0x2UL

#define SystemModuleInformation   11UL
#define SystemProcessInformation   5UL

// ---------------------------------------------------------------------------
// SSDT (x64)
// ---------------------------------------------------------------------------
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE {
    PULONG_PTR ServiceTable;
    PULONG     CounterTable;
    ULONG_PTR  NumberOfServices;
    PUCHAR     ParamTable;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

static PSYSTEM_SERVICE_DESCRIPTOR_TABLE fnKeServiceDescriptorTable = NULL;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
static PDEVICE_OBJECT    g_ScanDeviceObject   = NULL;
static PIO_WORKITEM      g_ScanWorkItem       = NULL;

// Debounce: track last full-scan tick (100ns units via KeQuerySystemTime).
static volatile LONGLONG g_LastFullScanTick   = 0;

// Re-entrancy guard (work item may fire concurrently from two queues).
static volatile LONG     g_ScanInProgress     = 0;

// Pending trigger level for queued work item (highest wins).
static volatile LONG     g_PendingTrigger     = (LONG)RK_TRIGGER_LIGHT;

static CONST PCWSTR g_CoreDriverObjectPaths[] = {
    L"\\Driver\\Disk",
    L"\\Driver\\PartMgr",
    L"\\Driver\\MountMgr",
    L"\\Driver\\Classpnp",
    L"\\Driver\\ataport",
    L"\\Driver\\storport",
    L"\\Driver\\scsiport",
    L"\\FileSystem\\Ntfs",
    L"\\FileSystem\\Fastfat",
    NULL
};

static CONST UCHAR g_MonitoredMajorFunctions[] = {
    IRP_MJ_CREATE,
    IRP_MJ_CLOSE,
    IRP_MJ_READ,
    IRP_MJ_WRITE,
    IRP_MJ_QUERY_INFORMATION,
    IRP_MJ_SET_INFORMATION,
    IRP_MJ_FLUSH_BUFFERS,
    IRP_MJ_DIRECTORY_CONTROL,
    IRP_MJ_FILE_SYSTEM_CONTROL,
    IRP_MJ_DEVICE_CONTROL,
    IRP_MJ_INTERNAL_DEVICE_CONTROL,
    IRP_MJ_CLEANUP,
    IRP_MJ_SHUTDOWN,
    IRP_MJ_SYSTEM_CONTROL,
    IRP_MJ_PNP,
    IRP_MJ_POWER,
    0xFF
};

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static VOID  RkWorkItemRoutine(_In_ PDEVICE_OBJECT DevObj, _In_opt_ PVOID Ctx);
static ULONG RkCheckSsdtIntegrity(VOID);
static ULONG RkCheckHiddenProcesses(VOID);
static ULONG RkCheckHiddenDrivers(VOID);
static ULONG RkCheckDriverObjectIntegrity(VOID);
static ULONG RkCheckObjectTypeCallbackTampering(VOID);
static ULONG RkCheckKernelInlineHooks(VOID);
static VOID  RkEmitFinding(_In_ ULONG IrpOpCode, _In_ ULONG SourcePid,
                            _In_opt_ PCWSTR ObjectName,
                            _In_opt_ PVOID  MemoryAddress, _In_ SIZE_T MemSize,
                            _In_ ULONG_PTR Extra1, _In_ ULONG_PTR Extra2);
static BOOLEAN RkAddressInModule(_In_ PVOID Address,
                                 _In_ PVOID Base, _In_ ULONG Size);
_Success_(return != FALSE)
static BOOLEAN RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size);
_Success_(return != FALSE)
static BOOLEAN RkQuerySystemModules(_Outptr_ PRTL_PROCESS_MODULES *Modules);
static VOID RkFreeSystemModules(_In_opt_ PRTL_PROCESS_MODULES Modules);
static PRTL_PROCESS_MODULE_INFORMATION RkFindModuleForAddress(
    _In_opt_ PRTL_PROCESS_MODULES Modules,
    _In_ PVOID Address);
static VOID RkAnsiToUnicodeBuffer(_In_opt_ PCSTR Source,
                                  _Out_writes_z_(OutCch) PWCHAR Out,
                                  _In_ SIZE_T OutCch);
_Success_(return != FALSE)
static BOOLEAN RkReferenceDriverObjectByPath(_In_ PCWSTR Path,
                                             _Out_ PDRIVER_OBJECT *DriverObject);
static PCWSTR RkIrpMajorToName(_In_ UCHAR MajorFunction);
static ULONG RkCheckDriverObjectPathIntegrity(_In_ PCWSTR Path,
                                              _In_opt_ PRTL_PROCESS_MODULES Modules,
                                              _In_ PVOID NtoBase,
                                              _In_ ULONG NtoSize,
                                              _In_ ULONG MaxFindings);
static ULONG RkScanDriverObjectDirectory(_In_ PCWSTR DirectoryPath,
                                         _In_ PRTL_PROCESS_MODULES Modules,
                                         _In_ ULONG MaxFindings);
_Success_(return != FALSE)
static BOOLEAN RkBuildVisibleProcessBitmap(_Out_writes_bytes_(BitmapBytes) PUCHAR Bitmap,
                                           _In_ ULONG BitmapBytes);
static BOOLEAN RkIsFullScanTelemetryIrp(_In_ ULONG EventIrp);

// ---------------------------------------------------------------------------
// RootkitDetectorInitialize
// ---------------------------------------------------------------------------
NTSTATUS
RootkitDetectorInitialize(VOID)
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, L"ZwQuerySystemInformation");
    fnZwQuerySystemInformation =
        (PZW_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&name);
    if (!fnZwQuerySystemInformation) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: ZwQuerySystemInformation not found\n");
#endif

        return STATUS_NOT_FOUND;
    }

    RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
    fnPsLookupProcessByProcessId =
        (PPS_LOOKUP_PROCESS_BY_PROCESS_ID)MmGetSystemRoutineAddress(&name);
    if (!fnPsLookupProcessByProcessId) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: PsLookupProcessByProcessId not found\n");
#endif

        return STATUS_NOT_FOUND;
    }

    RtlInitUnicodeString(&name, L"PsGetProcessImageFileName");
    fnPsGetProcessImageFileName =
        (PPS_GET_PROCESS_IMAGE_FILE_NAME)MmGetSystemRoutineAddress(&name);
    if (!fnPsGetProcessImageFileName) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: PsGetProcessImageFileName not found, process names will be generic\n");
#endif

    }

    RtlInitUnicodeString(&name, L"ZwQueryDirectoryObject");
    fnZwQueryDirectoryObject =
        (PZW_QUERY_DIRECTORY_OBJECT)MmGetSystemRoutineAddress(&name);
    if (!fnZwQueryDirectoryObject) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: ZwQueryDirectoryObject not found, hidden-driver scan will be limited\n");
#endif

    }

    RtlInitUnicodeString(&name, L"ObReferenceObjectByName");
    fnObReferenceObjectByName =
        (POB_REFERENCE_OBJECT_BY_NAME)MmGetSystemRoutineAddress(&name);
    if (!fnObReferenceObjectByName) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: ObReferenceObjectByName not found, hidden-driver and driver-object scans will be limited\n");
#endif

    }

    RtlInitUnicodeString(&name, L"IoFileObjectType");
    g_IoFileObjectType =
        (POBJECT_TYPE *)MmGetSystemRoutineAddress(&name);
    if (!g_IoFileObjectType) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: IoFileObjectType not found, object-type tamper scan will be limited\n");
#endif

    }

    RtlInitUnicodeString(&name, L"KeServiceDescriptorTable");
    fnKeServiceDescriptorTable =
        (PSYSTEM_SERVICE_DESCRIPTOR_TABLE)MmGetSystemRoutineAddress(&name);
    if (!fnKeServiceDescriptorTable) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: KeServiceDescriptorTable not found, SSDT scan will be skipped on this build\n");
#endif

    }

    
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: Initialized (event-driven, debounce=%lu ms)\n",
             (ULONG)ROOTKIT_DEBOUNCE_MS);
#endif

    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// RootkitDetectorSetDeviceObject
// ---------------------------------------------------------------------------
VOID
RootkitDetectorSetDeviceObject(_In_ PDEVICE_OBJECT DeviceObject)
{
    if (g_ScanWorkItem) {
        IoFreeWorkItem(g_ScanWorkItem);
    }
    g_ScanDeviceObject = DeviceObject;
    g_ScanWorkItem     = IoAllocateWorkItem(DeviceObject);
}

// ---------------------------------------------------------------------------
// RootkitDetectorCleanup
// ---------------------------------------------------------------------------
VOID
RootkitDetectorCleanup(VOID)
{
    LARGE_INTEGER delayInterval;

    // Block any future queue attempts before we tear down the work item/device.
    g_ScanDeviceObject = NULL;
    KeMemoryBarrier();

    // If a scan was already queued or is currently running, wait for it to drain
    // before freeing the shared IO_WORKITEM and before the caller tears down
    // driverData / the device object.
    delayInterval.QuadPart = -10 * 1000; // 1 ms
    while (InterlockedCompareExchange(&g_ScanInProgress, 0, 0) != 0) {
        KeDelayExecutionThread(KernelMode, FALSE, &delayInterval);
    }

    if (g_ScanWorkItem) {
        IoFreeWorkItem(g_ScanWorkItem);
        g_ScanWorkItem = NULL;
    }
    InterlockedExchange(&g_PendingTrigger, (LONG)RK_TRIGGER_LIGHT);
    
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: Cleanup done\n");
#endif

}

// ---------------------------------------------------------------------------
// RootkitDetectorOnDriverEvent
// Called on every relevant driver event (IRP dispatch path or callbacks).
// Debounces FULL scans; queues a passive-level work item.
// ---------------------------------------------------------------------------
VOID
RootkitDetectorOnDriverEvent(_In_ RK_TRIGGER Trigger, _In_ ULONG EventIrp)
{
    if (!g_ScanWorkItem || !g_ScanDeviceObject) {
        return;
    }

    if (RkIsFullScanTelemetryIrp(EventIrp) && Trigger < RK_TRIGGER_FULL) {
        Trigger = RK_TRIGGER_FULL;
    }

    // For FULL scans: enforce minimum interval between scans.
    if (Trigger == RK_TRIGGER_FULL) {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        LONGLONG debounce100ns = (LONGLONG)ROOTKIT_DEBOUNCE_MS * 10000LL;
        LONGLONG last = InterlockedCompareExchange64(&g_LastFullScanTick, 0, 0);

        if (last != 0 && (now.QuadPart - last) < debounce100ns) {
            // Too soon - upgrade a pending light scan to full but don't queue new item.
            InterlockedCompareExchange(&g_PendingTrigger,
                                       (LONG)RK_TRIGGER_FULL,
                                       (LONG)RK_TRIGGER_LIGHT);
            return;
        }
        InterlockedExchange64(&g_LastFullScanTick, now.QuadPart);
    }

    // Raise pending trigger level if the new trigger is heavier.
    LONG current, desired;
    do {
        current = InterlockedCompareExchange(&g_PendingTrigger, 0, 0);
        desired = ((LONG)Trigger > current) ? (LONG)Trigger : current;
    } while (InterlockedCompareExchange(&g_PendingTrigger, desired, current) != current);

    // Only one work item in flight at a time.
    if (InterlockedCompareExchange(&g_ScanInProgress, 1, 0) != 0) {
        return;
    }

    IoQueueWorkItem(g_ScanWorkItem, RkWorkItemRoutine, DelayedWorkQueue, NULL);
}

static BOOLEAN
RkIsFullScanTelemetryIrp(_In_ ULONG EventIrp)
{
    return (EventIrp >= IRP_KERNEL_REMOTE_THREAD && EventIrp <= IRP_USERMODE_HOOK_EVENT) ||
           (EventIrp >= IRP_ROOTKIT_SSDT_HOOK && EventIrp <= IRP_ROOTKIT_GENERIC);
}

// ---------------------------------------------------------------------------
// Work item (PASSIVE_LEVEL)
// ---------------------------------------------------------------------------
static VOID
RkWorkItemRoutine(_In_ PDEVICE_OBJECT DevObj, _In_opt_ PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DevObj);
    UNREFERENCED_PARAMETER(Ctx);

    // Drain the pending trigger atomically.
    RK_TRIGGER trigger = (RK_TRIGGER)InterlockedExchange(&g_PendingTrigger,
                                                          (LONG)RK_TRIGGER_LIGHT);
    __try {
        switch (trigger) {
        case RK_TRIGGER_FULL:
            RootkitDetectorRunScan();
            break;
        case RK_TRIGGER_DRIVER:
            RkCheckHiddenDrivers();
            RkCheckDriverObjectIntegrity();
            RkCheckObjectTypeCallbackTampering();
            RkCheckHiddenProcesses();
            break;
        case RK_TRIGGER_LIGHT:
        default:
            RkCheckSsdtIntegrity();
            RkCheckKernelInlineHooks();
            break;
        }
    }
    __finally {
        KeMemoryBarrier();
        InterlockedExchange(&g_ScanInProgress, 0);
    }
}

// ---------------------------------------------------------------------------
// RootkitDetectorRunScan (PASSIVE_LEVEL)
// ---------------------------------------------------------------------------
ULONG
RootkitDetectorRunScan(VOID)
{
    ULONG total = 0;
    total += RkCheckSsdtIntegrity();
    total += RkCheckKernelInlineHooks();
    total += RkCheckHiddenProcesses();
    total += RkCheckHiddenDrivers();
    total += RkCheckDriverObjectIntegrity();
    total += RkCheckObjectTypeCallbackTampering();
    if (total > 0) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: scan complete - %lu anomalies\n", total);
#endif

    }
    return total;
}

// ===========================================================================
// Helpers
// ===========================================================================
static VOID
RkEmitFinding(_In_ ULONG IrpOpCode, _In_ ULONG SourcePid,
              _In_opt_ PCWSTR ObjectName,
              _In_opt_ PVOID  MemoryAddress, _In_ SIZE_T MemSize,
              _In_ ULONG_PTR Extra1, _In_ ULONG_PTR Extra2)
{
    if (!cmd::fltport::isClientConnected()) return;

    // Rootkit findings are delivered as OwlyHookEvent (DeviceIoControl carrier, 0x000E).
    // OwlyHookEventType carries the IRP_ROOTKIT_* opcode so Rust can dispatch them.
    cmd::NonPagedLbvsSerializer<cmd::edrdrv::EventField> serializer;

    if (!serializer.write(EvFld::RawEventId,
            uint16_t(SysmonEv::DeviceIoControl)))          return;
    if (!serializer.write(EvFld::TickTime,
            (uint64_t)cmd::getTickCount64()))              return;
    if (!serializer.write(EvFld::ProcessPid,
            (uint32_t)SourcePid))                         return;
    if (!serializer.write(EvFld::OwlyHookEventType,
            (uint32_t)IrpOpCode))                         return;
    if (!serializer.write(EvFld::OwlyHookSourcePid,
            (uint32_t)SourcePid))                         return;
    if (!serializer.write(EvFld::OwlyHookArg1,
            (uint64_t)(ULONG_PTR)MemoryAddress))          return;
    if (!serializer.write(EvFld::OwlyHookArg2,
            (uint64_t)MemSize))                           return;
    if (!serializer.write(EvFld::OwlyHookArg3,
            (uint64_t)Extra1))                            return;
    if (!serializer.write(EvFld::OwlyHookArg4,
            (uint64_t)Extra2))                            return;

    if (ObjectName != NULL) {
        UNICODE_STRING objUs;
        RtlInitUnicodeString(&objUs, ObjectName);
        if (!cmd::write(serializer, EvFld::OwlyHookFunctionName, &objUs))
            return;
    }

    (VOID)cmd::fltport::sendRawEvent(serializer);
}

static BOOLEAN
RkAddressInModule(_In_ PVOID Address, _In_ PVOID Base, _In_ ULONG Size)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR base = (ULONG_PTR)Base;
    return (addr >= base && addr < (base + (ULONG_PTR)Size));
}

_Success_(return != FALSE)
static BOOLEAN
RkQuerySystemModules(_Outptr_ PRTL_PROCESS_MODULES *Modules)
{
    ULONG    need   = 0;
    NTSTATUS status;
    PRTL_PROCESS_MODULES mods;

    if (!Modules || !fnZwQuerySystemInformation) return FALSE;
    *Modules = NULL;

    status = fnZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &need);
    if (status != STATUS_INFO_LENGTH_MISMATCH || need == 0) return FALSE;

    need += 4096;
    mods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool,
                                                 need,
                                                 'kMhO');
    if (!mods) return FALSE;

    status = fnZwQuerySystemInformation(SystemModuleInformation, mods, need, NULL);
    if (!NT_SUCCESS(status) || mods->NumberOfModules == 0)
    {
        ExFreePoolWithTag(mods, 'kMhO');
        return FALSE;
    }

    *Modules = mods;
    return TRUE;
}

static VOID
RkFreeSystemModules(_In_opt_ PRTL_PROCESS_MODULES Modules)
{
    if (Modules) {
        ExFreePoolWithTag(Modules, 'kMhO');
    }
}

static PRTL_PROCESS_MODULE_INFORMATION
RkFindModuleForAddress(_In_opt_ PRTL_PROCESS_MODULES Modules, _In_ PVOID Address)
{
    if (!Modules || !Address) return NULL;

    for (ULONG i = 0; i < Modules->NumberOfModules; ++i) {
        if (RkAddressInModule(Address,
                              Modules->Modules[i].ImageBase,
                              Modules->Modules[i].ImageSize)) {
            return &Modules->Modules[i];
        }
    }

    return NULL;
}

static VOID
RkAnsiToUnicodeBuffer(_In_opt_ PCSTR Source,
                      _Out_writes_z_(OutCch) PWCHAR Out,
                      _In_ SIZE_T OutCch)
{
    ANSI_STRING as;
    UNICODE_STRING us;

    if (!Out || OutCch == 0) return;

    RtlZeroMemory(Out, OutCch * sizeof(WCHAR));
    if (!Source) return;

    RtlInitAnsiString(&as, Source);
    us.Buffer = Out;
    us.Length = 0;
    us.MaximumLength = (USHORT)(OutCch * sizeof(WCHAR));
    if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&us, &as, FALSE))) {
        Out[0] = L'\0';
        return;
    }

    SIZE_T terminatorIndex = (SIZE_T)(us.Length / sizeof(WCHAR));
    if (terminatorIndex >= OutCch) {
        terminatorIndex = OutCch - 1;
    }
    Out[terminatorIndex] = L'\0';
}

_Success_(return != FALSE)
static BOOLEAN
RkReferenceDriverObjectByPath(_In_ PCWSTR Path, _Out_ PDRIVER_OBJECT *DriverObject)
{
    UNICODE_STRING pathUs;

    if (!DriverObject || !Path || !fnObReferenceObjectByName) return FALSE;

    *DriverObject = NULL;
    RtlInitUnicodeString(&pathUs, Path);
    return NT_SUCCESS(fnObReferenceObjectByName(&pathUs,
                                                OBJ_CASE_INSENSITIVE,
                                                NULL,
                                                0,
                                                NULL,
                                                KernelMode,
                                                NULL,
                                                (PVOID *)DriverObject)) &&
           (*DriverObject != NULL);
}

static PCWSTR
RkIrpMajorToName(_In_ UCHAR MajorFunction)
{
    switch (MajorFunction) {
    case IRP_MJ_CREATE: return L"IRP_MJ_CREATE";
    case IRP_MJ_CLOSE: return L"IRP_MJ_CLOSE";
    case IRP_MJ_READ: return L"IRP_MJ_READ";
    case IRP_MJ_WRITE: return L"IRP_MJ_WRITE";
    case IRP_MJ_QUERY_INFORMATION: return L"IRP_MJ_QUERY_INFORMATION";
    case IRP_MJ_SET_INFORMATION: return L"IRP_MJ_SET_INFORMATION";
    case IRP_MJ_FLUSH_BUFFERS: return L"IRP_MJ_FLUSH_BUFFERS";
    case IRP_MJ_DIRECTORY_CONTROL: return L"IRP_MJ_DIRECTORY_CONTROL";
    case IRP_MJ_FILE_SYSTEM_CONTROL: return L"IRP_MJ_FILE_SYSTEM_CONTROL";
    case IRP_MJ_DEVICE_CONTROL: return L"IRP_MJ_DEVICE_CONTROL";
    case IRP_MJ_INTERNAL_DEVICE_CONTROL: return L"IRP_MJ_INTERNAL_DEVICE_CONTROL";
    case IRP_MJ_CLEANUP: return L"IRP_MJ_CLEANUP";
    case IRP_MJ_SHUTDOWN: return L"IRP_MJ_SHUTDOWN";
    case IRP_MJ_SYSTEM_CONTROL: return L"IRP_MJ_SYSTEM_CONTROL";
    case IRP_MJ_PNP: return L"IRP_MJ_PNP";
    case IRP_MJ_POWER: return L"IRP_MJ_POWER";
    default: return L"IRP_MJ_UNKNOWN";
    }
}

_Success_(return != FALSE)
static BOOLEAN
RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size)
{
    PRTL_PROCESS_MODULES mods = NULL;

    if (!Base || !Size) return FALSE;
    *Base = NULL;
    *Size = 0;

    if (!RkQuerySystemModules(&mods)) return FALSE;

    *Base = mods->Modules[0].ImageBase;
    *Size = mods->Modules[0].ImageSize;
    RkFreeSystemModules(mods);
    return TRUE;
}

static ULONG
RkCheckDriverPointerField(_In_ PCWSTR DriverPath,
                          _In_ PCWSTR FieldName,
                          _In_opt_ PVOID Pointer,
                          _In_ ULONG_PTR FieldCode,
                          _In_ PDRIVER_OBJECT DriverObject,
                          _In_opt_ PRTL_PROCESS_MODULES Modules,
                          _In_ PVOID NtoBase,
                          _In_ ULONG NtoSize)
{
    WCHAR desc[MAX_FILE_NAME_LENGTH] = {0};
    WCHAR ownerName[64] = {0};
    PRTL_PROCESS_MODULE_INFORMATION ownerModule;

    if (!Pointer || !DriverObject || !DriverObject->DriverStart || DriverObject->DriverSize == 0) {
        return 0;
    }

    if (RkAddressInModule(Pointer, DriverObject->DriverStart, DriverObject->DriverSize) ||
        RkAddressInModule(Pointer, NtoBase, NtoSize)) {
        return 0;
    }

    ownerModule = RkFindModuleForAddress(Modules, Pointer);
    if (ownerModule) {
        RkAnsiToUnicodeBuffer((PCSTR)(ownerModule->FullPathName + ownerModule->OffsetToFileName),
                              ownerName,
                              RTL_NUMBER_OF(ownerName));
    }

    if (ownerName[0]) {
        (VOID)RtlStringCchPrintfW(desc,
                                  RTL_NUMBER_OF(desc),
                                  L"%ws:%ws -> %ws",
                                  DriverPath,
                                  FieldName,
                                  ownerName);
    } else {
        (VOID)RtlStringCchPrintfW(desc,
                                  RTL_NUMBER_OF(desc),
                                  L"%ws:%ws -> unknown",
                                  DriverPath,
                                  FieldName);
    }

    
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: driver object hook %ws field=%ws ptr=%p\n",
             DriverPath,
             FieldName,
             Pointer);
#endif


    RkEmitFinding(IRP_ROOTKIT_KERNEL_HOOK,
                  0,
                  desc,
                  Pointer,
                  0,
                  FieldCode,
                  ownerModule ? (ULONG_PTR)ownerModule->ImageBase : 0);
    return 1;
}

static ULONG
RkCheckDriverObjectPathIntegrity(_In_ PCWSTR Path,
                                 _In_opt_ PRTL_PROCESS_MODULES Modules,
                                 _In_ PVOID NtoBase,
                                 _In_ ULONG NtoSize,
                                 _In_ ULONG MaxFindings)
{
    PDRIVER_OBJECT drv = NULL;
    ULONG findings = 0;

    if (!Path || MaxFindings == 0) return 0;
    if (!RkReferenceDriverObjectByPath(Path, &drv) || !drv) return 0;

    __try {
        if (!drv->DriverStart || drv->DriverSize == 0) {
            RkEmitFinding(IRP_ROOTKIT_GENERIC, 0, Path, NULL, 0, 0x10, 0);
            findings = 1;
            __leave;
        }

        if (findings < MaxFindings) {
            findings += RkCheckDriverPointerField(Path,
                                                  L"DriverInit",
                                                  (PVOID)drv->DriverInit,
                                                  0x1000,
                                                  drv,
                                                  Modules,
                                                  NtoBase,
                                                  NtoSize);
        }
        if (findings < MaxFindings) {
            findings += RkCheckDriverPointerField(Path,
                                                  L"DriverStartIo",
                                                  (PVOID)drv->DriverStartIo,
                                                  0x1001,
                                                  drv,
                                                  Modules,
                                                  NtoBase,
                                                  NtoSize);
        }
        if (findings < MaxFindings) {
            findings += RkCheckDriverPointerField(Path,
                                                  L"DriverUnload",
                                                  (PVOID)drv->DriverUnload,
                                                  0x1002,
                                                  drv,
                                                  Modules,
                                                  NtoBase,
                                                  NtoSize);
        }
        if (findings < MaxFindings && drv->DriverExtension) {
            findings += RkCheckDriverPointerField(Path,
                                                  L"AddDevice",
                                                  (PVOID)drv->DriverExtension->AddDevice,
                                                  0x1003,
                                                  drv,
                                                  Modules,
                                                  NtoBase,
                                                  NtoSize);
        }

        for (ULONG i = 0;
             g_MonitoredMajorFunctions[i] != 0xFF && findings < MaxFindings;
             ++i)
        {
            UCHAR major = g_MonitoredMajorFunctions[i];
            findings += RkCheckDriverPointerField(Path,
                                                  RkIrpMajorToName(major),
                                                  (PVOID)drv->MajorFunction[major],
                                                  0x2000 + major,
                                                  drv,
                                                  Modules,
                                                  NtoBase,
                                                  NtoSize);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: exception while checking driver object %ws (0x%X)\n",
                 Path,
                 GetExceptionCode());
#endif

    }

    ObDereferenceObject(drv);
    return findings;
}

static ULONG
RkScanDriverObjectDirectory(_In_ PCWSTR DirectoryPath,
                            _In_ PRTL_PROCESS_MODULES Modules,
                            _In_ ULONG MaxFindings)
{
    typedef struct _OBJECT_DIR_INFO {
        UNICODE_STRING Name;
        UNICODE_STRING TypeName;
    } OBJECT_DIR_INFO, *POBJECT_DIR_INFO;

    HANDLE hDir = NULL;
    UNICODE_STRING dirName;
    UNICODE_STRING driverTypeName;
    OBJECT_ATTRIBUTES oa;
    PUCHAR qbuf = NULL;
    ULONG findings = 0;
    ULONG ctx = 0;
    BOOLEAN firstCall = TRUE;
    NTSTATUS status;
    const ULONG qbufSize = 16384;

    if (!DirectoryPath || !Modules || MaxFindings == 0 || !fnZwQueryDirectoryObject) {
        return 0;
    }

    RtlInitUnicodeString(&dirName, DirectoryPath);
    RtlInitUnicodeString(&driverTypeName, L"Driver");
    InitializeObjectAttributes(&oa,
                               &dirName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    if (!NT_SUCCESS(status)) return 0;

    qbuf = (PUCHAR)ExAllocatePoolWithTag(PagedPool, qbufSize, 'qRhO');
    if (!qbuf) {
        ZwClose(hDir);
        return 0;
    }

    while (findings < MaxFindings) {
        ULONG ret = 0;
        status = fnZwQueryDirectoryObject(hDir,
                                          qbuf,
                                          qbufSize,
                                          FALSE,
                                          firstCall,
                                          &ctx,
                                          &ret);
        firstCall = FALSE;
        if (!NT_SUCCESS(status) && status != STATUS_MORE_ENTRIES) break;

        POBJECT_DIR_INFO info = (POBJECT_DIR_INFO)(PVOID)qbuf;
        while (info->Name.Length != 0 && findings < MaxFindings) {
            if (info->TypeName.Length != 0 &&
                !RtlEqualUnicodeString(&info->TypeName, &driverTypeName, TRUE)) {
                info++;
                continue;
            }

            WCHAR path[MAX_FILE_NAME_LENGTH] = {0};
            (VOID)RtlStringCchPrintfW(path,
                                      RTL_NUMBER_OF(path),
                                      L"%ws\\%wZ",
                                      DirectoryPath,
                                      &info->Name);

            PDRIVER_OBJECT drv = NULL;
            if (RkReferenceDriverObjectByPath(path, &drv) && drv) {
                if (drv->DriverStart &&
                    RkFindModuleForAddress(Modules, drv->DriverStart) == NULL) {
                    
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: hidden driver object %ws base=%p\n",
                             path,
                             drv->DriverStart);
#endif

                    RkEmitFinding(IRP_ROOTKIT_HIDDEN_DRIVER,
                                  0,
                                  path,
                                  drv->DriverStart,
                                  (SIZE_T)drv->Size,
                                  0,
                                  0);
                    ++findings;
                }
                ObDereferenceObject(drv);
            }
            info++;
        }

        if (status != STATUS_MORE_ENTRIES) break;
    }

    ExFreePoolWithTag(qbuf, 'qRhO');
    ZwClose(hDir);
    return findings;
}

static ULONG
RkCheckDriverObjectIntegrity(VOID)
{
    PRTL_PROCESS_MODULES mods = NULL;
    PVOID ntoBase = NULL;
    ULONG ntoSize = 0;
    ULONG findings = 0;

    if (!fnObReferenceObjectByName) return 0;
    if (!RkGetNtoskrnlRange(&ntoBase, &ntoSize)) return 0;
    if (!RkQuerySystemModules(&mods)) return 0;

    for (ULONG i = 0;
         g_CoreDriverObjectPaths[i] != NULL && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
         ++i)
    {
        findings += RkCheckDriverObjectPathIntegrity(g_CoreDriverObjectPaths[i],
                                                     mods,
                                                     ntoBase,
                                                     ntoSize,
                                                     ROOTKIT_MAX_FINDINGS_PER_PASS - findings);
    }

    RkFreeSystemModules(mods);
    return findings;
}

static ULONG
RkCheckObjectTypeCallbackTampering(VOID)
{
    //
    // The internal OBJECT_TYPE layout is build-sensitive and the previous
    // hardcoded cast produced false positives on newer Windows builds. Keep
    // this detector dormant until a version-aware implementation is added.
    //
    return 0;
}

// ===========================================================================
// 1. SSDT Integrity
// ===========================================================================
static ULONG
RkCheckSsdtIntegrity(VOID)
{
    ULONG  findings = 0;
    PVOID  ntoBase  = NULL;
    ULONG  ntoSize  = 0;

    if (!fnKeServiceDescriptorTable) return 0;
    if (!RkGetNtoskrnlRange(&ntoBase, &ntoSize)) return 0;

    __try {
        PULONG   table = (PULONG)fnKeServiceDescriptorTable->ServiceTable;
        ULONG_PTR count = fnKeServiceDescriptorTable->NumberOfServices;

        if (!table || count == 0 || count > 0x1000) return 0;

        for (ULONG_PTR i = 0;
             i < count && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
             ++i)
        {
            __try {
                LONG_PTR enc      = (LONG_PTR)(LONG)table[i];
                PVOID    resolved = (PVOID)((ULONG_PTR)table + (enc >> 4));

                if (!RkAddressInModule(resolved, ntoBase, ntoSize)) {
                    WCHAR desc[128];
                    (VOID)RtlStringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                                              L"SSDT[%llu]=0x%p outside ntoskrnl",
                                              (ULONGLONG)i, resolved);

                    
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: SSDT hook index=%llu -> %p\n",
                             (ULONGLONG)i, resolved);
#endif


                    RkEmitFinding(IRP_ROOTKIT_SSDT_HOOK, 0, desc,
                                  resolved, 0,
                                  (ULONG_PTR)i, (ULONG_PTR)enc);
                    ++findings;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: SSDT check exception 0x%X\n",
                 GetExceptionCode());
#endif

    }

    return findings;
}

// ===========================================================================
// 2. Hidden Process (DKOM detection)
// ===========================================================================
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG  NextEntryOffset;
    ULONG  NumberOfThreads;
    LARGE_INTEGER SpareLi[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG   BasePriority;
    HANDLE UniqueProcessId;
    // rest unused
} SYSTEM_PROCESS_INFORMATION;

static ULONG
RkCheckHiddenProcesses(VOID)
{
    ULONG    findings = 0;
    const ULONG BITMAP_BYTES = 65536 / 8;
    PUCHAR bitmapPrimary = NULL;
    PUCHAR bitmapSecondary = NULL;

    if (!fnZwQuerySystemInformation || !fnPsLookupProcessByProcessId) return 0;

    bitmapPrimary = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BITMAP_BYTES, 'bRhO');
    bitmapSecondary = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, BITMAP_BYTES, '2RhO');
    if (!bitmapPrimary || !bitmapSecondary) {
        if (bitmapPrimary) ExFreePoolWithTag(bitmapPrimary, 'bRhO');
        if (bitmapSecondary) ExFreePoolWithTag(bitmapSecondary, '2RhO');
        return 0;
    }

    if (!RkBuildVisibleProcessBitmap(bitmapPrimary, BITMAP_BYTES) ||
        !RkBuildVisibleProcessBitmap(bitmapSecondary, BITMAP_BYTES))
    {
        ExFreePoolWithTag(bitmapPrimary, 'bRhO');
        ExFreePoolWithTag(bitmapSecondary, '2RhO');
        return 0;
    }

    // Scan PID space: PIDs in PspCidTable but absent from the list are DKOM-hidden.
    for (ULONG pid = 4;
         pid < 65536 && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
         pid += 4)
    {
        if (pid == 0) continue;
        if ((bitmapPrimary[pid / 8] & (1 << (pid % 8))) ||
            (bitmapSecondary[pid / 8] & (1 << (pid % 8)))) {
            continue; // visible in at least one live snapshot
        }

        PEPROCESS proc = NULL;
        HANDLE pidHandle = (HANDLE)(ULONG_PTR)pid;
        if (NT_SUCCESS(fnPsLookupProcessByProcessId(pidHandle, &proc))
            && proc != NULL)
        {
            WCHAR name[32] = {0};
            PUCHAR imgName = fnPsGetProcessImageFileName ?
                                fnPsGetProcessImageFileName(proc) : NULL;
            if (imgName) {
                ANSI_STRING   as = { (USHORT)strnlen((PCHAR)imgName, 15), 15,
                                     (PCHAR)imgName };
                UNICODE_STRING us = { 0, sizeof(name), name };
                RtlAnsiStringToUnicodeString(&us, &as, FALSE);
            }

            
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: DKOM hidden process PID=%lu name=%S\n",
                     pid, name);
#endif

            RkEmitFinding(IRP_ROOTKIT_HIDDEN_PROCESS, pid,
                          name[0] ? name : L"<hidden>",
                          NULL, 0, (ULONG_PTR)pid, 0);
            ++findings;
            ObDereferenceObject(proc);
        }
    }

    ExFreePoolWithTag(bitmapPrimary, 'bRhO');
    ExFreePoolWithTag(bitmapSecondary, '2RhO');
    return findings;
}

_Success_(return != FALSE)
static BOOLEAN
RkBuildVisibleProcessBitmap(_Out_writes_bytes_(BitmapBytes) PUCHAR Bitmap,
                            _In_ ULONG BitmapBytes)
{
    NTSTATUS status;
    ULONG need = 0;
    PUCHAR buf = NULL;
    SYSTEM_PROCESS_INFORMATION *entry = NULL;

    if (!Bitmap || BitmapBytes == 0 || !fnZwQuerySystemInformation) {
        return FALSE;
    }

    RtlZeroMemory(Bitmap, BitmapBytes);

    status = fnZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &need);
    if (status != STATUS_INFO_LENGTH_MISMATCH || need == 0) {
        return FALSE;
    }

    need += 65536;
    buf = (PUCHAR)ExAllocatePoolWithTag(PagedPool, need, 'pRhO');
    if (!buf) {
        return FALSE;
    }

    status = fnZwQuerySystemInformation(SystemProcessInformation, buf, need, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'pRhO');
        return FALSE;
    }

    entry = (SYSTEM_PROCESS_INFORMATION *)(PVOID)buf;
    while (TRUE) {
        ULONG pid = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        if (pid < (BitmapBytes * 8)) {
            Bitmap[pid / 8] |= (UCHAR)(1 << (pid % 8));
        }
        if (!entry->NextEntryOffset) {
            break;
        }
        entry = (SYSTEM_PROCESS_INFORMATION *)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, 'pRhO');
    return TRUE;
}

// ===========================================================================
// 3. Hidden Driver
// ===========================================================================
static ULONG
RkCheckHiddenDrivers(VOID)
{
    PRTL_PROCESS_MODULES mods = NULL;
    ULONG findings = 0;

    if (!fnZwQueryDirectoryObject || !fnObReferenceObjectByName) {
        return 0;
    }

    if (!RkQuerySystemModules(&mods)) return 0;

    findings += RkScanDriverObjectDirectory(L"\\Driver",
                                            mods,
                                            ROOTKIT_MAX_FINDINGS_PER_PASS - findings);
    if (findings < ROOTKIT_MAX_FINDINGS_PER_PASS) {
        findings += RkScanDriverObjectDirectory(L"\\FileSystem",
                                                mods,
                                                ROOTKIT_MAX_FINDINGS_PER_PASS - findings);
    }

    RkFreeSystemModules(mods);
    return findings;
}

// ===========================================================================
// 4. Kernel Inline Hook Detection
// ===========================================================================
static CONST PCSTR g_MonitoredExports[] = {
    "NtCreateFile",        "NtOpenFile",           "NtReadFile",
    "NtWriteFile",         "NtDeleteFile",          "NtCreateProcess",
    "NtCreateProcessEx",   "NtTerminateProcess",    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory","NtWriteVirtualMemory","NtCreateThread",
    "NtCreateThreadEx",    "NtQuerySystemInformation","NtLoadDriver",
    "NtSetSystemInformation","NtOpenProcess",       "NtOpenThread",
    "NtCreateSection",     "NtMapViewOfSection",    "NtOpenDirectoryObject",
    "NtQueryDirectoryObject", "IofCallDriver",      "IofCompleteRequest",
    "PsLookupProcessByProcessId", "PsGetProcessImageFileName",
    "ObReferenceObjectByName",
    NULL
};

static ULONG
RkCheckKernelInlineHooks(VOID)
{
    ULONG  findings = 0;
    PVOID  ntoBase  = NULL;
    ULONG  ntoSize  = 0;

    if (!RkGetNtoskrnlRange(&ntoBase, &ntoSize)) return 0;

    for (ULONG i = 0;
         g_MonitoredExports[i] != NULL && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
         ++i)
    {
        ANSI_STRING    as;
        UNICODE_STRING us;
        RtlInitAnsiString(&as, g_MonitoredExports[i]);
        if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&us, &as, TRUE))) continue;

        PVOID fn = MmGetSystemRoutineAddress(&us);
        RtlFreeUnicodeString(&us);

        if (!fn || !RkAddressInModule(fn, ntoBase, ntoSize)) continue;

        __try {
            PUCHAR p       = (PUCHAR)fn;
            BOOLEAN hooked = FALSE;
            PVOID   target = NULL;

            // FF 25 rel32 - indirect JMP (x64 14-byte hook)
            if (p[0] == 0xFF && p[1] == 0x25) {
                LONG rel = *(LONG *)(p + 2);
                PVOID *ptr = (PVOID *)((ULONG_PTR)(p + 6) + rel);
                __try {
                    target = *ptr;
                    if (!RkAddressInModule(target, ntoBase, ntoSize))
                        hooked = TRUE;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            // E9 rel32 - relative JMP (5-byte hook)
            if (!hooked && p[0] == 0xE9) {
                LONG rel = *(LONG *)(p + 1);
                target = (PVOID)((ULONG_PTR)(p + 5) + rel);
                if (!RkAddressInModule(target, ntoBase, ntoSize))
                    hooked = TRUE;
            }

            // 48 B8 imm64 / FF E0 - mov rax, imm64; jmp rax (12-byte)
            if (!hooked &&
                p[0] == 0x48 && p[1] == 0xB8 &&
                p[10] == 0xFF && p[11] == 0xE0)
            {
                target = *(PVOID *)(p + 2);
                if (!RkAddressInModule(target, ntoBase, ntoSize))
                    hooked = TRUE;
            }

            if (hooked) {
                ANSI_STRING    an2;
                UNICODE_STRING wn;
                WCHAR          wnBuf[128] = {0};
                RtlInitAnsiString(&an2, g_MonitoredExports[i]);
                wn.Buffer = wnBuf; wn.Length = 0;
                wn.MaximumLength = sizeof(wnBuf);
                RtlAnsiStringToUnicodeString(&wn, &an2, FALSE);

                
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: inline hook %s -> %p\n",
                         g_MonitoredExports[i], target);
#endif

                RkEmitFinding(IRP_ROOTKIT_KERNEL_HOOK, 0, wnBuf,
                              fn, 0, (ULONG_PTR)target, 0);
                ++findings;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            
#if IS_DEBUG_IRP
_LOGINFO_RAW("RootkitDetector: exception inspecting %s\n",
                     g_MonitoredExports[i]);
#endif

        }
    }

    return findings;
}





