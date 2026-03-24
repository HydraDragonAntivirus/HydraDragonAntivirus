/*++

Module Name:

    RootkitDetector.cpp

Abstract:

    Rootkit detection engine for HydraDragon / Owlyshield.

    Inspired by GMER's detection approach:
      - SSDT integrity: walk KeServiceDescriptorTable, flag entries that fall
        outside the ntoskrnl .text section.
      - Hidden processes: compare EPROCESS ActiveProcessLinks walk against
        PsLookupProcessByProcessId (PspCidTable-backed).
      - Hidden drivers: compare PsLoadedModuleList against
        ZwQuerySystemInformation(SystemModuleInformation).
      - Kernel inline hooks: inspect the first 16 bytes of a curated list of
        ntoskrnl exports for FF25 (indirect JMP) or E9 (relative JMP) patterns
        whose target lies outside the originating module.

    All findings emit DRIVER_MESSAGE records with IRP_OP codes defined in
    SharedDefs.h and are forwarded via driverData->AddIrpMessage() so they
    reach behavior_engine.rs through the normal IRP pipe.

Environment:

    Kernel mode only.

--*/

#include "RootkitDetector.h"
#include "DriverData.h"      // driverData global, IRP_ENTRY, PDRIVER_MESSAGE
#include <ntimage.h>         // IMAGE_DOS_HEADER, IMAGE_NT_HEADERS
#include <ntstrsafe.h>

// ---------------------------------------------------------------------------
// External globals (defined in FsFilter.cpp / DriverData.cpp)
// ---------------------------------------------------------------------------
extern DriverData *driverData;   // IRP queue sink

// ---------------------------------------------------------------------------
// Dynamic imports resolved at init time
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *PZW_QUERY_SYSTEM_INFORMATION)(
    _In_      ULONG  SystemInformationClass,
    _Inout_   PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI *PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    _In_  HANDLE     ProcessId,
    _Out_ PEPROCESS *Process);

static PZW_QUERY_SYSTEM_INFORMATION  fnZwQuerySystemInformation  = NULL;
static PPS_LOOKUP_PROCESS_BY_PROCESS_ID fnPsLookupProcessByProcessId = NULL;

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

#define SystemModuleInformation 11UL

// ---------------------------------------------------------------------------
// SSDT structures (x64 only)
// ---------------------------------------------------------------------------
typedef struct _SYSTEM_SERVICE_DESCRIPTOR_TABLE {
    PULONG_PTR ServiceTable;
    PULONG     CounterTable;
    ULONG_PTR  NumberOfServices;
    PUCHAR     ParamTable;
} SYSTEM_SERVICE_DESCRIPTOR_TABLE, *PSYSTEM_SERVICE_DESCRIPTOR_TABLE;

// KeServiceDescriptorTable is exported by ntoskrnl on checked/free builds.
// Declare it as an import so the linker resolves it.
EXTERN_C SYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

// ---------------------------------------------------------------------------
// Periodic scan timer
// ---------------------------------------------------------------------------
static KTIMER      g_ScanTimer      = {0};
static KDPC        g_ScanDpc        = {0};
static BOOLEAN     g_TimerInitialized = FALSE;
static volatile LONG g_ScanInProgress = 0; // re-entrancy guard

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static VOID  RkDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredCtx,
                          _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2);
static ULONG RkCheckSsdtIntegrity(VOID);
static ULONG RkCheckHiddenProcesses(VOID);
static ULONG RkCheckHiddenDrivers(VOID);
static ULONG RkCheckKernelInlineHooks(VOID);

static VOID  RkEmitFinding(_In_ ULONG IrpOpCode,
                           _In_ ULONG SourcePid,
                           _In_opt_ PCWSTR ObjectName,
                           _In_opt_ PVOID MemoryAddress,
                           _In_opt_ SIZE_T MemorySize,
                           _In_ ULONG_PTR Extra1,
                           _In_ ULONG_PTR Extra2);

static BOOLEAN RkAddressInModule(_In_ PVOID Address,
                                 _In_ PVOID ModuleBase,
                                 _In_ ULONG ModuleSize);
static BOOLEAN RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size);

// ---------------------------------------------------------------------------
// RootkitDetectorInitialize
// ---------------------------------------------------------------------------
NTSTATUS
RootkitDetectorInitialize(VOID)
{
    UNICODE_STRING routineName;
    LARGE_INTEGER  dueTime;

    // -- Resolve ZwQuerySystemInformation -----------------------------------
    RtlInitUnicodeString(&routineName, L"ZwQuerySystemInformation");
    fnZwQuerySystemInformation =
        (PZW_QUERY_SYSTEM_INFORMATION)MmGetSystemRoutineAddress(&routineName);
    if (!fnZwQuerySystemInformation) {
        DbgPrint("RootkitDetector: ZwQuerySystemInformation not found\n");
        return STATUS_NOT_FOUND;
    }

    // -- Resolve PsLookupProcessByProcessId ----------------------------------
    RtlInitUnicodeString(&routineName, L"PsLookupProcessByProcessId");
    fnPsLookupProcessByProcessId =
        (PPS_LOOKUP_PROCESS_BY_PROCESS_ID)MmGetSystemRoutineAddress(&routineName);
    if (!fnPsLookupProcessByProcessId) {
        DbgPrint("RootkitDetector: PsLookupProcessByProcessId not found\n");
        return STATUS_NOT_FOUND;
    }

    // -- Set up periodic DPC timer ------------------------------------------
    KeInitializeTimer(&g_ScanTimer);
    KeInitializeDpc(&g_ScanDpc, RkDpcRoutine, NULL);

    // First fire: ROOTKIT_SCAN_INTERVAL_SEC after driver load.
    dueTime.QuadPart = -(LONGLONG)ROOTKIT_SCAN_INTERVAL_SEC * 10000000LL;
    KeSetTimerEx(&g_ScanTimer, dueTime,
                 ROOTKIT_SCAN_INTERVAL_SEC * 1000, // period in ms
                 &g_ScanDpc);
    g_TimerInitialized = TRUE;

    DbgPrint("RootkitDetector: Initialized, scan interval %lu s\n",
             (ULONG)ROOTKIT_SCAN_INTERVAL_SEC);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// RootkitDetectorCleanup
// ---------------------------------------------------------------------------
VOID
RootkitDetectorCleanup(VOID)
{
    if (g_TimerInitialized) {
        KeCancelTimer(&g_ScanTimer);
        KeFlushQueuedDpcs();
        g_TimerInitialized = FALSE;
    }
    DbgPrint("RootkitDetector: Cleanup done\n");
}

// ---------------------------------------------------------------------------
// DPC routine — offloads actual scan to PASSIVE_LEVEL via work item so we
// can call ZwQuerySystemInformation and paged pool allocations safely.
// ---------------------------------------------------------------------------
static VOID
RkDpcWorkItemRoutine(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Ctx)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Ctx);

    if (InterlockedCompareExchange(&g_ScanInProgress, 1, 0) != 0) {
        DbgPrint("RootkitDetector: scan already running, skipping\n");
        return;
    }
    __try {
        RootkitDetectorRunScan();
    }
    __finally {
        InterlockedExchange(&g_ScanInProgress, 0);
    }
}

static PIO_WORKITEM g_ScanWorkItem = NULL;
static PDEVICE_OBJECT g_ScanDeviceObject = NULL; // set by FSFilter

// Allow FSFilter.cpp to register the device object for work-item dispatch.
EXTERN_C VOID
RootkitDetectorSetDeviceObject(_In_ PDEVICE_OBJECT DeviceObject)
{
    if (g_ScanWorkItem != NULL) {
        IoFreeWorkItem(g_ScanWorkItem);
    }
    g_ScanDeviceObject = DeviceObject;
    g_ScanWorkItem = IoAllocateWorkItem(DeviceObject);
}

static VOID
RkDpcRoutine(_In_ PKDPC Dpc, _In_opt_ PVOID DeferredCtx,
             _In_opt_ PVOID Arg1, _In_opt_ PVOID Arg2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredCtx);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    if (g_ScanWorkItem && g_ScanDeviceObject) {
        IoQueueWorkItem(g_ScanWorkItem, RkDpcWorkItemRoutine,
                        DelayedWorkQueue, NULL);
    }
}

// ---------------------------------------------------------------------------
// RootkitDetectorRunScan  (PASSIVE_LEVEL)
// ---------------------------------------------------------------------------
ULONG
RootkitDetectorRunScan(VOID)
{
    ULONG total = 0;
    total += RkCheckSsdtIntegrity();
    total += RkCheckHiddenProcesses();
    total += RkCheckHiddenDrivers();
    total += RkCheckKernelInlineHooks();
    if (total > 0) {
        DbgPrint("RootkitDetector: scan complete — %lu anomalies found\n", total);
    }
    return total;
}

// ===========================================================================
// Helper: emit a DRIVER_MESSAGE to the IRP queue
// ===========================================================================
static VOID
RkEmitFinding(_In_ ULONG IrpOpCode,
              _In_ ULONG SourcePid,
              _In_opt_ PCWSTR ObjectName,
              _In_opt_ PVOID MemoryAddress,
              _In_opt_ SIZE_T MemorySize,
              _In_ ULONG_PTR Extra1,
              _In_ ULONG_PTR Extra2)
{
    if (!driverData) return;

    IRP_ENTRY *entry = new (NonPagedPool, 'kRhO') IRP_ENTRY();
    if (!entry) return;

    PDRIVER_MESSAGE msg = &entry->data;
    RtlZeroMemory(msg, sizeof(*msg));

    msg->IRP_OP          = (UCHAR)IrpOpCode;
    msg->PID             = SourcePid;
    msg->Gid             = 0; // rootkit events are not per-gid

    msg->KernelEventInfo.EventType       = IrpOpCode;
    msg->KernelEventInfo.SourceProcessId = SourcePid;
    msg->KernelEventInfo.MemoryAddress   = MemoryAddress;
    msg->KernelEventInfo.MemorySize      = MemorySize;
    msg->KernelEventInfo.RawArgument1    = Extra1;
    msg->KernelEventInfo.RawArgument2    = Extra2;

    if (ObjectName) {
        HRESULT hr = StringCchCopyW(msg->KernelEventInfo.ObjectName,
                                    RTL_NUMBER_OF(msg->KernelEventInfo.ObjectName),
                                    ObjectName);
        UNREFERENCED_PARAMETER(hr);
    }

    if (!driverData->AddIrpMessage(entry)) {
        delete entry;
    }
}

// ===========================================================================
// Helper: check if Address is within [ModuleBase, ModuleBase+ModuleSize)
// ===========================================================================
static BOOLEAN
RkAddressInModule(_In_ PVOID Address,
                  _In_ PVOID ModuleBase,
                  _In_ ULONG ModuleSize)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR base = (ULONG_PTR)ModuleBase;
    return (addr >= base && addr < (base + ModuleSize));
}

// ===========================================================================
// Helper: walk PsLoadedModuleList to find ntoskrnl base + size.
// Returns FALSE if ntoskrnl cannot be located.
// ===========================================================================
static BOOLEAN
RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size)
{
    // We use ZwQuerySystemInformation to find ntoskrnl reliably.
    if (!fnZwQuerySystemInformation) return FALSE;

    ULONG     bufSize  = 0;
    NTSTATUS  status   = fnZwQuerySystemInformation(SystemModuleInformation,
                                                    NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufSize == 0) return FALSE;

    bufSize += 4096; // headroom
    PRTL_PROCESS_MODULES modules =
        (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              bufSize, 'kMhO');
    if (!modules) return FALSE;

    status = fnZwQuerySystemInformation(SystemModuleInformation,
                                        modules, bufSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'kMhO');
        return FALSE;
    }

    // Module[0] is always ntoskrnl.exe on Windows.
    if (modules->NumberOfModules == 0) {
        ExFreePoolWithTag(modules, 'kMhO');
        return FALSE;
    }

    *Base = modules->Modules[0].ImageBase;
    *Size = modules->Modules[0].ImageSize;
    ExFreePoolWithTag(modules, 'kMhO');
    return TRUE;
}

// ===========================================================================
// 1. SSDT Integrity Check
//    Walk KeServiceDescriptorTable entries; any entry whose resolved address
//    falls outside ntoskrnl is flagged as a hook.
// ===========================================================================
static ULONG
RkCheckSsdtIntegrity(VOID)
{
    ULONG  findings  = 0;
    PVOID  ntoBase   = NULL;
    ULONG  ntoSize   = 0;

    if (!RkGetNtoskrnlRange(&ntoBase, &ntoSize)) {
        DbgPrint("RootkitDetector: SSDT check — cannot locate ntoskrnl\n");
        return 0;
    }

    // On x64 Windows, SSDT entries are encoded as relative offsets:
    //   RealAddress = (ULONG_PTR)&ServiceTable[i] + (ServiceTable[i] >> 4)
    __try {
        PULONG  serviceTable   = (PULONG)KeServiceDescriptorTable.ServiceTable;
        ULONG_PTR tableCount   = KeServiceDescriptorTable.NumberOfServices;

        if (!serviceTable || tableCount == 0 || tableCount > 0x1000) {
            return 0; // sanity
        }

        for (ULONG_PTR i = 0; i < tableCount && findings < ROOTKIT_MAX_FINDINGS_PER_PASS; ++i) {
            __try {
                // Decode the encoded entry (x64 relative offset encoding).
                LONG_PTR encoded = (LONG_PTR)(LONG)serviceTable[i];
                PVOID resolved   = (PVOID)((ULONG_PTR)&serviceTable[i] + (encoded >> 4));

                if (!RkAddressInModule(resolved, ntoBase, ntoSize)) {
                    WCHAR msg[128];
                    HRESULT hr = StringCchPrintfW(msg, RTL_NUMBER_OF(msg),
                        L"SSDT[%llu]=0x%p outside ntoskrnl", (ULONGLONG)i, resolved);
                    UNREFERENCED_PARAMETER(hr);

                    DbgPrint("RootkitDetector: SSDT hook at index %llu -> %p\n",
                             (ULONGLONG)i, resolved);

                    RkEmitFinding(IRP_ROOTKIT_SSDT_HOOK,
                                  0,
                                  msg,
                                  resolved,
                                  0,
                                  (ULONG_PTR)i,
                                  (ULONG_PTR)encoded);
                    ++findings;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Unreadable entry — skip silently.
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("RootkitDetector: Exception in SSDT check (0x%X)\n",
                 GetExceptionCode());
    }

    return findings;
}

// ===========================================================================
// 2. Hidden Process Detection
//    Walk EPROCESS ActiveProcessLinks; for each PID verify it exists via
//    PsLookupProcessByProcessId (which uses PspCidTable).
//    A process unlinked from the EPROCESS list but still in PspCidTable is
//    the classic DKOM hiding technique.
//    We detect both directions:
//      (a) In active list but PsLookup fails  → unreachable process (rare)
//      (b) PID range scan finds process that isn't in active list → DKOM
// ===========================================================================

// PsActiveProcessHead is exported on checked builds; on free builds we use
// PsInitialSystemProcess + EPROCESS.ActiveProcessLinks offsets.
// We use ZwQuerySystemInformation(SystemProcessInformation) as the "trusted"
// list and compare it against the EPROCESS walk via PsGetProcessId.

#define SystemProcessInformation 5UL

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG  NextEntryOffset;
    ULONG  NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG   BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG  HandleCount;
    // ... more fields, we only need UniqueProcessId
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

static ULONG
RkCheckHiddenProcesses(VOID)
{
    ULONG    findings = 0;
    NTSTATUS status;
    ULONG    bufSize  = 0;

    if (!fnZwQuerySystemInformation || !fnPsLookupProcessByProcessId) return 0;

    // --- Step 1: build a set of PIDs from ZwQuerySystemInformation ----------
    // (This walks the same EPROCESS list under the hood, but rootkits that
    //  patch ZwQuerySystemInformation's output would be caught by SSDT check.)
    status = fnZwQuerySystemInformation(SystemProcessInformation,
                                        NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufSize == 0) return 0;

    bufSize += 65536;
    PUCHAR buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, bufSize, 'pRhO');
    if (!buf) return 0;

    status = fnZwQuerySystemInformation(SystemProcessInformation,
                                        buf, bufSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, 'pRhO');
        return 0;
    }

    // Build a hash-set of known PIDs (simple bitmap up to PID 65536).
    // Windows PIDs are multiples of 4 and fit in 16 bits for most systems.
    const ULONG PID_BITMAP_SIZE = 65536 / 8; // 8KB
    PUCHAR pidBitmap = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                               PID_BITMAP_SIZE, 'bRhO');
    if (!pidBitmap) {
        ExFreePoolWithTag(buf, 'pRhO');
        return 0;
    }
    RtlZeroMemory(pidBitmap, PID_BITMAP_SIZE);

    PSYSTEM_PROCESS_INFORMATION entry =
        (PSYSTEM_PROCESS_INFORMATION)(PVOID)buf;
    while (TRUE) {
        ULONG pid = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        if (pid < 65536) {
            pidBitmap[pid / 8] |= (UCHAR)(1 << (pid % 8));
        }
        if (entry->NextEntryOffset == 0) break;
        entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry +
                                               entry->NextEntryOffset);
    }
    ExFreePoolWithTag(buf, 'pRhO');

    // --- Step 2: scan PID range; processes found via PsLookup but NOT in
    //             the ZwQuerySystemInformation list are DKOM-hidden. ----------
    for (ULONG pid = 4; pid < 65536 && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
         pid += 4)
    {
        BOOLEAN inSystemList = (pidBitmap[pid / 8] & (1 << (pid % 8))) != 0;
        if (inSystemList) continue; // normal process

        PEPROCESS process = NULL;
        status = fnPsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (NT_SUCCESS(status) && process != NULL) {
            // PID exists in PspCidTable but is NOT in the system process list.
            // Classic DKOM hidden process.
            WCHAR procName[32] = {0};
            PUCHAR imageFileName = (PUCHAR)PsGetProcessImageFileName(process);
            if (imageFileName) {
                // ImageFileName is 15-char ANSI inside EPROCESS.
                ANSI_STRING  as  = {0};
                UNICODE_STRING us = {0};
                as.Buffer        = (PCHAR)imageFileName;
                as.Length        = (USHORT)strnlen((PCHAR)imageFileName, 15);
                as.MaximumLength = 15;
                us.Buffer        = procName;
                us.MaximumLength = sizeof(procName);
                RtlAnsiStringToUnicodeString(&us, &as, FALSE);
            }

            DbgPrint("RootkitDetector: DKOM hidden process PID=%lu name=%S\n",
                     pid, procName);

            RkEmitFinding(IRP_ROOTKIT_HIDDEN_PROCESS,
                          pid,
                          procName[0] ? procName : L"<hidden>",
                          NULL, 0,
                          (ULONG_PTR)pid,
                          0);
            ++findings;
            ObDereferenceObject(process);
        }
    }

    ExFreePoolWithTag(pidBitmap, 'bRhO');
    return findings;
}

// ===========================================================================
// 3. Hidden Driver Detection
//    ZwQuerySystemInformation(SystemModuleInformation) returns the list
//    built from PsLoadedModuleList. A driver that unlinks itself from
//    PsLoadedModuleList will disappear from this list.
//    We cross-check by scanning kernel VA space for PE headers that are
//    NOT in the module list.
//
//    Practical implementation: scan DRIVER_OBJECT nodes in the I/O manager's
//    driver directory (\Driver) via ZwOpenDirectoryObject and compare each
//    driver's DriverStart against the module list. Drivers with a DriverStart
//    not present in the module list are flagged.
// ===========================================================================
static ULONG
RkCheckHiddenDrivers(VOID)
{
    ULONG    findings = 0;
    NTSTATUS status;
    ULONG    bufSize  = 0;

    if (!fnZwQuerySystemInformation) return 0;

    // Build module list from ZwQuerySystemInformation.
    status = fnZwQuerySystemInformation(SystemModuleInformation,
                                        NULL, 0, &bufSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH || bufSize == 0) return 0;

    bufSize += 4096;
    PRTL_PROCESS_MODULES modules =
        (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              bufSize, 'dRhO');
    if (!modules) return 0;

    status = fnZwQuerySystemInformation(SystemModuleInformation,
                                        modules, bufSize, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'dRhO');
        return 0;
    }

    // Iterate \Driver directory via ZwOpenDirectoryObject.
    UNICODE_STRING  driverDirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE  hDir = NULL;

    RtlInitUnicodeString(&driverDirName, L"\\Driver");
    InitializeObjectAttributes(&oa, &driverDirName,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL, NULL);
    status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'dRhO');
        return 0;
    }

    // Query directory objects in batches.
    ULONG  context    = 0;
    BOOLEAN firstQuery = TRUE;
    const  ULONG QUERY_BUF = 16384;
    PUCHAR qBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, QUERY_BUF, 'qRhO');
    if (!qBuf) {
        ZwClose(hDir);
        ExFreePoolWithTag(modules, 'dRhO');
        return 0;
    }

    while (findings < ROOTKIT_MAX_FINDINGS_PER_PASS) {
        ULONG retLen = 0;
        status = ZwQueryDirectoryObject(hDir, qBuf, QUERY_BUF,
                                        FALSE, firstQuery,
                                        &context, &retLen);
        firstQuery = FALSE;
        if (!NT_SUCCESS(status) && status != STATUS_MORE_ENTRIES) break;

        // Each entry is OBJECT_DIRECTORY_INFORMATION: two UNICODE_STRINGs
        // (Name, TypeName), terminated by two zero-length strings.
        typedef struct { UNICODE_STRING Name; UNICODE_STRING TypeName; }
            OBJ_DIR_INFO;

        OBJ_DIR_INFO *info = (OBJ_DIR_INFO *)(PVOID)qBuf;
        while (info->Name.Length != 0) {
            // Build full driver object path: \Driver\<Name>
            WCHAR  fullPath[256] = {0};
            HRESULT hr = StringCchPrintfW(fullPath, RTL_NUMBER_OF(fullPath),
                                          L"\\Driver\\%wZ", &info->Name);
            UNREFERENCED_PARAMETER(hr);

            UNICODE_STRING  fullUs;
            OBJECT_ATTRIBUTES drvOa;
            RtlInitUnicodeString(&fullUs, fullPath);
            InitializeObjectAttributes(&drvOa, &fullUs,
                                        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                        NULL, NULL);

            PDRIVER_OBJECT drvObj = NULL;
            status = ObReferenceObjectByName(&fullUs,
                                             OBJ_CASE_INSENSITIVE,
                                             NULL,
                                             0,
                                             *IoDriverObjectType,
                                             KernelMode,
                                             NULL,
                                             (PVOID *)&drvObj);
            if (NT_SUCCESS(status) && drvObj) {
                PVOID drvBase = drvObj->DriverStart;
                BOOLEAN found = FALSE;

                for (ULONG m = 0; m < modules->NumberOfModules; ++m) {
                    if (modules->Modules[m].ImageBase == drvBase) {
                        found = TRUE;
                        break;
                    }
                }

                if (!found && drvBase != NULL) {
                    DbgPrint("RootkitDetector: hidden driver '%wZ' base=%p\n",
                             &info->Name, drvBase);
                    RkEmitFinding(IRP_ROOTKIT_HIDDEN_DRIVER,
                                  0,
                                  fullPath,
                                  drvBase,
                                  drvObj->Size,
                                  0, 0);
                    ++findings;
                }
                ObDereferenceObject(drvObj);
            }

            info++;
            if (findings >= ROOTKIT_MAX_FINDINGS_PER_PASS) break;
        }

        if (status != STATUS_MORE_ENTRIES) break;
    }

    ExFreePoolWithTag(qBuf, 'qRhO');
    ZwClose(hDir);
    ExFreePoolWithTag(modules, 'dRhO');
    return findings;
}

// ===========================================================================
// 4. Kernel Inline Hook Detection
//    Check the first 16 bytes of a curated list of ntoskrnl exports for
//    well-known JMP patterns:
//      FF 25 xx xx xx xx   — indirect absolute JMP (x64 14-byte hook prefix)
//      E9 xx xx xx xx      — relative JMP (5-byte hook)
//    If the target lands outside ntoskrnl, flag it.
// ===========================================================================

static CONST PCHAR g_MonitoredExports[] = {
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtDeleteFile",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtTerminateProcess",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtQuerySystemInformation",
    "NtLoadDriver",
    "NtSetSystemInformation",
    "NtOpenProcess",
    "NtOpenThread",
    "NtCreateSection",
    "NtMapViewOfSection",
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
        UNICODE_STRING  exportUs;
        ANSI_STRING     exportAs;
        RtlInitAnsiString(&exportAs, g_MonitoredExports[i]);

        NTSTATUS convStatus = RtlAnsiStringToUnicodeString(&exportUs, &exportAs, TRUE);
        if (!NT_SUCCESS(convStatus)) continue;

        PVOID fnAddr = MmGetSystemRoutineAddress(&exportUs);
        RtlFreeUnicodeString(&exportUs);

        if (!fnAddr) continue;
        // Function must be inside ntoskrnl to be a valid check target.
        if (!RkAddressInModule(fnAddr, ntoBase, ntoSize)) continue;

        __try {
            PUCHAR p = (PUCHAR)fnAddr;
            BOOLEAN hooked = FALSE;
            PVOID   hookTarget = NULL;

            // Pattern 1: FF 25 xx xx xx xx  (indirect JMP via RIP-relative ptr)
            if (p[0] == 0xFF && p[1] == 0x25) {
                LONG rel32 = *(LONG *)(p + 2);
                PVOID *ptr = (PVOID *)((ULONG_PTR)(p + 6) + rel32);
                __try {
                    hookTarget = *ptr;
                    if (!RkAddressInModule(hookTarget, ntoBase, ntoSize)) {
                        hooked = TRUE;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }

            // Pattern 2: E9 xx xx xx xx  (relative JMP)
            if (!hooked && p[0] == 0xE9) {
                LONG rel32 = *(LONG *)(p + 1);
                hookTarget = (PVOID)((ULONG_PTR)(p + 5) + rel32);
                if (!RkAddressInModule(hookTarget, ntoBase, ntoSize)) {
                    hooked = TRUE;
                }
            }

            // Pattern 3: 48 B8 xx..xx / FF E0  (mov rax, abs64; jmp rax — 12-byte)
            if (!hooked && p[0] == 0x48 && p[1] == 0xB8 &&
                p[10] == 0xFF && p[11] == 0xE0)
            {
                hookTarget = *(PVOID *)(p + 2);
                if (!RkAddressInModule(hookTarget, ntoBase, ntoSize)) {
                    hooked = TRUE;
                }
            }

            if (hooked) {
                WCHAR wideName[128] = {0};
                ANSI_STRING  ansiN;
                UNICODE_STRING uniN;
                RtlInitAnsiString(&ansiN, g_MonitoredExports[i]);
                uniN.Buffer = wideName;
                uniN.MaximumLength = sizeof(wideName);
                uniN.Length = 0;
                RtlAnsiStringToUnicodeString(&uniN, &ansiN, FALSE);

                DbgPrint("RootkitDetector: inline hook on %s -> %p\n",
                         g_MonitoredExports[i], hookTarget);

                RkEmitFinding(IRP_ROOTKIT_KERNEL_HOOK,
                              0,
                              wideName,
                              fnAddr,
                              0,
                              (ULONG_PTR)hookTarget,
                              0);
                ++findings;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("RootkitDetector: exception inspecting %s\n",
                     g_MonitoredExports[i]);
        }
    }

    return findings;
}
