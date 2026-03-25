/*++

Module Name:

    RootkitDetector.cpp

Abstract:

    Event-driven rootkit detection engine.
    No timer - detection triggered via RootkitDetectorOnDriverEvent().

    Called by FSFilter.cpp on relevant IRP events:
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
#include "DriverData.h"
#include <ntimage.h>
#include <ntstrsafe.h>

// ---------------------------------------------------------------------------
// External
// ---------------------------------------------------------------------------
extern DriverData *driverData;

// ---------------------------------------------------------------------------
// Dynamic imports
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI *PZW_QUERY_SYSTEM_INFORMATION)(
    _In_      ULONG  SystemInformationClass,
    _Inout_   PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef NTSTATUS (NTAPI *PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
    _In_  HANDLE     ProcessId,
    _Out_ PEPROCESS *Process);

static PZW_QUERY_SYSTEM_INFORMATION     fnZwQuerySystemInformation    = NULL;
static PPS_LOOKUP_PROCESS_BY_PROCESS_ID fnPsLookupProcessByProcessId  = NULL;

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
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;
#pragma pack(pop)

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
} SYSTEM_SERVICE_DESCRIPTOR_TABLE;

EXTERN_C SYSTEM_SERVICE_DESCRIPTOR_TABLE KeServiceDescriptorTable;

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

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------
static VOID  RkWorkItemRoutine(_In_ PDEVICE_OBJECT DevObj, _In_opt_ PVOID Ctx);
static ULONG RkCheckSsdtIntegrity(VOID);
static ULONG RkCheckHiddenProcesses(VOID);
static ULONG RkCheckHiddenDrivers(VOID);
static ULONG RkCheckKernelInlineHooks(VOID);
static VOID  RkEmitFinding(_In_ ULONG IrpOpCode, _In_ ULONG SourcePid,
                            _In_opt_ PCWSTR ObjectName,
                            _In_opt_ PVOID  MemoryAddress, _In_ SIZE_T MemSize,
                            _In_ ULONG_PTR Extra1, _In_ ULONG_PTR Extra2);
static BOOLEAN RkAddressInModule(_In_ PVOID Address,
                                 _In_ PVOID Base, _In_ ULONG Size);
static BOOLEAN RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size);

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
        DbgPrint("RootkitDetector: ZwQuerySystemInformation not found\n");
        return STATUS_NOT_FOUND;
    }

    RtlInitUnicodeString(&name, L"PsLookupProcessByProcessId");
    fnPsLookupProcessByProcessId =
        (PPS_LOOKUP_PROCESS_BY_PROCESS_ID)MmGetSystemRoutineAddress(&name);
    if (!fnPsLookupProcessByProcessId) {
        DbgPrint("RootkitDetector: PsLookupProcessByProcessId not found\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("RootkitDetector: Initialized (event-driven, debounce=%lu ms)\n",
             (ULONG)ROOTKIT_DEBOUNCE_MS);
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
    if (g_ScanWorkItem) {
        IoFreeWorkItem(g_ScanWorkItem);
        g_ScanWorkItem = NULL;
    }
    DbgPrint("RootkitDetector: Cleanup done\n");
}

// ---------------------------------------------------------------------------
// RootkitDetectorOnDriverEvent
// Called on every relevant driver event (IRP dispatch path or callbacks).
// Debounces FULL scans; queues a passive-level work item.
// ---------------------------------------------------------------------------
VOID
RootkitDetectorOnDriverEvent(_In_ RK_TRIGGER Trigger, _In_ ULONG EventIrp)
{
    UNREFERENCED_PARAMETER(EventIrp);

    if (!g_ScanWorkItem || !g_ScanDeviceObject) {
        return;
    }

    // For FULL scans: enforce minimum interval between scans.
    if (Trigger == RK_TRIGGER_FULL) {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);

        LONGLONG debounce100ns = (LONGLONG)ROOTKIT_DEBOUNCE_MS * 10000LL;
        LONGLONG last = InterlockedCompareExchange64(&g_LastFullScanTick, 0, 0);

        if (last != 0 && (now.QuadPart - last) < debounce100ns) {
            // Too soon — upgrade a pending light scan to full but don't queue new item.
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
    if (total > 0) {
        DbgPrint("RootkitDetector: scan complete — %lu anomalies\n", total);
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
    if (!driverData) return;

    IRP_ENTRY *entry = new (NonPagedPool, 'kRhO') IRP_ENTRY();
    if (!entry) return;

    PDRIVER_MESSAGE msg = &entry->data;
    RtlZeroMemory(msg, sizeof(*msg));

    msg->IRP_OP                              = (UCHAR)IrpOpCode;
    msg->PID                                 = SourcePid;
    msg->Gid                                 = 0;
    msg->KernelEventInfo.EventType           = IrpOpCode;
    msg->KernelEventInfo.SourceProcessId     = SourcePid;
    msg->KernelEventInfo.MemoryAddress       = MemoryAddress;
    msg->KernelEventInfo.MemorySize          = MemSize;
    msg->KernelEventInfo.RawArgument1        = Extra1;
    msg->KernelEventInfo.RawArgument2        = Extra2;

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

static BOOLEAN
RkAddressInModule(_In_ PVOID Address, _In_ PVOID Base, _In_ ULONG Size)
{
    ULONG_PTR addr = (ULONG_PTR)Address;
    ULONG_PTR base = (ULONG_PTR)Base;
    return (addr >= base && addr < (base + (ULONG_PTR)Size));
}

static BOOLEAN
RkGetNtoskrnlRange(_Out_ PVOID *Base, _Out_ ULONG *Size)
{
    if (!fnZwQuerySystemInformation) return FALSE;

    ULONG    need   = 0;
    NTSTATUS status = fnZwQuerySystemInformation(SystemModuleInformation,
                                                 NULL, 0, &need);
    if (status != STATUS_INFO_LENGTH_MISMATCH || need == 0) return FALSE;

    need += 4096;
    PRTL_PROCESS_MODULES mods =
        (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED, need, 'kMhO');
    if (!mods) return FALSE;

    status = fnZwQuerySystemInformation(SystemModuleInformation, mods, need, NULL);
    if (!NT_SUCCESS(status) || mods->NumberOfModules == 0) {
        ExFreePoolWithTag(mods, 'kMhO');
        return FALSE;
    }

    *Base = mods->Modules[0].ImageBase;
    *Size = mods->Modules[0].ImageSize;
    ExFreePoolWithTag(mods, 'kMhO');
    return TRUE;
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

    if (!RkGetNtoskrnlRange(&ntoBase, &ntoSize)) return 0;

    __try {
        PULONG   table = (PULONG)KeServiceDescriptorTable.ServiceTable;
        ULONG_PTR count = KeServiceDescriptorTable.NumberOfServices;

        if (!table || count == 0 || count > 0x1000) return 0;

        for (ULONG_PTR i = 0;
             i < count && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
             ++i)
        {
            __try {
                LONG_PTR enc      = (LONG_PTR)(LONG)table[i];
                PVOID    resolved = (PVOID)((ULONG_PTR)&table[i] + (enc >> 4));

                if (!RkAddressInModule(resolved, ntoBase, ntoSize)) {
                    WCHAR desc[128];
                    StringCchPrintfW(desc, RTL_NUMBER_OF(desc),
                        L"SSDT[%llu]=0x%p outside ntoskrnl",
                        (ULONGLONG)i, resolved);

                    DbgPrint("RootkitDetector: SSDT hook index=%llu -> %p\n",
                             (ULONGLONG)i, resolved);

                    RkEmitFinding(IRP_ROOTKIT_SSDT_HOOK, 0, desc,
                                  resolved, 0,
                                  (ULONG_PTR)i, (ULONG_PTR)enc);
                    ++findings;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("RootkitDetector: SSDT check exception 0x%X\n",
                 GetExceptionCode());
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
    NTSTATUS status;
    ULONG    need     = 0;

    if (!fnZwQuerySystemInformation || !fnPsLookupProcessByProcessId) return 0;

    status = fnZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &need);
    if (status != STATUS_INFO_LENGTH_MISMATCH || need == 0) return 0;

    need += 65536;
    PUCHAR buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, need, 'pRhO');
    if (!buf) return 0;

    status = fnZwQuerySystemInformation(SystemProcessInformation, buf, need, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(buf, 'pRhO'); return 0; }

    // Build a 64KB bitmap of known PIDs.
    const ULONG BITMAP_BYTES = 65536 / 8;
    PUCHAR bitmap = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                            BITMAP_BYTES, 'bRhO');
    if (!bitmap) { ExFreePoolWithTag(buf, 'pRhO'); return 0; }
    RtlZeroMemory(bitmap, BITMAP_BYTES);

    SYSTEM_PROCESS_INFORMATION *entry =
        (SYSTEM_PROCESS_INFORMATION *)(PVOID)buf;
    while (TRUE) {
        ULONG pid = (ULONG)(ULONG_PTR)entry->UniqueProcessId;
        if (pid < 65536) bitmap[pid / 8] |= (UCHAR)(1 << (pid % 8));
        if (!entry->NextEntryOffset) break;
        entry = (SYSTEM_PROCESS_INFORMATION *)((PUCHAR)entry +
                                                entry->NextEntryOffset);
    }
    ExFreePoolWithTag(buf, 'pRhO');

    // Scan PID space: PIDs in PspCidTable but absent from the list are DKOM-hidden.
    for (ULONG pid = 4;
         pid < 65536 && findings < ROOTKIT_MAX_FINDINGS_PER_PASS;
         pid += 4)
    {
        if (bitmap[pid / 8] & (1 << (pid % 8))) continue; // visible, skip

        PEPROCESS proc = NULL;
        if (NT_SUCCESS(fnPsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc))
            && proc != NULL)
        {
            WCHAR name[32] = {0};
            PUCHAR imgName = (PUCHAR)PsGetProcessImageFileName(proc);
            if (imgName) {
                ANSI_STRING   as = { (USHORT)strnlen((PCHAR)imgName, 15), 15,
                                     (PCHAR)imgName };
                UNICODE_STRING us = { 0, sizeof(name), name };
                RtlAnsiStringToUnicodeString(&us, &as, FALSE);
            }

            DbgPrint("RootkitDetector: DKOM hidden process PID=%lu name=%S\n",
                     pid, name);
            RkEmitFinding(IRP_ROOTKIT_HIDDEN_PROCESS, pid,
                          name[0] ? name : L"<hidden>",
                          NULL, 0, (ULONG_PTR)pid, 0);
            ++findings;
            ObDereferenceObject(proc);
        }
    }

    ExFreePoolWithTag(bitmap, 'bRhO');
    return findings;
}

// ===========================================================================
// 3. Hidden Driver
// ===========================================================================
static ULONG
RkCheckHiddenDrivers(VOID)
{
    ULONG    findings = 0;
    NTSTATUS status;
    ULONG    need     = 0;

    if (!fnZwQuerySystemInformation) return 0;

    status = fnZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &need);
    if (status != STATUS_INFO_LENGTH_MISMATCH || need == 0) return 0;

    need += 4096;
    PRTL_PROCESS_MODULES mods =
        (PRTL_PROCESS_MODULES)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              need, 'dRhO');
    if (!mods) return 0;

    status = fnZwQuerySystemInformation(SystemModuleInformation, mods, need, NULL);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(mods, 'dRhO'); return 0; }

    UNICODE_STRING   dirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE            hDir = NULL;

    RtlInitUnicodeString(&dirName, L"\\Driver");
    InitializeObjectAttributes(&oa, &dirName,
                                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                NULL, NULL);
    if (!NT_SUCCESS(ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa))) {
        ExFreePoolWithTag(mods, 'dRhO');
        return 0;
    }

    const ULONG QBUF = 16384;
    PUCHAR qbuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, QBUF, 'qRhO');
    if (!qbuf) {
        ZwClose(hDir);
        ExFreePoolWithTag(mods, 'dRhO');
        return 0;
    }

    typedef struct { UNICODE_STRING Name; UNICODE_STRING TypeName; } OBJ_DIR_INFO;

    ULONG   ctx       = 0;
    BOOLEAN firstCall = TRUE;

    while (findings < ROOTKIT_MAX_FINDINGS_PER_PASS) {
        ULONG ret = 0;
        status = ZwQueryDirectoryObject(hDir, qbuf, QBUF,
                                        FALSE, firstCall, &ctx, &ret);
        firstCall = FALSE;
        if (!NT_SUCCESS(status) && status != STATUS_MORE_ENTRIES) break;

        OBJ_DIR_INFO *info = (OBJ_DIR_INFO *)(PVOID)qbuf;
        while (info->Name.Length != 0 &&
               findings < ROOTKIT_MAX_FINDINGS_PER_PASS)
        {
            WCHAR path[256] = {0};
            StringCchPrintfW(path, RTL_NUMBER_OF(path),
                             L"\\Driver\\%wZ", &info->Name);

            UNICODE_STRING pathUs;
            RtlInitUnicodeString(&pathUs, path);

            PDRIVER_OBJECT drv = NULL;
            if (NT_SUCCESS(ObReferenceObjectByName(
                    &pathUs, OBJ_CASE_INSENSITIVE, NULL, 0,
                    *IoDriverObjectType, KernelMode, NULL,
                    (PVOID *)&drv)) && drv)
            {
                PVOID base  = drv->DriverStart;
                BOOLEAN hit = TRUE;
                for (ULONG m = 0; m < mods->NumberOfModules; ++m) {
                    if (mods->Modules[m].ImageBase == base) { hit = FALSE; break; }
                }
                if (hit && base) {
                    DbgPrint("RootkitDetector: hidden driver '%wZ' base=%p\n",
                             &info->Name, base);
                    RkEmitFinding(IRP_ROOTKIT_HIDDEN_DRIVER, 0, path,
                                  base, (SIZE_T)drv->Size, 0, 0);
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
    ExFreePoolWithTag(mods, 'dRhO');
    return findings;
}

// ===========================================================================
// 4. Kernel Inline Hook Detection
// ===========================================================================
static CONST PCHAR g_MonitoredExports[] = {
    "NtCreateFile",        "NtOpenFile",           "NtReadFile",
    "NtWriteFile",         "NtDeleteFile",          "NtCreateProcess",
    "NtCreateProcessEx",   "NtTerminateProcess",    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory","NtWriteVirtualMemory","NtCreateThread",
    "NtCreateThreadEx",    "NtQuerySystemInformation","NtLoadDriver",
    "NtSetSystemInformation","NtOpenProcess",       "NtOpenThread",
    "NtCreateSection",     "NtMapViewOfSection",
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

            // FF 25 rel32 — indirect JMP (x64 14-byte hook)
            if (p[0] == 0xFF && p[1] == 0x25) {
                LONG rel = *(LONG *)(p + 2);
                PVOID *ptr = (PVOID *)((ULONG_PTR)(p + 6) + rel);
                __try {
                    target = *ptr;
                    if (!RkAddressInModule(target, ntoBase, ntoSize))
                        hooked = TRUE;
                } __except (EXCEPTION_EXECUTE_HANDLER) {}
            }

            // E9 rel32 — relative JMP (5-byte hook)
            if (!hooked && p[0] == 0xE9) {
                LONG rel = *(LONG *)(p + 1);
                target = (PVOID)((ULONG_PTR)(p + 5) + rel);
                if (!RkAddressInModule(target, ntoBase, ntoSize))
                    hooked = TRUE;
            }

            // 48 B8 imm64 / FF E0 — mov rax, imm64; jmp rax (12-byte)
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

                DbgPrint("RootkitDetector: inline hook %s -> %p\n",
                         g_MonitoredExports[i], target);
                RkEmitFinding(IRP_ROOTKIT_KERNEL_HOOK, 0, wnBuf,
                              fn, 0, (ULONG_PTR)target, 0);
                ++findings;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("RootkitDetector: exception inspecting %s\n",
                     g_MonitoredExports[i]);
        }
    }

    return findings;
}
