#include "AmsiProtection.h"
#include "common.h"
#include "common.h"
#include "DriverData.h"
#include <ntstrsafe.h>

extern DriverData* driverData;

// Heuristic signatures for AMSI bypass detection (lower-case)
static const PCWSTR g_AmsiBypassPatterns[] = {
    L"amsiinitfailed",
    L"amsiutils",
    L"amsiscanbuffer",
    L"amsicontext",
    L"amsisession",
    L"nonpublic,static", // Used in Reflection-based bypasses
    L"system.management.automation.amsi"
};

NTSTATUS AmsiInitialize() {
    return STATUS_SUCCESS;
}

VOID AmsiCleanup() {
}

VOID AmsiScanCommandLine(_In_ ULONG ProcessId, _In_ PCUNICODE_STRING CommandLine) {
    if (CommandLine == NULL || CommandLine->Buffer == NULL || CommandLine->Length == 0) {
        return;
    }

    // Convert command line to lowercase for case-insensitive matching
    WCHAR* lowerBuffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, CommandLine->Length + sizeof(WCHAR), 'isma');
    if (lowerBuffer == NULL) return;

    RtlCopyMemory(lowerBuffer, CommandLine->Buffer, CommandLine->Length);
    lowerBuffer[CommandLine->Length / sizeof(WCHAR)] = L'\0';
    // Lowercase in-place using the WDK-safe helper (no CRT dependency).
    ULONG const charCount = CommandLine->Length / sizeof(WCHAR);
    for (ULONG i = 0; i < charCount; i++)
        lowerBuffer[i] = RtlDowncaseUnicodeChar(lowerBuffer[i]);

    BOOLEAN matchFound = FALSE;
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_AmsiBypassPatterns); i++) {
        if (wcsstr(lowerBuffer, g_AmsiBypassPatterns[i]) != NULL) {
            matchFound = TRUE;
            break;
        }
    }

    if (matchFound) {
        // High-confidence bypass attempt detected via command line
        AmsiReportEvent(ProcessId, L"AmsiBypassHeuristic", lowerBuffer, (ULONG)CommandLine->Length);
    }

    ExFreePoolWithTag(lowerBuffer, 'isma');
}

NTSTATUS AmsiReportEvent(
    _In_ ULONG SourcePid,
    _In_opt_ PCWSTR FunctionName,
    _In_opt_ PVOID AmsiContent,
    _In_ ULONG AmsiSize
) {
    if (driverData == NULL || driverData->isFilterClosed())
        return STATUS_DEVICE_NOT_READY;

    // Use a unique IRP_ENTRY for AMSI telemetry to avoid touching ProcessProtection.cpp logic
    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    PDRIVER_MESSAGE newItem = &newEntry->data;
    
    BOOLEAN found = FALSE;
    ULONGLONG gid = driverData->GetProcessGid(SourcePid, &found);

    newItem->PID = SourcePid;
    newItem->Gid = gid;
    newItem->AttackerPID = SourcePid;
    newItem->AttackerGid = gid;
    newItem->IRP_OP = IRP_USERMODE_HOOK_EVENT;

    // Population of new high-fidelity telemetry fields specifically for AMSI
    newItem->KernelEventInfo.EventType = IRP_USERMODE_HOOK_EVENT;
    newItem->KernelEventInfo.SourceProcessId = SourcePid;
    newItem->KernelEventInfo.Timestamp = KeQueryInterruptTime();
    newItem->KernelEventInfo.IsAmsiEvent = TRUE;

    if (AmsiContent && AmsiSize > 0) {
        // Max 256 WCHARs = 512 bytes
        ULONG copySize = (AmsiSize > 510) ? 510 : AmsiSize;
        RtlCopyMemory(newItem->KernelEventInfo.AmsiContentSample, AmsiContent, copySize);
    }

    if (FunctionName) {
        RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, RTL_NUMBER_OF(newItem->KernelEventInfo.ObjectName), FunctionName);
    } else {
        RtlStringCchCopyW(newItem->KernelEventInfo.ObjectName, RTL_NUMBER_OF(newItem->KernelEventInfo.ObjectName), L"AmsiScanEvent");
    }

    // Dispatch to the same message queue used by other behavioral events
    if (!driverData->AddIrpMessage(newEntry)) {
        delete newEntry;
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}






