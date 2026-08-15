#include "AmsiProtection.h"
#include "common.h"
#include "osutils.h"   // cmd::getTickCount64
#include "fltport.h"
#include <ntstrsafe.h>

using EvFld   = cmd::edrdrv::EventField;
using SysmonEv = cmd::edrdrv::SysmonEvent;

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
    UNREFERENCED_PARAMETER(AmsiContent);
    UNREFERENCED_PARAMETER(AmsiSize);

    if (!cmd::fltport::isClientConnected())
        return STATUS_DEVICE_NOT_READY;

    // AMSI events are delivered as OwlyHookEvent (DeviceIoControl carrier, 0x000E).
    // OwlyHookEventType = IRP_USERMODE_HOOK_EVENT (20) identifies it on the Rust side.
    // OwlyHookFunctionName carries the label ("AmsiBypassHeuristic" etc.).
    cmd::NonPagedLbvsSerializer<cmd::edrdrv::EventField> serializer;

    if (!serializer.write(EvFld::RawEventId,
            uint16_t(SysmonEv::DeviceIoControl)))         return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::TickTime,
            (uint64_t)cmd::getTickCount64()))              return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::ProcessPid,
            (uint32_t)SourcePid))                         return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::OwlyHookEventType,
            (uint32_t)IRP_USERMODE_HOOK_EVENT))            return STATUS_NO_MEMORY;
    if (!serializer.write(EvFld::OwlyHookSourcePid,
            (uint32_t)SourcePid))                         return STATUS_NO_MEMORY;

    // Function name / label
    if (FunctionName != NULL) {
        UNICODE_STRING fnUs;
        RtlInitUnicodeString(&fnUs, FunctionName);
        if (!cmd::write(serializer, EvFld::OwlyHookFunctionName, &fnUs))
            return STATUS_NO_MEMORY;
    }

    return cmd::fltport::sendRawEvent(serializer);
}
