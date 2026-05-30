#pragma once
#include <fltKernel.h>
#include "SharedDefs.h"

/**
 * @brief Initialize the AMSI protection module.
 */
NTSTATUS AmsiInitialize();

/**
 * @brief Cleanup AMSI protection module resources.
 */
VOID AmsiCleanup();

/**
 * @brief Scans a process command line for common AMSI bypass patterns.
 * 
 * @param ProcessId The PID of the process.
 * @param CommandLine The full command line string.
 */
VOID AmsiScanCommandLine(_In_ ULONG ProcessId, _In_ PCUNICODE_STRING CommandLine);

/**
 * @brief Reports an AMSI-related security event to the user-mode behavioral engine.
 * 
 * @param SourcePid The PID that triggered the event.
 * @param FunctionName Optional name of the intercepted AMSI function.
 * @param AmsiContent Pointer to the captured script content or buffer.
 * @param AmsiSize Size of the content buffer.
 */
NTSTATUS AmsiReportEvent(
    _In_ ULONG SourcePid,
    _In_opt_ PCWSTR FunctionName,
    _In_opt_ PVOID AmsiContent,
    _In_ ULONG AmsiSize
);
