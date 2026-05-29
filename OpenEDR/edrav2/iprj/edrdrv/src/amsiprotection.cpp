//
// edrav2.edrdrv project
//
// AMSI Protection - AMSI bypass detection
// Migrated from Owlyshield minifilter
//
/// @file AMSI bypass detection and protection
/// @addtogroup edrdrv
/// @{
#include "common.h"
#include "amsiprotection.h"
#include "fltport.h"
#include <ntstrsafe.h>

namespace cmd {
namespace amsiprotection {

//
// Heuristic signatures for AMSI bypass detection (lower-case)
//
static const PCWSTR g_AmsiBypassPatterns[] = {
	L"amsiinitfailed",
	L"amsiutils",
	L"amsiscanbuffer",
	L"amsicontext",
	L"amsisession",
	L"nonpublic,static", // Used in Reflection-based bypasses
	L"system.management.automation.amsi"
};

///
/// Initialize AMSI protection
///
NTSTATUS initialize()
{
	LOGINFO1("AMSI Protection initialized");
	return STATUS_SUCCESS;
}

///
/// Cleanup AMSI protection
///
void finalize()
{
	LOGINFO1("AMSI Protection finalized");
}

///
/// Scan command line for AMSI bypass patterns
///
void scanCommandLine(
	_In_ ULONG ProcessId,
	_In_ PCUNICODE_STRING CommandLine)
{
	if (CommandLine == nullptr || CommandLine->Buffer == nullptr || CommandLine->Length == 0)
		return;

	// Convert command line to lowercase for case-insensitive matching
	WCHAR* lowerBuffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, 
		CommandLine->Length + sizeof(WCHAR), c_nAllocTag);
	if (lowerBuffer == nullptr)
		return;

	RtlCopyMemory(lowerBuffer, CommandLine->Buffer, CommandLine->Length);
	lowerBuffer[CommandLine->Length / sizeof(WCHAR)] = L'\0';
	
	// Lowercase in-place
	ULONG const charCount = CommandLine->Length / sizeof(WCHAR);
	for (ULONG i = 0; i < charCount; i++)
		lowerBuffer[i] = RtlDowncaseUnicodeChar(lowerBuffer[i]);

	BOOLEAN matchFound = FALSE;
	for (ULONG i = 0; i < RTL_NUMBER_OF(g_AmsiBypassPatterns); i++)
	{
		if (wcsstr(lowerBuffer, g_AmsiBypassPatterns[i]) != nullptr)
		{
			matchFound = TRUE;
			break;
		}
	}

	if (matchFound)
	{
		// High-confidence bypass attempt detected via command line
		reportEvent(ProcessId, L"AmsiBypassHeuristic", lowerBuffer, (ULONG)CommandLine->Length);
	}

	ExFreePoolWithTag(lowerBuffer, c_nAllocTag);
}

///
/// Report AMSI event to user mode
///
NTSTATUS reportEvent(
	_In_ ULONG SourcePid,
	_In_opt_ PCWSTR FunctionName,
	_In_opt_ PVOID AmsiContent,
	_In_ ULONG AmsiSize)
{
	// Create event message
	fltport::RawEvent event = {};
	event.nEventId = fltport::RawEventId::PROCMON_PROCESS_MEMORY_WRITE; // Reuse existing event type
	event.nProcessId = SourcePid;
	event.nThreadId = 0;
	
	// Send to user mode
	NTSTATUS status = fltport::sendRawEvent(&event);
	
	if (NT_SUCCESS(status))
	{
		LOGINFO2("AMSI bypass attempt detected from PID %lu", SourcePid);
	}
	
	return status;
}

} // namespace amsiprotection
} // namespace cmd

/// @}
