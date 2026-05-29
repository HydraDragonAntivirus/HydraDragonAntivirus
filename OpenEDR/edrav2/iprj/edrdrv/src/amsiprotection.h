//
// edrav2.edrdrv project
//
// AMSI Protection - AMSI bypass detection
// Migrated from Owlyshield minifilter
//
/// @file AMSI bypass detection and protection
/// @addtogroup edrdrv
/// @{
#pragma once

namespace cmd {
namespace amsiprotection {

///
/// Initialize AMSI protection
///
NTSTATUS initialize();

///
/// Cleanup AMSI protection
///
void finalize();

///
/// Scan command line for AMSI bypass patterns
///
void scanCommandLine(
	_In_ ULONG ProcessId,
	_In_ PCUNICODE_STRING CommandLine);

///
/// Report AMSI event to user mode
///
NTSTATUS reportEvent(
	_In_ ULONG SourcePid,
	_In_opt_ PCWSTR FunctionName,
	_In_opt_ PVOID AmsiContent,
	_In_ ULONG AmsiSize);

} // namespace amsiprotection
} // namespace cmd

/// @}
