//
// edrav2.edrdrv project
//
// Process Protection - Enhanced process monitoring and protection
// Migrated from Owlyshield minifilter
//
/// @file Process protection with kernel API monitoring
/// @addtogroup edrdrv
/// @{
#pragma once

namespace cmd {
namespace processprotection {

//
// Initialize process protection features
//
NTSTATUS InitProcessProtection();

//
// Cleanup process protection
//
VOID UninitProcessProtection();

//
// Process lifecycle events
//
NTSTATUS OnProcessCreate(_In_ HANDLE ProcessId, _In_ HANDLE ParentProcessId);
NTSTATUS OnProcessExit(_In_ HANDLE ProcessId);

//
// Process handle operation events
//
NTSTATUS OnProcessHandleOperation(
	_In_ HANDLE CallerProcessId,
	_In_ HANDLE TargetProcessId,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ UCHAR OperationType);

//
// Process termination attempt
//
NTSTATUS OnProcessTerminationAttempt(
	_In_ HANDLE AttackerPid,
	_In_ HANDLE TargetPid);

//
// Kernel API events
//
NTSTATUS OnKernelApiEvent(
	_In_ ULONG IrpOp,
	_In_ ULONG EventType,
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_opt_z_ PCWSTR FunctionName,
	_In_opt_ ULONG_PTR EventArg1,
	_In_opt_ ULONG_PTR EventArg2,
	_In_opt_ ULONG_PTR EventArg3,
	_In_opt_ ULONG_PTR EventArg4);

//
// Memory operations
//
NTSTATUS OnMemoryWrite(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_ PVOID TargetAddress,
	_In_ SIZE_T Size,
	_In_ BOOLEAN IsExecutableMemory);

NTSTATUS OnMemoryProtectionChange(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_ PVOID BaseAddress,
	_In_ SIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_In_ ULONG OldProtection);

//
// Thread operations
//
NTSTATUS OnThreadCreation(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_ PVOID StartRoutine);

VOID NoteRemoteThreadCandidate(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid);

BOOLEAN ResolveRemoteThreadCandidate(
	_In_ ULONG TargetPid,
	_Out_ PULONG SourcePid);

//
// APC operations
//
NTSTATUS OnApcQueueing(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_ HANDLE ThreadHandle,
	_In_ PVOID ApcRoutine);

//
// Section operations
//
NTSTATUS OnSectionOperation(
	_In_ ULONG SourcePid,
	_In_ ULONG TargetPid,
	_In_opt_ PCWSTR SectionName,
	_In_ UCHAR OperationType);

//
// Process protection exclude rules management
//
NTSTATUS SetProcessProtectionExcludeRulesFromBuffer(
	_In_reads_bytes_(BytesRead) PUCHAR Buffer,
	_In_ ULONG BytesRead);

VOID ReloadProcessProtectionExcludeRules();

//
// Utility functions
//
VOID FormatProcessDescriptorByPid(
	_In_ ULONG ProcessId,
	_Out_writes_z_(OutCch) PWCHAR OutBuffer,
	_In_ SIZE_T OutCch);

} // namespace processprotection
} // namespace cmd

/// @}
