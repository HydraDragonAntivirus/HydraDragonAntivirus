#pragma once

#include <fltKernel.h>

NTSTATUS
FSAllocateUnicodeString(_Inout_ PUNICODE_STRING String);

VOID FSFreeUnicodeString(_Inout_ PUNICODE_STRING String);

// Convert an NT namespace path (\Device\HarddiskVolumeX\...) to a DOS drive-letter
// path (C:\...) using IoGetDeviceObjectPointer + IoVolumeDeviceToDosName.
//
// IRQL: Must be called at PASSIVE_LEVEL.
// Returns TRUE and writes the converted path to OutBuffer on success.
// Returns FALSE and leaves OutBuffer unchanged on any failure (caller keeps original).
BOOLEAN
NtPathToDosPath(
    _In_z_          PCWSTR  NtPath,
    _Out_writes_z_(OutCch) PWCHAR  OutBuffer,
    _In_            SIZE_T  OutCch
);
