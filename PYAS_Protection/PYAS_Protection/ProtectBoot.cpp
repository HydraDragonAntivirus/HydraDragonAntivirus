#include "ProtectBoot.h"

#include <fltKernel.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntstrsafe.h>

#include "Driver_Common.h"

#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS \
    CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX \
    CTL_CODE(IOCTL_DISK_BASE, 0x000B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

//
// ProtectBoot.cpp
//
// Dangerous disk IOCTL protection using the existing SimplePYAS alert pipe.
// This file does NOT create a second pipe.
//
// JSON format matches the rest of this driver:
//   protected_file
//   attacker_path
//   attacker_pid
//   attack_type
//
// Extra field:
//   ioctl_code
//

extern "C" NTSTATUS SendAlertToPipe(_In_ PCWSTR Message, _In_ SIZE_T MessageLength);
extern "C" BOOLEAN IsProcessTrusted(_In_ HANDLE ProcessId);
extern "C" VOID NormalizeDevicePathToDos(_Inout_ PUNICODE_STRING Path);

static
BOOLEAN
ProtectBoot_IsDangerousDiskIoctl(
    _In_ ULONG IoControlCode
    )
{
    switch (IoControlCode)
    {
    case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
    case IOCTL_SCSI_PASS_THROUGH_DIRECT:
    case IOCTL_DISK_FORMAT_TRACKS:
    case IOCTL_DISK_FORMAT_TRACKS_EX:
        return TRUE;

    default:
        return FALSE;
    }
}

static
VOID
ProtectBoot_CopyTargetPath(
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_writes_bytes_(TargetPathBytes) PWCHAR TargetPath,
    _In_ SIZE_T TargetPathBytes
    )
{
    if (TargetPath == NULL || TargetPathBytes < sizeof(WCHAR))
        return;

    TargetPath[0] = L'\0';

    //
    // For disk/volume/device-control objects, a fully normalized filesystem
    // name is often unavailable. Prefer the file object's name if present,
    // otherwise use a stable logical target string.
    //
    if (FltObjects &&
        FltObjects->FileObject &&
        FltObjects->FileObject->FileName.Buffer &&
        FltObjects->FileObject->FileName.Length > 0)
    {
        NTSTATUS status = RtlStringCbPrintfW(
            TargetPath,
            TargetPathBytes,
            L"%wZ",
            &FltObjects->FileObject->FileName
            );

        if (NT_SUCCESS(status))
            return;
    }

    RtlStringCbCopyW(TargetPath, TargetPathBytes, L"BOOT_DISK_OR_DRIVE_LAYOUT");
}

static
NTSTATUS
ProtectBoot_SendDiskWiperAlert(
    _In_ HANDLE Pid,
    _In_ ULONG IoControlCode,
    _In_opt_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    WCHAR messageBuffer[2048];
    WCHAR escapedAttacker[768];
    WCHAR escapedTarget[512];
    WCHAR targetPath[512];

    PUNICODE_STRING attackerPath = NULL;

    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    RtlZeroMemory(escapedAttacker, sizeof(escapedAttacker));
    RtlZeroMemory(escapedTarget, sizeof(escapedTarget));
    RtlZeroMemory(targetPath, sizeof(targetPath));

    ProtectBoot_CopyTargetPath(FltObjects, targetPath, sizeof(targetPath));

    NTSTATUS status = SeLocateProcessImageName(PsGetCurrentProcess(), &attackerPath);
    if (NT_SUCCESS(status) && attackerPath && attackerPath->Buffer)
    {
        NormalizeDevicePathToDos(attackerPath);
    }

    PCWSTR attackerName =
        (attackerPath && attackerPath->Buffer) ? attackerPath->Buffer : L"Unknown";

    if (!EscapeJsonString(escapedAttacker, sizeof(escapedAttacker), attackerName))
    {
        RtlStringCbCopyW(escapedAttacker, sizeof(escapedAttacker), L"ErrorEscapingPath");
    }

    if (!EscapeJsonString(escapedTarget, sizeof(escapedTarget), targetPath))
    {
        RtlStringCbCopyW(escapedTarget, sizeof(escapedTarget), L"ErrorEscapingTarget");
    }

    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"source\":\"simplepyas\",\"category\":\"disk\",\"action\":\"blocked\",\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%llu,\"attack_type\":\"DISK_WIPER_ATTEMPT\",\"ioctl_code\":%lu}",
        escapedTarget,
        escapedAttacker,
        (unsigned long long)(ULONG_PTR)Pid,
        IoControlCode
        );

    if (attackerPath)
    {
        ExFreePool(attackerPath);
        attackerPath = NULL;
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProtectBoot] Failed to format disk-wiper alert: 0x%X\n", status);
        return status;
    }

    SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);
    status = SendAlertToPipe(messageBuffer, messageLength);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[ProtectBoot] Failed to send disk-wiper alert: 0x%X\n", status);
    }

    return status;
}

extern "C"
FLT_PREOP_CALLBACK_STATUS
ProtectBoot_PreDeviceControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (Data == NULL || Data->Iopb == NULL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // Never block kernel-mode storage-stack operations here.
    //
    if (Data->RequestorMode == KernelMode)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    //
    // IsProcessTrusted and SeLocateProcessImageName are PASSIVE_LEVEL only
    // in this implementation. At higher IRQL, do not false-block.
    //
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONG ioControlCode =
        Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;

    if (!ProtectBoot_IsDangerousDiskIoctl(ioControlCode))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    HANDLE pid = PsGetCurrentProcessId();

    if (IsProcessTrusted(pid))
    {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ProtectBoot_SendDiskWiperAlert(pid, ioControlCode, FltObjects);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;

    DbgPrint("[ProtectBoot] Blocked dangerous disk IOCTL 0x%X from PID %llu\n",
        ioControlCode,
        (unsigned long long)(ULONG_PTR)pid);

    return FLT_PREOP_COMPLETE;
}
