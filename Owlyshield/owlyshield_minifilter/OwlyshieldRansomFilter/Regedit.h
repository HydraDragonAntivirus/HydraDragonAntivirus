#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>

#define REG_TAG 'gkER'

// Paths to protect
#define REG_PROTECT_SUBPATH L"\\SOFTWARE\\OwlyShield"
#define REG_PROTECT_PYAS L"\\Services\\SimplePYASProtection"
#define REG_PROTECT_OWLY L"\\Services\\owlyshield_ransom"
#define REG_PROTECT_SANCTUM L"\\Services\\sanctum_ppl_runner"
#define REG_PROTECT_MBRFILTER L"\\Services\\MBRFilter"
#define REG_PROTECT_WINLOGON L"\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

// Declarations
NTSTATUS RegeditDriverEntry();
NTSTATUS RegeditUnloadDriver();

// Callback
NTSTATUS RegistryCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2
);

// Worker item
typedef struct _REGISTRY_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING RegPath;
    UNICODE_STRING AttackerPath;
    HANDLE AttackerPid;
    WCHAR Operation[64];
} REGISTRY_ALERT_WORK_ITEM, * PREGISTRY_ALERT_WORK_ITEM;
