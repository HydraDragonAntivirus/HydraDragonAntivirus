// Regedit.c - Registry protection with user-mode alerting (FIXED)
#include "Driver.h"
#include "Driver_Regedit.h"
#include "Driver_Common.h"
#include "Driver_Process.h"
#include "ProtectionRules.h"

LARGE_INTEGER Cookie;

// Work item for deferred registry alerts
typedef struct _REGISTRY_ALERT_WORK_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    UNICODE_STRING RegPath;
    UNICODE_STRING AttackerPath;
    HANDLE AttackerPid;
    WCHAR Operation[64];
} REGISTRY_ALERT_WORK_ITEM, * PREGISTRY_ALERT_WORK_ITEM;

// Prototypes
NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2);
VOID RegistryAlertWorker(PVOID Context);
NTSTATUS QueueRegistryAlertToUserMode(PUNICODE_STRING RegPath, PCWSTR Operation);

#define REGISTRY_READONLY_WRITE_MASK (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | \
                                      DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL)

static BOOLEAN IsCurrentRegistryTrusted(VOID);
static BOOLEAN RegistryAccessRequestsWrite(_In_ ACCESS_MASK DesiredAccess);
static BOOLEAN IsRegistryPathProtected(_In_ PUNICODE_STRING RegPath);
static BOOLEAN IsComRegistryPath(_In_ PUNICODE_STRING RegPath);
static BOOLEAN IsPerUserComRegistryPath(_In_ PUNICODE_STRING RegPath);
static NTSTATUS DenyRegistryOperation(_In_ PUNICODE_STRING RegPath, _In_ PCWSTR Operation);
static NTSTATUS ReportComRegistryOperation(_In_ PUNICODE_STRING RegPath, _In_ PCWSTR Operation);
static BOOLEAN BuildRegistryPath(
    _Inout_ PUNICODE_STRING RegPath,
    _In_opt_ PVOID RootObject,
    _In_opt_ PUNICODE_STRING CompleteName
);

// NOTE: Function definitions now have SAL annotations matching the header file.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject
);

BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern);


NTSTATUS RegeditDriverEntry()
{
    NTSTATUS status = CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Registry-Protection] Initialized successfully\r\n");
    }
    else
    {
        DbgPrint("[Registry-Protection] Failed to initialize: 0x%X\r\n", status);
    }
    return status;
}

NTSTATUS RegeditUnloadDriver()
{
    if (Cookie.QuadPart != 0)
    {
        CmUnRegisterCallback(Cookie);
        Cookie.QuadPart = 0;
    }
    DbgPrint("[Registry-Protection] Unloaded\r\n");
    return STATUS_SUCCESS;
}

// Worker routine running at PASSIVE_LEVEL
VOID RegistryAlertWorker(PVOID Context)
{
    PREGISTRY_ALERT_WORK_ITEM workItem = (PREGISTRY_ALERT_WORK_ITEM)Context;
    NTSTATUS status;
    WCHAR messageBuffer[2048];
    WCHAR escapedRegPath[1024];
    WCHAR escapedAttacker[1024];
    PCWSTR attackType;
    PCWSTR category;
    PCWSTR action;

    PCWSTR attackerName = workItem->AttackerPath.Buffer ? workItem->AttackerPath.Buffer : L"Unknown";
    BOOLEAN isComEvent = StartsWithInsensitive(workItem->Operation, L"COM_");
    BOOLEAN isTelemetryOnly = ContainsSubstringInsensitive(workItem->Operation, L"TELEMETRY");
    attackType = isComEvent ? L"COM_REGISTRY_TAMPERING" : L"REGISTRY_TAMPERING";
    category = isComEvent ? L"com" : L"registry";
    action = isTelemetryOnly ? L"telemetry" : L"blocked";

    RtlZeroMemory(escapedRegPath, sizeof(escapedRegPath));
    RtlZeroMemory(escapedAttacker, sizeof(escapedAttacker));

    if (workItem->RegPath.Buffer && workItem->RegPath.Length > 0 &&
        !EscapeJsonString(escapedRegPath, sizeof(escapedRegPath), workItem->RegPath.Buffer))
    {
        RtlStringCbCopyW(escapedRegPath, sizeof(escapedRegPath), L"ErrorEscapingPath");
    }

    if (!EscapeJsonString(escapedAttacker, sizeof(escapedAttacker), attackerName))
    {
        RtlStringCbCopyW(escapedAttacker, sizeof(escapedAttacker), L"ErrorEscapingPath");
    }

    // Build JSON message
    RtlZeroMemory(messageBuffer, sizeof(messageBuffer));
    status = RtlStringCbPrintfW(
        messageBuffer,
        sizeof(messageBuffer),
        L"{\"source\":\"simplepyas\",\"category\":\"%ws\",\"action\":\"%ws\",\"protected_file\":\"%ws\",\"attacker_path\":\"%ws\",\"attacker_pid\":%llu,\"attack_type\":\"%ws\",\"operation\":\"%ws\"}",
        category,
        action,
        escapedRegPath[0] ? escapedRegPath : L"",
        escapedAttacker,
        (ULONGLONG)(ULONG_PTR)workItem->AttackerPid,
        attackType,
        workItem->Operation
    );

    if (NT_SUCCESS(status))
    {
        SIZE_T messageLength = wcslen(messageBuffer) * sizeof(WCHAR);
        status = SendAlertToPipe(messageBuffer, messageLength);

        if (NT_SUCCESS(status))
        {
            DbgPrint("[Registry-Protection] Alert sent: PID %llu attempted %ws on %wZ\r\n",
                (ULONGLONG)(ULONG_PTR)workItem->AttackerPid,
                workItem->Operation,
                &workItem->RegPath);
        }
        else
        {
            DbgPrint("[Registry-Protection] Failed to send alert: 0x%X\r\n", status);
        }
    }
    else
    {
        DbgPrint("[Registry-Protection] Failed to format alert: 0x%X\r\n", status);
    }

    // Free allocated strings
    if (workItem->RegPath.Buffer)
        ExFreePoolWithTag(workItem->RegPath.Buffer, REG_TAG);
    if (workItem->AttackerPath.Buffer)
        ExFreePoolWithTag(workItem->AttackerPath.Buffer, REG_TAG);

    ExFreePoolWithTag(workItem, REG_TAG);
}

NTSTATUS QueueRegistryAlertToUserMode(
    PUNICODE_STRING RegPath,
    PCWSTR Operation
)
{
    PREGISTRY_ALERT_WORK_ITEM workItem;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    HANDLE currentPid = PsGetCurrentProcessId();
    PUNICODE_STRING attackerPath = NULL;
    NTSTATUS status;

    // Allocate work item
    workItem = (PREGISTRY_ALERT_WORK_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(REGISTRY_ALERT_WORK_ITEM),
        REG_TAG
    );

    if (!workItem)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(workItem, sizeof(REGISTRY_ALERT_WORK_ITEM));

    // Copy registry path
    if (RegPath && RegPath->Buffer && RegPath->Length > 0)
    {
        workItem->RegPath.Length = RegPath->Length;
        workItem->RegPath.MaximumLength = RegPath->Length + sizeof(WCHAR);
        workItem->RegPath.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            workItem->RegPath.MaximumLength,
            REG_TAG
        );

        if (workItem->RegPath.Buffer)
        {
            RtlCopyMemory(workItem->RegPath.Buffer, RegPath->Buffer, RegPath->Length);
            workItem->RegPath.Buffer[RegPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Get attacker process path
    status = SeLocateProcessImageName(currentProcess, &attackerPath);
    if (NT_SUCCESS(status) && attackerPath && attackerPath->Buffer && attackerPath->Length > 0)
    {
        workItem->AttackerPath.Length = attackerPath->Length;
        workItem->AttackerPath.MaximumLength = attackerPath->Length + sizeof(WCHAR);
        workItem->AttackerPath.Buffer = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            workItem->AttackerPath.MaximumLength,
            REG_TAG
        );

        if (workItem->AttackerPath.Buffer)
        {
            RtlCopyMemory(workItem->AttackerPath.Buffer, attackerPath->Buffer, attackerPath->Length);
            workItem->AttackerPath.Buffer[attackerPath->Length / sizeof(WCHAR)] = L'\0';
        }
    }

    // Free the allocated path from SeLocateProcessImageName
    if (attackerPath)
        ExFreePool(attackerPath);

    // Copy PID and operation
    workItem->AttackerPid = currentPid;
    RtlStringCbCopyW(workItem->Operation, sizeof(workItem->Operation), Operation ? Operation : L"UNKNOWN");

    // Queue work item
#pragma warning(suppress: 4996)
    ExInitializeWorkItem(&workItem->WorkItem, RegistryAlertWorker, workItem);
#pragma warning(suppress: 4996)
    ExQueueWorkItem(&workItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}

// FIXED: Added full SAL annotations to the function DEFINITION to match the DECLARATION in the header file.
// This resolves the "inconsistent annotation" and "uninitialized memory" warnings.
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

    // Explicitly initialize the Length to 0 to satisfy the static analyzer that we are not reading uninitialized memory.
    pRegistryPath->Length = 0;

    if (!pRegistryObject || !MmIsAddressValid(pRegistryObject))
        return FALSE;

    NTSTATUS Status;
    ULONG ReturnLen = 0;
    POBJECT_NAME_INFORMATION NameInfo = NULL;

    // First call to get required length
    Status = ObQueryNameString(pRegistryObject, NULL, 0, &ReturnLen);
    if (Status != STATUS_INFO_LENGTH_MISMATCH || ReturnLen == 0)
        return FALSE;

    NameInfo = (POBJECT_NAME_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, ReturnLen, REG_TAG);
    if (!NameInfo)
        return FALSE;

    RtlZeroMemory(NameInfo, ReturnLen);

    Status = ObQueryNameString(pRegistryObject, NameInfo, ReturnLen, &ReturnLen);
    if (!NT_SUCCESS(Status) || NameInfo->Name.Length == 0)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Ensure destination buffer is large enough
    if (NameInfo->Name.Length + sizeof(WCHAR) > pRegistryPath->MaximumLength)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    // Copy into caller-provided UNICODE_STRING
    RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);
    pRegistryPath->Buffer[pRegistryPath->Length / sizeof(WCHAR)] = L'\0';

    ExFreePoolWithTag(NameInfo, REG_TAG);
    return TRUE;
}

// Case-insensitive substring search: returns TRUE if Pattern exists in Source
BOOLEAN UnicodeContainsInsensitive(_In_ PUNICODE_STRING Source, _In_ PCWSTR Pattern)
{
    if (!Source || !Source->Buffer || Source->Length == 0 || !Pattern)
        return FALSE;

    UNICODE_STRING srcUp = { 0 }, patUp = { 0 };
    UNICODE_STRING pat;
    RtlInitUnicodeString(&pat, Pattern);

    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&srcUp, Source, TRUE)))
        return FALSE;
    if (!NT_SUCCESS(RtlUpcaseUnicodeString(&patUp, &pat, TRUE)))
    {
        RtlFreeUnicodeString(&srcUp);
        return FALSE;
    }

    BOOLEAN found = FALSE;
    ULONG srcChars = srcUp.Length / sizeof(WCHAR);
    ULONG patChars = patUp.Length / sizeof(WCHAR);

    if (patChars > 0 && patChars <= srcChars)
    {
        PWCHAR s = srcUp.Buffer;
        PWCHAR p = patUp.Buffer;
        for (ULONG i = 0; i + patChars <= srcChars; ++i)
        {
            if (RtlEqualMemory(&s[i], p, patChars * sizeof(WCHAR)))
            {
                found = TRUE;
                break;
            }
        }
    }

    RtlFreeUnicodeString(&srcUp);
    RtlFreeUnicodeString(&patUp);
    return found;
}

static BOOLEAN IsCurrentRegistryTrusted(VOID)
{
    HANDLE pid = PsGetCurrentProcessId();

    if (IsProcessTrusted(pid) || IsProtectedProcessByPid(pid))
        return TRUE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;

    return IsProtectedProcessByPath(PsGetCurrentProcess());
}

static BOOLEAN RegistryAccessRequestsWrite(_In_ ACCESS_MASK DesiredAccess)
{
    if (DesiredAccess == 0)
        return FALSE;

    if (DesiredAccess & MAXIMUM_ALLOWED)
        return TRUE;

    return (DesiredAccess & REGISTRY_READONLY_WRITE_MASK) != 0;
}

static BOOLEAN IsRegistryPathProtected(_In_ PUNICODE_STRING RegPath)
{
    return RegPath &&
           RegPath->Buffer &&
           RegPath->Length > 0 &&
           IsPathProtectedByType(RegPath->Buffer, RuleTypeRegistry);
}

static BOOLEAN IsComRegistryPath(_In_ PUNICODE_STRING RegPath)
{
    if (!RegPath || !RegPath->Buffer || RegPath->Length == 0)
        return FALSE;

    return UnicodeContainsInsensitive(RegPath, L"\\SOFTWARE\\Classes\\CLSID\\") ||
           UnicodeContainsInsensitive(RegPath, L"\\SOFTWARE\\Classes\\AppID\\") ||
           UnicodeContainsInsensitive(RegPath, L"\\Software\\Classes\\CLSID\\") ||
           UnicodeContainsInsensitive(RegPath, L"\\Software\\Classes\\AppID\\");
}

static BOOLEAN IsPerUserComRegistryPath(_In_ PUNICODE_STRING RegPath)
{
    if (!RegPath || !RegPath->Buffer || RegPath->Length == 0)
        return FALSE;

    return UnicodeContainsInsensitive(RegPath, L"\\REGISTRY\\USER\\") &&
           (UnicodeContainsInsensitive(RegPath, L"\\Software\\Classes\\CLSID\\") ||
            UnicodeContainsInsensitive(RegPath, L"\\Software\\Classes\\AppID\\"));
}

static NTSTATUS DenyRegistryOperation(_In_ PUNICODE_STRING RegPath, _In_ PCWSTR Operation)
{
    QueueRegistryAlertToUserMode(RegPath, Operation);
    return STATUS_ACCESS_DENIED;
}

static NTSTATUS ReportComRegistryOperation(_In_ PUNICODE_STRING RegPath, _In_ PCWSTR Operation)
{
    if (!IsComRegistryPath(RegPath))
        return STATUS_SUCCESS;

    BOOLEAN perUser = IsPerUserComRegistryPath(RegPath);
    WCHAR operationName[64];
    RtlZeroMemory(operationName, sizeof(operationName));
    if (!NT_SUCCESS(RtlStringCbPrintfW(
            operationName,
            sizeof(operationName),
            perUser ? L"%ws_BLOCKED" : L"%ws_TELEMETRY",
            Operation ? Operation : L"COM_REGISTRY")))
    {
        RtlStringCbCopyW(operationName, sizeof(operationName),
            perUser ? L"COM_REGISTRY_BLOCKED" : L"COM_REGISTRY_TELEMETRY");
    }

    QueueRegistryAlertToUserMode(RegPath, operationName);
    if (perUser)
        return STATUS_ACCESS_DENIED;

    return STATUS_SUCCESS;
}

static BOOLEAN AppendRegistryString(_Inout_ PUNICODE_STRING RegPath, _In_ PUNICODE_STRING Text)
{
    if (!RegPath || !RegPath->Buffer || !Text || !Text->Buffer || Text->Length == 0)
        return TRUE;

    if ((ULONG)RegPath->Length + (ULONG)Text->Length + sizeof(WCHAR) > RegPath->MaximumLength)
        return FALSE;

    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(RegPath, Text)))
        return FALSE;

    RegPath->Buffer[RegPath->Length / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN AppendRegistrySlash(_Inout_ PUNICODE_STRING RegPath)
{
    if (!RegPath || !RegPath->Buffer)
        return FALSE;

    if (RegPath->Length == 0)
        return TRUE;

    WCHAR last = RegPath->Buffer[(RegPath->Length / sizeof(WCHAR)) - 1];
    if (last == L'\\')
        return TRUE;

    if ((ULONG)RegPath->Length + sizeof(WCHAR) + sizeof(WCHAR) > RegPath->MaximumLength)
        return FALSE;

    if (!NT_SUCCESS(RtlAppendUnicodeToString(RegPath, L"\\")))
        return FALSE;

    RegPath->Buffer[RegPath->Length / sizeof(WCHAR)] = L'\0';
    return TRUE;
}

static BOOLEAN BuildRegistryPath(
    _Inout_ PUNICODE_STRING RegPath,
    _In_opt_ PVOID RootObject,
    _In_opt_ PUNICODE_STRING CompleteName
)
{
    if (!RegPath || !RegPath->Buffer || RegPath->MaximumLength == 0)
        return FALSE;

    RtlZeroMemory(RegPath->Buffer, RegPath->MaximumLength);
    RegPath->Length = 0;

    if (CompleteName && CompleteName->Buffer && CompleteName->Length > 0 && CompleteName->Buffer[0] == L'\\')
    {
        if ((ULONG)CompleteName->Length + sizeof(WCHAR) > RegPath->MaximumLength)
            return FALSE;

        RtlCopyUnicodeString(RegPath, CompleteName);
        RegPath->Buffer[RegPath->Length / sizeof(WCHAR)] = L'\0';
        return TRUE;
    }

    if (RootObject)
    {
        if (!GetNameForRegistryObject(RegPath, RootObject))
            return FALSE;
    }

    if (CompleteName && CompleteName->Buffer && CompleteName->Length > 0)
    {
        if (RegPath->Length == 0)
            return FALSE;

        if (!AppendRegistrySlash(RegPath))
            return FALSE;

        if (!AppendRegistryString(RegPath, CompleteName))
            return FALSE;
    }

    return RegPath->Length > 0;
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    RegPath.MaximumLength = sizeof(WCHAR) * 0x800;
    RegPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, RegPath.MaximumLength, REG_TAG);
    if (!RegPath.Buffer)
        return Status;
    RtlZeroMemory(RegPath.Buffer, RegPath.MaximumLength);

    // Length is already 0 from RtlZeroMemory, but being explicit does no harm.
    RegPath.Length = 0;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    if (IsCurrentRegistryTrusted())
    {
        ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
        return Status;
    }

    __try
    {
        switch (NotifyClass)
        {
        case RegNtPreDeleteValueKey:
        {
            PREG_DELETE_VALUE_KEY_INFORMATION pInfo = (PREG_DELETE_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        AppendRegistrySlash(&RegPath);
                        AppendRegistryString(&RegPath, pInfo->ValueName);
                    }

                    Status = ReportComRegistryOperation(&RegPath, L"COM_DELETE_VALUE");
                    if (!NT_SUCCESS(Status))
                        break;

                    if (IsRegistryPathProtected(&RegPath))
                    {
                        Status = DenyRegistryOperation(&RegPath, L"DELETE_VALUE");
                    }
                }
            }
            break;
        }

        case RegNtPreDeleteKey:
        {
            PREG_DELETE_KEY_INFORMATION pInfo = (PREG_DELETE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    Status = ReportComRegistryOperation(&RegPath, L"COM_DELETE_KEY");
                    if (!NT_SUCCESS(Status))
                        break;

                    if (IsRegistryPathProtected(&RegPath))
                    {
                        Status = DenyRegistryOperation(&RegPath, L"DELETE_KEY");
                    }
                }
            }
            break;
        }

        case RegNtPreSetValueKey:
        {
            PREG_SET_VALUE_KEY_INFORMATION pInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->ValueName && pInfo->ValueName->Length > 0)
                    {
                        AppendRegistrySlash(&RegPath);
                        AppendRegistryString(&RegPath, pInfo->ValueName);
                    }

                    // --- Winlogon Shell whitelist (BUGFIX: MOVED HERE AND CORRECTED) ---
                    {
                        // Only proceed if this is the Winlogon\Shell value
                        UNICODE_STRING uShell;
                        RtlInitUnicodeString(&uShell, L"Shell");

                        if (UnicodeContainsInsensitive(&RegPath, REG_PROTECT_WINLOGON) &&
                            pInfo->ValueName &&
                            RtlEqualUnicodeString(pInfo->ValueName, &uShell, TRUE) &&
                            (pInfo->Type == REG_SZ || pInfo->Type == REG_EXPAND_SZ))
                        {
                            // Basic sanity on incoming buffer
                            ULONG dataSize = (ULONG)pInfo->DataSize;
                            if (pInfo->Data && dataSize > 0 && dataSize < (260 * sizeof(WCHAR)))
                            {
                                // Safe local copy and null-terminate
                                WCHAR tmpBuf[260] = { 0 };
                                RtlCopyMemory(tmpBuf, pInfo->Data, min(dataSize, sizeof(tmpBuf) - sizeof(WCHAR)));

                                UNICODE_STRING candidate;
                                RtlInitUnicodeString(&candidate, tmpBuf);

                                // Upcase and *only if successful* use candidateUp.Buffer
                                UNICODE_STRING candidateUp = { 0 };
                                NTSTATUS upStatus = RtlUpcaseUnicodeString(&candidateUp, &candidate, TRUE);
                                if (!NT_SUCCESS(upStatus))
                                {
                                    // conservative deny if upcase fails
                                    QueueRegistryAlertToUserMode(&RegPath, L"SET_VALUE_TAMPERING_WINLOGON_SHELL_UPCASE_FAIL");
                                    Status = STATUS_ACCESS_DENIED;
                                }
                                else
                                {
                                    // Now it's safe to use candidateUp.Buffer
                                    PWCHAR buf = candidateUp.Buffer;
                                    LONG len = (LONG)(candidateUp.Length / sizeof(WCHAR));
                                    LONG start = 0, end = len - 1;

                                    while (start <= end && (buf[start] == L' ' || buf[start] == L'\t' || buf[start] == L'\r' || buf[start] == L'\n')) start++;
                                    while (end >= start && (buf[end] == L' ' || buf[end] == L'\t' || buf[end] == L'\r' || buf[end] == L'\n')) end--;
                                    if (end - start >= 1 && ((buf[start] == L'\"' && buf[end] == L'\"') || (buf[start] == L'\'' && buf[end] == L'\'')))
                                    {
                                        start++; end--;
                                    }

                                    if (end < start)
                                    {
                                        QueueRegistryAlertToUserMode(&RegPath, L"SET_VALUE_TAMPERING_WINLOGON_SHELL_EMPTY");
                                        RtlFreeUnicodeString(&candidateUp);
                                        Status = STATUS_ACCESS_DENIED;
                                    }
                                    else
                                    {
                                        LONG lastSep = -1;
                                        for (LONG i = end; i >= start; --i)
                                        {
                                            if (buf[i] == L'\\' || buf[i] == L'/') { lastSep = i; break; }
                                        }
                                        LONG fnameStart = (lastSep >= start) ? lastSep + 1 : start;
                                        ULONG fnameLen = (ULONG)(end - fnameStart + 1);
                                        const WCHAR ALLOWED[] = L"EXPLORER.EXE";
                                        ULONG allowedLen = (ULONG)wcslen(ALLOWED);

                                        BOOLEAN ok = FALSE;
                                        if (fnameLen == allowedLen)
                                        {
                                            ok = TRUE;
                                            for (ULONG i = 0; i < allowedLen; ++i)
                                            {
                                                if (buf[fnameStart + i] != ALLOWED[i]) { ok = FALSE; break; }
                                            }
                                        }

                                        RtlFreeUnicodeString(&candidateUp);

                                        if (!ok)
                                        {
                                            QueueRegistryAlertToUserMode(&RegPath, L"SET_VALUE_TAMPERING_WINLOGON_SHELL_INVALID");
                                            Status = STATUS_ACCESS_DENIED;
                                        }
                                        else
                                        {
                                            // Whitelist succeeded.
                                            // We must skip the other checks for this key.
                                            // We can safely leave the __try block.
                                            __leave;
                                        }
                                    }
                                } // end else upcase success
                            }
                            else
                            {
                                // No data or too large -> conservative deny
                                QueueRegistryAlertToUserMode(&RegPath, L"SET_VALUE_TAMPERING_WINLOGON_SHELL_BAD_SIZE");
                                Status = STATUS_ACCESS_DENIED;
                            }
                        } // end if Winlogon Shell
                    }
                    // --- end Winlogon Shell whitelist ---

                    Status = ReportComRegistryOperation(&RegPath, L"COM_SET_VALUE");
                    if (!NT_SUCCESS(Status))
                        break;

                    if (IsRegistryPathProtected(&RegPath))
                    {
                        Status = DenyRegistryOperation(&RegPath, L"SET_VALUE");
                    }
                }
            }
            break;
        }

        case RegNtPreRenameKey:
        {
            PREG_RENAME_KEY_INFORMATION pInfo = (PREG_RENAME_KEY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    if (pInfo->NewName && pInfo->NewName->Length > 0)
                    {
                        AppendRegistrySlash(&RegPath);
                        AppendRegistryString(&RegPath, pInfo->NewName);
                    }

                    Status = ReportComRegistryOperation(&RegPath, L"COM_RENAME_KEY");
                    if (!NT_SUCCESS(Status))
                        break;

                    if (IsRegistryPathProtected(&RegPath))
                    {
                        Status = DenyRegistryOperation(&RegPath, L"RENAME_KEY");
                    }
                }
            }
            break;
        }

        case RegNtPreCreateKeyEx:
        {
            PREG_CREATE_KEY_INFORMATION_V1 pInfo = (PREG_CREATE_KEY_INFORMATION_V1)Argument2;
            if (pInfo && BuildRegistryPath(&RegPath, pInfo->RootObject, pInfo->CompleteName))
            {
                Status = ReportComRegistryOperation(&RegPath, L"COM_CREATE_KEY");
                if (!NT_SUCCESS(Status))
                    break;

                if (IsRegistryPathProtected(&RegPath))
                {
                    Status = DenyRegistryOperation(&RegPath, L"CREATE_KEY");
                }
            }
            break;
        }

        case RegNtPreOpenKeyEx:
        {
            PREG_OPEN_KEY_INFORMATION_V1 pInfo = (PREG_OPEN_KEY_INFORMATION_V1)Argument2;
            if (pInfo && BuildRegistryPath(&RegPath, pInfo->RootObject, pInfo->CompleteName))
            {
                if (RegistryAccessRequestsWrite(pInfo->DesiredAccess))
                {
                    Status = ReportComRegistryOperation(&RegPath, L"COM_OPEN_KEY_WRITE");
                    if (!NT_SUCCESS(Status))
                        break;
                }

                if (IsRegistryPathProtected(&RegPath) &&
                    RegistryAccessRequestsWrite(pInfo->DesiredAccess))
                {
                    Status = DenyRegistryOperation(&RegPath, L"OPEN_KEY_WRITE");
                }
            }
            break;
        }

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DbgPrint("[Registry-Protection] Exception in callback: 0x%X\r\n", GetExceptionCode());
        Status = STATUS_SUCCESS; // Don't propagate exceptions
    }

    ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}
