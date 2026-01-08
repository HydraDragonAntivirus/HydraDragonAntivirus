#include "Regedit.h"
#include "DriverData.h"
#include <ntstrsafe.h>

// Global
LARGE_INTEGER Cookie;

// Helper functions (Internal)
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN GetNameForRegistryObject(
    _Inout_ _At_(pRegistryPath->Buffer, _Pre_writable_byte_size_(pRegistryPath->MaximumLength) _Post_z_)
    PUNICODE_STRING pRegistryPath,
    _In_  PVOID pRegistryObject)
{
    if (!pRegistryPath || pRegistryPath->MaximumLength == 0 || !pRegistryPath->Buffer)
        return FALSE;

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

    if (NameInfo->Name.Length > pRegistryPath->MaximumLength)
    {
        ExFreePoolWithTag(NameInfo, REG_TAG);
        return FALSE;
    }

    RtlCopyUnicodeString(pRegistryPath, &NameInfo->Name);
    ExFreePoolWithTag(NameInfo, REG_TAG);
    return TRUE;
}

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

VOID SendRegistryAlert(PUNICODE_STRING RegPath, PCWSTR Operation, HANDLE Pid)
{
    if (!driverData) return;

    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (!newEntry) return;

    // Set PID
    newEntry->data.PID = (ULONG)(ULONG_PTR)Pid;

    // Look up GID
    BOOLEAN isGidFound = FALSE;
    ULONGLONG gid = driverData->GetProcessGid(newEntry->data.PID, &isGidFound);
    if (gid != 0 && isGidFound) {
        newEntry->data.Gid = gid;
    }

    // Set Code
    newEntry->data.IRP_OP = IRP_REGISTRY;

    // Copy Path
    if (RegPath && RegPath->Buffer) {
        USHORT copyLen = min(RegPath->Length, MAX_FILE_NAME_SIZE - sizeof(WCHAR));
        RtlCopyMemory(newEntry->Buffer, RegPath->Buffer, copyLen);
        newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
        newEntry->filePath.Length = copyLen;
    }

    // Copy Operation to Extension
    RtlStringCbCopyW(newEntry->data.Extension, sizeof(newEntry->data.Extension), Operation);

    // Add to Driver Queue
    driverData->AddIrpMessage(newEntry);
}

NTSTATUS RegistryCallback(_In_ PVOID CallbackContext, _In_ PVOID Argument1, _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    NTSTATUS Status = STATUS_SUCCESS;

    UNICODE_STRING RegPath;
    RtlZeroMemory(&RegPath, sizeof(RegPath));
    // Allocate local buffer on stack or pool? Regedit.c used Pool.
    // Creating temp buffer on new operator is cleaner for C++ or ExAllocatePool.
    // Use ExAllocatePool for safety.
    RegPath.MaximumLength = sizeof(WCHAR) * 0x400; // 1024 chars
    RegPath.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, RegPath.MaximumLength, REG_TAG);
    
    if (!RegPath.Buffer) return Status;
    RegPath.Length = 0;

    REG_NOTIFY_CLASS NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    // Get current PID
    HANDLE hPid = PsGetCurrentProcessId();

    // Check if the process is already marked as malicious by prediction
    if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
        DbgPrint("!!! Regedit: BLOCKING operation from malicious Process: %lu\n", (ULONG)(ULONG_PTR)hPid);
        // We can't easily get the name here without potentially crashing if Argument2 isn't what we expect for all classes, 
        // but Status is already SUCCESS, so we just set it to DENIED.
        if (RegPath.Buffer) ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
        return STATUS_ACCESS_DENIED;
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
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }

                    if (TRUE) // Monitor all registry deletions
                    {
                        SendRegistryAlert(&RegPath, L"DELETE_VALUE", hPid);
                        
                        // If already marked as malicious by prediction, BLOCK it
                        if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
                             Status = STATUS_ACCESS_DENIED;
                        } else {
                             Status = STATUS_SUCCESS;
                        }
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
                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"DELETE_KEY", hPid);
                        if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
                             Status = STATUS_ACCESS_DENIED;
                        } else {
                             Status = STATUS_SUCCESS;
                        }
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
                        RtlAppendUnicodeToString(&RegPath, L"\\");
                        RtlAppendUnicodeStringToString(&RegPath, pInfo->ValueName);
                    }
                    
                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"SET_VALUE", hPid);
                        if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
                             Status = STATUS_ACCESS_DENIED;
                        } else {
                             Status = STATUS_SUCCESS;
                        }
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
                    if (TRUE)
                    {
                        SendRegistryAlert(&RegPath, L"RENAME_KEY", hPid);
                        if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
                             Status = STATUS_ACCESS_DENIED;
                        } else {
                             Status = STATUS_SUCCESS;
                        }
                    }
                }
            }
            break;
        }
        case RegNtPreSetKeySecurity:
        {
            PREG_SET_KEY_SECURITY_INFORMATION pInfo = (PREG_SET_KEY_SECURITY_INFORMATION)Argument2;
            if (pInfo && pInfo->Object)
            {
                if (GetNameForRegistryObject(&RegPath, pInfo->Object))
                {
                    SendRegistryAlert(&RegPath, L"SET_SECURITY", hPid);
                    if (driverData->IsProcessMalicious((ULONG)(ULONG_PTR)hPid)) {
                         Status = STATUS_ACCESS_DENIED;
                    } else {
                         Status = STATUS_SUCCESS;
                    }
                }
            }
            break;
        }

        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    if (RegPath.Buffer) ExFreePoolWithTag(RegPath.Buffer, REG_TAG);
    return Status;
}

NTSTATUS RegeditDriverEntry()
{
    NTSTATUS status = CmRegisterCallback(RegistryCallback, NULL, &Cookie);
    if (NT_SUCCESS(status))
    {
        DbgPrint("[Registry-Protection] Initialized successfully\r\n");
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
    return STATUS_SUCCESS;
}
