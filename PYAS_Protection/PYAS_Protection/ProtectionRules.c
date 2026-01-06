#include "ProtectionRules.h"
#include "Driver_Common.h"

#define RULE_DIRECTORY L"\\\\??\\C:\\Program Files\\HydraDragonAntivirus\\PYAS_Protection_Rules\\"
#define MAX_RULE_FILE_SIZE (64 * 1024) // 64KB safety cap for a single rule file

static PROTECTION_RULE_SET g_RuleSet = { 0 };
static FAST_MUTEX g_RuleMutex;
static BOOLEAN g_RuleMutexInitialized = FALSE;
static BOOLEAN g_RulesLoaded = FALSE;

static NTSTATUS EnsureRuleCapacity(PPROTECTION_RULE_SET RuleSet, ULONG RequiredCount)
{
    if (RuleSet->Capacity >= RequiredCount)
    {
        return STATUS_SUCCESS;
    }

    ULONG newCapacity = (RuleSet->Capacity == 0) ? 8 : RuleSet->Capacity * 2;
    if (newCapacity < RequiredCount)
    {
        newCapacity = RequiredCount;
    }

    SIZE_T allocSize = sizeof(PWSTR) * newCapacity;
    PWSTR* newArray = (PWSTR*)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, RULE_POOL_TAG);
    if (!newArray)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(newArray, allocSize);
    if (RuleSet->Rules && RuleSet->Count > 0)
    {
        RtlCopyMemory(newArray, RuleSet->Rules, sizeof(PWSTR) * RuleSet->Count);
        ExFreePoolWithTag(RuleSet->Rules, RULE_POOL_TAG);
    }

    RuleSet->Rules = newArray;
    RuleSet->Capacity = newCapacity;
    return STATUS_SUCCESS;
}

static NTSTATUS AddRuleString(PPROTECTION_RULE_SET RuleSet, PCWSTR RuleText, SIZE_T CharacterCount)
{
    NTSTATUS status = EnsureRuleCapacity(RuleSet, RuleSet->Count + 1);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    SIZE_T allocSize = (CharacterCount + 1) * sizeof(WCHAR);
    PWCHAR buffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, allocSize, RULE_POOL_TAG);
    if (!buffer)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, allocSize);
    RtlCopyMemory(buffer, RuleText, CharacterCount * sizeof(WCHAR));
    buffer[CharacterCount] = L'\0';

    RuleSet->Rules[RuleSet->Count++] = buffer;
    return STATUS_SUCCESS;
}

static VOID FreeRuleSet(PPROTECTION_RULE_SET RuleSet)
{
    if (!RuleSet)
    {
        return;
    }

    if (RuleSet->Rules)
    {
        for (ULONG i = 0; i < RuleSet->Count; i++)
        {
            if (RuleSet->Rules[i])
            {
                ExFreePoolWithTag(RuleSet->Rules[i], RULE_POOL_TAG);
            }
        }

        ExFreePoolWithTag(RuleSet->Rules, RULE_POOL_TAG);
    }

    RtlZeroMemory(RuleSet, sizeof(PROTECTION_RULE_SET));
}

static BOOLEAN IsDotDirectory(PUNICODE_STRING FileName)
{
    if (!FileName || !FileName->Buffer)
    {
        return TRUE;
    }

    if (FileName->Length == sizeof(WCHAR) && FileName->Buffer[0] == L'.')
    {
        return TRUE;
    }

    if (FileName->Length == 2 * sizeof(WCHAR) && FileName->Buffer[0] == L'.' && FileName->Buffer[1] == L'.')
    {
        return TRUE;
    }

    return FALSE;
}

static NTSTATUS AppendRulesFromBuffer(PPROTECTION_RULE_SET RuleSet, PUCHAR Buffer, ULONG BytesRead)
{
    if (!Buffer || BytesRead == 0)
    {
        return STATUS_SUCCESS;
    }

    // Treat the file as UTF-8/ASCII and convert manually into WCHAR lines
    ULONG start = 0;
    for (ULONG i = 0; i <= BytesRead; i++)
    {
        BOOLEAN isDelimiter = (i == BytesRead) || Buffer[i] == '\n' || Buffer[i] == '\r';
        if (isDelimiter)
        {
            if (i > start)
            {
                ULONG length = i - start;
                // Trim trailing whitespace
                while (length > 0 && (Buffer[start + length - 1] == ' ' || Buffer[start + length - 1] == '\t' || Buffer[start + length - 1] == '\r'))
                {
                    length--;
                }

                // Trim leading whitespace
                ULONG leading = 0;
                while (leading < length && (Buffer[start + leading] == ' ' || Buffer[start + leading] == '\t'))
                {
                    leading++;
                }

                if (length > leading)
                {
                    length -= leading;
                    PWCHAR ruleBuffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, (length + 1) * sizeof(WCHAR), RULE_POOL_TAG);
                    if (!ruleBuffer)
                    {
                        return STATUS_INSUFFICIENT_RESOURCES;
                    }

                    for (ULONG j = 0; j < length; j++)
                    {
                        ruleBuffer[j] = (WCHAR)Buffer[start + leading + j];
                    }
                    ruleBuffer[length] = L'\0';

                    NTSTATUS addStatus = AddRuleString(RuleSet, ruleBuffer, length);
                    ExFreePoolWithTag(ruleBuffer, RULE_POOL_TAG);
                    if (!NT_SUCCESS(addStatus))
                    {
                        return addStatus;
                    }
                }
            }
            start = i + 1;
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS LoadRulesFromFilePath(PUNICODE_STRING FilePath, PPROTECTION_RULE_SET RuleSet)
{
    IO_STATUS_BLOCK ioStatus = { 0 };
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle = NULL;
    NTSTATUS status;

    InitializeObjectAttributes(
        &objectAttributes,
        FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    status = ZwQueryInformationFile(
        fileHandle,
        &ioStatus,
        &fileInfo,
        sizeof(fileInfo),
        FileStandardInformation);

    if (!NT_SUCCESS(status))
    {
        ZwClose(fileHandle);
        return status;
    }

    if (fileInfo.EndOfFile.QuadPart <= 0 || fileInfo.EndOfFile.QuadPart > MAX_RULE_FILE_SIZE)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ULONG bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    PUCHAR buffer = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, bufferSize, RULE_POOL_TAG);
    if (!buffer)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);

    status = ZwReadFile(
        fileHandle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        buffer,
        bufferSize,
        NULL,
        NULL);

    if (NT_SUCCESS(status))
    {
        status = AppendRulesFromBuffer(RuleSet, buffer, (ULONG)ioStatus.Information);
    }

    ExFreePoolWithTag(buffer, RULE_POOL_TAG);
    ZwClose(fileHandle);
    return status;
}

static NTSTATUS LoadRulesFromDirectory(PPROTECTION_RULE_SET RuleSet)
{
    HANDLE dirHandle = NULL;
    IO_STATUS_BLOCK ioStatus = { 0 };
    UNICODE_STRING directoryPath;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;

    RtlInitUnicodeString(&directoryPath, RULE_DIRECTORY);
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);

    status = ZwCreateFile(
        &dirHandle,
        FILE_LIST_DIRECTORY | SYNCHRONIZE,
        &objectAttributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ULONG bufferSize = 4096;
    PFILE_DIRECTORY_INFORMATION dirInfo = (PFILE_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(NonPagedPoolNx, bufferSize, RULE_POOL_TAG);
    if (!dirInfo)
    {
        ZwClose(dirHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    BOOLEAN restartScan = TRUE;
    while (TRUE)
    {
        status = ZwQueryDirectoryFile(
            dirHandle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            dirInfo,
            bufferSize,
            FileDirectoryInformation,
            TRUE,
            NULL,
            restartScan);

        if (status == STATUS_NO_MORE_FILES)
        {
            status = STATUS_SUCCESS;
            break;
        }

        if (!NT_SUCCESS(status))
        {
            break;
        }

        restartScan = FALSE;

        PFILE_DIRECTORY_INFORMATION current = dirInfo;
        while (TRUE)
        {
            UNICODE_STRING fileName;
            fileName.Buffer = current->FileName;
            fileName.Length = (USHORT)current->FileNameLength;
            fileName.MaximumLength = (USHORT)current->FileNameLength;

            if (!IsDotDirectory(&fileName) && !(current->FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                USHORT fullLength = directoryPath.Length + fileName.Length + sizeof(WCHAR);
                PWCHAR fullPathBuffer = (PWCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, fullLength, RULE_POOL_TAG);
                if (!fullPathBuffer)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Cleanup;
                }

                RtlZeroMemory(fullPathBuffer, fullLength);
                RtlCopyMemory(fullPathBuffer, directoryPath.Buffer, directoryPath.Length);
                RtlCopyMemory((PUCHAR)fullPathBuffer + directoryPath.Length, fileName.Buffer, fileName.Length);
                fullPathBuffer[(fullLength / sizeof(WCHAR)) - 1] = L'\0';

                UNICODE_STRING fullPath;
                fullPath.Buffer = fullPathBuffer;
                fullPath.Length = fullLength - sizeof(WCHAR);
                fullPath.MaximumLength = fullLength;

                NTSTATUS loadStatus = LoadRulesFromFilePath(&fullPath, RuleSet);
                ExFreePoolWithTag(fullPathBuffer, RULE_POOL_TAG);

                if (!NT_SUCCESS(loadStatus))
                {
                    // Continue loading other files but remember the first failure
                    status = loadStatus;
                }
            }

            if (current->NextEntryOffset == 0)
            {
                break;
            }
            current = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)current + current->NextEntryOffset);
        }
    }

Cleanup:
    ExFreePoolWithTag(dirInfo, RULE_POOL_TAG);
    ZwClose(dirHandle);
    return status;
}

NTSTATUS InitializeProtectionRules()
{
    if (!g_RuleMutexInitialized)
    {
        ExInitializeFastMutex(&g_RuleMutex);
        g_RuleMutexInitialized = TRUE;
    }

    ExAcquireFastMutex(&g_RuleMutex);

    if (g_RulesLoaded)
    {
        ExReleaseFastMutex(&g_RuleMutex);
        return STATUS_SUCCESS;
    }

    FreeRuleSet(&g_RuleSet);
    NTSTATUS status = LoadRulesFromDirectory(&g_RuleSet);
    if (NT_SUCCESS(status))
    {
        g_RulesLoaded = TRUE;
    }

    ExReleaseFastMutex(&g_RuleMutex);
    return status;
}

VOID CleanupProtectionRules()
{
    if (!g_RuleMutexInitialized)
    {
        return;
    }

    ExAcquireFastMutex(&g_RuleMutex);
    FreeRuleSet(&g_RuleSet);
    g_RulesLoaded = FALSE;
    ExReleaseFastMutex(&g_RuleMutex);
}

BOOLEAN IsPathProtected(_In_ PCWSTR Path)
{
    if (!Path)
    {
        return FALSE;
    }

    // Kernel-enforced base paths (support both native and DOS prefix forms)
    static const PCWSTR kHardcodedRoots[] = {
        L"\\Program Files\\HydraDragonAntivirus",           // Native paths: \Device\\HarddiskVolumeX\\Program Files\\HydraDragonAntivirus
        L"\\??\\C:\\Program Files\\HydraDragonAntivirus" // DOS device paths: \??\\C:\\Program Files\\HydraDragonAntivirus
    };

    for (ULONG i = 0; i < ARRAYSIZE(kHardcodedRoots); ++i)
    {
        if (ContainsSubstringInsensitive(Path, kHardcodedRoots[i]))
        {
            return TRUE;
        }
    }

    if (!g_RuleMutexInitialized)
    {
        ExInitializeFastMutex(&g_RuleMutex);
        g_RuleMutexInitialized = TRUE;
    }

    // Load rules on first use
    if (!g_RulesLoaded)
    {
        InitializeProtectionRules();
    }

    ExAcquireFastMutex(&g_RuleMutex);

    BOOLEAN matched = FALSE;
    for (ULONG i = 0; i < g_RuleSet.Count; i++)
    {
        if (g_RuleSet.Rules[i] && ContainsSubstringInsensitive(Path, g_RuleSet.Rules[i]))
        {
            matched = TRUE;
            break;
        }
    }

    ExReleaseFastMutex(&g_RuleMutex);
    return matched;
}

