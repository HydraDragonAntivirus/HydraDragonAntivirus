#include "ProtectionRules.h"
#include "Driver_Common.h"
#include <ntstrsafe.h>

// Native directory path for loading rule files
#define RULE_DIRECTORY L"\\??\\C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\HydraDragon_Protection_Rules\\PYAS\\"
#define MAX_RULE_FILE_SIZE (64 * 1024) // 64KB safety cap for a single rule file

// Maximum extra chars added when expanding a hive prefix (HKCR\ -> \REGISTRY\MACHINE\SOFTWARE\CLASSES\)
#define REGISTRY_PREFIX_EXPANSION_MAX 64

static PROTECTION_RULE_SET g_RuleSets[RuleTypeMax] = { 0 };
static FAST_MUTEX g_RuleMutex;
static BOOLEAN g_RuleMutexInitialized = FALSE;
static BOOLEAN g_RulesLoaded = FALSE;

static const PCWSTR kRuleSubDirs[RuleTypeMax] = {
    L"Process\\",
    L"File\\",
    L"Registry\\"
};

// ---------------------------------------------------------------------------
// Registry hive prefix table
// Maps user-friendly names (as seen in regedit) to kernel NT path prefixes.
// Note: HKCU maps to \REGISTRY\USER\  -  the SID segment is absent from the
// stored rule, so ContainsSubstringInsensitive will still match correctly
// because the kernel path contains \REGISTRY\USER\<SID>\<subpath> and the
// rule will be matched as a substring from the subpath onwards.
// For precise per-hive matching, prefer HKLM or full \REGISTRY\ paths.
// ---------------------------------------------------------------------------
typedef struct _HIVE_MAP_ENTRY {
    PCWSTR UserPrefix;      // e.g., L"HKLM\\"
    SIZE_T UserPrefixLen;   // characters (not bytes), excluding null
    PCWSTR KernelPrefix;    // e.g., L"\\REGISTRY\\MACHINE\\"
} HIVE_MAP_ENTRY;

static const HIVE_MAP_ENTRY kHiveMap[] =
{
    // Sorted longest-prefix first to avoid ambiguous prefix matching
    { L"HKLM\\",  5,  L"\\REGISTRY\\MACHINE\\"                                                         },
    { L"HKCU\\",  5,  L"\\REGISTRY\\USER\\"                                                             },
    { L"HKCR\\",  5,  L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES\\"                                      },
    { L"HKCC\\",  5,  L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT\\"  },
    { L"HKU\\",   4,  L"\\REGISTRY\\USER\\"                                                             },
};
#define HIVE_MAP_COUNT (sizeof(kHiveMap) / sizeof(kHiveMap[0]))

// ---------------------------------------------------------------------------
// ValidateAndNormalizeRegistryRule
//
// Accepts a null-terminated rule string and writes the canonical kernel path
// into OutBuffer (size OutBufferChars wide-chars including null terminator).
//
// Accepted input formats:
//   HKLM\<path>        -> \REGISTRY\MACHINE\<path>
//   HKCU\<path>        -> \REGISTRY\USER\<path>   (see note above about SID)
//   HKCR\<path>        -> \REGISTRY\MACHINE\SOFTWARE\CLASSES\<path>
//   HKCC\<path>        -> \REGISTRY\MACHINE\SYSTEM\...\CURRENT\<path>
//   HKU\<path>         -> \REGISTRY\USER\<path>
//   \REGISTRY\<path>   -> kept as-is (already canonical)
//
// Returns FALSE and logs a warning for any other format.
// ---------------------------------------------------------------------------
_Success_(return != FALSE)
static BOOLEAN ValidateAndNormalizeRegistryRule(
    _In_  PCWSTR  RuleText,
    _Out_writes_(OutBufferChars) PWCHAR OutBuffer,
    _In_  SIZE_T  OutBufferChars)
{
    if (!RuleText || !OutBuffer || OutBufferChars == 0) return FALSE;

    // Already in kernel form?
    if (_wcsnicmp(RuleText, L"\\REGISTRY\\", 10) == 0)
    {
        NTSTATUS st = RtlStringCchCopyW(OutBuffer, OutBufferChars, RuleText);
        return NT_SUCCESS(st);
    }

    // Try each hive prefix
    for (ULONG i = 0; i < HIVE_MAP_COUNT; i++)
    {
        if (_wcsnicmp(RuleText, kHiveMap[i].UserPrefix, kHiveMap[i].UserPrefixLen) == 0)
        {
            PCWSTR subpath    = RuleText + kHiveMap[i].UserPrefixLen;
            SIZE_T kernelLen  = wcslen(kHiveMap[i].KernelPrefix);
            SIZE_T subLen     = wcslen(subpath);

            if (kernelLen + subLen + 1 > OutBufferChars)
            {
                DbgPrint("[ProtectionRules] Registry rule buffer too small for: %ws\n", RuleText);
                return FALSE;
            }

            RtlStringCchCopyW(OutBuffer, OutBufferChars, kHiveMap[i].KernelPrefix);
            RtlStringCchCatW (OutBuffer, OutBufferChars, subpath);
            return TRUE;
        }
    }

    DbgPrint("[ProtectionRules] Rejected registry rule  -  must start with HKLM\\, HKCU\\, "
             "HKCR\\, HKCC\\, HKU\\ or \\REGISTRY\\: %ws\n", RuleText);
    return FALSE;
}

// ---------------------------------------------------------------------------
// ValidateFileProcessRule
//
// A file or process rule is valid when it starts with:
//   X:\          -  standard DOS drive-letter path (most common)
//   \??\         -  NT device namespace path
//   \            -  relative/suffix path (accepted for user-profile paths whose
//                 full absolute path is unknown at rule-authoring time, e.g.
//                 \AppData\Roaming\Sanctum\).  Matching still uses
//                 ContainsSubstringInsensitive so these work correctly.
//
// Bare filenames or paths without any leading separator are rejected.
// ---------------------------------------------------------------------------
static BOOLEAN ValidateFileProcessRule(_In_ PCWSTR RuleText)
{
    if (!RuleText) return FALSE;
    SIZE_T len = wcslen(RuleText);
    if (len == 0) return FALSE;

    /* Drive-letter path: e.g. C:\ or c:\ */
    if (len >= 3
        && ((RuleText[0] >= L'A' && RuleText[0] <= L'Z') ||
            (RuleText[0] >= L'a' && RuleText[0] <= L'z'))
        && RuleText[1] == L':'
        && RuleText[2] == L'\\')
    {
        return TRUE;
    }

    /* NT device namespace prefix: \??\ */
    if (len >= 4 && _wcsnicmp(RuleText, L"\\??\\", 4) == 0)
    {
        return TRUE;
    }

    // Suffix / relative path (user-profile, driver subpaths, etc.)
    if (RuleText[0] == L'\\')
    {
        // Reject if it starts with \REGISTRY\  -  that belongs in the Registry ruleset
        if (_wcsnicmp(RuleText, L"\\REGISTRY\\", 10) == 0)
        {
            DbgPrint("[ProtectionRules] Rejected file/process rule  -  "
                     "\\REGISTRY\\ paths belong in the Registry ruleset: %ws\n", RuleText);
            return FALSE;
        }
        return TRUE;
    }

    DbgPrint("[ProtectionRules] Rejected file/process rule  -  must start with a drive letter "
             "(C:\\), \\??\\ or \\ : %ws\n", RuleText);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

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
    PWSTR* newArray  = (PWSTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, RULE_POOL_TAG);
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

    RuleSet->Rules    = newArray;
    RuleSet->Capacity = newCapacity;
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// AddRuleString
//
// Trims, comment-strips, validates and (for registry rules) normalizes a
// single rule line, then appends it to the given rule set if unique.
//
// RuleType controls which validation path is taken:
//   RuleTypeRegistry -> ValidateAndNormalizeRegistryRule
//   RuleTypeFile /
//   RuleTypeProcess  -> ValidateFileProcessRule
// ---------------------------------------------------------------------------
static NTSTATUS AddRuleString(
    _Inout_ PPROTECTION_RULE_SET RuleSet,
    _In_    PCWSTR               RuleText,
    _In_    SIZE_T               CharacterCount,
    _In_    RULE_TYPE            RuleType)
{
    if (!RuleSet || !RuleText || CharacterCount == 0)
    {
        return STATUS_SUCCESS;
    }

    // ------------------------------------------------------------------
    // 1. Trim leading whitespace
    // ------------------------------------------------------------------
    SIZE_T start = 0;
    SIZE_T end   = CharacterCount;

    while (start < end && (RuleText[start] == L' ' || RuleText[start] == L'\t'))
    {
        start++;
    }

    // ------------------------------------------------------------------
    // 2. Strip comments (# or //)
    // ------------------------------------------------------------------
    SIZE_T commentPos = (SIZE_T)-1;
    for (SIZE_T i = start; i < end; ++i)
    {
        if (RuleText[i] == L'#')
        {
            commentPos = i;
            break;
        }
        if ((i + 1) < end && RuleText[i] == L'/' && RuleText[i + 1] == L'/')
        {
            commentPos = i;
            break;
        }
    }
    if (commentPos != (SIZE_T)-1)
    {
        end = commentPos;
    }

    // ------------------------------------------------------------------
    // 3. Trim trailing whitespace and stray quote characters
    // ------------------------------------------------------------------
    while (end > start &&
           (RuleText[end - 1] == L' '  ||
            RuleText[end - 1] == L'\t' ||
            RuleText[end - 1] == L'\r' ||
            RuleText[end - 1] == L'"'))
    {
        end--;
    }

    if (end <= start)
    {
        return STATUS_SUCCESS; // empty / comment-only line
    }

    // ------------------------------------------------------------------
    // 4. Build a temporary null-terminated copy, normalising forward
    //    slashes to backslashes while copying.
    // ------------------------------------------------------------------
    SIZE_T rawLen  = end - start;
    // For registry rules, leave room for potential prefix expansion
    SIZE_T tmpSize = (rawLen + REGISTRY_PREFIX_EXPANSION_MAX + 1) * sizeof(WCHAR);
    PWCHAR tempBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, tmpSize, RULE_POOL_TAG);
    if (!tempBuf)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(tempBuf, tmpSize);
    for (SIZE_T i = 0; i < rawLen; ++i)
    {
        WCHAR ch = RuleText[start + i];
        if (ch == L'/') ch = L'\\';
        tempBuf[i] = ch;
    }
    tempBuf[rawLen] = L'\0';

    // ------------------------------------------------------------------
    // 5. Validate and (for registry) normalize
    // ------------------------------------------------------------------
    PWCHAR finalBuf   = NULL;
    SIZE_T finalChars = 0;

    if (RuleType == RuleTypeRegistry)
    {
        // Allocate output buffer big enough for the expanded kernel path
        SIZE_T outChars = rawLen + REGISTRY_PREFIX_EXPANSION_MAX + 1;
        finalBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, outChars * sizeof(WCHAR), RULE_POOL_TAG);
        if (!finalBuf)
        {
            ExFreePoolWithTag(tempBuf, RULE_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(finalBuf, outChars * sizeof(WCHAR));

        if (!ValidateAndNormalizeRegistryRule(tempBuf, finalBuf, outChars))
        {
            // Invalid format  -  skip rule silently (warning already printed inside helper)
            ExFreePoolWithTag(finalBuf, RULE_POOL_TAG);
            ExFreePoolWithTag(tempBuf,  RULE_POOL_TAG);
            return STATUS_SUCCESS;
        }

        finalChars = wcslen(finalBuf);

        // Shrink the allocation to the actual length (optional, avoids waste)
        PWCHAR shrunk = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, (finalChars + 1) * sizeof(WCHAR), RULE_POOL_TAG);
        if (shrunk)
        {
            RtlCopyMemory(shrunk, finalBuf, (finalChars + 1) * sizeof(WCHAR));
            ExFreePoolWithTag(finalBuf, RULE_POOL_TAG);
            finalBuf = shrunk;
        }
    }
    else
    {
        // File or Process rule
        if (!ValidateFileProcessRule(tempBuf))
        {
            // Invalid format  -  skip rule silently (warning already printed inside helper)
            ExFreePoolWithTag(tempBuf, RULE_POOL_TAG);
            return STATUS_SUCCESS;
        }

        finalChars = wcslen(tempBuf);
        finalBuf   = (PWCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, (finalChars + 1) * sizeof(WCHAR), RULE_POOL_TAG);
        if (!finalBuf)
        {
            ExFreePoolWithTag(tempBuf, RULE_POOL_TAG);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(finalBuf, tempBuf, (finalChars + 1) * sizeof(WCHAR));
    }

    ExFreePoolWithTag(tempBuf, RULE_POOL_TAG);

    // ------------------------------------------------------------------
    // 6. Deduplicate
    // ------------------------------------------------------------------
    for (ULONG i = 0; i < RuleSet->Count; ++i)
    {
        if (RuleSet->Rules[i] && _wcsicmp(RuleSet->Rules[i], finalBuf) == 0)
        {
            ExFreePoolWithTag(finalBuf, RULE_POOL_TAG);
            return STATUS_SUCCESS;
        }
    }

    // ------------------------------------------------------------------
    // 7. Grow array if needed and append
    // ------------------------------------------------------------------
    NTSTATUS status = EnsureRuleCapacity(RuleSet, RuleSet->Count + 1);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(finalBuf, RULE_POOL_TAG);
        return status;
    }

    RuleSet->Rules[RuleSet->Count++] = finalBuf;
    return STATUS_SUCCESS;
}

static VOID FreeRuleSet(PPROTECTION_RULE_SET RuleSet)
{
    if (!RuleSet)
    {
        return;
    }

    if (RuleSet->Rules && RuleSet->Count > 0)
    {
        for (ULONG i = 0; i < RuleSet->Count; i++)
        {
            if (RuleSet->Rules[i])
            {
                ExFreePoolWithTag(RuleSet->Rules[i], RULE_POOL_TAG);
                RuleSet->Rules[i] = NULL;
            }
        }
    }

    if (RuleSet->Rules)
    {
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
    if (FileName->Length == 2 * sizeof(WCHAR) &&
        FileName->Buffer[0] == L'.' && FileName->Buffer[1] == L'.')
    {
        return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// AppendRulesFromBuffer  -  parse a raw byte buffer (UTF-8 or UTF-16 LE/BE)
// into individual lines and call AddRuleString for each.
// RuleType is forwarded to AddRuleString so validation is applied per type.
// ---------------------------------------------------------------------------
static NTSTATUS AppendRulesFromBuffer(
    _Inout_ PPROTECTION_RULE_SET RuleSet,
    _In_    PUCHAR               Buffer,
    _In_    ULONG                BytesRead,
    _In_    RULE_TYPE            RuleType)
{
    if (!Buffer || BytesRead < 2)
    {
        return STATUS_SUCCESS;
    }

    // Detect UTF-16 LE BOM (0xFF 0xFE)
    BOOLEAN isUtf16LE = (Buffer[0] == 0xFF && Buffer[1] == 0xFE);
    // Detect UTF-16 BE BOM (0xFE 0xFF)
    BOOLEAN isUtf16BE = (Buffer[0] == 0xFE && Buffer[1] == 0xFF);

    if (isUtf16LE || isUtf16BE)
    {
        PWCHAR utf16Buffer = (PWCHAR)(Buffer + 2);
        ULONG  utf16Chars  = (BytesRead - 2) / sizeof(WCHAR);
        ULONG  lineStart   = 0;

        for (ULONG i = 0; i <= utf16Chars; i++)
        {
            BOOLEAN isDelim = (i == utf16Chars) ||
                              utf16Buffer[i] == L'\n' ||
                              utf16Buffer[i] == L'\r';
            if (isDelim)
            {
                if (i > lineStart)
                {
                    ULONG lineLen = i - lineStart;

                    // Trim trailing whitespace
                    while (lineLen > 0 && (utf16Buffer[lineStart + lineLen - 1] == L' '  ||
                                           utf16Buffer[lineStart + lineLen - 1] == L'\t' ||
                                           utf16Buffer[lineStart + lineLen - 1] == L'\r'))
                    {
                        lineLen--;
                    }

                    // Trim leading whitespace
                    ULONG leading = 0;
                    while (leading < lineLen && (utf16Buffer[lineStart + leading] == L' ' ||
                                                 utf16Buffer[lineStart + leading] == L'\t'))
                    {
                        leading++;
                    }

                    if (lineLen > leading)
                    {
                        lineLen -= leading;

                        // Byte-swap for UTF-16 BE
                        if (isUtf16BE)
                        {
                            for (ULONG k = 0; k < lineLen; k++)
                            {
                                WCHAR c = utf16Buffer[lineStart + leading + k];
                                utf16Buffer[lineStart + leading + k] = (WCHAR)((c << 8) | (c >> 8));
                            }
                        }

                        AddRuleString(RuleSet,
                                      &utf16Buffer[lineStart + leading],
                                      lineLen,
                                      RuleType);
                    }
                }
                lineStart = i + 1;
            }
        }
        return STATUS_SUCCESS;
    }

    // Fallback: treat as UTF-8 / ASCII
    ULONG lineStart = 0;
    for (ULONG i = 0; i <= BytesRead; i++)
    {
        BOOLEAN isDelim = (i == BytesRead) || Buffer[i] == '\n' || Buffer[i] == '\r';
        if (isDelim)
        {
            if (i > lineStart)
            {
                ULONG lineLen = i - lineStart;
                while (lineLen > 0 && (Buffer[lineStart + lineLen - 1] == ' '  ||
                                       Buffer[lineStart + lineLen - 1] == '\t' ||
                                       Buffer[lineStart + lineLen - 1] == '\r'))
                {
                    lineLen--;
                }

                ULONG leading = 0;
                while (leading < lineLen && (Buffer[lineStart + leading] == ' '  ||
                                             Buffer[lineStart + leading] == '\t'))
                {
                    leading++;
                }

                if (lineLen > leading)
                {
                    lineLen -= leading;
                    // Widen from ASCII to WCHAR
                    PWCHAR ruleBuffer = (PWCHAR)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, (lineLen + 1) * sizeof(WCHAR), RULE_POOL_TAG);
                    if (ruleBuffer)
                    {
                        for (ULONG j = 0; j < lineLen; j++)
                        {
                            ruleBuffer[j] = (WCHAR)Buffer[lineStart + leading + j];
                        }
                        ruleBuffer[lineLen] = L'\0';
                        AddRuleString(RuleSet, ruleBuffer, lineLen, RuleType);
                        ExFreePoolWithTag(ruleBuffer, RULE_POOL_TAG);
                    }
                }
            }
            lineStart = i + 1;
        }
    }
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// NormalizeDevicePathToDos
// Converts \Device\HarddiskVolumeN prefix to \??\C: (hardcoded for Volume3=C:).
// ---------------------------------------------------------------------------
VOID NormalizeDevicePathToDos(PUNICODE_STRING Path)
{
    if (!Path || !Path->Buffer || Path->Length < 28) return;

    const WCHAR DEVICE_PREFIX[] = L"\\Device\\HarddiskVolume3";
    const WCHAR DOS_PREFIX[]    = L"\\??\\C:";

    BOOLEAN startsWith = TRUE;
    SIZE_T  prefixLen  = (sizeof(DEVICE_PREFIX) / sizeof(WCHAR)) - 1;

    if (Path->Length < prefixLen * sizeof(WCHAR)) return;

    for (SIZE_T i = 0; i < prefixLen; i++)
    {
        if (RtlUpcaseUnicodeChar(Path->Buffer[i]) != RtlUpcaseUnicodeChar(DEVICE_PREFIX[i]))
        {
            startsWith = FALSE;
            break;
        }
    }

    if (startsWith)
    {
        SIZE_T dosLen   = (sizeof(DOS_PREFIX) / sizeof(WCHAR)) - 1;
        SIZE_T totalLen = (Path->Length / sizeof(WCHAR)) - prefixLen + dosLen;

        if (totalLen * sizeof(WCHAR) <= Path->MaximumLength)
        {
            RtlMoveMemory(&Path->Buffer[dosLen],
                          &Path->Buffer[prefixLen],
                          Path->Length - (prefixLen * sizeof(WCHAR)));
            RtlCopyMemory(Path->Buffer, DOS_PREFIX, dosLen * sizeof(WCHAR));
            Path->Length = (USHORT)(totalLen * sizeof(WCHAR));
            if (Path->Length + sizeof(WCHAR) <= Path->MaximumLength)
                Path->Buffer[Path->Length / sizeof(WCHAR)] = L'\0';
        }
    }
}

// ---------------------------------------------------------------------------
// LoadRulesFromFilePath  -  read a single rule file and append its contents.
// ---------------------------------------------------------------------------
static NTSTATUS LoadRulesFromFilePath(
    _In_ PUNICODE_STRING      FilePath,
    _Inout_ PPROTECTION_RULE_SET RuleSet,
    _In_ RULE_TYPE            RuleType)
{
    IO_STATUS_BLOCK ioStatus        = { 0 };
    OBJECT_ATTRIBUTES objectAttributes;
    HANDLE fileHandle               = NULL;
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

    if (fileInfo.EndOfFile.QuadPart <= 0 ||
        fileInfo.EndOfFile.QuadPart > MAX_RULE_FILE_SIZE)
    {
        ZwClose(fileHandle);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    ULONG bufferSize = (ULONG)fileInfo.EndOfFile.QuadPart;
    PUCHAR buffer    = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, RULE_POOL_TAG);
    if (!buffer)
    {
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(buffer, bufferSize);

    status = ZwReadFile(
        fileHandle,
        NULL, NULL, NULL,
        &ioStatus,
        buffer,
        bufferSize,
        NULL, NULL);

    if (NT_SUCCESS(status))
    {
        status = AppendRulesFromBuffer(RuleSet, buffer, (ULONG)ioStatus.Information, RuleType);
    }

    ExFreePoolWithTag(buffer, RULE_POOL_TAG);
    ZwClose(fileHandle);
    return status;
}

// ---------------------------------------------------------------------------
// LoadRulesFromDirectorySpecific  -  enumerate all files in a subdirectory and
// load each as a rule file.  RuleType is derived from the loop index in
// InitializeProtectionRules and forwarded through the call chain.
// ---------------------------------------------------------------------------
static NTSTATUS LoadRulesFromDirectorySpecific(
    _In_    PCWSTR               SubDirectory,
    _Inout_ PPROTECTION_RULE_SET RuleSet,
    _In_    RULE_TYPE            RuleType)
{
    HANDLE dirHandle              = NULL;
    IO_STATUS_BLOCK ioStatus      = { 0 };
    UNICODE_STRING directoryPath;
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status;

    WCHAR fullDirPath[256];
    RtlStringCbPrintfW(fullDirPath, sizeof(fullDirPath), L"%s%s", RULE_DIRECTORY, SubDirectory);

    RtlInitUnicodeString(&directoryPath, fullDirPath);
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
    PFILE_DIRECTORY_INFORMATION dirInfo =
        (PFILE_DIRECTORY_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, RULE_POOL_TAG);
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
            NULL, NULL, NULL,
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
            fileName.Buffer        = current->FileName;
            fileName.Length        = (USHORT)current->FileNameLength;
            fileName.MaximumLength = (USHORT)current->FileNameLength;

            if (!IsDotDirectory(&fileName) &&
                !(current->FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                USHORT fullLength     = directoryPath.Length + fileName.Length + sizeof(WCHAR);
                PWCHAR fullPathBuffer = (PWCHAR)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, fullLength, RULE_POOL_TAG);
                if (!fullPathBuffer)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    goto Cleanup;
                }

                RtlCopyMemory(fullPathBuffer, directoryPath.Buffer, directoryPath.Length);
                RtlCopyMemory((PUCHAR)fullPathBuffer + directoryPath.Length,
                              fileName.Buffer, fileName.Length);
                fullPathBuffer[(fullLength / sizeof(WCHAR)) - 1] = L'\0';

                UNICODE_STRING fullPath;
                fullPath.Buffer        = fullPathBuffer;
                fullPath.Length        = fullLength - sizeof(WCHAR);
                fullPath.MaximumLength = fullLength;

                NTSTATUS loadStatus = LoadRulesFromFilePath(&fullPath, RuleSet, RuleType);
                ExFreePoolWithTag(fullPathBuffer, RULE_POOL_TAG);

                if (!NT_SUCCESS(loadStatus))
                {
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

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

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

    for (int i = 0; i < RuleTypeMax; i++)
    {
        FreeRuleSet(&g_RuleSets[i]);
        LoadRulesFromDirectorySpecific(kRuleSubDirs[i], &g_RuleSets[i], (RULE_TYPE)i);
    }

    g_RulesLoaded = TRUE;
    ExReleaseFastMutex(&g_RuleMutex);
    return STATUS_SUCCESS;
}

VOID CleanupProtectionRules()
{
    if (!g_RuleMutexInitialized)
    {
        return;
    }

    ExAcquireFastMutex(&g_RuleMutex);
    for (int i = 0; i < RuleTypeMax; i++)
    {
        FreeRuleSet(&g_RuleSets[i]);
    }
    g_RulesLoaded = FALSE;
    ExReleaseFastMutex(&g_RuleMutex);
}

BOOLEAN IsPathProtectedByType(_In_ PCWSTR Path, _In_ RULE_TYPE RuleType)
{
    if (!Path || (LONG)RuleType < 0 || RuleType >= RuleTypeMax)
    {
        return FALSE;
    }

    // Kernel-enforced base paths  -  protect the HydraDragonAntivirus install
    // directory regardless of what rule files say.
    static const PCWSTR kHardcodedRoots[] = {
        L"\\Program Files\\HydraDragonAntivirus",
        L"\\??\\C:\\Program Files\\HydraDragonAntivirus"
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

    if (!g_RulesLoaded)
    {
        InitializeProtectionRules();
    }

    ExAcquireFastMutex(&g_RuleMutex);

    BOOLEAN matched = FALSE;
    PPROTECTION_RULE_SET ruleSet = &g_RuleSets[RuleType];

    for (ULONG i = 0; i < ruleSet->Count; i++)
    {
        if (ruleSet->Rules[i] && ContainsSubstringInsensitive(Path, ruleSet->Rules[i]))
        {
            matched = TRUE;
            break;
        }
    }

    ExReleaseFastMutex(&g_RuleMutex);
    return matched;
}

BOOLEAN IsPathProtected(_In_ PCWSTR Path)
{
    // Legacy support: default to File rules
    return IsPathProtectedByType(Path, RuleTypeFile);
}
