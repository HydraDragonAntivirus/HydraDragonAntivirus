#include "Driver.h"
#include "ProtectionRules.h"
#include "Driver_Common.h"
#include <ntstrsafe.h>

#define MAX_RULE_BLOB_SECTION_SIZE (256 * 1024) // per rule category, from user mode
#define ADD_RULE_LITERAL(RuleSet, Literal, RuleType) AddRuleString((RuleSet), (Literal), ARRAYSIZE(Literal) - 1, (RuleType))

static PROTECTION_RULE_SET g_RuleSets[RuleTypeMax] = { 0 };
static FAST_MUTEX g_RuleMutex;
static BOOLEAN g_RuleMutexInitialized = FALSE;
static BOOLEAN g_RulesLoaded = FALSE;

static VOID EnsureRuleMutexInitialized(VOID)
{
    if (!g_RuleMutexInitialized)
    {
        ExInitializeFastMutex(&g_RuleMutex);
        g_RuleMutexInitialized = TRUE;
    }
}

// Maximum extra chars added when expanding a hive prefix (HKCR\ -> \REGISTRY\MACHINE\SOFTWARE\CLASSES\)
#define REGISTRY_PREFIX_EXPANSION_MAX 64


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
            PCWSTR subpath   = RuleText + kHiveMap[i].UserPrefixLen;
            SIZE_T kernelLen = wcslen(kHiveMap[i].KernelPrefix);
            SIZE_T subLen    = wcslen(subpath);

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

    DbgPrint("[ProtectionRules] Rejected registry rule - must start with HKLM\\, HKCU\\, "
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
//                 \AppData\Roaming\Sanctum\).
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
        return TRUE;

    // Suffix / relative path (user-profile, driver subpaths, etc.)
    if (RuleText[0] == L'\\')
    {
        // Reject if it starts with \REGISTRY\  -  that belongs in the Registry ruleset
        if (_wcsnicmp(RuleText, L"\\REGISTRY\\", 10) == 0)
        {
            DbgPrint("[ProtectionRules] Rejected file/process rule - "
                     "\\REGISTRY\\ paths belong in the Registry ruleset: %ws\n", RuleText);
            return FALSE;
        }
        return TRUE;
    }

    DbgPrint("[ProtectionRules] Rejected file/process rule - must start with a drive letter "
             "(C:\\), \\??\\ or \\ : %ws\n", RuleText);
    return FALSE;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static NTSTATUS EnsureRuleCapacity(PPROTECTION_RULE_SET RuleSet, ULONG RequiredCount)
{
    if (RuleSet->Capacity >= RequiredCount)
        return STATUS_SUCCESS;

    ULONG newCapacity = (RuleSet->Capacity == 0) ? 8 : RuleSet->Capacity * 2;
    if (newCapacity < RequiredCount)
        newCapacity = RequiredCount;

    SIZE_T allocSize = sizeof(PWSTR) * newCapacity;
    PWSTR* newArray  = (PWSTR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, allocSize, RULE_POOL_TAG);
    if (!newArray)
        return STATUS_INSUFFICIENT_RESOURCES;

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

static BOOLEAN IsPathSeparator(_In_ WCHAR Character)
{
    return Character == L'\\' || Character == L'/';
}

static BOOLEAN IsDriveLetterPath(_In_ PCWSTR Path)
{
    if (!Path || wcslen(Path) < 3)
        return FALSE;

    return ((Path[0] >= L'A' && Path[0] <= L'Z') ||
            (Path[0] >= L'a' && Path[0] <= L'z')) &&
           Path[1] == L':' &&
           IsPathSeparator(Path[2]);
}

static BOOLEAN HasRuleBoundary(_In_ PCWSTR Path, _In_ SIZE_T RuleLength)
{
    WCHAR next = Path[RuleLength];
    return next == L'\0' || IsPathSeparator(next) || next == L':';
}

static BOOLEAN StartsWithRuleBoundary(_In_ PCWSTR Path, _In_ PCWSTR Rule)
{
    if (!Path || !Rule)
        return FALSE;

    SIZE_T ruleLen = wcslen(Rule);
    if (ruleLen == 0)
        return FALSE;

    if (!StartsWithInsensitive(Path, Rule))
        return FALSE;

    return HasRuleBoundary(Path, ruleLen) ||
           (ruleLen > 0 && IsPathSeparator(Rule[ruleLen - 1]));
}

static BOOLEAN FileRuleMatchesPath(_In_ PCWSTR Path, _In_ PCWSTR Rule)
{
    if (!Path || !Rule)
        return FALSE;

    if (StartsWithRuleBoundary(Path, Rule))
        return TRUE;

    if (StartsWithInsensitive(Path, L"\\??\\") && IsDriveLetterPath(Rule))
    {
        if (StartsWithRuleBoundary(Path + 4, Rule))
            return TRUE;
    }
    else if (StartsWithInsensitive(Rule, L"\\??\\") && IsDriveLetterPath(Path))
    {
        if (StartsWithRuleBoundary(Path, Rule + 4))
            return TRUE;
    }

    if (Rule[0] == L'\\' && !StartsWithInsensitive(Rule, L"\\??\\") && !StartsWithInsensitive(Rule, L"\\REGISTRY\\"))
    {
        for (PCWSTR cursor = Path; *cursor; cursor++)
        {
            if (*cursor == L'\\' && StartsWithRuleBoundary(cursor, Rule))
                return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN RegistrySubpathMatchesPath(_In_ PCWSTR Path, _In_ PCWSTR Subpath)
{
    if (!Path || !Subpath || Subpath[0] != L'\\')
        return FALSE;

    for (PCWSTR cursor = Path; *cursor; cursor++)
    {
        if (*cursor == L'\\' && StartsWithRuleBoundary(cursor, Subpath))
            return TRUE;
    }

    return FALSE;
}

static BOOLEAN RegistryRuleMatchesPath(_In_ PCWSTR Path, _In_ PCWSTR Rule)
{
    if (!Path || !Rule)
        return FALSE;

    if (StartsWithRuleBoundary(Path, Rule))
        return TRUE;

    static const PCWSTR kCurrentControlSetRule = L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\";
    static const PCWSTR kControlSetPath = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet";

    if (StartsWithInsensitive(Rule, kCurrentControlSetRule) &&
        StartsWithInsensitive(Path, kControlSetPath))
    {
        PCWSTR pathSuffix = Path + wcslen(kControlSetPath);
        while (*pathSuffix >= L'0' && *pathSuffix <= L'9')
            pathSuffix++;

        if (*pathSuffix == L'\\')
        {
            PCWSTR ruleSuffix = Rule + wcslen(kCurrentControlSetRule);
            SIZE_T ruleSuffixLen = wcslen(ruleSuffix);

            if (ruleSuffixLen > 0 &&
                StartsWithInsensitive(pathSuffix + 1, ruleSuffix) &&
                HasRuleBoundary(pathSuffix + 1, ruleSuffixLen))
            {
                return TRUE;
            }
        }
    }

    if (StartsWithInsensitive(Rule, L"\\REGISTRY\\USER\\"))
    {
        PCWSTR userSubpath = Rule + ARRAYSIZE(L"\\REGISTRY\\USER\\") - 2;
        if (userSubpath[0] == L'\\' && RegistrySubpathMatchesPath(Path, userSubpath))
            return TRUE;
    }

    return FALSE;
}

static BOOLEAN RuleMatchesPathByType(_In_ PCWSTR Path, _In_ PCWSTR Rule, _In_ RULE_TYPE RuleType)
{
    if (!Path || !Rule)
        return FALSE;

    if (RuleType == RuleTypeProcess)
        return EndsWithInsensitive(Path, Rule);

    if (RuleType == RuleTypeFile)
        return FileRuleMatchesPath(Path, Rule);

    if (RuleType == RuleTypeRegistry)
        return RegistryRuleMatchesPath(Path, Rule);

    return FALSE;
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
        return STATUS_SUCCESS;

    // ------------------------------------------------------------------
    // 1. Trim leading whitespace
    // ------------------------------------------------------------------
    SIZE_T start = 0;
    SIZE_T end   = CharacterCount;

    while (start < end && (RuleText[start] == L' ' || RuleText[start] == L'\t'))
        start++;

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
        end = commentPos;

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
        return STATUS_SUCCESS; // empty / comment-only line

    // ------------------------------------------------------------------
    // 4. Build a temporary null-terminated copy, normalising forward
    //    slashes to backslashes while copying.
    // ------------------------------------------------------------------
    SIZE_T rawLen  = end - start;
    SIZE_T tmpSize = (rawLen + REGISTRY_PREFIX_EXPANSION_MAX + 1) * sizeof(WCHAR);
    PWCHAR tempBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, tmpSize, RULE_POOL_TAG);
    if (!tempBuf)
        return STATUS_INSUFFICIENT_RESOURCES;

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
        ExFreePoolWithTag(RuleSet->Rules, RULE_POOL_TAG);

    RtlZeroMemory(RuleSet, sizeof(PROTECTION_RULE_SET));
}

static BOOLEAN IsDotDirectory(PUNICODE_STRING FileName)
{
    if (!FileName || !FileName->Buffer)
        return TRUE;
    if (FileName->Length == sizeof(WCHAR) && FileName->Buffer[0] == L'.')
        return TRUE;
    if (FileName->Length == 2 * sizeof(WCHAR) &&
        FileName->Buffer[0] == L'.' && FileName->Buffer[1] == L'.')
        return TRUE;
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
        return STATUS_SUCCESS;

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
                        lineLen--;

                    // Trim leading whitespace
                    ULONG leading = 0;
                    while (leading < lineLen && (utf16Buffer[lineStart + leading] == L' ' ||
                                                 utf16Buffer[lineStart + leading] == L'\t'))
                        leading++;

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
                    lineLen--;

                ULONG leading = 0;
                while (leading < lineLen && (Buffer[lineStart + leading] == ' '  ||
                                             Buffer[lineStart + leading] == '\t'))
                    leading++;

                if (lineLen > leading)
                {
                    lineLen -= leading;
                    // Widen from ASCII to WCHAR
                    PWCHAR ruleBuffer = (PWCHAR)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, (lineLen + 1) * sizeof(WCHAR), RULE_POOL_TAG);
                    if (ruleBuffer)
                    {
                        for (ULONG j = 0; j < lineLen; j++)
                            ruleBuffer[j] = (WCHAR)Buffer[lineStart + leading + j];
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
// Public API
// ---------------------------------------------------------------------------

NTSTATUS InitializeProtectionRules()
{
    //
    // Hardcoded rules for boot-time protection.
    // Instead of waiting for Sanctum to send rules over IOCTL, we populate
    // a base set of rules here to ensure protection starts immediately.
    //
    EnsureRuleMutexInitialized();

    ExAcquireFastMutex(&g_RuleMutex);
    
    // --- FILE PROTECTION RULES ---
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Program Files\\HydraDragonAntivirus", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\ProgramData\\HydraDragonAntivirus", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\ProgramData\\edrsvc", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\sanctum.dll", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\tasks\\hydradragonantivirus", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\owlyshieldransomfilter.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\RedDbgDrv.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\hyperhv.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\simplepyasprotection.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\mbrfilter.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\fs_minifilter.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\sanctum.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\drivers\\edrdrv.sys", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\edrpm64.dll", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\edrpm32.dll", RuleTypeFile);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeFile], L"\\??\\C:\\Windows\\System32\\edrmm.dll", RuleTypeFile);

    // --- PROCESS PROTECTION RULES ---
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\OpenEDR\\edrsvc.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\OpenEDR\\edrcon.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\HydraDragonLauncher\\hydradragonlauncher.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\HydraDragonAV\\HydraDragonAV.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\HydraDragonFirewall\\hydradragonfirewall.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\Owlyshield\\Owlyshield Service\\owlyshield_ransom.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\Sanctum\\um_engine.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\Sanctum\\AppData\\sanctum_ppl_runner.exe", RuleTypeProcess);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeProcess], L"\\hydradragon\\Sanctum\\app.exe", RuleTypeProcess);

    // --- REGISTRY PROTECTION RULES ---
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SOFTWARE\\Owlyshield", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\owlyshield_ransom", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\SimplePYASProtection", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\RedDbg", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\HyperDbg", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\hyperhv", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\sanctum_ppl_runner", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\MBRFilter", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\fs_minifilter", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\sanctum", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\edrdrv", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\edrsvc", RuleTypeRegistry);
    ADD_RULE_LITERAL(&g_RuleSets[RuleTypeRegistry], L"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", RuleTypeRegistry);

    g_RulesLoaded = TRUE;

    ExReleaseFastMutex(&g_RuleMutex);

    DbgPrint("[ProtectionRules] InitializeProtectionRules: %lu file, %lu process, %lu registry rules installed\n",
        g_RuleSets[RuleTypeFile].Count, g_RuleSets[RuleTypeProcess].Count, g_RuleSets[RuleTypeRegistry].Count);
    return STATUS_SUCCESS;
}

// Function removed because rules are no longer pushed from user mode

VOID CleanupProtectionRules()
{
    if (!g_RuleMutexInitialized)
        return;

    ExAcquireFastMutex(&g_RuleMutex);
    for (int i = 0; i < RuleTypeMax; i++)
        FreeRuleSet(&g_RuleSets[i]);
    g_RulesLoaded = FALSE;
    ExReleaseFastMutex(&g_RuleMutex);
}

BOOLEAN AreProtectionRulesLoaded()
{
    return g_RulesLoaded;
}

ULONG GetProtectionRuleCount(_In_ RULE_TYPE RuleType)
{
    if ((LONG)RuleType < 0 || RuleType >= RuleTypeMax || !g_RuleMutexInitialized)
        return 0;

    ExAcquireFastMutex(&g_RuleMutex);
    ULONG count = g_RuleSets[RuleType].Count;
    ExReleaseFastMutex(&g_RuleMutex);
    return count;
}

// ---------------------------------------------------------------------------
// IsPathProtectedByType
//
// If user-mode rules have not been sent yet, only the hardcoded product root is
// protected. The rule check never performs disk I/O and can safely run from
// process/file/registry callbacks.
// ---------------------------------------------------------------------------
BOOLEAN IsPathProtectedByType(_In_ PCWSTR Path, _In_ RULE_TYPE RuleType)
{
    if (!Path || (LONG)RuleType < 0 || RuleType >= RuleTypeMax)
        return FALSE;

    if (RuleType == RuleTypeFile)
    {
        static const PCWSTR kHardcodedRoots[] = {
            L"\\??\\C:\\Program Files\\HydraDragonAntivirus",
            L"\\??\\C:\\ProgramData\\HydraDragonAntivirus",
            L"\\??\\C:\\ProgramData\\edrsvc"
        };

        for (ULONG i = 0; i < ARRAYSIZE(kHardcodedRoots); ++i)
        {
            if (FileRuleMatchesPath(Path, kHardcodedRoots[i]))
                return TRUE;
        }
    }
    else if (RuleType == RuleTypeRegistry)
    {
        static const PCWSTR kHardcodedRegistryRoots[] = {
            L"\\REGISTRY\\MACHINE\\SOFTWARE\\Owlyshield",
            L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        };
        static const PCWSTR kHardcodedRegistrySubpaths[] = {
            L"\\Services\\owlyshield_ransom",
            L"\\Services\\SimplePYASProtection",
            L"\\Services\\RedDbg",
            L"\\Services\\HyperDbg",
            L"\\Services\\hyperhv",
            L"\\Services\\sanctum_ppl_runner",
            L"\\Services\\MBRFilter",
            L"\\Services\\fs_minifilter",
            L"\\Services\\sanctum",
            L"\\Services\\edrdrv",
            L"\\Services\\edrsvc"
        };

        for (ULONG i = 0; i < ARRAYSIZE(kHardcodedRegistryRoots); ++i)
        {
            if (RegistryRuleMatchesPath(Path, kHardcodedRegistryRoots[i]))
                return TRUE;
        }

        for (ULONG i = 0; i < ARRAYSIZE(kHardcodedRegistrySubpaths); ++i)
        {
            if (RegistrySubpathMatchesPath(Path, kHardcodedRegistrySubpaths[i]))
                return TRUE;
        }
    }

    if (!g_RulesLoaded || !g_RuleMutexInitialized)
        return FALSE;

    ExAcquireFastMutex(&g_RuleMutex);

    BOOLEAN matched = FALSE;
    PPROTECTION_RULE_SET ruleSet = &g_RuleSets[RuleType];

    for (ULONG i = 0; i < ruleSet->Count; i++)
    {
        if (ruleSet->Rules[i] && RuleMatchesPathByType(Path, ruleSet->Rules[i], RuleType))
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
    return IsPathProtectedByType(Path, RuleTypeFile);
}
