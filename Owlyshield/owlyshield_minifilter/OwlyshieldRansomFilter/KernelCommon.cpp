#include "KernelCommon.h"

void* __cdecl operator new(size_t size) {
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'RW');
}

void __cdecl operator delete(void* data, size_t size) {
    UNREFERENCED_PARAMETER(size);
    if (data != NULL)
        ExFreePoolWithTag(data, 'RW');
}

void __cdecl operator delete(void* data) {
    if (data != NULL)
        ExFreePoolWithTag(data, 'RW');
}

// FIXME: add count param for copy length, MAX_FILE_NAME_LENGTH - 1 is default value
NTSTATUS CopyWString(LPWSTR dest, LPCWSTR source, size_t size) {
    INT err = wcsncpy_s(dest, size, source, MAX_FILE_NAME_LENGTH - 1);
    if (err == 0) {
        dest[size - 1] = L'\0';
        return STATUS_SUCCESS;
    } else {
        return STATUS_INTERNAL_ERROR;
    }
}

WCHAR* stristr(const WCHAR* String, const WCHAR* Pattern) {
    WCHAR *pptr, *sptr, *start;

    for (start = (WCHAR*)String; *start != L'\0'; ++start) {
        while (
            ((*start != L'\0')
             && (RtlUpcaseUnicodeChar(*start)
                 != RtlUpcaseUnicodeChar(*Pattern)))) {
            ++start;
        }

        if (L'\0' == *start)
            return NULL;

        pptr = (WCHAR*)Pattern;
        sptr = (WCHAR*)start;

        while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr)) {
            sptr++;
            pptr++;

            if (L'\0' == *pptr)
                return (start);
        }
    }

    return NULL;
}

BOOLEAN startsWith(PUNICODE_STRING String, PWCHAR Pattern) {
    if (String == NULL || Pattern == NULL)
        return FALSE;
    PWCHAR buffer = String->Buffer;
    for (ULONG i = 0; i < wcslen(Pattern); i++) {
        if (String->Length <= 2 * i) {
            //DbgPrint("String ended before pattern, %d\n", i);
            return FALSE;
        }
        if (RtlDowncaseUnicodeChar(Pattern[i])
            != RtlDowncaseUnicodeChar(buffer[i])) {
            //DbgPrint("Chars not eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]), RtlDowncaseUnicodeChar(buffer[i]));
            return FALSE;
        }
        //DbgPrint("Chars are eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]), RtlDowncaseUnicodeChar(buffer[i]));
    }
    return TRUE;
}

// =========================================================================
// Path Classification and Finding Emission Functions
// =========================================================================

PCWSTR FSGetUefiPathFindingPrefix(_In_opt_ PUNICODE_STRING FilePath)
{
    if (FilePath == NULL || FilePath->Buffer == NULL)
    {
        return NULL;
    }

    WCHAR buffer[MAX_FILE_NAME_LENGTH];
    UNICODE_STRING normalizedPath;
    normalizedPath.Buffer = buffer;
    normalizedPath.Length = 0;
    normalizedPath.MaximumLength = sizeof(buffer);

    // Normalize the path for comparison
    if (!OwlyNormalizePathForMatch(FilePath, buffer, &normalizedPath))
    {
        return NULL;
    }

    PCWSTR pathStr = normalizedPath.Buffer;
    if (pathStr == NULL)
    {
        return NULL;
    }

    // Check for raw disk device access patterns
    if (wcsstr(pathStr, L"\\Device\\HarddiskVolume") != NULL ||
        wcsstr(pathStr, L"\\Device\\Harddisk") != NULL)
    {
        return L"uefi raw device access: ";
    }

    // Check for system critical paths
    if (wcsstr(pathStr, L"\\Windows\\System32\\drivers") != NULL ||
        wcsstr(pathStr, L"\\Windows\\System32\\") != NULL)
    {
        return L"system critical file: ";
    }

    // Check for boot-critical paths
    if (wcsstr(pathStr, L"\\Boot\\") != NULL ||
        wcsstr(pathStr, L"\\bootmgr") != NULL)
    {
        return L"boot critical file: ";
    }

    // Check for startup paths
    if (wcsstr(pathStr, L"\\Startup\\") != NULL ||
        wcsstr(pathStr, L"\\Start Menu\\Programs\\Startup") != NULL)
    {
        return L"startup file: ";
    }

    // Default to generic user file classification
    return L"user file: ";
}

VOID FSEmitGenericKernelPathFinding(
    _In_ ULONG PID,
    _In_ ULONGLONG GID,
    _In_opt_ PUNICODE_STRING FilePath,
    _In_opt_ PCWSTR FindingPrefix,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ NTSTATUS Status,
    _In_ UCHAR FileChange,
    _In_ ULONG_PTR ExtraInfo1,
    _In_ ULONG_PTR ExtraInfo2)
{
    UNREFERENCED_PARAMETER(PID);
    UNREFERENCED_PARAMETER(GID);
    UNREFERENCED_PARAMETER(FilePath);
    UNREFERENCED_PARAMETER(FindingPrefix);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(FileChange);
    UNREFERENCED_PARAMETER(ExtraInfo1);
    UNREFERENCED_PARAMETER(ExtraInfo2);

    // TODO: Implement actual finding emission to communication port
    // This should create a DRIVER_MESSAGE and queue it for user-mode delivery
    // For now, this is a stub to resolve compilation errors
    // The actual implementation should:
    // 1. Allocate a DRIVER_MESSAGE structure
    // 2. Populate it with the finding details
    // 3. Send it through the communication port to user-mode
}

BOOLEAN FSHasCreateWriteIntent(
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG CreateOptions)
{
    // Check for write-related access flags
    if ((DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA)) != 0)
    {
        return TRUE;
    }

    // Check for delete-on-close which implies write intent
    if ((CreateOptions & FILE_DELETE_ON_CLOSE) != 0)
    {
        return TRUE;
    }

    // Check for overwrite/truncate operations
    if ((CreateOptions & FILE_OVERWRITE_IF) != 0 || (CreateOptions & FILE_OVERWRITE) != 0)
    {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN FSIsRawBootDevicePath(_In_opt_ PUNICODE_STRING FilePath)
{
    if (FilePath == NULL || FilePath->Buffer == NULL)
    {
        return FALSE;
    }

    // Check for raw device patterns that would indicate boot device access
    WCHAR buffer[MAX_FILE_NAME_LENGTH];
    UNICODE_STRING normalizedPath;
    normalizedPath.Buffer = buffer;
    normalizedPath.Length = 0;
    normalizedPath.MaximumLength = sizeof(buffer);

    if (!OwlyNormalizePathForMatch(FilePath, buffer, &normalizedPath))
    {
        return FALSE;
    }

    PCWSTR pathStr = normalizedPath.Buffer;
    if (pathStr == NULL)
    {
        return FALSE;
    }

    // Check if this is a raw disk device (e.g., \Device\HarddiskVolume0, \Device\Harddisk0)
    if (wcsstr(pathStr, L"\\Device\\HarddiskVolume") != NULL ||
        wcsstr(pathStr, L"\\Device\\Harddisk") != NULL)
    {
        // Additional check: if there's nothing after the volume number, it's raw device access
        PCWSTR afterVolume = wcsstr(pathStr, L"\\Device\\HarddiskVolume");
        if (afterVolume != NULL)
        {
            // Skip past "\\Device\\HarddiskVolume" and the number
            while (*afterVolume != L'\0' && *afterVolume != L'\\')
            {
                afterVolume++;
            }
            // If we hit end of string or only have backslash, it's raw device access
            return (afterVolume[0] == L'\0' || (afterVolume[0] == L'\\' && afterVolume[1] != L'\\'));
        }
        return TRUE;
    }

    return FALSE;
}