#ifndef _DRIVER_COMMON_H_
#define _DRIVER_COMMON_H_

#include <ntifs.h>

// Tag for allocations
#define COMMON_POOL_TAG 'mmcC'

// Helper: Case-insensitive substring search (wcsstr equivalent for kernel)
// Returns TRUE if 'Substring' is found inside 'Source'
FORCEINLINE BOOLEAN ContainsSubstringInsensitive(PCWSTR Source, PCWSTR Substring)
{
    if (!Source || !Substring) return FALSE;

    UNICODE_STRING uSource, uSubstring;
    RtlInitUnicodeString(&uSource, Source);
    RtlInitUnicodeString(&uSubstring, Substring);

    // RtlFindUnicodeString is available in NtosKrnl.exe
    // Returns pointer to found substring or NULL
    // CaseInSensitive = TRUE
    // Note: RtlFindUnicodeString is available from XP onwards.
    // If stricmp/wcsstr is preferred, we can use that too, but Rtl is safer for UNICODE_STRINGs.
    // However, here we have PCWSTR. simpler manual check or using Rtl functions.

    // Let's use a manual loop for maximum compatibility and no external dependency issues if linked weirdly.
    // But RtlUpcaseUnicodeString logic is best.
    
    // Simplest Kernel Safe Way:
    // Convert to UNICODE_STRING and use RtlFindUnicodeString
    // NOTE: RtlFindUnicodeString takes UNICODE_STRING pointers.
    
    // Check if RtlFindUnicodeString is available (it should be standard). 
    // If not, we fall back to manual. But let's assume standard WDK.
    
    // Actually, 'Source' input here is PCWSTR (null terminated). 
    // We can just construct UNICODE_STRINGs wrapping them.
    
    if (uSource.Length < uSubstring.Length) return FALSE;

    // Use RtlFindUnicodeString
    // Prototype: PWCHAR RtlFindUnicodeString(PUNICODE_STRING SourceString, PUNICODE_STRING SearchString, BOOLEAN CaseInSensitive);
    
    // We need to look up if this function is exported correctly in all targets. 
    // It is generally safe.
    
    // To be absolutely safe and avoid "undefined symbol" errors if the environment is strict:
    // We'll implement a simple wcsstr-like using RtlUpcaseUnicodeChar
    
    SIZE_T srcLen = wcslen(Source);
    SIZE_T subLen = wcslen(Substring);
    
    if (subLen > srcLen) return FALSE;
    
    for (SIZE_T i = 0; i <= srcLen - subLen; i++)
    {
        BOOLEAN match = TRUE;
        for (SIZE_T j = 0; j < subLen; j++)
        {
            WCHAR c1 = RtlUpcaseUnicodeChar(Source[i + j]);
            WCHAR c2 = RtlUpcaseUnicodeChar(Substring[j]);
            if (c1 != c2)
            {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    
    return FALSE;
}

// Helper: Escape JSON string (backslashes)
// Dest must be large enough. Returns TRUE if successful.
// 'DestSize' is in bytes.
FORCEINLINE BOOLEAN EscapeJsonString(PWCHAR Dest, SIZE_T DestSize, PCWSTR Source)
{
    if (!Dest || !Source) return FALSE;

    SIZE_T srcLen = wcslen(Source);
    // Worst case: every char is a backslash -> double size
    // Plus null terminator.
    
    SIZE_T currentIdx = 0;
    SIZE_T maxChars = DestSize / sizeof(WCHAR);
    if (maxChars == 0) return FALSE;

    for (SIZE_T i = 0; i < srcLen; i++)
    {
        if (currentIdx + 2 >= maxChars) // Ensure space for char + potential escape + null
        {
            // Truncate if too long (safety)
            break;
        }

        if (Source[i] == L'\\')
        {
            Dest[currentIdx++] = L'\\';
            Dest[currentIdx++] = L'\\';
        }
        else if (Source[i] == L'"')
        {
            Dest[currentIdx++] = L'\\';
            Dest[currentIdx++] = L'"';
        }
        else
        {
            Dest[currentIdx++] = Source[i];
        }
    }

    Dest[currentIdx] = L'\0';
    return TRUE;
}

#endif // _DRIVER_COMMON_H_
