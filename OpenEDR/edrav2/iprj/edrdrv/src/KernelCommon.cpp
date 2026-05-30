#include "KernelCommon.h"
#include <intrin.h>

// Keep the kernel CRT declarations available, but avoid ntstrsafe formatting here:
// ntstrsafe's VPrintf path calls back into _vsnwprintf, which re-enters this shim.
#include <ntstrsafe.h>

#pragma warning(push)
#pragma warning(disable: 28251 28252 28253)
extern "C" int __cdecl __stdio_common_vswprintf(
    unsigned __int64 options, wchar_t *buffer, size_t count,
    const wchar_t *format, _locale_t locale, va_list arglist)
{
    UNREFERENCED_PARAMETER(options);
    UNREFERENCED_PARAMETER(locale);

    if (buffer == nullptr || count == 0 || format == nullptr)
    {
        return -1;
    }
#pragma warning(pop)

    buffer[0] = L'\0';

    __try
    {
        // Mirror the legacy null-termination behavior expected by the UCRT helper.
#pragma warning(push)
#pragma warning(disable: 4996)
        int result = _vsnwprintf(buffer, count - 1, format, arglist);
#pragma warning(pop)

        if ((result < 0) || (static_cast<size_t>(result) >= count))
        {
            buffer[count - 1] = L'\0';
            return -1;
        }

        buffer[result] = L'\0';
        return result;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        buffer[0] = L'\0';
        return -1;
    }
}

// FIXME: add count param for copy length, MAX_FILE_NAME_LENGTH - 1 is default value
NTSTATUS CopyWString(LPWSTR dest, LPCWSTR source, size_t size)
{
    INT err = wcsncpy_s(dest, size, source, MAX_FILE_NAME_LENGTH - 1);
    if (err == 0)
    {
        dest[size - 1] = L'\0';
        return STATUS_SUCCESS;
    }
    else
    {
        return STATUS_INTERNAL_ERROR;
    }
}

WCHAR *stristr(const WCHAR *String, const WCHAR *Pattern)
{
    WCHAR *pptr, *sptr, *start;

    for (start = (WCHAR *)String; *start != L'\0'; ++start)
    {
        while (((*start != L'\0') && (RtlUpcaseUnicodeChar(*start) != RtlUpcaseUnicodeChar(*Pattern))))
        {
            ++start;
        }

        if (L'\0' == *start)
            return NULL;

        pptr = (WCHAR *)Pattern;
        sptr = (WCHAR *)start;

        while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr))
        {
            sptr++;
            pptr++;

            if (L'\0' == *pptr)
                return (start);
        }
    }

    return NULL;
}

BOOLEAN startsWith(PUNICODE_STRING String, PWCHAR Pattern)
{
    if (String == NULL || Pattern == NULL)
        return FALSE;
    PWCHAR buffer = String->Buffer;
    for (ULONG i = 0; i < wcslen(Pattern); i++)
    {
        if (String->Length <= 2 * i)
        {
            // 
#if IS_DEBUG_IRP
_LOGINFO_RAW("String ended before pattern, %d\n", i);
#endif

            return FALSE;
        }
        if (RtlDowncaseUnicodeChar(Pattern[i]) != RtlDowncaseUnicodeChar(buffer[i]))
        {
            // 
#if IS_DEBUG_IRP
_LOGINFO_RAW("Chars not eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]),
            // RtlDowncaseUnicodeChar(buffer[i]));
#endif

            return FALSE;
        }
        // 
#if IS_DEBUG_IRP
_LOGINFO_RAW("Chars are eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]), RtlDowncaseUnicodeChar(buffer[i]));
#endif

    }
    return TRUE;
}

