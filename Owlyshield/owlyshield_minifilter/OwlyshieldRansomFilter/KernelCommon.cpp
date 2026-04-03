#include "KernelCommon.h"
#include <intrin.h>

// CRT string handling stubs for missing WDK symbols
#include <ntstrsafe.h>

#pragma warning(push)
#pragma warning(disable: 28251 28252 28253)
extern "C" int __cdecl __stdio_common_vswprintf(
    unsigned __int64 options, wchar_t *buffer, size_t count,
    const wchar_t *format, _locale_t locale, va_list arglist)
{
    UNREFERENCED_PARAMETER(options);
    UNREFERENCED_PARAMETER(locale);

    if (buffer == nullptr || count == 0)
    {
        return -1;
    }
#pragma warning(pop)

    NTSTATUS status = RtlStringCchVPrintfW(buffer, count, format, arglist);
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
    {
        size_t len = 0;
        RtlStringCchLengthW(buffer, count, &len);
        return static_cast<int>(len);
    }
    return -1;
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
            // DbgPrint("String ended before pattern, %d\n", i);
            return FALSE;
        }
        if (RtlDowncaseUnicodeChar(Pattern[i]) != RtlDowncaseUnicodeChar(buffer[i]))
        {
            // DbgPrint("Chars not eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]),
            // RtlDowncaseUnicodeChar(buffer[i]));
            return FALSE;
        }
        // DbgPrint("Chars are eq: %d, %d\n", RtlDowncaseUnicodeChar(Pattern[i]), RtlDowncaseUnicodeChar(buffer[i]));
    }
    return TRUE;
}
