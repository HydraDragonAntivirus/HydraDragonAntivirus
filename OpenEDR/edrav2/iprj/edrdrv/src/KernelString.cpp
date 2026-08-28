#include "KernelString.h"
#include "PoolTags.h"
#include <ntstrsafe.h>

NTSTATUS
FSAllocateUnicodeString(_Inout_ PUNICODE_STRING String)
/*++

Routine Description:

	This routine allocates a unicode string

Arguments:

	String - supplies the size of the string to be allocated in the MaximumLength field
			 return the unicode string

Return Value:

	STATUS_SUCCESS                  - success
	STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{
    String->Buffer =
        (PWCH)ExAllocatePoolWithTag(NonPagedPool, String->MaximumLength, OWLY_POOL_TAG_UNICODE_STRING);

    if (String->Buffer == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    String->Length = 0;

    return STATUS_SUCCESS;
}

VOID FSFreeUnicodeString(_Inout_ PUNICODE_STRING String)
/*++

Routine Description:

	This routine frees a unicode string

Arguments:

	String - supplies the string to be freed

Return Value:

	None

--*/
{
    if (String->Buffer) {
        ExFreePoolWithTag(String->Buffer, OWLY_POOL_TAG_UNICODE_STRING);
        String->Buffer = NULL;
    }

    String->Length = String->MaximumLength = 0;
    String->Buffer = NULL;
}

BOOLEAN
NtPathToDosPath(
    _In_z_          PCWSTR  NtPath,
    _Out_writes_z_(OutCch) PWCHAR  OutBuffer,
    _In_            SIZE_T  OutCch)
{
    if (!NtPath || !OutBuffer || OutCch == 0)
        return FALSE;

    // Zw* symbolic-link APIs require PASSIVE_LEVEL.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;

    // Already a DOS path (e.g. "C:\...") — nothing to do.
    if (NtPath[0] != L'\\')
        return FALSE;

    SIZE_T pathLen = wcsnlen(NtPath, 32767);
    if (pathLen == 0)
        return FALSE;

    // Enumerate \DosDevices\A: .. \DosDevices\Z:.
    // Each symlink points to the NT volume device name, e.g. \Device\HarddiskVolume3.
    // We pick the drive letter whose target is a prefix of NtPath, then
    // substitute that prefix with "X:".  This avoids IoGetDeviceObjectPointer
    // which requires the device to be ready for I/O and can fail transiently.

    WCHAR linkNameBuf[] = L"\\DosDevices\\A:";
    // Index 12 is the drive-letter position in the string above.

    WCHAR targetBuf[512] = {0};

    for (WCHAR letter = L'A'; letter <= L'Z'; letter++)
    {
        linkNameBuf[12] = letter;

        UNICODE_STRING linkStr;
        RtlInitUnicodeString(&linkStr, linkNameBuf);

        OBJECT_ATTRIBUTES objAttr;
        InitializeObjectAttributes(&objAttr, &linkStr,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   NULL, NULL);

        HANDLE hLink;
        NTSTATUS status = ZwOpenSymbolicLinkObject(&hLink, GENERIC_READ, &objAttr);
        if (!NT_SUCCESS(status))
            continue;

        UNICODE_STRING target;
        target.Buffer        = targetBuf;
        target.Length        = 0;
        target.MaximumLength = sizeof(targetBuf) - sizeof(WCHAR);
        RtlZeroMemory(targetBuf, sizeof(targetBuf));

        status = ZwQuerySymbolicLinkObject(hLink, &target, NULL);
        ZwClose(hLink);

        if (!NT_SUCCESS(status) || target.Length == 0)
            continue;

        SIZE_T targetChars = target.Length / sizeof(WCHAR);
        targetBuf[targetChars] = L'\0';

        if (pathLen < targetChars)
            continue;

        // NtPath must start with this target, followed by '\' or end-of-string.
        if (_wcsnicmp(NtPath, targetBuf, targetChars) != 0)
            continue;
        if (NtPath[targetChars] != L'\\' && NtPath[targetChars] != L'\0')
            continue;

        // Compose "X:" + NtPath[targetChars..]
        SIZE_T suffixChars = pathLen - targetChars;  // includes the leading '\'
        SIZE_T totalChars  = 2 + suffixChars;        // "X:" + suffix

        if (totalChars + 1 > OutCch)
            return FALSE;

        OutBuffer[0] = letter;
        OutBuffer[1] = L':';
        RtlCopyMemory(OutBuffer + 2, NtPath + targetChars, suffixChars * sizeof(WCHAR));
        OutBuffer[totalChars] = L'\0';
        return TRUE;
    }

    return FALSE;
}

