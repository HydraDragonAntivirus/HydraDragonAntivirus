#include "KernelString.h"
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
        (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, String->MaximumLength, 'RW');

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
        ExFreePoolWithTag(String->Buffer, 'RW');
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

    // Must be at PASSIVE_LEVEL for IoGetDeviceObjectPointer / IoVolumeDeviceToDosName
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;

    // Only handle paths that start with \Device\ (NT namespace).
    // Skip paths that are already in DOS form (start with a drive letter like "C:\").
    if (NtPath[0] != L'\\')
        return FALSE;

    // Find the 3rd backslash to delimit the volume component.
    // \Device\HarddiskVolume3\path\to\file.exe
    //  ^1     ^2              ^3
    SIZE_T pathLen = wcsnlen(NtPath, 32767);
    SIZE_T volumeEnd = 0;
    int slashCount = 0;
    for (SIZE_T i = 0; i < pathLen; i++) {
        if (NtPath[i] == L'\\') {
            slashCount++;
            if (slashCount == 3) {
                volumeEnd = i;
                break;
            }
        }
    }
    if (slashCount < 3)
        return FALSE;   // not a \Device\X\... path (e.g. just \Device\HarddiskVolume3)

    // Build a UNICODE_STRING for the volume-only portion: \Device\HarddiskVolume3
    UNICODE_STRING volumePart;
    volumePart.Buffer       = const_cast<PWCHAR>(NtPath);
    volumePart.Length       = (USHORT)(volumeEnd * sizeof(WCHAR));
    volumePart.MaximumLength = volumePart.Length;

    // Open the volume device object by its NT namespace name.
    PFILE_OBJECT  fileObj = NULL;
    PDEVICE_OBJECT devObj = NULL;
    NTSTATUS status = IoGetDeviceObjectPointer(&volumePart, FILE_READ_ATTRIBUTES, &fileObj, &devObj);
    if (!NT_SUCCESS(status))
        return FALSE;

    // Map device object → DOS drive letter (e.g., "C:")
    UNICODE_STRING dosName;
    status = IoVolumeDeviceToDosName(devObj, &dosName);
    ObDereferenceObject(fileObj);   // release ref obtained by IoGetDeviceObjectPointer
    if (!NT_SUCCESS(status))
        return FALSE;

    // Compose: dosName + &NtPath[volumeEnd]  (suffix includes the leading backslash)
    SIZE_T dosChars    = dosName.Length / sizeof(WCHAR);
    SIZE_T suffixChars = pathLen - volumeEnd;
    SIZE_T totalChars  = dosChars + suffixChars;

    if (totalChars + 1 > OutCch) {
        ExFreePool(dosName.Buffer);
        return FALSE;
    }

    RtlCopyMemory(OutBuffer,            dosName.Buffer,          dosName.Length);
    RtlCopyMemory(OutBuffer + dosChars, NtPath + volumeEnd, suffixChars * sizeof(WCHAR));
    OutBuffer[totalChars] = L'\0';

    ExFreePool(dosName.Buffer);
    return TRUE;
}