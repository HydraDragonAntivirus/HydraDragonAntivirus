#include "Log/File.hpp"

//The first arg example - L"\\??\\R:\\Trace.out"
void File::CreateFile(
	PCWSTR PathAndFile,
	ACCESS_MASK desiredAccess,
	ULONG fileAttributes,
	ULONG shareAccess,
	ULONG createDisposition,
	ULONG createOptions)
{
	UNICODE_STRING filePath;
	RtlInitUnicodeString(&filePath, PathAndFile);

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, &filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS Status = ZwCreateFile(&hFile, desiredAccess, &objectAttributes, &ioStatusBlock, NULL,
		fileAttributes, shareAccess, createDisposition, createOptions, NULL, 0);

	if (NT_SUCCESS(Status)) { KdPrint(("File create successfully\n")); }
	else { KdPrint(("Failed to create the file: %X\n", Status)); }

	return;
}

void File::DeleteFile()
{
	if (hFile != nullptr)
	{
		FILE_DISPOSITION_INFORMATION dispositionInfo;
		dispositionInfo.DeleteFile = TRUE;

		NTSTATUS Status = ZwSetInformationFile(hFile, &ioStatusBlock, &dispositionInfo, sizeof(FILE_DISPOSITION_INFORMATION),
			FileDispositionInformation);

		if (NT_SUCCESS(Status)) { KdPrint(("File delete successfully\n")); }
		else { ZwClose(hFile); KdPrint(("Failed to delete the file: %X\n", Status)); }
	}
	return;
}

size_t File::GetFileSize()
{
	FILE_STANDARD_INFORMATION FileInfo;
	//IO_STATUS_BLOCK ioStatusBlock;

	NTSTATUS status = ZwQueryInformationFile(hFile, &ioStatusBlock, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);

	if (NT_SUCCESS(status)) {
		KdPrint(("ZwQueryInformationFile successfully\n"));
		return FileInfo.EndOfFile.QuadPart;
	}
	else {
		KdPrint(("Failed on ZwQueryInformationFile: %p\n", status));
		return FileInfo.EndOfFile.QuadPart;
	}
}

LARGE_INTEGER byteOffset; bool A = false;
void File::WriteFile(PCH Values, const ULONG ValuesLen)//UNICODE_STRING Data)
{
	if (!A) { byteOffset.QuadPart = 0; A = true; }

	NTSTATUS Status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, (PVOID)Values, ValuesLen, &byteOffset, NULL);
	if (NT_SUCCESS(Status)) {
		byteOffset.QuadPart += ValuesLen;//Data.Length;
		//KdPrint(("Data written to the file successfully\n"));
	}
	else {
		KdPrint(("Failed to write data to the file: %X\n", Status));
	}
	
	return;
}

void File::CloseFile()
{
	ZwClose(hFile);
}