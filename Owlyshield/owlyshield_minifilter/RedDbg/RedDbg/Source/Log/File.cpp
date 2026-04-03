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
	if (hFile == nullptr)
	{
		return 0;
	}

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

void File::WriteFile(PCH Values, SIZE_T ValuesLen)//UNICODE_STRING Data)
{
	if (hFile == nullptr || Values == nullptr || ValuesLen == 0)
	{
		return;
	}

	if (ValuesLen > MAXULONG)
	{
		KdPrint(("Failed to write data to the file: buffer too large (%llu)\n", ValuesLen));
		return;
	}

	if (!ByteOffsetInitialized)
	{
		byteOffset.QuadPart = 0;
		ByteOffsetInitialized = true;
	}

	ULONG bytesToWrite = static_cast<ULONG>(ValuesLen);
	NTSTATUS Status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, (PVOID)Values, bytesToWrite, &byteOffset, NULL);
	if (NT_SUCCESS(Status)) {
		byteOffset.QuadPart += bytesToWrite;//Data.Length;
		//KdPrint(("Data written to the file successfully\n"));
	}
	else {
		KdPrint(("Failed to write data to the file: %X\n", Status));
	}
	
	return;
}

void File::CloseFile()
{
	if (hFile != nullptr)
	{
		ZwClose(hFile);
		hFile = nullptr;
		ByteOffsetInitialized = false;
		byteOffset.QuadPart = 0;
	}
}
