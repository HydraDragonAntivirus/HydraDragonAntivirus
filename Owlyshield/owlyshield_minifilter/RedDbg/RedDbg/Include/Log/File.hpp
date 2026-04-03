#pragma once
#include <ntddk.h>
#include <vector>
#include <string>

class File {
private:
	size_t GetFileSize();
public:
	HANDLE hFile = nullptr;
	IO_STATUS_BLOCK ioStatusBlock = {};
	LARGE_INTEGER byteOffset = {};
	bool ByteOffsetInitialized = false;
public:
	void CreateFile(
		PCWSTR PathAndFile,
		ACCESS_MASK desiredAccess,
		ULONG fileAttributes,
		ULONG shareAccess,
		ULONG createDisposition,
		ULONG createOptions);
	void DeleteFile();
	void CloseFile();
public:
	void WriteFile(PCH Values, SIZE_T ValuesLen);
};
