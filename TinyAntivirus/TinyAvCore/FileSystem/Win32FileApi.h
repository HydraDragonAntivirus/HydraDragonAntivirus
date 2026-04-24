#pragma once
#include <TinyAvBase.h>

namespace tinyav
{
namespace win32fs
{
	HRESULT OpenFile(__in LPCWSTR filePath,
		__in DWORD desiredAccess,
		__in DWORD shareMode,
		__in DWORD creationDisposition,
		__in DWORD flagsAndAttributes,
		__out HANDLE *handle);

	HRESULT CloseFile(__inout HANDLE *handle);

	HRESULT Read(__in HANDLE handle,
		__out_bcount(bufferSize) LPVOID buffer,
		__in DWORD bufferSize,
		__out DWORD *readSize);

	HRESULT Write(__in HANDLE handle,
		__in_bcount(bufferSize) LPCVOID buffer,
		__in DWORD bufferSize,
		__out DWORD *writtenSize);

	HRESULT Seek(__in HANDLE handle,
		__in LARGE_INTEGER distanceToMove,
		__in DWORD moveMethod,
		__out_opt ULARGE_INTEGER *newPos);

	HRESULT SeekToBegin(__in HANDLE handle);

	HRESULT ShrinkToCurrentPosition(__in HANDLE handle);

	HRESULT QueryAttributes(__in LPCWSTR filePath, __out WIN32_FIND_DATAW *attributes);

	HRESULT DeleteFilePath(__in LPCWSTR filePath);

	HRESULT DelayDeleteUntilReboot(__in LPCWSTR filePath);
}
}
