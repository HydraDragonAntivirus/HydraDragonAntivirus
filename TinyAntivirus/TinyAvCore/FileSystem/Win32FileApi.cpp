#include "Win32FileApi.h"

namespace tinyav
{
namespace win32fs
{
	HRESULT OpenFile(__in LPCWSTR filePath,
		__in DWORD desiredAccess,
		__in DWORD shareMode,
		__in DWORD creationDisposition,
		__in DWORD flagsAndAttributes,
		__out HANDLE *handle)
	{
		if (filePath == NULL || handle == NULL) return E_INVALIDARG;
		*handle = CreateFileW(filePath, desiredAccess, shareMode, NULL, creationDisposition, flagsAndAttributes, NULL);
		return (*handle == INVALID_HANDLE_VALUE) ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
	}

	HRESULT CloseFile(__inout HANDLE *handle)
	{
		if (handle == NULL) return E_INVALIDARG;
		if (*handle == NULL || *handle == INVALID_HANDLE_VALUE)
		{
			*handle = INVALID_HANDLE_VALUE;
			return S_OK;
		}

		BOOL ok = CloseHandle(*handle);
		*handle = INVALID_HANDLE_VALUE;
		return ok ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	HRESULT Read(__in HANDLE handle,
		__out_bcount(bufferSize) LPVOID buffer,
		__in DWORD bufferSize,
		__out DWORD *readSize)
	{
		if (handle == NULL || handle == INVALID_HANDLE_VALUE || buffer == NULL || readSize == NULL)
			return E_INVALIDARG;

		return ReadFile(handle, buffer, bufferSize, readSize, NULL) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	HRESULT Write(__in HANDLE handle,
		__in_bcount(bufferSize) LPCVOID buffer,
		__in DWORD bufferSize,
		__out DWORD *writtenSize)
	{
		if (handle == NULL || handle == INVALID_HANDLE_VALUE || buffer == NULL || writtenSize == NULL)
			return E_INVALIDARG;

		return WriteFile(handle, buffer, bufferSize, writtenSize, NULL) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	HRESULT Seek(__in HANDLE handle,
		__in LARGE_INTEGER distanceToMove,
		__in DWORD moveMethod,
		__out_opt ULARGE_INTEGER *newPos)
	{
		if (handle == NULL || handle == INVALID_HANDLE_VALUE) return E_INVALIDARG;

		LARGE_INTEGER result = {};
		BOOL ok = SetFilePointerEx(handle, distanceToMove, &result, moveMethod);
		if (!ok) return HRESULT_FROM_WIN32(GetLastError());
		if (newPos) newPos->QuadPart = static_cast<ULONGLONG>(result.QuadPart);
		return S_OK;
	}

	HRESULT SeekToBegin(__in HANDLE handle)
	{
		LARGE_INTEGER origin = {};
		return Seek(handle, origin, FILE_BEGIN, NULL);
	}

	HRESULT ShrinkToCurrentPosition(__in HANDLE handle)
	{
		if (handle == NULL || handle == INVALID_HANDLE_VALUE) return E_INVALIDARG;
		return SetEndOfFile(handle) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	HRESULT QueryAttributes(__in LPCWSTR filePath, __out WIN32_FIND_DATAW *attributes)
	{
		if (filePath == NULL || attributes == NULL) return E_INVALIDARG;

		HANDLE findHandle = FindFirstFileW(filePath, attributes);
		if (findHandle == INVALID_HANDLE_VALUE)
			return HRESULT_FROM_WIN32(GetLastError());

		FindClose(findHandle);
		return S_OK;
	}

	HRESULT DeleteFilePath(__in LPCWSTR filePath)
	{
		if (filePath == NULL) return E_INVALIDARG;
		return DeleteFileW(filePath) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}

	HRESULT DelayDeleteUntilReboot(__in LPCWSTR filePath)
	{
		if (filePath == NULL) return E_INVALIDARG;
		return MoveFileExW(filePath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT) ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	}
}
}
