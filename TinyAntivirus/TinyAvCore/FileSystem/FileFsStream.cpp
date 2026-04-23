#include "FileFsStream.h"
#include "Win32FileApi.h"

CFileFsStream::CFileFsStream()
{
	m_hFile = INVALID_HANDLE_VALUE;
	ZeroMemory(&m_currentPos, sizeof(m_currentPos));
	m_cacheSize = 0;
	m_cache = new char[DEFAULT_MAX_CACHE_SIZE];
	ZeroMemory(&m_cachePos, sizeof(m_cachePos));
}

CFileFsStream::~CFileFsStream()
{
	if (m_cache)
	{
		delete[] m_cache;
		m_cache = NULL;
	}
}

HRESULT WINAPI CFileFsStream::QueryInterface(
	__in REFIID riid,
	__out _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject)
{
	if (ppvObject == NULL) return E_INVALIDARG;

	if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(IFsStream)))
	{
		*ppvObject = static_cast<IFsStream*>(this);
		AddRef();
		return S_OK;
	}

	return E_NOINTERFACE;
}

HRESULT WINAPI CFileFsStream::Read(
	__out_bcount(bufferSize) LPVOID buffer,
	__in ULONG bufferSize, 
	__out_opt ULONG * readSize)
{
	ULONG r;
	if (m_hFile == INVALID_HANDLE_VALUE) return E_NOT_SET;
	if (buffer == NULL || bufferSize == 0) return E_INVALIDARG;

	if ((m_cachePos.QuadPart <= m_currentPos.QuadPart) &&
		(m_currentPos.QuadPart + bufferSize < m_cachePos.QuadPart + m_cacheSize))
	{
		memcpy(buffer, &m_cache[m_currentPos.QuadPart - m_cachePos.QuadPart], bufferSize);
		m_currentPos.QuadPart += bufferSize;
		LARGE_INTEGER distanceToMove;
		distanceToMove.QuadPart = m_currentPos.QuadPart;
		if (readSize) *readSize = bufferSize;

		HRESULT hr = tinyav::win32fs::Seek(m_hFile, distanceToMove, FILE_BEGIN, NULL);
		if (FAILED(hr))
		{
			return hr;
		}
	}
	else
	{
		DWORD bytesRead = 0;
		HRESULT hr = tinyav::win32fs::Read(m_hFile, buffer, bufferSize, &bytesRead);
		if (FAILED(hr))
		{
			return hr;
		}
		r = bytesRead;

		if (r)
		{
			m_cacheSize = r < DEFAULT_MAX_CACHE_SIZE ? r : DEFAULT_MAX_CACHE_SIZE;
			memcpy(m_cache, buffer, m_cacheSize);
		}

		m_cachePos.QuadPart = m_currentPos.QuadPart;
		m_currentPos.QuadPart += r;

		if (readSize) *readSize = r;
	}

	return S_OK;
}

HRESULT WINAPI CFileFsStream::ReadAt(
	__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod, 
	__out_bcount(bufferSize) LPVOID buffer, __in ULONG bufferSize, __out_opt ULONG * readSize)
{
	HRESULT hr = Seek(NULL, offset, moveMethod);
	if (FAILED(hr)) return hr;
	return Read(buffer, bufferSize, readSize);
}

HRESULT WINAPI CFileFsStream::Write(
	__in_bcount(bufferSize) LPCVOID buffer,
	__in ULONG bufferSize, 
	__out_opt ULONG * writtenSize)
{
	ULONG w;
	if (m_hFile == INVALID_HANDLE_VALUE) return E_NOT_SET;
	if (buffer == NULL || bufferSize == 0) return E_INVALIDARG;

	// write to disk
	DWORD bytesWritten = 0;
	HRESULT hr = tinyav::win32fs::Write(m_hFile, buffer, bufferSize, &bytesWritten);
	if (FAILED(hr))
	{
		return hr;
	}
	w = bytesWritten;

	// update cache
	if ((m_cachePos.QuadPart < m_currentPos.QuadPart) &&
		(m_currentPos.QuadPart + w < m_cachePos.QuadPart + m_cacheSize))
	{
		memcpy(&m_cache[m_currentPos.QuadPart - m_cachePos.QuadPart], buffer, w);
		m_currentPos.QuadPart += w;
	}
	else
	{
		m_cacheSize = w < DEFAULT_MAX_CACHE_SIZE ? w : DEFAULT_MAX_CACHE_SIZE;
		memcpy(m_cache, buffer, m_cacheSize);
		m_cachePos.QuadPart = m_currentPos.QuadPart;
		m_currentPos.QuadPart += w;
	}

	if (writtenSize) *writtenSize = w;
	return S_OK;
}

HRESULT WINAPI CFileFsStream::WriteAt(__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod, __in_bcount(bufferSize) LPCVOID buffer, __in ULONG bufferSize, __out_opt ULONG * writtenSize)
{
	HRESULT hr = Seek(NULL, offset, moveMethod);
	if (FAILED(hr)) return hr;
	return Write(buffer, bufferSize, writtenSize);
}

HRESULT WINAPI CFileFsStream::Tell(__out ULARGE_INTEGER * pos)
{
	if (m_hFile == INVALID_HANDLE_VALUE) return E_NOT_SET;
	if (pos == NULL) return E_INVALIDARG;

	*pos = m_currentPos;
	return S_OK;
}

HRESULT WINAPI CFileFsStream::Seek(
	__out_opt ULARGE_INTEGER * pos,
	__in LARGE_INTEGER const distanceToMove,
	__in const FsStreamSeek MoveMethod)
{
	if (m_hFile == INVALID_HANDLE_VALUE) return E_NOT_SET;
	DWORD dwMoveMethod = 0;
	switch (MoveMethod)
	{
	case IFsStream::FsStreamBegin:
		dwMoveMethod = FILE_BEGIN;
		break;

	case IFsStream::FsStreamCurrent:
		dwMoveMethod = FILE_CURRENT;
		break;

	case IFsStream::FsStreamEnd:
		dwMoveMethod = FILE_END;
		break;

	default:
		return E_INVALIDARG;
	}

	HRESULT hr = tinyav::win32fs::Seek(m_hFile, distanceToMove, dwMoveMethod, &m_currentPos);

	if (SUCCEEDED(hr))
	{
		if (pos) *pos = m_currentPos;
		if (m_cachePos.QuadPart > m_currentPos.QuadPart ||
			m_cachePos.QuadPart + m_cacheSize < m_currentPos.QuadPart)
		{
			m_cacheSize = 0;
		}
	}
	return hr;
}

void WINAPI CFileFsStream::SetFileHandle(__in void* const handle)
{
	m_hFile = (HANDLE)handle;
	if (m_hFile != NULL && m_hFile != INVALID_HANDLE_VALUE)
	{
		// Init cache
		tinyav::win32fs::SeekToBegin(m_hFile);
		DWORD r = 0;
		if (SUCCEEDED(tinyav::win32fs::Read(m_hFile, m_cache, DEFAULT_MAX_CACHE_SIZE, &r)) && r > 0)
		{
			m_cacheSize = (size_t)r;
		}
		ZeroMemory(&m_cachePos, sizeof(m_cachePos));
		tinyav::win32fs::SeekToBegin(m_hFile);
	}
}

HRESULT WINAPI CFileFsStream::Shrink(void)
{
	if (m_hFile == NULL || m_hFile == INVALID_HANDLE_VALUE) return E_NOT_VALID_STATE;
	HRESULT hr = tinyav::win32fs::ShrinkToCurrentPosition(m_hFile);
	if (FAILED(hr)) return hr;

	if ((m_cachePos.QuadPart <= m_currentPos.QuadPart) &&
		(m_currentPos.QuadPart < m_cachePos.QuadPart + m_cacheSize))
		m_cacheSize = (size_t)(m_currentPos.QuadPart - m_cachePos.QuadPart);
	else
		m_cacheSize = 0;
	return S_OK;
}
