#include "MemoryFs.h"

CMemoryFs::CMemoryFs()
{
	m_delimiter = StringW(L"\\");
	m_flags = 0;
	m_error = 0;
	m_fsType = IVirtualFs::memory;
	m_container = NULL;
	m_attributes = FILE_ATTRIBUTE_NORMAL;
	m_isOpened = FALSE;
	ZeroMemory(&m_currentPos, sizeof(m_currentPos));
	RefreshTimestamps();
}

CMemoryFs::~CMemoryFs()
{
	if (m_container)
	{
		m_container->Release();
		m_container = NULL;
	}
}

HRESULT WINAPI CMemoryFs::QueryInterface(__in REFIID riid,
	__out _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject)
{
	if (ppvObject == NULL) return E_INVALIDARG;

	if (IsEqualIID(riid, IID_IUnknown) ||
		IsEqualIID(riid, __uuidof(IVirtualFs)) ||
		IsEqualIID(riid, __uuidof(IMemoryFs)))
	{
		*ppvObject = static_cast<IMemoryFs*>(this);
		AddRef();
		return S_OK;
	}

	if (IsEqualIID(riid, __uuidof(IFsAttribute)))
	{
		*ppvObject = static_cast<IFsAttribute*>(this);
		AddRef();
		return S_OK;
	}

	if (IsEqualIID(riid, __uuidof(IFsStream)))
	{
		*ppvObject = static_cast<IFsStream*>(this);
		AddRef();
		return S_OK;
	}

	*ppvObject = NULL;
	return E_NOINTERFACE;
}

HRESULT WINAPI CMemoryFs::Create(__in LPCWSTR lpFileName, __in ULONG const flags)
{
	if (lpFileName == NULL || _tcslen(lpFileName) == 0) return E_INVALIDARG;
	m_fileName = lpFileName;
	m_flags = flags;
	m_isOpened = TRUE;
	m_currentPos.QuadPart = 0;
	RefreshTimestamps();
	m_error = ERROR_SUCCESS;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Close(void)
{
	m_isOpened = FALSE;
	m_currentPos.QuadPart = 0;
	if (TEST_FLAG(m_flags, fsDeferredDeletion))
	{
		m_buffer.clear();
		m_fileName.clear();
		m_flags = 0;
	}
	m_error = ERROR_SUCCESS;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::ReCreate(__in_opt void* handle, __in_opt ULONG const flags)
{
	if (handle != NULL) return E_INVALIDARG;
	if (flags != 0) m_flags = flags;
	m_currentPos.QuadPart = 0;
	m_isOpened = TRUE;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::GetHandle(__out LPVOID * fileHandle)
{
	if (fileHandle == NULL) return E_INVALIDARG;
	if (m_isOpened == FALSE) return E_NOT_SET;
	*fileHandle = m_buffer.empty() ? static_cast<LPVOID>(this) : static_cast<LPVOID>(m_buffer.data());
	return S_OK;
}

HRESULT WINAPI CMemoryFs::GetFsType(__out ULONG * fsType)
{
	if (fsType == NULL) return E_INVALIDARG;
	*fsType = m_fsType;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::IsOpened(__out BOOL *isOpened)
{
	if (isOpened == NULL) return E_INVALIDARG;
	*isOpened = m_isOpened;
	return S_OK;
}

ULONG WINAPI CMemoryFs::GetError(void)
{
	return m_error;
}

void WINAPI CMemoryFs::SetError(__in const ULONG error)
{
	m_error = error;
}

HRESULT WINAPI CMemoryFs::GetFlags(__out ULONG *flags)
{
	if (flags == NULL) return E_INVALIDARG;
	*flags = m_flags;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::GetFullPath(__out BSTR *fullPath)
{
	if (fullPath == NULL) return E_INVALIDARG;
	if (m_fileName.empty()) return E_NOT_SET;

	StringW fullName = m_fileName;
	if (m_container)
	{
		BSTR containerFullPath = NULL;
		if (SUCCEEDED(m_container->GetFullPath(&containerFullPath)) && containerFullPath)
		{
			fullName = StringW(containerFullPath) + m_delimiter + m_fileName;
			SysFreeString(containerFullPath);
		}
	}

	*fullPath = SysAllocString(fullName.c_str());
	return (*fullPath == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMemoryFs::GetFileName(__out BSTR *fileName)
{
	if (fileName == NULL) return E_INVALIDARG;
	if (m_fileName.empty()) return E_NOT_SET;
	*fileName = SysAllocString(m_fileName.c_str());
	return (*fileName == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMemoryFs::GetFileExt(__out BSTR *fileExt)
{
	if (fileExt == NULL) return E_INVALIDARG;
	if (m_fileName.empty()) return E_NOT_SET;
	size_t pos = m_fileName.rfind(L'.');
	if (pos == StringW::npos || pos + 1 >= m_fileName.length()) return E_NOT_SET;
	*fileExt = SysAllocString(m_fileName.substr(pos + 1).c_str());
	return (*fileExt == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMemoryFs::GetContainer(__out IVirtualFs **container)
{
	if (container == NULL) return E_INVALIDARG;
	if (m_container == NULL) return E_NOT_SET;
	m_container->AddRef();
	*container = m_container;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::SetContainer(__in IVirtualFs *container)
{
	if (m_container)
	{
		m_container->Release();
		m_container = NULL;
	}
	m_container = container;
	if (m_container)
	{
		m_container->AddRef();
	}
	return S_OK;
}

HRESULT WINAPI CMemoryFs::DeferredDelete(void)
{
	m_flags |= fsDeferredDeletion;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::SetBuffer(__in_bcount_opt(bufferSize) LPCVOID buffer, __in ULONG bufferSize)
{
	m_buffer.resize(bufferSize);
	if (bufferSize > 0)
	{
		if (buffer == NULL) return E_INVALIDARG;
		memcpy(m_buffer.data(), buffer, bufferSize);
	}
	m_currentPos.QuadPart = 0;
	m_isOpened = TRUE;
	RefreshTimestamps();
	return S_OK;
}

HRESULT WINAPI CMemoryFs::GetBuffer(__out_bcount_part_opt(bufferSize, *copiedSize) LPVOID buffer,
	__in ULONG bufferSize,
	__out_opt ULONG *copiedSize)
{
	if (copiedSize) *copiedSize = 0;
	if (buffer == NULL && bufferSize > 0) return E_INVALIDARG;
	ULONG toCopy = static_cast<ULONG>(std::min<size_t>(bufferSize, m_buffer.size()));
	if (toCopy > 0 && buffer)
	{
		memcpy(buffer, m_buffer.data(), toCopy);
	}
	if (copiedSize) *copiedSize = toCopy;
	return (toCopy == m_buffer.size()) ? S_OK : S_FALSE;
}

HRESULT WINAPI CMemoryFs::GetBufferSize(__out ULARGE_INTEGER *bufferSize)
{
	return Size(bufferSize);
}

HRESULT WINAPI CMemoryFs::SetFilePath(__in LPCWSTR lpFilePath, __in_opt void* handle)
{
	UNREFERENCED_PARAMETER(handle);
	if (lpFilePath == NULL || _tcslen(lpFilePath) == 0) return E_INVALIDARG;
	m_fileName = lpFilePath;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Size(__out ULARGE_INTEGER * fileSize)
{
	if (fileSize == NULL) return E_INVALIDARG;
	fileSize->QuadPart = static_cast<ULONGLONG>(m_buffer.size());
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Attributes(__out DWORD *attribs)
{
	if (attribs == NULL) return E_INVALIDARG;
	*attribs = m_attributes;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::SetAttributes(__in DWORD attribs)
{
	m_attributes = attribs;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Time(__out_opt FILETIME *lpCreationTime,
	__out_opt FILETIME *lpLastAccessTime,
	__out_opt FILETIME *lpLastWriteTime)
{
	if (lpCreationTime == NULL && lpLastAccessTime == NULL && lpLastWriteTime == NULL)
	{
		return E_INVALIDARG;
	}

	if (lpCreationTime) *lpCreationTime = m_creationTime;
	if (lpLastAccessTime) *lpLastAccessTime = m_lastAccessTime;
	if (lpLastWriteTime) *lpLastWriteTime = m_lastWriteTime;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::SetTime(__in_opt FILETIME *lpCreationTime,
	__in_opt FILETIME *lpLastAccessTime,
	__in_opt FILETIME *lpLastWriteTime)
{
	if (lpCreationTime == NULL && lpLastAccessTime == NULL && lpLastWriteTime == NULL)
	{
		return E_INVALIDARG;
	}

	if (lpCreationTime) m_creationTime = *lpCreationTime;
	if (lpLastAccessTime) m_lastAccessTime = *lpLastAccessTime;
	if (lpLastWriteTime) m_lastWriteTime = *lpLastWriteTime;
	return S_OK;
}

void WINAPI CMemoryFs::SetFileHandle(__in void* const handle)
{
	UNREFERENCED_PARAMETER(handle);
	m_currentPos.QuadPart = 0;
}

HRESULT WINAPI CMemoryFs::Read(__out_bcount(bufferSize) LPVOID buffer, __in ULONG bufferSize, __out_opt ULONG * readSize)
{
	if (buffer == NULL || bufferSize == 0) return E_INVALIDARG;
	if (m_isOpened == FALSE) return E_NOT_SET;
	if (readSize) *readSize = 0;

	size_t available = (m_currentPos.QuadPart < m_buffer.size()) ? (m_buffer.size() - static_cast<size_t>(m_currentPos.QuadPart)) : 0;
	size_t toRead = std::min<size_t>(bufferSize, available);
	if (toRead > 0)
	{
		memcpy(buffer, m_buffer.data() + static_cast<size_t>(m_currentPos.QuadPart), toRead);
		m_currentPos.QuadPart += toRead;
	}
	if (readSize) *readSize = static_cast<ULONG>(toRead);
	GetSystemTimeAsFileTime(&m_lastAccessTime);
	return S_OK;
}

HRESULT WINAPI CMemoryFs::ReadAt(__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod,
	__out_bcount(bufferSize) LPVOID buffer, __in ULONG bufferSize, __out_opt ULONG * readSize)
{
	HRESULT hr = SeekInternal(offset, moveMethod);
	if (FAILED(hr)) return hr;
	return Read(buffer, bufferSize, readSize);
}

HRESULT WINAPI CMemoryFs::Write(__in_bcount(bufferSize) LPCVOID buffer, __in ULONG bufferSize, __out_opt ULONG * writtenSize)
{
	if (buffer == NULL || bufferSize == 0) return E_INVALIDARG;
	if (m_isOpened == FALSE) return E_NOT_SET;
	if (writtenSize) *writtenSize = 0;

	size_t writeEnd = static_cast<size_t>(m_currentPos.QuadPart) + bufferSize;
	if (writeEnd > m_buffer.size())
	{
		m_buffer.resize(writeEnd);
	}

	memcpy(m_buffer.data() + static_cast<size_t>(m_currentPos.QuadPart), buffer, bufferSize);
	m_currentPos.QuadPart += bufferSize;
	if (writtenSize) *writtenSize = bufferSize;
	GetSystemTimeAsFileTime(&m_lastAccessTime);
	GetSystemTimeAsFileTime(&m_lastWriteTime);
	return S_OK;
}

HRESULT WINAPI CMemoryFs::WriteAt(__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod,
	__in_bcount(bufferSize) LPCVOID buffer, __in ULONG bufferSize, __out_opt ULONG * writtenSize)
{
	HRESULT hr = SeekInternal(offset, moveMethod);
	if (FAILED(hr)) return hr;
	return Write(buffer, bufferSize, writtenSize);
}

HRESULT WINAPI CMemoryFs::Tell(__out ULARGE_INTEGER * pos)
{
	if (pos == NULL) return E_INVALIDARG;
	if (m_isOpened == FALSE) return E_NOT_SET;
	*pos = m_currentPos;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Seek(__out_opt ULARGE_INTEGER * pos, __in LARGE_INTEGER const distanceToMove, __in const FsStreamSeek MoveMethod)
{
	HRESULT hr = SeekInternal(distanceToMove, MoveMethod);
	if (FAILED(hr)) return hr;
	if (pos) *pos = m_currentPos;
	return S_OK;
}

HRESULT WINAPI CMemoryFs::Shrink(void)
{
	if (m_isOpened == FALSE) return E_NOT_SET;
	if (m_currentPos.QuadPart < m_buffer.size())
	{
		m_buffer.resize(static_cast<size_t>(m_currentPos.QuadPart));
	}
	GetSystemTimeAsFileTime(&m_lastWriteTime);
	return S_OK;
}

HRESULT WINAPI CMemoryFs::SeekInternal(__in LARGE_INTEGER const distanceToMove, __in const FsStreamSeek moveMethod)
{
	if (m_isOpened == FALSE) return E_NOT_SET;

	LONGLONG base = 0;
	switch (moveMethod)
	{
	case IFsStream::FsStreamBegin:
		base = 0;
		break;
	case IFsStream::FsStreamCurrent:
		base = static_cast<LONGLONG>(m_currentPos.QuadPart);
		break;
	case IFsStream::FsStreamEnd:
		base = static_cast<LONGLONG>(m_buffer.size());
		break;
	default:
		return E_INVALIDARG;
	}

	LONGLONG target = base + distanceToMove.QuadPart;
	if (target < 0) return HRESULT_FROM_WIN32(ERROR_NEGATIVE_SEEK);
	m_currentPos.QuadPart = static_cast<ULONGLONG>(target);
	return S_OK;
}

void WINAPI CMemoryFs::RefreshTimestamps(void)
{
	GetSystemTimeAsFileTime(&m_creationTime);
	m_lastAccessTime = m_creationTime;
	m_lastWriteTime = m_creationTime;
}
