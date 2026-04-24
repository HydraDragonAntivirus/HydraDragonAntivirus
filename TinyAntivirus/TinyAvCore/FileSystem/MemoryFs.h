#pragma once
#include <TinyAvCore.h>

class CMemoryFs :
	public CRefCount,
	public IMemoryFs,
	public IFsAttribute,
	public IFsStream
{
protected:
	StringW m_delimiter;
	StringW m_fileName;
	std::vector<BYTE> m_buffer;
	ULONG m_flags;
	ULONG m_error;
	ULONG m_fsType;
	IVirtualFs *m_container;
	ULARGE_INTEGER m_currentPos;
	DWORD m_attributes;
	FILETIME m_creationTime;
	FILETIME m_lastAccessTime;
	FILETIME m_lastWriteTime;
	BOOL m_isOpened;

	virtual ~CMemoryFs();

public:
	CMemoryFs();

	DECLARE_REF_COUNT();

	virtual HRESULT WINAPI QueryInterface(__in REFIID riid,
		__out _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject) override;

	virtual HRESULT WINAPI Create(__in LPCWSTR lpFileName, __in ULONG const flags) override;
	virtual HRESULT WINAPI Close(void) override;
	virtual HRESULT WINAPI ReCreate(__in_opt void* handle = NULL, __in_opt ULONG const flags = 0) override;
	virtual HRESULT WINAPI GetHandle(__out LPVOID * fileHandle) override;
	virtual HRESULT WINAPI GetFsType(__out ULONG * fsType) override;
	virtual HRESULT WINAPI IsOpened(__out BOOL *isOpened) override;
	virtual ULONG WINAPI GetError(void) override;
	virtual void WINAPI SetError(__in const ULONG error) override;
	virtual HRESULT WINAPI GetFlags(__out ULONG *flags) override;
	virtual HRESULT WINAPI GetFullPath(__out BSTR *fullPath) override;
	virtual HRESULT WINAPI GetFileName(__out BSTR *fileName) override;
	virtual HRESULT WINAPI GetFileExt(__out BSTR *fileExt) override;
	virtual HRESULT WINAPI GetContainer(__out IVirtualFs **container) override;
	virtual HRESULT WINAPI SetContainer(__in IVirtualFs *container) override;
	virtual HRESULT WINAPI DeferredDelete(void) override;

	virtual HRESULT WINAPI SetBuffer(__in_bcount_opt(bufferSize) LPCVOID buffer, __in ULONG bufferSize) override;
	virtual HRESULT WINAPI GetBuffer(__out_bcount_part_opt(bufferSize, *copiedSize) LPVOID buffer,
		__in ULONG bufferSize,
		__out_opt ULONG *copiedSize) override;
	virtual HRESULT WINAPI GetBufferSize(__out ULARGE_INTEGER *bufferSize) override;

	virtual HRESULT WINAPI SetFilePath(__in LPCWSTR lpFilePath, __in_opt void* handle = NULL) override;
	virtual HRESULT WINAPI Size(__out ULARGE_INTEGER * fileSize) override;
	virtual HRESULT WINAPI Attributes(__out DWORD *attribs) override;
	virtual HRESULT WINAPI SetAttributes(__in DWORD attribs) override;
	virtual HRESULT WINAPI Time(__out_opt FILETIME *lpCreationTime,
		__out_opt FILETIME *lpLastAccessTime,
		__out_opt FILETIME *lpLastWriteTime) override;
	virtual HRESULT WINAPI SetTime(__in_opt FILETIME *lpCreationTime,
		__in_opt FILETIME *lpLastAccessTime,
		__in_opt FILETIME *lpLastWriteTime) override;

	virtual void WINAPI SetFileHandle(__in void* const handle) override;
	virtual HRESULT WINAPI Read(__out_bcount(bufferSize) LPVOID buffer, __in ULONG bufferSize, __out_opt ULONG * readSize) override;
	virtual HRESULT WINAPI ReadAt(__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod,
		__out_bcount(bufferSize) LPVOID buffer, __in ULONG bufferSize, __out_opt ULONG * readSize) override;
	virtual HRESULT WINAPI Write(__in_bcount(bufferSize) LPCVOID buffer, __in ULONG bufferSize, __out_opt ULONG * writtenSize) override;
	virtual HRESULT WINAPI WriteAt(__in LARGE_INTEGER const offset, __in const FsStreamSeek moveMethod,
		__in_bcount(bufferSize) LPCVOID buffer, __in ULONG bufferSize, __out_opt ULONG * writtenSize) override;
	virtual HRESULT WINAPI Tell(__out ULARGE_INTEGER * pos) override;
	virtual HRESULT WINAPI Seek(__out_opt ULARGE_INTEGER * pos, __in LARGE_INTEGER const distanceToMove, __in const FsStreamSeek MoveMethod) override;
	virtual HRESULT WINAPI Shrink(void) override;

protected:
	HRESULT WINAPI SeekInternal(__in LARGE_INTEGER const distanceToMove, __in const FsStreamSeek moveMethod);
	void WINAPI RefreshTimestamps(void);
};
