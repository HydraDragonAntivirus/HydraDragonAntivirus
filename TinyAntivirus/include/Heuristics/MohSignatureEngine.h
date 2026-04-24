#pragma once
#include <TinyAvBase.h>
#include <FileSystem/FsObject.h>
#include <vector>

MIDL_INTERFACE("7E4F2B1C-3A0D-4D4F-8E2B-9C1D3F8E2B1C")
IMosSignatureEngine : public IUnknown
{
public:
	BEGIN_INTERFACE

	/* Load signatures from a decrypted CVD/IVD buffer */
	virtual HRESULT WINAPI LoadSignatures(__in_bcount(size) const void* buffer, __in size_t size) = 0;

	/* Clear all loaded signatures */
	virtual HRESULT WINAPI Reset() = 0;

	/* Match signatures against a file stream or memory buffer */
	virtual HRESULT WINAPI Match(__in IVirtualFs* file, __out_bcount(maxName) WCHAR* malwareName, __in size_t maxName) = 0;

	END_INTERFACE
};

// {4B2E1F3D-5C6D-4E7F-8A9B-0C1D2E3F4G5H}
DEFINE_GUID(CLSID_CMosSignatureEngine, 0x4B2E1F3D, 0x5C6D, 0x4E7F, 0x8A, 0x9B, 0x0C, 0x1D, 0x2E, 0x3F, 0x4B, 0x5C);
