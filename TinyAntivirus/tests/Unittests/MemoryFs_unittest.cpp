#include <gtest/gtest.h>
#include <TinyAvCore.h>

TEST(MemoryFs, ReadWriteAndShrink)
{
	IMemoryFs * memoryFs = NULL;
	ASSERT_HRESULT_SUCCEEDED(CreateClassObject(CLSID_CMemoryFs, 0, __uuidof(IMemoryFs), (LPVOID*)&memoryFs));
	ASSERT_NE(nullptr, memoryFs);

	unsigned char initialData[] = { 0x4d, 0x5a, 0x90, 0x00 };
	ASSERT_HRESULT_SUCCEEDED(memoryFs->Create(L"ProcessMemory.bin", IVirtualFs::fsRead | IVirtualFs::fsWrite | IVirtualFs::fsAttrNormal));
	ASSERT_HRESULT_SUCCEEDED(memoryFs->SetBuffer(initialData, sizeof(initialData)));

	IFsAttribute * attribute = NULL;
	ASSERT_HRESULT_SUCCEEDED(memoryFs->QueryInterface(__uuidof(IFsAttribute), (LPVOID*)&attribute));
	ASSERT_NE(nullptr, attribute);

	ULARGE_INTEGER fileSize = {};
	ASSERT_HRESULT_SUCCEEDED(attribute->Size(&fileSize));
	ASSERT_EQ(sizeof(initialData), fileSize.QuadPart);

	IFsStream * stream = NULL;
	ASSERT_HRESULT_SUCCEEDED(memoryFs->QueryInterface(__uuidof(IFsStream), (LPVOID*)&stream));
	ASSERT_NE(nullptr, stream);

	unsigned char readBuffer[4] = {};
	ULONG readSize = 0;
	LARGE_INTEGER zero = {};
	ASSERT_HRESULT_SUCCEEDED(stream->ReadAt(zero, IFsStream::FsStreamBegin, readBuffer, sizeof(readBuffer), &readSize));
	ASSERT_EQ(sizeof(readBuffer), readSize);
	ASSERT_EQ(0, memcmp(initialData, readBuffer, sizeof(initialData)));

	unsigned char patchData[] = { 0x90, 0x90 };
	LARGE_INTEGER patchOffset = {};
	patchOffset.QuadPart = 2;
	ULONG writtenSize = 0;
	ASSERT_HRESULT_SUCCEEDED(stream->WriteAt(patchOffset, IFsStream::FsStreamBegin, patchData, sizeof(patchData), &writtenSize));
	ASSERT_EQ(sizeof(patchData), writtenSize);

	ULARGE_INTEGER currentPos = {};
	ASSERT_HRESULT_SUCCEEDED(stream->Tell(&currentPos));
	ASSERT_EQ(4, currentPos.QuadPart);

	LARGE_INTEGER shrinkOffset = {};
	shrinkOffset.QuadPart = 3;
	ASSERT_HRESULT_SUCCEEDED(stream->Seek(&currentPos, shrinkOffset, IFsStream::FsStreamBegin));
	ASSERT_HRESULT_SUCCEEDED(stream->Shrink());

	ASSERT_HRESULT_SUCCEEDED(attribute->Size(&fileSize));
	ASSERT_EQ(3, fileSize.QuadPart);

	unsigned char finalBuffer[3] = {};
	readSize = 0;
	ASSERT_HRESULT_SUCCEEDED(stream->ReadAt(zero, IFsStream::FsStreamBegin, finalBuffer, sizeof(finalBuffer), &readSize));
	ASSERT_EQ(sizeof(finalBuffer), readSize);
	ASSERT_EQ(0x4d, finalBuffer[0]);
	ASSERT_EQ(0x5a, finalBuffer[1]);
	ASSERT_EQ(0x90, finalBuffer[2]);

	ULONG rawSize = 0;
	unsigned char rawBuffer[3] = {};
	ASSERT_HRESULT_SUCCEEDED(memoryFs->GetBuffer(rawBuffer, sizeof(rawBuffer), &rawSize));
	ASSERT_EQ(sizeof(rawBuffer), rawSize);

	stream->Release();
	attribute->Release();
	memoryFs->Release();
}
