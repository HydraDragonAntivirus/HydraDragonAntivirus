#include <gtest/gtest.h>
#include <TinyAvCore.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace
{
	struct IMPORT_LIBRARY_SPEC
	{
		std::string dll;
		std::vector<std::string> functions;
	};

	DWORD AlignUp(const DWORD value, const DWORD alignment)
	{
		return (value + alignment - 1) & ~(alignment - 1);
	}

	template <typename T>
	void WriteStruct(std::vector<unsigned char>& image, const size_t offset, const T& value)
	{
		memcpy(image.data() + offset, &value, sizeof(value));
	}

	void WriteBytes(std::vector<unsigned char>& image, const size_t offset, const std::vector<unsigned char>& bytes)
	{
		if (!bytes.empty())
			memcpy(image.data() + offset, bytes.data(), bytes.size());
	}

	void WriteString(std::vector<unsigned char>& image, const size_t offset, const std::string& value)
	{
		memcpy(image.data() + offset, value.c_str(), value.length());
		image[offset + value.length()] = '\0';
	}

	std::vector<unsigned char> BuildPeImage(
		const std::vector<IMPORT_LIBRARY_SPEC>& imports,
		const std::vector<unsigned char>& entryCode,
		const std::vector<unsigned char>& lastSectionCode,
		const char *lastSectionName,
		const DWORD lastSectionCharacteristics,
		const bool entryPointInLastSection = false)
	{
		const DWORD fileAlignment = 0x200;
		const DWORD sectionAlignment = 0x1000;
		const DWORD headersSize = 0x200;
		const DWORD textRawOffset = 0x200;
		const DWORD textRawSize = 0x600;
		const DWORD textRva = 0x1000;
		const DWORD textVirtualSize = 0x600;
		const DWORD lastRawOffset = textRawOffset + textRawSize;
		const DWORD lastRawSize = 0x200;
		const DWORD lastRva = 0x2000;
		const DWORD lastVirtualSize = 0x200;
		const DWORD imageSize = 0x3000;
		const DWORD fileSize = lastRawOffset + lastRawSize;

		std::vector<unsigned char> image(fileSize, 0);

		IMAGE_DOS_HEADER dos = {};
		dos.e_magic = IMAGE_DOS_SIGNATURE;
		dos.e_lfanew = 0x80;
		WriteStruct(image, 0, dos);

		IMAGE_NT_HEADERS32 nt = {};
		nt.Signature = IMAGE_NT_SIGNATURE;
		nt.FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
		nt.FileHeader.NumberOfSections = 2;
		nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
		nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
		nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
		nt.OptionalHeader.AddressOfEntryPoint = entryPointInLastSection ? lastRva : textRva;
		nt.OptionalHeader.BaseOfCode = textRva;
		nt.OptionalHeader.BaseOfData = lastRva;
		nt.OptionalHeader.ImageBase = 0x400000;
		nt.OptionalHeader.SectionAlignment = sectionAlignment;
		nt.OptionalHeader.FileAlignment = fileAlignment;
		nt.OptionalHeader.SizeOfImage = imageSize;
		nt.OptionalHeader.SizeOfHeaders = headersSize;
		nt.OptionalHeader.SizeOfCode = textRawSize + lastRawSize;
		nt.OptionalHeader.SizeOfInitializedData = lastRawSize;
		nt.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
		nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
		nt.OptionalHeader.SizeOfStackReserve = 0x100000;
		nt.OptionalHeader.SizeOfStackCommit = 0x1000;
		nt.OptionalHeader.SizeOfHeapReserve = 0x100000;
		nt.OptionalHeader.SizeOfHeapCommit = 0x1000;

		IMAGE_SECTION_HEADER text = {};
		memcpy(text.Name, ".text", 5);
		text.Misc.VirtualSize = textVirtualSize;
		text.VirtualAddress = textRva;
		text.SizeOfRawData = textRawSize;
		text.PointerToRawData = textRawOffset;
		text.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

		IMAGE_SECTION_HEADER last = {};
		const size_t lastSectionNameLength = strlen(lastSectionName);
		const size_t copiedNameLength = (lastSectionNameLength < IMAGE_SIZEOF_SHORT_NAME) ?
			lastSectionNameLength :
			IMAGE_SIZEOF_SHORT_NAME;
		memcpy(last.Name, lastSectionName, copiedNameLength);
		last.Misc.VirtualSize = lastVirtualSize;
		last.VirtualAddress = lastRva;
		last.SizeOfRawData = lastRawSize;
		last.PointerToRawData = lastRawOffset;
		last.Characteristics = lastSectionCharacteristics;

		WriteStruct(image, dos.e_lfanew, nt);
		const size_t sectionTableOffset = dos.e_lfanew +
			FIELD_OFFSET(IMAGE_NT_HEADERS32, OptionalHeader) +
			nt.FileHeader.SizeOfOptionalHeader;
		WriteStruct(image, sectionTableOffset, text);
		WriteStruct(image, sectionTableOffset + sizeof(IMAGE_SECTION_HEADER), last);

		WriteBytes(image, entryPointInLastSection ? lastRawOffset : textRawOffset, entryCode);
		WriteBytes(image, lastRawOffset, lastSectionCode);

		if (!imports.empty())
		{
			struct IMPORT_LAYOUT
			{
				DWORD intRva = 0;
				DWORD iatRva = 0;
				DWORD nameRva = 0;
				std::vector<DWORD> functionNameRvas;
			};

			const DWORD importDirectoryRva = textRva + 0x100;
			size_t importDirectoryRaw = textRawOffset + 0x100;
			DWORD cursorRva = importDirectoryRva + static_cast<DWORD>((imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
			size_t cursorRaw = importDirectoryRaw + (imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
			std::vector<IMPORT_LAYOUT> layouts(imports.size());

			for (size_t i = 0; i < imports.size(); ++i)
			{
				const size_t thunkBytes = (imports[i].functions.size() + 1) * sizeof(DWORD);
				layouts[i].intRva = cursorRva;
				cursorRva += static_cast<DWORD>(thunkBytes);
				cursorRaw += thunkBytes;
				layouts[i].iatRva = cursorRva;
				cursorRva += static_cast<DWORD>(thunkBytes);
				cursorRaw += thunkBytes;
			}

			for (size_t i = 0; i < imports.size(); ++i)
			{
				layouts[i].nameRva = cursorRva;
				WriteString(image, cursorRaw, imports[i].dll);
				cursorRva += static_cast<DWORD>(imports[i].dll.length() + 1);
				cursorRaw += imports[i].dll.length() + 1;
				cursorRva = AlignUp(cursorRva, 2);
				cursorRaw = AlignUp(static_cast<DWORD>(cursorRaw), 2);
			}

			for (size_t i = 0; i < imports.size(); ++i)
			{
				layouts[i].functionNameRvas.reserve(imports[i].functions.size());
				for (const std::string& functionName : imports[i].functions)
				{
					layouts[i].functionNameRvas.push_back(cursorRva);
					WORD hint = 0;
					WriteStruct(image, cursorRaw, hint);
					WriteString(image, cursorRaw + sizeof(hint), functionName);
					cursorRva += static_cast<DWORD>(sizeof(hint) + functionName.length() + 1);
					cursorRaw += sizeof(hint) + functionName.length() + 1;
					cursorRva = AlignUp(cursorRva, 2);
					cursorRaw = AlignUp(static_cast<DWORD>(cursorRaw), 2);
				}
			}

			for (size_t i = 0; i < imports.size(); ++i)
			{
				IMAGE_IMPORT_DESCRIPTOR descriptor = {};
				descriptor.OriginalFirstThunk = layouts[i].intRva;
				descriptor.Name = layouts[i].nameRva;
				descriptor.FirstThunk = layouts[i].iatRva;
				WriteStruct(image, importDirectoryRaw + i * sizeof(IMAGE_IMPORT_DESCRIPTOR), descriptor);

				for (size_t thunkIndex = 0; thunkIndex < layouts[i].functionNameRvas.size(); ++thunkIndex)
				{
					const DWORD functionRva = layouts[i].functionNameRvas[thunkIndex];
					WriteStruct(image, (layouts[i].intRva - textRva) + textRawOffset + thunkIndex * sizeof(DWORD), functionRva);
					WriteStruct(image, (layouts[i].iatRva - textRva) + textRawOffset + thunkIndex * sizeof(DWORD), functionRva);
				}
			}

			nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = importDirectoryRva;
			nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = static_cast<DWORD>((imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
			WriteStruct(image, dos.e_lfanew, nt);
		}

		return image;
	}

	void AnalyzeImage(const std::vector<unsigned char>& image, MOS_PE_SIGNATURE_RESULT *result)
	{
		ASSERT_NE(nullptr, result);

		IMemoryFs *memoryFs = NULL;
		IPeFile *parser = NULL;
		BOOL matched = FALSE;
		ZeroMemory(result, sizeof(*result));

		ASSERT_HRESULT_SUCCEEDED(CreateClassObject(CLSID_CMemoryFs, 0, __uuidof(IMemoryFs), (LPVOID*)&memoryFs));
		ASSERT_HRESULT_SUCCEEDED(CreateClassObject(CLSID_CPeFileParser, 0, __uuidof(IPeFile), (LPVOID*)&parser));
		ASSERT_HRESULT_SUCCEEDED(memoryFs->Create(L"heuristic-test.exe", IVirtualFs::fsRead | IVirtualFs::fsWrite | IVirtualFs::fsAttrNormal));
		ASSERT_HRESULT_SUCCEEDED(memoryFs->SetBuffer(image.data(), static_cast<ULONG>(image.size())));
		ASSERT_HRESULT_SUCCEEDED(parser->CheckType(memoryFs, &matched));
		ASSERT_TRUE(matched);
		ASSERT_HRESULT_SUCCEEDED(AnalyzeMosPeSignatures(parser, result));

		parser->ReleaseCurrentFile();
		parser->Release();
		memoryFs->Release();
	}
}

TEST(MosPeSignatures, DetectsImportMix)
{
	std::vector<IMPORT_LIBRARY_SPEC> imports = {
		{
			"kernel32.dll",
			{
				"GetModuleHandleA", "Sleep", "FindFirstFileA", "FindNextFileA",
				"MoveFileA", "WinExec", "DeleteFileA", "WriteFile", "CreateFileA",
				"CreateProcessA", "GetTempPathA", "GetTempFileNameA",
				"GetSystemDirectoryA", "LoadLibraryA", "CreateRemoteThread"
			}
		},
		{ "shell32.dll", { "ShellExecuteA" } }
	};

	std::vector<unsigned char> image = BuildPeImage(
		imports,
		{ 0xC3 },
		{ 0x90, 0x90, 0xC3 },
		".data",
		IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	MOS_PE_SIGNATURE_RESULT result = {};
	AnalyzeImage(image, &result);
	ASSERT_TRUE(result.detected);
	ASSERT_TRUE(TEST_FLAG(result.flags, MosPeSignatureSuspiciousImportMix));
	ASSERT_TRUE(TEST_FLAG(result.flags, MosPeSignatureLoaderImports));
}

TEST(MosPeSignatures, DetectsEntrypointJumpIntoSuspiciousLastSection)
{
	std::vector<unsigned char> image = BuildPeImage(
		{},
		{ 0xE9, 0xFB, 0x0F, 0x00, 0x00 },
		{ 0x55, 0x8B, 0xEC, 0x81, 0xEC, 0x20, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x10, 0x40, 0x00, 0xC3 },
		".MOS",
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	MOS_PE_SIGNATURE_RESULT result = {};
	AnalyzeImage(image, &result);
	ASSERT_TRUE(result.detected);
	ASSERT_TRUE(TEST_FLAG(result.flags, MosPeSignatureEntrypointToLastSection));
	ASSERT_TRUE(TEST_FLAG(result.flags, MosPeSignatureEntrypointLoaderStub));
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureLoaderImports));
}

TEST(MosPeSignatures, IgnoresBenignImports)
{
	std::vector<IMPORT_LIBRARY_SPEC> imports = {
		{ "user32.dll", { "MessageBoxA" } },
		{ "comctl32.dll", { "InitCommonControlsEx" } },
		{ "kernel32.dll", { "LoadLibraryA" } }
	};

	std::vector<unsigned char> image = BuildPeImage(
		imports,
		{ 0xC3 },
		{ 0x90, 0x90, 0xC3 },
		".data",
		IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	MOS_PE_SIGNATURE_RESULT result = {};
	AnalyzeImage(image, &result);
	ASSERT_FALSE(result.detected);
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureSuspiciousImportMix));
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureEntrypointToLastSection));
}

TEST(MosPeSignatures, IgnoresLoaderOnlyImports)
{
	std::vector<IMPORT_LIBRARY_SPEC> imports = {
		{ "kernel32.dll", { "LoadLibraryA", "GetProcAddress" } },
		{ "advapi32.dll", { "RegOpenKeyExA" } }
	};

	std::vector<unsigned char> image = BuildPeImage(
		imports,
		{ 0xC3 },
		{ 0x90, 0x90, 0xC3 },
		".data",
		IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	MOS_PE_SIGNATURE_RESULT result = {};
	AnalyzeImage(image, &result);
	ASSERT_FALSE(result.detected);
	ASSERT_TRUE(TEST_FLAG(result.flags, MosPeSignatureLoaderImports));
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureSuspiciousImportMix));
}

TEST(MosPeSignatures, IgnoresDriverStylePageSection)
{
	std::vector<unsigned char> image = BuildPeImage(
		{},
		{ 0xE9, 0xFB, 0x0F, 0x00, 0x00 },
		{ 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x08, 0xC3 },
		"PAGE",
		IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

	MOS_PE_SIGNATURE_RESULT result = {};
	AnalyzeImage(image, &result);
	ASSERT_FALSE(result.detected);
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureEntrypointToLastSection));
	ASSERT_FALSE(TEST_FLAG(result.flags, MosPeSignatureWritableExecutableLastSection));
}
