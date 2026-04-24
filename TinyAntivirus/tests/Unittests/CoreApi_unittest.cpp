#include "gtest/gtest.h"
#include <TinyAvCore.h>
#include <windows.h>
#include <shlwapi.h>
#include <string>

#pragma comment(lib, "shlwapi.lib")

namespace
{
	std::wstring FindPathUpwards(const wchar_t *relativePath)
	{
		WCHAR currentDirectory[MAX_PATH + 1] = {};
		if (GetCurrentDirectoryW(MAX_PATH, currentDirectory) == 0)
			return std::wstring();

		std::wstring cursor = currentDirectory;
		for (int i = 0; i < 8 && !cursor.empty(); ++i)
		{
			const std::wstring candidate = cursor + L"\\" + relativePath;
			if (PathFileExistsW(candidate.c_str()))
				return candidate;

			size_t separator = cursor.find_last_of(L"\\/");
			if (separator == std::wstring::npos)
				break;
			cursor.erase(separator);
		}

		return std::wstring();
	}

	bool HasLoadedDatabaseFileName(const wchar_t* expectedFileName)
	{
		const __int64 signatureCount = CoreGetLoadedSignatureCount();
		for (__int64 i = 0; i < signatureCount; ++i)
		{
			WCHAR sourcePath[MAX_PATH + 1] = {};
			if (CoreCopyLoadedSignatureSourcePath(static_cast<unsigned int>(i), sourcePath, _countof(sourcePath)) != 1)
				continue;

			LPCWSTR fileName = PathFindFileNameW(sourcePath);
			if (_wcsicmp(fileName, expectedFileName) == 0)
				return true;
		}

		return false;
	}
}

TEST(CoreApiTest, BasicInit)
{
	EXPECT_EQ(CoreInit(), 1);
	EXPECT_EQ(CoreGetBuildNumber(), 2026);
	EXPECT_EQ(CoreUninit(), 1);
}

TEST(CoreApiTest, Instances)
{
	CoreInit();
	__int64 instance = CoreNewInstance();
	EXPECT_NE(instance, 0);
	EXPECT_EQ(CoreDeleteInstance(), 1);
	CoreUninit();
}

TEST(CoreApiTest, Signatures)
{
	EXPECT_EQ(CoreLoadSignatures(L"non_existent.cvd"), 0);
}

TEST(CoreApiTest, UtfConversions)
{
	char utf8[64] = {};
	wchar_t utf16[64] = {};

	EXPECT_GT(CoreUtf16_8((unsigned __int16*)L"Emirhan Ucan", (__int64)utf8, _countof(utf8)), 0);
	EXPECT_STREQ(utf8, "Emirhan Ucan");

	EXPECT_GT(CoreUtf8_16((unsigned char*)"TinyAntivirusEngine", (unsigned short*)utf16, _countof(utf16)), 0);
	EXPECT_STREQ(utf16, L"TinyAntivirusEngine");
}

TEST(CoreApiTest, SignatureDirectoryLoad)
{
	const std::wstring signatureDirectory = FindPathUpwards(L"TinyAntivirus\\decompile");
	if (signatureDirectory.empty())
		GTEST_SKIP() << "TinyAntivirus\\decompile directory is not available in this environment.";

	EXPECT_EQ(CoreLoadSignatures(signatureDirectory.c_str()), 1);

	DWORD *lastOpenError = static_cast<DWORD*>(CoreGetLastOpenError());
	ASSERT_NE(lastOpenError, nullptr);
	EXPECT_EQ(*lastOpenError, ERROR_SUCCESS);
	EXPECT_GT(CoreGetLoadedSignatureCount(), 10);
	EXPECT_TRUE(HasLoadedDatabaseFileName(L"emalware.cvd"));
	EXPECT_TRUE(HasLoadedDatabaseFileName(L"zip.xmd"));
}

TEST(CoreApiTest, SignatureFileLoadIvd)
{
	const std::wstring signatureFile = FindPathUpwards(L"TinyAntivirus\\decompile\\xlmrd.ivd");
	if (signatureFile.empty())
		GTEST_SKIP() << "TinyAntivirus\\decompile\\xlmrd.ivd is not available in this environment.";

	EXPECT_EQ(CoreLoadSignatures(signatureFile.c_str()), 1);

	DWORD *lastOpenError = static_cast<DWORD*>(CoreGetLastOpenError());
	ASSERT_NE(lastOpenError, nullptr);
	EXPECT_EQ(*lastOpenError, ERROR_SUCCESS);
}

TEST(CoreApiTest, SignatureFileLoadRvd)
{
	const std::wstring signatureFile = FindPathUpwards(L"TinyAntivirus\\decompile\\orice.rvd");
	if (signatureFile.empty())
		GTEST_SKIP() << "TinyAntivirus\\decompile\\orice.rvd is not available in this environment.";

	EXPECT_EQ(CoreLoadSignatures(signatureFile.c_str()), 1);

	DWORD *lastOpenError = static_cast<DWORD*>(CoreGetLastOpenError());
	ASSERT_NE(lastOpenError, nullptr);
	EXPECT_EQ(*lastOpenError, ERROR_SUCCESS);
}

TEST(CoreApiTest, LoadedSignatureMetadata)
{
	const std::wstring signatureDirectory = FindPathUpwards(L"TinyAntivirus\\decompile");
	if (signatureDirectory.empty())
		GTEST_SKIP() << "TinyAntivirus\\decompile directory is not available in this environment.";

	ASSERT_EQ(CoreLoadSignatures(signatureDirectory.c_str()), 1);

	const __int64 signatureCount = CoreGetLoadedSignatureCount();
	ASSERT_GE(signatureCount, 3);

	WCHAR firstName[260] = {};
	WCHAR firstSourcePath[MAX_PATH + 1] = {};

	EXPECT_EQ(CoreCopyLoadedSignatureName(0, firstName, _countof(firstName)), 1);
	EXPECT_EQ(CoreCopyLoadedSignatureSourcePath(0, firstSourcePath, _countof(firstSourcePath)), 1);
	EXPECT_NE(CoreGetLoadedSignatureType(0), SignatureDatabaseUnknown);
	EXPECT_NE(wcslen(firstName), 0u);
	EXPECT_STREQ(firstName, L"xlmrd");
	EXPECT_TRUE(PathFileExistsW(firstSourcePath));
	EXPECT_TRUE(HasLoadedDatabaseFileName(L"cab.xmd"));
}

TEST(CoreApiTest, SharedSignatureSource)
{
	const std::wstring signatureDirectory = FindPathUpwards(L"TinyAntivirus\\decompile");
	if (signatureDirectory.empty())
		GTEST_SKIP() << "TinyAntivirus\\decompile directory is not available in this environment.";

	ASSERT_EQ(CoreLoadSignatures(signatureDirectory.c_str()), 1);

	WCHAR sharedSourcePath[MAX_PATH + 1] = {};
	ASSERT_EQ(CoreCopySharedSignatureSourcePath(sharedSourcePath, _countof(sharedSourcePath)), 1);
	EXPECT_STREQ(sharedSourcePath, signatureDirectory.c_str());
	EXPECT_EQ(CoreReloadSharedSignatures(), 1);
	EXPECT_GT(CoreGetLoadedSignatureCount(), 10);
}
