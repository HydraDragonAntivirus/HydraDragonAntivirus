#include <gtest/gtest.h>
#include <TinyAvCore.h>
#include <Heuristics/MohSignatureEngine.h>
#include <string>
#include <vector>

namespace
{
	HRESULT MatchBuffer(
		const std::vector<unsigned char>& buffer,
		const bool loadSignatures,
		const bool resetAfterLoad,
		std::wstring* verdict)
	{
		IMosSignatureEngine* engine = NULL;
		IMemoryFs* memoryFs = NULL;
		HRESULT hr = CreateMosSignatureEngine(&engine);
		if (FAILED(hr))
			return hr;

		if (loadSignatures)
		{
			static const unsigned char kDummySignatureBlob[] = "VirLock";
			hr = engine->LoadSignatures(kDummySignatureBlob, sizeof(kDummySignatureBlob) - 1);
			if (FAILED(hr))
			{
				engine->Release();
				return hr;
			}
		}

		if (resetAfterLoad)
		{
			hr = engine->Reset();
			if (FAILED(hr))
			{
				engine->Release();
				return hr;
			}
		}

		hr = CreateClassObject(CLSID_CMemoryFs, 0, __uuidof(IMemoryFs), (LPVOID*)&memoryFs);
		if (FAILED(hr))
		{
			engine->Release();
			return hr;
		}

		hr = memoryFs->Create(L"moh-engine-test.bin", IVirtualFs::fsRead | IVirtualFs::fsWrite | IVirtualFs::fsAttrNormal);
		if (SUCCEEDED(hr))
			hr = memoryFs->SetBuffer(buffer.data(), static_cast<ULONG>(buffer.size()));

		if (SUCCEEDED(hr) && verdict)
		{
			WCHAR malwareName[MAX_NAME] = {};
			hr = engine->Match(memoryFs, malwareName, _countof(malwareName));
			if (hr == S_OK)
				*verdict = malwareName;
		}

		memoryFs->Release();
		engine->Release();
		return hr;
	}
}

TEST(MohSignatureEngine, RequiresLoadedSignatureContextForOpenRules)
{
	const std::vector<unsigned char> buffer =
	{
		'C','O','M','S','P','E','C','\0',
		'/','c',' ','d','e','l',' ','\0',
		'\\','Z','o','m','b','i','e','.','e','x','e','\0',
		'R','e','l','e','a','s','e',' ','N','o','t','e','s','.','l','n','k','\0',
	};

	std::wstring verdict;
	EXPECT_EQ(S_FALSE, MatchBuffer(buffer, false, false, &verdict));
	EXPECT_TRUE(verdict.empty());
}

TEST(MohSignatureEngine, MatchesVirLockAnchorsAfterSignaturesAreLoaded)
{
	const std::vector<unsigned char> buffer =
	{
		'C','O','M','S','P','E','C','\0',
		'/','c',' ','d','e','l',' ','\0',
		'\\','Z','o','m','b','i','e','.','e','x','e','\0',
		'R','e','l','e','a','s','e',' ','N','o','t','e','s','.','l','n','k','\0',
	};

	std::wstring verdict;
	EXPECT_EQ(S_OK, MatchBuffer(buffer, true, false, &verdict));
	EXPECT_EQ(L"Win32.VirLock.Gen", verdict);
}

TEST(MohSignatureEngine, ResetClearsOpenRulePack)
{
	const std::vector<unsigned char> buffer =
	{
		'F','u','l','l',' ','D','e','l','p','h','i',' ','V','i','r','u','s','/','W','o','r','m',' ',
		'm','a','d','e',' ','B','y',' ','F','u','T','u','R','a','X','\0',
	};

	std::wstring verdict;
	EXPECT_EQ(S_FALSE, MatchBuffer(buffer, true, true, &verdict));
	EXPECT_TRUE(verdict.empty());
}
