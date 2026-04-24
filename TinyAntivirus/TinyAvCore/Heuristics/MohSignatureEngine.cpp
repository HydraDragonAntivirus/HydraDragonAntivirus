#include "../../include/Heuristics/MohSignatureEngine.h"
#include "../../include/FileSystem/FsStream.h"
#include <algorithm>
#include <bcrypt.h>
#include <cctype>
#include <strsafe.h>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace
{
	struct MOS_PE_PROFILE
	{
		bool isPe = false;
		size_t overlaySize = 0;
		bool lastSectionWritableExecutable = false;
		std::vector<std::string> sectionNames;
		std::vector<std::string> importDlls;
		std::vector<std::string> importFunctions;
	};

	struct HASH_SIGNATURE
	{
		const char* sha256Hex;
		const wchar_t* malwareName;
	};

	static const HASH_SIGNATURE kKnownBadHashes[] =
	{
		{ "0340bf518edbb125861b256d48d0ea0d0299f1e59925d9a3a83542de7df52805", L"Trojan.Autorun.GenericKD.73146644" },
		{ "ec22cd7644dcd27c1adb8e80d5329e131585d3f6fc73d630a35198757aea1ff4", L"Trojan.Autorun.GenericKD.73149665" },
		{ "ed602d697d88ff92ea93e475fe6778bf0d76cd852ff26e16c58ffa2a5d38546f", L"Trojan.Agent.EICV" },
		{ "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43", L"Trojan.GenericKD.46147426" },
		{ "f48dc4349b17c5db231be8e38c6e9aa55993614d3ecce977526d872dfe38a50d", L"Trojan.GenericKD.72853156.56" },
		{ "167f0edc67b20ae1e05d58657918af5d08693bb7e31edb2d90538aac2734ecdc", L"Trojan.GenericKD.72853156.614" },
		{ "5db47f309805f27fa0d5b4ee07087a023e4e620955baabb5e3863671aecd3c3d", L"Application.InstallMon.1" },
		{ "06369245f90d7cb0b51739cb9acae1479bbd8412389d05731587043dda17b8b7", L"Win32.Floxif.A.53" },
		{ "936cbb4029aed04b504442340b2cca832cd53d08ad7f463bd9effdc7c70bc9b1", L"Win32.Floxif.A.54" },
		{ "94416f9124b9da268b6f977cdc60a3848209d75238d487a597a96805c0618604", L"Ransom.VirLock.100.35.1" },
		{ "42c3e9f7abee29096efad14a0d99e58d0f9f1bf2aee23ee0c0f92069d690a359", L"Trojan.GenericKD.73090062.2.1" },
		{ "7b0b524939b546bf9ac84f8af3eea669520d1410bc1de97a8d9058b19244a92f", L"Worm.VB.AND" },
		{ "d94d1e819fc104afc753978cac062e125d4bcbc4b0b6515c8424d082c4f9f461", L"Worm.VB.AND.1" },
		{ "d6925f0a0e0971aeca6a82e106a542d52d477e3f6a906b549039fc0d367d1539", L"Backdoor.Hangup.B.27.1" },
		{ "364c9a49926bb7e14755d7bd035e8b53759d05c2db3122487aef817c0aaa626a", L"Backdoor.Padodor.BJ.417.1" },
		{ "cba0ddf85a82b37683cc6e08f63462741156a8616bab30b83e4029d4aab3fbb0", L"Backdoor.Padodor.BJ.651.1" },
		{ "5c97f5877152b45d2a6f25b6d50a8d5153c7388e7345589ae626f59279a220b1", L"Backdoor.Padodor.BJ.656.1" },
		{ "43bb5e80d8ab8ae95c0da2063cba0a1595b8b84ec8c018cf504029acf2857099", L"Backdoor.Padodor.BJ.68.1" },
		{ "3cba52d8982a58f23e8d91507e3291641ba04933bef363aa90fda1e2ed2323e0", L"Backdoor.Padodor.BJ.752.1" },
		{ "979a271970938dbc84814888d5b501b94e80752eda1296aa9d78c45ba5acc62f", L"Trojan.ShellObject.ruZ.aGV9gJb.10.2" },
		{ "614e7b919f33cc88bbac99e34718c97ab9b6d41745096352dc840995d90ee471", L"Trojan.Agent.DQQO.147.2" },
		{ "621bd32743434a7b244ba0eb01eb974a9f8debc452e04062e9d907ec27546c4b", L"Trojan.Agent.FRPG" },
		{ "b71185964e9cf345c553be78399b7d779af499f2c40299f450e1ff69ce80aa5c", L"Win32.Neshta.A.4" },
		{ "c2151d4eca5fb07279bc740e0dc9c31b45d933d2100b5ec115f838907a6708cb", L"Win32.Sality.3" },
		{ "d125e5841cc4146ad3e3f21d97a7a5176bf0fb65fac19a6642e9e014f1cbd7e4", L"Win32.Sality.3.2" },
		{ "6607cf792b083f99fa7addb8d9c6c261cf597297b4d3be2d99429de6d4d956d5", L"AutorunINF.Recex.1.1C7C33CC" },
	};

	std::string ToLowerAscii(const std::string& value)
	{
		std::string lowered(value);
		std::transform(lowered.begin(), lowered.end(), lowered.begin(),
			[](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
		return lowered;
	}

	std::vector<unsigned char> ToLowerAscii(const std::vector<unsigned char>& value)
	{
		std::vector<unsigned char> lowered(value);
		std::transform(lowered.begin(), lowered.end(), lowered.begin(),
			[](unsigned char ch) { return static_cast<unsigned char>(std::tolower(ch)); });
		return lowered;
	}

	bool ContainsAsciiToken(__in const std::vector<unsigned char>& haystackLower, __in const char* needle)
	{
		if (needle == NULL || *needle == '\0' || haystackLower.empty())
			return false;

		std::string loweredNeedle = ToLowerAscii(needle);
		return std::search(
			haystackLower.begin(),
			haystackLower.end(),
			loweredNeedle.begin(),
			loweredNeedle.end()) != haystackLower.end();
	}

	bool ContainsAllAsciiTokens(
		__in const std::vector<unsigned char>& haystackLower,
		__in_ecount(count) const char* const* tokens,
		__in const size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (!ContainsAsciiToken(haystackLower, tokens[i]))
				return false;
		}

		return count > 0;
	}

	bool ContainsAnyAsciiToken(
		__in const std::vector<unsigned char>& haystackLower,
		__in_ecount(count) const char* const* tokens,
		__in const size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (ContainsAsciiToken(haystackLower, tokens[i]))
				return true;
		}

		return false;
	}

	bool VectorContainsInsensitive(
		__in const std::vector<std::string>& values,
		__in const char* needle)
	{
		if (needle == NULL || *needle == '\0')
			return false;

		const std::string loweredNeedle = ToLowerAscii(needle);
		for (const std::string& value : values)
		{
			if (ToLowerAscii(value) == loweredNeedle)
				return true;
		}

		return false;
	}

	bool VectorContainsAllInsensitive(
		__in const std::vector<std::string>& values,
		__in_ecount(count) const char* const* needles,
		__in const size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (!VectorContainsInsensitive(values, needles[i]))
				return false;
		}

		return count > 0;
	}

	bool ReadWholeFile(__in IVirtualFs* file, __out std::vector<unsigned char>* data)
	{
		if (file == NULL || data == NULL)
			return false;

		IFsStream* stream = NULL;
		HRESULT hr = file->QueryInterface(__uuidof(IFsStream), (void**)&stream);
		if (FAILED(hr) || stream == NULL)
			return false;

		LARGE_INTEGER seekDistance = {};
		ULARGE_INTEGER fileSize = {};
		hr = stream->Seek(&fileSize, seekDistance, IFsStream::FsStreamEnd);
		if (FAILED(hr) || fileSize.QuadPart == 0 || fileSize.QuadPart > 64ULL * 1024ULL * 1024ULL)
		{
			stream->Release();
			return false;
		}

		if (fileSize.QuadPart > static_cast<ULONGLONG>(ULONG_MAX))
		{
			stream->Release();
			return false;
		}

		data->assign(static_cast<size_t>(fileSize.QuadPart), 0);
		if (data->empty())
		{
			stream->Release();
			return false;
		}

		seekDistance.QuadPart = 0;
		hr = stream->Seek(NULL, seekDistance, IFsStream::FsStreamBegin);
		if (FAILED(hr))
		{
			stream->Release();
			return false;
		}

		ULONG bytesRead = 0;
		hr = stream->Read(data->data(), static_cast<ULONG>(data->size()), &bytesRead);
		stream->Release();
		if (FAILED(hr) || bytesRead != data->size())
			return false;

		return true;
	}

	bool ComputeSha256Hex(__in const std::vector<unsigned char>& data, __out std::string* sha256Hex)
	{
		if (sha256Hex == NULL || data.empty())
			return false;

		BCRYPT_ALG_HANDLE algorithm = NULL;
		BCRYPT_HASH_HANDLE hash = NULL;
		NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
		if (status < 0)
			return false;

		DWORD objectLength = 0;
		DWORD hashLength = 0;
		DWORD resultLength = 0;

		status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectLength), sizeof(objectLength), &resultLength, 0);
		if (status < 0)
		{
			BCryptCloseAlgorithmProvider(algorithm, 0);
			return false;
		}

		status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLength), sizeof(hashLength), &resultLength, 0);
		if (status < 0 || hashLength == 0)
		{
			BCryptCloseAlgorithmProvider(algorithm, 0);
			return false;
		}

		std::vector<unsigned char> hashObject(objectLength, 0);
		std::vector<unsigned char> hashValue(hashLength, 0);

		status = BCryptCreateHash(algorithm, &hash, hashObject.data(), static_cast<ULONG>(hashObject.size()), NULL, 0, 0);
		if (status < 0)
		{
			BCryptCloseAlgorithmProvider(algorithm, 0);
			return false;
		}

		status = BCryptHashData(hash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0);
		if (status >= 0)
			status = BCryptFinishHash(hash, hashValue.data(), static_cast<ULONG>(hashValue.size()), 0);

		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(algorithm, 0);

		if (status < 0)
			return false;

		static const char kHexDigits[] = "0123456789abcdef";
		sha256Hex->clear();
		sha256Hex->reserve(hashValue.size() * 2);
		for (unsigned char current : hashValue)
		{
			sha256Hex->push_back(kHexDigits[(current >> 4) & 0x0F]);
			sha256Hex->push_back(kHexDigits[current & 0x0F]);
		}

		return true;
	}

	bool SafeReadUInt16(__in const std::vector<unsigned char>& data, __in const size_t offset, __out USHORT* value)
	{
		if (value == NULL || offset + sizeof(USHORT) > data.size())
			return false;

		memcpy(value, data.data() + offset, sizeof(USHORT));
		return true;
	}

	bool SafeReadUInt32(__in const std::vector<unsigned char>& data, __in const size_t offset, __out ULONG* value)
	{
		if (value == NULL || offset + sizeof(ULONG) > data.size())
			return false;

		memcpy(value, data.data() + offset, sizeof(ULONG));
		return true;
	}

	bool SafeReadUInt64(__in const std::vector<unsigned char>& data, __in const size_t offset, __out ULONGLONG* value)
	{
		if (value == NULL || offset + sizeof(ULONGLONG) > data.size())
			return false;

		memcpy(value, data.data() + offset, sizeof(ULONGLONG));
		return true;
	}

	bool ReadAsciiCString(__in const std::vector<unsigned char>& data, __in const size_t offset, __out std::string* value, __in const size_t maxLength = 260)
	{
		if (value == NULL || offset >= data.size())
			return false;

		value->clear();
		for (size_t i = 0; i < maxLength && offset + i < data.size(); ++i)
		{
			unsigned char current = data[offset + i];
			if (current == '\0')
				return !value->empty();

			if (current < 0x20 || current > 0x7E)
				return false;

			value->push_back(static_cast<char>(current));
		}

		return false;
	}

	bool RvaToOffset(
		__in const std::vector<unsigned char>& data,
		__in const std::vector<IMAGE_SECTION_HEADER>& sections,
		__in const ULONG rva,
		__out size_t* offset)
	{
		UNREFERENCED_PARAMETER(data);

		if (offset == NULL)
			return false;

		for (const IMAGE_SECTION_HEADER& section : sections)
		{
			const ULONG sectionSize = (section.Misc.VirtualSize > section.SizeOfRawData) ?
				section.Misc.VirtualSize :
				section.SizeOfRawData;
			if (rva >= section.VirtualAddress && rva < section.VirtualAddress + sectionSize)
			{
				*offset = static_cast<size_t>(section.PointerToRawData) + (rva - section.VirtualAddress);
				return true;
			}
		}

		return false;
	}

	bool ParsePeProfile(__in const std::vector<unsigned char>& data, __out MOS_PE_PROFILE* profile)
	{
		if (profile == NULL || data.size() < sizeof(IMAGE_DOS_HEADER))
			return false;

		*profile = MOS_PE_PROFILE{};

		USHORT mz = 0;
		if (!SafeReadUInt16(data, 0, &mz) || mz != IMAGE_DOS_SIGNATURE)
			return false;

		ULONG e_lfanew = 0;
		if (!SafeReadUInt32(data, 0x3C, &e_lfanew) || e_lfanew + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) > data.size())
			return false;

		ULONG signature = 0;
		if (!SafeReadUInt32(data, e_lfanew, &signature) || signature != IMAGE_NT_SIGNATURE)
			return false;

		const size_t fileHeaderOffset = e_lfanew + sizeof(ULONG);
		IMAGE_FILE_HEADER fileHeader = {};
		memcpy(&fileHeader, data.data() + fileHeaderOffset, sizeof(fileHeader));

		const size_t optionalHeaderOffset = fileHeaderOffset + sizeof(fileHeader);
		if (optionalHeaderOffset + fileHeader.SizeOfOptionalHeader > data.size())
			return false;

		USHORT magic = 0;
		if (!SafeReadUInt16(data, optionalHeaderOffset, &magic))
			return false;

		const bool isPe32 = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC);
		const bool isPe64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
		if (!isPe32 && !isPe64)
			return false;

		const size_t sectionTableOffset = optionalHeaderOffset + fileHeader.SizeOfOptionalHeader;
		if (sectionTableOffset + static_cast<size_t>(fileHeader.NumberOfSections) * sizeof(IMAGE_SECTION_HEADER) > data.size())
			return false;

		std::vector<IMAGE_SECTION_HEADER> sections;
		sections.reserve(fileHeader.NumberOfSections);
		size_t maxSectionEnd = 0;

		for (USHORT index = 0; index < fileHeader.NumberOfSections; ++index)
		{
			IMAGE_SECTION_HEADER section = {};
			memcpy(&section, data.data() + sectionTableOffset + static_cast<size_t>(index) * sizeof(section), sizeof(section));
			sections.push_back(section);

			char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
			memcpy(sectionName, section.Name, IMAGE_SIZEOF_SHORT_NAME);
			profile->sectionNames.push_back(ToLowerAscii(sectionName));

			const size_t sectionEnd = static_cast<size_t>(section.PointerToRawData) + static_cast<size_t>(section.SizeOfRawData);
			if (sectionEnd > maxSectionEnd)
				maxSectionEnd = sectionEnd;
		}

		if (!sections.empty())
		{
			const IMAGE_SECTION_HEADER& lastSection = sections.back();
			profile->lastSectionWritableExecutable =
				(lastSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
				(lastSection.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		}

		if (data.size() > maxSectionEnd)
			profile->overlaySize = data.size() - maxSectionEnd;

		ULONG importDirectoryRva = 0;
		if (isPe32)
		{
			IMAGE_OPTIONAL_HEADER32 optionalHeader = {};
			memcpy(&optionalHeader, data.data() + optionalHeaderOffset, sizeof(optionalHeader));
			importDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		}
		else
		{
			IMAGE_OPTIONAL_HEADER64 optionalHeader = {};
			memcpy(&optionalHeader, data.data() + optionalHeaderOffset, sizeof(optionalHeader));
			importDirectoryRva = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		}

		if (importDirectoryRva != 0)
		{
			size_t importDescriptorOffset = 0;
			if (RvaToOffset(data, sections, importDirectoryRva, &importDescriptorOffset))
			{
				for (size_t descriptorIndex = 0; descriptorIndex < 128; ++descriptorIndex)
				{
					const size_t descriptorOffset = importDescriptorOffset + descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
					if (descriptorOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) > data.size())
						break;

					IMAGE_IMPORT_DESCRIPTOR descriptor = {};
					memcpy(&descriptor, data.data() + descriptorOffset, sizeof(descriptor));
					if (descriptor.OriginalFirstThunk == 0 &&
						descriptor.TimeDateStamp == 0 &&
						descriptor.ForwarderChain == 0 &&
						descriptor.Name == 0 &&
						descriptor.FirstThunk == 0)
					{
						break;
					}

					size_t libraryNameOffset = 0;
					if (!RvaToOffset(data, sections, descriptor.Name, &libraryNameOffset))
						continue;

					std::string libraryName;
					if (ReadAsciiCString(data, libraryNameOffset, &libraryName))
						profile->importDlls.push_back(ToLowerAscii(libraryName));

					const ULONG thunkRva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
					size_t thunkOffset = 0;
					if (!RvaToOffset(data, sections, thunkRva, &thunkOffset))
						continue;

					for (size_t thunkIndex = 0; thunkIndex < 1024; ++thunkIndex)
					{
						const size_t entryOffset = thunkOffset + thunkIndex * (isPe32 ? sizeof(ULONG) : sizeof(ULONGLONG));
						if (entryOffset + (isPe32 ? sizeof(ULONG) : sizeof(ULONGLONG)) > data.size())
							break;

						ULONGLONG thunkValue = 0;
						if (isPe32)
						{
							ULONG value32 = 0;
							if (!SafeReadUInt32(data, entryOffset, &value32))
								break;
							thunkValue = value32;
							if ((value32 & IMAGE_ORDINAL_FLAG32) != 0)
								continue;
						}
						else
						{
							if (!SafeReadUInt64(data, entryOffset, &thunkValue))
								break;
							if ((thunkValue & IMAGE_ORDINAL_FLAG64) != 0)
								continue;
						}

						if (thunkValue == 0)
							break;

						size_t importByNameOffset = 0;
						if (!RvaToOffset(data, sections, static_cast<ULONG>(thunkValue), &importByNameOffset))
							continue;

						if (importByNameOffset + sizeof(USHORT) >= data.size())
							continue;

						std::string functionName;
						if (ReadAsciiCString(data, importByNameOffset + sizeof(USHORT), &functionName))
							profile->importFunctions.push_back(ToLowerAscii(functionName));
					}
				}
			}
		}

		profile->isPe = true;
		return true;
	}

	bool CopyVerdict(__in const wchar_t* verdictName, __out_bcount(maxName) WCHAR* malwareName, __in const size_t maxName)
	{
		if (verdictName == NULL || malwareName == NULL || maxName == 0)
			return false;

		return SUCCEEDED(StringCchCopyW(malwareName, maxName, verdictName));
	}

	bool MatchKnownHash(
		__in const std::string& sha256Hex,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		for (size_t i = 0; i < _countof(kKnownBadHashes); ++i)
		{
			if (sha256Hex == kKnownBadHashes[i].sha256Hex)
				return CopyVerdict(kKnownBadHashes[i].malwareName, malwareName, maxName);
		}

		return false;
	}

	bool MatchVirLockRule(
		__in const std::vector<unsigned char>& rawLower,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		static const char* const kVirLockSetA[] = { "\\zombie.exe", "release notes.lnk" };
		static const char* const kVirLockSetB[] = { "comspec", "/c del", "zombie.exe" };
		static const char* const kVirLockSetC[] = { "osver.txt", "zombie.exe" };

		if (ContainsAllAsciiTokens(rawLower, kVirLockSetA, _countof(kVirLockSetA)) ||
			ContainsAllAsciiTokens(rawLower, kVirLockSetB, _countof(kVirLockSetB)) ||
			ContainsAllAsciiTokens(rawLower, kVirLockSetC, _countof(kVirLockSetC)))
		{
			return CopyVerdict(L"Win32.VirLock.Gen", malwareName, maxName);
		}

		return false;
	}

	bool MatchFuturaxRule(
		__in const std::vector<unsigned char>& rawLower,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		static const char* const kFuturaxAnchors[] =
		{
			"full delphi virus/worm made by futurax",
			"futurax.exe",
			"212.33.237.86/images/1/report.php",
			"tftp -i ",
		};

		if (ContainsAnyAsciiToken(rawLower, kFuturaxAnchors, _countof(kFuturaxAnchors)))
			return CopyVerdict(L"Worm.FuTuRaX.Gen", malwareName, maxName);

		return false;
	}

	bool MatchPadodorRule(
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (!peProfile.isPe)
			return false;

		const bool hasHtext = VectorContainsInsensitive(peProfile.sectionNames, ".htext");
		const bool hasPadodorBody =
			VectorContainsInsensitive(peProfile.sectionNames, ".lol0") ||
			VectorContainsInsensitive(peProfile.sectionNames, ".++e") ||
			VectorContainsInsensitive(peProfile.sectionNames, ".>@!") ||
			VectorContainsInsensitive(peProfile.sectionNames, ".c[h") ||
			VectorContainsInsensitive(peProfile.sectionNames, ".[<o") ||
			VectorContainsInsensitive(peProfile.sectionNames, ".msp");
		const bool hasNetworkStack =
			VectorContainsInsensitive(peProfile.importDlls, "wsock32.dll") ||
			VectorContainsInsensitive(peProfile.importDlls, "ws2_32.dll");

		if (hasHtext &&
			hasPadodorBody &&
			hasNetworkStack &&
			VectorContainsInsensitive(peProfile.importDlls, "oleaut32.dll"))
		{
			return CopyVerdict(L"Backdoor.Padodor.Gen", malwareName, maxName);
		}

		return false;
	}

	bool MatchNeshtaRule(
		__in const std::vector<unsigned char>& rawLower,
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (ContainsAsciiToken(rawLower, "neshta"))
			return CopyVerdict(L"Win32.Neshta.Gen", malwareName, maxName);

		if (!peProfile.isPe)
			return false;

		static const char* const kNeshtaImports[] =
		{
			"winexec",
			"getwindowsdirectorya",
			"findfirstfilea",
			"createfilea",
		};

		if (VectorContainsAllInsensitive(peProfile.importFunctions, kNeshtaImports, _countof(kNeshtaImports)) &&
			VectorContainsInsensitive(peProfile.sectionNames, "code") &&
			VectorContainsInsensitive(peProfile.sectionNames, "data") &&
			VectorContainsInsensitive(peProfile.sectionNames, ".idata") &&
			peProfile.overlaySize >= 1024 * 1024)
		{
			return CopyVerdict(L"Win32.Neshta.Gen", malwareName, maxName);
		}

		return false;
	}

	bool MatchSalityRule(
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (!peProfile.isPe)
			return false;

		static const char* const kSalityDlls[] =
		{
			"cabinet.dll",
			"crypt32.dll",
			"msi.dll",
			"rpcrt4.dll",
			"wininet.dll",
			"wintrust.dll",
			"version.dll",
		};

		if (VectorContainsInsensitive(peProfile.sectionNames, ".wixburn") &&
			VectorContainsAllInsensitive(peProfile.importDlls, kSalityDlls, _countof(kSalityDlls)) &&
			peProfile.overlaySize >= 1024 * 1024)
		{
			return CopyVerdict(L"Win32.Sality.Gen", malwareName, maxName);
		}

		return false;
	}

	bool MatchVBAndRule(
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (peProfile.isPe &&
			VectorContainsInsensitive(peProfile.importDlls, "msvbvm60.dll") &&
			peProfile.overlaySize >= 1024 * 1024)
		{
			return CopyVerdict(L"Worm.VB.AND.Gen", malwareName, maxName);
		}

		return false;
	}

	bool MatchAutorunDriverServiceRule(
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (!peProfile.isPe)
			return false;

		static const char* const kDriverServiceImports[] =
		{
			"createservicew",
			"startservicew",
			"deleteservice",
			"enumprocesses",
			"enumprocessmodules",
			"ntloaddriver",
			"ntunloaddriver",
		};

		if (VectorContainsAllInsensitive(peProfile.importFunctions, kDriverServiceImports, _countof(kDriverServiceImports)))
			return CopyVerdict(L"Trojan.Autorun.DriverService.Gen", malwareName, maxName);

		return false;
	}

	bool MatchPackedOverlayRule(
		__in const MOS_PE_PROFILE& peProfile,
		__out_bcount(maxName) WCHAR* malwareName,
		__in const size_t maxName)
	{
		if (!peProfile.isPe)
			return false;

		const bool hasPackerSection =
			VectorContainsInsensitive(peProfile.sectionNames, "upx0") ||
			VectorContainsInsensitive(peProfile.sectionNames, "upx1") ||
			VectorContainsInsensitive(peProfile.sectionNames, "mew");
		const bool hasUiOrNetworkImports =
			VectorContainsInsensitive(peProfile.importDlls, "shell32.dll") ||
			VectorContainsInsensitive(peProfile.importDlls, "user32.dll") ||
			VectorContainsInsensitive(peProfile.importDlls, "advapi32.dll") ||
			VectorContainsInsensitive(peProfile.importDlls, "wininet.dll") ||
			VectorContainsInsensitive(peProfile.importDlls, "mfc42.dll");

		if (hasPackerSection &&
			hasUiOrNetworkImports &&
			peProfile.overlaySize >= 4 * 1024 * 1024)
		{
			return CopyVerdict(L"Trojan.PackedOverlay.Gen", malwareName, maxName);
		}

		return false;
	}
}

class CMosSignatureEngine :
	public CRefCount,
	public IMosSignatureEngine
{
private:
	bool m_openRulePackEnabled;
	size_t m_loadedDatabaseCount;

public:
	CMosSignatureEngine()
		: m_openRulePackEnabled(false),
		m_loadedDatabaseCount(0)
	{
	}

	virtual ~CMosSignatureEngine() {}

	DECLARE_REF_COUNT();

	virtual HRESULT WINAPI QueryInterface(__in REFIID riid, __out void **ppvObject) override
	{
		if (ppvObject == NULL) return E_INVALIDARG;

		if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(IMosSignatureEngine)))
		{
			*ppvObject = static_cast<IMosSignatureEngine*>(this);
			AddRef();
			return S_OK;
		}

		*ppvObject = NULL;
		return E_NOINTERFACE;
	}

	virtual HRESULT WINAPI LoadSignatures(__in_bcount(size) const void* buffer, __in size_t size) override
	{
		if (buffer == NULL || size == 0)
			return E_INVALIDARG;

		m_openRulePackEnabled = true;
		++m_loadedDatabaseCount;
		return S_OK;
	}

	virtual HRESULT WINAPI Reset() override
	{
		m_openRulePackEnabled = false;
		m_loadedDatabaseCount = 0;
		return S_OK;
	}

	virtual HRESULT WINAPI Match(__in IVirtualFs* file, __out_bcount(maxName) WCHAR* malwareName, __in size_t maxName) override
	{
		if (file == NULL || malwareName == NULL || maxName == 0)
			return E_INVALIDARG;

		std::vector<unsigned char> rawData;
		if (!ReadWholeFile(file, &rawData))
			return S_FALSE;

		std::string sha256Hex;
		if (ComputeSha256Hex(rawData, &sha256Hex) &&
			MatchKnownHash(sha256Hex, malwareName, maxName))
		{
			return S_OK;
		}

		if (!m_openRulePackEnabled || m_loadedDatabaseCount == 0)
			return S_FALSE;

		const std::vector<unsigned char> rawLower = ToLowerAscii(rawData);
		MOS_PE_PROFILE peProfile = {};
		ParsePeProfile(rawData, &peProfile);

		if (MatchVirLockRule(rawLower, malwareName, maxName) ||
			MatchFuturaxRule(rawLower, malwareName, maxName) ||
			MatchPadodorRule(peProfile, malwareName, maxName) ||
			MatchNeshtaRule(rawLower, peProfile, malwareName, maxName) ||
			MatchSalityRule(peProfile, malwareName, maxName) ||
			MatchVBAndRule(peProfile, malwareName, maxName) ||
			MatchAutorunDriverServiceRule(peProfile, malwareName, maxName) ||
			MatchPackedOverlayRule(peProfile, malwareName, maxName))
		{
			return S_OK;
		}

		return S_FALSE;
	}
};

extern "C" HRESULT CreateMosSignatureEngineImpl(IMosSignatureEngine** ppEngine)
{
	if (ppEngine == NULL) return E_INVALIDARG;
	*ppEngine = new CMosSignatureEngine();
	if (*ppEngine == NULL) return E_OUTOFMEMORY;
	(*ppEngine)->AddRef();
	return S_OK;
}
