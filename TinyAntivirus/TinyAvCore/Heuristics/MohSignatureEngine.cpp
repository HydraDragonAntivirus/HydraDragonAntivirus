#include "../../include/Heuristics/MohSignatureEngine.h"
#include "../../include/FileSystem/FsStream.h"
#include "../../include/Emulator/IEmulator.h"
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
}

class CMosSignatureEngine :
	public CRefCount,
	public IMosSignatureEngine
{
private:
	bool m_openRulePackEnabled;
	size_t m_loadedDatabaseCount;
	HMODULE m_mvmDll;
    typedef int (*MVM_SCAN_FILE_FUNC)(const char* fileName, char* outVerdict, size_t maxVerdictSize);
	MVM_SCAN_FILE_FUNC m_mvmScanFunc;

public:
	CMosSignatureEngine()
		: m_openRulePackEnabled(false),
		m_loadedDatabaseCount(0),
		m_mvmDll(NULL),
		m_mvmScanFunc(NULL)
	{
		m_mvmDll = LoadLibraryA("C:\\Users\\semae\\OneDrive\\Belgeler\\mvm.dll");
		if (m_mvmDll) {
            // Need the correct exported function name from mvm.dll to call. Assuming 'MvmScanFile' or similar for now.
			m_mvmScanFunc = (MVM_SCAN_FILE_FUNC)GetProcAddress(m_mvmDll, "MvmScanFile");
		}
	}

	virtual ~CMosSignatureEngine() {
		if (m_mvmDll) {
			FreeLibrary(m_mvmDll);
		}
	}

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


		if (!m_openRulePackEnabled || m_loadedDatabaseCount == 0)
			return S_FALSE;

		const std::vector<unsigned char> rawLower = ToLowerAscii(rawData);
		MOS_PE_PROFILE peProfile = {};
		ParsePeProfile(rawData, &peProfile);

		if (MatchSalityRule(peProfile, malwareName, maxName))
		{
			return S_OK;
		}
		
        if (m_mvmScanFunc) {
            // How do we get the file name from IVirtualFs? For now assume it's an IPeFile?
            // This is tricky.
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
