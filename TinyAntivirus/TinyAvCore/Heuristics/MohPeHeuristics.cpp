#include "../../include/Heuristics/MohPeHeuristics.h"
#include "../../include/FileSystem/FsStream.h"
#include <string.h>

namespace
{
	struct IMPORT_HEURISTIC_STATE
	{
		ULONG dllCount = 0;
		ULONG functionCount = 0;
		ULONG benignUiCount = 0;
		ULONG executionCount = 0;
		ULONG stagingCount = 0;
		bool hasLoadLibraryFamily = false;
		bool hasUrlDownloadToFile = false;
		bool hasShellExecute = false;
		bool hasCreateProcess = false;
		bool hasCreateRemoteThread = false;
		bool hasSingleUrlmonDownloadImport = false;
		bool hasSingleShellExecuteImport = false;
	};

	static const char * const kBenignUiImports[] =
	{
		"MessageBox",
		"CreatePopupMenu",
		"AppendMenu",
		"InitCommonControlsEx",
	};

	static const char * const kExecutionImports[] =
	{
		"GetModuleHandle",
		"Sleep",
		"FindFirstFile",
		"FindNextFile",
		"MoveFile",
		"WinExec",
		"DeleteFile",
		"WriteFile",
		"CreateFile",
		"CreateProcess",
		"ShellExecute",
	};

	static const char * const kStagingImports[] =
	{
		"GetTempPath",
		"GetTempFileName",
		"GetWindowsDirectory",
		"GetSystemDirectory",
		"CreateRemoteThread",
		"SetWindowsHookEx",
	};

	bool IsZeroImportDescriptor(__in const IMAGE_IMPORT_DESCRIPTOR& descriptor)
	{
		return descriptor.OriginalFirstThunk == 0 &&
			descriptor.TimeDateStamp == 0 &&
			descriptor.ForwarderChain == 0 &&
			descriptor.Name == 0 &&
			descriptor.FirstThunk == 0;
	}

	static const char * const kCommonSectionNames[] =
	{
		".text",
		".data",
		".rdata",
		".idata",
		".edata",
		".pdata",
		".xdata",
		".rsrc",
		".reloc",
		".tls",
		".bss",
		".crt",
		".didat",
		".gfids",
		".sxdata",
		".00cfg",
		"PAGE",
		"PAGED",
		"INIT",
		"POOLCODE",
	};

	void MarkFlag(__inout MOS_PE_SIGNATURE_RESULT *result, __in const ULONG flag, __in const ULONG score)
	{
		if (result == NULL) return;
		if (!TEST_FLAG(result->flags, flag))
		{
			result->flags |= flag;
			result->score += score;
		}
	}

	bool EqualsInsensitive(__in const StringA& lhs, __in const char *rhs)
	{
		return rhs != NULL && _stricmp(lhs.c_str(), rhs) == 0;
	}

	bool MatchesStemInsensitive(__in const StringA& value, __in const char *stem)
	{
		if (stem == NULL) return false;
		size_t stemLen = strlen(stem);
		return value.length() >= stemLen && _strnicmp(value.c_str(), stem, stemLen) == 0;
	}

	bool MatchesAnyStem(__in const StringA& value, __in_ecount(count) const char * const *patterns, __in const size_t count)
	{
		for (size_t i = 0; i < count; ++i)
		{
			if (MatchesStemInsensitive(value, patterns[i]))
				return true;
		}
		return false;
	}

	StringA GetSectionName(__in const IMAGE_SECTION_HEADER& sectionHeader)
	{
		char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
		memcpy(name, sectionHeader.Name, IMAGE_SIZEOF_SHORT_NAME);
		return StringA(name);
	}

	bool IsCommonSectionName(__in const IMAGE_SECTION_HEADER& sectionHeader)
	{
		StringA name = GetSectionName(sectionHeader);
		return MatchesAnyStem(name, kCommonSectionNames, _countof(kCommonSectionNames));
	}

	UINT GetSectionEndRva(__in const IMAGE_SECTION_HEADER& sectionHeader)
	{
		DWORD sectionSize = (sectionHeader.Misc.VirtualSize > sectionHeader.SizeOfRawData) ?
			sectionHeader.Misc.VirtualSize :
			sectionHeader.SizeOfRawData;
		return sectionHeader.VirtualAddress + sectionSize;
	}

	bool IsRvaInsideSection(__in const UINT rva, __in const IMAGE_SECTION_HEADER& sectionHeader)
	{
		return rva >= sectionHeader.VirtualAddress && rva < GetSectionEndRva(sectionHeader);
	}

	bool HasWritableExecutableCode(__in const IMAGE_SECTION_HEADER& sectionHeader)
	{
		return TEST_FLAG(sectionHeader.Characteristics, IMAGE_SCN_CNT_CODE) &&
			TEST_FLAG(sectionHeader.Characteristics, IMAGE_SCN_MEM_EXECUTE) &&
			TEST_FLAG(sectionHeader.Characteristics, IMAGE_SCN_MEM_WRITE);
	}

	HRESULT ReadExactFromRva(
		__in IPeFile *peFile,
		__in IFsStream *stream,
		__in const UINT rva,
		__out_bcount(bufferSize) void *buffer,
		__in const ULONG bufferSize)
	{
		if (peFile == NULL || stream == NULL || buffer == NULL) return E_INVALIDARG;

		UINT fileOffset = 0;
		HRESULT hr = peFile->RvaToFileOffset(rva, &fileOffset);
		if (FAILED(hr)) return hr;

		LARGE_INTEGER offset = {};
		offset.QuadPart = fileOffset;
		ULONG bytesRead = 0;
		hr = stream->ReadAt(offset, IFsStream::FsStreamBegin, buffer, bufferSize, &bytesRead);
		if (FAILED(hr)) return hr;
		return (bytesRead == bufferSize) ? S_OK : HRESULT_FROM_WIN32(ERROR_HANDLE_EOF);
	}

	HRESULT ReadAnsiStringFromRva(
		__in IPeFile *peFile,
		__in IFsStream *stream,
		__in const UINT rva,
		__out StringA *value,
		__in const size_t maxLength = 260)
	{
		if (peFile == NULL || stream == NULL || value == NULL) return E_INVALIDARG;
		value->clear();

		for (size_t i = 0; i < maxLength; ++i)
		{
			unsigned char ch = 0;
			HRESULT hr = ReadExactFromRva(peFile, stream, rva + static_cast<UINT>(i), &ch, sizeof(ch));
			if (FAILED(hr)) return hr;
			if (ch == '\0') return S_OK;
			value->push_back(static_cast<char>(ch));
		}

		return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
	}

	void AnalyzeImportedFunction(
		__in const StringA& functionName,
		__inout IMPORT_HEURISTIC_STATE *state)
	{
		if (state == NULL) return;

		if (MatchesAnyStem(functionName, kBenignUiImports, _countof(kBenignUiImports)))
			++state->benignUiCount;

		if (MatchesAnyStem(functionName, kExecutionImports, _countof(kExecutionImports)))
			++state->executionCount;

		if (MatchesAnyStem(functionName, kStagingImports, _countof(kStagingImports)))
			++state->stagingCount;

		if (MatchesStemInsensitive(functionName, "LoadLibrary"))
			state->hasLoadLibraryFamily = true;

		if (MatchesStemInsensitive(functionName, "URLDownloadToFile"))
			state->hasUrlDownloadToFile = true;

		if (MatchesStemInsensitive(functionName, "ShellExecute"))
			state->hasShellExecute = true;

		if (MatchesStemInsensitive(functionName, "CreateProcess"))
			state->hasCreateProcess = true;

		if (MatchesStemInsensitive(functionName, "CreateRemoteThread"))
			state->hasCreateRemoteThread = true;
	}

	void AnalyzeImportHeuristics(
		__in IPeFile *peFile,
		__in IFsStream *stream,
		__in const IMAGE_NT_HEADERS32& peHeader,
		__inout MOS_PE_SIGNATURE_RESULT *result)
	{
		if (peFile == NULL || stream == NULL || result == NULL) return;

		IMAGE_DATA_DIRECTORY importDirectory = peHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
			return;

		IMPORT_HEURISTIC_STATE state = {};
		for (UINT descriptorIndex = 0; descriptorIndex < 128; ++descriptorIndex)
		{
			IMAGE_IMPORT_DESCRIPTOR descriptor = {};
			UINT descriptorRva = importDirectory.VirtualAddress + descriptorIndex * sizeof(IMAGE_IMPORT_DESCRIPTOR);
			if (FAILED(ReadExactFromRva(peFile, stream, descriptorRva, &descriptor, sizeof(descriptor))))
				break;

			if (IsZeroImportDescriptor(descriptor))
				break;

			StringA libraryName;
			if (FAILED(ReadAnsiStringFromRva(peFile, stream, descriptor.Name, &libraryName)))
				continue;

			++state.dllCount;

			UINT thunkRva = descriptor.OriginalFirstThunk ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
			ULONG importCountForDll = 0;
			bool hasUrlDownloadImport = false;
			bool hasShellExecuteImport = false;

			for (UINT thunkIndex = 0; thunkIndex < 1024; ++thunkIndex)
			{
				DWORD thunkData = 0;
				if (FAILED(ReadExactFromRva(peFile, stream, thunkRva + thunkIndex * sizeof(DWORD), &thunkData, sizeof(thunkData))))
					break;

				if (thunkData == 0)
					break;

				++state.functionCount;
				++importCountForDll;

				if (IMAGE_SNAP_BY_ORDINAL32(thunkData))
					continue;

				StringA functionName;
				if (FAILED(ReadAnsiStringFromRva(peFile, stream, thunkData + sizeof(WORD), &functionName)))
					continue;

				AnalyzeImportedFunction(functionName, &state);
				hasUrlDownloadImport = hasUrlDownloadImport || MatchesStemInsensitive(functionName, "URLDownloadToFile");
				hasShellExecuteImport = hasShellExecuteImport || MatchesStemInsensitive(functionName, "ShellExecute");
			}

			if (EqualsInsensitive(libraryName, "urlmon.dll") &&
				importCountForDll == 1 &&
				hasUrlDownloadImport)
			{
				state.hasSingleUrlmonDownloadImport = true;
			}

			if (EqualsInsensitive(libraryName, "shell32.dll") &&
				importCountForDll == 1 &&
				hasShellExecuteImport)
			{
				state.hasSingleShellExecuteImport = true;
			}
		}

		result->importDllCount = state.dllCount;
		result->importFunctionCount = state.functionCount;

		if (state.benignUiCount == 0 &&
			state.executionCount >= 9 &&
			state.stagingCount >= 3)
		{
			MarkFlag(result, MosPeSignatureSuspiciousImportMix, 4);
		}

		if ((state.dllCount <= 2 && state.hasLoadLibraryFamily) ||
			state.hasSingleUrlmonDownloadImport ||
			state.hasSingleShellExecuteImport)
		{
			MarkFlag(result, MosPeSignatureLoaderImports, 2);
		}

		if ((state.hasUrlDownloadToFile && state.hasShellExecute) ||
			(state.hasUrlDownloadToFile && state.hasCreateProcess) ||
			(state.hasShellExecute && state.hasCreateRemoteThread))
		{
			MarkFlag(result, MosPeSignatureNetworkExecutionImports, 3);
		}
	}

	bool TryResolveRelativeBranchTarget(
		__in_bcount(bytesRead) const BYTE *buffer,
		__in const ULONG bytesRead,
		__in const ULONG offset,
		__in const UINT instructionRva,
		__out UINT *targetRva,
		__out ULONG *instructionSize)
	{
		if (buffer == NULL || targetRva == NULL || instructionSize == NULL || offset >= bytesRead)
			return false;

		*instructionSize = 0;
		*targetRva = 0;

		if ((buffer[offset] == 0xE8 || buffer[offset] == 0xE9) && offset + 5 <= bytesRead)
		{
			INT32 rel32 = 0;
			memcpy(&rel32, buffer + offset + 1, sizeof(rel32));
			*instructionSize = 5;
			*targetRva = instructionRva + offset + *instructionSize + rel32;
			return true;
		}

		if ((buffer[offset] == 0xEB || (buffer[offset] >= 0x70 && buffer[offset] <= 0x7F)) && offset + 2 <= bytesRead)
		{
			INT8 rel8 = 0;
			memcpy(&rel8, buffer + offset + 1, sizeof(rel8));
			*instructionSize = 2;
			*targetRva = instructionRva + offset + *instructionSize + rel8;
			return true;
		}

		if (buffer[offset] == 0x0F &&
			offset + 6 <= bytesRead &&
			buffer[offset + 1] >= 0x80 &&
			buffer[offset + 1] <= 0x8F)
		{
			INT32 rel32 = 0;
			memcpy(&rel32, buffer + offset + 2, sizeof(rel32));
			*instructionSize = 6;
			*targetRva = instructionRva + offset + *instructionSize + rel32;
			return true;
		}

		return false;
	}

	void AnalyzeEntrypointStub(
		__in IPeFile *peFile,
		__in IFsStream *stream,
		__in const UINT stubRva,
		__inout MOS_PE_SIGNATURE_RESULT *result)
	{
		if (peFile == NULL || stream == NULL || result == NULL) return;

		BYTE stub[64] = {};
		if (FAILED(ReadExactFromRva(peFile, stream, stubRva, stub, sizeof(stub))))
			return;

		if (stub[0] != 0x55 || stub[1] != 0x8B || stub[2] != 0xEC)
			return;

		bool hasStackFrame = (stub[3] == 0x81 && stub[4] == 0xEC) ||
			(stub[3] == 0x83 && stub[4] == 0xEC);
		if (!hasStackFrame)
			return;

		for (size_t i = 5; i + 1 < sizeof(stub); ++i)
		{
			if (stub[i] == 0xE8 || (stub[i] == 0xFF && stub[i + 1] == 0x15))
			{
				MarkFlag(result, MosPeSignatureEntrypointLoaderStub, 2);
				return;
			}
		}
	}

	void AnalyzeSectionHeuristics(
		__in IPeFile *peFile,
		__in IFsStream *stream,
		__in const IMAGE_NT_HEADERS32& peHeader,
		__inout MOS_PE_SIGNATURE_RESULT *result)
	{
		if (peFile == NULL || stream == NULL || result == NULL) return;

		UINT sectionCount = peFile->GetSectionCount();
		if (sectionCount == 0)
			return;

		IMAGE_SECTION_HEADER lastSection = {};
		if (FAILED(peFile->GetSectionHeader(sectionCount - 1, &lastSection)))
			return;

		result->lastSectionIndex = sectionCount - 1;

		UINT entrySectionIndex = 0;
		if (FAILED(peFile->FindSectionByRva(peHeader.OptionalHeader.AddressOfEntryPoint, &entrySectionIndex)))
			return;

		result->entrySectionIndex = entrySectionIndex;

		if (IsCommonSectionName(lastSection))
			return;

		if (!HasWritableExecutableCode(lastSection))
			return;

		MarkFlag(result, MosPeSignatureWritableExecutableLastSection, 2);

		BYTE entryBytes[256] = {};
		ULONG bytesRead = 0;
		if (FAILED(peFile->ReadEntryPointData(entryBytes, sizeof(entryBytes), &bytesRead)) || bytesRead == 0)
			return;

		const UINT entryPointRva = peHeader.OptionalHeader.AddressOfEntryPoint;
		for (ULONG offset = 0; offset < bytesRead; ++offset)
		{
			UINT targetRva = 0;
			ULONG instructionSize = 0;
			if (!TryResolveRelativeBranchTarget(entryBytes, bytesRead, offset, entryPointRva, &targetRva, &instructionSize))
				continue;

			if (!IsRvaInsideSection(targetRva, lastSection))
				continue;

			MarkFlag(result, MosPeSignatureEntrypointToLastSection, 4);
			if (offset == 0)
				AnalyzeEntrypointStub(peFile, stream, targetRva, result);
			return;
		}
	}
}

HRESULT WINAPI AnalyzeMosPeSignatures(__in IPeFile *peFile, __out MOS_PE_SIGNATURE_RESULT *result)
{
	if (peFile == NULL || result == NULL) return E_INVALIDARG;

	ZeroMemory(result, sizeof(*result));
	result->entrySectionIndex = static_cast<UINT>(-1);
	result->lastSectionIndex = static_cast<UINT>(-1);

	IMAGE_NT_HEADERS32 peHeader = {};
	HRESULT hr = peFile->GetPEHeader(&peHeader);
	if (FAILED(hr)) return hr;

	IFsStream *stream = NULL;
	hr = peFile->QueryInterface(__uuidof(IFsStream), (LPVOID*)&stream);
	if (FAILED(hr)) return hr;

	AnalyzeImportHeuristics(peFile, stream, peHeader, result);
	AnalyzeSectionHeuristics(peFile, stream, peHeader, result);

	stream->Release();

	bool hasImportMix = TEST_FLAG(result->flags, MosPeSignatureSuspiciousImportMix);
	bool hasLoaderImports = TEST_FLAG(result->flags, MosPeSignatureLoaderImports);
	bool hasNetworkImports = TEST_FLAG(result->flags, MosPeSignatureNetworkExecutionImports);
	bool hasLastSectionJump = TEST_FLAG(result->flags, MosPeSignatureEntrypointToLastSection);
	bool hasWritableExecLastSection = TEST_FLAG(result->flags, MosPeSignatureWritableExecutableLastSection);
	bool hasEntrypointStub = TEST_FLAG(result->flags, MosPeSignatureEntrypointLoaderStub);

	const bool hasSectionComposite = hasLastSectionJump &&
		hasWritableExecLastSection &&
		(hasEntrypointStub || hasLoaderImports || hasNetworkImports);
	const bool hasLoaderComposite = hasLoaderImports && (hasNetworkImports || hasSectionComposite);

	result->detected = hasImportMix ||
		hasLoaderComposite ||
		hasSectionComposite;

	return S_OK;
}
