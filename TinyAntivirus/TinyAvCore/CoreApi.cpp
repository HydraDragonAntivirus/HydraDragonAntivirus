#include <TinyAvCore.h>
#include <windows.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include "Scanner/CvdParser.h"

#pragma comment(lib, "shlwapi.lib")

namespace
{
	const WCHAR kSharedSignatureSourceEnvironment[] = L"TINYAV_SIGNATURE_SOURCE";

	IScanner* g_pScanner = NULL;
	IModuleManager* g_pModuleMgr = NULL;
	IMosSignatureEngine* g_pSignatureEngine = NULL;
	CCvdParser g_CvdParser;
	LONG g_initCount = 0;
	DWORD g_lastOpenError = ERROR_SUCCESS;


	void SetCoreError(__in const DWORD error)
	{
		g_lastOpenError = error;
	}

	std::wstring GetExecutableDirectory()
	{
		WCHAR modulePath[MAX_PATH + 1] = {};
		if (GetModuleFileNameW(NULL, modulePath, MAX_PATH) == 0)
			return std::wstring();

		PathRemoveFileSpecW(modulePath);
		return std::wstring(modulePath);
	}

	void RememberSharedSignatureSource(__in const std::wstring& path)
	{
		if (!path.empty())
			SetEnvironmentVariableW(kSharedSignatureSourceEnvironment, path.c_str());
	}

	std::wstring ReadSharedSignatureSource()
	{
		DWORD required = GetEnvironmentVariableW(kSharedSignatureSourceEnvironment, NULL, 0);
		if (required == 0)
			return std::wstring();

		std::vector<WCHAR> buffer(static_cast<size_t>(required), L'\0');
		DWORD written = GetEnvironmentVariableW(kSharedSignatureSourceEnvironment, buffer.data(), required);
		if (written == 0 || written >= required)
			return std::wstring();

		return std::wstring(buffer.data(), written);
	}

	bool ReadSignatureMagic(__in const std::wstring& path, __out_ecount(magicCapacity) BYTE* magicBuffer, __in const DWORD magicCapacity)
	{
		if (magicBuffer == NULL || magicCapacity == 0)
			return false;

		HANDLE fileHandle = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (fileHandle == INVALID_HANDLE_VALUE)
			return false;

		DWORD bytesRead = 0;
		const BOOL success = ReadFile(fileHandle, magicBuffer, magicCapacity, &bytesRead, NULL);
		CloseHandle(fileHandle);
		return success && bytesRead == magicCapacity;
	}

	bool LooksLikeSignatureCandidate(__in const std::wstring& path)
	{
		LPCWSTR extension = PathFindExtensionW(path.c_str());
		if (extension != NULL && _wcsicmp(extension, L".cvd") == 0)
			return true;

		BYTE magic[4] = {};
		if (!ReadSignatureMagic(path, magic, _countof(magic)))
			return false;

		static const BYTE kIndexedBinaryMagic[4] = { 0xC0, 0x01, 0xC0, 0xDE };
		if (memcmp(magic, kIndexedBinaryMagic, sizeof(kIndexedBinaryMagic)) == 0)
			return true;

		if (memcmp(magic, "AVXS", 4) == 0 ||
			memcmp(magic, "UNPD", 4) == 0 ||
			memcmp(magic, "VESG", 4) == 0)
		{
			return true;
		}

		return false;
	}

	int GetSignatureLoadPriority(__in const std::wstring& path)
	{
		LPCWSTR fileName = PathFindFileNameW(path.c_str());
		if (_wcsicmp(fileName, L"xlmrd.cvd") == 0)
			return 0;
		if (_wcsicmp(fileName, L"xlmrd.ivd") == 0)
			return 1;
		if (_wcsicmp(fileName, L"orice.rvd") == 0)
			return 2;
		return 100;
	}

	void CollectDirectorySignatureCandidates(__in const std::wstring& directory, __out std::vector<std::wstring>* candidates)
	{
		if (candidates == NULL)
			return;

		candidates->clear();

		WIN32_FIND_DATAW findData = {};
		const std::wstring searchPattern = directory + L"\\*";
		HANDLE findHandle = FindFirstFileW(searchPattern.c_str(), &findData);
		if (findHandle == INVALID_HANDLE_VALUE)
			return;

		do
		{
			if (TEST_FLAG(findData.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY))
				continue;

			const std::wstring candidatePath = directory + L"\\" + findData.cFileName;
			if (LooksLikeSignatureCandidate(candidatePath))
				candidates->push_back(candidatePath);
		} while (FindNextFileW(findHandle, &findData));

		FindClose(findHandle);

		std::sort(candidates->begin(), candidates->end(),
			[](const std::wstring& left, const std::wstring& right)
			{
				const int leftPriority = GetSignatureLoadPriority(left);
				const int rightPriority = GetSignatureLoadPriority(right);
				if (leftPriority != rightPriority)
					return leftPriority < rightPriority;

				return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE) == CSTR_LESS_THAN;
			});
	}

	bool TryLoadSignatureFile(__in const std::wstring& path, __in const bool append)
	{
		DWORD attributes = GetFileAttributesW(path.c_str());
		if (attributes == INVALID_FILE_ATTRIBUTES)
		{
			SetCoreError(GetLastError());
			return false;
		}

		if (TEST_FLAG(attributes, FILE_ATTRIBUTE_DIRECTORY))
		{
			SetCoreError(ERROR_DIRECTORY);
			return false;
		}

		if (!LooksLikeSignatureCandidate(path))
		{
			SetCoreError(ERROR_NOT_SUPPORTED);
			return false;
		}

		const bool loaded = append ? g_CvdParser.Append(path) : g_CvdParser.Load(path);
		if (loaded)
		{
			if (g_pSignatureEngine)
			{
				if (!append) g_pSignatureEngine->Reset();
				const std::vector<unsigned char>& data = g_CvdParser.GetData();
				g_pSignatureEngine->LoadSignatures(data.data(), data.size());
			}
			SetCoreError(ERROR_SUCCESS);
			return true;
		}


		SetCoreError(ERROR_INVALID_DATA);
		return false;
	}

	bool TryLoadSignatureSet(__in const std::wstring& basePath)
	{
		if (basePath.empty())
		{
			SetCoreError(ERROR_INVALID_PARAMETER);
			return false;
		}

		if (!PathIsDirectoryW(basePath.c_str()))
			return TryLoadSignatureFile(basePath, false);

		g_CvdParser.Reset();

		std::vector<std::wstring> candidates;
		CollectDirectorySignatureCandidates(basePath, &candidates);
		if (candidates.empty())
		{
			SetCoreError(ERROR_FILE_NOT_FOUND);
			return false;
		}

		bool loaded = false;
		DWORD lastFailure = ERROR_SUCCESS;
		for (size_t i = 0; i < candidates.size(); ++i)
		{
			if (TryLoadSignatureFile(candidates[i], loaded))
			{
				loaded = true;
				continue;
			}

			if (lastFailure == ERROR_SUCCESS)
				lastFailure = g_lastOpenError;
		}

		if (loaded)
		{
			SetCoreError(ERROR_SUCCESS);
			return true;
		}

		SetCoreError(lastFailure == ERROR_SUCCESS ? ERROR_INVALID_DATA : lastFailure);
		return false;
	}

	HRESULT EnsureSignatureEngine()
	{
		if (g_pSignatureEngine != NULL)
			return S_OK;

		return CreateMosSignatureEngine(&g_pSignatureEngine);
	}

	HRESULT AddLoadedScanModules()
	{
		if (g_pModuleMgr == NULL || g_pScanner == NULL)
			return E_NOT_VALID_STATE;

		IModule** modules = NULL;
		size_t moduleCount = 0;
		HRESULT hr = g_pModuleMgr->QueryModule(modules, moduleCount, ScanModule);
		if (FAILED(hr))
			return hr;

		for (size_t i = 0; i < moduleCount; ++i)
		{
			IScanModule* scanModule = NULL;
			if (modules[i] &&
				SUCCEEDED(modules[i]->QueryInterface(__uuidof(IScanModule), (void**)&scanModule)))
			{
				g_pScanner->AddScanModule(scanModule);
				scanModule->Release();
			}

			if (modules[i])
				modules[i]->Release();
		}

		if (modules)
			CoTaskMemFree(modules);
		return S_OK;
	}

	void ReleaseServices()
	{
		if (g_pScanner)
		{
			g_pScanner->Release();
			g_pScanner = NULL;
		}

		if (g_pModuleMgr)
		{
			g_pModuleMgr->Unload(ScanModule);
			g_pModuleMgr->Release();
			g_pModuleMgr = NULL;
		}

		if (g_pSignatureEngine)
		{
			g_pSignatureEngine->Release();
			g_pSignatureEngine = NULL;
		}
	}


	HRESULT EnsureServicesInitialized()
	{
		if (g_pScanner && g_pModuleMgr)
		{
			InterlockedIncrement(&g_initCount);
			return S_OK;
		}

		HRESULT hr = CreateClassObject(CLSID_CModuleMgrService, 0, __uuidof(IModuleManager), (void**)&g_pModuleMgr);
		if (FAILED(hr))
		{
			SetCoreError(HRESULT_CODE(hr));
			return hr;
		}

		hr = CreateClassObject(CLSID_CScanService, 0, __uuidof(IScanner), (void**)&g_pScanner);
		if (FAILED(hr))
		{
			SetCoreError(HRESULT_CODE(hr));
			ReleaseServices();
			return hr;
		}

		hr = CreateMosSignatureEngine(&g_pSignatureEngine);
		if (FAILED(hr))
		{
			SetCoreError(HRESULT_CODE(hr));
			ReleaseServices();
			return hr;
		}


		const std::wstring moduleDirectory = GetExecutableDirectory();
		if (!moduleDirectory.empty())
		{
			hr = g_pModuleMgr->Load(moduleDirectory.c_str(), ScanModule, 0);
			if (SUCCEEDED(hr) || hr == E_FAIL || hr == E_NOT_SET)
			{
				HRESULT addHr = AddLoadedScanModules();
				if (FAILED(addHr) && addHr != E_NOT_SET)
				{
					SetCoreError(HRESULT_CODE(addHr));
					ReleaseServices();
					return addHr;
				}
			}
		}

		if (!moduleDirectory.empty())
		{
			if (TryLoadSignatureSet(moduleDirectory))
				RememberSharedSignatureSource(moduleDirectory);
		}
		InterlockedExchange(&g_initCount, 1);
		SetCoreError(ERROR_SUCCESS);
		return S_OK;
	}

	bool CopyUtf8ToWideBuffer(__in const std::string& value, __out_ecount(capacity) WCHAR* buffer, __in const unsigned int capacity)
	{
		if (buffer == NULL || capacity == 0)
		{
			SetCoreError(ERROR_INVALID_PARAMETER);
			return false;
		}

		int written = MultiByteToWideChar(
			CP_UTF8,
			0,
			value.c_str(),
			-1,
			buffer,
			static_cast<int>(capacity));
		if (written == 0)
		{
			SetCoreError(GetLastError());
			return false;
		}

		SetCoreError(ERROR_SUCCESS);
		return true;
	}
}

extern "C"
{

__int64 WINAPI CoreInit()
{
	return SUCCEEDED(EnsureServicesInitialized()) ? 1 : 0;
}

__int64 WINAPI CoreInit2(__m128i *a1)
{
	UNREFERENCED_PARAMETER(a1);
	return CoreInit();
}

__int64 WINAPI CoreInit3(__int64 a1)
{
	UNREFERENCED_PARAMETER(a1);
	return CoreInit();
}

__int64 WINAPI CoreInit4_0(__m128i *a1, __int64 a2)
{
	UNREFERENCED_PARAMETER(a1);
	UNREFERENCED_PARAMETER(a2);
	return CoreInit();
}

__int64 WINAPI CoreInit5(int a1, __int64 a2, __int64 a3, __int64 a4)
{
	UNREFERENCED_PARAMETER(a1);
	UNREFERENCED_PARAMETER(a2);
	UNREFERENCED_PARAMETER(a3);
	UNREFERENCED_PARAMETER(a4);
	return CoreInit();
}

__int64 WINAPI CoreInitEx(__int64 a1)
{
	UNREFERENCED_PARAMETER(a1);
	return CoreInit();
}

__int64 WINAPI CoreUninit()
{
	LONG remaining = InterlockedCompareExchange(&g_initCount, 0, 0);
	if (remaining == 0)
		return 0;

	remaining = InterlockedDecrement(&g_initCount);
	if (remaining != 0)
		return 0;

	ReleaseServices();
	SetCoreError(ERROR_SUCCESS);
	return 1;
}

__int64 WINAPI CoreNewInstance()
{
	return (__int64)g_pScanner;
}

__int64 WINAPI CoreDeleteInstance()
{
	return 1;
}

__int64 WINAPI CoreSet(__int64 instance, signed int id, __int64 value1, __int64 value2)
{
	UNREFERENCED_PARAMETER(id);
	UNREFERENCED_PARAMETER(value1);
	UNREFERENCED_PARAMETER(value2);
	return (instance != 0) ? 1 : 0;
}

__int64 WINAPI CoreGet()
{
	return 0;
}

__int64 WINAPI CoreGetBuildNumber()
{
	return 2026;
}

__int64 WINAPI CoreUtf16_8(unsigned __int16 *a1, __int64 a2, unsigned int a3)
{
	if (a1 == NULL || a2 == 0 || a3 == 0)
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	int written = WideCharToMultiByte(
		CP_UTF8,
		0,
		reinterpret_cast<LPCWCH>(a1),
		-1,
		reinterpret_cast<LPSTR>(a2),
		static_cast<int>(a3),
		NULL,
		NULL);
	if (written == 0)
		SetCoreError(GetLastError());
	else
		SetCoreError(ERROR_SUCCESS);
	return written;
}

__int64 WINAPI CoreUtf8_16(unsigned char *a1, unsigned short *a2, unsigned int a3)
{
	if (a1 == NULL || a2 == NULL || a3 == 0)
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	int written = MultiByteToWideChar(
		CP_UTF8,
		0,
		reinterpret_cast<LPCCH>(a1),
		-1,
		reinterpret_cast<LPWSTR>(a2),
		static_cast<int>(a3));
	if (written == 0)
		SetCoreError(GetLastError());
	else
		SetCoreError(ERROR_SUCCESS);
	return written;
}

__int64 WINAPI CoreLoadSignatures(const WCHAR* path)
{
	if (path == NULL || *path == L'\0')
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (!TryLoadSignatureSet(path))
		return 0;

	RememberSharedSignatureSource(path);
	return 1;
}

__int64 WINAPI CoreReloadSharedSignatures()
{
	const std::wstring sharedSource = ReadSharedSignatureSource();
	if (sharedSource.empty())
	{
		SetCoreError(ERROR_NOT_FOUND);
		return 0;
	}

	if (FAILED(EnsureSignatureEngine()))
	{
		SetCoreError(ERROR_GEN_FAILURE);
		return 0;
	}

	return TryLoadSignatureSet(sharedSource) ? 1 : 0;
}

__int64 WINAPI CoreGetLoadedSignatureCount()
{
	return static_cast<__int64>(g_CvdParser.GetDatabases().size());
}

__int64 WINAPI CoreGetLoadedSignatureType(unsigned int index)
{
	const std::vector<SIGNATURE_DATABASE_INFO>& databases = g_CvdParser.GetDatabases();
	if (index >= databases.size())
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return SignatureDatabaseUnknown;
	}

	SetCoreError(ERROR_SUCCESS);
	return databases[index].type;
}

__int64 WINAPI CoreCopyLoadedSignatureName(unsigned int index, WCHAR* buffer, unsigned int capacity)
{
	const std::vector<SIGNATURE_DATABASE_INFO>& databases = g_CvdParser.GetDatabases();
	if (index >= databases.size())
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	return CopyUtf8ToWideBuffer(databases[index].name, buffer, capacity) ? 1 : 0;
}

__int64 WINAPI CoreCopyLoadedSignatureSourcePath(unsigned int index, WCHAR* buffer, unsigned int capacity)
{
	const std::vector<SIGNATURE_DATABASE_INFO>& databases = g_CvdParser.GetDatabases();
	if (index >= databases.size() || buffer == NULL || capacity == 0)
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	if (FAILED(StringCchCopyW(buffer, capacity, databases[index].sourcePath.c_str())))
	{
		SetCoreError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	SetCoreError(ERROR_SUCCESS);
	return 1;
}

__int64 WINAPI CoreCopySharedSignatureSourcePath(WCHAR* buffer, unsigned int capacity)
{
	if (buffer == NULL || capacity == 0)
	{
		SetCoreError(ERROR_INVALID_PARAMETER);
		return 0;
	}

	const std::wstring sharedSource = ReadSharedSignatureSource();
	if (sharedSource.empty())
	{
		SetCoreError(ERROR_NOT_FOUND);
		return 0;
	}

	if (FAILED(StringCchCopyW(buffer, capacity, sharedSource.c_str())))
	{
		SetCoreError(ERROR_INSUFFICIENT_BUFFER);
		return 0;
	}

	SetCoreError(ERROR_SUCCESS);
	return 1;
}

void* WINAPI CoreGetLastOpenError()
{
	return &g_lastOpenError;
}

HRESULT WINAPI CreateMosSignatureEngine(IMosSignatureEngine** ppEngine)
{
	// Forward to implementation in MohSignatureEngine.cpp
	extern HRESULT CreateMosSignatureEngineImpl(IMosSignatureEngine** ppEngine);
	return CreateMosSignatureEngineImpl(ppEngine);
}

IMosSignatureEngine* WINAPI CoreGetSignatureEngine()
{
	if (g_pSignatureEngine == NULL)
		EnsureSignatureEngine();

	if (g_pSignatureEngine)
		g_pSignatureEngine->AddRef();
	return g_pSignatureEngine;
}

}
