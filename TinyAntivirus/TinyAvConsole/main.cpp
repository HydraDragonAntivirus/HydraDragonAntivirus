#include <windows.h>
#include <stdio.h>
#include <TinyAvCore.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
#include "getopt.h"
#include "ConsoleObserver.h"

#if defined DEBUG || defined _DEBUG
#include <crtdbg.h>
#endif
//////////////////////////////////////////////////////////////////////////

// notelemetry
#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus
	void _cdecl __vcrt_initialize_telemetry_provider() {}
	void _cdecl __telemetry_main_invoke_trigger() {}
	void _cdecl __telemetry_main_return_trigger() {}
	void _cdecl __vcrt_uninitialize_telemetry_provider() {}
#ifdef __cplusplus
};
#endif // __cplusplus
//////////////////////////////////////////////////////////////////////////


void Usage(void)
{
	puts("Usage:");
	puts("  TinyAvConsole.exe -d <path> [options]\n");
	puts("Options:");
	puts("  -d <path>   Target directory or file system path to scan");
	puts("  -e <dir>    Plug-in directory. Default: executable directory");
	puts("  -g <path>   Signature file or directory (all parseable DB containers such as .cvd/.ivd/.rvd/.xmd)");
	puts("  -p <mask>   File pattern. Default: *.*");
	puts("  -D <depth>  Directory recursion depth. Default: -1 (unlimited)");
	puts("  -A <depth>  Archive recursion depth. Default: -1 (unlimited)");
	puts("  -s <bytes>  Maximum file size in bytes. Default: 10485760");
	puts("  -m <mode>   Scan mode: k = disinfect, s = detect only");
	puts("  -h          Show this help\n");
	puts("Examples:");
	puts("  TinyAvConsole.exe -d C:\\samples -m s");
	puts("  TinyAvConsole.exe -d C:\\samples -g C:\\repo\\TinyAntivirus\\decompile -m s");
	puts("  TinyAvConsole.exe -d C:\\samples -A 2 -D 4 -m k\n");
	puts("Built-in engines:");
	puts("  - SalityKiller for W32.Sality.PE disinfection");
	puts("  - MinimalOpenSignatures (MOS) for conservative PE signature and heuristic detection");
	puts("  - ZIP archive scanning is already supported\n");
	exit(0);
}

void PrintSignatureLoadResult(__in LPCWSTR signaturePath, __in BOOL success)
{
	DWORD errorCode = ERROR_GEN_FAILURE;
	DWORD *lastOpenError = static_cast<DWORD*>(CoreGetLastOpenError());
	if (lastOpenError)
		errorCode = *lastOpenError;

	wprintf(L"[MOS] Loading signatures from %s... %s", signaturePath, success ? L"Success" : L"Failed");
	if (!success)
		wprintf(L" (error: %lu)", errorCode);
	wprintf(L"\n");
}

LPCWSTR GetSignatureTypeDisplayName(__in const __int64 type)
{
	switch (type)
	{
	case SignatureDatabaseCvd:
		return L"CVD";
	case SignatureDatabaseIndexedBinary:
		return L"IndexedBinary";
	case SignatureDatabaseAvxs:
		return L"AVXS";
	case SignatureDatabasePlaceholder:
		return L"Placeholder";
	default:
		return L"Unknown";
	}
}

void PrintLoadedSignatureSummary(void)
{
	const __int64 databaseCount = CoreGetLoadedSignatureCount();
	if (databaseCount <= 0)
		return;

	wprintf(L"[MOS] Loaded signature databases: %lld\n", databaseCount);
	for (__int64 i = 0; i < databaseCount; ++i)
	{
		WCHAR name[MAX_PATH + 1] = {};
		WCHAR sourcePath[MAX_PATH + 1] = {};
		const __int64 type = CoreGetLoadedSignatureType(static_cast<unsigned int>(i));
		if (CoreCopyLoadedSignatureName(static_cast<unsigned int>(i), name, _countof(name)) != 1)
			wcscpy_s(name, _countof(name), L"(unnamed)");
		if (CoreCopyLoadedSignatureSourcePath(static_cast<unsigned int>(i), sourcePath, _countof(sourcePath)) != 1)
			wcscpy_s(sourcePath, _countof(sourcePath), L"(unknown)");

		wprintf(L"[MOS]   %lld. %s [%s] - %s\n", i + 1, name, GetSignatureTypeDisplayName(type), sourcePath);
	}

	puts("[MOS] Signature runtime matching (xlmrd/orice) is ACTIVE.");
}


void PrintWelcome()
{
	puts("--------------------------------------------------------------------------");
	puts("TinyAntivirus version 0.2");
	puts("Copyright (C) 2016, develbranch.com.");
	puts("Copyright (C) 2026, Emirhan Ucan.");
	puts("TinyAntivirus comes with ABSOLUTELY NO WARRANTY");
	puts("This is free software, and you are welcome to redistribute it under ");
	puts("certain conditions.");
	puts("--------------------------------------------------------------------------");
}

int wmain(int argc, wchar_t* argv[])
{
	PrintWelcome();
#if defined DEBUG || defined _DEBUG
	{
		int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
		_CrtSetDbgFlag(flag | _CRTDBG_LEAK_CHECK_DF);
		//_CrtSetBreakAlloc(0x1337);
	}
#endif
	HRESULT hr;
	WCHAR szPattern[MAX_PATH + 1] = L"*.*";
	WCHAR szTargetDir[MAX_PATH + 1] = {};
	WCHAR szPluginsSubDir[MAX_PATH + 1] = {};
	WCHAR szPluginsDir[MAX_PATH + 1] = {};
	WCHAR szSignaturePath[MAX_PATH + 1] = {};
	int c;
	int depth = -1;
	int archiveDepth = -1;
	ULARGE_INTEGER maxFileSize = {};
	int mode = 2; //kill mode
	maxFileSize.QuadPart = 10 * 1024 * 1024;
	// -p
	while ((c = getopt_w(argc, argv, L"e:A:D:d:g:p:s:m:h")) != -1)
	{
		switch (c)
		{
		case L'e':
			wcscpy_s((wchar_t*)szPluginsSubDir, MAX_PATH, optarg_w);
			break;

		case L'A':
			archiveDepth = _wtoi(optarg_w);
			break;

		case L'D':
			depth = _wtoi(optarg_w);
			break;
		
		case L'd':
			wcscpy_s((wchar_t*)szTargetDir, MAX_PATH, optarg_w);
			break;

		case L'g':
			wcscpy_s((wchar_t*)szSignaturePath, MAX_PATH, optarg_w);
			break;

		case L'p':
			wcscpy_s((wchar_t*)szPattern, MAX_PATH, optarg_w);
			break;

		case L's':
			maxFileSize.QuadPart = _wtoi(optarg_w);
			break;
	
		case L'm': // mode
			if ((optarg_w[0] & 0xdf) == L'K') // kill mode
				mode = 2;
			if ((optarg_w[0] & 0xdf) == L'S') // Scan mode
				mode = 1;
			break;

		case L'h':
			Usage();
			break;
		default:
			Usage();
			break;
		}
	}

	if (wcslen(szTargetDir) == 0)
		return 1;

	IScanObserver * consoleObserver = NULL;
	IScanner * scanner = NULL;
	IModuleManager *mgr = NULL;
	IFsEnumContext * enumContext = NULL;
	IVirtualFs *container = NULL;

	if (FAILED(CreateClassObject(CLSID_CModuleMgrService, 0, __uuidof(IModuleManager), (LPVOID*)&mgr)) ||
		FAILED(CreateClassObject(CLSID_CScanService, 0, __uuidof(IScanner), (LPVOID*)&scanner)) ||
		FAILED(CreateClassObject(CLSID_CFileFsEnumContext, 0, __uuidof(IFsEnumContext), (LPVOID*)&enumContext)) ||
		FAILED(CreateClassObject(CLSID_CFileFs, 0, __uuidof(IVirtualFs), (LPVOID*)&container)) ||
		((consoleObserver = static_cast<IScanObserver *>(new CConsoleObserver)) == NULL)
		)
	{
		if (scanner) scanner->Release();
		if (mgr) mgr->Release();
		if (enumContext) enumContext->Release();
		if (container) container->Release();
		if (consoleObserver) consoleObserver->Release();
		return 1;
	}

	GetModuleFileNameW(NULL, szPluginsDir, MAX_PATH);
	PathRemoveFileSpecW(szPluginsDir);
	if (wcslen(szPluginsSubDir) > 0)
		PathAppendW(szPluginsDir, szPluginsSubDir);

	if (wcslen(szSignaturePath) > 0)
	{
		WCHAR szResolvedSignaturePath[MAX_PATH + 1] = {};
		LPCWSTR signaturePath = szSignaturePath;
		DWORD resolvedLength = GetFullPathNameW(szSignaturePath, MAX_PATH, szResolvedSignaturePath, NULL);
		if (resolvedLength > 0 && resolvedLength <= MAX_PATH)
			signaturePath = szResolvedSignaturePath;

		BOOL signatureLoaded = (CoreLoadSignatures(signaturePath) == 1);
		PrintSignatureLoadResult(signaturePath, signatureLoaded);
		if (!signatureLoaded)
		{
			consoleObserver->Release();
			enumContext->Release();
			container->Release();
			scanner->Release();
			mgr->Release();
			return 1;
		}

		PrintLoadedSignatureSummary();
	}

	if (SUCCEEDED(mgr->Load(szPluginsDir, NULL, 0)))
	{
		IModule **scanModule = NULL;
		size_t moduleCount = 0;

		if (SUCCEEDED(mgr->QueryModule(scanModule, moduleCount, ScanModule)))
		{
			for (size_t i = 0; i < moduleCount; ++i)
			{
				scanner->AddScanModule(dynamic_cast<IScanModule*>(scanModule[i]));
				scanModule[i]->Release();
			}

			CoTaskMemFree(scanModule);
		}

		if (
			SUCCEEDED(hr = scanner->AddScanObserver(consoleObserver)) &&
			SUCCEEDED(hr = enumContext->SetSearchPattern(szPattern)) &&
			SUCCEEDED(hr = enumContext->SetMaxDepth(depth)) &&
			SUCCEEDED(hr = enumContext->SetMaxDepthInArchive(archiveDepth)) &&
			SUCCEEDED(hr = enumContext->SetMaxFileSize(maxFileSize)) &&
			SUCCEEDED(hr = enumContext->SetFlags((mode == 1) ? IFsEnumContext::DetectOnly : IFsEnumContext::Disinfect)) &&
			SUCCEEDED(hr = container->Create(szTargetDir, 0)) &&
			SUCCEEDED(hr = enumContext->SetSearchContainer(container))
			)
		{
			hr = scanner->Start(enumContext);
			scanner->Forever();
		}
	}
	consoleObserver->Release();
	enumContext->Release();
	container->Release();
	scanner->Release();
	mgr->Unload(ScanModule);
	mgr->Release();
	return 0;
}
