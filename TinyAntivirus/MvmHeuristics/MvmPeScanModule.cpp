#include "MvmPeScanModule.h"

extern HMODULE g_hMod;

namespace
{
	LPCWSTR GetHeuristicName(__in const ULONG flags)
	{
		if (TEST_FLAG(flags, MvmPeHeuristicEntrypointToLastSection))
			return L"HEUR:Win32.MVM.SectionJump";

		if (TEST_FLAG(flags, MvmPeHeuristicSuspiciousImportMix))
			return L"HEUR:Win32.MVM.ImportMix";

		return L"HEUR:Win32.MVM.Suspicious";
	}
}

CMvmPeScanModule::CMvmPeScanModule()
{
	m_info.handle = g_hMod;
	m_info.type = ScanModule;
	wcscpy_s(m_info.name, MAX_NAME, L"HEUR:Win32.MVM.PE");
	m_parser = NULL;
}

CMvmPeScanModule::~CMvmPeScanModule()
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}
}

HRESULT WINAPI CMvmPeScanModule::QueryInterface(__in REFIID riid, __out void **ppvObject)
{
	if (ppvObject == NULL) return E_INVALIDARG;

	if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(IScanModule)))
	{
		*ppvObject = static_cast<IScanModule*>(this);
		AddRef();
		return S_OK;
	}

	*ppvObject = NULL;
	return E_NOINTERFACE;
}

HRESULT WINAPI CMvmPeScanModule::GetModuleInfo(__out MODULE_INFO *scanInfo)
{
	if (scanInfo == NULL) return E_INVALIDARG;
	*scanInfo = m_info;
	return S_OK;
}

ModuleType WINAPI CMvmPeScanModule::GetType(void)
{
	return m_info.type;
}

HRESULT WINAPI CMvmPeScanModule::GetName(__out BSTR *name)
{
	if (name == NULL) return E_INVALIDARG;
	*name = SysAllocString(m_info.name);
	return (*name == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMvmPeScanModule::OnScanInitialize(void)
{
	return CreateClassObject(CLSID_CPeFileParser, 0, __uuidof(IPeFile), (LPVOID*)&m_parser);
}

HRESULT WINAPI CMvmPeScanModule::Scan(__in IVirtualFs *file, __in IFsEnumContext *context, __in IScanObserver *observer)
{
	if (file == NULL || context == NULL || observer == NULL) return E_INVALIDARG;
	if (m_parser == NULL) return E_NOT_VALID_STATE;

	SCAN_RESULT scanResult = {};
	scanResult.scanResult = NoVirus;
	scanResult.cleanResult = DonotClean;
	scanResult.action = LeaveVirus;

	HRESULT hr = observer->OnPreScan(file, context);
	if (FAILED(hr)) return hr;

	BOOL isMatched = FALSE;
	hr = m_parser->CheckType(file, &isMatched);
	if (FAILED(hr) || !isMatched)
	{
		m_parser->ReleaseCurrentFile();
		return hr;
	}

	MVM_PE_HEURISTIC_RESULT heuristicResult = {};
	hr = AnalyzeMvmPeHeuristics(m_parser, &heuristicResult);
	if (FAILED(hr))
	{
		hr = S_OK;
		goto Exit;
	}

	if (!heuristicResult.detected)
	{
		hr = S_OK;
		goto Exit;
	}

	scanResult.scanResult = VirusDetected;
	wcscpy_s(scanResult.malwareName, MAX_NAME, GetHeuristicName(heuristicResult.flags));

	hr = observer->OnPreClean(file, context, &scanResult);
	if (FAILED(hr)) goto Exit;

	scanResult.action = LeaveVirus;
	scanResult.cleanResult = DonotClean;
	hr = S_OK;

Exit:
	observer->OnPostClean(file, context, &scanResult);
	m_parser->ReleaseCurrentFile();
	return hr;
}

HRESULT WINAPI CMvmPeScanModule::OnScanShutdown(void)
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}
	return S_OK;
}
