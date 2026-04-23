#include "MohPeScanModule.h"

extern HMODULE g_hMod;

namespace
{
	LPCWSTR GetHeuristicName(__in const ULONG flags)
	{
		if (TEST_FLAG(flags, MohPeHeuristicEntrypointToLastSection))
			return L"HEUR:Win32.Moh.SectionJump";

		if (TEST_FLAG(flags, MohPeHeuristicSuspiciousImportMix))
			return L"HEUR:Win32.Moh.ImportMix";

		return L"HEUR:Win32.Moh.Suspicious";
	}
}

CMohPeScanModule::CMohPeScanModule()
{
	m_info.handle = g_hMod;
	m_info.type = ScanModule;
	wcscpy_s(m_info.name, MAX_NAME, L"HEUR:Win32.Moh.PE");
	m_parser = NULL;
}

CMohPeScanModule::~CMohPeScanModule()
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}
}

HRESULT WINAPI CMohPeScanModule::QueryInterface(__in REFIID riid, __out void **ppvObject)
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

HRESULT WINAPI CMohPeScanModule::GetModuleInfo(__out MODULE_INFO *scanInfo)
{
	if (scanInfo == NULL) return E_INVALIDARG;
	*scanInfo = m_info;
	return S_OK;
}

ModuleType WINAPI CMohPeScanModule::GetType(void)
{
	return m_info.type;
}

HRESULT WINAPI CMohPeScanModule::GetName(__out BSTR *name)
{
	if (name == NULL) return E_INVALIDARG;
	*name = SysAllocString(m_info.name);
	return (*name == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMohPeScanModule::OnScanInitialize(void)
{
	return CreateClassObject(CLSID_CPeFileParser, 0, __uuidof(IPeFile), (LPVOID*)&m_parser);
}

HRESULT WINAPI CMohPeScanModule::Scan(__in IVirtualFs *file, __in IFsEnumContext *context, __in IScanObserver *observer)
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

	Moh_PE_HEURISTIC_RESULT heuristicResult = {};
	hr = AnalyzeMohPeHeuristics(m_parser, &heuristicResult);
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

HRESULT WINAPI CMohPeScanModule::OnScanShutdown(void)
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}
	return S_OK;
}
