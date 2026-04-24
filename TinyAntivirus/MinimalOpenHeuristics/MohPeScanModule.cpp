#include "MohPeScanModule.h"

extern HMODULE g_hMod;

namespace
{
	LPCWSTR GetSignatureName(__in const ULONG flags)
	{
		if (TEST_FLAG(flags, MosPeSignatureEntrypointToLastSection))
			return L"HEUR:Win32.MOS.SectionJump";

		if (TEST_FLAG(flags, MosPeSignatureSuspiciousImportMix))
			return L"HEUR:Win32.MOS.ImportMix";

		return L"HEUR:Win32.MOS.Suspicious";
	}
}

CMosPeScanModule::CMosPeScanModule()
{
	m_info.handle = g_hMod;
	m_info.type = ScanModule;
	wcscpy_s(m_info.name, MAX_NAME, L"MinimalOpenSignatures");
	m_parser = NULL;
	m_sigEngine = NULL;
}


CMosPeScanModule::~CMosPeScanModule()
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}

	if (m_sigEngine)
	{
		m_sigEngine->Release();
		m_sigEngine = NULL;
	}
}

HRESULT WINAPI CMosPeScanModule::QueryInterface(__in REFIID riid, __out void **ppvObject)
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

HRESULT WINAPI CMosPeScanModule::GetModuleInfo(__out MODULE_INFO *scanInfo)
{
	if (scanInfo == NULL) return E_INVALIDARG;
	*scanInfo = m_info;
	return S_OK;
}

ModuleType WINAPI CMosPeScanModule::GetType(void)
{
	return m_info.type;
}

HRESULT WINAPI CMosPeScanModule::GetName(__out BSTR *name)
{
	if (name == NULL) return E_INVALIDARG;
	*name = SysAllocString(m_info.name);
	return (*name == NULL) ? E_OUTOFMEMORY : S_OK;
}

HRESULT WINAPI CMosPeScanModule::OnScanInitialize(void)
{
	HRESULT hr = CreateClassObject(CLSID_CPeFileParser, 0, __uuidof(IPeFile), (LPVOID*)&m_parser);
	if (FAILED(hr))
		return hr;

	// TinyAvCore is currently linked statically into both the console and the
	// plug-in, so reload the shared signature source here to mirror what the
	// launcher loaded before the module started scanning.
	CoreReloadSharedSignatures();
	
	if (m_sigEngine) m_sigEngine->Release();
	m_sigEngine = CoreGetSignatureEngine();
	
	return S_OK;
}


HRESULT WINAPI CMosPeScanModule::Scan(__in IVirtualFs *file, __in IFsEnumContext *context, __in IScanObserver *observer)
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

	MOS_PE_SIGNATURE_RESULT signatureResult = {};
	hr = AnalyzeMosPeSignatures(m_parser, &signatureResult);
	if (SUCCEEDED(hr) && signatureResult.detected)
	{
		scanResult.scanResult = VirusDetected;
		wcscpy_s(scanResult.malwareName, MAX_NAME, GetSignatureName(signatureResult.flags));
		goto Report;
	}

	// Runtime signature matching for xlmrd/orice
	if (m_sigEngine)
	{
		hr = m_sigEngine->Match(file, scanResult.malwareName, MAX_NAME);
		if (hr == S_OK)
		{
			scanResult.scanResult = VirusDetected;
			goto Report;
		}
	}

	hr = S_OK;
	goto Exit;

Report:

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

HRESULT WINAPI CMosPeScanModule::OnScanShutdown(void)
{
	if (m_parser)
	{
		m_parser->Release();
		m_parser = NULL;
	}
	return S_OK;
}
