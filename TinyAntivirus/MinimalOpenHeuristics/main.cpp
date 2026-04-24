#include <windows.h>
#include <TinyAvCore.h>
#include "MohPeScanModule.h"

#if defined DEBUG || defined _DEBUG
#include <crtdbg.h>
#endif

HMODULE g_hMod = NULL;

BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,
	DWORD fdwReason,
	LPVOID lpReserved)
{
#if defined DEBUG || defined _DEBUG
	{
		int flag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
		_CrtSetDbgFlag(flag | _CRTDBG_LEAK_CHECK_DF);
	}
#endif

	UNREFERENCED_PARAMETER(lpReserved);

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hinstDLL);
		g_hMod = hinstDLL;
		break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#ifdef __cplusplus
extern "C"
{
#endif

	__declspec(dllexport) HRESULT WINAPI CreateModuleObject(__in REFCLSID rclsid, __in DWORD dwClsContext, __in REFIID riid, __out LPVOID *ppv)
	{
		UNREFERENCED_PARAMETER(rclsid);
		UNREFERENCED_PARAMETER(dwClsContext);
		if (ppv == NULL) return E_INVALIDARG;

		if (IsEqualIID(riid, __uuidof(IModule)))
		{
			*ppv = static_cast<IModule*>(new CMosPeScanModule());
			return S_OK;
		}

		*ppv = NULL;
		return E_NOINTERFACE;
	}

#ifdef __cplusplus
}
#endif

//////////////////////////////////////////////////////////////////////////
// notelemetry
#ifdef __cplusplus
extern "C"
{
#endif
	void _cdecl __vcrt_initialize_telemetry_provider() {}
	void _cdecl __telemetry_main_invoke_trigger() {}
	void _cdecl __telemetry_main_return_trigger() {}
	void _cdecl __vcrt_uninitialize_telemetry_provider() {}
#ifdef __cplusplus
};
#endif
//////////////////////////////////////////////////////////////////////////
