#include "../include/TinyAvCore.h"
#include "Module/ModuleMgrService.h"
#include "Scanner/ScanService.h"
#include <windows.h>

static IModuleManager *g_pModuleMgr = nullptr;
static IScanner *g_pScanner = nullptr;

extern "C" {

__int64 WINAPI CoreInit() {
  if (g_pModuleMgr)
    return 0;

  HRESULT hr =
      CreateClassObject(CLSID_CModuleMgrService, 0, __uuidof(IModuleManager),
                        (LPVOID *)&g_pModuleMgr);
  if (FAILED(hr))
    return hr;

  hr = CreateClassObject(CLSID_CScanService, 0, __uuidof(IScanner),
                         (LPVOID *)&g_pScanner);
  if (FAILED(hr)) {
    g_pModuleMgr->Release();
    g_pModuleMgr = nullptr;
    return hr;
  }

  // Default initialization logic
  // In bdcore, this would load plugins from a "Plugins" directory
  WCHAR szModulePath[MAX_PATH];
  GetModuleFileNameW(NULL, szModulePath, MAX_PATH);
  for (int i = (int)wcslen(szModulePath) - 1; i >= 0; i--) {
    if (szModulePath[i] == L'\\') {
      szModulePath[i + 1] = L'\0';
      break;
    }
  }
  wcscat_s(szModulePath, MAX_PATH, L"Plugins");

  g_pModuleMgr->Load(szModulePath, NULL, 0);

  return 0; // Success
}

__int64 WINAPI CoreInitEx(__int64 a1) {
  // Similar to CoreInit but maybe with custom path or flags
  return CoreInit();
}

__int64 WINAPI CoreUninit() {
  if (g_pScanner) {
    g_pScanner->Release();
    g_pScanner = nullptr;
  }
  if (g_pModuleMgr) {
    g_pModuleMgr->Unload(ScanModule);
    g_pModuleMgr->Release();
    g_pModuleMgr = nullptr;
  }
  return 0;
}

__int64 WINAPI CoreSet(__int64 instance, signed int id, __int64 value1,
                       __int64 value2) {
  // Placeholder for setting engine options
  return 0;
}

__int64 WINAPI CoreGet() {
  // Placeholder for getting engine state
  return 0;
}

__int64 WINAPI CoreGetBuildNumber() { return 2026; }

void *WINAPI CoreGetLastOpenError() { return nullptr; }
}
