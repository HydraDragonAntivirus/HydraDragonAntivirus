#include <iostream>
#include "xvneng.h"

#ifdef _WIN32
    #include <windows.h>
    #define symLoad GetProcAddress
#else
    #include <dlfcn.h>
    #define symLoad dlsym
#endif

using namespace std;

int main()
{
    // ---- 1. Load the shared library ----------------------------------------

#ifdef _WIN32
    HINSTANCE handle = LoadLibrary(L"C:\\XvirusSDK\\bin\\Windows\\XvirusSDK.dll"); // change to your path
#else
    void* handle = dlopen("/usr/local/lib/XvirusSDK.so", RTLD_LAZY); // change to your path
#endif

    if (!handle)
    {
        wcerr << L"Failed to load XvirusSDK library." << endl;
        return EXIT_FAILURE;
    }

    // ---- 2. Resolve function pointers ---------------------------------------

    VersionFn version = (VersionFn) symLoad(handle, VersionFnKey);
    LoadFn    load    = (LoadFn)    symLoad(handle, LoadFnKey);
    UnloadFn  unload  = (UnloadFn)  symLoad(handle, UnloadFnKey);
    ScanFn    scan    = (ScanFn)    symLoad(handle, ScanFnKey);

    // ---- 3. Print SDK version -----------------------------------------------

    wcout << L"Xvirus SDK " << version() << endl;

    // ---- 4. Load the engine (databases + AI model) --------------------------

    ActionResult loadResult = load(false);
    if (!loadResult.sucess)
    {
        wcerr << L"Engine load failed: " << loadResult.error << endl;
        return EXIT_FAILURE;
    }
    wcout << loadResult.result << endl;

    // ---- 5. Scan a file -----------------------------------------------------

#ifdef _WIN32
    const wchar_t* targetFile = L"C:\\Windows\\System32\\notepad.exe"; // change to the file you want to scan
#else
    const wchar_t* targetFile = L"/usr/bin/bash"; // change to the file you want to scan
#endif

    ScanResult result = scan(targetFile);
    if (!result.sucess)
    {
        wcerr << L"Scan error: " << result.error << endl;
    }
    else
    {
        wcout << L"\nFile:      " << result.path                              << endl;
        wcout << L"Malware:   " << (result.isMalware ? L"Yes" : L"No")       << endl;
        wcout << L"Detection: " << result.name                                << endl;
        wcout << L"Score:     " << result.malwareScore                        << endl;
    }

    // ---- 6. Unload the engine -----------------------------------------------

    unload();

#ifdef _WIN32
    FreeLibrary(handle);
#else
    dlclose(handle);
#endif

    return EXIT_SUCCESS;
}
