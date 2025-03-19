// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "resource.h"
#include <windows.h>
#include <string>

// Global variable to store our module handle (which contains the resources).
static HMODULE g_hThisModule = NULL;

// Helper function to extract a resource from the module to an output file.
// hModule: Module handle containing the resource.
// lpName: Resource identifier (e.g., MAKEINTRESOURCE(...)).
// lpType: Resource type (e.g., RT_RCDATA).
// outputFile: The full path where the resource will be written.
bool ExtractResourceToFile(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType, const std::wstring& outputFile)
{
    // Locate the resource in the module.
    HRSRC hResource = FindResource(hModule, lpName, lpType);
    if (!hResource)
    {
        OutputDebugStringW(L"FindResource failed.\n");
        return false;
    }

    // Get the size of the resource.
    DWORD dwSize = SizeofResource(hModule, hResource);
    if (dwSize == 0)
    {
        OutputDebugStringW(L"SizeofResource returned 0.\n");
        return false;
    }

    // Load the resource.
    HGLOBAL hLoadedResource = LoadResource(hModule, hResource);
    if (!hLoadedResource)
    {
        OutputDebugStringW(L"LoadResource failed.\n");
        return false;
    }

    // Lock the resource to obtain a pointer to its data.
    LPVOID pResourceData = LockResource(hLoadedResource);
    if (!pResourceData)
    {
        OutputDebugStringW(L"LockResource failed.\n");
        return false;
    }

    // Create or overwrite the output file.
    HANDLE hFile = CreateFileW(outputFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        OutputDebugStringW(L"CreateFile failed.\n");
        return false;
    }

    // Write the resource data to the file.
    DWORD dwWritten = 0;
    BOOL bWrite = WriteFile(hFile, pResourceData, dwSize, &dwWritten, NULL);
    CloseHandle(hFile);

    if (!bWrite || dwWritten != dwSize)
    {
        OutputDebugStringW(L"WriteFile failed or incomplete.\n");
        return false;
    }

    return true;
}

// Exported function to extract all DLL resources to 
// "C:\Program Files\HydraDragonAntivirus\temp", load HydraDragonAVSandboxie.dll from that folder,
// and then call its exported InjectDllMain function (if available).
extern "C" __declspec(dllexport) void __stdcall InjectDllMain(HINSTANCE hSbieDll, ULONG_PTR UnusedParameter)
{
    UNREFERENCED_PARAMETER(hSbieDll);
    UNREFERENCED_PARAMETER(UnusedParameter);

    // Define the target extraction folder.
    const std::wstring targetFolder = L"C:\\Program Files\\HydraDragonAntivirus\\temp";

    // Create the target folder if it does not exist.
    CreateDirectoryW(targetFolder.c_str(), NULL);

    // Define the list of DLL resources and their corresponding output filenames.
    struct ResourceFile {
        int resourceId;
        const wchar_t* fileName;
    };

    ResourceFile resources[] = {
        { IDR_ARCHIVE_DLL,                 L"archive.dll" },
        { IDR_BZ2_DLL,                     L"bz2.dll" },
        { IDR_HYDRA_DRAGON_AV_SANDBOXIE,   L"HydraDragonAVSandboxie.dll" },
        { IDR_LIBCRYPTO_3_X64_DLL,         L"libcrypto-3-x64.dll" },
        { IDR_LIBLZMA_DLL,                 L"liblzma.dll" },
        { IDR_LZ4_DLL,                     L"lz4.dll" },
        { IDR_ZLIB1_DLL,                   L"zlib1.dll" },
        { IDR_ZSTD_DLL,                    L"zstd.dll" }
    };

    // Loop through each resource and extract it to the target folder.
    for (const auto& res : resources)
    {
        std::wstring outputFile = targetFolder + L"\\" + res.fileName;
        if (!ExtractResourceToFile(g_hThisModule, MAKEINTRESOURCE(res.resourceId), RT_RCDATA, outputFile))
        {
            std::wstring debugMsg = L"Failed to extract resource with id: " + std::to_wstring(res.resourceId) + L"\n";
            OutputDebugStringW(debugMsg.c_str());
        }
        else
        {
            std::wstring debugMsg = L"Successfully extracted resource with id: " + std::to_wstring(res.resourceId) + L"\n";
            OutputDebugStringW(debugMsg.c_str());
        }
    }

    // Load HydraDragonAVSandboxie.dll from the target folder.
    std::wstring sbieDllPath = targetFolder + L"\\HydraDragonAVSandboxie.dll";
    HMODULE hDll = LoadLibraryW(sbieDllPath.c_str());
    if (hDll)
    {
        OutputDebugStringW(L"HydraDragonAVSandboxie.dll loaded successfully.\n");

        // Retrieve the InjectDllMain function from the loaded DLL.
        typedef void(__stdcall* PFN_InjectDllMain)(HINSTANCE, ULONG_PTR);
        PFN_InjectDllMain pInjectDllMain = (PFN_InjectDllMain)GetProcAddress(hDll, "InjectDllMain");
        if (pInjectDllMain)
        {
            OutputDebugStringW(L"InjectDllMain function found. Calling it now...\n");
            // Call the function with our module handle and a parameter of 0.
            pInjectDllMain(g_hThisModule, 0);
            OutputDebugStringW(L"InjectDllMain called successfully.\n");
        }
        else
        {
            OutputDebugStringW(L"InjectDllMain function not found in HydraDragonAVSandboxie.dll.\n");
        }
    }
    else
    {
        OutputDebugStringW(L"Failed to load HydraDragonAVSandboxie.dll.\n");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Save our module handle for resource extraction.
        g_hThisModule = hModule;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
