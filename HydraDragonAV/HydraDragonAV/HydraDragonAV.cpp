//HydraDragonAV.cpp
#include "framework.h" //GUI Interface things
#include "HydraDragonAV.h" //GUI Interface things
#include <string>
#include <cmath>
#include <commdlg.h>  // Common Dialogs
#include <fstream>     // File stream
#include <array>     /// For std::array
#include <cassert>   /// For assert
#include <cstdint>   /// For uint8_t, uint32_t and uint64_t data types
#include <iomanip>   /// For std::setfill and std::setw
#include <iostream>  /// For IO operations
#include <sstream>   /// For std::stringstream
#include <utility>   /// For std::move
#include <vector>    /// For std::vector
#include <algorithm>  /// For std::copy
#include <vector>     /// For std::vector
#include <tchar.h> 
#include <stdio.h>  /// For iterate over all files in YARA_RULES_FOLDER directory
#include <strsafe.h> 
#include <regex> //// For regex replace
#include "yara\\yara.h" // For yara
#include "yara.cpp" // For yara
// Define the maximum buffer size for reading the file content
#define MAX_BUFFER_SIZE 1024
#pragma comment(lib, "yara\\libyara64.lib") // Link yara libraries with modules
#define IDC_YARA_CHECK 1006 // Define ID for the yara button
// Define the YARA rule folder paths
#define YARA_RULES_FOLDER (ExePath0() + L"signatures\\rules\\yara\\")
#define YARA_EXCLUDED_RULES_FOLDER L"signatures\\rules\\excluded_yara_rules\\"
#define MAX_LOADSTRING 100
using namespace std;

// Global variable for the file path
std::wstring g_filePath;
// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
std::wstring ExePath0() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}
std::wstring FindVirusShareFile(const std::wstring& folderPath) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((folderPath + L"\\virusshare.xz").c_str(), &findFileData);

    if (hFind != INVALID_HANDLE_VALUE) {
        FindClose(hFind);
        return folderPath + L"\\virusshare.xz";
    }

    return L""; // Return empty string if the file is not found
}
void LzmaScan() {
    // Open file dialog to select the file
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    // Initialize the OPENFILENAME structure
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = nullptr;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = nullptr;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Display the Open File dialog box
    if (GetOpenFileName(&ofn)) {
        // User selected a file, proceed with scanning
        std::wstring selectedFilePath(szFileName);

        // Check if the selected file exists
        std::ifstream selectedFile(selectedFilePath);
        if (!selectedFile) {
            MessageBoxW(nullptr, L"Selected file not found.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }

        // Find the path to the virusshare.xz file
        std::wstring virusshareFilePath = FindVirusShareFile(HASH_SIGNATURES_FOLDER);
        if (virusshareFilePath.empty()) {
            MessageBoxW(nullptr, L"Virusshare file not found.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }

        // Decompress the virusshare.xz file and extract MD5 checksums
        std::vector<std::string> virusshareMD5Checksums = DecompressLzmaFile(virusshareFilePath);

        // Calculate MD5 checksum of the selected file
        std::string selectedFileMD5 = GetMD5StringFromFile(selectedFilePath);

        // Compare MD5 checksums
        bool matchFound = std::find(virusshareMD5Checksums.begin(), virusshareMD5Checksums.end(), selectedFileMD5) != virusshareMD5Checksums.end();

        // Trigger action on match
        if (matchFound) {
            MessageBoxW(nullptr, L"Virus detected!", L"Virus Alert", MB_OK | MB_ICONWARNING);
        }
        else {
            MessageBoxW(nullptr, L"No virus detected.", L"Scan Result", MB_OK | MB_ICONINFORMATION);
        }
    }
    else {
        // User canceled file selection
        MessageBoxW(nullptr, L"File selection canceled.", L"Information", MB_OK | MB_ICONINFORMATION);
    }
}
void CheckFileWithYARA() {
    // Initialize SEH
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    // Initialize YARA library
    if (yr_initialize() != 0) {
        MessageBoxW(nullptr, L"Failed to initialize YARA library.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Load rules from YARA_RULES_FOLDER
    WIN32_FIND_DATA findFileData;
    ZeroMemory(&findFileData, sizeof(findFileData)); // Initialize findFileData with ZeroMemory
    HANDLE hFind = FindFirstFile((YARA_RULES_FOLDER + L"*.yar").c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        MessageBoxW(nullptr, L"Failed to find YARA rules in the specified folder.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }

    std::vector<YR_RULES*> rulesList;

    do {
        if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring ruleFilePath = YARA_RULES_FOLDER + std::wstring(findFileData.cFileName);
            std::ifstream ruleFile(ruleFilePath);

            if (ruleFile.is_open()) {
                std::string rule((std::istreambuf_iterator<char>(ruleFile)), std::istreambuf_iterator<char>());

                // Create the compiler
                YR_COMPILER* compiler;
                if (yr_compiler_create(&compiler) != 0) {
                    MessageBoxW(nullptr, L"Failed to create YARA compiler.", L"Error", MB_OK | MB_ICONERROR);
                    return;
                }

                if (yr_compiler_add_string(compiler, rule.c_str(), nullptr) != 0) {
                    char error_buffer[1024];
                    yr_compiler_get_error_message(compiler, error_buffer, sizeof(error_buffer));
                    std::wstring error_message = L"Failed to compile rule: " + ruleFilePath + L". Error: " + std::wstring(error_buffer, error_buffer + strlen(error_buffer));
                    MessageBoxW(nullptr, error_message.c_str(), L"Error", MB_OK | MB_ICONERROR);
                    return;
                }
                ruleFile.close();

                // Get YARA rules from the compiler
                YR_RULES* rules;
                if (yr_compiler_get_rules(compiler, &rules) != 0) {
                    MessageBoxW(nullptr, L"Failed to get rules from YARA compiler.", L"Error", MB_OK | MB_ICONERROR);
                    return;
                }

                rulesList.push_back(rules);

                yr_compiler_destroy(compiler);  // Destroy the compiler after getting the rules
            }
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);

    // Open file dialog
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        int narrowSize = WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, nullptr, 0, nullptr, nullptr);
        std::string narrowFilePath(narrowSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, &narrowFilePath[0], narrowSize, nullptr, nullptr);

        std::ifstream file(narrowFilePath, std::ios::binary);
        if (!file.is_open()) {
            MessageBoxW(nullptr, L"Failed to open the selected file.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string fileContentBuffer = buffer.str();

        // Perform YARA scan
        for (auto& rules : rulesList) {
            int scanResult = yr_rules_scan_mem(rules, reinterpret_cast<const uint8_t*>(fileContentBuffer.c_str()), fileContentBuffer.size(), 0, callbackyara, NULL, 0);
        }

        file.close();
    }
    else {
        MessageBoxW(nullptr, L"File selection canceled.", L"Information", MB_OK | MB_ICONINFORMATION);
    }

    // Cleanup
    for (auto& rules : rulesList) {
        yr_rules_destroy(rules);
    }
    yr_finalize();
}

void CalculateTLSH() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    // Initialize the OPENFILENAME structure
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    // Display the file open dialog
    if (GetOpenFileName(&ofn)) {
        // Get the file path
        std::wstring filePath(szFileName);

        // Convert the wide string to narrow string
        std::string narrowFilePath(filePath.begin(), filePath.end());

        // Open the file in binary mode
        std::ifstream file(narrowFilePath, std::ios::binary);

        if (file.is_open()) {
            // Read the entire file into a buffer
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContentBuffer = buffer.str();

            // Compute the TLSH hash
            Tlsh tlsh;
            tlsh.final((const unsigned char*)fileContentBuffer.c_str(), fileContentBuffer.size());

            // Get the TLSH hash value
            const char* tlshHash = tlsh.getHash();

            file.close();

            // Display the TLSH hash in a message box with "T1" prefix
            std::string tlshHashWithT1 = "T1" + std::string(tlshHash);
            MessageBoxA(nullptr, tlshHashWithT1.c_str(), "TLSH Hash with T1", MB_OK | MB_ICONINFORMATION);
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void CalculateSSDeep() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Convert the wide string to narrow string
        std::string narrowFilePath(g_filePath.begin(), g_filePath.end());

        // Open the file in binary mode
        std::ifstream file(narrowFilePath, std::ios::binary);

        if (file.is_open()) {
            // Read the entire file into a buffer
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContentBuffer = buffer.str();

            // Allocate a buffer for the result
            char resultBuffer[FUZZY_MAX_RESULT];

            // Compute the SSDeep hash
            int status = fuzzy_hash_buf(reinterpret_cast<const unsigned char*>(fileContentBuffer.c_str()), fileContentBuffer.size(), resultBuffer);

            file.close();

            if (status == 0) {
                // Convert the SSDeep hash to a wide string
                std::wstring wideSSDeepHash(resultBuffer, resultBuffer + FUZZY_MAX_RESULT);

                // Display the SSDeep hash in a message box
                MessageBoxW(nullptr, wideSSDeepHash.c_str(), L"SSDeep Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SSDeep calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SSDeep hash.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void CalculateSHA256() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Convert the wide string to narrow string
        std::string narrowFilePath(g_filePath.begin(), g_filePath.end());

        // Open the file in binary mode
        std::ifstream file(narrowFilePath, std::ios::binary);

        if (file.is_open()) {
            // Calculate SHA256 hash
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContent = buffer.str();

            std::string sha256Hash = hashing::sha256::sha256(fileContent);

            file.close();

            if (!sha256Hash.empty()) {
                // Convert the SHA256 hash to a wide string
                std::wstring wideSHA256Hash(sha256Hash.begin(), sha256Hash.end());

                // Display the SHA256 hash in a message box
                MessageBoxW(nullptr, wideSHA256Hash.c_str(), L"SHA256 Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SHA256 calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SHA256 hash.", L"Error", MB_OK | MB_ICONERROR);
            }
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void CalculateMD5() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Call your MD5 hash calculation function with the file path
        std::string md5Hash = GetMD5StringFromFile(g_filePath);
        if (!md5Hash.empty()) {
            // Display the MD5 hash in a message box
            MessageBoxA(nullptr, md5Hash.c_str(), "MD5 Hash", MB_OK | MB_ICONINFORMATION);
        }
        else {
            // Display an error message if MD5 calculation fails
            MessageBox(nullptr, L"Failed to calculate MD5 hash.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void CalculateSHA1() {
    OPENFILENAME ofn;
    WCHAR szFileName[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFileName;
    ofn.lpstrFile[0] = '\0';
    ofn.nMaxFile = sizeof(szFileName) / sizeof(*szFileName);
    ofn.lpstrFilter = L"All Files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn)) {
        g_filePath = szFileName;

        // Convert the wide string to narrow string
        std::string narrowFilePath(g_filePath.begin(), g_filePath.end());

        // Open the file in binary mode
        std::ifstream file(narrowFilePath, std::ios::binary);

        if (file.is_open()) {
            // Calculate SHA1 hash
            std::stringstream buffer;
            buffer << file.rdbuf();
            std::string fileContent = buffer.str();

            // Calculate SHA-1 hash
            void* sha1Signature = hashing::sha1::hash_bs(fileContent.c_str(), fileContent.size());
            std::string sha1Hex = hashing::sha1::sig2hex(sha1Signature);

            file.close();

            if (!sha1Hex.empty()) {
                // Convert the SHA1 hash to a wide string
                std::wstring wideSHA1Hash(sha1Hex.begin(), sha1Hex.end());

                // Display the SHA1 hash in a message box
                MessageBoxW(nullptr, wideSHA1Hash.c_str(), L"SHA1 Hash", MB_OK | MB_ICONINFORMATION);
            }
            else {
                // Display an error message if SHA1 calculation fails
                MessageBoxW(nullptr, L"Failed to calculate SHA1 hash.", L"Error", MB_OK | MB_ICONERROR);
            }

            // Clean up allocated memory
            delete[] sha1Signature;
        }
        else {
            // Display an error message if the file cannot be opened
            MessageBoxW(nullptr, L"Failed to open the file.", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        // Create the "Calculate MD5" button
        HWND hButtonMD5 = CreateWindow(
            L"BUTTON",
            L"Calculate MD5",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            10, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_MD5,
            hInst,
            nullptr);

        if (hButtonMD5 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SHA1" button
        HWND hButtonSHA1 = CreateWindow(
            L"BUTTON",
            L"Calculate SHA1",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            140, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SHA1,
            hInst,
            nullptr);

        if (hButtonSHA1 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SHA256" button
        HWND hButtonSHA256 = CreateWindow(
            L"BUTTON",
            L"Calculate SHA256",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            270, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SHA256,
            hInst,
            nullptr);

        if (hButtonSHA256 == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate SSDeep" button
        HWND hButtonSSDeep = CreateWindow(
            L"BUTTON",
            L"Calculate SSDeep",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            400, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_SSDEEP,
            hInst,
            nullptr);

        if (hButtonSSDeep == nullptr) {
            // Handle button creation failure
            return -1;
        }

        // Create the "Calculate TLSH" button
        HWND hButtonTLSH = CreateWindow(
            L"BUTTON",
            L"Calculate TLSH",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            530, 10, 120, 30,
            hWnd,
            (HMENU)IDC_CALCULATE_TLSH,
            hInst,
            nullptr);

        if (hButtonTLSH == nullptr) {
            // Handle button creation failure
            return -1;
        }
        // Create the "YARA Check" button
        HWND hButtonYaraCheck = CreateWindow(
            L"BUTTON",
            L"YARA Check",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            660, 10, 120, 30,
            hWnd,
            (HMENU)IDC_YARA_CHECK,
            hInst,
            nullptr);
        if (hButtonYaraCheck == nullptr) {
            // Handle button creation failure
            return -1;
        }
        // Create the "LZMA Scan" button
        HWND hButtonLzmaScan = CreateWindow(
            L"BUTTON",
            L"LZMA Scan",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            790, 10, 120, 30,
            hWnd,
            (HMENU)IDC_LZMA_SCAN,
            hInst,
            nullptr);

        if (hButtonLzmaScan == nullptr) {
            // Handle button creation failure
            return -1;
        }
        // Create the "LZMA Scan" button
        HWND hButtonLzmaCompress = CreateWindow(
            L"BUTTON",
            L"LZMA Compress",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            790, 50, 120, 30,
            hWnd,
            (HMENU)IDC_LZMA_COMPRESS,
            hInst,
            nullptr);

        if (hButtonLzmaCompress == nullptr) {
            // Handle button creation failure
            return -1;
        }
        break;
    }
    case WM_COMMAND: {
        int wmId = LOWORD(wParam);
        switch (wmId) {
        case IDC_CALCULATE_MD5:
            CalculateMD5();
            break;
        case IDC_CALCULATE_SHA256:
            CalculateSHA256();
            break;
        case IDC_CALCULATE_SSDEEP:
            CalculateSSDeep();
            break;
        case IDC_CALCULATE_SHA1:
            CalculateSHA1();
            break;
        case IDC_CALCULATE_TLSH:
            CalculateTLSH();
            break;
        case IDM_ABOUT:
            DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
            break;
        case IDC_YARA_CHECK:
            CheckFileWithYARA();
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        case IDC_LZMA_SCAN:
            LzmaScan();
            break;
        case IDC_LZMA_COMPRESS:
            XzCalling();
            break;
        }
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        // TODO: Add any drawing code that uses hdc here...
        EndPaint(hWnd, &ps);
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

ATOM MyRegisterClass(HINSTANCE hInstance) {
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_HYDRADRAGONAV));
    wcex.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEW(IDC_HYDRADRAGONAV);
    wcex.lpszClassName = szWindowClass;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow) {
    hInst = hInstance; // Store instance handle in our global variable

    HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

    if (!hWnd) {
        return FALSE;
    }

    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    return TRUE;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPWSTR lpCmdLine,
    _In_ int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_HYDRADRAGONAV, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    if (!InitInstance(hInstance, nCmdShow)) {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_HYDRADRAGONAV));

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int)msg.wParam;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}