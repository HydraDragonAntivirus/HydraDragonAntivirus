// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "resource.h"
#include <windows.h>
#include <detours/detours.h>
#include <shellapi.h>
#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <vector>
#include <string>
#include <sstream>
#include <algorithm>
#include <unordered_map>
#include <shlwapi.h>
#include <process.h>
#include <stdlib.h>
#include <mmsystem.h>
#include <winternl.h>
#include <wincrypt.h>
#include <fstream>
#include <archive.h>
#include <archive_entry.h>
#include <strsafe.h>
#include <wchar.h>
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Advapi32.lib")

constexpr unsigned long long ONE_GB = 1073741824ULL; 
constexpr unsigned long long ONE_TB = 1099511627776ULL;

// -----------------------------------------------------------------
// Global Paths and Variables
// -----------------------------------------------------------------
const WCHAR LOG_FOLDER[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs";
const WCHAR SIGMA_LOG_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEsigma_log.txt";
const WCHAR ERROR_LOG_FILE[] = L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEerror_log.txt";
const WCHAR KNOWN_EXTENSIONS_FILE[] = L"C:\\Program Files\\HydraDragonAntivirus\\knownextensions\\extensions.txt";
// The full location of diec.exe (Detect It Easy Console)
const std::wstring detectiteasy_console_path = L"C:\\Program Files\\HydraDragonAntivirus\\detectiteasy\\diec.exe";

std::vector<std::wstring> g_knownExtensions;
static bool g_bExtensionsLoaded = false;

// -----------------------------------------------------------------
// Global Module Handles
// -----------------------------------------------------------------
// Our own module handle (stored during DLL_PROCESS_ATTACH)
HMODULE g_hThisModule = NULL;

// -----------------------------------------------------------------
// Global Registry Mapping
// -----------------------------------------------------------------
CRITICAL_SECTION g_registryMapLock;
std::unordered_map<HKEY, std::wstring> g_registryKeyMap;

// Helper function: Converts a base HKEY to a string.
std::wstring GetBaseKeyName(HKEY hKey) {
    if (hKey == HKEY_CLASSES_ROOT) return L"HKEY_CLASSES_ROOT";
    else if (hKey == HKEY_CURRENT_USER) return L"HKCU";
    else if (hKey == HKEY_LOCAL_MACHINE) return L"HKLM";
    else if (hKey == HKEY_USERS) return L"HKEY_USERS";
    else if (hKey == HKEY_CURRENT_CONFIG) return L"HKEY_CURRENT_CONFIG";
    else return L"(unknown)";
}

// ===== Added Global Variable for Ransomware Detection =====
static int g_ransomware_detection_count = 0;

// -----------------------------------------------------------------
// Thread-local flag to prevent recursive logging.
// -----------------------------------------------------------------
__declspec(thread) bool g_bInLogging = false;

// Helper: Write a timestamped log entry to DONTREMOVEHomePageChange.txt.
void WriteLog(const wchar_t* message)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\DONTREMOVEHomePageChange.txt", L"a+") == 0 && f)
    {
        time_t now = time(NULL);
        struct tm tmNow;
        localtime_s(&tmNow, &now);
        wchar_t timeBuffer[64] = { 0 };
        wcsftime(timeBuffer, 64, L"%Y-%m-%d %H:%M:%S", &tmNow);
        fwprintf(f, L"[%s] %s\n", timeBuffer, message);
        fclose(f);
    }
}

// Chrome Homepage Monitoring using Registry Notifications.
// Monitors the registry key for Chrome homepage (adjust key/value as needed).
DWORD WINAPI ChromeRegistryMonitorThread(LPVOID lpParam)
{
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Google\\Chrome", 0, KEY_READ | KEY_NOTIFY, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        WriteLog(L"Chrome monitor: Failed to open registry key.");
        return 1;
    }

    while (true)
    {
        lResult = RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_LAST_SET, NULL, FALSE);
        if (lResult == ERROR_SUCCESS)
        {
            wchar_t homepage[512] = { 0 };
            DWORD bufSize = sizeof(homepage);
            lResult = RegQueryValueExW(hKey, L"Homepage", NULL, NULL, (LPBYTE)homepage, &bufSize);
            if (lResult == ERROR_SUCCESS)
            {
                wchar_t logMsg[1024] = { 0 };
                StringCchPrintfW(logMsg, 1024, L"Chrome homepage changed: %s", homepage);
                WriteLog(logMsg);
            }
            else
            {
                WriteLog(L"Chrome monitor: Homepage value changed but could not be read.");
            }
        }
        else
        {
            WriteLog(L"Chrome monitor: RegNotifyChangeKeyValue failed.");
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);

    return 0;
}

// Edge Homepage Monitoring using Registry Notifications.
// Assumes Edge homepage is stored in HKEY_CURRENT_USER\Software\Policies\Microsoft\Edge
// and the value is named "HomepageLocation" (adjust as needed).
DWORD WINAPI EdgeRegistryMonitorThread(LPVOID lpParam)
{
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Edge", 0, KEY_READ | KEY_NOTIFY, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        WriteLog(L"Edge monitor: Failed to open registry key.");
        return 1;
    }

    while (true)
    {
        lResult = RegNotifyChangeKeyValue(hKey, TRUE, REG_NOTIFY_CHANGE_LAST_SET, NULL, FALSE);
        if (lResult == ERROR_SUCCESS)
        {
            wchar_t homepage[512] = { 0 };
            DWORD bufSize = sizeof(homepage);
            lResult = RegQueryValueExW(hKey, L"HomepageLocation", NULL, NULL, (LPBYTE)homepage, &bufSize);
            if (lResult == ERROR_SUCCESS)
            {
                wchar_t logMsg[1024] = { 0 };
                StringCchPrintfW(logMsg, 1024, L"Edge homepage changed: %s", homepage);
                WriteLog(logMsg);
            }
            else
            {
                WriteLog(L"Edge monitor: Homepage value changed but could not be read.");
            }
        }
        else
        {
            WriteLog(L"Edge monitor: RegNotifyChangeKeyValue failed.");
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);

    return 0;
}

// Helper: Get the Firefox prefs.js path by scanning the Firefox Profiles directory.
// Returns an empty string if no valid prefs.js is found.
std::wstring GetFirefoxPrefsPath()
{
    wchar_t userProfile[MAX_PATH] = { 0 };
    DWORD size = GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH);
    if (size == 0 || size > MAX_PATH)
        return L"";

    // Construct the base path for Firefox profiles.
    std::wstring profilesPath = std::wstring(userProfile) + L"\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles";

    // Use FindFirstFile to enumerate directories in the Profiles folder.
    std::wstring prefsPath;
    std::wstring searchPath = profilesPath + L"\\*";
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        do
        {
            // Skip files and only consider directories (excluding "." and "..").
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
                wcscmp(findData.cFileName, L".") != 0 &&
                wcscmp(findData.cFileName, L"..") != 0)
            {
                std::wstring possiblePrefs = profilesPath + L"\\" + findData.cFileName + L"\\prefs.js";
                if (PathFileExistsW(possiblePrefs.c_str()))
                {
                    prefsPath = possiblePrefs;
                    break;  // Use the first valid profile found.
                }
            }
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
    return prefsPath;
}

// Firefox Homepage Monitoring using File Change Notifications.
// It retrieves the Firefox prefs.js path dynamically and monitors it for changes.
DWORD WINAPI FirefoxFileMonitorThread(LPVOID lpParam)
{
    std::wstring prefsFilePath = GetFirefoxPrefsPath();
    if (prefsFilePath.empty())
    {
        WriteLog(L"Firefox monitor: Could not locate prefs.js file.");
        return 1;
    }

    // Extract the directory from prefsFilePath.
    wchar_t directory[MAX_PATH] = { 0 };
    wcscpy_s(directory, prefsFilePath.c_str());
    wchar_t* pLastSlash = wcsrchr(directory, L'\\');
    if (pLastSlash)
        *pLastSlash = 0;

    // Set up directory change notification.
    HANDLE hChange = FindFirstChangeNotificationW(directory, FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE);
    if (hChange == INVALID_HANDLE_VALUE)
    {
        WriteLog(L"Firefox monitor: Failed to set up directory change notification.");
        return 1;
    }

    while (true)
    {
        DWORD waitStatus = WaitForSingleObject(hChange, INFINITE);
        if (waitStatus == WAIT_OBJECT_0)
        {
            // When a change is signaled, open prefs.js and search for the homepage setting.
            FILE* f = nullptr;
            if (_wfopen_s(&f, prefsFilePath.c_str(), L"r") == 0 && f)
            {
                wchar_t line[1024] = { 0 };
                wchar_t homepage[512] = { 0 };
                while (fgetws(line, 1024, f))
                {
                    // Look for the line containing "browser.startup.homepage"
                    if (wcsstr(line, L"browser.startup.homepage") != NULL)
                    {
                        // Expected format: user_pref("browser.startup.homepage", "http://www.example.com");
                        wchar_t* start = wcschr(line, L',');
                        if (start)
                        {
                            start++; // Skip the comma.
                            while (*start == L' ' || *start == L'\t') start++;
                            if (*start == L'"')
                            {
                                start++;
                                wchar_t* end = wcschr(start, L'"');
                                if (end)
                                {
                                    size_t len = end - start;
                                    wcsncpy_s(homepage, start, len);
                                    homepage[len] = L'\0';
                                    break;
                                }
                            }
                        }
                    }
                }
                fclose(f);

                wchar_t logMsg[1024] = { 0 };
                if (wcslen(homepage) > 0)
                    StringCchPrintfW(logMsg, 1024, L"Firefox homepage changed: %s", homepage);
                else
                    StringCchPrintfW(logMsg, 1024, L"Firefox prefs.js changed but homepage setting not found.");

                WriteLog(logMsg);
            }
            else
            {
                WriteLog(L"Firefox monitor: Failed to open prefs.js for reading.");
            }

            if (FindNextChangeNotification(hChange) == FALSE)
            {
                WriteLog(L"Firefox monitor: Failed to reset change notification.");
                break;
            }
        }
        else
        {
            WriteLog(L"Firefox monitor: WaitForSingleObject failed.");
            break;
        }
    }

    FindCloseChangeNotification(hChange);
    return 0;
}

// -----------------------------------------------------------------
// Notification Infrastructure via Shell_NotifyIcon
// -----------------------------------------------------------------
// --------------------- Notification Infrastructure ---------------------
HWND g_hNotificationWnd = NULL;

HWND CreateNotificationWindow()
{
    const wchar_t* className = L"HydraDragonNotificationWindowClass";
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = className;
    RegisterClass(&wc);
    HWND hWnd = CreateWindow(className, L"", WS_OVERLAPPED,
        CW_USEDEFAULT, CW_USEDEFAULT, 100, 100,
        NULL, NULL, wc.hInstance, NULL);
    return hWnd;
}

void TriggerNotification(const WCHAR* title, const WCHAR* msg)
{
    auto* pData = new std::pair<std::wstring, std::wstring>(title, msg);
    HANDLE hThread = CreateThread(NULL, 0,
        [](LPVOID lpParam) -> DWORD {
            auto* p = (std::pair<std::wstring, std::wstring>*)lpParam;
            // Play sound.
            PlaySound(L"C:\\Program Files\\HydraDragonAntivirus\\assets\\alert.wav",
                NULL, SND_FILENAME | SND_ASYNC);
            // Prepare notification.
            NOTIFYICONDATA nid = { 0 };
            nid.cbSize = sizeof(nid);
            nid.hWnd = g_hNotificationWnd;
            nid.uID = 1001;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_USER + 1;
            nid.hIcon = LoadIcon(NULL, IDI_WARNING);
            wcscpy_s(nid.szTip, p->first.c_str());
            Shell_NotifyIcon(NIM_ADD, &nid);
            nid.uFlags = NIF_INFO;
            wcscpy_s(nid.szInfo, p->second.c_str());
            wcscpy_s(nid.szInfoTitle, p->first.c_str());
            nid.dwInfoFlags = NIIF_WARNING;
            Shell_NotifyIcon(NIM_MODIFY, &nid);
            Sleep(5000);
            Shell_NotifyIcon(NIM_DELETE, &nid);
            delete p;
            return 0;
        },
        pData, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
}

// --------------------- End Notification Infrastructure ---------------------


// -----------------------------------------------------------------
// Asynchronous Logging for Regular Logs
// -----------------------------------------------------------------
CRITICAL_SECTION g_logLock;
std::vector<std::wstring> g_logQueue;
HANDLE g_hLogThread = NULL;
volatile bool g_bLogThreadRunning = true;

void EnsureLogDirectory()
{
    CreateDirectory(LOG_FOLDER, NULL);
}

DWORD WINAPI LoggerThreadProc(LPVOID lpParameter)
{
    while (g_bLogThreadRunning)
    {
        std::vector<std::wstring> localQueue;
        EnterCriticalSection(&g_logLock);
        if (!g_logQueue.empty())
            localQueue.swap(g_logQueue);
        LeaveCriticalSection(&g_logLock);
        if (!localQueue.empty())
        {
            EnsureLogDirectory();
            FILE* f = nullptr;
            if (_wfopen_s(&f, SIGMA_LOG_FILE, L"a+") == 0 && f)
            {
                for (const auto& msg : localQueue)
                    fwprintf(f, L"%s\n", msg.c_str());
                fclose(f);
            }
        }
    }
    return 0;
}

void QueueLogMessage(const std::wstring& message)
{
    EnterCriticalSection(&g_logLock);
    g_logQueue.push_back(message);
    LeaveCriticalSection(&g_logLock);
}

void WriteSigmaLog(const WCHAR* eventType, const WCHAR* details)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    WCHAR timeBuffer[64];
    wcsftime(timeBuffer, 64, L"%Y-%m-%dT%H:%M:%SZ", &tm_now);
    WCHAR logEntry[2048];
    _snwprintf_s(logEntry, 2048, _TRUNCATE,
        L"{\"timestamp\":\"%s\", \"event\":\"%s\", \"details\":\"%s\"}",
        timeBuffer, eventType, details);
    QueueLogMessage(logEntry);
}

void SafeWriteSigmaLog(const WCHAR* eventType, const WCHAR* details)
{
    if (g_bInLogging)
        return;
    g_bInLogging = true;
    WriteSigmaLog(eventType, details);
    g_bInLogging = false;
}

// Helper: Convert std::wstring (UTF-16) to std::string (UTF-8)
std::string WideStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, NULL, 0, NULL, NULL);
    std::vector<char> buffer(size_needed);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, buffer.data(), size_needed, NULL, NULL);
    return std::string(buffer.data());
}

// Check if a file is an archive based on its extension.
bool IsArchiveFile(const std::wstring& filePath) {
    size_t pos = filePath.find_last_of(L'.');
    if (pos != std::wstring::npos) {
        std::wstring ext = filePath.substr(pos);
        std::transform(ext.begin(), ext.end(), ext.begin(), towlower);
        if (ext == L".zip" || ext == L".7z" || ext == L".rar")
            return true;
    }
    return false;
}

// Use libarchive to sum the uncompressed size of an archive.
uint64_t GetTotalUncompressedSize(const std::wstring& archivePath) {
    uint64_t totalSize = 0;
    std::string archivePathUtf8 = WideStringToUtf8(archivePath);
    struct archive* a = archive_read_new();
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);
    if (archive_read_open_filename(a, archivePathUtf8.c_str(), 10240) != ARCHIVE_OK) {
        SafeWriteSigmaLog(L"ZipBomb", L"Failed to open archive for zip bomb check");
        archive_read_free(a);
        return 0;
    }
    struct archive_entry* entry = nullptr;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        totalSize += archive_entry_size(entry);
        archive_read_data_skip(a);
    }
    archive_read_close(a);
    archive_read_free(a);
    return totalSize;
}

// Check the given file: if it is an archive and its compressed size is small (<1GB)
// but it expands to over 1TB uncompressed, flag it as a zip bomb.
void CheckForZipBomb(const std::wstring& filePath) {
    if (!IsArchiveFile(filePath))
        return;

    // Get the compressed file size on disk.
    LARGE_INTEGER fileSize;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SafeWriteSigmaLog(L"ZipBomb", L"Failed to open archive file for zip bomb check");
        return;
    }
    if (!GetFileSizeEx(hFile, &fileSize)) {
        SafeWriteSigmaLog(L"ZipBomb", L"Failed to get file size for zip bomb check");
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    // Only check archives that are small on disk.
    if (fileSize.QuadPart < ONE_GB) {
        uint64_t totalUncompressedSize = GetTotalUncompressedSize(filePath);
        if (totalUncompressedSize > ONE_TB) {
            SafeWriteSigmaLog(L"ZipBomb", L"HEUR:Win32.ZipBomb.gen detected!");
            TriggerNotification(L"Virus Detected: HEUR:Win32.ZipBomb.gen",
                L"Archive expands to more than 1TB uncompressed");
        }
    }
}

// ===== Added Helper Functions for Ransomware Detection =====

// Checks if a file is readable by trying to open it.
bool is_readable(const std::wstring& file_path)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, file_path.c_str(), L"rb") == 0 && f != nullptr)
    {
        fclose(f);
        return true;
    }
    return false;
}

// Checks if the file has a known extension by comparing the final extension
// with the list loaded in g_knownExtensions.
bool has_known_extension(const std::wstring& file_path)
{
    std::wstring filename = PathFindFileNameW(file_path.c_str());
    size_t pos = filename.find_last_of(L'.');
    if (pos == std::wstring::npos)
        return false;
    std::wstring ext = filename.substr(pos);
    std::wstring extLower = ext;
    std::transform(extLower.begin(), extLower.end(), extLower.begin(), towlower);
    for (auto& known : g_knownExtensions)
    {
        std::wstring knownLower = known;
        std::transform(knownLower.begin(), knownLower.end(), knownLower.begin(), towlower);
        if (extLower == knownLower)
            return true;
    }
    return false;
}

// Converts the Python ransomware check to C++.
// Returns true if the file is suspected to be ransomware.
bool is_ransomware(const std::wstring& file_path)
{
    std::wstring filename = PathFindFileNameW(file_path.c_str());
    std::vector<std::wstring> parts;
    std::wstringstream wss(filename);
    std::wstring token;
    while (std::getline(wss, token, L'.'))
    {
        parts.push_back(token);
    }

    if (parts.size() < 3)
    {
        SafeWriteSigmaLog(L"is_ransomware", L"File does not have multiple extensions, not flagged as ransomware.");
        return false;
    }

    // Check the second last extension.
    std::wstring prev_ext = std::wstring(L".") + parts[parts.size() - 2];
    std::transform(prev_ext.begin(), prev_ext.end(), prev_ext.begin(), towlower);
    bool prev_known = false;
    for (auto& known : g_knownExtensions)
    {
        std::wstring knownLower = known;
        std::transform(knownLower.begin(), knownLower.end(), knownLower.begin(), towlower);
        if (prev_ext == knownLower)
        {
            prev_known = true;
            break;
        }
    }
    if (!prev_known)
    {
        SafeWriteSigmaLog(L"is_ransomware", L"Previous extension not known, file not flagged as ransomware.");
        return false;
    }

    // Check the final extension.
    std::wstring final_ext = std::wstring(L".") + parts.back();
    std::transform(final_ext.begin(), final_ext.end(), final_ext.begin(), towlower);
    bool final_known = false;
    for (auto& known : g_knownExtensions)
    {
        std::wstring knownLower = known;
        std::transform(knownLower.begin(), knownLower.end(), knownLower.begin(), towlower);
        if (final_ext == knownLower)
        {
            final_known = true;
            break;
        }
    }
    if (final_known)
    {
        SafeWriteSigmaLog(L"is_ransomware", L"Final extension is known, file not flagged as ransomware.");
        return false;
    }

    if (has_known_extension(file_path) || is_readable(file_path))
    {
        SafeWriteSigmaLog(L"is_ransomware", L"File is readable or has known extension, not flagged as ransomware.");
        return false;
    }
    else
    {
        // Use Detect It Easy with the -j argument.
        std::wstring command = L"\"" + detectiteasy_console_path + L"\" -j \"" + file_path + L"\"";
        FILE* pipe = _wpopen(command.c_str(), L"r");
        if (!pipe)
        {
            SafeWriteSigmaLog(L"is_ransomware", L"Failed to execute Detect It Easy, flagging as ransomware.");
            return true;
        }
        wchar_t buffer[128];
        std::wstring result;
        while (fgetws(buffer, 128, pipe))
            result += buffer;
        _pclose(pipe);

        // Save JSON output to a uniquely named file using _wfopen_s.
        static int detectiteasyRansomCount = 1;
        WCHAR jsonFileName[MAX_PATH];
        _snwprintf_s(jsonFileName, MAX_PATH, _TRUNCATE,
            L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\detectiteasy_ransom_%d.json", detectiteasyRansomCount);
        detectiteasyRansomCount++;
        FILE* jsonFile = nullptr;
        if (_wfopen_s(&jsonFile, jsonFileName, L"w") == 0 && jsonFile != nullptr)
        {
            fwprintf(jsonFile, L"%s", result.c_str());
            fclose(jsonFile);
        }

        // New check: if the output contains "Binary" and "Unknown: Unknown",
        // then flag the file as a ransomware encrypted file (skip PE32/PE64 checks).
        if (result.find(L"Binary") != std::wstring::npos &&
            result.find(L"Unknown: Unknown") != std::wstring::npos)
        {
            SafeWriteSigmaLog(L"is_ransomware", L"Detect It Easy output indicates a possible ransomware encrypted file.");
            return true;
        }
        else
        {
            SafeWriteSigmaLog(L"is_ransomware", L"Detect It Easy output did not confirm suspicious status.");
            return false;
        }
    }
}

// Implements the ransomware alert logic.
void ransomware_alert(const std::wstring& file_path)
{
    SafeWriteSigmaLog(L"ransomware_alert", (L"Running ransomware alert check for file: " + file_path).c_str());

    if (is_ransomware(file_path))
    {
        g_ransomware_detection_count++;
        wchar_t msg[256];
        _snwprintf_s(msg, 256, _TRUNCATE, L"File '%s' flagged as potential ransomware. Count: %d", file_path.c_str(), g_ransomware_detection_count);
        SafeWriteSigmaLog(L"ransomware_alert", msg);

        // When exactly two alerts occur, a placeholder for searching files with the same extension.
        if (g_ransomware_detection_count == 2)
        {
            LPCWSTR ext = PathFindExtensionW(file_path.c_str());
            if (ext && ext[0] != L'\0')
            {
                SafeWriteSigmaLog(L"ransomware_alert", L"Searching for files with the same extension for additional ransomware signs.");
                // (Implement directory scanning and checking for ransomware on each found file as needed.)
            }
        }

        // When detections reach a threshold, notify the user.
        if (g_ransomware_detection_count >= 10)
        {
            TriggerNotification(L"Virus Detected: HEUR:Win32.Ransom.gen@FileTrap", L"Potential ransomware detected in main file");
            SafeWriteSigmaLog(L"ransomware_alert", L"User has been notified about potential ransomware in main file.");
        }
    }
}

// Helper function: Constructs the full key path from a parent key and subkey,
// and adds it to the global registry map.
void AddRegistryKeyMapping(HKEY hParent, LPCWSTR lpSubKey, HKEY hNewKey) {
    std::wstring parentPath;
    if (hParent) {
        EnterCriticalSection(&g_registryMapLock);
        auto it = g_registryKeyMap.find(hParent);
        if (it != g_registryKeyMap.end())
            parentPath = it->second;
        else
            parentPath = GetBaseKeyName(hParent);
        LeaveCriticalSection(&g_registryMapLock);
    }
    else {
        parentPath = L"(null)";
    }
    std::wstring fullPath = parentPath;
    if (lpSubKey && lpSubKey[0] != L'\0')
        fullPath += L"\\" + std::wstring(lpSubKey);
    EnterCriticalSection(&g_registryMapLock);
    g_registryKeyMap[hNewKey] = fullPath;
    LeaveCriticalSection(&g_registryMapLock);
}

// -----------------------------------------------------------------
// Asynchronous Logging for Error Logs
// -----------------------------------------------------------------
CRITICAL_SECTION g_errorLogLock;
std::vector<std::wstring> g_errorLogQueue;
HANDLE g_hErrorLogThread = NULL;
volatile bool g_bErrorLogThreadRunning = true;

DWORD WINAPI ErrorLoggerThreadProc(LPVOID lpParameter)
{
    while (g_bErrorLogThreadRunning)
    {
        std::vector<std::wstring> localQueue;
        EnterCriticalSection(&g_errorLogLock);
        if (!g_errorLogQueue.empty())
            localQueue.swap(g_errorLogQueue);
        LeaveCriticalSection(&g_errorLogLock);
        if (!localQueue.empty())
        {
            EnsureLogDirectory();
            FILE* f = nullptr;
            if (_wfopen_s(&f, ERROR_LOG_FILE, L"a+") == 0 && f)
            {
                for (const auto& msg : localQueue)
                    fwprintf(f, L"%s\n", msg.c_str());
                fclose(f);
            }
        }
    }
    return 0;
}

void QueueErrorLogMessage(const std::wstring& message)
{
    EnterCriticalSection(&g_errorLogLock);
    g_errorLogQueue.push_back(message);
    LeaveCriticalSection(&g_errorLogLock);
}

void WriteErrorLog(const WCHAR* eventType, const WCHAR* details)
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    WCHAR timeBuffer[64];
    wcsftime(timeBuffer, 64, L"%Y-%m-%dT%H:%M:%SZ", &tm_now);
    WCHAR logEntry[2048];
    _snwprintf_s(logEntry, 2048, _TRUNCATE,
        L"{\"timestamp\":\"%s\", \"event\":\"%s\", \"details\":\"%s\"}",
        timeBuffer, eventType, details);
    QueueErrorLogMessage(logEntry);
}

// -----------------------------------------------------------------
// NormalizePath and IsOurLogFile Helper Functions
// -----------------------------------------------------------------
bool NormalizePath(std::wstring& path)
{
    const std::wstring prefix = L"\\\\?\\";
    if (path.compare(0, prefix.length(), prefix) == 0)
    {
        path = path.substr(prefix.length());
        return true;
    }
    return false;
}

bool IsOurLogFile(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring path(filePath);
    NormalizePath(path);
    std::transform(path.begin(), path.end(), path.begin(), towlower);
    // Check for our specific text log files.
    if (path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremovesigma_log.txt") != std::wstring::npos ||
        path.find(L"c:\\dontremovehydradragonantiviruslogs\\dontremoveerror_log.txt") != std::wstring::npos)
        return true;
    // For any JSON file, if it's in our logs folder, consider it ours.
    if (path.find(L"c:\\dontremovehydradragonantiviruslogs\\") != std::wstring::npos)
    {
        if (path.size() >= 5 && path.compare(path.size() - 5, 5, L".json") == 0)
            return true;
    }
    return false;
}

bool IsOurLogFileForDetection(LPCWSTR filePath)
{
    if (!filePath)
        return false;
    std::wstring path(filePath);
    const std::wstring prefix = L"\\\\?\\";
    if (path.compare(0, prefix.length(), prefix) == 0)
        path = path.substr(prefix.length());
    std::transform(path.begin(), path.end(), path.begin(), towlower);
    size_t pos = path.find_last_of(L"\\/");
    std::wstring basename = (pos != std::wstring::npos) ? path.substr(pos + 1) : path;
    // Check our text log files by name.
    if (basename == L"dontremovesigma_log.txt" ||
        basename == L"dontremoveerror_log.txt")
        return true;
    // Instead of a hardcoded JSON file name, check if the file's name ends with ".json"
    if (basename.size() >= 5 && basename.compare(basename.size() - 5, 5, L".json") == 0)
        return true;
    return false;
}

// -----------------------------------------------------------------
// Load Known Extensions from File
// -----------------------------------------------------------------

void LoadKnownExtensions()
{
    if (g_bExtensionsLoaded)
        return;

    g_knownExtensions.clear();
    FILE* f = nullptr;
    if (_wfopen_s(&f, KNOWN_EXTENSIONS_FILE, L"r") == 0 && f)
    {
        wchar_t line[256];
        while (fgetws(line, 256, f))
        {
            size_t len = wcslen(line);
            while (len > 0 && (line[len - 1] == L'\n' || line[len - 1] == L'\r'))
            {
                line[len - 1] = L'\0';
                len--;
            }
            if (len > 0)
                g_knownExtensions.push_back(line);
        }
        fclose(f);
        SafeWriteSigmaLog(L"LoadKnownExtensions", L"Known extensions loaded successfully.");
        g_bExtensionsLoaded = true;
    }
    else
    {
        WriteErrorLog(L"LoadKnownExtensions", L"Failed to open known extensions file.");
    }
}

// -----------------------------------------------------------------
// New Helper Function: CalculateMD5Hash
// -----------------------------------------------------------------
bool CalculateMD5Hash(const std::wstring& filePath, std::wstring& hashStr)
{
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    BYTE buffer[4096];
    DWORD bytesRead = 0;
    BYTE hash[16] = { 0 };
    DWORD hashLen = sizeof(hash);
    bool bSuccess = false;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
        {
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0)
            {
                if (!CryptHashData(hHash, buffer, bytesRead, 0))
                    break;
            }
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
            {
                wchar_t hexBuffer[33] = { 0 };
                for (DWORD i = 0; i < hashLen; i++)
                {
                    swprintf(hexBuffer + i * 2, 3, L"%02x", hash[i]);
                }
                hashStr = hexBuffer;
                bSuccess = true;
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return bSuccess;
}

// -----------------------------------------------------------------
// Resource Extraction and File Diffing Helper Functions
// -----------------------------------------------------------------
bool ExtractResourceToFile(HMODULE hModule, LPCTSTR lpName, LPCTSTR lpType, const std::wstring& outputPath)
{
    HRSRC hRes = FindResource(hModule, lpName, lpType);
    if (!hRes)
    {
        SafeWriteSigmaLog(L"ExtractResource", L"Failed to find resource.");
        return false;
    }
    DWORD dwSize = SizeofResource(hModule, hRes);
    if (dwSize == 0)
    {
        SafeWriteSigmaLog(L"ExtractResource", L"Resource size is zero.");
        return false;
    }
    HGLOBAL hResData = LoadResource(hModule, hRes);
    if (!hResData)
    {
        SafeWriteSigmaLog(L"ExtractResource", L"Failed to load resource.");
        return false;
    }
    LPVOID pData = LockResource(hResData);
    if (!pData)
    {
        SafeWriteSigmaLog(L"ExtractResource", L"Failed to lock resource.");
        return false;
    }
    FILE* f = nullptr;
    _wfopen_s(&f, outputPath.c_str(), L"wb");
    if (!f)
    {
        SafeWriteSigmaLog(L"ExtractResource", L"Failed to open output file for writing.");
        return false;
    }
    fwrite(pData, 1, dwSize, f);
    fclose(f);
    SafeWriteSigmaLog(L"ExtractResource", L"Resource extracted successfully.");
    return true;
}

bool LoadFileToBuffer(const std::wstring& filePath, std::vector<char>& buffer)
{
    FILE* f = nullptr;
    if (_wfopen_s(&f, filePath.c_str(), L"rb") != 0 || !f)
        return false;
    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    rewind(f);
    buffer.resize(fileSize);
    size_t bytesRead = fread(buffer.data(), 1, fileSize, f);
    fclose(f);
    return bytesRead == (size_t)fileSize;
}

std::wstring GenerateBinaryDiff(const std::vector<char>& baseline, const std::vector<char>& extracted)
{
    std::wstringstream diffStream;
    size_t minSize = (baseline.size() < extracted.size()) ? baseline.size() : extracted.size();
    for (size_t i = 0; i < minSize; i++) {
        if (baseline[i] != extracted[i]) {
            diffStream << L"Offset 0x" << std::hex << i << L": 0x"
                << std::hex << (int)(unsigned char)baseline[i]
                << L" -> 0x" << std::hex << (int)(unsigned char)extracted[i] << L"\n";
        }
    }
    if (baseline.size() != extracted.size()) {
        diffStream << L"File sizes differ. Baseline size: " << baseline.size()
            << L", Extracted size: " << extracted.size() << L"\n";
    }
    return diffStream.str();
}

bool FileExists(const std::wstring& filePath)
{
    DWORD attrib = GetFileAttributes(filePath.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

void WriteMaliciousDiffLog(const std::wstring& diff)
{
    std::wstring diffLogPath = LOG_FOLDER;
    diffLogPath += L"\\malicious_diff_log.txt";
    FILE* f = nullptr;
    _wfopen_s(&f, diffLogPath.c_str(), L"a+");
    if (f)
    {
        fwprintf(f, L"%s\n", diff.c_str());
        fclose(f);
        SafeWriteSigmaLog(L"DiffLog", L"Malicious diff log written.");
    }
    else
    {
        SafeWriteSigmaLog(L"DiffLog", L"Failed to write malicious diff log.");
    }
}

// -----------------------------------------------------------------
// MBR Monitoring Functions and Globals
// -----------------------------------------------------------------
volatile bool g_bMBRMonitorRunning = true;
HANDLE g_hMBRMonitorThread = NULL;
std::vector<char> g_baselineMBR;

std::vector<char> GetMBR()
{
    std::vector<char> mbr(512, 0);
    HANDLE hDrive = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hDrive == INVALID_HANDLE_VALUE)
        return std::vector<char>();
    DWORD bytesRead = 0;
    BOOL bRead = ReadFile(hDrive, mbr.data(), 512, &bytesRead, NULL);
    CloseHandle(hDrive);
    if (!bRead || bytesRead != 512)
        return std::vector<char>();
    return mbr;
}

DWORD WINAPI MBRMonitorThreadProc(LPVOID lpParameter)
{
    while (g_bMBRMonitorRunning)
    {
        std::vector<char> currentMBR = GetMBR();
        if (!currentMBR.empty() && currentMBR != g_baselineMBR)
        {
            SafeWriteSigmaLog(L"MBRMonitor", L"HEUR:Win32.Possible.Bootkit.MBR.gen alert");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Possible.Bootkit.MBR.gen", L"MBR has been modified");
        }
    }
    return 0;
}

// -----------------------------------------------------------------
// Registry Monitoring via RegNotifyChangeKeyValue
// -----------------------------------------------------------------
// This version uses a dedicated monitoring thread (RegistryMonitorThreadProc)
// that checks the key "HKCU\Software\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
// for any changes to the following registry values (case-insensitive):
//   DisablePerformanceMonitor
//   DisableTaskMgr
//   DisableMMC
//   DisableEventViewer
//   NoWinKeys
//   DisableSnippingTool
//   DisableMagnifier
//   DisableEaseOfAccess
//   DisableCAD
//   DisableMSCONFIG
//   DisableCMD
//   DisableRegistryTools
//
// If any value is found set to 1, a heuristic log is generated in the format:
//   HEUR:Win32.Susp.Reg.Trojan.<RegistryName>.gen
// and a notification is triggered.
// Note: Windows registry key/value names are case-insensitive, so even if the values
// are added with different letter cases than those listed below, they will still be detected.
volatile bool g_bRegistryMonitorRunning = true;
volatile bool g_bRegistrySetupMonitorRunning = true;
volatile bool g_bRegistryWinlogonShellMonitorRunning = true;
volatile bool g_bRegistryKeyboardLayoutMonitorRunning = true;
volatile bool g_bTimeMonitorRunning = true;
HANDLE g_hRegistryMonitorThread = NULL;
HANDLE g_hRegistrySetupMonitorThread = NULL;
HANDLE g_hRegistryWinlogonShellMonitorThread = NULL;
HANDLE g_hRegistryKeyboardLayoutMonitorThread = NULL;
HANDLE g_hTimeMonitorThread = NULL;

// Function to check the system date.
void CheckSystemDateAnomaly()
{
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_s(&tm_now, &now);
    int currentYear = tm_now.tm_year + 1900;  // tm_year is years since 1900

    // For real-time monitoring, assume baselineYear is the expected year (e.g., 2025).
    const int baselineYear = 2025;

    // If the current year is more than 10 years ahead of the baseline or is 2035 or later,
    // flag as malicious.
    if ((currentYear - baselineYear) > 10 || currentYear >= 2035)
    {
        SafeWriteSigmaLog(L"TimeAnomaly", L"HEUR:Win32.Trojan.Bypass.Time.gen detected: Suspicious system date");
        TriggerNotification(L"Virus Detected: HEUR:Win32.Trojan.Bypass.Time.gen", L"System time appears to be manipulated.");
    }
}

// Thread procedure to continuously monitor the system date.
DWORD WINAPI TimeMonitorThreadProc(LPVOID lpParameter)
{
    while (g_bTimeMonitorRunning)
    {
        CheckSystemDateAnomaly();
        Sleep(1000);  // Check every second. Adjust as needed.
    }
    return 0;
}

DWORD WINAPI RegistryKeyboardLayoutMonitorThreadProc(LPVOID lpParameter)
{
    while (g_bRegistryKeyboardLayoutMonitorRunning)
    {
        HKEY hKey = NULL;
        // Try to open the Keyboard Layout registry key.
        LONG lResult = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout",
            0,
            KEY_READ | KEY_NOTIFY,
            &hKey);
        if (lResult == ERROR_FILE_NOT_FOUND)
        {
            // The key has been deleted.
            SafeWriteSigmaLog(L"RegistryKeyboardLayoutMonitor",
                L"HEUR:Win32.Susp.Reg.Wiper.gen - Key deleted: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Wiper.gen",
                L"Registry key deleted: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
            break;
        }
        else if (lResult != ERROR_SUCCESS)
        {
            // Could not open key for some other reason; wait and try again.
            SafeWriteSigmaLog(L"RegistryKeyboardLayoutMonitor",
                L"Failed to open registry key: HKLM\\SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout");
            Sleep(1000);
            continue;
        }

        // Wait for any change in the key.
        lResult = RegNotifyChangeKeyValue(
            hKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE);
        if (lResult == ERROR_SUCCESS)
        {
            DWORD dwValue = 0;
            DWORD dwSize = sizeof(dwValue);
            // Query the "DisableCAD" value.
            lResult = RegQueryValueExW(hKey, L"DisableCAD", NULL, NULL, (LPBYTE)&dwValue, &dwSize);
            if (lResult == ERROR_SUCCESS && dwValue == 1)
            {
                WCHAR virusTitle[256];
                _snwprintf_s(virusTitle, 256, _TRUNCATE,
                    L"Virus Detected: HEUR:Win32.Susp.Reg.Trojan.DisableCAD.gen@Keyboard");
                SafeWriteSigmaLog(L"RegistryKeyboardLayoutMonitor", virusTitle);

                WCHAR notifMsg[256];
                _snwprintf_s(notifMsg, 256, _TRUNCATE,
                    L"Registry change detected: DisableCAD set to 1 in Keyboard Layout");
                TriggerNotification(virusTitle, notifMsg);
            }
        }
        else
        {
            WCHAR errBuffer[256];
            _snwprintf_s(errBuffer, 256, _TRUNCATE,
                L"RegNotifyChangeKeyValue error on Keyboard Layout key: %d", lResult);
            SafeWriteSigmaLog(L"RegistryKeyboardLayoutMonitor", errBuffer);
        }
        if (hKey)
            RegCloseKey(hKey);
    }
    return 0;
}

DWORD WINAPI RegistryWinlogonShellMonitorThreadProc(LPVOID lpParameter)
{
    HKEY hKey = NULL;
    // Open the Winlogon key with KEY_READ and KEY_NOTIFY access.
    LONG lResult = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0,
        KEY_READ | KEY_NOTIFY,
        &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        SafeWriteSigmaLog(L"RegistryWinlogonShellMonitor", L"Failed to open Winlogon key for monitoring.");
        return 1;
    }

    while (g_bRegistryWinlogonShellMonitorRunning)
    {
        // Wait for any change in the key.
        lResult = RegNotifyChangeKeyValue(
            hKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE);
        if (lResult == ERROR_SUCCESS)
        {
            WCHAR shellValue[1024] = { 0 };
            DWORD dwSize = sizeof(shellValue);
            lResult = RegQueryValueExW(hKey, L"Shell", NULL, NULL, (LPBYTE)shellValue, &dwSize);
            if (lResult == ERROR_SUCCESS)
            {
                // Compare the current value to "explorer.exe" (case-insensitive).
                if (_wcsicmp(shellValue, L"explorer.exe") != 0)
                {
                    // The value is not simply "explorer.exe" → trigger a heuristic alert.
                    SafeWriteSigmaLog(L"RegistryWinlogonShellMonitor",
                        L"HEUR:Win32.Susp.Reg.Trojan.Startup.SafeMode.gen");
                    WCHAR notifMsg[512];
                    _snwprintf_s(notifMsg, 512, _TRUNCATE,
                        L"Winlogon Shell value changed to: %s", shellValue);
                    TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Trojan.Startup.SafeMode.gen", notifMsg);
                }
            }
        }
        else
        {
            WCHAR errBuffer[256];
            _snwprintf_s(errBuffer, 256, _TRUNCATE,
                L"RegNotifyChangeKeyValue error on Winlogon Shell: %d", lResult);
            SafeWriteSigmaLog(L"RegistryWinlogonShellMonitor", errBuffer);
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);
    return 0;
}

DWORD WINAPI RegistrySetupMonitorThreadProc(LPVOID lpParameter)
{
    HKEY hKeySetup = NULL;

    while (g_bRegistrySetupMonitorRunning)
    {
        // Try to open the key with KEY_NOTIFY access.
        LONG lResult = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"SYSTEM\\Setup",
            0,
            KEY_READ | KEY_NOTIFY,
            &hKeySetup);

        if (lResult == ERROR_FILE_NOT_FOUND)  // Key deleted
        {
            SafeWriteSigmaLog(L"RegistrySetupMonitor", L"HEUR:Win32.Susp.Reg.Wiper.gen - Key deleted: HKLM\\SYSTEM\\Setup");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Wiper.gen", L"Registry key deleted: HKLM\\SYSTEM\\Setup");
            break;
        }
        else if (lResult != ERROR_SUCCESS)
        {
            SafeWriteSigmaLog(L"RegistrySetupMonitor", L"Failed to open HKLM\\SYSTEM\\Setup for monitoring.");
            return 1;
        }

        bool suspicious = false;
        std::wstring details;

        // --- Check CmdLine: if not empty ---
        WCHAR cmdLineValue[1024] = { 0 };
        DWORD dwSize = sizeof(cmdLineValue);
        lResult = RegQueryValueExW(hKeySetup, L"CmdLine", NULL, NULL, (LPBYTE)cmdLineValue, &dwSize);
        if (lResult == ERROR_SUCCESS && cmdLineValue[0] != L'\0')
        {
            suspicious = true;
            details += L"CmdLine not empty; ";
        }

        // --- Check OOBEInProgress ---
        DWORD oobeValue = 0;
        dwSize = sizeof(oobeValue);
        lResult = RegQueryValueExW(hKeySetup, L"OOBEInProgress", NULL, NULL, (LPBYTE)&oobeValue, &dwSize);
        if (lResult == ERROR_SUCCESS && oobeValue == 1)
        {
            suspicious = true;
            details += L"OOBEInProgress=1; ";
        }

        // --- Check SystemSetupInProgress ---
        DWORD sysSetupValue = 0;
        dwSize = sizeof(sysSetupValue);
        lResult = RegQueryValueExW(hKeySetup, L"SystemSetupInProgress", NULL, NULL, (LPBYTE)&sysSetupValue, &dwSize);
        if (lResult == ERROR_SUCCESS && sysSetupValue == 1)
        {
            suspicious = true;
            details += L"SystemSetupInProgress=1; ";
        }

        // --- Check SetupType ---
        DWORD setupTypeValue = 0;
        dwSize = sizeof(setupTypeValue);
        lResult = RegQueryValueExW(hKeySetup, L"SetupType", NULL, NULL, (LPBYTE)&setupTypeValue, &dwSize);
        if (lResult == ERROR_SUCCESS && setupTypeValue == 2)
        {
            suspicious = true;
            details += L"SetupType=2; ";
        }

        // If any condition is met, trigger a single alert.
        if (suspicious)
        {
            SafeWriteSigmaLog(L"RegistrySetupMonitor",
                L"HEUR:Win32.Susp.Reg.Trojan.Startup.Setup.gen");
            WCHAR notifMsg[512];
            _snwprintf_s(notifMsg, 512, _TRUNCATE,
                L"Registry change detected: %s", details.c_str());
            TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Trojan.Startup.Setup.gen", notifMsg);
        }

        // Wait for any change in the key.
        lResult = RegNotifyChangeKeyValue(
            hKeySetup,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE);

        if (lResult != ERROR_SUCCESS)
        {
            WCHAR errBuffer[256];
            _snwprintf_s(errBuffer, 256, _TRUNCATE,
                L"RegNotifyChangeKeyValue error on HKLM\\SYSTEM\\Setup: %d", lResult);
            SafeWriteSigmaLog(L"RegistrySetupMonitor", errBuffer);
            break;
        }
    }

    if (hKeySetup)
        RegCloseKey(hKeySetup);
    return 0;
}

DWORD WINAPI RegistryMonitorThreadProc(LPVOID lpParameter)
{
    HKEY hKey = NULL;

    while (g_bRegistryMonitorRunning)
    {
        // Try to open the key with KEY_NOTIFY access.
        LONG lResult = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            KEY_READ | KEY_NOTIFY,
            &hKey);

        if (lResult == ERROR_FILE_NOT_FOUND)  // Key deleted
        {
            SafeWriteSigmaLog(L"RegistryMonitor", L"HEUR:Win32.Susp.Reg.Wiper.gen - Key deleted: HKCU\\Policies\\System");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Wiper.gen", L"Registry key deleted: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
            break;
        }
        else if (lResult != ERROR_SUCCESS)
        {
            SafeWriteSigmaLog(L"RegistryMonitor", L"Failed to open registry key for monitoring.");
            return 1;
        }

        const WCHAR* monitoredValues[] = {
            L"DisablePerformanceMonitor",
            L"DisableTaskMgr",
            L"DisableMMC",
            L"DisableEventViewer",
            L"NoWinKeys",
            L"DisableSnippingTool",
            L"DisableMagnifier",
            L"DisableEaseOfAccess",
            L"DisableCAD",
            L"DisableMSCONFIG",
            L"DisableCMD",
            L"DisableRegistryTools"
        };
        const int numValues = sizeof(monitoredValues) / sizeof(monitoredValues[0]);

        // Wait for any change in the key.
        lResult = RegNotifyChangeKeyValue(
            hKey,
            FALSE,
            REG_NOTIFY_CHANGE_LAST_SET,
            NULL,
            FALSE);

        if (lResult == ERROR_SUCCESS)
        {
            for (int i = 0; i < numValues; i++)
            {
                DWORD dwValue = 0;
                DWORD dwSize = sizeof(dwValue);
                lResult = RegQueryValueExW(hKey, monitoredValues[i], NULL, NULL, (LPBYTE)&dwValue, &dwSize);
                if (lResult == ERROR_SUCCESS && dwValue == 1)
                {
                    WCHAR logMsg[256];
                    _snwprintf_s(logMsg, 256, _TRUNCATE,
                        L"HEUR:Win32.Susp.Reg.Trojan.%s.gen", monitoredValues[i]);
                    SafeWriteSigmaLog(L"RegistryMonitor", logMsg);

                    WCHAR virusTitle[256];
                    _snwprintf_s(virusTitle, 256, _TRUNCATE,
                        L"Virus Detected: %s", logMsg);

                    WCHAR notifMsg[256];
                    _snwprintf_s(notifMsg, 256, _TRUNCATE,
                        L"Registry change detected: %s set to 1", monitoredValues[i]);
                    TriggerNotification(virusTitle, notifMsg);
                }
            }
        }
        else
        {
            WCHAR errBuffer[256];
            _snwprintf_s(errBuffer, 256, _TRUNCATE, L"RegNotifyChangeKeyValue error: %d", lResult);
            SafeWriteSigmaLog(L"RegistryMonitor", errBuffer);
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);
    return 0;
}

// -----------------------------------------------------------------
// Hook for RemoveDirectoryW to detect folder deletion.
// -----------------------------------------------------------------
typedef BOOL(WINAPI* RemoveDirectoryW_t)(LPCWSTR);
static RemoveDirectoryW_t TrueRemoveDirectoryW = RemoveDirectoryW;

BOOL WINAPI HookedRemoveDirectoryW(LPCWSTR lpPathName)
{
    if (lpPathName)
    {
        std::wstring path(lpPathName);
        NormalizePath(path);
        std::transform(path.begin(), path.end(), path.begin(), towlower);
        if (path.find(L"c:\\dontremovehydradragonantiviruslogs") != std::wstring::npos)
        {
            SafeWriteSigmaLog(L"RemoveDirectoryW", L"HEUR:Win32.Trojan.Wiper.Log.gen@FileTrap - Log directory deletion detected");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Trojan.Wiper.Log.gen@FileTrap", L"Warning: Log directory was deleted (Wiper behavior detected)");
        }
    }
    return TrueRemoveDirectoryW(lpPathName);
}

// -----------------------------------------------------------------
// Registry Hooks
// -----------------------------------------------------------------

// --- Hooked RegSetValueExW ---
// In this modified version, the registry hook logs the call but does not perform
// individual detection. The centralized RegistryMonitorThreadProc now handles detection.
typedef LSTATUS(WINAPI* RegSetValueExW_t)(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD);
static RegSetValueExW_t TrueRegSetValueExW = RegSetValueExW;

LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType,
    const BYTE* lpData, DWORD cbData)
{
    // Retrieve full key path from the global mapping.
    std::wstring fullKeyPath;
    EnterCriticalSection(&g_registryMapLock);
    auto it = g_registryKeyMap.find(hKey);
    if (it != g_registryKeyMap.end())
        fullKeyPath = it->second;
    LeaveCriticalSection(&g_registryMapLock);

    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegSetValueExW called: KeyPath = %s, ValueName = %s, Type = %u, DataSize = %u",
        fullKeyPath.c_str(), lpValueName ? lpValueName : L"(null)", dwType, cbData);
    SafeWriteSigmaLog(L"RegSetValueExW", buffer);

    // Call the original function without additional registry callback detection.
    return TrueRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

// --- Hooked RegCreateKeyExW ---
typedef LSTATUS(WINAPI* RegCreateKeyExW_t)(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD);
static RegCreateKeyExW_t TrueRegCreateKeyExW = RegCreateKeyExW;

LSTATUS WINAPI HookedRegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass,
    DWORD dwOptions, REGSAM samDesired, const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY phkResult, LPDWORD lpdwDisposition)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegCreateKeyExW called: SubKey = %s", lpSubKey ? lpSubKey : L"(null)");
    SafeWriteSigmaLog(L"RegCreateKeyExW", buffer);

    LSTATUS status = TrueRegCreateKeyExW(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired,
        lpSecurityAttributes, phkResult, lpdwDisposition);

    if (status == ERROR_SUCCESS && phkResult && *phkResult) {
        AddRegistryKeyMapping(hKey, lpSubKey, *phkResult);
    }
    return status;
}

// --- Hooked RegOpenKeyExW ---
typedef LSTATUS(WINAPI* RegOpenKeyExW_t)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
static RegOpenKeyExW_t TrueRegOpenKeyExW = RegOpenKeyExW;

LSTATUS WINAPI HookedRegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"RegOpenKeyExW called: SubKey = %s", lpSubKey ? lpSubKey : L"(null)");
    SafeWriteSigmaLog(L"RegOpenKeyExW", buffer);

    LSTATUS status = TrueRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    if (status == ERROR_SUCCESS && phkResult && *phkResult)
    {
        AddRegistryKeyMapping(hKey, lpSubKey, *phkResult);
    }
    return status;
}

// -----------------------------------------------------------------
// Other Hooks (DeleteFileW, CreateFileW, WriteFile, MoveFileW, etc.)
// -----------------------------------------------------------------
typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
static DeleteFileW_t TrueDeleteFileW = DeleteFileW;

BOOL WINAPI HookedDeleteFileW(LPCWSTR lpFileName)
{
    if (lpFileName)
    {
        if (IsOurLogFileForDetection(lpFileName))
        {
            SafeWriteSigmaLog(L"DeleteFileW", L"HEUR:Win32.Trojan.Wiper.Log.gen - Log file deletion detected");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Trojan.Wiper.Log.gen", L"Warning: A log file was deleted (Wiper behavior detected)");
        }
        else
        {
            WCHAR buffer[1024];
            _snwprintf_s(buffer, 1024, _TRUNCATE,
                L"DeleteFileW called: FileName = %s", lpFileName);
            SafeWriteSigmaLog(L"DeleteFileW", buffer);
        }
    }
    else
    {
        SafeWriteSigmaLog(L"DeleteFileW", L"DeleteFileW called: FileName = (null)");
    }
    return TrueDeleteFileW(lpFileName);
}

// Define NtQuerySystemInformation function pointer type.
typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// Structure for boot environment information.
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    BOOLEAN BootInTestSignMode;
    BOOLEAN BootRomImage;
    BOOLEAN BootDebugEnabled;
    BOOLEAN BootDoubleCheck;
    BOOLEAN BootDisplay;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, * PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

// Check if test signing mode is enabled using Windows API.
bool IsTestSigningEnabled()
{
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (!hNtdll)
        return false;

    NtQuerySystemInformation_t NtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation)
        return false;

    SYSTEM_BOOT_ENVIRONMENT_INFORMATION bootInfo = { 0 };
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)23, &bootInfo, sizeof(bootInfo), NULL);
    if (status != 0)
        return false;
    return (bootInfo.BootInTestSignMode != 0);
}

// Helper: check if a string ends with ".sys"
bool endsWithSys(const std::wstring& str)
{
    return (str.size() >= 4 && 0 == str.compare(str.size() - 4, 4, L".sys"));
}

// Helper: Check file signature via PowerShell.
// Returns true if the signature is valid (and no issues are found).
bool CheckSignature(const std::wstring& filePath, std::wstring& status)
{
    std::wstring psCommand = L"(Get-AuthenticodeSignature \"" + filePath + L"\").Status";
    std::wstring fullCommand = L"powershell.exe -Command " + psCommand;

    FILE* pipe = _wpopen(fullCommand.c_str(), L"r");
    if (!pipe)
    {
        status = L"Failed to run PowerShell command";
        return false;
    }
    wchar_t buffer[256];
    std::wstring output;
    while (fgetws(buffer, 256, pipe))
        output += buffer;
    _pclose(pipe);

    size_t start = output.find_first_not_of(L" \n\r\t");
    size_t end = output.find_last_not_of(L" \n\r\t");
    if (start != std::wstring::npos && end != std::wstring::npos)
        output = output.substr(start, end - start + 1);
    status = output;

    bool isValid = (output.find(L"Valid") != std::wstring::npos);
    bool issues = (output.find(L"HashMismatch") != std::wstring::npos ||
        output.find(L"NotTrusted") != std::wstring::npos);
    return (isValid && !issues);
}

// Helper: Check if signature verification is manipulated using certutil.
// If certutil output contains "Bypass" or "Manipulated", we treat the check as manipulated.
bool IsSignatureCheckManipulated(const std::wstring& filePath, std::wstring& certOutput)
{
    std::wstring command = L"certutil -verify \"" + filePath + L"\"";
    FILE* pipe = _wpopen(command.c_str(), L"r");
    if (!pipe)
    {
        certOutput = L"Failed to execute certutil";
        return false;
    }
    wchar_t buffer[256];
    std::wstring output;
    while (fgetws(buffer, 256, pipe))
        output += buffer;
    _pclose(pipe);
    certOutput = output;
    if (output.find(L"Bypass") != std::wstring::npos ||
        output.find(L"Manipulated") != std::wstring::npos)
    {
        return true;
    }
    return false;
}

// Updated function to check unsigned driver (for .sys files)
void CheckUnsignedDriver(const std::wstring& filePath)
{
    if (!endsWithSys(filePath))
        return;

    // Check if test signing mode is enabled.
    static bool testModeFlagged = false;
    if (IsTestSigningEnabled())
    {
        if (!testModeFlagged)
        {
            testModeFlagged = true;
            return; // First time in test mode; do not flag.
        }
    }

    // Use PowerShell to check the file's digital signature.
    std::wstring signatureStatus;
    bool isSignatureValid = CheckSignature(filePath, signatureStatus);
    if (isSignatureValid)
    {
        SafeWriteSigmaLog(L"CheckUnsignedDriver", L"File signature is valid, no unsigned driver detected.");
        return;
    }
    else
    {
        std::wstring logMsg = L"File signature check failed: " + signatureStatus;
        SafeWriteSigmaLog(L"CheckUnsignedDriver", logMsg.c_str());
    }

    // Use certutil to check if the signature verification is manipulated.
    std::wstring certOutput;
    if (IsSignatureCheckManipulated(filePath, certOutput))
    {
        SafeWriteSigmaLog(L"CheckUnsignedDriver", L"Signature check manipulated detected: HEUR:Win32.Trojan.Bypass.Signing.gen");
        TriggerNotification(L"Unsigned Driver Detected", L"HEUR:Win32.Trojan.Bypass.Signing.gen");
        return;
    }

    // Run Detect It Easy (diec.exe) with the -j argument to obtain JSON output.
    std::wstring command = L"\"" + detectiteasy_console_path + L"\" -j \"" + filePath + L"\"";
    FILE* pipe = _wpopen(command.c_str(), L"r");
    if (!pipe)
    {
        SafeWriteSigmaLog(L"CheckUnsignedDriver", L"Failed to execute detectiteasy command");
        return;
    }
    wchar_t buffer[256];
    std::wstring jsonResult;
    while (fgetws(buffer, 256, pipe))
        jsonResult += buffer;
    _pclose(pipe);

    // Save the JSON output to a uniquely named file using _wfopen_s.
    static int detectiteasyCount = 1;
    WCHAR jsonFileName[MAX_PATH];
    _snwprintf_s(jsonFileName, MAX_PATH, _TRUNCATE,
        L"C:\\DONTREMOVEHydraDragonAntivirusLogs\\detectiteasy_%d.json", detectiteasyCount);
    detectiteasyCount++;

    FILE* jsonFile = nullptr;
    if (_wfopen_s(&jsonFile, jsonFileName, L"w") == 0 && jsonFile != nullptr)
    {
        fwprintf(jsonFile, L"%s", jsonResult.c_str());
        fclose(jsonFile);
    }

    // Check JSON output for PE markers.
    bool isPE32 = (jsonResult.find(L"PE32") != std::wstring::npos);
    bool isPE64 = (jsonResult.find(L"PE64") != std::wstring::npos);

    if (isPE32)
    {
        SafeWriteSigmaLog(L"UnsignedDriverCheck", L"HEUR:Win32.Possible.Rootkit.gen detected");
        TriggerNotification(L"Unsigned Driver Detected", L"HEUR:Win32.Possible.Rootkit.gen");
    }
    else if (isPE64)
    {
        SafeWriteSigmaLog(L"UnsignedDriverCheck", L"HEUR:Win64.Possible.Rootkit.gen detected");
        TriggerNotification(L"Unsigned Driver Detected", L"HEUR:Win64.Possible.Rootkit.gen");
    }
}

typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static CreateFileW_t TrueCreateFileW = CreateFileW;

// Modify your existing HookedCreateFileW hook to call CheckForZipBomb.
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    if (!IsOurLogFile(lpFileName))
    {
        WCHAR buffer[1024];
        _snwprintf_s(buffer, 1024, _TRUNCATE,
            L"CreateFileW called: FileName = %s, Access = 0x%X, Disposition = %u",
            lpFileName ? lpFileName : L"(null)", dwDesiredAccess, dwCreationDisposition);
        SafeWriteSigmaLog(L"CreateFileW", buffer);

        // Existing: Check for unsigned driver or ransomware.
        if (lpFileName)
        {
            std::wstring filePath(lpFileName);
            if (endsWithSys(filePath))
                CheckUnsignedDriver(filePath);
            ransomware_alert(filePath);

            // NEW: If the new file is an archive, check for zip bombs.
            if (IsArchiveFile(filePath)) {
                CheckForZipBomb(filePath);
            }
        }
    }
    return TrueCreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

typedef BOOL(WINAPI* WriteFile_t)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static WriteFile_t TrueWriteFile = WriteFile;

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    WCHAR filePath[512] = L"(unknown)";
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD ret = GetFinalPathNameByHandleW(hFile, filePath, 512, FILE_NAME_NORMALIZED);
        if (ret == 0)
            wcscpy_s(filePath, 512, L"(unknown)");
    }
    if (!IsOurLogFile(filePath))
    {
        WCHAR buffer[1024];
        _snwprintf_s(buffer, 1024, _TRUNCATE,
            L"WriteFile called: File = %s, BytesToWrite = %u", filePath, nNumberOfBytesToWrite);
        SafeWriteSigmaLog(L"WriteFile", buffer);
    }
    return TrueWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

typedef BOOL(WINAPI* MoveFileW_t)(LPCWSTR, LPCWSTR);
static MoveFileW_t TrueMoveFileW = MoveFileW;

BOOL WINAPI HookedMoveFileW(LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"MoveFileW called: From = %s To = %s",
        lpExistingFileName ? lpExistingFileName : L"(null)",
        lpNewFileName ? lpNewFileName : L"(null)");
    SafeWriteSigmaLog(L"MoveFileW", buffer);
    return TrueMoveFileW(lpExistingFileName, lpNewFileName);
}

// -----------------------------------------------------------------
// Sandboxie SBIE API Hooking (unchanged)
// -----------------------------------------------------------------
typedef void* (__stdcall* P_SbieDll_Hook)(const char*, void*, void*);
typedef LONG(WINAPI* P_SbieDll_UpdateConf)(WCHAR, const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*);
static P_SbieDll_UpdateConf TrueSbieDll_UpdateConf = NULL;

LONG WINAPI HookedSbieDll_UpdateConf(WCHAR operation_code, const WCHAR* password,
    const WCHAR* section_name, const WCHAR* setting_name, const WCHAR* value)
{
    WCHAR buffer[1024];
    _snwprintf_s(buffer, 1024, _TRUNCATE,
        L"SbieDll_UpdateConf called: op=%c, section=%s, setting=%s, value=%s",
        operation_code, section_name ? section_name : L"(null)",
        setting_name ? setting_name : L"(null)",
        value ? value : L"(null)");
    SafeWriteSigmaLog(L"SbieDll_UpdateConf", buffer);
    return TrueSbieDll_UpdateConf(operation_code, password, section_name, setting_name, value);
}

typedef BOOLEAN(__stdcall* P_SbieDll_RegisterDllCallback)(void(__stdcall*)(const WCHAR*, HMODULE));
void __stdcall MyDllCallback(const WCHAR* ImageName, HMODULE ImageBase)
{
    WCHAR details[512];
    _snwprintf_s(details, 512, _TRUNCATE,
        L"ImageName: %s, ModuleBase: 0x%p", ImageName, ImageBase);
    SafeWriteSigmaLog(L"DLL_Event", details);
}

// Global variables for file trap monitoring.
volatile bool g_bFileTrapMonitorRunning = true;
HANDLE g_hFileTrapMonitorThread = NULL;

DWORD WINAPI FileTrapMonitorThreadProc(LPVOID lpParameter)
{
    // Build full paths for the extracted and baseline files.
    std::wstring extractedFilePath = LOG_FOLDER;
    extractedFilePath += L"\\DONTREMOVEHydraDragonFileTrap.exe";
    std::wstring baselineFilePath = LOG_FOLDER;
    baselineFilePath += L"\\baseline_DONTREMOVEHydraDragonFileTrap.exe";

    while (g_bFileTrapMonitorRunning)
    {
        Sleep(5000); // Check every 5 seconds (adjust as necessary)

        // Only perform the check if both files exist.
        if (FileExists(baselineFilePath) && FileExists(extractedFilePath))
        {
            std::wstring baselineHash, extractedHash;
            if (CalculateMD5Hash(baselineFilePath, baselineHash) &&
                CalculateMD5Hash(extractedFilePath, extractedHash))
            {
                if (baselineHash != extractedHash)
                {
                    // A hash mismatch is detected: generate and log a binary diff.
                    std::vector<char> baselineBuffer, extractedBuffer;
                    if (LoadFileToBuffer(baselineFilePath, baselineBuffer) &&
                        LoadFileToBuffer(extractedFilePath, extractedBuffer))
                    {
                        std::wstring diff = GenerateBinaryDiff(baselineBuffer, extractedBuffer);
                        SafeWriteSigmaLog(L"FileTrap", L"HEUR:Win32.Trojan.Injector.gen@FileTrap - Hash mismatch detected.");
                        WriteMaliciousDiffLog(diff);
                        TriggerNotification(L"FileTrap Real-Time Alert", L"HEUR:Win32.Trojan.Injector.gen@FileTrap - Hash mismatch detected. Possible file injection attempt detected!");
                    }
                }
            }
            else
            {
                SafeWriteSigmaLog(L"FileTrap", L"Failed to calculate file hashes during monitoring.");
            }
        }
    }
    return 0;
}

// Function to start the file trap monitor thread.
void StartFileTrapMonitor()
{
    g_hFileTrapMonitorThread = CreateThread(
        NULL, 0, FileTrapMonitorThreadProc, NULL, 0, NULL);
    if (g_hFileTrapMonitorThread)
    {
        SafeWriteSigmaLog(L"FileTrapMonitor", L"File trap monitoring thread started.");
    }
    else
    {
        SafeWriteSigmaLog(L"FileTrapMonitor", L"Failed to start file trap monitoring thread.");
    }
}

static HMODULE g_hSbieDll = NULL;
// ------------------ InjectDllMain ------------------
extern "C" __declspec(dllexport) void __stdcall InjectDllMain(HINSTANCE hSbieDll, ULONG_PTR UnusedParameter)
{
    // Enter function
    SafeWriteSigmaLog(L"InjectDllMain", L"Entered InjectDllMain");

    // Save the Sandboxie DLL handle.
    g_hSbieDll = hSbieDll;
    WCHAR buffer[256];
    _snwprintf_s(buffer, 256, _TRUNCATE, L"InjectDllMain called. SbieDll handle: 0x%p", hSbieDll);
    SafeWriteSigmaLog(L"InjectDllMain", buffer);

    // Verify that our own module handle has been initialized.
    if (!g_hThisModule)
    {
        SafeWriteSigmaLog(L"InjectDllMain", L"g_hThisModule is not initialized.");
        return;
    }

    // Extract the embedded resource "DONTREMOVEHydraDragonFileTrap.exe" and check for modifications.
    {
        std::wstring extractedFilePath = LOG_FOLDER;
        extractedFilePath += L"\\DONTREMOVEHydraDragonFileTrap.exe";
        // Extract the resource using our stored module handle.
        if (ExtractResourceToFile(g_hThisModule, MAKEINTRESOURCE(IDR_HYDRA_DRAGON_FILETRAP), RT_RCDATA, extractedFilePath))
        {
            std::wstring baselineFilePath = LOG_FOLDER;
            baselineFilePath += L"\\baseline_DONTREMOVEHydraDragonFileTrap.exe";
            if (!FileExists(baselineFilePath))
            {
                // No baseline exists: copy the extracted file as the baseline.
                CopyFile(extractedFilePath.c_str(), baselineFilePath.c_str(), FALSE);
                SafeWriteSigmaLog(L"Baseline", L"Baseline file created.");
            }
            else
            {
                std::wstring baselineHash, extractedHash;
                if (CalculateMD5Hash(baselineFilePath, baselineHash) &&
                    CalculateMD5Hash(extractedFilePath, extractedHash))
                {
                    if (baselineHash != extractedHash)
                    {
                        // Hash mismatch detected: load file buffers and generate diff.
                        std::vector<char> baselineBuffer, extractedBuffer;
                        if (LoadFileToBuffer(baselineFilePath, baselineBuffer) &&
                            LoadFileToBuffer(extractedFilePath, extractedBuffer))
                        {
                            std::wstring diff = GenerateBinaryDiff(baselineBuffer, extractedBuffer);
                            SafeWriteSigmaLog(L"FileTrap", L"HEUR:Win32.Trojan.Injector.gen@FileTrap - Hash mismatch detected.");
                            WriteMaliciousDiffLog(diff);
                        }
                    }
                    else
                    {
                        SafeWriteSigmaLog(L"FileTrap", L"No hash mismatch detected.");
                    }
                }
                else
                {
                    SafeWriteSigmaLog(L"HashCalculation", L"Failed to compute file hashes.");
                }
            }
        }
        else
        {
            SafeWriteSigmaLog(L"FileTrap", L"Failed to extract resource DONTREMOVEHydraDragonFileTrap.exe");
        }
    }

    // Load known extensions and digital signature checking modules.
    LoadKnownExtensions();
    SafeWriteSigmaLog(L"InjectDllMain", L"Digital signature and unsigned driver checking modules loaded.");

    // Register the Sandboxie callback.
    P_SbieDll_RegisterDllCallback p_RegisterDllCallback =
        (P_SbieDll_RegisterDllCallback)GetProcAddress(hSbieDll, "SbieDll_RegisterDllCallback");
    if (p_RegisterDllCallback)
    {
        BOOLEAN result = p_RegisterDllCallback(MyDllCallback);
        if (result)
            SafeWriteSigmaLog(L"RegisterDllCallback", L"Callback registered successfully.");
        else
            SafeWriteSigmaLog(L"RegisterDllCallback", L"Callback registration failed.");
    }
    else
    {
        SafeWriteSigmaLog(L"RegisterDllCallback", L"Failed to retrieve SbieDll_RegisterDllCallback address.");
    }

    // Retrieve and hook Sandboxie's API.
    P_SbieDll_Hook p_SbieDll_Hook = (P_SbieDll_Hook)GetProcAddress(hSbieDll, "SbieDll_Hook");
    if (p_SbieDll_Hook)
    {
        TrueSbieDll_UpdateConf = (P_SbieDll_UpdateConf)
            p_SbieDll_Hook("SbieDll_UpdateConf", GetProcAddress(hSbieDll, "SbieDll_UpdateConf"), HookedSbieDll_UpdateConf);
        if (TrueSbieDll_UpdateConf)
            SafeWriteSigmaLog(L"SbieDll_UpdateConf", L"Hooked successfully.");
        else
            SafeWriteSigmaLog(L"SbieDll_UpdateConf", L"Failed to hook.");
    }
    else
    {
        SafeWriteSigmaLog(L"SbieDll_Hook", L"Failed to retrieve SbieDll_Hook address.");
    }

    // Create the notification window.
    g_hNotificationWnd = CreateNotificationWindow();

    // Start asynchronous logging threads.
    g_hLogThread = CreateThread(NULL, 0, LoggerThreadProc, NULL, 0, NULL);
    g_hErrorLogThread = CreateThread(NULL, 0, ErrorLoggerThreadProc, NULL, 0, NULL);

    // Start MBR monitoring.
    std::vector<char> g_baselineMBR = GetMBR();
    if (!g_baselineMBR.empty())
    {
        g_hMBRMonitorThread = CreateThread(NULL, 0, MBRMonitorThreadProc, NULL, 0, NULL);
    }
    else
    {
        SafeWriteSigmaLog(L"MBRMonitor", L"Failed to read baseline MBR.");
    }

    // Start Registry monitoring for HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System.
    g_hRegistryMonitorThread = CreateThread(NULL, 0, RegistryMonitorThreadProc, NULL, 0, NULL);

    // Start Registry monitoring for HKLM\SYSTEM\Setup.
    g_hRegistrySetupMonitorThread = CreateThread(NULL, 0, RegistrySetupMonitorThreadProc, NULL, 0, NULL);
    if (!g_hRegistrySetupMonitorThread)
    {
        SafeWriteSigmaLog(L"RegistrySetupMonitor", L"Failed to start RegistrySetupMonitor thread.");
    }

    // Start Winlogon Shell monitoring for HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon.
    g_hRegistryWinlogonShellMonitorThread = CreateThread(NULL, 0, RegistryWinlogonShellMonitorThreadProc, NULL, 0, NULL);
    if (!g_hRegistryWinlogonShellMonitorThread)
    {
        SafeWriteSigmaLog(L"RegistryWinlogonShellMonitor", L"Failed to start RegistryWinlogonShellMonitor thread.");
    }

    // Start Registry monitoring for HKLM\SYSTEM\CurrentControlSet\Control\Keyboard Layout.
    g_hRegistryKeyboardLayoutMonitorThread = CreateThread(NULL, 0, RegistryKeyboardLayoutMonitorThreadProc, NULL, 0, NULL);
    if (!g_hRegistryKeyboardLayoutMonitorThread)
    {
        SafeWriteSigmaLog(L"RegistryKeyboardLayoutMonitor", L"Failed to start RegistryKeyboardLayoutMonitor thread.");
    }

    // Start the Time Monitor thread for system date checks.
    g_hTimeMonitorThread = CreateThread(NULL, 0, TimeMonitorThreadProc, NULL, 0, NULL);
    if (!g_hTimeMonitorThread)
    {
        SafeWriteSigmaLog(L"TimeMonitor", L"Failed to start TimeMonitorThread.");
    }

    // ***** Added: Create browser homepage monitoring threads *****
    HANDLE hChromeThread = CreateThread(NULL, 0, ChromeRegistryMonitorThread, NULL, 0, NULL);
    HANDLE hEdgeThread = CreateThread(NULL, 0, EdgeRegistryMonitorThread, NULL, 0, NULL);
    HANDLE hFirefoxThread = CreateThread(NULL, 0, FirefoxFileMonitorThread, NULL, 0, NULL);

    OutputDebugString(L"InjectDllMain completed successfully.\n");
}

// ------------------ DllMain ------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Save our own module handle for resource extraction.
        g_hThisModule = hModule;
        // Disable thread notifications to reduce overhead.
        DisableThreadLibraryCalls(hModule);

        // Initialize critical sections.
        InitializeCriticalSection(&g_logLock);
        InitializeCriticalSection(&g_errorLogLock);
        InitializeCriticalSection(&g_registryMapLock);

        // Queue the initial log message.
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_ATTACH\"}");

        // Create the log directory and start the logging threads.
        EnsureLogDirectory();
        g_bLogThreadRunning = true;
        g_hLogThread = CreateThread(NULL, 0, LoggerThreadProc, NULL, 0, NULL);
        g_bErrorLogThreadRunning = true;
        g_hErrorLogThread = CreateThread(NULL, 0, ErrorLoggerThreadProc, NULL, 0, NULL);

        // Attach hooks using Detours.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        // Attach registry hooks.
        DetourAttach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourAttach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourAttach(&(PVOID&)TrueRegOpenKeyExW, HookedRegOpenKeyExW);
        // Attach file and directory hooks.
        DetourAttach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourAttach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourAttach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourAttach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourAttach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();

        // Start monitoring threads.
        g_hRegistryMonitorThread = CreateThread(NULL, 0, RegistryMonitorThreadProc, NULL, 0, NULL);
        // Start Registry monitoring for HKLM\ SYSTEM\Setup.
        g_hRegistrySetupMonitorThread = CreateThread(NULL, 0, RegistrySetupMonitorThreadProc, NULL, 0, NULL);
        // Start Winlogon Shell monitoring thread.
        g_hRegistryWinlogonShellMonitorThread = CreateThread(NULL, 0, RegistryWinlogonShellMonitorThreadProc, NULL, 0, NULL);
        // Start Keyboard Layout monitoring thread.
        g_hRegistryKeyboardLayoutMonitorThread = CreateThread(NULL, 0, RegistryKeyboardLayoutMonitorThreadProc, NULL, 0, NULL);

        // Start the time monitor thread.
        g_hTimeMonitorThread = CreateThread(NULL, 0, TimeMonitorThreadProc, NULL, 0, NULL);
        if (g_hTimeMonitorThread)
        {
            SafeWriteSigmaLog(L"TimeMonitor", L"Time monitor thread started.");
        }
        else
        {
            SafeWriteSigmaLog(L"TimeMonitor", L"Failed to start time monitor thread.");
        }

        // Start the file trap monitor thread directly.
        g_hFileTrapMonitorThread = CreateThread(NULL, 0, FileTrapMonitorThreadProc, NULL, 0, NULL);
        if (g_hFileTrapMonitorThread)
        {
            SafeWriteSigmaLog(L"FileTrapMonitor", L"File trap monitoring thread started.");
        }
        else
        {
            SafeWriteSigmaLog(L"FileTrapMonitor", L"Failed to start file trap monitoring thread.");
        }

        // ***** Added: Create browser homepage monitoring threads *****
        HANDLE hChromeThread = CreateThread(NULL, 0, ChromeRegistryMonitorThread, NULL, 0, NULL);
        HANDLE hEdgeThread = CreateThread(NULL, 0, EdgeRegistryMonitorThread, NULL, 0, NULL);
        HANDLE hFirefoxThread = CreateThread(NULL, 0, FirefoxFileMonitorThread, NULL, 0, NULL);

        break;

    case DLL_PROCESS_DETACH:
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_DETACH\"}");

        // Stop logging threads.
        g_bLogThreadRunning = false;
        if (g_hLogThread)
        {
            WaitForSingleObject(g_hLogThread, 2000);
            CloseHandle(g_hLogThread);
        }
        g_bErrorLogThreadRunning = false;
        if (g_hErrorLogThread)
        {
            WaitForSingleObject(g_hErrorLogThread, 2000);
            CloseHandle(g_hErrorLogThread);
        }

        // Stop monitoring threads.
        g_bMBRMonitorRunning = false;
        if (g_hMBRMonitorThread)
        {
            WaitForSingleObject(g_hMBRMonitorThread, 2000);
            CloseHandle(g_hMBRMonitorThread);
        }
        // Stop HKCU Registry monitoring.
        g_bRegistryMonitorRunning = false;
        if (g_hRegistryMonitorThread)
        {
            WaitForSingleObject(g_hRegistryMonitorThread, 2000);
            CloseHandle(g_hRegistryMonitorThread);
        }
        // Stop HKLM\ SYSTEM\Setup Registry monitoring.
        g_bRegistrySetupMonitorRunning = false;
        if (g_hRegistrySetupMonitorThread)
        {
            WaitForSingleObject(g_hRegistrySetupMonitorThread, 2000);
            CloseHandle(g_hRegistrySetupMonitorThread);
        }
        // Stop Winlogon Shell monitoring.
        g_bRegistryWinlogonShellMonitorRunning = false;
        if (g_hRegistryWinlogonShellMonitorThread)
        {
            WaitForSingleObject(g_hRegistryWinlogonShellMonitorThread, 2000);
            CloseHandle(g_hRegistryWinlogonShellMonitorThread);
        }
        // Stop Keyboard Layout monitoring.
        g_bRegistryKeyboardLayoutMonitorRunning = false;
        if (g_hRegistryKeyboardLayoutMonitorThread)
        {
            WaitForSingleObject(g_hRegistryKeyboardLayoutMonitorThread, 2000);
            CloseHandle(g_hRegistryKeyboardLayoutMonitorThread);
        }
        // Signal the time monitor thread to stop.
        g_bTimeMonitorRunning = false;
        if (g_hTimeMonitorThread)
        {
            WaitForSingleObject(g_hTimeMonitorThread, 2000);
            CloseHandle(g_hTimeMonitorThread);
        }
        // Signal the file trap monitor thread to stop.
        g_bFileTrapMonitorRunning = false;
        if (g_hFileTrapMonitorThread)
        {
            WaitForSingleObject(g_hFileTrapMonitorThread, 2000);
            CloseHandle(g_hFileTrapMonitorThread);
        }

        // Detach hooks.
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueRegSetValueExW, HookedRegSetValueExW);
        DetourDetach(&(PVOID&)TrueRegCreateKeyExW, HookedRegCreateKeyExW);
        DetourDetach(&(PVOID&)TrueRegOpenKeyExW, HookedRegOpenKeyExW);
        DetourDetach(&(PVOID&)TrueDeleteFileW, HookedDeleteFileW);
        DetourDetach(&(PVOID&)TrueCreateFileW, HookedCreateFileW);
        DetourDetach(&(PVOID&)TrueWriteFile, HookedWriteFile);
        DetourDetach(&(PVOID&)TrueMoveFileW, HookedMoveFileW);
        DetourDetach(&(PVOID&)TrueRemoveDirectoryW, HookedRemoveDirectoryW);
        DetourTransactionCommit();

        // Delete critical sections.
        DeleteCriticalSection(&g_logLock);
        DeleteCriticalSection(&g_errorLogLock);
        DeleteCriticalSection(&g_registryMapLock);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
