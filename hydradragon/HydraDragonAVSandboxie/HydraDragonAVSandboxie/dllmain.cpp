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
#include <filesystem>
#include <mutex>
#include <iostream>
#include <shlobj.h>

constexpr unsigned long long ONE_GB = 1073741824ULL; 
constexpr unsigned long long ONE_TB = 1099511627776ULL;

//-----------------------------------------------------------------------------
// Helper: Get the desktop directory path
static std::wstring GetDesktopDirectory() {
    wchar_t path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, SHGFP_TYPE_CURRENT, path))) {
        return std::wstring(path);
    }
    // fallback: return empty string on failure
    return L"";
}

//-----------------------------------------------------------------------------
// Helper: expand an environment variable (e.g. "%ProgramFiles%") into a std::wstring
static std::wstring ExpandGetEnv(const wchar_t* envVar) {
    // first call returns required length (including terminating NUL)
    DWORD len = ::ExpandEnvironmentStringsW(envVar, nullptr, 0);
    if (len == 0) {
        // failure: return empty or fallback
        return L"";
    }
    // allocate buffer and call again
    std::wstring buf(len, L'\0');
    ::ExpandEnvironmentStringsW(envVar, &buf[0], len);
    // remove the extra null at the end
    if (!buf.empty() && buf.back() == L'\0')
        buf.pop_back();
    return buf;
}

//-----------------------------------------------------------------------------
// Compute the desktop directory once, in static init order:
static std::wstring DESKTOP_DIRECTORY = GetDesktopDirectory();

//-----------------------------------------------------------------------------
// Compute the base "%ProgramFiles%" once, in static init order:
static std::wstring PROGRAM_FILES = ExpandGetEnv(L"%ProgramFiles%");

//-----------------------------------------------------------------------------
// Now build all of your paths - these run immediately after DESKTOP_DIRECTORY
static std::wstring LOG_FOLDER =
DESKTOP_DIRECTORY + L"\\HydraDragonAntivirus\\DONTREMOVEHydraDragonAntivirusLogs";

static std::wstring SIGMA_LOG_FILE =
LOG_FOLDER + L"\\DONTREMOVEsigma_log.txt";

static std::wstring ERROR_LOG_FILE =
LOG_FOLDER + L"\\DONTREMOVEerror_log.txt";

static std::wstring KNOWN_EXTENSIONS_FILE =
PROGRAM_FILES + L"\\HydraDragonAntivirus\\knownextensions\\extensions.txt";

static std::wstring DETECTIT_EASY_CONSOLE_PATH =
PROGRAM_FILES + L"\\HydraDragonAntivirus\\detectiteasy\\diec.exe";

static std::wstring ASSETS_SOUND_PATH =
PROGRAM_FILES + L"\\HydraDragonAntivirus\\assets\\alert.wav";

//-----------------------------------------------------------------------------
// I need WCHAR* arrays, I can expose them easily:
const WCHAR* GetLogFolderCStr() { return LOG_FOLDER.c_str(); }
const WCHAR* GetSigmaLogFileCStr() { return SIGMA_LOG_FILE.c_str(); }
const WCHAR* GetErrorLogFileCStr() { return ERROR_LOG_FILE.c_str(); }
const WCHAR* GetKnownExtensionsFileCStr() { return KNOWN_EXTENSIONS_FILE.c_str(); }
const WCHAR* GetDiecPathCStr() { return DETECTIT_EASY_CONSOLE_PATH.c_str(); }

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

// -----------------------------------------------------------------
// Asynchronous Logging for Regular Logs
// -----------------------------------------------------------------
CRITICAL_SECTION g_logLock;
std::vector<std::wstring> g_logQueue;
HANDLE g_hLogThread = NULL;
volatile bool g_bLogThreadRunning = true;
void EnsureLogDirectory();

// Helper function: Write a timestamped CSV log entry to DONTREMOVEHomePageChange.txt.
void WriteLog(const wchar_t* message)
{
    // Build the full path: <ProgramFiles>\HydraDragonAntivirus\DONTREMOVEHydraDragonAntivirusLogs\DONTREMOVEHomePageChange.txt
    std::wstring logPath = LOG_FOLDER + L"\\DONTREMOVEHomePageChange.txt";

    FILE* f = nullptr;
    if (_wfopen_s(&f, logPath.c_str(), L"a+") == 0 && f)
    {
        // Append the CSV message (e.g. "Chrome,homepage_value")
        fwprintf(f, L"%s\n", message);
        fclose(f);
    }
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

//------------------------------------------------------------------------------
// Ensure log directory exists
//------------------------------------------------------------------------------
void EnsureLogDirectory()
{
    std::error_code ec;
    std::filesystem::create_directories(LOG_FOLDER, ec);
    if (ec) {
        std::cerr << "Error: Failed to create log directory: "
            << ec.message() << std::endl;
    }
}

void SafeWriteSigmaLog(const WCHAR* eventType, const WCHAR* details)
{
    EnsureLogDirectory();  // Make sure log folder exists

    if (g_bInLogging)
        return;

    g_bInLogging = true;
    WriteSigmaLog(eventType, details);
    g_bInLogging = false;
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
            if (_wfopen_s(&f, SIGMA_LOG_FILE.c_str(), L"a+") == 0 && f)
            {
                for (const auto& msg : localQueue)
                    fwprintf(f, L"%s\n", msg.c_str());
                fclose(f);
            }
        }
    }
    return 0;
}

// Chrome homepage monitoring thread
DWORD WINAPI ChromeRegistryMonitorThread(LPVOID lpParam)
{
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Google\\Chrome", 0, KEY_READ | KEY_NOTIFY, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        SafeWriteSigmaLog(L"ChromeMonitor", L"Chrome monitor: Failed to open registry key.");
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
                // Build CSV message without using StringCchPrintfW
                wchar_t csvLog[1024] = { 0 };
                swprintf_s(csvLog, 1024, L"Chrome,%s", homepage);
                // Log the match event using SafeWriteSigmaLog
                SafeWriteSigmaLog(L"ChromeMonitorCSV", csvLog);
            }
            else
            {
                SafeWriteSigmaLog(L"ChromeMonitor", L"Chrome monitor: Homepage value changed but could not be read.");
            }
        }
        else
        {
            SafeWriteSigmaLog(L"ChromeMonitor", L"Chrome monitor: RegNotifyChangeKeyValue failed.");
            break;
        }
    }

    if (hKey)
        RegCloseKey(hKey);

    return 0;
}

// Edge homepage monitoring thread
DWORD WINAPI EdgeRegistryMonitorThread(LPVOID lpParam)
{
    HKEY hKey = NULL;
    LONG lResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Policies\\Microsoft\\Edge", 0, KEY_READ | KEY_NOTIFY, &hKey);
    if (lResult != ERROR_SUCCESS)
    {
        SafeWriteSigmaLog(L"EdgeMonitor", L"Edge monitor: Failed to open registry key.");
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
                wchar_t csvLog[1024] = { 0 };
                swprintf_s(csvLog, 1024, L"Edge,%s", homepage);
                SafeWriteSigmaLog(L"EdgeMonitorCSV", csvLog);
            }
            else
            {
                SafeWriteSigmaLog(L"EdgeMonitor", L"Edge monitor: Homepage value changed but could not be read.");
            }
        }
        else
        {
            SafeWriteSigmaLog(L"EdgeMonitor", L"Edge monitor: RegNotifyChangeKeyValue failed.");
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

// Firefox homepage monitoring thread (using file change notifications)
DWORD WINAPI FirefoxFileMonitorThread(LPVOID lpParam)
{
    std::wstring prefsFilePath = GetFirefoxPrefsPath();
    if (prefsFilePath.empty())
    {
        SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox monitor: Could not locate prefs.js file.");
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
        SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox monitor: Failed to set up directory change notification.");
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

                if (wcslen(homepage) > 0)
                {
                    wchar_t csvLog[1024] = { 0 };
                    swprintf_s(csvLog, 1024, L"Firefox,%s", homepage);
                    SafeWriteSigmaLog(L"FirefoxMonitorCSV", csvLog);
                }
                else
                {
                    SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox prefs.js changed but homepage setting not found.");
                }
            }
            else
            {
                SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox monitor: Failed to open prefs.js for reading.");
            }

            if (FindNextChangeNotification(hChange) == FALSE)
            {
                SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox monitor: Failed to reset change notification.");
                break;
            }
        }
        else
        {
            SafeWriteSigmaLog(L"FirefoxMonitor", L"Firefox monitor: WaitForSingleObject failed.");
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
    // pack title/msg for the thread
    auto* pData = new std::pair<std::wstring, std::wstring>(title, msg);

    HANDLE hThread = CreateThread(
        nullptr, 0,
        [](LPVOID lpParam) -> DWORD {
            auto* p = static_cast<std::pair<std::wstring, std::wstring>*>(lpParam);

            // Play from our precomputed ASSETS_SOUND_PATH
            PlaySoundW(ASSETS_SOUND_PATH.c_str(), nullptr, SND_FILENAME | SND_ASYNC);

            // Show tray icon + balloon
            NOTIFYICONDATAW nid = {};
            nid.cbSize = sizeof(nid);
            nid.hWnd = g_hNotificationWnd;
            nid.uID = 1001;
            nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
            nid.uCallbackMessage = WM_USER + 1;
            nid.hIcon = LoadIcon(nullptr, IDI_WARNING);

            wcsncpy_s(nid.szTip, p->first.c_str(), _TRUNCATE);
            Shell_NotifyIconW(NIM_ADD, &nid);

            nid.uFlags = NIF_INFO;
            wcsncpy_s(nid.szInfoTitle, p->first.c_str(), _TRUNCATE);
            wcsncpy_s(nid.szInfo, p->second.c_str(), _TRUNCATE);
            nid.dwInfoFlags = NIIF_WARNING;
            Shell_NotifyIconW(NIM_MODIFY, &nid);

            Sleep(5000);
            Shell_NotifyIconW(NIM_DELETE, &nid);

            delete p;
            return 0;
        },
        pData, 0, nullptr);

    if (hThread) CloseHandle(hThread);
}

// --------------------- End Notification Infrastructure ---------------------


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
// Returns true if the file is suspected to be ransomware.
bool is_ransomware(const std::wstring& file_path)
{
    // 1) split filename into “name.parts.ext1.ext2…”
    std::wstring filename = PathFindFileNameW(file_path.c_str());
    std::vector<std::wstring> parts;
    std::wstringstream wss(filename);
    std::wstring token;
    while (std::getline(wss, token, L'.'))
        parts.push_back(token);

    if (parts.size() < 3)
    {
        SafeWriteSigmaLog(L"is_ransomware",
            L"File does not have multiple extensions, not flagged as ransomware.");
        return false;
    }

    // 2) check penultimate extension against known list
    std::wstring prev_ext = L"." + parts[parts.size() - 2];
    std::transform(prev_ext.begin(), prev_ext.end(), prev_ext.begin(), towlower);
    bool prev_known = false;
    for (auto& known : g_knownExtensions)
    {
        std::wstring kl = known;
        std::transform(kl.begin(), kl.end(), kl.begin(), towlower);
        if (prev_ext == kl) { prev_known = true; break; }
    }
    if (!prev_known)
    {
        SafeWriteSigmaLog(L"is_ransomware",
            L"Previous extension not known, file not flagged as ransomware.");
        return false;
    }

    // 3) check final extension—if known, skip
    std::wstring final_ext = L"." + parts.back();
    std::transform(final_ext.begin(), final_ext.end(), final_ext.begin(), towlower);
    for (auto& known : g_knownExtensions)
    {
        std::wstring kl = known;
        std::transform(kl.begin(), kl.end(), kl.begin(), towlower);
        if (final_ext == kl)
        {
            SafeWriteSigmaLog(L"is_ransomware",
                L"Final extension is known, file not flagged as ransomware.");
            return false;
        }
    }

    // 4) if file is readable or has any known extension, skip
    if (has_known_extension(file_path) || is_readable(file_path))
    {
        SafeWriteSigmaLog(L"is_ransomware",
            L"File is readable or has known extension, not flagged as ransomware.");
        return false;
    }

    // 5) run Detect It Easy for JSON analysis
    std::wstring cmd = L"\"" + DETECTIT_EASY_CONSOLE_PATH + L"\" -j \"" + file_path + L"\"";
    FILE* pipe = _wpopen(cmd.c_str(), L"r");                    // .c_str() → const wchar_t* :contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}
    if (!pipe)
    {
        SafeWriteSigmaLog(L"is_ransomware",
            L"Failed to execute Detect It Easy, flagging as ransomware.");
        return true;
    }
    std::wstring result;
    wchar_t buf[128];
    while (fgetws(buf, _countof(buf), pipe))
        result += buf;
    _pclose(pipe);

    // 6) save JSON into LOG_FOLDER (no hard‑coded path)
    static int cnt = 1;
    std::error_code ec;
    std::filesystem::create_directories(LOG_FOLDER, ec);        // error_code must be lvalue :contentReference[oaicite:2]{index=2}
    std::wstring jsonFile = LOG_FOLDER
        + L"\\detectiteasy_ransom_" + std::to_wstring(cnt++) + L".json";
    FILE* jf = nullptr;
    if (_wfopen_s(&jf, jsonFile.c_str(), L"w") == 0 && jf)
    {
        fwprintf(jf, L"%s", result.c_str());
        fclose(jf);
    }

    // 7) if JSON contains “Binary” & “Unknown: Unknown”, flag as ransomware
    if (result.find(L"Binary") != std::wstring::npos &&
        result.find(L"Unknown: Unknown") != std::wstring::npos)
    {
        SafeWriteSigmaLog(L"is_ransomware",
            L"Detect It Easy output indicates a possible ransomware encrypted file.");
        return true;
    }

    SafeWriteSigmaLog(L"is_ransomware",
        L"Detect It Easy output did not confirm suspicious status.");
    return false;
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
            if (_wfopen_s(&f, ERROR_LOG_FILE.c_str(), L"a+") == 0 && f)
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

    // 1) Normalize and lowercase the incoming path
    std::wstring path(filePath);
    NormalizePath(path);
    std::transform(path.begin(), path.end(), path.begin(), towlower);

    // 2) Build a lowercase version of LOG_FOLDER at runtime
    std::wstring folder = LOG_FOLDER;                // LOG_FOLDER was built from %ProgramFiles% + "\\..Logs" :contentReference[oaicite:0]{index=0}:contentReference[oaicite:1]{index=1}
    NormalizePath(folder);                           // strip any \\?\ prefix if present
    std::transform(folder.begin(), folder.end(), folder.begin(), towlower);

    // 3) If the path is not under our log-folder, it's not "ours"
    const std::wstring prefix = folder + L"\\";
    if (path.rfind(prefix, 0) != 0)                  // rfind(...,0)==0 means"starts with"
        return false;

    // 4) Extract just the filename portion
    size_t pos = path.find_last_of(L"\\/");
    std::wstring name = (pos == std::wstring::npos)
        ? path
        : path.substr(pos + 1);

    // 5) Compare the basename against our two text‑log names...
    if (name == L"dontremovesigma_log.txt" ||
        name == L"dontremoveerror_log.txt")
    {
        return true;
    }

    // 6) …or, if it ends in “.json”, treat any JSON in that folder as ours
    if (name.size() >= 5 &&
        name.compare(name.size() - 5, 5, L".json") == 0)
    {
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
    if (_wfopen_s(&f, KNOWN_EXTENSIONS_FILE.c_str(), L"r") == 0 && f)
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

//------------------------------------------------------------------------------
// Initialize and Start Logging
//------------------------------------------------------------------------------
void InitializeLogging()
{
    InitializeCriticalSection(&g_logLock);
    InitializeCriticalSection(&g_errorLogLock);
    InitializeCriticalSection(&g_registryMapLock);

    g_bLogThreadRunning = true;
    g_hLogThread = CreateThread(nullptr, 0, LoggerThreadProc, nullptr, 0, nullptr);
    if (!g_hLogThread)
    {
        OutputDebugStringW(L"Failed to start log thread\n");
        g_bLogThreadRunning = false;
    }
}

//------------------------------------------------------------------------------
// Stop and Cleanup Logging
//------------------------------------------------------------------------------
void CleanupLogging()
{
    g_bLogThreadRunning = false;
    if (g_hLogThread)
    {
        WaitForSingleObject(g_hLogThread, INFINITE);
        CloseHandle(g_hLogThread);
        g_hLogThread = nullptr;
    }

    DeleteCriticalSection(&g_logLock);
    DeleteCriticalSection(&g_errorLogLock);
    DeleteCriticalSection(&g_registryMapLock);
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

static constexpr int MBR_SIZE = 512;
static constexpr int DISK_SIG_OFFSET = 440;
static constexpr int DISK_SIG_LENGTH = 4;

// Read 512‑byte MBR and zero out the disk signature bytes
std::vector<char> GetStableMBR()
{
    std::vector<char> mbr = GetMBR();      // your existing read-from-\\.\PhysicalDrive0
    if (mbr.size() == MBR_SIZE) {
        // Zero out the 4‑byte disk signature so it won't trigger a false alarm
        std::fill_n(mbr.begin() + DISK_SIG_OFFSET, DISK_SIG_LENGTH, 0);
    }
    return mbr;
}

DWORD WINAPI MBRMonitorThreadProc(LPVOID)
{
    // 1) Prime the baseline with a “stable” MBR
    g_baselineMBR = GetStableMBR();
    if (g_baselineMBR.size() != MBR_SIZE) {
        // failed to read MBR; bail out or retry later
        return 1;
    }

    // 2) Poll, but only detect when the *stable* MBR really differs
    while (g_bMBRMonitorRunning)
    {
        auto current = GetStableMBR();
        if (current.size() == MBR_SIZE && current != g_baselineMBR)
        {
            SafeWriteSigmaLog(L"MBRMonitor", L"HEUR:Win32.Possible.Bootkit.MBR.gen alert (real change)");
            TriggerNotification(
                L"Virus Detected: HEUR:Win32.Possible.Bootkit.MBR.gen",
                L"MBR has been modified"
            );
            // update baseline so you don’t spam on the same change
            g_baselineMBR = std::move(current);
        }

        Sleep(5000);  // you can adjust this interval as needed
    }
    return 0;
}

// -----------------------------------------------------------------
// Registry Monitoring via RegNotifyChangeKeyValue
// -----------------------------------------------------------------
// This version uses a dedicated monitoring thread (RegistryMonitorThreadProc)
// that checks the key "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
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
        Sleep(1000);  // Check every second.
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
            HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            KEY_READ | KEY_NOTIFY,
            &hKey);

        if (lResult == ERROR_FILE_NOT_FOUND)  // Key deleted
        {
            SafeWriteSigmaLog(L"RegistryMonitor", L"HEUR:Win32.Susp.Reg.Wiper.gen - Key deleted: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
            TriggerNotification(L"Virus Detected: HEUR:Win32.Susp.Reg.Wiper.gen", L"Registry key deleted: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
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
        // turn the incoming path into a lowercase std::wstring
        std::wstring path(lpPathName);
        NormalizePath(path);
        std::transform(path.begin(), path.end(), path.begin(), towlower);

        // build the lowercase log‑folder prefix dynamically
        std::wstring logFolder = LOG_FOLDER;
        std::transform(logFolder.begin(), logFolder.end(), logFolder.begin(), towlower);

        // if the path being removed sits under our log folder…
        if (path.rfind(logFolder, 0) == 0  // rfind(...,0)==0 means “path starts with logFolder”
            || path.find(logFolder + L"\\") != std::wstring::npos)
        {
            SafeWriteSigmaLog(
                L"RemoveDirectoryW",
                L"HEUR:Win32.Trojan.Wiper.Log.gen@FileTrap - Log directory deletion detected"
            );
            TriggerNotification(
                L"Virus Detected: HEUR:Win32.Trojan.Wiper.Log.gen@FileTrap",
                L"Warning: Log directory was deleted (Wiper behavior detected)"
            );
        }
    }

    // call through to the real RemoveDirectoryW
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
        // 1) hall.dll in System32?
        wchar_t sysDir[MAX_PATH] = { 0 };
        if (GetSystemDirectoryW(sysDir, MAX_PATH))
        {
            std::wstring target = sysDir;
            if (target.back() != L'\\')
                target += L'\\';
            target += L"hall.dll";

            // lowercase both for case-insensitive exact compare
            std::wstring path(lpFileName);
            std::transform(path.begin(), path.end(), path.begin(), ::towlower);
            std::transform(target.begin(), target.end(), target.begin(), ::towlower);

            if (path == target)
            {
                SafeWriteSigmaLog(
                    L"DeleteFileW",
                    L"HEUR:Win32.Trojan.Wiper.hall.gen – System32\\hall.dll deletion detected"
                );
                TriggerNotification(
                    L"Virus Detected: HEUR:Win32.Trojan.Wiper.hall.gen",
                    L"Warning: System32\\hall.dll was deleted (HALL wiper behavior detected)"
                );
                // let it proceed; remove this `return` if you want to BLOCK the delete:
            }
        }

        // 2) your existing “log‐folder” deletion hook
        if (IsOurLogFileForDetection(lpFileName))
        {
            SafeWriteSigmaLog(
                L"DeleteFileW",
                L"HEUR:Win32.Trojan.Wiper.Log.gen – Log file deletion detected"
            );
            TriggerNotification(
                L"Virus Detected: HEUR:Win32.Trojan.Wiper.Log.gen",
                L"Warning: A log file was deleted (Wiper behavior detected)"
            );
        }
        else
        {
            // 3) generic DeleteFileW logging
            wchar_t buffer[1024];
            _snwprintf_s(buffer, _countof(buffer), _TRUNCATE,
                L"DeleteFileW called on: %s", lpFileName);
            SafeWriteSigmaLog(L"DeleteFileW", buffer);
        }
    }
    else
    {
        SafeWriteSigmaLog(L"DeleteFileW", L"DeleteFileW called: FileName = (null)");
    }

    // 4) finally, forward to the real API
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

// Helper: Check if signature is invalid or manipulated,
// but allow test-signed binaries (which are signed but not trusted by default).
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
    while (fgetws(buffer, sizeof(buffer) / sizeof(buffer[0]), pipe))
        output += buffer;

    _pclose(pipe);
    certOutput = output;

    // Acceptable errors for test-signed or dev-signed binaries
    bool isTestSigned =
        output.find(L"End entity certificate is not trusted") != std::wstring::npos ||
        output.find(L"Partial certificate chain") != std::wstring::npos ||
        output.find(L"Root certificate is not trusted") != std::wstring::npos;

    // Unacceptable failures indicating tampering or corruption
    bool isInvalidSignature =
        output.find(L"Signature verification failed") != std::wstring::npos ||
        output.find(L"Cert chain validation failed") != std::wstring::npos ||
        output.find(L"Cannot find object or property") != std::wstring::npos ||
        output.find(L"Bad signature") != std::wstring::npos;

    // If signature is invalid (not just test-signed), flag it
    if (isInvalidSignature && !isTestSigned)
    {
        return true; // Signature is invalid or manipulated
    }

    return false; // Signature is OK or test-signed
}

// Updated function to check unsigned driver (for .sys files)
void CheckUnsignedDriver(const std::wstring& filePath)
{
    if (!endsWithSys(filePath))
        return;

    // 1) Test‑signing: only flag on the *second* hit in test mode
    static bool testModeFlagged = false;
    if (IsTestSigningEnabled())
    {
        if (!testModeFlagged)
        {
            testModeFlagged = true;
            return;
        }
    }

    // 2) PowerShell signature check
    std::wstring signatureStatus;
    if (CheckSignature(filePath, signatureStatus))
    {
        SafeWriteSigmaLog(
            L"CheckUnsignedDriver",
            L"File signature is valid, no unsigned driver detected."
        );
        return;
    }
    SafeWriteSigmaLog(
        L"CheckUnsignedDriver",
        (L"File signature check failed: " + signatureStatus).c_str()
    );

    // 3) certutil manipulation check
    std::wstring certOutput;
    if (IsSignatureCheckManipulated(filePath, certOutput))
    {
        SafeWriteSigmaLog(
            L"CheckUnsignedDriver",
            L"Signature check manipulated detected: HEUR:Win32.Trojan.Bypass.Signing.gen"
        );
        TriggerNotification(
            L"Unsigned Driver Detected",
            L"HEUR:Win32.Trojan.Bypass.Signing.gen"
        );
        return;
    }

    // 4) Run Detect It Easy (diec.exe -j …)
    std::wstring diec = DETECTIT_EASY_CONSOLE_PATH;               // use configured path
    std::wstring command = L"\"" + diec + L"\" -j \"" + filePath + L"\"";
    FILE* pipe = _wpopen(command.c_str(), L"r");
    if (!pipe)
    {
        SafeWriteSigmaLog(
            L"CheckUnsignedDriver",
            L"Failed to execute detectiteasy command"
        );
        return;
    }
    std::wstring jsonResult;
    wchar_t buffer[256];
    while (fgetws(buffer, 256, pipe))
        jsonResult += buffer;
    _pclose(pipe);

    // 5) Save JSON into your LOG_FOLDER (no hard‑coded path)
    static int diecCount = 1;
    std::wstring folder = LOG_FOLDER;
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);             // error_code must be an lvalue :contentReference[oaicite:0]{index=0}
    if (ec)
    {
        SafeWriteSigmaLog(
            L"CheckUnsignedDriver",
            (L"Failed to create log folder: " + std::wstring(ec.message().begin(), ec.message().end())).c_str()
        );
        // but continue—maybe folder already existed
    }

    std::wstring jsonPath = folder
        + L"\\detectiteasy_" + std::to_wstring(diecCount++) + L".json";

    FILE* jsonFile = nullptr;
    if (_wfopen_s(&jsonFile, jsonPath.c_str(), L"w") == 0 && jsonFile)
    {
        fwprintf(jsonFile, L"%s", jsonResult.c_str());
        fclose(jsonFile);
    }

    // 6) Inspect JSON for PE markers
    bool isPE32 = (jsonResult.find(L"PE32") != std::wstring::npos);
    bool isPE64 = (jsonResult.find(L"PE64") != std::wstring::npos);

    if (isPE32)
    {
        SafeWriteSigmaLog(
            L"UnsignedDriverCheck",
            L"HEUR:Win32.Possible.Rootkit.gen detected"
        );
        TriggerNotification(
            L"Unsigned Driver Detected",
            L"HEUR:Win32.Possible.Rootkit.gen"
        );
    }
    else if (isPE64)
    {
        SafeWriteSigmaLog(
            L"UnsignedDriverCheck",
            L"HEUR:Win64.Possible.Rootkit.gen detected"
        );
        TriggerNotification(
            L"Unsigned Driver Detected",
            L"HEUR:Win64.Possible.Rootkit.gen"
        );
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
        Sleep(1000); // Check every second

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

extern "C" __declspec(dllexport) void CALLBACK Run(
    HWND    /*hwnd*/,
    HINSTANCE /*hinst*/,
    LPSTR   /*lpszCmdLine*/,
    int     /*nCmdShow*/
)
{
    printf_s("Run: Exported function called\n");
}

// ------------------ DllMain ------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // Save our own module handle for resource extraction.
        g_hThisModule = hModule;
        EnsureLogDirectory();
        InitializeLogging();
        // Disable thread notifications to reduce overhead.
        DisableThreadLibraryCalls(hModule);

        // ---- Begin DllMain logic ----
        SafeWriteSigmaLog(L"DllMain", L"Entered DllMain");
        WCHAR buffer[256];
        _snwprintf_s(buffer, 256, _TRUNCATE, L"DllMain called.");
        SafeWriteSigmaLog(L"DllMain", buffer);

        if (!g_hThisModule)
        {
            SafeWriteSigmaLog(L"DllMain", L"g_hThisModule is not initialized.");
            break;
        }

        // Extract embedded resource and compare against baseline
        {
            std::wstring extractedFilePath = LOG_FOLDER;
            extractedFilePath += L"\\DONTREMOVEHydraDragonFileTrap.exe";
            if (ExtractResourceToFile(g_hThisModule, MAKEINTRESOURCE(IDR_HYDRA_DRAGON_FILETRAP), RT_RCDATA, extractedFilePath))
            {
                std::wstring baselineFilePath = LOG_FOLDER;
                baselineFilePath += L"\\baseline_DONTREMOVEHydraDragonFileTrap.exe";
                if (!FileExists(baselineFilePath))
                {
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

        // Load extension and signature checks
        LoadKnownExtensions();
        SafeWriteSigmaLog(L"DllMain", L"Digital signature and unsigned driver checking modules called.");

        // Create notification window
        g_hNotificationWnd = CreateNotificationWindow();

        // Start async logging threads
        g_bLogThreadRunning = true;
        g_hLogThread = CreateThread(NULL, 0, LoggerThreadProc, NULL, 0, NULL);
        g_bErrorLogThreadRunning = true;
        g_hErrorLogThread = CreateThread(NULL, 0, ErrorLoggerThreadProc, NULL, 0, NULL);

        // Start MBR monitoring
        std::vector<char> g_baselineMBR = GetMBR();
        if (!g_baselineMBR.empty())
        {
            g_bMBRMonitorRunning = true;
            g_hMBRMonitorThread = CreateThread(NULL, 0, MBRMonitorThreadProc, NULL, 0, NULL);
        }
        else
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_ACCESS_DENIED)
            {
                SafeWriteSigmaLog(L"MBRMonitor", L"Access denied – possibly running in a sandbox. Skipping MBR read.");
            }
            else
            {
                SafeWriteSigmaLog(L"MBRMonitor", L"Failed to read baseline MBR.");
            }
        }

        // Registry and other monitors
        g_bRegistryMonitorRunning = true;
        g_hRegistryMonitorThread = CreateThread(NULL, 0, RegistryMonitorThreadProc, NULL, 0, NULL);
        g_bRegistrySetupMonitorRunning = true;
        g_hRegistrySetupMonitorThread = CreateThread(NULL, 0, RegistrySetupMonitorThreadProc, NULL, 0, NULL);
        g_bRegistryWinlogonShellMonitorRunning = true;
        g_hRegistryWinlogonShellMonitorThread = CreateThread(NULL, 0, RegistryWinlogonShellMonitorThreadProc, NULL, 0, NULL);
        g_bRegistryKeyboardLayoutMonitorRunning = true;
        g_hRegistryKeyboardLayoutMonitorThread = CreateThread(NULL, 0, RegistryKeyboardLayoutMonitorThreadProc, NULL, 0, NULL);
        g_bTimeMonitorRunning = true;
        g_hTimeMonitorThread = CreateThread(NULL, 0, TimeMonitorThreadProc, NULL, 0, NULL);
        if (!g_hTimeMonitorThread) SafeWriteSigmaLog(L"TimeMonitor", L"Failed to start TimeMonitorThread.");
        g_bFileTrapMonitorRunning = true;
        g_hFileTrapMonitorThread = CreateThread(NULL, 0, FileTrapMonitorThreadProc, NULL, 0, NULL);
        if (!g_hFileTrapMonitorThread) SafeWriteSigmaLog(L"FileTrapMonitor", L"Failed to start file trap monitoring thread.");

        // Browser-specific monitoring
        CreateThread(nullptr, 0, ChromeRegistryMonitorThread, nullptr, 0, nullptr);
        CreateThread(nullptr, 0, EdgeRegistryMonitorThread, nullptr, 0, nullptr);
        CreateThread(nullptr, 0, FirefoxFileMonitorThread, nullptr, 0, nullptr);
   
        // Queue initial log message
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_ATTACH\"}");
        break;
    }

    case DLL_PROCESS_DETACH:
        CleanupLogging();
        // Queue detach log
        QueueLogMessage(L"{\"timestamp\":\"(n/a)\", \"event\":\"DllMain\", \"details\":\"DLL_PROCESS_DETACH\"}");
        // Signal threads to stop and clean up
        g_bLogThreadRunning = false; if (g_hLogThread) { WaitForSingleObject(g_hLogThread, 2000); CloseHandle(g_hLogThread); }
        g_bErrorLogThreadRunning = false; if (g_hErrorLogThread) { WaitForSingleObject(g_hErrorLogThread, 2000); CloseHandle(g_hErrorLogThread); }
        g_bMBRMonitorRunning = false; if (g_hMBRMonitorThread) { WaitForSingleObject(g_hMBRMonitorThread, 2000); CloseHandle(g_hMBRMonitorThread); }
        g_bRegistryMonitorRunning = false; if (g_hRegistryMonitorThread) { WaitForSingleObject(g_hRegistryMonitorThread, 2000); CloseHandle(g_hRegistryMonitorThread); }
        g_bRegistrySetupMonitorRunning = false; if (g_hRegistrySetupMonitorThread) { WaitForSingleObject(g_hRegistrySetupMonitorThread, 2000); CloseHandle(g_hRegistrySetupMonitorThread); }
        g_bRegistryWinlogonShellMonitorRunning = false; if (g_hRegistryWinlogonShellMonitorThread) { WaitForSingleObject(g_hRegistryWinlogonShellMonitorThread, 2000); CloseHandle(g_hRegistryWinlogonShellMonitorThread); }
        g_bRegistryKeyboardLayoutMonitorRunning = false; if (g_hRegistryKeyboardLayoutMonitorThread) { WaitForSingleObject(g_hRegistryKeyboardLayoutMonitorThread, 2000); CloseHandle(g_hRegistryKeyboardLayoutMonitorThread); }
        g_bTimeMonitorRunning = false; if (g_hTimeMonitorThread) { WaitForSingleObject(g_hTimeMonitorThread, 2000); CloseHandle(g_hTimeMonitorThread); }
        g_bFileTrapMonitorRunning = false; if (g_hFileTrapMonitorThread) { WaitForSingleObject(g_hFileTrapMonitorThread, 2000); CloseHandle(g_hFileTrapMonitorThread); }

        // Detach Detours hooks
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

        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}
