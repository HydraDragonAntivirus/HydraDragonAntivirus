#include "HydraDragonAV.h"
#include "ClamAVScanner.h"
#include "framework.h"
#include <Windows.h>
#include <Psapi.h>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// YARA Headers
#include <yara.h>

#pragma comment(lib, "Psapi.lib")

namespace fs = std::filesystem;

// Paths
#define PIPE_NAME L"\\\\.\\pipe\\HydraDragonAV"
#define CLAMAV_DIR L"C:\\Program Files\\ClamAV\\"
#define HYDRADRAGON_DIR L"C:\\Program Files\\HydraDragonAntivirus\\"
#define CLAMAV_DLL CLAMAV_DIR L"libclamav.dll"
#define CLAMAV_DB CLAMAV_DIR L"database"
#define FRESHCLAM_EXE CLAMAV_DIR L"freshclam.exe"
#define YARA_RULES_FOLDER HYDRADRAGON_DIR L"hydradragon\\yara\\"

// Scanner Global
static std::unique_ptr<clamav::Scanner> g_clamavScanner;
static YR_RULES *g_yaraRules = nullptr;
constexpr auto CLAMAV_UPDATE_INTERVAL = std::chrono::hours(2);
constexpr auto CLAMAV_DEFINITION_MAX_AGE = std::chrono::hours(12);
constexpr DWORD FRESHCLAM_TIMEOUT_MS = 180u * 1000u;

static std::unordered_set<std::string> g_excludedRules;

struct ScanCacheEntry {
  std::uintmax_t fileSize = 0;
  fs::file_time_type lastWriteTime{};
  std::chrono::steady_clock::time_point cachedAt{};
  std::string response;
};

static std::mutex g_scanCacheMutex;
static std::unordered_map<std::wstring, ScanCacheEntry> g_scanCache;

constexpr auto SCAN_CACHE_TTL = std::chrono::seconds(30);
constexpr std::size_t SCAN_CACHE_MAX_ENTRIES = 4096;

static std::atomic<std::uint64_t> g_totalScanRequests{0};

constexpr SIZE_T HYDRADRAGON_PRIVATE_BYTES_RESTART_LIMIT =
    static_cast<SIZE_T>(1536ull * 1024ull * 1024ull); // 1.5 GiB
constexpr auto MEMORY_MONITOR_INTERVAL = std::chrono::seconds(30);
constexpr UINT HYDRADRAGON_MEMORY_RECYCLE_EXIT_CODE = 100;



SIZE_T GetCurrentProcessPrivateBytes() {
  PROCESS_MEMORY_COUNTERS_EX counters{};
  counters.cb = sizeof(counters);

  if (!GetProcessMemoryInfo(GetCurrentProcess(),
                            reinterpret_cast<PROCESS_MEMORY_COUNTERS *>(&counters),
                            sizeof(counters))) {
    return 0;
  }

  return counters.PrivateUsage;
}

void StartMemoryGuardThread() {
  std::thread([]() {
    while (true) {
      std::this_thread::sleep_for(MEMORY_MONITOR_INTERVAL);

      const SIZE_T privateBytes = GetCurrentProcessPrivateBytes();
      if (privateBytes == 0) {
        continue;
      }

#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
      std::cout << "[MemoryGuard] private_bytes=" << privateBytes
                << " scans=" << g_totalScanRequests.load() << std::endl;
#endif

      if (privateBytes >= HYDRADRAGON_PRIVATE_BYTES_RESTART_LIMIT) {
        std::cerr << "[MemoryGuard] HydraDragonAV private memory reached "
                  << privateBytes
                  << " bytes after "
                  << g_totalScanRequests.load()
                  << " scan requests. Recycling scanner process to prevent "
                     "RADAR_PRE_LEAK_64 / native engine memory growth."
                  << std::endl;

        // Controller-managed scanner engine: use a distinct exit code so the
        // controller can restart it cleanly.
        ExitProcess(HYDRADRAGON_MEMORY_RECYCLE_EXIT_CODE);
      }
    }
  }).detach();
}

void LoadExcludedRules() {
  std::string path = "C:\\Program "
                     "Files\\HydraDragonAntivirus\\hydradragon\\excluded_yara_"
                     "rules\\excluded_yara_rules.txt";
  std::ifstream file(path);
  if (!file.is_open()) {
    std::cerr << "[YARA] Excluded rules file not found at " << path
              << std::endl;
    return;
  }
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty()) {
      g_excludedRules.insert(line);
    }
  }
  std::cout << "[YARA] Loaded " << g_excludedRules.size() << " excluded rules."
            << std::endl;
}


std::wstring NormalizeCachePath(const std::wstring &path) {
  std::wstring normalized = path;
  std::replace(normalized.begin(), normalized.end(), L'/', L'\\');

  std::transform(
      normalized.begin(), normalized.end(), normalized.begin(),
      [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });

  return normalized;
}

bool TryGetCachedScanResponse(const std::wstring &path, std::string &response) {
  std::error_code ec;

  if (!fs::exists(path, ec) || ec || !fs::is_regular_file(path, ec) || ec) {
    return false;
  }

  const auto fileSize = fs::file_size(path, ec);
  if (ec) {
    return false;
  }

  const auto lastWriteTime = fs::last_write_time(path, ec);
  if (ec) {
    return false;
  }

  const auto key = NormalizeCachePath(path);
  const auto now = std::chrono::steady_clock::now();

  std::lock_guard<std::mutex> lock(g_scanCacheMutex);

  auto it = g_scanCache.find(key);
  if (it == g_scanCache.end()) {
    return false;
  }

  const auto &entry = it->second;

  if (entry.fileSize != fileSize || entry.lastWriteTime != lastWriteTime) {
    g_scanCache.erase(it);
    return false;
  }

  if (now - entry.cachedAt > SCAN_CACHE_TTL) {
    g_scanCache.erase(it);
    return false;
  }

  response = entry.response;
  return true;
}

void StoreCachedScanResponse(const std::wstring &path, const std::string &response) {
  std::error_code ec;

  if (!fs::exists(path, ec) || ec || !fs::is_regular_file(path, ec) || ec) {
    return;
  }

  const auto fileSize = fs::file_size(path, ec);
  if (ec) {
    return;
  }

  const auto lastWriteTime = fs::last_write_time(path, ec);
  if (ec) {
    return;
  }

  const auto key = NormalizeCachePath(path);

  std::lock_guard<std::mutex> lock(g_scanCacheMutex);

  if (g_scanCache.size() >= SCAN_CACHE_MAX_ENTRIES) {
    g_scanCache.clear();
  }

  g_scanCache[key] = ScanCacheEntry{
      fileSize,
      lastWriteTime,
      std::chrono::steady_clock::now(),
      response,
  };
}

bool IsClamAvDatabaseStale() {
  std::error_code ec;
  const fs::path dbPath(CLAMAV_DB);
  if (!fs::exists(dbPath, ec) || !fs::is_directory(dbPath, ec)) {
    std::cerr << "[ClamAV] Database directory missing: " << dbPath.string()
              << std::endl;
    return true;
  }

  bool foundDefinition = false;
  fs::file_time_type latestDefinition{};
  for (const auto &entry : fs::directory_iterator(dbPath, ec)) {
    if (ec) {
      std::cerr << "[ClamAV] Failed to enumerate database directory: "
                << ec.message() << std::endl;
      return true;
    }

    std::error_code entryEc;
    if (!entry.is_regular_file(entryEc)) {
      continue;
    }

    std::wstring extension = entry.path().extension().wstring();
    std::transform(
        extension.begin(), extension.end(), extension.begin(),
        [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });

    if (extension != L".cvd" && extension != L".cld") {
      continue;
    }

    const auto writeTime = entry.last_write_time(entryEc);
    if (entryEc) {
      std::cerr << "[ClamAV] Failed to read definition timestamp: "
                << entry.path().string() << std::endl;
      continue;
    }

    if (!foundDefinition || writeTime > latestDefinition) {
      latestDefinition = writeTime;
      foundDefinition = true;
    }
  }

  if (!foundDefinition) {
    std::cerr << "[ClamAV] No .cvd/.cld definition files found." << std::endl;
    return true;
  }

  return latestDefinition + CLAMAV_DEFINITION_MAX_AGE <
         fs::file_time_type::clock::now();
}

bool RunFreshclam() {
  std::error_code ec;
  const fs::path freshclamPath(FRESHCLAM_EXE);
  if (!fs::exists(freshclamPath, ec)) {
    std::cerr << "[ClamAV] freshclam.exe not found: " << freshclamPath.string()
              << std::endl;
    return false;
  }

  std::wstring applicationName = freshclamPath.wstring();
  std::wstring commandLine = L"\"" + applicationName + L"\"";
  std::vector<wchar_t> mutableCommandLine(commandLine.begin(),
                                          commandLine.end());
  mutableCommandLine.push_back(L'\0');

  STARTUPINFOW startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  PROCESS_INFORMATION processInfo{};

  const BOOL created = CreateProcessW(
      applicationName.c_str(), mutableCommandLine.data(), nullptr, nullptr,
      FALSE, 0, nullptr, CLAMAV_DIR, &startupInfo, &processInfo);

  if (!created) {
    std::cerr << "[ClamAV] Failed to start freshclam.exe. Error: "
              << GetLastError() << std::endl;
    return false;
  }

  const DWORD waitResult =
      WaitForSingleObject(processInfo.hProcess, FRESHCLAM_TIMEOUT_MS);
  if (waitResult == WAIT_TIMEOUT) {
    std::cerr << "[ClamAV] freshclam.exe timed out." << std::endl;
    TerminateProcess(processInfo.hProcess, 1);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    return false;
  }

  DWORD exitCode = 1;
  if (!GetExitCodeProcess(processInfo.hProcess, &exitCode)) {
    std::cerr << "[ClamAV] Could not read freshclam.exe exit code. Error: "
              << GetLastError() << std::endl;
  }

  CloseHandle(processInfo.hThread);
  CloseHandle(processInfo.hProcess);

  if (exitCode != 0) {
    std::cerr << "[ClamAV] freshclam.exe failed with code " << exitCode
              << std::endl;
    return false;
  }

  std::cout << "[ClamAV] freshclam.exe completed successfully." << std::endl;
  return true;
}

void UpdateClamAvDefinitionsIfNeeded() {
  if (!IsClamAvDatabaseStale()) {
    std::cout << "[ClamAV] Definitions are current." << std::endl;
    return;
  }

  std::cout << "[ClamAV] Updating definitions via freshclam.exe..."
            << std::endl;
  if (!RunFreshclam()) {
    return;
  }

  if (g_clamavScanner && g_clamavScanner->IsReady()) {
    if (g_clamavScanner->ReloadDatabase()) {
      std::cout << "[ClamAV] Database reloaded after freshclam update."
                << std::endl;
    } else {
      std::cerr << "[ClamAV] Database reload failed after freshclam update."
                << std::endl;
    }
  }
}

void StartClamAvDefinitionUpdateThread() {
  std::thread([]() {
    while (true) {
      std::this_thread::sleep_for(CLAMAV_UPDATE_INTERVAL);
      UpdateClamAvDefinitionsIfNeeded();
    }
  }).detach();
}

// YARA Callback
int yara_callback(YR_SCAN_CONTEXT *context, int message, void *message_data,
                  void *user_data) {
  if (message == CALLBACK_MSG_RULE_MATCHING) {
    auto *matches = static_cast<std::vector<std::string> *>(user_data);
    auto *rule = static_cast<YR_RULE *>(message_data);
    std::string rule_name = rule->identifier;

    // Always check for VMProtect
    std::string lowerMatch = rule_name;
    std::transform(lowerMatch.begin(), lowerMatch.end(), lowerMatch.begin(),
                   ::tolower);
    if (lowerMatch.find("vmprotect") != std::string::npos) {
      // We use a special marker or just add it to a separate vector.
      // Wait, we can't easily pass two vectors.
      // But look at ProcessRequest! It checks the resulting yaraMatches vector.
      // So if we exclude it here, ProcessRequest won't see it to set
      // is_vmprotect. We must add it to matches if it's vmprotect, OR pass a
      // special struct. Alternatively, in HydraDragonAV.cpp we can just not
      // exclude it from yaraMatches here, but exclude it in ProcessRequest for
      // the final JSON. Let's do it in ProcessRequest.
    }

    if (g_excludedRules.find(rule_name) == g_excludedRules.end()) {
      matches->push_back(rule_name);
    } else if (lowerMatch.find("vmprotect") != std::string::npos) {
      // It IS excluded, but it's a vmprotect rule. We still need the main logic
      // to see it. Let's push a special prefix to indicate it's only for
      // vmprotect and should not trigger malicious.
      matches->push_back("VMPROTECT_ONLY:" + rule_name);
    }
  }
  return CALLBACK_CONTINUE;
}

// Logic to load YARA rules
bool LoadYaraRules() {
  YR_COMPILER *compiler = nullptr;
  if (yr_compiler_create(&compiler) != 0)
    return false;

  std::error_code ec;
  if (fs::exists(YARA_RULES_FOLDER, ec)) {
    for (const auto &entry : fs::directory_iterator(YARA_RULES_FOLDER, ec)) {
      if (ec)
        break;
      if (entry.path().extension() == ".yar") {
        std::ifstream file(entry.path());
        if (!file.is_open())
          continue;
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());

        // Use the filename as the identifier for errors
        std::string fileName = entry.path().filename().string();
        if (yr_compiler_add_string(compiler, content.c_str(), nullptr) != 0) {
          std::cerr << "[YARA] Failed to compile: " << fileName << std::endl;
        }
      }
    }
  } else {
    std::cerr << "[YARA] Rules folder not found: "
              << fs::path(YARA_RULES_FOLDER).string() << std::endl;
  }

  if (yr_compiler_get_rules(compiler, &g_yaraRules) != 0) {
    yr_compiler_destroy(compiler);
    return false;
  }

  yr_compiler_destroy(compiler);
  return true;
}

void ProcessRequest(const std::string &request, std::string &response) {
  // Basic JSON extraction for {"path": "..."}
  std::string filePathStr;
  size_t path_key_pos = request.find("\"path\"");
  if (path_key_pos != std::string::npos) {
    size_t colon_pos = request.find(":", path_key_pos);
    if (colon_pos != std::string::npos) {
      size_t start_quote = request.find("\"", colon_pos);
      if (start_quote != std::string::npos) {
        size_t end_quote = request.find("\"", start_quote + 1);
        if (end_quote != std::string::npos) {
          filePathStr =
              request.substr(start_quote + 1, end_quote - start_quote - 1);
        }
      }
    }
  }

  if (filePathStr.empty()) {
    response =
        "{\"status\":\"error\", \"message\":\"missing or invalid path\"}";
    return;
  }

  g_totalScanRequests.fetch_add(1, std::memory_order_relaxed);

  // Convert escaped backslashes if any (basic)
  std::string cleanPath;
  for (size_t i = 0; i < filePathStr.size(); ++i) {
    if (filePathStr[i] == '\\' && i + 1 < filePathStr.size() &&
        filePathStr[i + 1] == '\\') {
      cleanPath += '\\';
      i++;
    } else {
      cleanPath += filePathStr[i];
    }
  }

  // Convert to wstring for ClamAV and filesystem check
  std::wstring wFilePath;
  int len = MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, NULL, 0);
  if (len > 0) {
    std::vector<wchar_t> wbuf(len);
    MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, wbuf.data(), len);
    wFilePath = wbuf.data();
  } else {
    // Fallback simple conversion
    wFilePath.assign(cleanPath.begin(), cleanPath.end());
  }


  if (fs::exists(wFilePath)) {
    std::string cachedResponse;
    if (TryGetCachedScanResponse(wFilePath, cachedResponse)) {
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
      std::cout << "[Cache] Returning cached scan result for: " << cleanPath
                << std::endl;
#endif
      response = cachedResponse;
      return;
    }
  }

  std::vector<std::string> yaraMatches;
  std::string clamavVirusName;
  std::string xvirusDetectionName;
  double xvirusMalwareScore = 0.0;
  bool isMalicious = false;

  bool is_vmprotect = false;

  // YARA Scan
  if (g_yaraRules && fs::exists(wFilePath)) {
    std::vector<std::string> rawMatches;
    yr_rules_scan_file(g_yaraRules, cleanPath.c_str(), 0, yara_callback,
                       &rawMatches, 0);

    for (const auto &match : rawMatches) {
      std::string lowerMatch = match;
      std::transform(lowerMatch.begin(), lowerMatch.end(), lowerMatch.begin(),
                     ::tolower);

      if (lowerMatch.find("vmprotect") != std::string::npos) {
        is_vmprotect = true;
      }

      if (match.find("VMPROTECT_ONLY:") == 0) {
        // This rule was excluded from detection, but flagged for VMProtect.
        // Skip adding to JSON.
        continue;
      }

      isMalicious = true;
      yaraMatches.push_back(match);
    }
  }

  // ClamAV Scan
  if (g_clamavScanner && g_clamavScanner->IsReady() && fs::exists(wFilePath)) {
    auto result = g_clamavScanner->ScanFile(wFilePath);
    if (result.IsVirus()) {
      clamavVirusName = result.virus_name;
      isMalicious = true;
    }
  }

  // Build JSON Response
  std::stringstream ss;
  ss << "{\"status\":\"success\", \"malicious\":"
     << (isMalicious ? "true" : "false")
     << ", \"is_vmprotect\":" << (is_vmprotect ? "true" : "false")
     << ", \"yara\":[";
  for (size_t i = 0; i < yaraMatches.size(); ++i) {
    ss << "\"" << yaraMatches[i] << "\""
       << (i == yaraMatches.size() - 1 ? "" : ",");
  }
  ss << "], \"clamav\":\"" << clamavVirusName << "\"}";
  response = ss.str();

  if (fs::exists(wFilePath)) {
    StoreCachedScanResponse(wFilePath, response);
  }
}

int main() {
  std::cout << "[HydraDragonAV] Starting SCANNER ENGINE (Pipe Server)..."
            << std::endl;
  StartMemoryGuardThread();

  // Initialize YARA
  if (yr_initialize() != 0) {
    std::cerr << "[YARA] Failed to initialize YARA library." << std::endl;
    return 1;
  }
  if (!LoadYaraRules()) {
    std::cerr << "[YARA] Warning: Failed to load YARA rules or folder empty."
              << std::endl;
  }
  LoadExcludedRules();

  // Initialize ClamAV
  std::cout << "[ClamAV] Initializing Scanner..." << std::endl;
  UpdateClamAvDefinitionsIfNeeded();
  g_clamavScanner = clamav::Scanner::CreateAsync(CLAMAV_DLL, CLAMAV_DB);
  StartClamAvDefinitionUpdateThread();

  // We don't block main here; if a scan comes in before ready, ScanFile will
  // handle it or wait

  while (true) {
    HANDLE hPipe =
        CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         PIPE_UNLIMITED_INSTANCES,
                         1024 * 64, // Larger buffer for paths/results
                         1024 * 64, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
      std::cerr << "[Pipe] Failed to create named pipe. Error: "
                << GetLastError() << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(2));
      continue;
    }

    if (ConnectNamedPipe(hPipe, NULL) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
      char buffer[65536]; // Support very long paths
      DWORD bytesRead;
      if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        std::string request(buffer);
        std::string response;

        ProcessRequest(request, response);

        DWORD bytesWritten;
        WriteFile(hPipe, response.c_str(), (DWORD)response.size(),
                  &bytesWritten, NULL);
        FlushFileBuffers(hPipe);
      }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
  }

  if (g_yaraRules)
    yr_rules_destroy(g_yaraRules);
  yr_finalize();

  return 0;
}
