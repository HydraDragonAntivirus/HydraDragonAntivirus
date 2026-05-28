#include "HydraDragonAV.h"
#include "ClamAVScanner.h"
#include "framework.h"
#include <Windows.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

// YARA Headers
#include <yara.h>

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
constexpr DWORD FRESHCLAM_TIMEOUT_MS = 300u * 1000u;

static std::unordered_set<std::string> g_excludedRules;
static std::mutex g_clamavUpdateMutex;

std::string JsonEscape(const std::string &value) {
  std::ostringstream escaped;
  for (unsigned char ch : value) {
    switch (ch) {
    case '"':
      escaped << "\\\"";
      break;
    case '\\':
      escaped << "\\\\";
      break;
    case '\b':
      escaped << "\\b";
      break;
    case '\f':
      escaped << "\\f";
      break;
    case '\n':
      escaped << "\\n";
      break;
    case '\r':
      escaped << "\\r";
      break;
    case '\t':
      escaped << "\\t";
      break;
    default:
      if (ch < 0x20) {
        escaped << "\\u" << std::hex << std::uppercase;
        escaped.width(4);
        escaped.fill('0');
        escaped << static_cast<int>(ch);
        escaped << std::dec << std::nouppercase;
      } else {
        escaped << static_cast<char>(ch);
      }
      break;
    }
  }
  return escaped.str();
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
  std::unique_lock<std::mutex> updateLock(g_clamavUpdateMutex, std::try_to_lock);
  if (!updateLock.owns_lock()) {
    std::cout << "[ClamAV] Definition update already running; skipping duplicate request." << std::endl;
    return;
  }

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

void StartInitialClamAvDefinitionUpdateThread() {
  std::thread([]() {
    std::cout << "[ClamAV] Initial definition update will run in the background." << std::endl;

    // Avoid racing freshclam writes against libclamav's first database load.
    // If initialization takes too long or fails, still allow freshclam to try.
    if (g_clamavScanner) {
      for (int i = 0; i < 60 && g_clamavScanner->IsInitializing(); ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }

    UpdateClamAvDefinitionsIfNeeded();
  }).detach();
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

  int compiledCount = 0;
  int failedCount = 0;
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
          ++failedCount;
          std::cerr << "[YARA] Failed to compile: " << fileName << std::endl;
        } else {
          ++compiledCount;
        }
      }
    }
  } else {
    std::cerr << "[YARA] Rules folder not found: "
              << fs::path(YARA_RULES_FOLDER).string() << std::endl;
  }

  if (compiledCount == 0) {
    std::cerr << "[YARA] No .yar files compiled from "
              << fs::path(YARA_RULES_FOLDER).string() << std::endl;
    yr_compiler_destroy(compiler);
    return false;
  }

  if (yr_compiler_get_rules(compiler, &g_yaraRules) != 0) {
    yr_compiler_destroy(compiler);
    return false;
  }

  std::cout << "[YARA] Compiled " << compiledCount << " YARA rule file(s).";
  if (failedCount > 0) {
    std::cout << " Failed: " << failedCount;
  }
  std::cout << std::endl;

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
    ss << "\"" << JsonEscape(yaraMatches[i]) << "\""
       << (i == yaraMatches.size() - 1 ? "" : ",");
  }
  ss << "], \"clamav\":\"" << JsonEscape(clamavVirusName) << "\"}";
  response = ss.str();
}

int main() {
  std::cout << "[HydraDragonAV] Starting SCANNER ENGINE (Pipe Server)..."
            << std::endl;

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

  // Initialize ClamAV without blocking pipe creation. freshclam runs in the
  // background so the scanner engine can accept pipe requests immediately.
  std::cout << "[ClamAV] Initializing Scanner..." << std::endl;
  g_clamavScanner = clamav::Scanner::CreateAsync(CLAMAV_DLL, CLAMAV_DB);
  StartInitialClamAvDefinitionUpdateThread();
  StartClamAvDefinitionUpdateThread();

  std::cout << "[Pipe] Starting pipe server at \\\\.\\pipe\\HydraDragonAV..."
            << std::endl;

  while (true) {
    HANDLE hPipe =
        CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         PIPE_UNLIMITED_INSTANCES,
                         1024 * 64, // Larger buffer for paths/results
                         1024 * 64, 0, NULL);

    if (hPipe != INVALID_HANDLE_VALUE) {
      std::cout << "[Pipe] Pipe created. Waiting for client..." << std::endl;
    }

    if (hPipe == INVALID_HANDLE_VALUE) {
      std::cerr << "[Pipe] Failed to create named pipe. Error: "
                << GetLastError() << std::endl;
      std::this_thread::sleep_for(std::chrono::seconds(2));
      continue;
    }

    if (ConnectNamedPipe(hPipe, NULL) ||
        GetLastError() == ERROR_PIPE_CONNECTED) {
      std::cout << "[Pipe] Client connected." << std::endl;
      char buffer[65536]; // Support very long paths
      DWORD bytesRead;
      if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        buffer[bytesRead] = '\0';
        std::string request(buffer);
        std::string response;

        ProcessRequest(request, response);

        DWORD bytesWritten = 0;
        if (!WriteFile(hPipe, response.c_str(), (DWORD)response.size(),
                       &bytesWritten, NULL)) {
          std::cerr << "[Pipe] WriteFile failed. Error: " << GetLastError()
                    << std::endl;
        } else {
          std::cout << "[Pipe] Response sent (" << bytesWritten << " bytes)."
                    << std::endl;
        }
        FlushFileBuffers(hPipe);
      } else {
        std::cerr << "[Pipe] ReadFile failed. Error: " << GetLastError()
                  << std::endl;
      }
    } else {
      std::cerr << "[Pipe] ConnectNamedPipe failed. Error: " << GetLastError()
                << std::endl;
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
  }

  if (g_yaraRules)
    yr_rules_destroy(g_yaraRules);
  yr_finalize();

  return 0;
}
