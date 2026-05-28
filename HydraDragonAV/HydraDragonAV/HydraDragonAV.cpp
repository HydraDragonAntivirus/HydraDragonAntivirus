#include "HydraDragonAV.h"
#include "ClamAVScanner.h"
#include "framework.h"
#include <Windows.h>
#include <Psapi.h>
#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <queue>
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

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
#define PIPE_NAME           L"\\\\.\\pipe\\HydraDragonAV"
#define CLAMAV_DIR          L"C:\\Program Files\\ClamAV\\"
#define HYDRADRAGON_DIR     L"C:\\Program Files\\HydraDragonAntivirus\\"
#define CLAMAV_DLL          CLAMAV_DIR  L"libclamav.dll"
#define CLAMAV_DB           CLAMAV_DIR  L"database"
#define FRESHCLAM_EXE       CLAMAV_DIR  L"freshclam.exe"
#define YARA_RULES_FOLDER   HYDRADRAGON_DIR L"hydradragon\\yara\\"

// ---------------------------------------------------------------------------
// Scanner globals
// ---------------------------------------------------------------------------
static std::unique_ptr<clamav::Scanner> g_clamavScanner;
static std::vector<YR_RULES*> g_yaraRulesets;
constexpr auto  CLAMAV_UPDATE_INTERVAL        = std::chrono::hours(2);
constexpr auto  CLAMAV_DEFINITION_MAX_AGE     = std::chrono::hours(12);
constexpr DWORD FRESHCLAM_TIMEOUT_MS          = 180u * 1000u;

static std::unordered_set<std::string> g_excludedRules;

// ---------------------------------------------------------------------------
// Memory guard.
// Uses a baseline + growth limit instead of a low fixed cap. ClamAV can
// legitimately reserve hundreds of MiB after loading signatures, so a fixed
// 512 MiB process limit can cause restart loops.
// ---------------------------------------------------------------------------
constexpr SIZE_T HYDRADRAGON_PRIVATE_BYTES_GROWTH_LIMIT =
    static_cast<SIZE_T>(512ull * 1024ull * 1024ull); // baseline + 512 MiB
constexpr SIZE_T HYDRADRAGON_PRIVATE_BYTES_ABSOLUTE_LIMIT =
    static_cast<SIZE_T>(1536ull * 1024ull * 1024ull); // emergency cap: 1.5 GiB
constexpr auto MEMORY_MONITOR_INTERVAL = std::chrono::seconds(30);
constexpr UINT HYDRADRAGON_MEMORY_RECYCLE_EXIT_CODE = 100;

static std::atomic<SIZE_T> g_memoryBaselinePrivateBytes{0};

// ---------------------------------------------------------------------------
// ClamAV engine recycle interval.
// cl_scanfile() accumulates heap fragmentation inside libclamav.dll over
// thousands of scans. Periodically destroying and recreating the engine
// (via ReloadDatabase) flushes that internal state completely.
// ---------------------------------------------------------------------------
constexpr std::uint64_t CLAMAV_ENGINE_RECYCLE_INTERVAL = 25'000; // scans
static std::atomic<std::uint64_t> g_scansSinceEngineRecycle{0};
static std::mutex g_engineRecycleMutex; // one recycle at a time

// ---------------------------------------------------------------------------
// Hard file-size caps for YARA and ClamAV.
// Unbounded scans on multi-hundred-MB files (installers, ISOs) can cause
// enormous transient allocations inside both engines.
// ---------------------------------------------------------------------------
constexpr std::uintmax_t YARA_MAX_SCAN_BYTES   = 64ull  * 1024ull * 1024ull; //  64 MiB
constexpr std::uintmax_t CLAMAV_MAX_SCAN_BYTES = 256ull * 1024ull * 1024ull; // 256 MiB

// ---------------------------------------------------------------------------
// Scan cache
// ---------------------------------------------------------------------------
struct ScanCacheEntry {
    std::uintmax_t            fileSize       = 0;
    fs::file_time_type        lastWriteTime  = {};
    std::chrono::steady_clock::time_point cachedAt = {};
    std::string               response;
};

static std::mutex g_scanCacheMutex;
static std::unordered_map<std::wstring, ScanCacheEntry> g_scanCache;

constexpr auto        SCAN_CACHE_TTL         = std::chrono::seconds(30);
constexpr std::size_t SCAN_CACHE_MAX_ENTRIES = 4096;

// Total requests counter (used by memory guard log)
static std::atomic<std::uint64_t> g_totalScanRequests{0};

// ---------------------------------------------------------------------------
// Thread-pool pipe server.
// The original design serialised every scan: accept → read → scan → write
// on a single thread. Under burst load, clients pile up waiting behind a
// slow YARA/ClamAV scan. This pool allows N concurrent scan threads while
// the accept loop keeps accepting new connections immediately.
// ---------------------------------------------------------------------------
static constexpr std::size_t PIPE_WORKER_THREADS = 4; // tune to core count

struct PipeWorkItem {
    HANDLE hPipe;
};

static std::queue<PipeWorkItem>   g_pipeQueue;
static std::mutex                 g_pipeQueueMutex;
static std::condition_variable    g_pipeQueueCV;
static std::atomic<bool>          g_shutdown{false};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------


std::string JsonEscapeString(const std::string& value) {
    static constexpr char kHex[] = "0123456789ABCDEF";

    std::string escaped;
    escaped.reserve(value.size() + 16);

    for (unsigned char ch : value) {
        switch (ch) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (ch < 0x20) {
                escaped += "\\u00";
                escaped.push_back(kHex[(ch >> 4) & 0x0F]);
                escaped.push_back(kHex[ch & 0x0F]);
            } else {
                escaped.push_back(static_cast<char>(ch));
            }
            break;
        }
    }

    return escaped;
}

std::string BuildJsonErrorResponse(const std::string& message) {
    return std::string("{\"status\":\"error\",\"message\":\"") +
           JsonEscapeString(message) + "\"}";
}

SIZE_T GetCurrentProcessPrivateBytes() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(),
                              reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters),
                              sizeof(counters))) {
        return 0;
    }
    return counters.PrivateUsage;
}

// ---------------------------------------------------------------------------
// Heap-trim thread.
// After heavy scan bursts the CRT / Windows heap holds onto free blocks.
// HeapCompact coalesces them; SetProcessWorkingSetSize(-1,-1) tells the
// kernel it may reclaim the now-idle physical pages — reducing the RSS that
// RADAR monitors.  Runs every 5 minutes, completely off the hot path.
// ---------------------------------------------------------------------------
void StartHeapTrimThread() {
    std::thread([]() {
        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(std::chrono::minutes(5));

            ::HeapCompact(::GetProcessHeap(), 0);
            ::SetProcessWorkingSetSize(::GetCurrentProcess(),
                                       static_cast<SIZE_T>(-1),
                                       static_cast<SIZE_T>(-1));
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
            std::cout << "[HeapTrim] Compacted heap and trimmed working set."
                      << std::endl;
#endif
        }
    }).detach();
}

void StartMemoryGuardThread() {
    std::thread([]() {
        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(MEMORY_MONITOR_INTERVAL);

            const SIZE_T privateBytes = GetCurrentProcessPrivateBytes();
            if (privateBytes == 0) continue;

            SIZE_T baseline = g_memoryBaselinePrivateBytes.load(std::memory_order_relaxed);
            if (baseline == 0) {
                g_memoryBaselinePrivateBytes.store(privateBytes, std::memory_order_relaxed);
                baseline = privateBytes;
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
                std::cout << "[MemoryGuard] baseline_private_bytes=" << baseline
                          << std::endl;
#endif
                continue;
            }

            const SIZE_T growthLimit = baseline + HYDRADRAGON_PRIVATE_BYTES_GROWTH_LIMIT;
            const bool exceededGrowth = privateBytes >= growthLimit;
            const bool exceededAbsolute = privateBytes >= HYDRADRAGON_PRIVATE_BYTES_ABSOLUTE_LIMIT;

#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
            std::cout << "[MemoryGuard] private_bytes=" << privateBytes
                      << " baseline=" << baseline
                      << " growth_limit=" << growthLimit
                      << " absolute_limit=" << HYDRADRAGON_PRIVATE_BYTES_ABSOLUTE_LIMIT
                      << " scans=" << g_totalScanRequests.load() << std::endl;
#endif

            if (exceededGrowth || exceededAbsolute) {
                std::cerr << "[MemoryGuard] HydraDragonAV private memory reached "
                          << privateBytes << " bytes after "
                          << g_totalScanRequests.load()
                          << " scan requests. Baseline=" << baseline
                          << ", growth_limit=" << growthLimit
                          << ", absolute_limit="
                          << HYDRADRAGON_PRIVATE_BYTES_ABSOLUTE_LIMIT
                          << ". Recycling scanner process."
                          << std::endl;
                ExitProcess(HYDRADRAGON_MEMORY_RECYCLE_EXIT_CODE);
            }
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// Periodic ClamAV engine recycle.
// Every CLAMAV_ENGINE_RECYCLE_INTERVAL scans we call ReloadDatabase(),
// which in ClamAVScanner.cpp frees the old cl_engine, allocates a fresh one,
// and reloads signatures.  This flushes all accumulated libclamav internal
// heap fragmentation without a full process restart.
// ---------------------------------------------------------------------------
static void MaybeRecycleClamAvEngine() {
    const auto count = g_scansSinceEngineRecycle.fetch_add(1, std::memory_order_relaxed) + 1;
    if (count < CLAMAV_ENGINE_RECYCLE_INTERVAL) return;

    // Only one thread should run the recycle; others skip and reset.
    std::unique_lock<std::mutex> lock(g_engineRecycleMutex, std::try_to_lock);
    if (!lock.owns_lock()) return;

    g_scansSinceEngineRecycle.store(0, std::memory_order_relaxed);

    if (!g_clamavScanner || !g_clamavScanner->IsReady()) return;

    std::cout << "[ClamAV] Scheduled engine recycle after "
              << CLAMAV_ENGINE_RECYCLE_INTERVAL << " scans." << std::endl;

    if (g_clamavScanner->ReloadDatabase()) {
        // Compact heap right after the engine free/alloc cycle.
        ::HeapCompact(::GetProcessHeap(), 0);
        std::cout << "[ClamAV] Engine recycled and heap compacted." << std::endl;
    } else {
        std::cerr << "[ClamAV] Engine recycle (ReloadDatabase) failed." << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Excluded rules loader
// ---------------------------------------------------------------------------
void LoadExcludedRules() {
    const std::string path =
        "C:\\Program Files\\HydraDragonAntivirus\\hydradragon"
        "\\excluded_yara_rules\\excluded_yara_rules.txt";
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[YARA] Excluded rules file not found at " << path << std::endl;
        return;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) g_excludedRules.insert(line);
    }
    std::cout << "[YARA] Loaded " << g_excludedRules.size()
              << " excluded rules." << std::endl;
}

// ---------------------------------------------------------------------------
// Scan cache helpers
// ---------------------------------------------------------------------------
std::wstring NormalizeCachePath(const std::wstring& path) {
    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
    return normalized;
}

bool TryGetCachedScanResponse(const std::wstring& path, std::string& response) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec || !fs::is_regular_file(path, ec) || ec) return false;

    const auto fileSize      = fs::file_size(path, ec);       if (ec) return false;
    const auto lastWriteTime = fs::last_write_time(path, ec); if (ec) return false;

    const auto key = NormalizeCachePath(path);
    const auto now = std::chrono::steady_clock::now();

    std::lock_guard<std::mutex> lock(g_scanCacheMutex);

    auto it = g_scanCache.find(key);
    if (it == g_scanCache.end()) return false;

    const auto& entry = it->second;
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

// LRU single-entry eviction replaces the old nuke-all
// g_scanCache.clear().  The original strategy erased 4096 heap allocations
// at once → massive free-list churn → heap fragmentation that RADAR read as
// a leak. Evicting one oldest entry per insertion keeps the heap steady.
void StoreCachedScanResponse(const std::wstring& path, const std::string& response) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec || !fs::is_regular_file(path, ec) || ec) return;

    const auto fileSize      = fs::file_size(path, ec);       if (ec) return;
    const auto lastWriteTime = fs::last_write_time(path, ec); if (ec) return;

    const auto key = NormalizeCachePath(path);

    std::lock_guard<std::mutex> lock(g_scanCacheMutex);

    // [FIX] Evict the single oldest entry instead of clearing the whole map.
    if (g_scanCache.size() >= SCAN_CACHE_MAX_ENTRIES) {
        auto oldest = g_scanCache.begin();
        for (auto it = g_scanCache.begin(); it != g_scanCache.end(); ++it) {
            if (it->second.cachedAt < oldest->second.cachedAt)
                oldest = it;
        }
        g_scanCache.erase(oldest);
    }

    g_scanCache[key] = ScanCacheEntry{
        fileSize,
        lastWriteTime,
        std::chrono::steady_clock::now(),
        response,
    };
}

// ---------------------------------------------------------------------------
// ClamAV definition staleness / update
// ---------------------------------------------------------------------------
bool IsClamAvDatabaseStale() {
    std::error_code ec;
    const fs::path dbPath(CLAMAV_DB);
    if (!fs::exists(dbPath, ec) || !fs::is_directory(dbPath, ec)) {
        std::cerr << "[ClamAV] Database directory missing: "
                  << dbPath.string() << std::endl;
        return true;
    }

    bool foundDefinition = false;
    fs::file_time_type latestDefinition{};
    for (const auto& entry : fs::directory_iterator(dbPath, ec)) {
        if (ec) {
            std::cerr << "[ClamAV] Failed to enumerate database directory: "
                      << ec.message() << std::endl;
            return true;
        }
        std::error_code entryEc;
        if (!entry.is_regular_file(entryEc)) continue;

        std::wstring extension = entry.path().extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
        if (extension != L".cvd" && extension != L".cld") continue;

        const auto writeTime = entry.last_write_time(entryEc);
        if (entryEc) {
            std::cerr << "[ClamAV] Failed to read definition timestamp: "
                      << entry.path().string() << std::endl;
            continue;
        }
        if (!foundDefinition || writeTime > latestDefinition) {
            latestDefinition  = writeTime;
            foundDefinition   = true;
        }
    }

    if (!foundDefinition) {
        std::cerr << "[ClamAV] No .cvd/.cld definition files found." << std::endl;
        return true;
    }
    return latestDefinition + CLAMAV_DEFINITION_MAX_AGE < fs::file_time_type::clock::now();
}

bool RunFreshclam() {
    std::error_code ec;
    const fs::path freshclamPath(FRESHCLAM_EXE);
    if (!fs::exists(freshclamPath, ec)) {
        std::cerr << "[ClamAV] freshclam.exe not found: "
                  << freshclamPath.string() << std::endl;
        return false;
    }

    std::wstring applicationName = freshclamPath.wstring();
    std::wstring commandLine     = L"\"" + applicationName + L"\"";
    std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
    mutableCommandLine.push_back(L'\0');

    STARTUPINFOW       startupInfo{};  startupInfo.cb = sizeof(startupInfo);
    PROCESS_INFORMATION processInfo{};

    const BOOL created = CreateProcessW(
        applicationName.c_str(), mutableCommandLine.data(),
        nullptr, nullptr, FALSE, 0, nullptr, CLAMAV_DIR,
        &startupInfo, &processInfo);

    if (!created) {
        std::cerr << "[ClamAV] Failed to start freshclam.exe. Error: "
                  << GetLastError() << std::endl;
        return false;
    }

    const DWORD waitResult = WaitForSingleObject(processInfo.hProcess, FRESHCLAM_TIMEOUT_MS);
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
        std::cerr << "[ClamAV] freshclam.exe failed with code " << exitCode << std::endl;
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
    std::cout << "[ClamAV] Updating definitions via freshclam.exe..." << std::endl;
    if (!RunFreshclam()) return;

    if (g_clamavScanner && g_clamavScanner->IsReady()) {
        if (g_clamavScanner->ReloadDatabase()) {
            std::cout << "[ClamAV] Database reloaded after freshclam update." << std::endl;
        } else {
            std::cerr << "[ClamAV] Database reload failed after freshclam update." << std::endl;
        }
    }
}

void StartClamAvDefinitionUpdateThread() {
    std::thread([]() {
        while (!g_shutdown.load()) {
            std::this_thread::sleep_for(CLAMAV_UPDATE_INTERVAL);
            UpdateClamAvDefinitionsIfNeeded();
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// YARA callback
// ---------------------------------------------------------------------------
int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data,
                  void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* matches   = static_cast<std::vector<std::string>*>(user_data);
        auto* rule      = static_cast<YR_RULE*>(message_data);
        std::string rule_name = rule->identifier;

        std::string lowerMatch = rule_name;
        std::transform(lowerMatch.begin(), lowerMatch.end(),
                       lowerMatch.begin(), ::tolower);

        if (g_excludedRules.find(rule_name) == g_excludedRules.end()) {
            matches->push_back(rule_name);
        } else if (lowerMatch.find("vmprotect") != std::string::npos) {
            matches->push_back("VMPROTECT_ONLY:" + rule_name);
        }
    }
    return CALLBACK_CONTINUE;
}

// ---------------------------------------------------------------------------
// YARA compiled rules loader
// ---------------------------------------------------------------------------
bool LoadYaraRules() {
    g_yaraRulesets.clear();

    std::error_code ec;
    const fs::path rulesFolder(YARA_RULES_FOLDER);

    if (!fs::exists(rulesFolder, ec) || !fs::is_directory(rulesFolder, ec)) {
        std::cerr << "[YARA] Compiled rules folder not found: "
                  << rulesFolder.string() << std::endl;
        return false;
    }

    std::size_t loadedRulesets = 0;

    for (const auto& entry : fs::directory_iterator(rulesFolder, ec)) {
        if (ec) {
            std::cerr << "[YARA] Failed to enumerate rules folder: "
                      << ec.message() << std::endl;
            break;
        }

        std::error_code entryEc;
        if (!entry.is_regular_file(entryEc) || entryEc) {
            continue;
        }

        std::wstring extension = entry.path().extension().wstring();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });

        // HydraDragon ships compiled YARA rules. Source .yar files are not
        // compiled at runtime. .yrc is the compiled ruleset format.
        if (extension != L".yrc") {
            continue;
        }

        const std::string compiledPath = entry.path().string();
        YR_RULES* rules = nullptr;
        const int loadResult = yr_rules_load(compiledPath.c_str(), &rules);

        if (loadResult != ERROR_SUCCESS || rules == nullptr) {
            std::cerr << "[YARA] Failed to load compiled ruleset: "
                      << compiledPath << " error=" << loadResult << std::endl;
            if (rules != nullptr) {
                yr_rules_destroy(rules);
            }
            continue;
        }

        g_yaraRulesets.push_back(rules);
        ++loadedRulesets;

#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
        std::cout << "[YARA] Loaded compiled ruleset: "
                  << compiledPath << std::endl;
#endif
    }

    std::cout << "[YARA] Loaded " << loadedRulesets
              << " compiled .yrc ruleset(s)." << std::endl;

    if (loadedRulesets == 0) {
        std::cerr << "[YARA] No compiled .yrc rulesets were loaded from: "
                  << rulesFolder.string() << std::endl;
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// ProcessRequest — core scan logic
// ---------------------------------------------------------------------------
void ProcessRequest(const std::string& request, std::string& response) {
    // Basic JSON extraction for {"path": "..."}
    std::string filePathStr;
    size_t path_key_pos = request.find("\"path\"");
    if (path_key_pos != std::string::npos) {
        size_t colon_pos   = request.find(":", path_key_pos);
        if (colon_pos != std::string::npos) {
            size_t start_quote = request.find("\"", colon_pos);
            if (start_quote != std::string::npos) {
                size_t end_quote = request.find("\"", start_quote + 1);
                if (end_quote != std::string::npos)
                    filePathStr = request.substr(start_quote + 1,
                                                  end_quote - start_quote - 1);
            }
        }
    }

    if (filePathStr.empty()) {
        response = BuildJsonErrorResponse("missing or invalid path");
        return;
    }

    g_totalScanRequests.fetch_add(1, std::memory_order_relaxed);

    // Unescape double-backslashes
    std::string cleanPath;
    for (size_t i = 0; i < filePathStr.size(); ++i) {
        if (filePathStr[i] == '\\' && i + 1 < filePathStr.size() &&
            filePathStr[i + 1] == '\\') {
            cleanPath += '\\';
            ++i;
        } else {
            cleanPath += filePathStr[i];
        }
    }

    // UTF-8 → wstring
    std::wstring wFilePath;
    int len = MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, nullptr, 0);
    if (len > 0) {
        std::vector<wchar_t> wbuf(len);
        MultiByteToWideChar(CP_UTF8, 0, cleanPath.c_str(), -1, wbuf.data(), len);
        wFilePath = wbuf.data();
    } else {
        wFilePath.assign(cleanPath.begin(), cleanPath.end());
    }

    // Cache hit?
    if (fs::exists(wFilePath)) {
        std::string cachedResponse;
        if (TryGetCachedScanResponse(wFilePath, cachedResponse)) {
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
            std::cout << "[Cache] Returning cached scan result for: "
                      << cleanPath << std::endl;
#endif
            response = cachedResponse;
            return;
        }
    }

    std::vector<std::string> yaraMatches;
    std::string              clamavVirusName;
    bool                     isMalicious  = false;
    bool                     is_vmprotect = false;

    // YARA: scan with compiled .yrc rulesets. Skip oversized files and
    // keep a timeout so a problematic rule cannot stall the pipe worker.
    if (!g_yaraRulesets.empty() && fs::exists(wFilePath)) {
        std::error_code ec;
        const auto fileBytes = fs::file_size(wFilePath, ec);

        if (!ec && fileBytes <= YARA_MAX_SCAN_BYTES) {
            std::vector<std::string> rawMatches;

            for (YR_RULES* ruleset : g_yaraRulesets) {
                if (ruleset == nullptr) {
                    continue;
                }

                yr_rules_scan_file(ruleset, cleanPath.c_str(), 0,
                                   yara_callback, &rawMatches, 60);
            }

            for (const auto& match : rawMatches) {
                std::string lowerMatch = match;
                std::transform(lowerMatch.begin(), lowerMatch.end(),
                               lowerMatch.begin(), ::tolower);

                if (lowerMatch.find("vmprotect") != std::string::npos)
                    is_vmprotect = true;

                if (match.find("VMPROTECT_ONLY:") == 0) continue;

                isMalicious = true;
                yaraMatches.push_back(match);
            }
        } else if (!ec) {
            std::cout << "[YARA] Skipping oversized file ("
                      << fileBytes << " bytes): " << cleanPath << std::endl;
        }
    }

    // [FIX 3 — ClamAV] Skip oversized files.
    if (g_clamavScanner && g_clamavScanner->IsReady() && fs::exists(wFilePath)) {
        std::error_code ec;
        const auto fileBytes = fs::file_size(wFilePath, ec);

        if (!ec && fileBytes <= CLAMAV_MAX_SCAN_BYTES) {
            auto result = g_clamavScanner->ScanFile(wFilePath);
            if (result.IsVirus()) {
                clamavVirusName = result.virus_name;
                isMalicious     = true;
            }
        } else if (!ec) {
            std::cout << "[ClamAV] Skipping oversized file ("
                      << fileBytes << " bytes): " << cleanPath << std::endl;
        }
    }

    // Trigger periodic engine recycle.
    MaybeRecycleClamAvEngine();

    // Build JSON response.
    // Never concatenate unescaped YARA/ClamAV strings directly into JSON:
    // rule names and signatures may contain quotes, backslashes, newlines or
    // control characters, which would break Owlyshield's serde_json parser.
    std::stringstream ss;
    ss << "{\"status\":\"success\",\"malicious\":"
       << (isMalicious ? "true" : "false")
       << ",\"is_vmprotect\":" << (is_vmprotect ? "true" : "false")
       << ",\"yara\":[";
    for (size_t i = 0; i < yaraMatches.size(); ++i) {
        ss << "\"" << JsonEscapeString(yaraMatches[i]) << "\""
           << (i + 1 == yaraMatches.size() ? "" : ",");
    }
    ss << "],\"clamav\":\"" << JsonEscapeString(clamavVirusName) << "\"}";
    response = ss.str();

    if (fs::exists(wFilePath))
        StoreCachedScanResponse(wFilePath, response);
}

// ---------------------------------------------------------------------------
// Thread-pool worker — handles one connected pipe client.
// ---------------------------------------------------------------------------
void PipeWorkerThread() {
    while (!g_shutdown.load()) {
        HANDLE hPipe = INVALID_HANDLE_VALUE;

        {
            std::unique_lock<std::mutex> lock(g_pipeQueueMutex);
            g_pipeQueueCV.wait(lock, []() {
                return !g_pipeQueue.empty() || g_shutdown.load();
            });
            if (g_shutdown.load()) break;
            hPipe = g_pipeQueue.front().hPipe;
            g_pipeQueue.pop();
        }

        if (hPipe == INVALID_HANDLE_VALUE) continue;

        char  buffer[65536];
        DWORD bytesRead = 0;
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
            buffer[bytesRead] = '\0';
            std::string request(buffer);
            std::string response;
            ProcessRequest(request, response);
            DWORD bytesWritten = 0;
            WriteFile(hPipe, response.c_str(),
                      static_cast<DWORD>(response.size()),
                      &bytesWritten, nullptr);
            FlushFileBuffers(hPipe);
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "[HydraDragonAV] Starting SCANNER ENGINE (Pipe Server)..."
              << std::endl;

    // Enable Low Fragmentation Heap for the process heap.
    // LFH dramatically reduces heap fragmentation from thousands of small
    // alloc/free cycles (cache strings, YARA match vectors, etc.).
    {
        ULONG heapType = 2; // HeapCompatibilityInformation — enable LFH
        ::HeapSetInformation(::GetProcessHeap(),
                             HeapCompatibilityInformation,
                             &heapType, sizeof(heapType));
    }

    StartMemoryGuardThread();
    StartHeapTrimThread();

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

    // Initialize ClamAV. Do not run freshclam synchronously before the
    // pipe server starts; a slow update must not make the engine look dead.
    std::cout << "[ClamAV] Initializing Scanner..." << std::endl;
    g_clamavScanner = clamav::Scanner::CreateAsync(CLAMAV_DLL, CLAMAV_DB);

    std::thread([]() {
        UpdateClamAvDefinitionsIfNeeded();
    }).detach();

    StartClamAvDefinitionUpdateThread();

    // Spin up the pipe worker thread pool.
    std::vector<std::thread> workers;
    workers.reserve(PIPE_WORKER_THREADS);
    for (std::size_t i = 0; i < PIPE_WORKER_THREADS; ++i)
        workers.emplace_back(PipeWorkerThread);

    // Accept loop — creates a pipe instance, waits for a client, hands it
    // off to the pool immediately so the next client is never kept waiting.
    while (!g_shutdown.load()) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024 * 64,
            1024 * 64,
            0,
            nullptr);

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[Pipe] Failed to create named pipe. Error: "
                      << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        // Block until a client connects, then immediately hand off.
        if (ConnectNamedPipe(hPipe, nullptr) ||
            GetLastError() == ERROR_PIPE_CONNECTED) {
            std::lock_guard<std::mutex> lock(g_pipeQueueMutex);
            g_pipeQueue.push({hPipe});
            g_pipeQueueCV.notify_one();
        } else {
            // No client actually connected; discard this instance.
            CloseHandle(hPipe);
        }
    }

    // Graceful shutdown
    g_shutdown.store(true);
    g_pipeQueueCV.notify_all();
    for (auto& t : workers) {
        if (t.joinable()) t.join();
    }

    for (YR_RULES* ruleset : g_yaraRulesets) {
        if (ruleset != nullptr) {
            yr_rules_destroy(ruleset);
        }
    }
    g_yaraRulesets.clear();
    yr_finalize();

    return 0;
}
