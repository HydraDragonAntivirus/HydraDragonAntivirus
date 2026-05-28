#include "ClamAVScanner.h"

#include <filesystem>
#include <cstring>
#include <iostream>
#include <sstream>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace clamav {
namespace {

std::string TrimLineBreaks(std::string value) {
    while (!value.empty() && (value.back() == '\r' || value.back() == '\n')) {
        value.pop_back();
    }
    return value;
}

void DefaultLogger(const char* level, const std::string& message) {
    std::ostringstream oss;
    oss << "[ClamAV][" << (level ? level : "INFO") << "] " << message << '
';
    const std::string line = oss.str();
    const std::string level_str = level ? std::string(level) : std::string();
    const bool is_debug = level_str == "DEBUG";

#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
    ::OutputDebugStringA(line.c_str());
#endif

    // DEBUG messages are development-only. In release builds, do not print
    // clean-file spam to the user's terminal.
    if (is_debug) {
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
        std::cout << line;
#endif
        return;
    }

    if (level_str == "ERROR" || level_str == "WARN") {
        std::cerr << line;
    } else {
        std::cout << line;
    }
}

} // namespace

Scanner::Scanner(const std::wstring& libclamav_path,
                 const std::wstring& dbpath,
                 bool autoreload,
                 std::uint32_t dboptions,
                 EngineOptions engine_options,
                 LogCallback logger)
    : Scanner(libclamav_path,
              dbpath,
              autoreload,
              dboptions,
              std::move(engine_options),
              std::move(logger),
              false) {
}

Scanner::Scanner(const std::wstring& libclamav_path,
                 const std::wstring& dbpath,
                 bool autoreload,
                 std::uint32_t dboptions,
                 EngineOptions engine_options,
                 LogCallback logger,
                 bool defer_init)
    : libclamav_path_(libclamav_path),
      dbpath_(dbpath),
      autoreload_(autoreload),
      dboptions_(dboptions),
      engine_options_(std::move(engine_options)),
      logger_(std::move(logger)) {
    if (!logger_) {
        logger_ = DefaultLogger;
    }

    if (!defer_init) {
        init_in_progress_.store(true);
        SetInitStage("Starting");
        const bool ok = InitInternal();
        SignalInitFinished(ok);
    }
}

Scanner::~Scanner() {
    if (init_thread_.joinable()) {
        init_thread_.join();
    }

    Cleanup();
}

std::unique_ptr<Scanner> Scanner::CreateAsync(const std::wstring& libclamav_path,
                              const std::wstring& dbpath,
                              bool autoreload,
                              std::uint32_t dboptions,
                              EngineOptions engine_options,
                              LogCallback logger) {
    auto scanner = std::unique_ptr<Scanner>(new Scanner(libclamav_path,
                                                        dbpath,
                                                        autoreload,
                                                        dboptions,
                                                        std::move(engine_options),
                                                        std::move(logger),
                                                        true));
    scanner->StartAsyncInitialization();
    return scanner;
}

Scanner::EngineOptions Scanner::DefaultEngineOptions() {
    return {
        {0u, 512ul * 1024ul * 1024ul},
        {1u, 512ul * 1024ul * 1024ul},
        {2u, 50ul},
        {3u, 2000ul},
    };
}

bool Scanner::IsReady() const noexcept {
    return is_ready_.load();
}

bool Scanner::IsInitializing() const noexcept {
    return init_in_progress_.load();
}

std::string Scanner::GetInitStage() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return init_stage_;
}

std::string Scanner::GetInitError() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return init_error_;
}

bool Scanner::WaitUntilReady() {
    std::unique_lock<std::mutex> lock(state_mutex_);
    state_cv_.wait(lock, [this]() {
        return !init_in_progress_.load();
    });
    return init_success_ && is_ready_.load();
}

bool Scanner::WaitUntilReadyFor(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(state_mutex_);
    const bool finished = state_cv_.wait_for(lock, timeout, [this]() {
        return !init_in_progress_.load();
    });
    return finished && init_success_ && is_ready_.load();
}

ScanResult Scanner::ScanFile(const std::wstring& filepath) {
    if (!is_ready_.load()) {
        if (init_in_progress_.load()) {
            Log("INFO", "Scanner not ready yet. Waiting for background initialization to finish.");
            if (!WaitUntilReady()) {
                Log("ERROR", "Cannot scan: scanner initialization failed.");
                return {};
            }
        } else {
            Log("ERROR", "Cannot scan: scanner is not initialized.");
            return {};
        }
    }

    std::error_code ec;
    if (!fs::exists(filepath, ec) || ec) {
        Log("ERROR", "File does not exist: " + WideToUtf8(filepath));
        return {};
    }

    if (!fs::is_regular_file(filepath, ec) || ec) {
        Log("WARN", "Skipping non-regular file: " + WideToUtf8(filepath));
        return {};
    }

    const std::string utf8_path = WideToUtf8(filepath);
    const char* virname = nullptr;
    unsigned long bytes_scanned = 0;

#ifdef HYDRADRAGON_CLAMAV_COLLECT_SCAN_BYTES
    unsigned long* scanned_ptr = &bytes_scanned;
#else
    // Do not request scanned-byte telemetry by default.
    // This prevents LibClamAV warning spam:
    // cl_scanfile_callback: scanned_bytes exceeds UINT32_MAX
    unsigned long* scanned_ptr = nullptr;
#endif

    ClScanOptions scan_opts{};
    scan_opts.general = CL_SCAN_GENERAL_HEURISTICS;

    int result = -1;
    {
        std::lock_guard<std::mutex> lock(engine_mutex_);
        if (!api_.cl_scanfile || !engine_) {
            Log("ERROR", "Engine not initialized.");
            return {};
        }

        result = api_.cl_scanfile(
            utf8_path.c_str(),
            &virname,
            scanned_ptr,
            engine_,
            &scan_opts);
    }

    ScanResult output;
    output.result_code = result;
    output.bytes_scanned = bytes_scanned;

    if (result == CL_CLEAN) {
#if defined(_DEBUG) || defined(HYDRADRAGON_DEBUG)
        Log("DEBUG", "File clean: " + utf8_path);
#endif
        return output;
    }

    if (result == CL_VIRUS) {
        if (virname != nullptr) {
            output.virus_name = virname;
        }
        Log("WARN", "Virus found in " + utf8_path + ": " +
                         (output.virus_name.empty() ? std::string("Unknown") : output.virus_name));
        return output;
    }

    Log("ERROR", "Scan error for " + utf8_path + ": " + GetErrorMessage(result));
    return output;
}

std::future<ScanResult> Scanner::ScanFileAsync(const std::wstring& filepath) {
    return std::async(std::launch::async, [this, filepath]() {
        return ScanFile(filepath);
    });
}

bool Scanner::ReloadDatabase() {
    if (!WaitUntilReady()) {
        Log("ERROR", "Cannot reload database because initialization did not complete successfully.");
        return false;
    }

    Log("INFO", "Reloading ClamAV database.");
    return LoadDatabaseOnly();
}

void Scanner::StartAsyncInitialization() {
    init_in_progress_.store(true);
    SetInitStage("Starting");
    init_thread_ = std::thread(&Scanner::AsyncInitWorker, this);
}

void Scanner::AsyncInitWorker() {
    const bool ok = InitInternal();
    SignalInitFinished(ok);
}

bool Scanner::InitInternal() {
    if (!LoadLibraryOnly()) {
        return false;
    }

    if (!InitClamAvOnly()) {
        return false;
    }

    if (!LoadDatabaseOnly()) {
        return false;
    }

    SetInitStage("Complete");
    is_ready_.store(true);
    Log("INFO", "ClamAV scanner initialized successfully.");
    return true;
}

bool Scanner::LoadLibraryOnly() {
    SetInitStage("Loading DLL");

    std::error_code ec;
    if (!fs::exists(libclamav_path_, ec) || ec) {
        SetInitFailure("Library path does not exist: " + WideToUtf8(libclamav_path_));
        return false;
    }

    const fs::path dll_path(libclamav_path_);
    const std::wstring dll_dir = dll_path.parent_path().wstring();

    if (!dll_dir.empty()) {
        ::SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);
        dll_dir_cookie_ = ::AddDllDirectory(dll_dir.c_str());
    }

    module_ = ::LoadLibraryExW(
        libclamav_path_.c_str(),
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_USER_DIRS);

    if (!module_) {
        module_ = ::LoadLibraryW(libclamav_path_.c_str());
    }

    if (!module_) {
        SetInitFailure("Failed to load libclamav.dll: " + FormatWin32Error(::GetLastError()));
        return false;
    }

    if (!BindApi()) {
        return false;
    }

    Log("INFO", "Loaded libclamav DLL: " + WideToUtf8(libclamav_path_));
    return true;
}

bool Scanner::InitClamAvOnly() {
    SetInitStage("Initializing ClamAV");

    if (!api_.cl_init) {
        SetInitFailure("cl_init is not available.");
        return false;
    }

    const int res = api_.cl_init(0u);
    if (res != CL_SUCCESS) {
        SetInitFailure("cl_init failed: " + GetErrorMessage(res));
        return false;
    }

    return true;
}

bool Scanner::LoadDatabaseOnly() {
    SetInitStage("Loading signatures");

    std::error_code ec;
    if (!fs::exists(dbpath_, ec) || ec || !fs::is_directory(dbpath_, ec)) {
        SetInitFailure("Database path is invalid: " + WideToUtf8(dbpath_));
        return false;
    }

    return LoadDB();
}

bool Scanner::LoadDB() {
    std::lock_guard<std::mutex> lock(engine_mutex_);

    if (!api_.cl_engine_new || !api_.cl_load || !api_.cl_engine_compile) {
        SetInitFailure("Required ClamAV exports are missing for database load.");
        return false;
    }

    if (engine_ && api_.cl_engine_free) {
        api_.cl_engine_free(engine_);
        engine_ = nullptr;
    }

    engine_ = api_.cl_engine_new();
    if (!engine_) {
        SetInitFailure("Failed to create ClamAV engine.");
        return false;
    }

    const std::string utf8_dbpath = WideToUtf8(dbpath_);
    std::uint32_t signatures_loaded = 0;

    int res = api_.cl_load(
        utf8_dbpath.c_str(),
        engine_,
        &signatures_loaded,
        dboptions_);

    if (res != CL_SUCCESS) {
        const std::string msg = "cl_load failed: " + GetErrorMessage(res);
        api_.cl_engine_free(engine_);
        engine_ = nullptr;
        SetInitFailure(msg);
        return false;
    }

    if (api_.cl_engine_set_num) {
        for (const auto& [option_id, value] : engine_options_) {
            res = api_.cl_engine_set_num(engine_, option_id, value);
            if (res != CL_SUCCESS) {
                Log("WARN", "Failed to set engine option " + std::to_string(option_id) +
                                " = " + std::to_string(value) + ": " + GetErrorMessage(res));
            }
        }
    }

    SetInitStage("Compiling engine");
    res = api_.cl_engine_compile(engine_);
    if (res != CL_SUCCESS) {
        const std::string msg = "cl_engine_compile failed: " + GetErrorMessage(res);
        api_.cl_engine_free(engine_);
        engine_ = nullptr;
        SetInitFailure(msg);
        return false;
    }

    Log("INFO", "ClamAV database ready. Signatures loaded: " + std::to_string(signatures_loaded));
    return true;
}

bool Scanner::BindApi() {
    auto bind_required = [this](const char* name, auto& out) -> bool {
        out = reinterpret_cast<std::decay_t<decltype(out)>>(::GetProcAddress(module_, name));
        if (!out) {
            SetInitFailure(std::string("Missing required export: ") + name);
            return false;
        }
        return true;
    };

    auto bind_optional = [this](const char* name, auto& out) {
        out = reinterpret_cast<std::decay_t<decltype(out)>>(::GetProcAddress(module_, name));
        if (!out) {
            Log("WARN", std::string("Missing optional export: ") + name);
        }
    };

    if (!bind_required("cl_init", api_.cl_init)) {
        return false;
    }
    if (!bind_required("cl_engine_new", api_.cl_engine_new)) {
        return false;
    }
    if (!bind_required("cl_engine_free", api_.cl_engine_free)) {
        return false;
    }
    if (!bind_required("cl_load", api_.cl_load)) {
        return false;
    }
    if (!bind_required("cl_engine_compile", api_.cl_engine_compile)) {
        return false;
    }
    if (!bind_required("cl_scanfile", api_.cl_scanfile)) {
        return false;
    }

    bind_optional("cl_engine_set_num", api_.cl_engine_set_num);
    bind_optional("cl_retver", api_.cl_retver);
    bind_optional("cl_strerror", api_.cl_strerror);

    return true;
}

void Scanner::SetInitStage(const std::string& stage) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    init_stage_ = stage;
}

void Scanner::SetInitFailure(const std::string& message) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        init_stage_ = "Failed";
        init_error_ = message;
        init_success_ = false;
    }
    is_ready_.store(false);
    Log("ERROR", message);
}

void Scanner::SignalInitFinished(bool success) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        init_success_ = success;
        if (!success && init_error_.empty()) {
            init_error_ = "Unknown initialization error.";
            init_stage_ = "Failed";
        }
    }

    if (!success) {
        is_ready_.store(false);
    }

    init_in_progress_.store(false);
    state_cv_.notify_all();
}

void Scanner::Cleanup() {
    std::lock_guard<std::mutex> lock(engine_mutex_);

    if (engine_ && api_.cl_engine_free) {
        api_.cl_engine_free(engine_);
        engine_ = nullptr;
    }

    if (module_) {
        ::FreeLibrary(module_);
        module_ = nullptr;
    }

    if (dll_dir_cookie_) {
        ::RemoveDllDirectory(dll_dir_cookie_);
        dll_dir_cookie_ = nullptr;
    }
}

std::string Scanner::GetErrorMessage(int error_code) const {
    if (api_.cl_strerror) {
        if (const char* message = api_.cl_strerror(error_code); message != nullptr) {
            return TrimLineBreaks(message);
        }
    }

    return "Error code: " + std::to_string(error_code);
}

std::string Scanner::WideToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int required = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        nullptr,
        0,
        nullptr,
        nullptr);

    if (required <= 0) {
        return {};
    }

    std::string result(static_cast<std::size_t>(required), '\0');
    const int written = ::WideCharToMultiByte(
        CP_UTF8,
        0,
        value.c_str(),
        static_cast<int>(value.size()),
        result.data(),
        required,
        nullptr,
        nullptr);

    if (written <= 0) {
        return {};
    }

    return result;
}

std::string Scanner::FormatWin32Error(DWORD error_code) {
    LPWSTR buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS;

    const DWORD length = ::FormatMessageW(
        flags,
        nullptr,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    if (length == 0 || buffer == nullptr) {
        return "Win32 error code: " + std::to_string(error_code);
    }

    std::wstring wide(buffer, length);
    ::LocalFree(buffer);
    return TrimLineBreaks(WideToUtf8(wide));
}

void Scanner::Log(const char* level, const std::string& message) const {
    logger_(level, message);
}

} // namespace clamav
