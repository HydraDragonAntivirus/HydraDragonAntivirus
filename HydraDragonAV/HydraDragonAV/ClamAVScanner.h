#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

namespace clamav {

struct ClScanOptions {
    std::uint32_t general = 0;
    std::uint32_t parse = 0;
    std::uint32_t heuristic = 0;
    std::uint32_t mail = 0;
    std::uint32_t dev = 0;
};

constexpr int CL_CLEAN = 0;
constexpr int CL_VIRUS = 1;
constexpr int CL_SUCCESS = 0;
constexpr std::uint32_t CL_DB_STDOPT = 0;
constexpr std::uint32_t CL_SCAN_GENERAL_HEURISTICS = (1u << 2);

struct ScanResult {
    int result_code = -1;
    std::string virus_name;
    unsigned long bytes_scanned = 0;

    [[nodiscard]] bool IsClean() const noexcept {
        return result_code == CL_CLEAN;
    }

    [[nodiscard]] bool IsVirus() const noexcept {
        return result_code == CL_VIRUS;
    }

    [[nodiscard]] bool IsKnownResult() const noexcept {
        return IsClean() || IsVirus();
    }
};

using LogCallback = std::function<void(const char* level, const std::string& message)>;

class Scanner {
public:
    using EngineOptions = std::unordered_map<std::uint32_t, unsigned long>;

    Scanner(const std::wstring& libclamav_path,
            const std::wstring& dbpath,
            bool autoreload = false,
            std::uint32_t dboptions = CL_DB_STDOPT,
            EngineOptions engine_options = DefaultEngineOptions(),
            LogCallback logger = {});

    ~Scanner();

    Scanner(const Scanner&) = delete;
    Scanner& operator=(const Scanner&) = delete;
    Scanner(Scanner&&) = delete;
    Scanner& operator=(Scanner&&) = delete;

    static std::unique_ptr<Scanner> CreateAsync(const std::wstring& libclamav_path,
                                const std::wstring& dbpath,
                                bool autoreload = false,
                                std::uint32_t dboptions = CL_DB_STDOPT,
                                EngineOptions engine_options = DefaultEngineOptions(),
                                LogCallback logger = {});

    static EngineOptions DefaultEngineOptions();

    [[nodiscard]] bool IsReady() const noexcept;
    [[nodiscard]] bool IsInitializing() const noexcept;
    [[nodiscard]] std::string GetInitStage() const;
    [[nodiscard]] std::string GetInitError() const;

    bool WaitUntilReady();
    bool WaitUntilReadyFor(std::chrono::milliseconds timeout);

    ScanResult ScanFile(const std::wstring& filepath);
    std::future<ScanResult> ScanFileAsync(const std::wstring& filepath);

    bool ReloadDatabase();

private:
    struct Api final {
        using cl_init_fn = int(__cdecl*)(std::uint32_t);
        using cl_engine_new_fn = void* (__cdecl*)();
        using cl_engine_free_fn = int(__cdecl*)(void*);
        using cl_load_fn = int(__cdecl*)(const char*, void*, std::uint32_t*, std::uint32_t);
        using cl_engine_compile_fn = int(__cdecl*)(void*);
        using cl_engine_set_num_fn = int(__cdecl*)(void*, std::uint32_t, unsigned long);
        using cl_scanfile_fn = int(__cdecl*)(const char*, const char**, unsigned long*, const void*, const ClScanOptions*);
        using cl_retver_fn = const char* (__cdecl*)();
        using cl_strerror_fn = const char* (__cdecl*)(int);

        cl_init_fn cl_init = nullptr;
        cl_engine_new_fn cl_engine_new = nullptr;
        cl_engine_free_fn cl_engine_free = nullptr;
        cl_load_fn cl_load = nullptr;
        cl_engine_compile_fn cl_engine_compile = nullptr;
        cl_engine_set_num_fn cl_engine_set_num = nullptr;
        cl_scanfile_fn cl_scanfile = nullptr;
        cl_retver_fn cl_retver = nullptr;
        cl_strerror_fn cl_strerror = nullptr;
    };

    Scanner(const std::wstring& libclamav_path,
            const std::wstring& dbpath,
            bool autoreload,
            std::uint32_t dboptions,
            EngineOptions engine_options,
            LogCallback logger,
            bool defer_init);

    void StartAsyncInitialization();
    void AsyncInitWorker();
    bool InitInternal();

    bool LoadLibraryOnly();
    bool InitClamAvOnly();
    bool LoadDatabaseOnly();
    bool LoadDB();
    bool BindApi();

    void SetInitStage(const std::string& stage);
    void SetInitFailure(const std::string& message);
    void SignalInitFinished(bool success);
    void Cleanup();

    [[nodiscard]] std::string GetErrorMessage(int error_code) const;
    [[nodiscard]] static std::string WideToUtf8(const std::wstring& value);
    [[nodiscard]] static std::string FormatWin32Error(DWORD error_code);
    void Log(const char* level, const std::string& message) const;

    std::wstring libclamav_path_;
    std::wstring dbpath_;
    bool autoreload_ = false;
    std::uint32_t dboptions_ = CL_DB_STDOPT;
    EngineOptions engine_options_;
    LogCallback logger_;

    HMODULE module_ = nullptr;
    DLL_DIRECTORY_COOKIE dll_dir_cookie_ = nullptr;
    void* engine_ = nullptr;
    Api api_{};

    std::atomic<bool> is_ready_{false};
    std::atomic<bool> init_in_progress_{false};
    bool init_success_ = false;

    mutable std::mutex state_mutex_;
    std::condition_variable state_cv_;
    std::string init_stage_ = "Not started";
    std::string init_error_;

    std::thread init_thread_;
    mutable std::mutex engine_mutex_;
};

} // namespace clamav
