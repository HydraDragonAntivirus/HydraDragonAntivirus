// Daemon mode: poll a directory, scan new/changed files with worker threads.
// Build alongside openedr_static.dll, run: daemon.exe [watchDir]
// NOTE: no SHA-256 in std; unchanged files are skipped by (size, mtime).
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <cstdlib>

#include "openedr.hpp"

namespace fs = std::filesystem;

namespace {

const long long kMaxSize = 48LL * 1024 * 1024;

std::string ExtractVerdict(const std::string& json) {
    const std::string key = "\"verdict\"";
    size_t i = json.find(key);
    if (i == std::string::npos) return "Unknown";
    size_t c = json.find(':', i);
    if (c == std::string::npos) return "Unknown";
    size_t q1 = json.find('"', c);
    if (q1 == std::string::npos) return "Unknown";
    size_t q2 = json.find('"', q1 + 1);
    if (q2 == std::string::npos) return "Unknown";
    return json.substr(q1 + 1, q2 - q1 - 1);
}

struct Shared {
    openedr::Scanner* scanner;
    std::mutex mutex;
    std::condition_variable cv;
    std::queue<std::string> jobs;
    std::map<std::string, std::pair<long long, long long>> seen;
    std::atomic<bool> stop{false};
    std::atomic<long long> scanned{0};
    std::atomic<long long> hits{0};
};

long long MtimeNs(const fs::path& p) {
    try {
        auto t = fs::last_write_time(p);
        return static_cast<long long>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                t.time_since_epoch())
                .count());
    } catch (...) {
        return 0;
    }
}

void Worker(Shared* sh, const std::set<std::string>& flag) {
    for (;;) {
        std::string path;
        {
            std::unique_lock<std::mutex> lock(sh->mutex);
            sh->cv.wait(lock, [&] { return sh->stop.load() || !sh->jobs.empty(); });
            if (sh->stop.load() && sh->jobs.empty()) return;
            path = sh->jobs.front();
            sh->jobs.pop();
        }
        std::string report;
        try {
            report = sh->scanner->scan_file(path);
        } catch (const std::exception& ex) {
            std::cerr << "[-] scan failed " << path << ": " << ex.what() << "\n";
            continue;
        }
        std::string verdict = ExtractVerdict(report);
        ++sh->scanned;
        if (flag.count(verdict)) {
            ++sh->hits;
            std::cout << "[!] " << verdict << " :: " << path << "\n";
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    std::string watch = (argc > 1) ? argv[1] : "OpenMalwareScannerPortable";
    try {
        openedr::Scanner scanner("OpenMalwareScannerPortable");
        std::cout << "[*] Watching " << watch << " - Ctrl+C to stop\n";

        Shared sh;
        sh.scanner = &scanner;
        const std::set<std::string> flag = {"Malicious", "Suspicious"};

        std::vector<std::thread> workers;
        for (int i = 0; i < 2; ++i)
            workers.emplace_back(Worker, &sh, std::cref(flag));

        for (;;) {
            try {
                for (auto& entry : fs::recursive_directory_iterator(watch)) {
                    if (!entry.is_regular_file()) continue;
                    std::string p = entry.path().string();
                    long long size = 0;
                    try {
                        size = static_cast<long long>(entry.file_size());
                    } catch (...) {
                        continue;
                    }
                    if (size <= 0 || size > kMaxSize) continue;
                    auto key = std::make_pair(size, MtimeNs(entry.path()));
                    bool fresh = false;
                    {
                        std::lock_guard<std::mutex> lock(sh.mutex);
                        auto it = sh.seen.find(p);
                        if (it == sh.seen.end() || it->second != key) {
                            sh.seen[p] = key;
                            fresh = true;
                        }
                    }
                    if (fresh) {
                        std::lock_guard<std::mutex> lock(sh.mutex);
                        sh.jobs.push(p);
                        sh.cv.notify_one();
                    }
                }
            } catch (const std::exception& ex) {
                std::cerr << "[-] walk failed: " << ex.what() << "\n";
            }
            std::cout << "[...] scanned=" << sh.scanned.load()
                      << " hits=" << sh.hits.load() << "\n";
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
