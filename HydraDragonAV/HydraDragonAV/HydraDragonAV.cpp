#include "framework.h"
#include "HydraDragonAV.h"
#include "ClamAVScanner.h"
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <filesystem>
#include <Windows.h>
#include <algorithm>
#include <cctype>

// YARA Headers
#include "yara/yara.h"

namespace fs = std::filesystem;

// Paths
#define PIPE_NAME L"\\\\.\\pipe\\HydraDragonAV"
#define ENGINES_DIR L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\HydraDragonAV\\engines\\clamav\\"
#define CLAMAV_DLL ENGINES_DIR L"libclamav.dll"
#define CLAMAV_DB  ENGINES_DIR L"database"
#define YARA_RULES_FOLDER L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\signatures\\rules\\yara\\"

// Scanner Global
static std::unique_ptr<clamav::Scanner> g_clamavScanner;
static YR_RULES* g_yaraRules = nullptr;

// YARA Callback
int yara_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* matches = static_cast<std::vector<std::string>*>(user_data);
        auto* rule = static_cast<YR_RULE*>(message_data);
        matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

// Logic to load YARA rules
bool LoadYaraRules() {
    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != 0) return false;

    std::error_code ec;
    if (fs::exists(YARA_RULES_FOLDER, ec)) {
        for (const auto& entry : fs::directory_iterator(YARA_RULES_FOLDER, ec)) {
            if (ec) break;
            if (entry.path().extension() == ".yar") {
                std::ifstream file(entry.path());
                if (!file.is_open()) continue;
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                
                // Use the filename as the identifier for errors
                std::string fileName = entry.path().filename().string();
                if (yr_compiler_add_string(compiler, content.c_str(), nullptr) != 0) {
                    std::cerr << "[YARA] Failed to compile: " << fileName << std::endl;
                }
            }
        }
    } else {
        std::cerr << "[YARA] Rules folder not found: " << fs::path(YARA_RULES_FOLDER).string() << std::endl;
    }

    if (yr_compiler_get_rules(compiler, &g_yaraRules) != 0) {
        yr_compiler_destroy(compiler);
        return false;
    }

    yr_compiler_destroy(compiler);
    return true;
}

void ProcessRequest(const std::string& request, std::string& response) {
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
                    filePathStr = request.substr(start_quote + 1, end_quote - start_quote - 1);
                }
            }
        }
    }

    if (filePathStr.empty()) {
        response = "{\"status\":\"error\", \"message\":\"missing or invalid path\"}";
        return;
    }

    // Convert escaped backslashes if any (basic)
    std::string cleanPath;
    for (size_t i = 0; i < filePathStr.size(); ++i) {
        if (filePathStr[i] == '\\' && i + 1 < filePathStr.size() && filePathStr[i+1] == '\\') {
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
    bool isMalicious = false;

    bool is_vmprotect = false;

    // YARA Scan
    if (g_yaraRules && fs::exists(wFilePath)) {
        yr_rules_scan_file(g_yaraRules, cleanPath.c_str(), 0, yara_callback, &yaraMatches, 0);
        if (!yaraMatches.empty()) {
            isMalicious = true;
            for (const auto& match : yaraMatches) {
                std::string lowerMatch = match;
                std::transform(lowerMatch.begin(), lowerMatch.end(), lowerMatch.begin(), ::tolower);
                if (lowerMatch.find("vmprotect") != std::string::npos) {
                    is_vmprotect = true;
                }
            }
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
    ss << "{\"status\":\"success\", \"malicious\":" << (isMalicious ? "true" : "false") << ", \"is_vmprotect\":" << (is_vmprotect ? "true" : "false") << ", \"yara\":[";
    for (size_t i = 0; i < yaraMatches.size(); ++i) {
        ss << "\"" << yaraMatches[i] << "\"" << (i == yaraMatches.size() - 1 ? "" : ",");
    }
    ss << "], \"clamav\":\"" << clamavVirusName << "\"}";
    response = ss.str();
}

int main() {
    std::cout << "[HydraDragonAV] Starting SCANNER ENGINE (Pipe Server)..." << std::endl;

    // Initialize YARA
    if (yr_initialize() != 0) {
        std::cerr << "[YARA] Failed to initialize YARA library." << std::endl;
        return 1;
    }
    if (!LoadYaraRules()) {
        std::cerr << "[YARA] Warning: Failed to load YARA rules or folder empty." << std::endl;
    }

    // Initialize ClamAV
    std::cout << "[ClamAV] Initializing Scanner..." << std::endl;
    g_clamavScanner = clamav::Scanner::CreateAsync(CLAMAV_DLL, CLAMAV_DB);
    
    // We don't block main here; if a scan comes in before ready, ScanFile will handle it or wait
    
    while (true) {
        HANDLE hPipe = CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024 * 64, // Larger buffer for paths/results
            1024 * 64,
            0,
            NULL
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::cerr << "[Pipe] Failed to create named pipe. Error: " << GetLastError() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
            continue;
        }

        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            char buffer[65536]; // Support very long paths
            DWORD bytesRead;
            if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
                buffer[bytesRead] = '\0';
                std::string request(buffer);
                std::string response;
                
                ProcessRequest(request, response);

                DWORD bytesWritten;
                WriteFile(hPipe, response.c_str(), (DWORD)response.size(), &bytesWritten, NULL);
                FlushFileBuffers(hPipe);
            }
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    if (g_yaraRules) yr_rules_destroy(g_yaraRules);
    yr_finalize();

    return 0;
}