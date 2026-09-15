#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <stdexcept>
#include <vector>
#include <cstdint>
#include "../c/openedr_static.h"

namespace openedr {

struct StringDeleter {
    void operator()(char* p) const noexcept {
        if (p) {
            openedr_static_free_string(p);
        }
    }
};

using ScopedJsonString = std::unique_ptr<char, StringDeleter>;

class Scanner {
public:
    explicit Scanner(const std::string& rules_dir = "") {
        const char* dir = rules_dir.empty() ? nullptr : rules_dir.c_str();
        if (openedr_static_init(dir) != 0) {
            throw std::runtime_error("Failed to initialize OpenEDR Static Scanner Engine");
        }
    }

    std::string scan_file(const std::string& file_path) {
        ScopedJsonString res(openedr_static_scan_file(file_path.c_str()));
        if (!res) return R"({"error": true, "message": "Scan failed"})";
        return std::string(res.get());
    }

    std::string scan_bytes(const std::vector<uint8_t>& data, const std::string& virtual_name = "sample.bin") {
        ScopedJsonString res(openedr_static_scan_bytes(data.data(), data.size(), virtual_name.c_str()));
        if (!res) return R"({"error": true, "message": "Scan failed"})";
        return std::string(res.get());
    }

    std::string scan_url(const std::string& url) {
        ScopedJsonString res(openedr_static_scan_url(url.c_str()));
        if (!res) return R"({"error": true, "message": "Scan failed"})";
        return std::string(res.get());
    }

    std::string check_registry(const std::string& reg_path) {
        ScopedJsonString res(openedr_static_check_registry(reg_path.c_str()));
        if (!res) return R"({"error": true, "message": "Scan failed"})";
        return std::string(res.get());
    }

    enum class FlsVerdict {
        Safe = 1,
        Malicious = 2,
        Unknown = 0,
        Error = -1
    };

    FlsVerdict query_fls(const std::string& sha1_hex) {
        int32_t code = openedr_static_check_fls_sha1(sha1_hex.c_str());
        return static_cast<FlsVerdict>(code);
    }
};

} // namespace openedr
