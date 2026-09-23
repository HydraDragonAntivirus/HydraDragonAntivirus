#ifndef OPENEDR_STATIC_H
#define OPENEDR_STATIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef OPENEDR_STATIC_EXPORTS
    #define OPENEDR_API __declspec(dllexport)
  #else
    #define OPENEDR_API __declspec(dllimport)
  #endif
#else
  #define OPENEDR_API __attribute__((visibility("default")))
#endif

/**
 * @brief Initialize the static scanning engine with a base directory containing rules.
 * @param base_rules_dir Directory path containing database/, yara_rules/, models/, signer_rules/, hash_rules/.
 *                       Pass NULL to look next to the DLL.
 * @return 0 on success, -1 on failure.
 */
OPENEDR_API int32_t openedr_static_init(const char* base_rules_dir);

/**
 * @brief Scan a file on disk by its path.
 * @param file_path Absolute or relative path to the file.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_scan_file(const char* file_path);

/**
 * @brief Scan a raw byte buffer in memory.
 * @param data Pointer to the memory buffer.
 * @param len Buffer length in bytes.
 * @param file_name Optional virtual file name (e.g. "sample.exe") or NULL.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_scan_bytes(const uint8_t* data, size_t len, const char* file_name);

/**
 * @brief Scan a URL for phishing or malicious patterns (web parity: ML + CIDR + BinaryFuse16 whitelist).
 * @param url URL string to analyze.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 *         JSON: { target_url, verdict, malware_probability, is_malicious, whitelisted, blacklisted }.
 */
OPENEDR_API char* openedr_static_scan_url(const char* url);

/**
 * @brief Full URL threat inspection via Rust YAML Threat Engine (web parity: web_inspect_url).
 * @param url URL string to analyze.
 * @param liveness_code 0=unknown, 1=active, 2=inactive/dead (NXDOMAIN).
 * @return JSON threat report on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_inspect_url(const char* url, int32_t liveness_code);

/**
 * @brief Full URL + page-content inspection (web parity: web_inspect_url_content).
 * @param url URL string to analyze.
 * @param liveness_code 0=unknown, 1=active, 2=inactive/dead.
 * @param content Optional fetched HTML/JS/DOM text, or NULL.
 * @return JSON threat report on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_inspect_url_content(const char* url, int32_t liveness_code, const char* content);

/**
 * @brief Load a tree-model bundle from memory: kind 0=PE, 1=JS, 2=URL, 3=APK (web parity).
 * @return 1 on success, 0 on parse failure.
 */
OPENEDR_API int32_t openedr_static_load_model(uint32_t kind, const uint8_t* data, size_t len);

/**
 * @brief Load one compiled YARA .yrc bundle (web parity). Returns 1/0.
 */
OPENEDR_API int32_t openedr_static_load_yara(const uint8_t* data, size_t len);

/**
 * @brief Compile one YARA source document (web parity). Returns 1/0.
 */
OPENEDR_API int32_t openedr_static_load_yara_src(const uint8_t* data, size_t len);

/**
 * @brief Load hydradragonsig string-rule YAML (web parity). Returns rule count or -1.
 */
OPENEDR_API int32_t openedr_static_set_string_rules(const uint8_t* data, size_t len);

/**
 * @brief Alias of openedr_static_set_string_rules (web parity: web_set_registry_rules).
 */
OPENEDR_API int32_t openedr_static_set_registry_rules(const uint8_t* data, size_t len);

/**
 * @brief Load BinaryFuse16 URL/domain/IP whitelist .xf bytes (web parity). Returns 1/0.
 */
OPENEDR_API int32_t openedr_static_load_url_whitelist(const uint8_t* data, size_t len);

/**
 * @brief Load custom YAML URL threat rules (web parity). Returns rule count or -1.
 */
OPENEDR_API int32_t openedr_static_load_url_rules(const uint8_t* data, size_t len);

/**
 * @brief Add a subdomain to the unwhitelist set (web parity). Returns 1/0.
 */
OPENEDR_API int32_t openedr_static_add_unwhitelisted_subdomain(const char* host);

/**
 * @brief Check if a subdomain is unwhitelisted (web parity). Returns 1/0.
 */
OPENEDR_API int32_t openedr_static_is_unwhitelisted_subdomain(const char* host);

/**
 * @brief APK tree-bundle readiness (web parity: 1 = apk_trees.bin loaded).
 */
OPENEDR_API uint32_t openedr_static_apk_loaded(void);

/**
 * @brief Check a registry key path against PUA registry rules.
 * @param reg_path Registry path string.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_check_registry(const char* reg_path);

/**
 * @brief Scan a Windows EVTX log file with Hayabusa rules.
 * @param evtx_path Path to the .evtx file.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_scan_evtx(const char* evtx_path);

/**
 * @brief Scan live Windows system event logs with Hayabusa rules.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_scan_system_events(void);

/**
 * @brief Check the hosts file for hijacking/tampering.
 * @param hosts_path Custom hosts path, or NULL for the system default.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_check_hosts_file(const char* hosts_path);

/**
 * @brief Restore the hosts file to the clean Windows template.
 * @param hosts_path Custom hosts path, or NULL for the system default.
 * @param create_backup Non-zero to keep a timestamped .backup copy.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_restore_hosts_file(const char* hosts_path, int32_t create_backup);

/**
 * @brief Free a C-string returned by openedr_static scanning functions.
 * @param s Pointer to the heap-allocated C-string.
 */
OPENEDR_API void openedr_static_free_string(char* s);

#ifdef __cplusplus
}
#endif

#endif /* OPENEDR_STATIC_H */
