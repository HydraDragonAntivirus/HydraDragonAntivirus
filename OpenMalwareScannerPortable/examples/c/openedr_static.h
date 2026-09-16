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
 * @brief Scan a URL for phishing or malicious patterns using the LightGBM ONNX model.
 * @param url URL string to analyze.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_scan_url(const char* url);

/**
 * @brief Check a registry key path against PUA registry rules.
 * @param reg_path Registry path string.
 * @return JSON-formatted string on the heap. MUST be freed using openedr_static_free_string.
 */
OPENEDR_API char* openedr_static_check_registry(const char* reg_path);

/**
 * @brief Query Comodo FLS cloud database for a file's SHA-1 hash.
 * @param sha1_hex 40-character hexadecimal SHA-1 string.
 * @return 1 = Safe/Trusted, 2 = Malicious, 0 = Unknown/Absent, -1 = Network/Protocol Error.
 */
OPENEDR_API int32_t openedr_static_check_fls_sha1(const char* sha1_hex);

/**
 * @brief Free a C-string returned by openedr_static scanning functions.
 * @param s Pointer to the heap-allocated C-string.
 */
OPENEDR_API void openedr_static_free_string(char* s);

#ifdef __cplusplus
}
#endif

#endif /* OPENEDR_STATIC_H */
