//
// edrav2.edrdrv project
//
// Quarantine functionality for malicious files
// Ported from Owlyshield minifilter
//
/// @file Quarantine operations header
///
/// @addtogroup edrdrv
/// @{
#pragma once

namespace cmd {
namespace quarantine {

//
// Quarantine directory path (configurable)
//
extern UNICODE_STRING g_quarantinePath;
extern ERESOURCE g_quarantinePathLock;

//
// Pool tags for quarantine operations
//
constexpr ULONG c_nQuarantinePathTag = 'pQrE'; // ErQp - EDR Quarantine path
constexpr ULONG c_nQuarantineFileTag = 'fQrE'; // ErQf - EDR Quarantine file temp

///
/// @brief Initialize quarantine subsystem
/// @return STATUS_SUCCESS on success
///
NTSTATUS initialize();

///
/// @brief Cleanup quarantine subsystem
///
void finalize();

///
/// @brief Set the quarantine directory path
/// @param[in] path Pointer to UNICODE_STRING containing the quarantine path
/// @return STATUS_SUCCESS on success
///
NTSTATUS setQuarantinePath(_In_ PUNICODE_STRING path);

///
/// @brief Get the current quarantine directory path
/// @param[out] path Pointer to receive the quarantine path (caller must not free)
/// @return STATUS_SUCCESS on success
///
NTSTATUS getQuarantinePath(_Out_ PUNICODE_STRING* path);

///
/// @brief Check if a path is within the quarantine directory
/// @param[in] path Path to check
/// @return TRUE if path is in quarantine directory, FALSE otherwise
///
BOOLEAN isPathInQuarantineDir(_In_ PUNICODE_STRING path);

///
/// @brief Delete a file by path
/// @param[in] filePath Full path to the file to delete
/// @return STATUS_SUCCESS on success
///
NTSTATUS deleteFileByPath(_In_ PUNICODE_STRING filePath);

///
/// @brief Quarantine a file by moving it to the quarantine directory
/// @param[in] filePath Full path to the file to quarantine
/// @return STATUS_SUCCESS on success
///
/// @details This function:
/// 1. Creates the quarantine directory if it doesn't exist
/// 2. Moves the file to the quarantine directory
/// 3. Renames the file with .quarantined extension to prevent execution
///
NTSTATUS quarantineFileByPath(_In_ PUNICODE_STRING filePath);

} // namespace quarantine
} // namespace cmd

/// @}
