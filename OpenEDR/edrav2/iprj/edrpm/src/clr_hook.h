#pragma once

#include "pch.h"
#include <string>
#include <vector>

namespace cmd {
namespace edrpm {

///
/// @brief Result of scanning an in-memory .NET assembly
///
enum class ClrScanVerdict
{
    Clean = 0,
    Suspicious = 1,
    Malicious = 2,
    Unknown = 3
};

///
/// @brief Information extracted from intercepted Assembly.Load(byte[])
///
struct DotNetAssemblyInfo
{
    std::string sha1Hash;
    size_t dataSize = 0;
    bool isPeValid = false;
    bool isBlocked = false;
    std::string detectedReason;
};

///
/// @brief Initialize the CLR hook engine
/// Checks if clr.dll is already loaded; if so, hooks nLoadImage.
/// Also registers for DLL load notifications to hook clr.dll if loaded dynamically.
///
bool InitClrHookEngine();

///
/// @brief Shutdown the CLR hook engine and unhook nLoadImage
///
void ShutdownClrHookEngine();

///
/// @brief Returns the resolved and hooked nLoadImage function address (if any)
///
PVOID GetHookedLoadImageAddress();

///
/// @brief Re-hooks nLoadImage if it was tampered with or unhooked
///
bool RehookLoadImage();

///
/// @brief Compute standard SHA-1 hash for arbitrary byte buffer
///
std::string ComputeSha1(const uint8_t* data, size_t size);

} // namespace edrpm
} // namespace cmd
