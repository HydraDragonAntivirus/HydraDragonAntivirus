#pragma once

#include <cstdint>
#include <string>

namespace cmd {
namespace win {

/// Initialize Owlyshield ransomware protection DLL
/// @return true on success, false on failure
bool InitOwlyshield();

/// Ingest event data into Owlyshield for behavioral analysis
/// @param data Pointer to MessagePack-serialized IOMessage
/// @param len Length of data in bytes
/// @return true on success, false on failure
bool OwlyshieldIngest(const uint8_t* data, uint32_t len);

/// Shutdown Owlyshield engine and unload DLL
void ShutdownOwlyshield();

/// Install the HydraDragon firewall CA into the Windows ROOT trust store.
/// Driver-independent; safe to call before the edrdrv driver is loaded
/// (e.g. from the edrsvc install script).
/// @return true on success, false on failure
bool OwlyshieldInstallCa();

/// Quarantine a file into an encrypted .hqf container and remove the original.
/// Driver-independent; safe to call before the edrdrv driver is loaded.
/// @param filePath Wide-character path of the file to quarantine
/// @return true on success, false on failure
bool OwlyshieldQuarantineFile(const std::wstring& filePath);

} // namespace win
} // namespace cmd
