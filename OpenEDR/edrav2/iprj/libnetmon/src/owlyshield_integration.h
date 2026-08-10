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

/// Ingest a serialized OpenEDR enriched event (single-line JSON) into the
/// behavior engine over the in-process FFI channel.
/// @param sPayload UTF-8 JSON event payload
/// @return true on success, false on failure
bool OwlyshieldIngestOpenedrEvent(const std::string& sPayload);

/// Ingest firewall FULL_PACKET packed data (single-line JSON) into the
/// behavior engine over the in-process FFI channel.
/// @param sPayload UTF-8 JSON packed-data payload
/// @return true on success, false on failure
bool OwlyshieldIngestFirewallPackedData(const std::string& sPayload);

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

/// Stop/pause antivirus protection state
bool OwlyshieldStopProtection();

/// Start/resume antivirus protection state
bool OwlyshieldStartProtection();

/// Returns true if antivirus protection is currently stopped/paused
bool OwlyshieldIsProtectionStopped();

} // namespace win
} // namespace cmd
