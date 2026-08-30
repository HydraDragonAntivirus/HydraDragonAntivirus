#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Return codes
constexpr int OWLY_OK = 0;
constexpr int OWLY_ALREADY_STARTED = 1;
constexpr int OWLY_DRIVER_ERROR = 2;
constexpr int OWLY_NOT_STARTED = 3;
constexpr int OWLY_DESERIALIZE_ERROR = 4;
constexpr int OWLY_CA_INSTALL_ERROR = 5;
constexpr int OWLY_QUARANTINE_ERROR = 6;

// Initialize and start the Owlyshield ransomware protection engine
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_start();

// Install the HydraDragon firewall CA into the Windows ROOT trust store.
// Driver-independent: called by edrsvc during setup, before the driver loads.
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_install_ca();

// Quarantine a file into an encrypted .hqf container and remove the original.
// file_path: pointer to UTF-8 file path
// len: length of the path in bytes
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_quarantine_file(const uint8_t* file_path, uint32_t len);

// Ingest a serialized IOMessage event from the driver
// data: pointer to MessagePack-serialized IOMessage
// len: length of data in bytes
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_ingest(const uint8_t* data, uint32_t len);

// Ingest a serialized OpenEDR enriched event (single-line JSON) into the
// behavior engine. data: UTF-8 JSON payload, len: length in bytes.
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_ingest_openedr_event(const uint8_t* data, uint32_t len);

// Ingest firewall FULL_PACKET packed data (single-line JSON) into the behavior
// engine. data: UTF-8 JSON payload, len: length in bytes.
// Returns OWLY_OK on success, or an error code on failure
__declspec(dllimport) int32_t owlyshield_dll_ingest_firewall_packed_data(const uint8_t* data, uint32_t len);

// Stop the Owlyshield engine and cleanup resources
__declspec(dllimport) void owlyshield_dll_stop();

#ifdef __cplusplus
}
#endif
