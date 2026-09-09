#pragma once

#include "pch.h"
#include <string>

namespace cmd {
namespace edrpm {

///
/// @brief Register a specific function hook to be monitored by the watchdog
/// @param moduleName Name of the DLL (e.g. "ntdll.dll", "clr.dll")
/// @param funcName Name of the function (e.g. "NtWriteVirtualMemory", "nLoadImage")
/// @param address Target function virtual address
/// @param checkSize Number of bytes to monitor (typically 5 to 16 bytes)
///
bool RegisterHookToWatch(const char* moduleName, const char* funcName, PVOID address, size_t checkSize = 16);

///
/// @brief Starts the comprehensive background anti-unhooking integrity monitor
/// (Sanctum-inspired watchdog thread that verifies ntdll.dll .text hash and all critical API hooks, with self-healing)
///
bool StartAntiUnhookWatchdog();

///
/// @brief Stops the anti-unhooking watchdog thread
///
void StopAntiUnhookWatchdog();

///
/// @brief Returns whether the anti-unhook watchdog is currently running
///
bool IsAntiUnhookWatchdogRunning();

///
/// @brief Get the baseline SHA-1 hash of ntdll.dll .text section
///
std::string GetNtdllTextHash();

} // namespace edrpm
} // namespace cmd
