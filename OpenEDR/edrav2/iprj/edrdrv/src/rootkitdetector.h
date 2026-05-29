//
// EDRDrv
//
// Rootkit Detection Module
// Ported from Owlyshield minifilter
//
// Detects:
// 1. SSDT integrity - entries pointing outside ntoskrnl
// 2. Hidden process - PspCidTable vs EPROCESS list mismatch (DKOM)
// 3. Hidden driver - object directory entry missing from module list
// 4. Driver object integrity - DriverInit/AddDevice/MajorFunction mismatch
// 5. Kernel inline hook - FF25 / E9 / mov-rax-jmp-rax on ntoskrnl exports
// 6. Object type tampering - unsupported file-object callbacks enabled
//

#pragma once

namespace cmd {
namespace rootkit {

//
// Trigger types for rootkit scanning
//
enum class RkTrigger : ULONG
{
	LIGHT = 0,  // Quick checks (SSDT, object type)
	FULL = 1,   // All checks including process/driver enumeration
	DRIVER = 2  // Driver-specific checks only
};

//
// Rootkit finding codes
//
constexpr ULONG RK_FINDING_SSDT_HOOK = 0x1001;
constexpr ULONG RK_FINDING_HIDDEN_PROCESS = 0x1002;
constexpr ULONG RK_FINDING_HIDDEN_DRIVER = 0x1003;
constexpr ULONG RK_FINDING_DRIVER_INTEGRITY = 0x1004;
constexpr ULONG RK_FINDING_KERNEL_INLINE_HOOK = 0x1005;
constexpr ULONG RK_FINDING_OBJECT_TYPE_TAMPER = 0x1006;

//
// Configuration
//
constexpr ULONG RK_SCAN_DEBOUNCE_MS = 5000;  // Minimum time between full scans
constexpr ULONG RK_MAX_DRIVER_PATH = 260;

//
// Initialize rootkit detector
//
NTSTATUS initialize();

//
// Cleanup rootkit detector
//
void finalize();

//
// Trigger a rootkit scan (debounced for FULL scans)
//
void triggerScan(RkTrigger trigger);

//
// Event-driven scan trigger (called on driver load/unload)
//
void onDriverEvent();

//
// Run immediate scan (bypasses debouncing)
//
ULONG runScanImmediate(RkTrigger trigger);

} // namespace rootkit
} // namespace cmd
