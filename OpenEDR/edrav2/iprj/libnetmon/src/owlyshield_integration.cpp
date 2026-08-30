///
/// @file Owlyshield ransomware protection DLL integration
///

#include "pch.h"
#include "owlyshield_ransom.h"
#include <windows.h>
#include <atomic>

namespace cmd {
namespace win {

static HMODULE g_hOwlyshieldDll = nullptr;

// True only once owlyshield_dll_start() has actually returned OWLY_OK.
// Resolving GetProcAddress is not enough: the pointers can be non-null
// while the Rust engine hasn't finished start() yet, which is exactly
// what produced "ingest called before start" in the DLL's own log.
static std::atomic<bool> g_bOwlyshieldStarted{ false };

// Function pointers
typedef int32_t (*OwlyshieldDllStartFn)();
typedef int32_t (*OwlyshieldDllIngestFn)(const uint8_t*, uint32_t);
typedef int32_t (*OwlyshieldDllIngestOpenedrEventFn)(const uint8_t*, uint32_t);
typedef int32_t (*OwlyshieldDllIngestFirewallPackedDataFn)(const uint8_t*, uint32_t);
typedef void (*OwlyshieldDllStopFn)();

static OwlyshieldDllStartFn g_owlyshield_dll_start = nullptr;
static OwlyshieldDllIngestFn g_owlyshield_dll_ingest = nullptr;
static OwlyshieldDllIngestOpenedrEventFn g_owlyshield_dll_ingest_openedr_event = nullptr;
static OwlyshieldDllIngestFirewallPackedDataFn g_owlyshield_dll_ingest_firewall_packed_data = nullptr;
static OwlyshieldDllStopFn g_owlyshield_dll_stop = nullptr;

// Callback the Owlyshield engine invokes to republish a hook/LLE_DEVICE_IOCTL
// event (UTF-8 JSON) into OpenEDR. Resolved from the DLL and registered after
// the engine starts.
typedef void (*OwlyshieldDllSetPublishCallbackFn)(void(*cb)(const uint8_t*, uint32_t));
static OwlyshieldDllSetPublishCallbackFn g_owlyshield_dll_set_publish_callback = nullptr;

// Forward an Owlyshield-published event into libsysmon's injection path.
extern "C" static void OwlyshieldPublishCallback(const uint8_t* data, uint32_t len)
{
	owlyshield_publish_openedr_event_impl(data, len);
}

///
/// Load owlyshield_ransom.dll and initialize function pointers
///
bool InitOwlyshield()
{
	if (g_hOwlyshieldDll != nullptr)
		return true; // Already loaded

	// Load the DLL from the same directory as edrsvc.exe
	g_hOwlyshieldDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
	if (g_hOwlyshieldDll == nullptr)
	{
		LOGLVL(Debug, "Failed to load owlyshield_ransom.dll (error: " << ::GetLastError() << ")");
		return false;
	}

	// Get function pointers
	g_owlyshield_dll_start = (OwlyshieldDllStartFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_start");
	g_owlyshield_dll_ingest = (OwlyshieldDllIngestFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_ingest");
	g_owlyshield_dll_ingest_openedr_event = (OwlyshieldDllIngestOpenedrEventFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_ingest_openedr_event");
	g_owlyshield_dll_ingest_firewall_packed_data = (OwlyshieldDllIngestFirewallPackedDataFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_ingest_firewall_packed_data");
	g_owlyshield_dll_stop = (OwlyshieldDllStopFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_stop");
	g_owlyshield_dll_set_publish_callback = (OwlyshieldDllSetPublishCallbackFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_set_publish_callback");

	if (g_owlyshield_dll_start == nullptr || 
	    g_owlyshield_dll_ingest == nullptr || 
	    g_owlyshield_dll_ingest_openedr_event == nullptr ||
	    g_owlyshield_dll_ingest_firewall_packed_data == nullptr ||
	    g_owlyshield_dll_stop == nullptr)
	{
		LOGLVL(Debug, "Failed to get Owlyshield DLL function addresses");
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		return false;
	}

	// Start the Owlyshield engine. Only flip g_bOwlyshieldStarted AFTER this
	// returns OK — until then, ingest calls must be rejected on the C++ side
	// even though the function pointers are already non-null.
	int32_t result = g_owlyshield_dll_start();
	if (result != OWLY_OK)
	{
		LOGLVL(Debug, "owlyshield_dll_start failed with code: " << result);
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		g_owlyshield_dll_start = nullptr;
		g_owlyshield_dll_ingest = nullptr;
		g_owlyshield_dll_ingest_openedr_event = nullptr;
		g_owlyshield_dll_ingest_firewall_packed_data = nullptr;
		g_owlyshield_dll_stop = nullptr;
		return false;
	}

	g_bOwlyshieldStarted.store(true, std::memory_order_release);

	// Register the hook-event republish callback so API-hook telemetry observed by
	// the Owlyshield engine is re-injected into OpenEDR's pipeline (enables PTM
	// rules such as CRYPTO_API_MASS). Optional: ignore if the export is absent.
	if (g_owlyshield_dll_set_publish_callback != nullptr)
		g_owlyshield_dll_set_publish_callback(OwlyshieldPublishCallback);

	LOGLVL(Debug, "Owlyshield ransomware protection initialized successfully");
	return true;
}

///
/// Ingest event data into Owlyshield for analysis
///
bool OwlyshieldIngest(const uint8_t* data, uint32_t len)
{
	if (!g_bOwlyshieldStarted.load(std::memory_order_acquire) || g_owlyshield_dll_ingest == nullptr)
		return false;

	int32_t result = g_owlyshield_dll_ingest(data, len);
	return (result == OWLY_OK);
}

///
/// Ingest an OpenEDR enriched event (single-line JSON) over the in-process FFI channel.
///
bool OwlyshieldIngestOpenedrEvent(const std::string& sPayload)
{
	if (sPayload.empty())
		return false;

	if (!g_bOwlyshieldStarted.load(std::memory_order_acquire) || g_owlyshield_dll_ingest_openedr_event == nullptr)
		return false;

	int32_t result = g_owlyshield_dll_ingest_openedr_event(
		reinterpret_cast<const uint8_t*>(sPayload.data()),
		static_cast<uint32_t>(sPayload.size()));
	return (result == OWLY_OK);
}

///
/// Ingest firewall FULL_PACKET packed data (single-line JSON) over the in-process FFI channel.
///
bool OwlyshieldIngestFirewallPackedData(const std::string& sPayload)
{
	if (sPayload.empty())
		return false;

	if (!g_bOwlyshieldStarted.load(std::memory_order_acquire) || g_owlyshield_dll_ingest_firewall_packed_data == nullptr)
		return false;

	int32_t result = g_owlyshield_dll_ingest_firewall_packed_data(
		reinterpret_cast<const uint8_t*>(sPayload.data()),
		static_cast<uint32_t>(sPayload.size()));
	return (result == OWLY_OK);
}

///
/// Install the HydraDragon firewall CA into the Windows ROOT trust store.
///
/// Driver-independent: generates (or reuses) the persisted CA and installs the
/// certificate. Uses a private DLL handle so it does not interfere with the
/// engine state used by InitOwlyshield()/ShutdownOwlyshield().
///
bool OwlyshieldInstallCa()
{
	typedef int32_t (*OwlyshieldDllInstallCaFn)();

	HMODULE hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
	if (hDll == nullptr)
	{
		LOGLVL(Debug, "Failed to load owlyshield_ransom.dll for CA install (error: " << ::GetLastError() << ")");
		return false;
	}

	auto fnInstallCa = (OwlyshieldDllInstallCaFn)::GetProcAddress(hDll, "owlyshield_dll_install_ca");
	if (fnInstallCa == nullptr)
	{
		LOGLVL(Debug, "Failed to get owlyshield_dll_install_ca address");
		::FreeLibrary(hDll);
		return false;
	}

	int32_t result = fnInstallCa();
	::FreeLibrary(hDll);

	if (result != OWLY_OK)
	{
		LOGLVL(Debug, "owlyshield_dll_install_ca failed with code: " << result);
		return false;
	}

	LOGLVL(Debug, "HydraDragon firewall CA installed into Windows trust store");
	return true;
}

///
/// Quarantine a file into an encrypted .hqf container and remove the original.
///
/// Driver-independent: uses a private DLL handle so it does not interfere with
/// the engine state used by InitOwlyshield()/ShutdownOwlyshield().
///
bool OwlyshieldQuarantineFile(const std::wstring& filePath)
{
	typedef int32_t (*OwlyshieldDllQuarantineFileFn)(const uint8_t*, uint32_t);

	if (filePath.empty())
	{
		LOGLVL(Debug, "OwlyshieldQuarantineFile: empty path");
		return false;
	}

	// Convert wide path to UTF-8 for the Rust FFI.
	std::string sUtf8 = string::convertWCharToUtf8(filePath);
	if (sUtf8.empty())
	{
		LOGLVL(Debug, "OwlyshieldQuarantineFile: failed to convert path to UTF-8");
		return false;
	}

	HMODULE hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
	if (hDll == nullptr)
	{
		LOGLVL(Debug, "Failed to load owlyshield_ransom.dll for quarantine (error: " << ::GetLastError() << ")");
		return false;
	}

	auto fnQuarantine = (OwlyshieldDllQuarantineFileFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file");
	if (fnQuarantine == nullptr)
	{
		LOGLVL(Debug, "Failed to get owlyshield_dll_quarantine_file address");
		::FreeLibrary(hDll);
		return false;
	}

	int32_t result = fnQuarantine(
		reinterpret_cast<const uint8_t*>(sUtf8.data()),
		static_cast<uint32_t>(sUtf8.size()));
	::FreeLibrary(hDll);

	if (result != OWLY_OK)
	{
		LOGLVL(Debug, "owlyshield_dll_quarantine_file failed with code: " << result);
		return false;
	}

	LOGLVL(Debug, "File quarantined into encrypted container");
	return true;
}

///
/// Shutdown Owlyshield and unload the DLL
///
void ShutdownOwlyshield()
{
	if (g_hOwlyshieldDll != nullptr)
	{
		// Flip the flag first so any in-flight ingest call from another
		// thread bails out instead of racing with FreeLibrary().
		g_bOwlyshieldStarted.store(false, std::memory_order_release);

		if (g_owlyshield_dll_stop != nullptr)
		{
			g_owlyshield_dll_stop();
			LOGLVL(Debug, "Owlyshield engine stopped");
		}

		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		g_owlyshield_dll_start = nullptr;
		g_owlyshield_dll_ingest = nullptr;
		g_owlyshield_dll_ingest_openedr_event = nullptr;
		g_owlyshield_dll_ingest_firewall_packed_data = nullptr;
		g_owlyshield_dll_stop = nullptr;
	}
}

///
/// Stop/pause antivirus protection state via DLL FFI call
///
bool OwlyshieldStopProtection()
{
	typedef int32_t (*OwlyshieldDllStopProtectionFn)();

	HMODULE hDll = g_hOwlyshieldDll != nullptr ? g_hOwlyshieldDll : ::GetModuleHandleW(L"owlyshield_ransom.dll");
	if (hDll == nullptr) return false;

	auto fnStop = (OwlyshieldDllStopProtectionFn)::GetProcAddress(hDll, "owlyshield_dll_stop_protection");
	if (fnStop == nullptr) return false;

	return (fnStop() == OWLY_OK);
}

///
/// Start/resume antivirus protection state via DLL FFI call
///
bool OwlyshieldStartProtection()
{
	typedef int32_t (*OwlyshieldDllStartProtectionFn)();

	HMODULE hDll = g_hOwlyshieldDll != nullptr ? g_hOwlyshieldDll : ::GetModuleHandleW(L"owlyshield_ransom.dll");
	if (hDll == nullptr) return false;

	auto fnStart = (OwlyshieldDllStartProtectionFn)::GetProcAddress(hDll, "owlyshield_dll_start_protection");
	if (fnStart == nullptr) return false;

	return (fnStart() == OWLY_OK);
}

///
/// Returns true if antivirus protection is currently stopped/paused
///
bool OwlyshieldIsProtectionStopped()
{
	typedef int32_t (*OwlyshieldDllIsProtectionStoppedFn)();

	HMODULE hDll = g_hOwlyshieldDll != nullptr ? g_hOwlyshieldDll : ::GetModuleHandleW(L"owlyshield_ransom.dll");
	if (hDll == nullptr) return false;

	auto fnIsStopped = (OwlyshieldDllIsProtectionStoppedFn)::GetProcAddress(hDll, "owlyshield_dll_is_protection_stopped");
	if (fnIsStopped == nullptr) return false;

	return (fnIsStopped() == 1);
}

} // namespace win
} // namespace cmd
