///
/// @file Owlyshield ransomware protection DLL integration
///

#include "pch.h"
#include "owlyshield_ransom.h"
#include <windows.h>

namespace cmd {
namespace win {

static HMODULE g_hOwlyshieldDll = nullptr;

// Function pointers
typedef int32_t (*OwlyshieldDllStartFn)();
typedef int32_t (*OwlyshieldDllIngestFn)(const uint8_t*, uint32_t);
typedef void (*OwlyshieldDllStopFn)();

static OwlyshieldDllStartFn g_owlyshield_dll_start = nullptr;
static OwlyshieldDllIngestFn g_owlyshield_dll_ingest = nullptr;
static OwlyshieldDllStopFn g_owlyshield_dll_stop = nullptr;

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
	g_owlyshield_dll_stop = (OwlyshieldDllStopFn)::GetProcAddress(g_hOwlyshieldDll, "owlyshield_dll_stop");

	if (g_owlyshield_dll_start == nullptr || 
	    g_owlyshield_dll_ingest == nullptr || 
	    g_owlyshield_dll_stop == nullptr)
	{
		LOGLVL(Debug, "Failed to get Owlyshield DLL function addresses");
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		return false;
	}

	// Start the Owlyshield engine
	int32_t result = g_owlyshield_dll_start();
	if (result != OWLY_OK)
	{
		LOGLVL(Debug, "owlyshield_dll_start failed with code: " << result);
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		return false;
	}

	LOGLVL(Debug, "Owlyshield ransomware protection initialized successfully");
	return true;
}

///
/// Ingest event data into Owlyshield for analysis
///
bool OwlyshieldIngest(const uint8_t* data, uint32_t len)
{
	if (g_owlyshield_dll_ingest == nullptr)
		return false;

	int32_t result = g_owlyshield_dll_ingest(data, len);
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
/// Shutdown Owlyshield and unload the DLL
///
void ShutdownOwlyshield()
{
	if (g_hOwlyshieldDll != nullptr)
	{
		if (g_owlyshield_dll_stop != nullptr)
		{
			g_owlyshield_dll_stop();
			LOGLVL(Debug, "Owlyshield engine stopped");
		}

		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		g_owlyshield_dll_start = nullptr;
		g_owlyshield_dll_ingest = nullptr;
		g_owlyshield_dll_stop = nullptr;
	}
}

} // namespace win
} // namespace cmd
