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
		LOGERROR("Failed to load owlyshield_ransom.dll (error: " << ::GetLastError() << ")");
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
		LOGERROR("Failed to get Owlyshield DLL function addresses");
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		return false;
	}

	// Start the Owlyshield engine
	int32_t result = g_owlyshield_dll_start();
	if (result != OWLY_OK)
	{
		LOGERROR("owlyshield_dll_start failed with code: " << result);
		::FreeLibrary(g_hOwlyshieldDll);
		g_hOwlyshieldDll = nullptr;
		return false;
	}

	LOGINFO("Owlyshield ransomware protection initialized successfully");
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
/// Shutdown Owlyshield and unload the DLL
///
void ShutdownOwlyshield()
{
	if (g_hOwlyshieldDll != nullptr)
	{
		if (g_owlyshield_dll_stop != nullptr)
		{
			g_owlyshield_dll_stop();
			LOGINFO("Owlyshield engine stopped");
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
