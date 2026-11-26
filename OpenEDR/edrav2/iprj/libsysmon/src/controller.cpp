//
// edrav2.libsysmon project
// 
// Author: Denis Kroshin (06.02.2019)
// Reviewer: Podpruzhnikov Yury (18.02.2019)
//
///
/// @file System Monitor Controller implementation
///
/// @addtogroup sysmon System Monitor library
/// @{
#include "pch.h"
#include "controller.h"
#include "../../libprocmon/inc/procmonevent.h"
#include <libcore/inc/zerotrust.hpp>
#include <libcore/inc/kstack_resolve.hpp>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string_view>
#include <windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <cctype>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>

#undef CMD_COMPONENT
#define CMD_COMPONENT "libsysmon"

namespace cmd {
namespace win {

namespace {

//
// Dynamic hook ownership (OpenEDR side).
//
// owlyshield only maintains the event-id map for interpreting hook events;
// registration (MESSAGE_ADD_HOOK) and per-process apply (MESSAGE_HOOK_PROCESS)
// are issued here, straight to edrdrv, from the ptm.local.src cryptoApiList.
// Event ids are 0x6000 + file order on both sides so the maps stay in sync.
//
namespace hookmgr {

	constexpr uint32_t c_nHookEventIdStart = 0x6000;
	constexpr size_t c_nMaxTargets = 512; // hard cap: driver table is bounded

	struct HookTarget
	{
		std::wstring module;
		std::wstring function;
	};

	static std::mutex s_mtxHook;
	static std::vector<HookTarget> s_targets;
	static bool s_targetsLoaded = false;
	static bool s_targetsRegistered = false;

	struct ComMessage
	{
		uint32_t type;
		uint32_t pid;
		uint64_t gid;
		wchar_t path[520];
		wchar_t quarantine_path[520];
	};
	static_assert(sizeof(ComMessage) == 2096, "COM_MESSAGE wire layout must stay 2096 bytes");

	constexpr uint32_t MSG_ADD_HOOK = 9;
	constexpr uint32_t MSG_HOOK_PROCESS = 10;
	constexpr uint32_t IOCTL_OWLY = (0x00000022u << 16) | (0u << 14) | (0x921u << 2) | 0u;

	static bool sendDriverMessage(const ComMessage& msg)
	{
		HANDLE hDev = ::CreateFileW(L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}",
			GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (hDev == INVALID_HANDLE_VALUE)
			return false;
		DWORD nRet = 0;
		const BOOL ok = ::DeviceIoControl(hDev, IOCTL_OWLY,
			const_cast<ComMessage*>(&msg), sizeof(msg), nullptr, 0, &nRet, nullptr);
		::CloseHandle(hDev);
		return ok != FALSE;
	}

	static void fillWideField(wchar_t* dst, size_t cap, const std::wstring& src)
	{
		if (cap == 0)
			return;
		size_t n = src.size();
		if (n >= cap)
			n = cap - 1;
		for (size_t i = 0; i < n; ++i)
			dst[i] = src[i];
		dst[n] = 0;
	}

	// Mirror of the Rust normalize_hook_module_name: full paths and dotted
	// names pass through, bare names gain ".dll" (driver matches BaseDllName).
	static std::wstring normalizeModule(const std::wstring& raw)
	{
		if (raw.empty() || raw == L"*")
			return L"";
		if (raw.find(L'\\') != std::wstring::npos || raw.find(L'/') != std::wstring::npos)
			return raw;
		if (raw.find(L'.') != std::wstring::npos)
			return raw;
		return raw + L".dll";
	}

	static std::vector<std::wstring> ptmCandidatePaths()
	{
		std::vector<std::wstring> out;
		wchar_t wsExe[MAX_PATH] = {};
		if (::GetModuleFileNameW(nullptr, wsExe, MAX_PATH) > 0)
		{
			std::wstring s(wsExe);
			size_t pos = s.find_last_of(L"\\/");
			if (pos != std::wstring::npos)
				out.push_back(s.substr(0, pos + 1) + L"ptm.local.src");
		}
		out.push_back(L"C:\\Program Files\\HydraDragonAntivirus\\OpenEDR\\ptm.local.src");
		out.push_back(L"ptm.local.src");
		out.push_back(L"OpenEDR\\edrav2\\iprj\\edrdata\\ptm.local.src");
		return out;
	}

	static std::wstring resolveExportCasing(const std::wstring& moduleName, const std::wstring& funcName)
	{
		HMODULE hMod = ::LoadLibraryExW(moduleName.c_str(), nullptr, LOAD_LIBRARY_AS_DATAFILE);
		if (!hMod)
			hMod = ::GetModuleHandleW(moduleName.c_str());
		if (hMod)
		{
			PBYTE base = (PBYTE)((ULONG_PTR)hMod & ~3);
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
			if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 && dos->e_lfanew < 0x10000000)
			{
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
				if (nt->Signature == IMAGE_NT_SIGNATURE)
				{
					DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					DWORD expSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
					if (expRva && expSize)
					{
						PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(base + expRva);
						PDWORD names = (PDWORD)(base + exp->AddressOfNames);
						for (DWORD i = 0; i < exp->NumberOfNames; ++i)
						{
							const char* expName = (const char*)(base + names[i]);
							std::wstring wexp(expName, expName + strlen(expName));
							if (_wcsicmp(wexp.c_str(), funcName.c_str()) == 0)
							{
								::FreeLibrary(hMod);
								return wexp;
							}
						}
					}
				}
			}
			::FreeLibrary(hMod);
		}
		if (_wcsicmp(funcName.c_str(), L"writeprocessmemory") == 0) return L"WriteProcessMemory";
		if (_wcsicmp(funcName.c_str(), L"ntcreatethreadex") == 0) return L"NtCreateThreadEx";
		if (_wcsicmp(funcName.c_str(), L"bcryptclosealgorithmprovider") == 0) return L"BCryptCloseAlgorithmProvider";
		if (_wcsicmp(funcName.c_str(), L"bcryptimportkey") == 0) return L"BCryptImportKey";
		if (_wcsicmp(funcName.c_str(), L"bcryptimportkeypair") == 0) return L"BCryptImportKeyPair";
		if (_wcsicmp(funcName.c_str(), L"bcryptopenalgorithmprovider") == 0) return L"BCryptOpenAlgorithmProvider";
		return funcName;
	}


	// Targeted scan for `"cryptoApiList": [ "mod!func", ... ]`: bracket
	// matched with string awareness, so brackets or // inside literals and
	// //-comments elsewhere in the policy file cannot confuse it.
	static std::vector<HookTarget> extractApiList(const std::string& content)
	{
		std::vector<HookTarget> out;
		const std::string key = "\"cryptoApiList\"";
		size_t keyPos = content.find(key);
		if (keyPos == std::string::npos)
			return out;
		size_t i = keyPos + key.size();
		const size_t n = content.size();
		// Seek array open.
		size_t depth = 0;
		bool started = false;
		for (; i < n; ++i)
		{
			if (content[i] == '[') { started = true; depth = 1; ++i; break; }
		}
		if (!started)
			return out;
		std::string cur;
		bool inStr = false, esc = false;
		for (; i < n && depth > 0 && out.size() < c_nMaxTargets; ++i)
		{
			const char c = content[i];
			if (inStr)
			{
				if (esc) { cur.push_back(c); esc = false; }
				else if (c == '\\') esc = true;
				else if (c == '"')
				{
					inStr = false;
					size_t bang = cur.find('!');
					if (bang != std::string::npos && bang > 0 && bang + 1 < cur.size())
					{
						HookTarget t;
						// UTF-8 policy file is ASCII here (module/function names).
						t.module.assign(cur.begin(), cur.begin() + bang);
						t.function.assign(cur.begin() + bang + 1, cur.end());
						// narrow->wide: names are ASCII by construction.
						std::wstring wmod(t.module.begin(), t.module.end());
						std::wstring wfn(t.function.begin(), t.function.end());
						wmod = normalizeModule(wmod);
						if (!wmod.empty() && !wfn.empty() && wmod.size() < 64 && wfn.size() < 256)
						{
							t.module = wmod;
							t.function = wfn;
							out.push_back(std::move(t));
						}
					}
					cur.clear();
				}
				else cur.push_back(c);
				continue;
			}
			if (c == '"') { inStr = true; cur.clear(); }
			else if (c == '[') ++depth;
			else if (c == ']')
			{
				if (--depth == 0) break;
			}
		}
		return out;
	}


	static std::vector<HookTarget> loadTargetsLocked()
	{
		std::vector<HookTarget> targets;
		auto isDuplicate = [&](const HookTarget& t) {
			for (const auto& existing : targets)
			{
				if (_wcsicmp(existing.module.c_str(), t.module.c_str()) == 0 &&
					_wcsicmp(existing.function.c_str(), t.function.c_str()) == 0)
					return true;
			}
			return false;
		};

		// 1. Load from ptm.local.src
		for (const auto& path : ptmCandidatePaths())
		{
			// Through the config reader: the installed copy is AES-packed, and a raw
			// read saw only ciphertext (0 targets, so no process was ever hooked).
			std::string content = io::readConfigText(path);
			if (content.empty())
				continue;
			auto specs = extractApiList(content);
			if (!specs.empty())
			{
				for (auto& s : specs)
				{
					if (!isDuplicate(s) && targets.size() < c_nMaxTargets)
						targets.push_back(std::move(s));
				}
				break;
			}
		}



		return targets;
	}

	// Register the whole list (0x6000 + file order, mirroring the Rust id
	// map). Marked done only on full success so a not-yet-ready driver is
	// retried on the next process sighting; re-sending is idempotent
	// (same id overwrites the same target).
	static void ensureRegisteredLocked()
	{
		if (s_targetsRegistered)
			return;
		if (s_targets.empty())
			return;
		size_t ok = 0;
		for (size_t i = 0; i < s_targets.size(); ++i)
		{
			ComMessage msg = {};
			msg.type = MSG_ADD_HOOK;
			msg.pid = 0;
			msg.gid = (uint64_t)(c_nHookEventIdStart + i);
			fillWideField(msg.path, 520, s_targets[i].module);
			fillWideField(msg.quarantine_path, 520, s_targets[i].function);
			if (sendDriverMessage(msg))
				++ok;
		}
		if (ok == s_targets.size())
		{
			s_targetsRegistered = true;
			LOGLVL(Critical, FMT("hookmgr: registered " << ok << "/" << s_targets.size()
				<< " hook targets from ptm.local.src"));
		}
	}

	// Called for every new process (raw ProcessCreate). Skips non-hookeable
	// identities; failures are silent by design (driver refuses protected
	// targets; retry happens naturally on next sighting paths).
	static void applyHooksToProcess(uint32_t pid)
	{
		if (pid == 0 || pid == 4)
			return;
		if (pid == ::GetCurrentProcessId())
			return;
		{
			std::scoped_lock _lock(s_mtxHook);
			if (!s_targetsLoaded)
			{
				s_targets = loadTargetsLocked();
				s_targetsLoaded = true;
				LOGLVL(Critical, FMT("hookmgr: loaded " << s_targets.size()
					<< " hook targets from ptm.local.src cryptoApiList"));
			}
			if (s_targets.empty())
				return;
			ensureRegisteredLocked();
		}
		ComMessage msg = {};
		msg.type = MSG_HOOK_PROCESS;
		msg.pid = pid;
		sendDriverMessage(msg);
	}

} // namespace hookmgr

const char* getOpenEdrWireEventType(edrdrv::SysmonEvent rawEvent, Event eventType)
{
	switch (rawEvent)
	{
		case edrdrv::SysmonEvent::DeviceIoControl:
			return "LLE_DEVICE_IOCTL";
		case edrdrv::SysmonEvent::NamedPipeCreate:
			return "LLE_NAMED_PIPE_CREATE";
		case edrdrv::SysmonEvent::NamedPipeServerCreate:
			return "LLE_NAMED_PIPE_SERVER_CREATE";
		case edrdrv::SysmonEvent::SelfDefense:
			return "LLE_SELF_DEFENSE";
		default:
			return getEventTypeString(eventType);
	}
}

// HIPS verdict gate (hips_rules.json — separate from firewall rules):
// a persistent user "allow" verdict vetoes the kernel kill below.
// Missing/unparseable file or any non-allow verdict falls through to kill.
static std::string toLowerAsciiStr(const std::string& s)
{
	std::string out(s);
	for (std::string::iterator it = out.begin(); it != out.end(); ++it)
		*it = static_cast<char>(std::tolower(static_cast<unsigned char>(*it)));
	return out;
}

static bool hipsUserAllows(const std::string& sExePath)
{
	if (sExePath.empty())
		return false;
	const std::string key = toLowerAsciiStr(sExePath);
	std::ifstream file("C:\\ProgramData\\edrsvc\\hips_rules.json", std::ios::binary);
	if (!file)
		return false;
	// Append-log format: {"action":"...","path":"...","time":"..."}.
	// Last matching line wins.
	std::string lastAction;
	std::string line;
	while (std::getline(file, line))
	{
		if (!line.empty() && line[line.size() - 1] == '\r')
			line.erase(line.size() - 1);
		if (line.empty())
			continue;
		try
		{
			auto vEvent = variant::deserializeFromJson(line);
			const std::string sPath = vEvent.get("path", std::string());
			if (sPath.empty() || toLowerAsciiStr(sPath) != key)
				continue;
			lastAction = toLowerAsciiStr(vEvent.get("action", std::string()));
		}
		catch (...) {}
	}
	return lastAction == "allow" || lastAction == "allow_always";
}

} // namespace

//
//
//
SystemMonitorController* SystemMonitorController::s_pInstance = nullptr;

SystemMonitorController::SystemMonitorController()
	: m_hFltPortReceiver(c_sPortName, c_nTreadsCount, edrdrv::c_nReplyMode, "SysMon::EventsPool")
{
	s_pInstance = this;
}

//
//
//
SystemMonitorController::~SystemMonitorController()
{
	if (m_fInitialized)
		stopThreads();
}

//
//
//
void SystemMonitorController::finalConstruct(Variant vConfig)
{
	CHECK_IN_SOURCE_LOCATION();
	m_fStopDriverOnShutdown = vConfig.get("stopDriverOnShutdown", m_fStopDriverOnShutdown);
	m_nThreadsCount = vConfig.get("threadsCount", c_nTreadsCount);
	m_eInjection = vConfig.get("injectNewProcesses", InjectionMode::None);
	m_vDefaultDriverConfig = vConfig.get("driverConfig", Dictionary());
	m_vSelfProtectConfig = vConfig.get("selfprotectConfig", Variant());
	m_sStartMode = vConfig.get("startMode", m_sStartMode);
	m_pReceiver = queryInterfaceSafe<IDataReceiver>(vConfig.get("receiver", nullptr));

	CHECK_IN_SOURCE_LOCATION();
	if (m_eInjection == InjectionMode::Driver)
	{
		m_vDefaultDriverConfig.put("enableDllInject", true);
		Sequence sqDllName;
#ifdef _WIN64
		std::wstring sSystemDir(getCatalogData("os.systemDir"));
		std::wstring sSyswowDir(getCatalogData("os.syswowDir"));
		if (std::filesystem::exists(sSystemDir + L"\\" + c_sInjDll64) &&
			std::filesystem::exists(sSyswowDir + L"\\" + c_sInjDll32))
		{
			sqDllName.push_back(sSystemDir + L"\\" + c_sInjDll64);
			sqDllName.push_back(sSyswowDir + L"\\" + c_sInjDll32);
		}
		else
		{
#if defined(FEATURE_ENABLE_MADCHOOK)
			LOGWRN("Injection DLLs not found in system directory. Use default directory.");
			std::wstring sImageDir(getCatalogData("app.imagePath"));
			sqDllName.push_back(sImageDir + L"\\" + c_sInjDll64);
			sqDllName.push_back(sImageDir + L"\\" + c_sInjDll32);
#else
			LOGWRN("Injection DLLs not found in system directory.");
#endif
		}
#else
		std::wstring sSystemDir(getCatalogData("os.systemDir"));
		if (std::filesystem::exists(sSystemDir + L"\\" + c_sInjDll32))
		{
			sqDllName.push_back(sSystemDir + L"\\" + c_sInjDll32);
		}
		else
		{
			LOGWRN("Injection DLLs not found in system directory. Use default directory.");
			std::wstring sImageDir(getCatalogData("app.imagePath"));
			sqDllName.push_back(sImageDir + L"\\" + c_sInjDll32);
		}
#endif
		m_vDefaultDriverConfig.put("injectedDll", sqDllName);
	}
	else
		m_vDefaultDriverConfig.put("enableDllInject", false);

	CHECK_IN_SOURCE_LOCATION();

	TRACE_BEGIN
	m_vEventSchema = variant::deserializeFromJson(edrdrv::c_sEventSchema);
	m_vConfigSchema = variant::deserializeFromJson(edrdrv::c_sConfigSchema);
	m_vUpdateRulesSchema = variant::deserializeFromJson(edrdrv::c_sUpdateRulesSchema);
	m_vSetProcessInfoSchema = variant::deserializeFromJson(edrdrv::c_sSetProcessInfoSchema);

	TRACE_END("Can't deserialize driver schema.");

	m_nSelfPid = GetCurrentProcessId();
}

//
//
//
void SystemMonitorController::loadState(Variant /* vState */)
{
}

//
//
//
Variant SystemMonitorController::saveState()
{
	return {};
}

//
//
//
void SystemMonitorController::install(Variant vParams)
{
	bool fReinstall = execCommand(createObject(CLSID_WinServiceController), "isExist",
			Dictionary({ {"name", c_sDrvSrvName} }));

	// We must stop service on reinstall
	if (fReinstall)
	{
		(void) execCommand(createObject(CLSID_WinServiceController), "stop",
			Dictionary({ {"name", c_sDrvSrvName} }));
	}

	namespace fs = std::filesystem;

	fs::path sDriverName(vParams.get("driverName", c_sDriverName));
	auto sDriverPath = fs::path(getCatalogData("app.imagePath")) / sDriverName;
	if (!fs::exists(sDriverPath))
		error::NotFound(SL, FMT("Driver <" << sDriverPath << "> is not found")).throwException();

	if (vParams.get("useSystemDir", true))
	{
		auto sSystemDriverPath = fs::path(getCatalogData("os.systemDir")) / L"drivers" / sDriverName; 
		fs::copy_file(sDriverPath, sSystemDriverPath, fs::copy_options::overwrite_existing);
		sDriverPath = sSystemDriverPath;
	}

	std::string sStartMode = vParams.get("startMode", m_sStartMode);
	Size nStartMode = (sStartMode == "auto") ? SERVICE_SYSTEM_START :
		((sStartMode == "manual") ? SERVICE_DEMAND_START : SERVICE_DISABLED);

	// Install to system
	Variant vResult = execCommand(Dictionary({
			{"processor", Dictionary({{"clsid", CLSID_WinServiceController}}) }, 
			{"command", "create"},
			{"params", Dictionary({
				{"name", c_sDrvSrvName},
				{"path", sDriverPath.native()},
				{"type", SERVICE_FILE_SYSTEM_DRIVER},
				{"startMode", nStartMode},
				{"errorControl", SERVICE_ERROR_NORMAL},
				{"displayName", "EDR Agent activity monitor"},
				{"group", "FSFilter Activity Monitor"},
				{"dependencies", Sequence({"FltMgr"})},
				{"reinstall", fReinstall}
			})},
		}));

	std::wstring sRegKey(c_sServiceRegKey);
	sRegKey += L"\\";
	sRegKey += c_sDrvSrvName;
	LSTATUS status = RegSetKeyValueW(HKEY_LOCAL_MACHINE, sRegKey.c_str(),
		c_sSupportedFeatures, REG_DWORD, &c_dwSupportedFeaturesValue, sizeof(c_dwSupportedFeaturesValue));
	if (status != ERROR_SUCCESS)
		error::win::WinApiError(SL, status, "Fail to create registry key").throwException();

	sRegKey += L"\\";
	sRegKey += c_sInstancesRegKey;
	status = RegSetKeyValueW(HKEY_LOCAL_MACHINE, sRegKey.c_str(), c_sDefaultInstance, REG_SZ,
		&c_sDefaultInstanceValue, sizeof(c_sDefaultInstanceValue));
	if (status != ERROR_SUCCESS)
		error::win::WinApiError(SL, status, "Fail to create registry key").throwException();

	sRegKey += L"\\";
	sRegKey += c_sDefaultInstanceValue;
	status = RegSetKeyValueW(HKEY_LOCAL_MACHINE, sRegKey.c_str(), c_sFlags, REG_DWORD,
		&c_dwFlags, sizeof(c_dwFlags));
	if (status != ERROR_SUCCESS)
		error::win::WinApiError(SL, status, "Fail to create registry key").throwException();
	status = RegSetKeyValueW(HKEY_LOCAL_MACHINE, sRegKey.c_str(), c_sAltitude, REG_SZ,
		&edrdrv::c_sAltitudeValue, sizeof(edrdrv::c_sAltitudeValue));
	if (status != ERROR_SUCCESS)
		error::win::WinApiError(SL, status, "Fail to create registry key").throwException();
}

//
//
void SystemMonitorController::ensureMbrFilterDriver()
{
	namespace fs = std::filesystem;
	wchar_t szSysDir[MAX_PATH] = { 0 };
	::GetSystemDirectoryW(szSysDir, MAX_PATH);
	fs::path destPath = fs::path(szSysDir) / L"drivers" / L"MBRFilter.sys";

	// Search for staged source MBRFilter.sys
	wchar_t szModule[MAX_PATH] = { 0 };
	::GetModuleFileNameW(NULL, szModule, MAX_PATH);
	fs::path appDir = fs::path(szModule).parent_path();
	fs::path srcPath = appDir / L"MBRFilter.sys";
	std::error_code ec;
	if (!fs::exists(srcPath, ec))
	{
		fs::path fallbackPath = appDir.parent_path() / L"hydradragon" / L"MBRFilter" / L"MBRFilter.sys";
		if (fs::exists(fallbackPath, ec))
			srcPath = fallbackPath;
	}

	if (fs::exists(srcPath, ec))
	{
		if (fs::copy_file(srcPath, destPath, fs::copy_options::update_existing, ec) && !ec)
		{
			LOGINF("[MBR] Staged MBRFilter.sys to " << destPath.string());
		}
	}

	if (!fs::exists(destPath, ec))
	{
		LOGWRN("[MBR] MBRFilter.sys not found at " << destPath.string());
		return;
	}

	// Add MBRFilter to UpperFilters
	HKEY hClassKey = NULL;
	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
		L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}", 
		0, KEY_READ | KEY_WRITE, &hClassKey) == ERROR_SUCCESS)
	{
		DWORD dwType = 0;
		DWORD dwSize = 0;
		bool bAlreadyPresent = false;
		if (::RegQueryValueExW(hClassKey, L"UpperFilters", NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS && dwSize > 0)
		{
			std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
			if (::RegQueryValueExW(hClassKey, L"UpperFilters", NULL, &dwType, (LPBYTE)buffer.data(), &dwSize) == ERROR_SUCCESS)
			{
				const wchar_t* p = buffer.data();
				while (*p)
				{
					std::wstring item(p);
					std::wstring lowerItem = item;
					std::transform(lowerItem.begin(), lowerItem.end(), lowerItem.begin(), ::towlower);
					if (lowerItem == L"mbrfilter")
					{
						bAlreadyPresent = true;
						break;
					}
					p += item.length() + 1;
				}
			}
		}

		if (!bAlreadyPresent)
		{
			std::vector<wchar_t> newMultiSz;
			if (dwSize > 0)
			{
				std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
				if (::RegQueryValueExW(hClassKey, L"UpperFilters", NULL, &dwType, (LPBYTE)buffer.data(), &dwSize) == ERROR_SUCCESS)
				{
					const wchar_t* p = buffer.data();
					while (*p)
					{
						std::wstring item(p);
						newMultiSz.insert(newMultiSz.end(), item.begin(), item.end());
						newMultiSz.push_back(L'\0');
						p += item.length() + 1;
					}
				}
			}
			std::wstring mbrItem = L"MBRFilter";
			newMultiSz.insert(newMultiSz.end(), mbrItem.begin(), mbrItem.end());
			newMultiSz.push_back(L'\0');
			newMultiSz.push_back(L'\0');

			::RegSetValueExW(hClassKey, L"UpperFilters", 0, REG_MULTI_SZ, 
				(const BYTE*)newMultiSz.data(), (DWORD)(newMultiSz.size() * sizeof(wchar_t)));
			LOGINF("[MBR] Added MBRFilter to disk class UpperFilters");
		}
		::RegCloseKey(hClassKey);
	}

	// Register and start service
	SC_HANDLE hSCM = ::OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM != NULL)
	{
		SC_HANDLE hSvc = ::OpenServiceW(hSCM, L"MBRFilter", SERVICE_ALL_ACCESS);
		if (hSvc == NULL)
		{
			hSvc = ::CreateServiceW(
				hSCM,
				L"MBRFilter",
				L"MBRFilter Driver",
				SERVICE_ALL_ACCESS,
				SERVICE_KERNEL_DRIVER,
				SERVICE_BOOT_START,
				SERVICE_ERROR_NORMAL,
				destPath.c_str(),
				L"PnP Filter",
				NULL, NULL, NULL, NULL
			);
			if (hSvc != NULL)
			{
				LOGINF("[MBR] Created MBRFilter kernel driver service");
			}
		}

		if (hSvc != NULL)
		{
			if (::StartServiceW(hSvc, 0, NULL))
			{
				LOGINF("[MBR] MBRFilter driver service started");
			}
			::CloseServiceHandle(hSvc);
		}
		::CloseServiceHandle(hSCM);
	}
}

//
// Standalone hypervisor drivers staged next to the service by the installer.
// The driver is chosen by the processor vendor: RedDbg virtualizes AMD (SVM)
// processors, HyperDbg's hyperhv - Intel (VT-x) ones. The service names are
// the ones of the driver INF files.
//
struct HypervisorDriverInfo
{
	const wchar_t* pszFileName;
	const wchar_t* pszServiceName;
	const wchar_t* pszDisplayName;
};

static constexpr HypervisorDriverInfo c_AmdHypervisorDriver = { L"RedDbgDrv.sys", L"RedDbg", L"RedDbg Kernel Debugger Service" };
static constexpr HypervisorDriverInfo c_IntelHypervisorDriver = { L"hyperhv.sys", L"hyperhv", L"HyperDbg Hypervisor Service" };

//
// Returns the hypervisor driver for the current processor or nullptr.
//
static const HypervisorDriverInfo* getHypervisorDriverForCpu()
{
	int regs[4] = {};
	__cpuid(regs, 0);

	char sVendor[13] = {};
	memcpy(sVendor + 0, &regs[1], 4); // EBX
	memcpy(sVendor + 4, &regs[3], 4); // EDX
	memcpy(sVendor + 8, &regs[2], 4); // ECX

	if (strcmp(sVendor, "AuthenticAMD") == 0)
		return &c_AmdHypervisorDriver;
	if (strcmp(sVendor, "GenuineIntel") == 0)
		return &c_IntelHypervisorDriver;
	return nullptr;
}

//
// Stages, registers and starts the hypervisor driver that matches the
// processor. edrdrv binds to its device (hypervisor bridge) when the service
// connects to the filter port, so this is called before that connection.
// The driver is optional: nothing happens if it is not staged by the installer.
//
void SystemMonitorController::ensureHypervisorDriver()
{
	namespace fs = std::filesystem;

	const HypervisorDriverInfo* pDriver = getHypervisorDriverForCpu();
	if (pDriver == nullptr)
	{
		LOGINF("[HV] Unknown processor vendor, no hypervisor driver is used");
		return;
	}

	wchar_t szSysDir[MAX_PATH] = { 0 };
	::GetSystemDirectoryW(szSysDir, MAX_PATH);
	fs::path destPath = fs::path(szSysDir) / L"drivers" / pDriver->pszFileName;

	wchar_t szModule[MAX_PATH] = { 0 };
	::GetModuleFileNameW(NULL, szModule, MAX_PATH);
	fs::path srcPath = fs::path(szModule).parent_path() / pDriver->pszFileName;

	// update_existing: a newer staged driver (product upgrade) replaces the old one
	std::error_code ec;
	if (fs::exists(srcPath, ec))
	{
		if (fs::copy_file(srcPath, destPath, fs::copy_options::update_existing, ec) && !ec)
		{
			LOGINF("[HV] Staged hypervisor driver to " << destPath.string());
		}
	}

	if (!fs::exists(destPath, ec))
	{
		LOGINF("[HV] Hypervisor driver is not installed: " << destPath.string());
		return;
	}

	SC_HANDLE hSCM = ::OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
		return;

	SC_HANDLE hSvc = ::OpenServiceW(hSCM, pDriver->pszServiceName, SERVICE_ALL_ACCESS);
	if (hSvc == NULL)
	{
		// Demand start: the driver is started by this service only
		hSvc = ::CreateServiceW(
			hSCM,
			pDriver->pszServiceName,
			pDriver->pszDisplayName,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			destPath.c_str(),
			NULL, NULL, NULL, NULL, NULL
		);
		if (hSvc != NULL)
		{
			LOGINF("[HV] Created hypervisor driver service");
		}
	}

	if (hSvc != NULL)
	{
		if (::StartServiceW(hSvc, 0, NULL))
		{
			LOGINF("[HV] Hypervisor driver service started");
		}
		else if (::GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
		{
			LOGWRN("[HV] Can't start hypervisor driver service, error " << ::GetLastError());
		}
		::CloseServiceHandle(hSvc);
	}
	::CloseServiceHandle(hSCM);
}

//
// Removes both hypervisor drivers (the product can be moved between machines).
// A running hypervisor driver can not be unloaded: its service is marked for
// deletion and its file is removed after the reboot if it is still in use.
//
void SystemMonitorController::uninstallHypervisorDriver()
{
	wchar_t szSysDir[MAX_PATH] = { 0 };
	::GetSystemDirectoryW(szSysDir, MAX_PATH);

	for (const HypervisorDriverInfo* pDriver : { &c_AmdHypervisorDriver, &c_IntelHypervisorDriver })
	{
		std::string sServiceName = string::convertWCharToUtf8(pDriver->pszServiceName);
		(void)execCommand(createObject(CLSID_WinServiceController), "stop",
			Dictionary({ { "name", sServiceName } }));
		(void)execCommand(createObject(CLSID_WinServiceController), "delete",
			Dictionary({ { "name", sServiceName } }));

		std::filesystem::path destPath = std::filesystem::path(szSysDir) / L"drivers" / pDriver->pszFileName;
		std::error_code ec;
		if (std::filesystem::exists(destPath, ec) && !std::filesystem::remove(destPath, ec))
		{
			::MoveFileExW(destPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
		}
	}
}

void SystemMonitorController::uninstallMbrFilterDriver()
{
	// Clean up UpperFilters
	HKEY hClassKey = NULL;
	if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
		L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e967-e325-11ce-bfc1-08002be10318}", 
		0, KEY_READ | KEY_WRITE, &hClassKey) == ERROR_SUCCESS)
	{
		DWORD dwType = 0;
		DWORD dwSize = 0;
		if (::RegQueryValueExW(hClassKey, L"UpperFilters", NULL, &dwType, NULL, &dwSize) == ERROR_SUCCESS && dwSize > 0)
		{
			std::vector<wchar_t> buffer(dwSize / sizeof(wchar_t) + 2, 0);
			if (::RegQueryValueExW(hClassKey, L"UpperFilters", NULL, &dwType, (LPBYTE)buffer.data(), &dwSize) == ERROR_SUCCESS)
			{
				std::vector<wchar_t> newMultiSz;
				const wchar_t* p = buffer.data();
				while (*p)
				{
					std::wstring item(p);
					std::wstring lowerItem = item;
					std::transform(lowerItem.begin(), lowerItem.end(), lowerItem.begin(), ::towlower);
					if (lowerItem != L"mbrfilter")
					{
						newMultiSz.insert(newMultiSz.end(), item.begin(), item.end());
						newMultiSz.push_back(L'\0');
					}
					p += item.length() + 1;
				}
				if (newMultiSz.empty())
				{
					::RegDeleteValueW(hClassKey, L"UpperFilters");
				}
				else
				{
					newMultiSz.push_back(L'\0');
					::RegSetValueExW(hClassKey, L"UpperFilters", 0, REG_MULTI_SZ, 
						(const BYTE*)newMultiSz.data(), (DWORD)(newMultiSz.size() * sizeof(wchar_t)));
				}
			}
		}
		::RegCloseKey(hClassKey);
	}

	// Stop & delete service
	(void)execCommand(createObject(CLSID_WinServiceController), "stop",
		Dictionary({ { "name", "MBRFilter" } }));
	(void)execCommand(createObject(CLSID_WinServiceController), "delete",
		Dictionary({ { "name", "MBRFilter" } }));

	// Delete binary
	wchar_t szSysDir[MAX_PATH] = { 0 };
	::GetSystemDirectoryW(szSysDir, MAX_PATH);
	std::filesystem::path destPath = std::filesystem::path(szSysDir) / L"drivers" / L"MBRFilter.sys";
	if (std::filesystem::exists(destPath))
	{
		std::error_code ec;
		std::filesystem::remove(destPath, ec);
	}
}

//
void SystemMonitorController::uninstall(Variant vParams)
{
	// Clean up MBRFilter driver completely in C++
	uninstallMbrFilterDriver();

	// Remove the standalone hypervisor driver (RedDbg / HyperDbg)
	uninstallHypervisorDriver();

	// FIXME: I'm not sure that it is correct to call shutdown here because teoretically the controller
	// can be even not started
	shutdown();

	(void)execCommand(createObject(CLSID_WinServiceController), "stop",
		Dictionary({ { "name", c_sDrvSrvName } }));

	Variant vResult = execCommand(Dictionary({
		{"processor", Dictionary({{"clsid", CLSID_WinServiceController}}) },
		{"command", "delete"},
		{"params", Dictionary({
			{"name", c_sDrvSrvName},
		})},
	}));

	namespace fs = std::filesystem;
	fs::path sDriverName(vParams.get("driverName", c_sDriverName));
	auto sDriverPath = fs::path(getCatalogData("os.systemDir")) / L"drivers" / sDriverName;
	if (fs::exists(sDriverPath))
		std::filesystem::remove(sDriverPath);
}

//
//
//
void SystemMonitorController::start()
{
	startInt();
}

//
//
//
bool SystemMonitorController::startInt()
{
	TRACE_BEGIN;
	LOGLVL(Detailed, "SysMon controller is being started");

	std::scoped_lock _lock(m_mtxStartStop);
	if (m_fInitialized)
	{
		LOGLVL(Detailed, "SysMon controller already started");
		return false;
	}

	Size nStartMode = (m_sStartMode == "auto") ? SERVICE_SYSTEM_START :
		((m_sStartMode == "manual") ? SERVICE_DEMAND_START : SERVICE_DISABLED);

	Variant vResult = execCommand(Dictionary({
			{"processor", Dictionary({{"clsid", CLSID_WinServiceController}}) },
			{"command", "start"},
			{"params", Dictionary({
				{"name", c_sDrvSrvName},
				{"startMode", nStartMode},
			})},
		}));

	vResult = execCommand(Dictionary({
			{"processor", Dictionary({{"clsid", CLSID_WinServiceController}}) },
			{"command", "waitState"},
			{"params", Dictionary({
				{"name", c_sDrvSrvName},
				{"state", SERVICE_RUNNING},
				{"timeout", 30000},
			})},
		}));

	m_fInitialized = true;
	m_fWasStarted = true;

	// Connect to fltport should be before update selfprotection
	startThreads();

	// The driver's eventFlags always come from the configuration (edrsvc.cfg),
	// training mode included. The configuration enables every raw event type:
	// masking FileCreate (7) / FileClose (9) in the driver dropped those events
	// before the enricher, policy or training recorder could see them, so a
	// dropped file raised no event at all. Volume is handled after the driver
	// (the enricher never scans inline on FileClose), not by a type mask here.
	sendConfig(m_vDefaultDriverConfig);

	// update selfprotection rules
	if (!m_vSelfProtectConfig.isNull())
	{
		TRACE_BEGIN;
		// updateProcessRules
		Variant vProcessRulesSets = m_vSelfProtectConfig.get("processRules", Sequence());
		if (vProcessRulesSets.isDictionaryLike())
			vProcessRulesSets = Sequence({ vProcessRulesSets });
		for (auto vProcessRules : vProcessRulesSets)
			updateProcessRules(vProcessRules);

		// updateFileRules
		Variant vFileRules = m_vSelfProtectConfig.get("fileRules", nullptr);
		if(!vFileRules.isNull())
			updateFileRules(vFileRules);

		// updateRegRules
		Variant vRegRules = m_vSelfProtectConfig.get("regRules", nullptr);
		if (!vRegRules.isNull())
			updateRegRules(vRegRules);

		// updateUserModeHooks from JSON
		Variant vHookRules = m_vSelfProtectConfig.get("userModeHooks", m_vSelfProtectConfig.get("hookRules", nullptr));
		if (!vHookRules.isNull())
			updateUserModeHooks(vHookRules);

		// curProcessInfo
		Variant vCurProcessInfo = m_vSelfProtectConfig.get("curProcessInfo", nullptr);
		if (!vCurProcessInfo.isNull())
		{
			vCurProcessInfo = vCurProcessInfo.clone();
			vCurProcessInfo.put("pid", m_nSelfPid);
			setProcessInfo(vCurProcessInfo);
		}

		TRACE_END("Can't set self protection rules.");
	}

	sendStartMonitoring();

	LOGLVL(Detailed, "SysMon controller is started");
	return true;
	TRACE_END("Fail to start SysMon controller");
}

//
//
//
void SystemMonitorController::stop()
{
	stopInt();
}

//
//
//
bool SystemMonitorController::stopInt()
{
	TRACE_BEGIN
	LOGLVL(Detailed, "SysMon controller is being stopped");

	std::scoped_lock _lock(m_mtxStartStop);
	if (!m_fInitialized)
	{
		LOGLVL(Detailed, "SysMon controller already stopped");
		return false;
	}

	sendStopMonitoring();
	stopThreads();
	m_fInitialized = false;

	LOGLVL(Detailed, "SysMon controller is stopped");
	return true;
	TRACE_END("Fail to stop SysMon controller");
}

//
//
//
void SystemMonitorController::shutdown()
{
	TRACE_BEGIN
	LOGLVL(Detailed, "SysMon controller is being shutdowned");

	// Stop driver
	try
	{
		do 
		{
			if (!m_fStopDriverOnShutdown)
				break;
			if (!m_fWasStarted)
				break;

			bool fExist = execCommand(createObject(CLSID_WinServiceController), "isExist", 
				Dictionary({ { "name", c_sDrvSrvName } }));
			if (!fExist) 
				break;

			// Check the service is run
			Variant vServiceStatus = execCommand(createObject(CLSID_WinServiceController), "queryStatus",
				Dictionary({ { "name", c_sDrvSrvName } }));
			if (vServiceStatus["state"] != 4 /*SERVICE_RUNNING*/)
				break;

			CMD_TRY
			{
				sendConfig(Dictionary({ {"disableSelfProtection", true} }));
			}
			CMD_PREPARE_CATCH
			catch (error::Exception& e)
			{
				e.log(SL, "Can't stop driver protection");
			}

			// Close Handle to driver
			m_pIoctl.reset();

			(void)execCommand(createObject(CLSID_WinServiceController), "stop",
				Dictionary({ { "name", c_sDrvSrvName } }));
		} while (false);
	}
	catch (error::win::WinApiError& e)
	{
		auto errorCode = e.getWinErrorCode();
		// EDR-2040. Skip error ERROR_SHUTDOWN_IN_PROGRESS
		if (errorCode != ERROR_SHUTDOWN_IN_PROGRESS)
			throw;
	}

	LOGLVL(Detailed, "SysMon controller is shutdowned");
	TRACE_END("Fail to shutdown System Monitor");
}

//
//
//
void SystemMonitorController::startThreads()
{
	Handler handler = [this](HandlerContext& ctxt)
	{
		return this->parseEvent(ctxt.pInData, ctxt.nInDataSize);
	};

	// Ensure the standalone hypervisor driver (RedDbg on AMD, HyperDbg on
	// Intel) is staged and started before the filter port is connected:
	// edrdrv binds its hypervisor bridge on that connection.
	ensureHypervisorDriver();

	m_hFltPortReceiver.Start(handler);

	m_fStopSanctumPipe = false;
	m_sanctumPipeThread = std::thread(&SystemMonitorController::sanctumPipeServerLoop, this);

	// Ensure MBRFilter driver is staged, registered, and active
	ensureMbrFilterDriver();

	m_fStopMbrFilterPipe = false;
	m_mbrFilterPipeThread = std::thread(&SystemMonitorController::mbrFilterPipeServerLoop, this);

	m_fStopHipsDecisionPipe = false;
	m_hipsDecisionPipeThread = std::thread(&SystemMonitorController::hipsDecisionPipeServerLoop, this);
}

//
//
//
void SystemMonitorController::stopThreads()
{	
	m_hFltPortReceiver.Stop();
	m_pIoctl.reset();

	m_fStopSanctumPipe = true;
	// Wake up the pipe so it can exit
	auto hWake = ::CreateFileW(L"\\\\.\\pipe\\SanctumTelemetry", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hWake != INVALID_HANDLE_VALUE) {
		::CloseHandle(hWake);
	}
	if (m_sanctumPipeThread.joinable())
		m_sanctumPipeThread.join();

	m_fStopMbrFilterPipe = true;
	auto hMbrWake = ::CreateFileW(L"\\\\.\\pipe\\Global\\mbr_filter_alerts", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hMbrWake != INVALID_HANDLE_VALUE) {
		::CloseHandle(hMbrWake);
	}
	if (m_mbrFilterPipeThread.joinable())
		m_mbrFilterPipeThread.join();

	m_fStopHipsDecisionPipe = true;
	auto hHipsWake = ::CreateFileW(L"\\\\.\\pipe\\HydraHipDecision", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hHipsWake != INVALID_HANDLE_VALUE) {
		::CloseHandle(hHipsWake);
	}
	if (m_hipsDecisionPipeThread.joinable())
		m_hipsDecisionPipeThread.join();
}

namespace sanctum_bridge {
void SubmitSanctumTelemetry(
	const std::string& sEventType,
	const std::string& sExePath,
	const std::string& sDetails,
	const std::string& sJson);
void SendGuiPipeLine(const std::string& sLine);
void EnsureProcessDict(Variant& vEvent, uint32_t nPid, const std::string& sProcPath);
void ForwardToReceiverSafe(const ObjPtr<IDataReceiver>& pReceiver, const Variant& vEvent);
} // namespace sanctum_bridge

void SystemMonitorController::mbrFilterPipeServerLoop()
{
	LOGINF("[MBR] Starting MBRFilter alert pipe listener on \\\\.\\pipe\\Global\\mbr_filter_alerts");
	const LPCWSTR pipeName = L"\\\\.\\pipe\\Global\\mbr_filter_alerts";

	while (!m_fStopMbrFilterPipe)
	{
		HANDLE hPipe = ::CreateNamedPipeW(
			pipeName,
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			262144, 262144,
			0, NULL
		);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			::Sleep(1000);
			continue;
		}

		BOOL bConnected = ::ConnectNamedPipe(hPipe, NULL) ? TRUE : (::GetLastError() == ERROR_PIPE_CONNECTED);
		if (bConnected && !m_fStopMbrFilterPipe)
		{
			std::vector<wchar_t> buffer(65536, 0);
			DWORD dwRead = 0;
			if (::ReadFile(hPipe, buffer.data(), (DWORD)(buffer.size() * sizeof(wchar_t)), &dwRead, NULL) && dwRead > 0)
			{
				std::wstring alertMsg(buffer.data(), dwRead / sizeof(wchar_t));
				std::string sAlertUtf8 = string::convertWCharToUtf8(alertMsg);
				while (!sAlertUtf8.empty() &&
					(sAlertUtf8.back() == '\0' || sAlertUtf8.back() == '\r' || sAlertUtf8.back() == '\n' ||
					 sAlertUtf8.back() == ' ' || sAlertUtf8.back() == '\t'))
				{
					sAlertUtf8.pop_back();
				}

				if (!sAlertUtf8.empty())
				{
					LOGLVL(Critical, "[MBR ALERT] Sector 0 write attempt: " << sAlertUtf8);

					// Parse "DISK:<num>|<process_path>" emitted by MBRFilter.sys
					std::string sDiskNum = "0";
					std::string sProcPath;
					auto barPos = sAlertUtf8.find('|');
					if (barPos != std::string::npos)
					{
						std::string sLeft = sAlertUtf8.substr(0, barPos);
						if (sLeft.rfind("DISK:", 0) == 0 && sLeft.size() > 5)
							sDiskNum = sLeft.substr(5);
						sProcPath = sAlertUtf8.substr(barPos + 1);
						while (!sProcPath.empty() && (sProcPath.front() == ' ' || sProcPath.front() == '\t'))
							sProcPath.erase(sProcPath.begin());
					}
					else if (sAlertUtf8.rfind("DISK:", 0) == 0 && sAlertUtf8.size() > 5)
					{
						sDiskNum = sAlertUtf8.substr(5);
					}

					uint64_t nDiskNum = 0;
					try
					{
						nDiskNum = std::stoull(sDiskNum);
					}
					catch (...) { nDiskNum = 0; }

					const std::string sDiskPath = "\\\\.\\PhysicalDrive" + std::to_string(nDiskNum);
					const std::string sEffectiveProc = sProcPath.empty()
						? ("PhysicalDrive" + std::to_string(nDiskNum))
						: sProcPath;

					Variant vEvent = Dictionary();
					vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_DISK_RAW_WRITE_ACCESS));
					vEvent.put("type", "MBR_SECTOR0_RAW_WRITE");
					vEvent.put("source", "mbrfilter");
					vEvent.put("tickTime", static_cast<uint64_t>(::GetTickCount64()));
					vEvent.put("path", sDiskPath);
					vEvent.put("disk", sDiskPath);
					vEvent.put("diskNumber", nDiskNum);
					vEvent.put("sector", static_cast<uint64_t>(0));
					vEvent.put("mbrAlert", sAlertUtf8);
					sanctum_bridge::EnsureProcessDict(vEvent, 0, sEffectiveProc);

					try
					{
						const std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
						const std::string sDetails = "MBR Sector 0 raw write blocked by MBRFilter: " + sAlertUtf8;
						sanctum_bridge::SubmitSanctumTelemetry("MBR_SECTOR0_RAW_WRITE", sEffectiveProc, sDetails, sJson);
					}
					catch (...) {}

					vEvent.put("telemetryAlreadySubmitted", true);
					sanctum_bridge::ForwardToReceiverSafe(m_pReceiver, vEvent);

					sanctum_bridge::SendGuiPipeLine(
						"THREAT_ALERT:MBRFilter_Sector0Write|" + sEffectiveProc + " (PhysicalDrive" + std::to_string(nDiskNum) + ")");
					sanctum_bridge::SendGuiPipeLine(
						"BEHAVIOR_EVENT:" + sEffectiveProc + "|MBR_SECTOR0_RAW_WRITE [Alert: " + sAlertUtf8 + "]");
				}
			}
		}

		::DisconnectNamedPipe(hPipe);
		::CloseHandle(hPipe);
	}
	LOGINF("[MBR] MBRFilter alert pipe listener stopped");
}

void SystemMonitorController::killProcessViaDriver(uint32_t pid)
{
	if (pid == 0 || pid == 4)
		return;

	// edrdrv.sys COM_MESSAGE protocol for MESSAGE_KILL_ONLY_GID (6)
	// Byte layout: ULONG type (6), ULONG pid (0), ULONGLONG gid (pid | 0x8000000000000000)
	#pragma pack(push, 1)
	struct ComKillMessage {
		uint32_t type;
		uint32_t pid;
		uint64_t gid;
		wchar_t path[520];
		wchar_t quarantine_path[520];
	} msg = {};
	#pragma pack(pop)

	msg.type = 6; // MESSAGE_KILL_ONLY_GID
	msg.pid = 0;
	msg.gid = (static_cast<uint64_t>(pid)) | 0x8000000000000000ULL;

	LOGLVL(Critical, "[HIPS KILL] Executing Ring-0 kernel driver kill for PID: " << pid);

	HANDLE hDevice = ::CreateFileW(
		L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr
	);

	if (hDevice != INVALID_HANDLE_VALUE)
	{
		uint32_t outputRes = 0;
		DWORD bytesReturned = 0;
		// IOCTL_OWLY_COMPAT_MESSAGE = 0x222484
		::DeviceIoControl(hDevice, 0x222484, &msg, sizeof(msg), &outputRes, sizeof(outputRes), &bytesReturned, nullptr);
		::CloseHandle(hDevice);
	}
}

void SystemMonitorController::hipsDecisionPipeServerLoop()
{
	LOGINF("[HIPS] Starting HIPS Decision pipe listener on \\\\.\\pipe\\HydraHipDecision");
	const LPCWSTR pipeName = L"\\\\.\\pipe\\HydraHipDecision";

	while (!m_fStopHipsDecisionPipe)
	{
		SECURITY_DESCRIPTOR sd;
		::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
		::SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.lpSecurityDescriptor = &sd;
		sa.bInheritHandle = FALSE;

		HANDLE hPipe = ::CreateNamedPipeW(
			pipeName,
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			65536, 65536,
			0, &sa
		);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			::Sleep(500);
			continue;
		}

		BOOL bConnected = ::ConnectNamedPipe(hPipe, NULL) ? TRUE : (::GetLastError() == ERROR_PIPE_CONNECTED);
		if (bConnected && !m_fStopHipsDecisionPipe)
		{
			std::vector<char> buffer(4096, 0);
			DWORD dwRead = 0;
			if (::ReadFile(hPipe, buffer.data(), (DWORD)(buffer.size() - 1), &dwRead, NULL) && dwRead > 0)
			{
				std::string sCmd(buffer.data(), dwRead);
				// Format: HIPS_KILL:<PID>|<DECISION>|<EXE_PATH>
				// Example: HIPS_KILL:1234|block|C:\malware.exe
				// Example: HIPS_KILL:1234|allow|C:\app.exe
				// Example: HIPS_KILL:1234|restricted|C:\app.exe
				// Or: ZERO_TRUST:1 / ZERO_TRUST:0
				if (sCmd.rfind("ZERO_TRUST:", 0) == 0)
				{
					bool enable = (sCmd.find("1") != std::string::npos || sCmd.find("true") != std::string::npos);
					cmd::zerotrust::ZeroTrustManager::instance().setEnabled(enable);
					LOGINF("[HIPS] Zero Trust mode toggled via pipe: " << (enable ? "ENABLED" : "DISABLED"));
				}
				else if (sCmd.rfind("HIPS_KILL:", 0) == 0)
				{
					std::string sPayload = sCmd.substr(10);
					size_t sep1 = sPayload.find('|');
					if (sep1 != std::string::npos)
					{
						std::string sPidStr = sPayload.substr(0, sep1);
						uint32_t targetPid = static_cast<uint32_t>(std::strtoul(sPidStr.c_str(), nullptr, 10));
						std::string sRest = sPayload.substr(sep1 + 1);
						size_t sep2 = sRest.find('|');
						std::string sDecision = (sep2 == std::string::npos) ? sRest : sRest.substr(0, sep2);
						std::string sExePath = (sep2 == std::string::npos) ? "" : sRest.substr(sep2 + 1);

						if (targetPid != 0)
						{
							if (sDecision == "allow" || sDecision == "allow_always")
							{
								if (!sExePath.empty())
									cmd::zerotrust::ZeroTrustManager::instance().addSessionWhitelist(sExePath);
								cmd::zerotrust::ResumeProcessByPid(targetPid);
								LOGINF("[HIPS] Resumed process " << targetPid << " (" << sExePath << ") and whitelisted for session");
							}
							else if (sDecision == "allow_once")
							{
								cmd::zerotrust::ResumeProcessByPid(targetPid);
								LOGINF("[HIPS] Resumed process " << targetPid << " for single execution");
							}
							else if (sDecision == "restricted")
							{
								cmd::zerotrust::ZeroTrustManager::instance().addRestrictedPid(targetPid);
								cmd::zerotrust::ResumeProcessByPid(targetPid);
								LOGINF("[HIPS] Resumed process " << targetPid << " under VirusKov Restricted Mode");
							}
							else
							{
								// HIPS verdict gate: a persistent user "allow" in
								// hips_rules.json vetoes the kill (firewall-independent).
								if (!sExePath.empty() && hipsUserAllows(sExePath))
								{
									LOGINF("[HIPS] Kill vetoed by persistent user allow verdict for: " << sExePath);
									cmd::zerotrust::ResumeProcessByPid(targetPid);
								}
								else
								{
									killProcessViaDriver(targetPid);
								}
							}
						}
					}
				}
			}
		}

		::DisconnectNamedPipe(hPipe);
		::CloseHandle(hPipe);
	}
	LOGINF("[HIPS] HIPS Decision pipe listener stopped");
}

namespace sanctum_bridge {

typedef void (*SanctumTelemetrySubmitFn)(
	const uint8_t*, uint32_t,
	const uint8_t*, uint32_t,
	const uint8_t*, uint32_t,
	const uint8_t*, uint32_t);

SanctumTelemetrySubmitFn GetSanctumTelemetrySubmitFn()
{
	static std::atomic<SanctumTelemetrySubmitFn> s_fnTelemetry{ nullptr };
	if (auto cached = s_fnTelemetry.load(std::memory_order_acquire))
		return cached;
	HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
	if (!hDll)
		hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
	if (hDll)
	{
		auto fn = reinterpret_cast<SanctumTelemetrySubmitFn>(
			::GetProcAddress(hDll, "owlyshield_telemetry_submit_event"));
		if (fn)
		{
			s_fnTelemetry.store(fn, std::memory_order_release);
			return fn;
		}
	}
	return nullptr;
}

void SubmitSanctumTelemetry(
	const std::string& sEventType,
	const std::string& sExePath,
	const std::string& sDetails,
	const std::string& sJson)
{
	if (auto fn = GetSanctumTelemetrySubmitFn())
	{
		fn(
			reinterpret_cast<const uint8_t*>(sEventType.data()), static_cast<uint32_t>(sEventType.size()),
			reinterpret_cast<const uint8_t*>(sExePath.data()), static_cast<uint32_t>(sExePath.size()),
			reinterpret_cast<const uint8_t*>(sDetails.data()), static_cast<uint32_t>(sDetails.size()),
			reinterpret_cast<const uint8_t*>(sJson.data()), static_cast<uint32_t>(sJson.size()));
	}
}

std::string ResolvePidImagePathUtf8(uint32_t nPid)
{
	if (nPid == 0)
		return "";
	if (nPid == 4)
		return "System";
	HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, nPid);
	if (!hProc)
		return "";
	wchar_t wsPath[1024] = {};
	DWORD cch = static_cast<DWORD>(sizeof(wsPath) / sizeof(wsPath[0]));
	const BOOL ok = ::QueryFullProcessImageNameW(hProc, 0, wsPath, &cch);
	::CloseHandle(hProc);
	if (!ok || cch == 0)
		return "";
	const int nUtf8 = ::WideCharToMultiByte(CP_UTF8, 0, wsPath, static_cast<int>(cch), nullptr, 0, nullptr, nullptr);
	if (nUtf8 <= 0)
		return "";
	std::string out(static_cast<size_t>(nUtf8), '\0');
	::WideCharToMultiByte(CP_UTF8, 0, wsPath, static_cast<int>(cch), &out[0], nUtf8, nullptr, nullptr);
	return out;
}

void SendGuiPipeLine(const std::string& sLine)
{
	std::string sClean;
	sClean.reserve(sLine.size() + 1);
	for (char c : sLine)
	{
		if (c == '\r' || c == '\n')
			sClean.push_back(' ');
		else
			sClean.push_back(c);
	}
	sClean.push_back('\n');

	HANDLE hGuiPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hGuiPipe != INVALID_HANDLE_VALUE)
	{
		DWORD written = 0;
		::WriteFile(hGuiPipe, sClean.data(), static_cast<DWORD>(sClean.size()), &written, NULL);
		::CloseHandle(hGuiPipe);
	}
}

uint64_t ExtractUint64Safe(const Variant& v, const char* szKey, uint64_t nDefault = 0)
{
	if (v.getType() != variant::ValueType::Dictionary || !v.has(szKey))
		return nDefault;
	try
	{
		const auto val = v.get(szKey);
		if (val.getType() == variant::ValueType::Integer)
			return static_cast<uint64_t>(val);
	}
	catch (...) {}
	return nDefault;
}

std::string ExtractStringSafe(const Variant& v, const char* szKey)
{
	if (v.getType() != variant::ValueType::Dictionary || !v.has(szKey))
		return "";
	try
	{
		const auto val = v.get(szKey);
		if (val.getType() == variant::ValueType::String)
			return std::string(val);
	}
	catch (...) {}
	return "";
}

bool ExtractBoolSafe(const Variant& v, const char* szKey, bool fDefault = false)
{
	if (v.getType() != variant::ValueType::Dictionary || !v.has(szKey))
		return fDefault;
	try
	{
		const auto val = v.get(szKey);
		if (val.getType() == variant::ValueType::Boolean)
			return static_cast<bool>(val);
		if (val.getType() == variant::ValueType::Integer)
			return static_cast<uint64_t>(val) != 0;
	}
	catch (...) {}
	return fDefault;
}

std::string ExtractPathSafe(const Variant& v, const char* szDotPath)
{
	try
	{
		if (auto optP = variant::getByPathSafe(v, szDotPath))
		{
			if (optP.value().getType() == variant::ValueType::String)
				return std::string(optP.value());
		}
	}
	catch (...) {}
	return "";
}

void EnsureProcessDict(Variant& vEvent, uint32_t nPid, const std::string& sProcPath)
{
	Dictionary vImg;
	if (!sProcPath.empty())
	{
		vImg.put("rawPath", sProcPath);
		vImg.put("abstractPath", sProcPath);
		vImg.put("path", sProcPath);
	}
	Dictionary vProc;
	vProc.put("pid", nPid);
	vProc.put("imageFile", vImg);
	vEvent.put("process", vProc);
}

void ForwardToReceiverSafe(const ObjPtr<IDataReceiver>& pReceiver, const Variant& vEvent)
{
	if (!pReceiver)
		return;
	try
	{
		pReceiver->put(vEvent);
	}
	catch (const error::Exception& ex)
	{
		LOGLVL(Detailed, "Sanctum event skipped by OpenEDR enricher: " << ex.what());
	}
	catch (...) {}
}

void ProcessSanctumJsonLine(const std::string& sLine, const ObjPtr<IDataReceiver>& pReceiver)
{
	Variant vEvent;
	try
	{
		vEvent = variant::deserializeFromJson(sLine);
	}
	catch (...)
	{
		LOGWRN("Failed to parse Sanctum event JSON");
		return;
	}

	if (vEvent.getType() != variant::ValueType::Dictionary)
		return;

	uint32_t nPid = static_cast<uint32_t>(ExtractUint64Safe(vEvent, "pid", 0));
	if (nPid == 0 && vEvent.has("process"))
		nPid = static_cast<uint32_t>(ExtractUint64Safe(vEvent.get("process"), "pid", 0));

	std::string sProcPath = ExtractPathSafe(vEvent, "process.imageFile.abstractPath");
	if (sProcPath.empty()) sProcPath = ExtractPathSafe(vEvent, "process.imageFile.rawPath");
	if (sProcPath.empty()) sProcPath = ExtractPathSafe(vEvent, "process.imageFile.path");
	if (sProcPath.empty()) sProcPath = ExtractPathSafe(vEvent, "process.path");
	if (sProcPath.empty()) sProcPath = ExtractPathSafe(vEvent, "data.EtwThreatIntelligence.process_image");
	if (sProcPath.empty() && nPid > 0)
		sProcPath = ResolvePidImagePathUtf8(nPid);

	const uint64_t nTickTime = ExtractUint64Safe(vEvent, "tickTime", static_cast<uint64_t>(::GetTickCount64()));
	const std::string sType = ExtractStringSafe(vEvent, "type");
	const std::string sSubType = ExtractStringSafe(vEvent, "subType");
	const std::string sSanctumType = ExtractStringSafe(vEvent, "sanctumEventType");

	// 1. Driver telemetry (DRIVER_LOAD / HVCI_BLOCK / DRIVER_SERVICE_SET)
	if (vEvent.has("driver") || sType == "LLE_DRIVER_LOAD" ||
		sSubType == "DRIVER_LOAD" || sSubType == "HVCI_BLOCK" || sSubType == "DRIVER_SERVICE_SET")
	{
		std::string sDriverImg = ExtractPathSafe(vEvent, "driver.image");
		if (sDriverImg.empty()) sDriverImg = ExtractPathSafe(vEvent, "file.rawPath");
		const std::string sAction = ExtractPathSafe(vEvent, "driver.action");
		const std::string sEffectiveProc = sProcPath.empty() ? sDriverImg : sProcPath;

		EnsureProcessDict(vEvent, nPid, sEffectiveProc);
		if (!vEvent.has("file") && !sDriverImg.empty())
		{
			Dictionary vFile;
			vFile.put("rawPath", sDriverImg);
			vFile.put("abstractPath", sDriverImg);
			vEvent.put("file", vFile);
		}
		vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_DRIVER_LOAD));
		vEvent.put("type", "LLE_DRIVER_LOAD");
		vEvent.put("tickTime", nTickTime);

		if (sSubType == "HVCI_BLOCK" || sAction == "BLOCK")
		{
			vEvent.put("sanctumEventType", "SANCTUM_HVCI_BLOCK");
			const std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
			const std::string sDetails = "Sanctum HVCI/blocklist blocked driver: " + sDriverImg;
			SubmitSanctumTelemetry("SANCTUM_HVCI_BLOCK", sEffectiveProc, sDetails, sJson);
			vEvent.put("sanctumTelemetrySubmitted", true);
			SendGuiPipeLine("THREAT_ALERT:Sanctum_HVCI_Block|" + sDriverImg + " (" + sEffectiveProc + ")");
			SendGuiPipeLine("BEHAVIOR_EVENT:" + sEffectiveProc + "|SANCTUM_HVCI_BLOCK [Sanctum/Rust]");
		}
		else if (!sEffectiveProc.empty())
		{
			SendGuiPipeLine("BEHAVIOR_EVENT:" + sEffectiveProc + "|LLE_DRIVER_LOAD [Sanctum/Rust]");
		}

		ForwardToReceiverSafe(pReceiver, vEvent);
		return;
	}

	// 2. Ghost Hunting (direct / indirect syscall abuse)
	if ((vEvent.has("syscall_name") && vEvent.has("hex_payload")) || sSanctumType == "SANCTUM_GHOST_HUNT")
	{
		const std::string sSyscall = ExtractStringSafe(vEvent, "syscall_name");
		EnsureProcessDict(vEvent, nPid, sProcPath);
		vEvent.put("sanctumEventType", "SANCTUM_GHOST_HUNT");
		vEvent.put("source", "sanctum_ghost_hunt");
		const std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
		const std::string sDetails = "Direct syscall detected: " + sSyscall;
		SubmitSanctumTelemetry("SANCTUM_GHOST_HUNT", sProcPath, sDetails, sJson);

		vEvent.put("sanctumTelemetrySubmitted", true);
		vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_INJECTION_ACTIVITY));
		vEvent.put("tickTime", nTickTime);
		ForwardToReceiverSafe(pReceiver, vEvent);

		SendGuiPipeLine("THREAT_ALERT:Sanctum_GhostHunt|" + sProcPath + " (" + sSyscall + ")");
		if (!sProcPath.empty())
			SendGuiPipeLine("BEHAVIOR_EVENT:" + sProcPath + "|SANCTUM_GHOST_HUNT [Sanctum/Rust]");
		return;
	}

	// 3. AMSI Bypass Attempt
	if ((vEvent.has("function_name") && vEvent.has("offending_address")) || sSanctumType == "SANCTUM_AMSI_BYPASS")
	{
		const std::string sFunc = ExtractStringSafe(vEvent, "function_name");
		EnsureProcessDict(vEvent, nPid, sProcPath);
		vEvent.put("sanctumEventType", "SANCTUM_AMSI_BYPASS");
		vEvent.put("source", "sanctum_amsi");
		const std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
		const std::string sDetails = "AMSI bypass attempt: " + sFunc;
		SubmitSanctumTelemetry("SANCTUM_AMSI_BYPASS", sProcPath, sDetails, sJson);

		vEvent.put("sanctumTelemetrySubmitted", true);
		vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_INJECTION_ACTIVITY));
		vEvent.put("tickTime", nTickTime);
		ForwardToReceiverSafe(pReceiver, vEvent);

		SendGuiPipeLine("THREAT_ALERT:Sanctum_AmsiBypass|" + sProcPath + " (" + sFunc + ")");
		if (!sProcPath.empty())
			SendGuiPipeLine("BEHAVIOR_EVENT:" + sProcPath + "|SANCTUM_AMSI_BYPASS [Sanctum/Rust]");
		return;
	}

	// 4. Syscall struct (ETW:TI & Injected DLL hooks)
	if (vEvent.has("data") && vEvent.has("source"))
	{
		EnsureProcessDict(vEvent, nPid, sProcPath);
		const Variant vData = vEvent.get("data");

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("EtwThreatIntelligence"))
		{
			const Variant vTi = vData.get("EtwThreatIntelligence");
			const std::string sFunc = ExtractStringSafe(vTi, "function");
			const std::string sEvtName = ExtractStringSafe(vTi, "event_name");
			const bool fRemote = ExtractBoolSafe(vTi, "remote", false);
			const bool fSuspicious = ExtractBoolSafe(vTi, "suspicious", false);
			const uint32_t nTargetPid = static_cast<uint32_t>(ExtractUint64Safe(vTi, "target_pid", 0));

			vEvent.put("sanctumEventType", "SANCTUM_ETW_TI");
			vEvent.put("function", sFunc);
			vEvent.put("event_name", sEvtName);
			vEvent.put("remote", fRemote);
			vEvent.put("suspicious", fSuspicious);
			if (nTargetPid != 0)
			{
				vEvent.put("target_pid", nTargetPid);
				Dictionary vTarget;
				vTarget.put("pid", nTargetPid);
				vEvent.put("target", vTarget);
			}

			const std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
			const std::string sDetails = sFunc + " (" + sEvtName + ")";
			SubmitSanctumTelemetry("SANCTUM_ETW_TI", sProcPath, sDetails, sJson);

			if (fSuspicious || fRemote)
			{
				vEvent.put("sanctumTelemetrySubmitted", true);
				vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_INJECTION_ACTIVITY));
				vEvent.put("tickTime", nTickTime);
				ForwardToReceiverSafe(pReceiver, vEvent);
				if (!sProcPath.empty())
					SendGuiPipeLine("BEHAVIOR_EVENT:" + sProcPath + "|SANCTUM_ETW_TI [Sanctum/Rust]");
			}
			return;
		}

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("NtCreateThreadEx"))
		{
			const Variant vInner = vData.get("NtCreateThreadEx");
			const uint32_t nTargetPid = static_cast<uint32_t>(ExtractUint64Safe(vInner, "target_pid", 0));
			vEvent.put("sanctumEventType", "SANCTUM_SYSCALL_CREATE_THREAD");
			SubmitSanctumTelemetry("SANCTUM_SYSCALL_CREATE_THREAD", sProcPath, "NtCreateThreadEx",
				variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
			if (nTargetPid != 0 && nTargetPid != nPid)
			{
				Dictionary vTarget;
				vTarget.put("pid", nTargetPid);
				vEvent.put("target", vTarget);
				vEvent.put("sanctumTelemetrySubmitted", true);
				vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_REMOTE_THREAD_CREATE));
				vEvent.put("tickTime", nTickTime);
				ForwardToReceiverSafe(pReceiver, vEvent);
			}
			return;
		}

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("NtWriteVirtualMemory"))
		{
			const Variant vInner = vData.get("NtWriteVirtualMemory");
			const uint32_t nTargetPid = static_cast<uint32_t>(ExtractUint64Safe(vInner, "target_pid", 0));
			vEvent.put("sanctumEventType", "SANCTUM_SYSCALL_WRITE_VM");
			SubmitSanctumTelemetry("SANCTUM_SYSCALL_WRITE_VM", sProcPath, "NtWriteVirtualMemory",
				variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
			if (nTargetPid != 0 && nTargetPid != nPid)
			{
				Dictionary vTarget;
				vTarget.put("pid", nTargetPid);
				vEvent.put("target", vTarget);
				vEvent.put("sanctumTelemetrySubmitted", true);
				vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_PROCESS_MEMORY_WRITE));
				vEvent.put("tickTime", nTickTime);
				ForwardToReceiverSafe(pReceiver, vEvent);
			}
			return;
		}

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("NtOpenProcess"))
		{
			const Variant vInner = vData.get("NtOpenProcess");
			const uint32_t nTargetPid = static_cast<uint32_t>(ExtractUint64Safe(vInner, "target_pid", 0));
			const uint32_t nMask = static_cast<uint32_t>(ExtractUint64Safe(vInner, "desired_mask", 0));
			vEvent.put("sanctumEventType", "SANCTUM_SYSCALL_OPEN_PROCESS");
			SubmitSanctumTelemetry("SANCTUM_SYSCALL_OPEN_PROCESS", sProcPath, "NtOpenProcess",
				variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
			if (nTargetPid != 0 && nTargetPid != nPid)
			{
				Dictionary vTarget;
				vTarget.put("pid", nTargetPid);
				vEvent.put("target", vTarget);
				vEvent.put("accessMask", nMask);
				vEvent.put("sanctumTelemetrySubmitted", true);
				vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_PROCESS_OPEN));
				vEvent.put("tickTime", nTickTime);
				ForwardToReceiverSafe(pReceiver, vEvent);
			}
			return;
		}

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("NtAllocateVirtualMemory"))
		{
			const Variant vInner = vData.get("NtAllocateVirtualMemory");
			const uint32_t nDestPid = static_cast<uint32_t>(ExtractUint64Safe(vInner, "dest_pid", 0));
			const uint32_t nProtect = static_cast<uint32_t>(ExtractUint64Safe(vInner, "protect_flags", 0));
			vEvent.put("sanctumEventType", "SANCTUM_SYSCALL_ALLOC_VM");
			SubmitSanctumTelemetry("SANCTUM_SYSCALL_ALLOC_VM", sProcPath, "NtAllocateVirtualMemory",
				variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
			if ((nDestPid != 0 && nDestPid != nPid) || (nProtect & 0x40u) != 0)
			{
				if (nDestPid != 0)
				{
					Dictionary vTarget;
					vTarget.put("pid", nDestPid);
					vEvent.put("target", vTarget);
				}
				vEvent.put("sanctumTelemetrySubmitted", true);
				vEvent.put("baseType", static_cast<uint64_t>(Event::LLE_INJECTION_ACTIVITY));
				vEvent.put("tickTime", nTickTime);
				ForwardToReceiverSafe(pReceiver, vEvent);
			}
			return;
		}

		if (vData.getType() == variant::ValueType::Dictionary && vData.has("NetworkActivity"))
		{
			vEvent.put("sanctumEventType", "SANCTUM_NETWORK_ACTIVITY");
			SubmitSanctumTelemetry("SANCTUM_NETWORK_ACTIVITY", sProcPath, "Sanctum ETW/WinINet network telemetry",
				variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
			return;
		}

		vEvent.put("sanctumEventType", "SANCTUM_SYSCALL");
		SubmitSanctumTelemetry("SANCTUM_SYSCALL", sProcPath, "",
			variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));
		return;
	}

	// 5. Fallback / Explicit SANCTUM_* / Sanctum PPL ETW event
	const std::string sFallbackType = !sSanctumType.empty()
		? sSanctumType
		: (!sType.empty() ? sType : "SANCTUM_TELEMETRY");
	const std::string sDetails = ExtractStringSafe(vEvent, "details");
	EnsureProcessDict(vEvent, nPid, sProcPath);
	SubmitSanctumTelemetry(sFallbackType, sProcPath, sDetails,
		variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine));

	if (sFallbackType == "SANCTUM_ETW_BLINDING")
	{
		SendGuiPipeLine("THREAT_ALERT:Sanctum_EtwBlinding|" + (sDetails.empty() ? sFallbackType : sDetails));
	}
	if (!sProcPath.empty() && sFallbackType != "DNS_QUERY")
		SendGuiPipeLine("BEHAVIOR_EVENT:" + sProcPath + "|" + sFallbackType + " [Sanctum/Rust]");

	if (vEvent.has("baseType"))
	{
		const uint64_t nBase = ExtractUint64Safe(vEvent, "baseType", 0);
		if (nBase > 0 && nBase <= 0x3Bu)
		{
			vEvent.put("sanctumTelemetrySubmitted", true);
			vEvent.put("tickTime", nTickTime);
			ForwardToReceiverSafe(pReceiver, vEvent);
		}
	}
}

} // namespace sanctum_bridge

void SystemMonitorController::sanctumPipeServerLoop()
{
	while (!m_fStopSanctumPipe)
	{
		auto hPipe = ::CreateNamedPipeW(
			L"\\\\.\\pipe\\SanctumTelemetry",
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			0, 65536, 0, nullptr);

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(250));
			continue;
		}

		BOOL fConnected = ::ConnectNamedPipe(hPipe, nullptr) ? TRUE : (::GetLastError() == ERROR_PIPE_CONNECTED);
		if (!fConnected || m_fStopSanctumPipe)
		{
			::CloseHandle(hPipe);
			continue;
		}

		LOGLVL(Detailed, "Sanctum connected to \\\\.\\pipe\\SanctumTelemetry");

		std::string sCarry;
		char pBuffer[65536] = {};
		while (!m_fStopSanctumPipe)
		{
			DWORD nRead = 0;
			if (!::ReadFile(hPipe, pBuffer, sizeof(pBuffer), &nRead, nullptr) || nRead == 0)
				break;

			sCarry.append(pBuffer, pBuffer + nRead);
			for (;;)
			{
				auto nPos = sCarry.find('\n');
				if (nPos == std::string::npos)
					break;

				auto sLine = sCarry.substr(0, nPos);
				sCarry.erase(0, nPos + 1);

				if (!sLine.empty())
					sanctum_bridge::ProcessSanctumJsonLine(sLine, m_pReceiver);
			}
		}

		::DisconnectNamedPipe(hPipe);
		::CloseHandle(hPipe);
	}
}

//
//
//
std::map<edrdrv::SysmonEvent, Event> mEventMap = {
	{edrdrv::SysmonEvent::ProcessCreate, Event::LLE_PROCESS_CREATE},
	{edrdrv::SysmonEvent::ProcessDelete, Event::LLE_PROCESS_DELETE},
	{edrdrv::SysmonEvent::RegistryKeyNameChange, Event::LLE_REGISTRY_KEY_NAME_CHANGE},
	{edrdrv::SysmonEvent::RegistryKeyCreate, Event::LLE_REGISTRY_KEY_CREATE},
	{edrdrv::SysmonEvent::RegistryKeyDelete, Event::LLE_REGISTRY_KEY_DELETE},
	{edrdrv::SysmonEvent::RegistryValueSet, Event::LLE_REGISTRY_VALUE_SET},
	{edrdrv::SysmonEvent::RegistryValueDelete, Event::LLE_REGISTRY_VALUE_DELETE},
	{edrdrv::SysmonEvent::FileCreate, Event::LLE_FILE_CREATE},
	{edrdrv::SysmonEvent::FileDelete, Event::LLE_FILE_DELETE},
	{edrdrv::SysmonEvent::FileClose, Event::LLE_FILE_CLOSE},
	{edrdrv::SysmonEvent::FileDataChange, Event::LLE_FILE_DATA_CHANGE},
	{edrdrv::SysmonEvent::FileDataReadFull, Event::LLE_FILE_DATA_READ_FULL},
	{edrdrv::SysmonEvent::FileDataWriteFull, Event::LLE_FILE_DATA_WRITE_FULL},
	{edrdrv::SysmonEvent::ProcessOpen, Event::LLE_PROCESS_OPEN},
	{edrdrv::SysmonEvent::DeviceIoControl, Event::LLE_DEVICE_RAW_WRITE_ACCESS},
	{edrdrv::SysmonEvent::NamedPipeCreate, Event::LLE_NAMED_PIPE_CREATE},
	{edrdrv::SysmonEvent::SelfDefense, Event::LLE_PROCESS_OPEN},
	{edrdrv::SysmonEvent::FileMapRead, Event::LLE_FILE_MAP_READ},
	{edrdrv::SysmonEvent::FileMapWrite, Event::LLE_FILE_MAP_WRITE},
	{edrdrv::SysmonEvent::FileRename, Event::LLE_FILE_RENAME},
	{edrdrv::SysmonEvent::OwlyPreImageSaved, Event::LLE_FILE_PREIMAGE_SAVED},
	{edrdrv::SysmonEvent::ThreadOpen, Event::LLE_THREAD_OPEN},
	{edrdrv::SysmonEvent::DesktopOpen, Event::LLE_DESKTOP_OPEN},
	{edrdrv::SysmonEvent::ImageLoad, Event::LLE_IMAGE_LOAD},
	{edrdrv::SysmonEvent::DriverLoad, Event::LLE_DRIVER_LOAD},
	{edrdrv::SysmonEvent::RemoteThreadCreate, Event::LLE_REMOTE_THREAD_CREATE},
	{edrdrv::SysmonEvent::NamedPipeServerCreate, Event::LLE_NAMED_PIPE_SERVER_CREATE},
};

//
//
//
#ifdef ENABLE_EVENT_TIMINGS
bool SystemMonitorController::parseEvent(const Byte* pBuffer, const Size nBufferSize, std::pair<Size, Size>& nTimes)
#else
bool SystemMonitorController::parseEvent(const Byte* pBuffer, const Size nBufferSize)
#endif
{
	CMD_TRY
	{
#ifdef ENABLE_EVENT_TIMINGS
		using namespace std::chrono;
		auto t0 = steady_clock::now();
#endif
		Variant vEvent = variant::deserializeFromLbvs(pBuffer, nBufferSize, m_vEventSchema);
		edrdrv::SysmonEvent nRawEventId = vEvent["rawEventId"];
		LOGLVL(Trace, "Parse raw event <" << size_t(nRawEventId) <<
			"> from process <" << getByPath(vEvent, "process.pid", -1) << ">");

		// Dynamic hook ownership lives here (OpenEDR), not in owlyshield:
		// every new process gets MESSAGE_HOOK_PROCESS after the ptm.local.src
		// target list is registered once via MESSAGE_ADD_HOOK. Event ids are
		// 0x6000 + file order, mirroring the Rust id map so hook events keep
		// resolving to API names on both sides. Best-effort: failures never
		// break event parsing.
		try
		{
			if (nRawEventId == edrdrv::SysmonEvent::ProcessCreate)
			{
				int64_t nNewPid = getByPath(vEvent, "process.pid", int64_t(0));
				if (nNewPid > 0)
					hookmgr::applyHooksToProcess((uint32_t)nNewPid);
			}
		}
		catch (...) {}

		// Kernel-stack attribution at parse time (not at notify time) so
		// every downstream consumer — enricher, pattern engine
		// (ptm.local.src imatch on file.kernelStackSymbols), notifier, GUI —
		// sees the resolved module!export chain. Raw hex stays in
		// file.kernelStack for offline forensics. Best-effort: failures
		// leave the event untouched.
		try
		{
			if (auto optK = variant::getByPathSafe(vEvent, "file.kernelStack"))
			{
				const std::string sRaw = std::string(optK.value());
				if (!sRaw.empty() && sRaw != "<undefined>" && sRaw != "null")
				{
					uint32_t nStackPid = 0;
					if (auto optP = variant::getByPathSafe(vEvent, "process.pid"))
					{
						try { nStackPid = static_cast<uint32_t>(optP.value()); }
						catch (...) {}
					}
					const std::string sResolved =
						cmd::kstack::resolveStackForPid(sRaw, nStackPid, 6);
					if (!sResolved.empty())
						vEvent.put("kernelStackSymbols", sResolved);
				}
			}
		}
		catch (...) {}
#ifdef ENABLE_EVENT_TIMINGS
		auto t1 = steady_clock::now();
#endif

		// Add LLE type
		auto eEvent = mEventMap[nRawEventId];

		// DeviceIoControl is the LBVS carrier for both kernel hook events and
		// hypervisor events.  If owlyHv.* fields are present this is a hypervisor
		// event — promote baseType to LLE_DEVICE_IOCTL so EventEnricher routes it
		// correctly.  Hook events carry owlyHook.* fields instead.
		if (nRawEventId == edrdrv::SysmonEvent::DeviceIoControl)
		{
			// Build the owlyHook sub-dict from owlyHook.* LBVS fields
			if (vEvent.has("owlyHookEventType"))
			{
				Dictionary vHook;
				std::wstring sFuncName = vEvent.get("owlyHookFunctionName", L"");
				vHook.put("eventType",    vEvent.get("owlyHookEventType", 0));
				vHook.put("functionName", sFuncName);
				vHook.put("arg1",         vEvent.get("owlyHookArg1", uint64_t(0)));
				vHook.put("arg2",         vEvent.get("owlyHookArg2", uint64_t(0)));
				vHook.put("arg3",         vEvent.get("owlyHookArg3", uint64_t(0)));
				vHook.put("arg4",         vEvent.get("owlyHookArg4", uint64_t(0)));
				uint32_t nSourcePid = vEvent.get("owlyHookSourcePid", uint32_t(0));
				uint32_t nTargetPid = vEvent.get("owlyHookTargetPid", uint32_t(0));
				vHook.put("sourcePid",    nSourcePid);
				vHook.put("targetPid",    nTargetPid);

				Dictionary vProc;
				vProc.put("pid", nSourcePid);
				vEvent.put("process", vProc);

				bool fJsonMatched = isMatchingJsonHook(sFuncName);
				vHook.put("isJsonMatched", fJsonMatched);
				vEvent.put("owlyHook", vHook);

				// Kernel hook events share the IOCTL baseType so EventEnricher
				// (which overwrites "type" from baseType) emits LLE_DEVICE_IOCTL
				// and Owlyshield dispatches them via the owlyHook sub-dict.
				eEvent = Event::LLE_DEVICE_IOCTL;

				if (fJsonMatched)
				{
					uint64_t a1 = vEvent.get("owlyHookArg1", uint64_t(0));
					uint64_t a2 = vEvent.get("owlyHookArg2", uint64_t(0));
					uint64_t a3 = vEvent.get("owlyHookArg3", uint64_t(0));
					uint64_t a4 = vEvent.get("owlyHookArg4", uint64_t(0));

					LOGLVL(Debug, "[MATCHED API HOOK DEBUG] PID=" << nSourcePid
						<< " TargetPID=" << nTargetPid
						<< " API=" << string::convertWCharToUtf8(sFuncName)
						<< " Args=[0x" << std::hex << a1
						<< ", 0x" << a2
						<< ", 0x" << a3
						<< ", 0x" << a4 << std::dec << "]");
				}
			}

			// Build the owlyHv sub-dict from the nested owlyHv.* dict (hypervisor
			// path). The LBVS deserializer creates a nested dictionary for the
			// dotted schema names ("owlyHv.memoryAddress" -> { owlyHv: { ... } }).
#if OWLY_HYPERVISOR_SUPPORT
			if (vEvent.has("owlyHv"))
			{
				Variant vHvRaw = vEvent.get("owlyHv");
				Dictionary vHv;
				vHv.put("memoryAddress",      vHvRaw.get("memoryAddress",      uint64_t(0)));
				vHv.put("memorySize",         vHvRaw.get("memorySize",         uint64_t(0)));
				vHv.put("memoryProtection",   vHvRaw.get("memoryProtection",   uint32_t(0)));
				vHv.put("isExecutableMemory", vHvRaw.get("isExecutableMemory", uint32_t(0)));
				vHv.put("threadHandle",       vHvRaw.get("threadHandle",       uint64_t(0)));
				vHv.put("threadStartRoutine", vHvRaw.get("threadStartRoutine", uint64_t(0)));
				vHv.put("accessMask",         vHvRaw.get("accessMask",         uint32_t(0)));
				vHv.put("operationStatus",    vHvRaw.get("operationStatus",    uint32_t(0)));
				vHv.put("coreId",             vHvRaw.get("coreId",             uint32_t(0)));
				vHv.put("threadId",           vHvRaw.get("threadId",           uint32_t(0)));
				vHv.put("isDllLoad",          vHvRaw.get("isDllLoad",          uint32_t(0)));
				vHv.put("isApiBasedLoad",     vHvRaw.get("isApiBasedLoad",     uint32_t(0)));
				vHv.put("loadedDllPath",      vHvRaw.get("loadedDllPath",      L""));
				vHv.put("isAcgEnabled",       vHvRaw.get("isAcgEnabled",       uint32_t(0)));
				vHv.put("timestamp",          vHvRaw.get("timestamp",          uint64_t(0)));
				vHv.put("targetPid",          vHvRaw.get("targetPid",          uint32_t(0)));
				vHv.put("context",            vHvRaw.get("context",            uint64_t(0)));
				vEvent.put("owlyHv", vHv);
				// Hypervisor events get a distinct baseType
				eEvent = Event::LLE_DEVICE_IOCTL;
			}
#endif // OWLY_HYPERVISOR_SUPPORT
		}

		vEvent.put("baseType", eEvent);
		vEvent.put("rawEventId", createRaw(c_nClassId, (uint32_t)nRawEventId));
		vEvent.put("type", getOpenEdrWireEventType(nRawEventId, eEvent));
		vEvent.put("source", "openedr");
		// Telemetry is forwarded to Owlyshield after enrichment in EventEnricher::put()

		if (m_eInjection == InjectionMode::Controller && eEvent == Event::LLE_PROCESS_CREATE)
		{
			uint32_t nPid = getByPath(vEvent, "process.pid", 0);
			if (nPid != 0)
			{
				run([](uint32_t pid) {
					(void) execCommand(Dictionary({
							{"processor", "objects.processMonitorController" },
							{"command", "inject"},
							{"params", Dictionary({ {"pid", pid} })},
						}));
				}, nPid);
			}
		}

		// Send message to receiver
		if (!m_pReceiver)
			error::InvalidArgument(SL, "Receiver interface is undefined").throwException();

		// Only forward SelfDefense events that carry hostile access bits.
		// Benign read/query probes from background Windows services are dropped entirely —
		// they are the primary source of queue saturation and have no detection value.
		if (nRawEventId == edrdrv::SysmonEvent::SelfDefense)
		{
			// Access rights that indicate a real attack attempt.
			// Mirrors eDetectedAccessMask in objmon.cpp postProcessObjectAccess.
			static constexpr uint32_t c_nHostileAccessMask =
				0x0001 | // PROCESS_TERMINATE
				0x0002 | // PROCESS_CREATE_THREAD
				0x0008 | // PROCESS_VM_OPERATION
				0x0010 | // PROCESS_VM_READ
				0x0020 | // PROCESS_VM_WRITE
				0x0040 | // PROCESS_DUP_HANDLE
				0x0080 | // PROCESS_CREATE_PROCESS
				0x0100 | // PROCESS_SET_QUOTA
				0x0200 | // PROCESS_SET_INFORMATION
				0x0800;  // PROCESS_SUSPEND_RESUME

			uint32_t nAccessMask = getByPath(vEvent, "accessMask", uint32_t(0));
			if ((nAccessMask & c_nHostileAccessMask) == 0)
				return true; // drop — harmless query/read probe, not an attack
		}

		try
		{
			m_pReceiver->put(vEvent);
		}
		catch (error::LimitExceeded& e)
		{
			LOGWRN(FMT("System monitor receiver queue limit exceeded: " << e.what()));
		}

		// Broadcast ALL raw events (process, memory, threads, file, registry, hooks) to Pascal GUI
		try
		{
			std::string sSrcPath;
			if (auto optP = variant::getByPathSafe(vEvent, "process.imageFile.abstractPath"))
				sSrcPath = std::string(optP.value());
			else if (auto optP2 = variant::getByPathSafe(vEvent, "process.imageFile.rawPath"))
				sSrcPath = std::string(optP2.value());
			else if (auto optP3 = variant::getByPathSafe(vEvent, "process.path"))
				sSrcPath = std::string(optP3.value());

			std::string sEvtType = vEvent.get("type", std::string());
			if (sEvtType.empty()) sEvtType = vEvent.get("eventType", std::string());

			if (!sSrcPath.empty() && !sEvtType.empty())
			{
				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string pipeMsg = "BEHAVIOR_EVENT:" + sSrcPath + "|" + sEvtType + "\n";
					DWORD written = 0;
					::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}
			}
		}
		catch (...) {}
#ifdef ENABLE_EVENT_TIMINGS
		auto t2 = steady_clock::now();
		milliseconds lbvsTime(duration_cast<milliseconds>(t1 - t0));
		milliseconds queueTime(duration_cast<milliseconds>(t2 - t1));
		nTimes.first = Size(lbvsTime.count());
		nTimes.second = Size(queueTime.count());
#endif
	}
	CMD_PREPARE_CATCH
	catch (error::Exception& e)
	{
		e.log(SL, "System monitor fail to parse event");
		LOGLVL(Trace, string::convertToHex(pBuffer, pBuffer + nBufferSize));
		return false;
	}
	return true;
}



// 
// FIXME: Can we use enum for nCode?
//
void SystemMonitorController::sendIoctl(uint32_t nCode, void* pInput, Size nInput, 
	void* pOutput, Size nOutput)
{
	if (!m_pIoctl)
	{
		m_pIoctl = sys::win::ScopedFileHandle(CreateFileW(CMD_ERDDRV_IOCTLDEVICE_WIN32_NAME,
			GENERIC_READ | GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (!m_pIoctl)
			error::win::WinApiError(SL, "Fail to open IOCTL device").throwException();
	}

	DWORD nReturnSize = 0;
	if (!::DeviceIoControl(m_pIoctl, nCode, pInput, (DWORD)nInput, pOutput, (DWORD)nOutput, &nReturnSize, nullptr))
		error::win::WinApiError(SL, "Fail to communicate with IOCTL device").throwException();
	if (nReturnSize != nOutput)
		error::RuntimeError(SL, FMT("Incorrect size returned from IOCTL device. Wait <" << 
			nOutput << ">, got <" << nReturnSize << ">")).throwException();
}

//
//
//
void SystemMonitorController::sendStartMonitoring()
{
	sendIoctl(CMD_ERDDRV_IOCTL_START, nullptr, 0U, nullptr, 0U);
}

//
//
//
void SystemMonitorController::sendStopMonitoring()
{
	sendIoctl(CMD_ERDDRV_IOCTL_STOP, nullptr, 0U, nullptr, 0U);
}

//
//
//
void SystemMonitorController::sendConfig(Variant vDrvConfig)
{
	TRACE_BEGIN;
	std::vector<uint8_t> data;
	if (!variant::serializeToLbvs(vDrvConfig, m_vConfigSchema, data))
		LOGLVL(Filtered, "Can't serialize edrdrv.sys config: " << vDrvConfig);
	
	sendIoctl(CMD_ERDDRV_IOCTL_SET_CONFIG, data.data(), data.size(), nullptr, 0);
	TRACE_END("Can't set edrdrv.sys config.");
}

//
//
//
void SystemMonitorController::updateProcessRules(Variant vParams)
{
	TRACE_BEGIN;
	std::vector<uint8_t> data;
	if (!variant::serializeToLbvs(vParams, m_vUpdateRulesSchema, data))
		LOGLVL(Filtered, "updateProcessRules: can't serialize all fields into lvbs: " << vParams);
	sendIoctl(CMD_ERDDRV_IOCTL_UPDATE_PROCESS_RULES, data.data(), data.size(), nullptr, 0);
	TRACE_END("Can't update process rules.");
}

//
//
//
void SystemMonitorController::setProcessInfo(Variant vParams)
{
	std::vector<uint8_t> data;
	if (!variant::serializeToLbvs(vParams, m_vSetProcessInfoSchema, data))
		LOGLVL(Filtered, "setProcessInfo: can't serialize all fields into lvbs: " << vParams);
	sendIoctl(CMD_ERDDRV_IOCTL_SET_PROCESS_INFO, data.data(), data.size(), nullptr, 0);
}

//
//
//
void SystemMonitorController::updateFileRules(Variant vParams)
{
	TRACE_BEGIN;

	// Normalize passed rules[].path
	if (vParams.get("rules", Variant()).isSequenceLike())
	{
		auto pFileInformation = queryInterface<sys::win::IFileInformation>(queryService("fileDataProvider"));

		// Clone before modification
		vParams = vParams.clone();

		Variant vRules = vParams.get("rules", Variant());
		for (auto vRule : vRules)
		{
			Variant vPath;
			CMD_TRY
			{
				vPath = vRule.get("path", Variant());
				if (!vPath.isString())
					continue;
				std::wstring sPath = vPath;
				std::wstring sNtPath = pFileInformation->normalizePathName(sPath, {}, sys::win::PathType::NtPath);
				vRule.put("path", sNtPath);
			}
			CMD_PREPARE_CATCH
			catch (error::Exception& e)
			{
				e.log(SL, FMT("Can't normalize path <" << vPath << ">"));
			}
		}
	}

	// Call IOCTL
	std::vector<uint8_t> data;
	if (!variant::serializeToLbvs(vParams, m_vUpdateRulesSchema, data))
		LOGLVL(Filtered, "updateFileRules: can't serialize all fields into lvbs: " << vParams);
	sendIoctl(CMD_ERDDRV_IOCTL_UPDATE_FILE_RULES, data.data(), data.size(), nullptr, 0);

	TRACE_END("Can't update files rules.");
}

//
//
//
void SystemMonitorController::updateRegRules(Variant vParams)
{
	TRACE_BEGIN;
	std::vector<uint8_t> data;
	if (!variant::serializeToLbvs(vParams, m_vUpdateRulesSchema, data))
		LOGLVL(Filtered, "updateRegRules: can't serialize all fields into lvbs: " << vParams);
	sendIoctl(CMD_ERDDRV_IOCTL_UPDATE_REG_RULES, data.data(), data.size(), nullptr, 0);
	TRACE_END("Can't update registry rules.");
}

//
//
//
void SystemMonitorController::updateUserModeHooks(Variant vParams)
{
	TRACE_BEGIN;
	Variant vHooks = vParams.isSequenceLike() ? vParams : vParams.get("hooks", vParams.get("rules", vParams));
	if (!vHooks.isSequenceLike())
		return;

#pragma pack(push, 8)
	struct OwlyHookMsg {
		uint32_t type;
		uint32_t pid;
		uint64_t gid;
		wchar_t path[520];
		wchar_t quarantine_path[520];
	};
#pragma pack(pop)

	static constexpr DWORD c_nIoctlOwlyCompat = 0x00222484; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)

	{
		std::lock_guard<std::mutex> lock(m_mtxJsonHooks);
		m_vJsonHooks.clear();
	}

	ULONG nEventIdBase = 0x6000;
	for (Size i = 0; i < vHooks.getSize(); ++i)
	{
		Variant vItem = vHooks[i];
		if (!vItem.isDictionaryLike())
			continue;

		std::wstring wsModule = vItem.get("module", L"*");
		std::wstring wsFunction = vItem.get("function", vItem.get("name", L""));
		if (wsFunction.empty())
			continue;

		uint64_t nEventId = vItem.get("eventId", uint64_t(nEventIdBase + (ULONG)i));

		{
			std::lock_guard<std::mutex> lock(m_mtxJsonHooks);
			m_vJsonHooks.push_back({ wsModule, wsFunction, nEventId });
		}

		OwlyHookMsg msg = {};
		msg.type = 9; // MESSAGE_ADD_HOOK
		msg.pid = 0;
		msg.gid = nEventId;
		wcsncpy_s(msg.path, wsModule.c_str(), _TRUNCATE);
		wcsncpy_s(msg.quarantine_path, wsFunction.c_str(), _TRUNCATE);

		try
		{
			sendIoctl(c_nIoctlOwlyCompat, &msg, sizeof(msg), nullptr, 0);
			LOGLVL(Detailed, FMT("Registered JSON user-mode hook: " << string::convertWCharToUtf8(wsModule)
				<< "!" << string::convertWCharToUtf8(wsFunction) << " (id=" << nEventId << ")"));
		}
		catch (error::Exception& e)
		{
			LOGLVL(Filtered, FMT("Failed to register JSON user-mode hook "
				<< string::convertWCharToUtf8(wsModule) << "!" << string::convertWCharToUtf8(wsFunction)
				<< ": " << e.what()));
		}
	}

	// Scan and hook all existing running processes on initial setup
	HANDLE hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32W pe = {};
		pe.dwSize = sizeof(pe);
		if (::Process32FirstW(hSnapshot, &pe))
		{
			do
			{
				if (pe.th32ProcessID <= 4 || pe.th32ProcessID == (DWORD)m_nSelfPid)
					continue;

				OwlyHookMsg hookMsg = {};
				hookMsg.type = 10; // MESSAGE_HOOK_PROCESS
				hookMsg.pid = pe.th32ProcessID;
				try
				{
					sendIoctl(c_nIoctlOwlyCompat, &hookMsg, sizeof(hookMsg), nullptr, 0);
				}
				catch (...)
				{
					// Best-effort for existing processes
				}
			} while (::Process32NextW(hSnapshot, &pe));
		}
		::CloseHandle(hSnapshot);
	}

	TRACE_END("Can't update user-mode hooks.");
}

//
//
//
bool SystemMonitorController::isMatchingJsonHook(const std::wstring& sFullFuncName) const
{
	if (sFullFuncName.empty())
		return false;

	std::lock_guard<std::mutex> lock(m_mtxJsonHooks);
	if (m_vJsonHooks.empty())
		return false;

	std::wstring sIncomingModule;
	std::wstring sIncomingFunc = sFullFuncName;
	auto nPos = sFullFuncName.rfind(L'!');
	if (nPos != std::wstring::npos)
	{
		sIncomingModule = sFullFuncName.substr(0, nPos);
		sIncomingFunc = sFullFuncName.substr(nPos + 1);
	}

	for (const auto& entry : m_vJsonHooks)
	{
		if (_wcsicmp(sIncomingFunc.c_str(), entry.sFunction.c_str()) == 0)
		{
			if (entry.sModule == L"*" || sIncomingModule.empty() || _wcsicmp(sIncomingModule.c_str(), entry.sModule.c_str()) == 0)
			{
				return true;
			}
		}
	}
	return false;
}

///
/// @copydoc ICommandProcessor::execute() 
///
/// #### Processors
///   * 'objects.systemMonitorController'
///
/// #### Supported commands
///
Variant SystemMonitorController::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN
		LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### install()
	/// Installs a driver.
	///   * driverName [str] - name of driver (absolute or relative).
	///   * useSystemDir [bool] - copy/delete driver to/from system directory.
	///   * startMode [string,opt] - the following string modes are supported:
	///	    * "manual" - manual start.
	///     * "auto" - automatic start (at OS start).
	///     * "off" - disable start.
	///
	if (vCommand == "install")
	{
		install(vParams);
		return true;
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### uninstall()
	/// Uninstalls a driver.
	///   * driverName [str] - name of driver (absolute or relative).
	///   * useSystemDir [bool] - copy/delete driver to/from system directory.
	///
	else if (vCommand == "uninstall")
	{
		if (!execCommand(Dictionary({
				{"processor", Dictionary({{"clsid", CLSID_WinServiceController}}) },
				{"command", "isExist"},
				{"params", Dictionary({ {"name", c_sDrvSrvName} })},
			})))
			return false;

		uninstall(vParams);
		return true;
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### start()
	/// Starts the driver and the controller.
	///
	else if (vCommand == "start")
	{
		return startInt();
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### stop()
	/// Stops the controller.
	///
	else if (vCommand == "stop")
	{
		return stopInt();
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### shutdown()
	/// Stops the driver and free controller's resources.
	///
	else if (vCommand == "shutdown")
	{
		shutdown();
		return {};
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### setDriverConfig()
	/// Updates the driver's configuration.
	///
	else if (vCommand == "setDriverConfig")
	{
		sendConfig(vParams);
		return {};
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### updateProcessRules()
	/// Updates processes rules.
	/// Apply rules for all exist process after update.
	///
	/// Parameters:
	///   * **type** [int] - specify rule list. Values: edrdrv::RuleType.
	///   * **mode** [int] - update mode. Values: edrdrv::UpdateRulesMode.
	///   * **tag** [str, opt] - tag for UpdateRulesMode::DeleteByTag. In this mode other fields are ignored.
	///   * **persistent** [bool, opt] - update persistent rules (default: `false`).
	///   * **rules** - sequence of rule. Each rule is dict with fields:
	///     * imagePath [str] - postfix of image path.
	///          if `imagePath` is empty string or absent - the rule is always applied.
	///     * value [bool] - specified value if condition is true.
	///     * inherit [bool, opt] - value is inherited by child process (default: `false`).
	///     * tag [str, opt] - tag for deletion.
	///
	/// Rules application:
	/// There several rules sets. One for each edrdrv::RuleType.
	/// Each rules set has 2 rules list: non-persistent and persistent.
	/// 
	/// Rules are applied for process folowing way.
	/// * Inherit parent options, which are specified as inherited.
	/// * Apply rules for all not inherited options.
	///   First applied rule stops rule checking for this option.
	///   * Firstly non-persistent rule list is applied.
	///   * Finally persistent rule list is applied.
	/// 
	else if (vCommand == "updateProcessRules")
	{
		updateProcessRules(vParams);
		return {};
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### setProcessInfo()
	/// Forcibly set options for existing process by PID. 
	/// If option is not specified it is not changed.
	/// If option is set with this command, it can not be changed by processes rules update.
	///
	/// Parameters:
	///   * **pid** [int] - pid
	///   * **trusted** [bool, opt] - TBD.
	///   * **protected** [bool, opt] - TBD.
	///   * **sendEvent** [bool, opt] - TBD.
	///   * **enableInject** [bool, opt] - TBD.
	/// 
	else if (vCommand == "setProcessInfo" || vCommand == "setProcessOptions")
	{
		setProcessInfo(vParams);
		return {};
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### updateFileRules()
	/// Updates the file rules.
	///
	/// Parameters:
	///   * "mode" [int] - update mode. Values: edrdrv::UpdateRulesMode
	///   * "tag" [str, opt] - tag for UpdateRulesMode::DeleteByTag. In this mode other fields are ignored.
	///   * "rules" - sequence of rule. Each rule is dict with fields:
	///     * "path" [str] - DOS path to protected file / directory
	///     * "recursive" [bool, opt] - rules applied for nested objects. default value is false.
	///     * "value" [int] - edrdrv::AccessType
	///     * "tag" [str, opt] - tag for deletion.
	/// 
	/// 
	else if (vCommand == "updateFileRules")
	{
		updateFileRules(vParams);
		return {};
	}

	///
	/// @fn Variant SystemMonitorController::execute()
	///
	/// ##### updateRegRules()
	/// Updates the registry rules.
	///
	/// Parameters:
	///   * **mode** [int] - update mode. Values: edrdrv::UpdateRulesMode.
	///   * **tag** [str, opt] - tag for UpdateRulesMode::DeleteByTag. In this mode other fields are ignored.
	///   * **rules** - sequence of rule. Each rule is dict with fields:
	///     * path [str] - normalized (abstract) path to protected registry key (see abstract path in policy).
	///     * recursive [bool, opt] - rules applied for nested objects (default: `false`).
	///     * value [int] - edrdrv::AccessType.
	///     * tag [str, opt] - tag for deletion.
	/// 
	else if (vCommand == "updateRegRules")
	{
		updateRegRules(vParams);
		return {};
	}
	else if (vCommand == "updateUserModeHooks")
	{
		updateUserModeHooks(vParams);
		return {};
	}

	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
	error::InvalidArgument(SL, FMT("SystemMonitorController doesn't support a command <"
		<< vCommand << ">")).throwException();
}

} // namespace win
} // namespace cmd

/// @}
