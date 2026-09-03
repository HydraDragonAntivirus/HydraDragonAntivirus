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

#include <mutex>
#include <string_view>
#include <windows.h>
#include <tlhelp32.h>

#undef CMD_COMPONENT
#define CMD_COMPONENT "libsysmon"

namespace cmd {
namespace win {

namespace {

const char* getOpenEdrWireEventType(edrdrv::SysmonEvent rawEvent, Event eventType)
{
	switch (rawEvent)
	{
		case edrdrv::SysmonEvent::DeviceIoControl:
			return "LLE_DEVICE_IOCTL";
		case edrdrv::SysmonEvent::NamedPipeCreate:
			return "LLE_NAMED_PIPE_CREATE";
		case edrdrv::SysmonEvent::SelfDefense:
			return "LLE_SELF_DEFENSE";
		default:
			return getEventTypeString(eventType);
	}
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

	if (fs::exists(srcPath) && !fs::exists(destPath))
	{
		std::error_code ec;
		fs::copy_file(srcPath, destPath, fs::copy_options::overwrite_existing, ec);
		if (!ec)
		{
			LOGINF("[MBR] Staged MBRFilter.sys to " << destPath.string());
		}
	}

	if (!fs::exists(destPath))
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
				LOGLVL(Critical, "[MBR ALERT] Sector 0 write attempt: " << sAlertUtf8);

				// Forward MBR Alert to Pascal GUI
				try
				{
					HANDLE hGuiPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
						GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
					if (hGuiPipe != INVALID_HANDLE_VALUE)
					{
						std::string pipeMsg = "BEHAVIOR_EVENT:PhysicalDrive0|MBR_SECTOR0_RAW_WRITE [Alert: " + sAlertUtf8 + "]\n";
						DWORD written = 0;
						::WriteFile(hGuiPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
						::CloseHandle(hGuiPipe);
					}
				}
				catch (...) {}
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
		HANDLE hPipe = ::CreateNamedPipeW(
			pipeName,
			PIPE_ACCESS_INBOUND,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			65536, 65536,
			0, NULL
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
				if (sCmd.rfind("HIPS_KILL:", 0) == 0)
				{
					std::string sPayload = sCmd.substr(10);
					size_t sep1 = sPayload.find('|');
					if (sep1 != std::string::npos)
					{
						std::string sPidStr = sPayload.substr(0, sep1);
						uint32_t targetPid = static_cast<uint32_t>(std::strtoul(sPidStr.c_str(), nullptr, 10));
						if (targetPid != 0)
						{
							killProcessViaDriver(targetPid);
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
				{
					try
					{
						auto vEvent = variant::deserializeFromJson(sLine);
						if (m_pReceiver)
							m_pReceiver->put(vEvent);

						// Also broadcast Rust/Sanctum events directly to Pascal GUI
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
							if (sEvtType.empty()) sEvtType = "SANCTUM_TELEMETRY";

							if (!sSrcPath.empty())
							{
								HANDLE hGuiPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
									GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
								if (hGuiPipe != INVALID_HANDLE_VALUE)
								{
									std::string pipeMsg = "BEHAVIOR_EVENT:" + sSrcPath + "|" + sEvtType + " [Sanctum/Rust]\n";
									DWORD written = 0;
									::WriteFile(hGuiPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
									::CloseHandle(hGuiPipe);
								}
							}
						}
						catch (...) {}
					}
					catch (...)
					{
						LOGWRN("Failed to parse Sanctum event JSON");
					}
				}
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
	{edrdrv::SysmonEvent::NamedPipeCreate, Event::LLE_DEVICE_LINK_CREATE},
	{edrdrv::SysmonEvent::SelfDefense, Event::LLE_PROCESS_OPEN},
	{edrdrv::SysmonEvent::FileMapRead, Event::LLE_FILE_MAP_READ},
	{edrdrv::SysmonEvent::FileMapWrite, Event::LLE_FILE_MAP_WRITE},
	{edrdrv::SysmonEvent::FileRename, Event::LLE_FILE_RENAME},
	{edrdrv::SysmonEvent::OwlyPreImageSaved, Event::LLE_FILE_PREIMAGE_SAVED},
	{edrdrv::SysmonEvent::ThreadOpen, Event::LLE_THREAD_OPEN},
	{edrdrv::SysmonEvent::DesktopOpen, Event::LLE_DESKTOP_OPEN},
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
				0x0020 | // PROCESS_VM_WRITE
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
