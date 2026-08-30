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
void SystemMonitorController::loadState(Variant vState)
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
//
void SystemMonitorController::uninstall(Variant vParams)
{
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
				vHook.put("eventType",    vEvent.get("owlyHookEventType", 0));
				vHook.put("functionName", vEvent.get("owlyHookFunctionName", L""));
				vHook.put("arg1",         vEvent.get("owlyHookArg1", uint64_t(0)));
				vHook.put("arg2",         vEvent.get("owlyHookArg2", uint64_t(0)));
				vHook.put("arg3",         vEvent.get("owlyHookArg3", uint64_t(0)));
				vHook.put("arg4",         vEvent.get("owlyHookArg4", uint64_t(0)));
				vHook.put("sourcePid",    vEvent.get("owlyHookSourcePid", uint32_t(0)));
				vHook.put("targetPid",    vEvent.get("owlyHookTargetPid", uint32_t(0)));
				vEvent.put("owlyHook", vHook);
				// Kernel hook events share the IOCTL baseType so EventEnricher
				// (which overwrites "type" from baseType) emits LLE_DEVICE_IOCTL
				// and Owlyshield dispatches them via the owlyHook sub-dict.
				eEvent = Event::LLE_DEVICE_IOCTL;
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
// Re-inject an OpenEDR event (built by the Owlyshield engine) into the pipeline.
// Mirrors the tail of parseEvent() so PTM rules see the same shape as a driver
// event: an LLE_DEVICE_IOCTL with the owlyHook sub-dict already present.
//
void SystemMonitorController::injectEvent(Variant vEvent)
{
	if (s_pInstance == nullptr)
		return;
	vEvent.put("baseType", (int)Event::LLE_DEVICE_IOCTL);
	vEvent.put("type", getOpenEdrWireEventType(edrdrv::SysmonEvent::DeviceIoControl, Event::LLE_DEVICE_IOCTL));
	vEvent.put("source", "openedr");
	if (!s_pInstance->m_pReceiver)
		return;
	try
	{
		s_pInstance->m_pReceiver->put(vEvent);
	}
	catch (error::LimitExceeded& e)
	{
		LOGWRN(FMT("System monitor receiver queue limit exceeded (inject): " << e.what()));
	}
}

//
// C-linkage entry point called by the Owlyshield engine (owlyshield_ransom.dll)
// to republish a hook/LLE_DEVICE_IOCTL event (UTF-8 JSON) into OpenEDR.
//
extern "C" void owlyshield_publish_openedr_event_impl(const uint8_t* data, uint32_t len)
{
	if (data == nullptr || len == 0)
		return;
	std::string_view sv(reinterpret_cast<const char*>(data), len);
	Variant vEvent = variant::deserializeFromJson(sv);
	if (vEvent.isNull())
		return;
	SystemMonitorController::injectEvent(vEvent);
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

	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
	error::InvalidArgument(SL, FMT("SystemMonitorController doesn't support a command <"
		<< vCommand << ">")).throwException();
}

} // namespace win
} // namespace cmd

/// @}
