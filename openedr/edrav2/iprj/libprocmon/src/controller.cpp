//
// edrav2.libprocmon
// 
// Author: Denis Kroshin (20.04.2019)
// Reviewer: Denis Bogdanov (13.05.2019)
//
///
/// @file Process Monitor Controller implementation
///
///
/// @addtogroup procmon Process Monitor library
/// @{
#include "pch.h"
#include "controller.h"
#include "procmonevent.h"

#undef CMD_COMPONENT
#define CMD_COMPONENT "procmon"

namespace cmd {
namespace win {

//
//
//
ProcessMonitorController::ProcessMonitorController()
	: m_hFltPortReceiver(c_sPortName, c_nTreadsCount, true, "ProcMon::EventsPool")
{
	std::srand((unsigned int)std::time(0));
}

//
//
//
ProcessMonitorController::~ProcessMonitorController()
{
}

//
//
//
void ProcessMonitorController::finalConstruct(Variant vConfig)
{
	CHECK_IN_SOURCE_LOCATION();
	m_pReceiver = queryInterfaceSafe<IDataReceiver>(vConfig.get("receiver", {}));
	m_nTimeout = vConfig.get("timeout", c_nDefaultTimeout);
	if (m_pReceiver)
	{
		m_fInjectOnStart = vConfig.get("injectAllOnStart", m_fInjectOnStart);
		m_fUninjectOnExit = vConfig.get("uninjectAllOnExit", m_fUninjectOnExit);
		m_vInjectionConfig = vConfig.get("injectionConfig", Dictionary({}));
		// FIXME: Do we need this parameter now?
		m_sTargetProcessName = vConfig.get("targetProcessName", L"");

		TRACE_BEGIN
		m_vEventSchema = variant::deserializeFromJson(edrpm::c_sEventSchema);
		m_vConfigSchema = variant::deserializeFromJson(edrpm::c_sConfigSchema);
		TRACE_END("Can't deserialize schema");
		CHECK_IN_SOURCE_LOCATION();
		m_hGlobalEvent.reset(::OpenEvent(EVENT_ALL_ACCESS, FALSE, edrpm::c_sGlobalCaptureEvent));
		if (m_hGlobalEvent)
			ResetEvent(m_hGlobalEvent);
		else
		{
			SECURITY_ATTRIBUTES Security;
			SECURITY_DESCRIPTOR Descriptor;
			memset(&Security, 0, sizeof(Security));
			memset(&Descriptor, 0, sizeof(Descriptor));
			InitializeSecurityDescriptor(&Descriptor, SECURITY_DESCRIPTOR_REVISION);
			SetSecurityDescriptorDacl(&Descriptor, TRUE, NULL, FALSE);
			Security.nLength = sizeof(Security);
			Security.lpSecurityDescriptor = &Descriptor;
			Security.bInheritHandle = FALSE;

			m_hGlobalEvent.reset(CreateEvent(&Security, TRUE, FALSE, edrpm::c_sGlobalCaptureEvent));
		}
		if (!m_hGlobalEvent)
			error::RuntimeError("Fail to create global handle").throwException();
	}

	// Setup directories
	m_sSystemDir = getCatalogData("os.systemDir");
#ifdef _WIN64
	m_sSyswowDir = getCatalogData("os.syswowDir");
	if (!std::filesystem::exists(m_sSystemDir / c_sInjDll64) ||
		!std::filesystem::exists(m_sSyswowDir / c_sInjDll32))
	{
		LOGWRN("Injection DLLs not found in system directory. Use default directory.");
		m_sSystemDir = getCatalogData("app.imagePath", ".");
		m_sSyswowDir = m_sSystemDir;
	}
#else
	if (!std::filesystem::exists(m_sSystemDir / c_sInjDll32))
	{
		LOGWRN("Injection DLLs not found in system directory. Use default directory.");
		m_sSystemDir = getCatalogData("app.imagePath", ".");
	}
#endif
}

//
// FIXME: Maybe it is better to create universal function looking specified dll?
//
bool ProcessMonitorController::isDllLoadedIntoProcess(const uint32_t dwPid, const std::wstring_view sDllName)
{
	sys::win::ScopedFileHandle hModuleSnap;
	do
	{
		hModuleSnap.reset(::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPid));
	} while (hModuleSnap == INVALID_HANDLE_VALUE && GetLastError() == ERROR_BAD_LENGTH);
	if (hModuleSnap == INVALID_HANDLE_VALUE)
		return false;

	MODULEENTRY32 me32;
	me32.dwSize = sizeof(me32);
	if (Module32First(hModuleSnap, &me32))
	{
		do
		{
			if (sDllName == me32.szModule)
				return true;
		} while (Module32Next(hModuleSnap, &me32));
	}
	return false;
}

//
//
//
void WINAPI ProcessMonitorController::ipcEventsCallbackInt(const void* pMessageBuf, unsigned long dwMessageLen, void* pAnswerBuf, unsigned long dwAnswerLen, void* pContext, bool& fHasAnswer)
{
	edrpm::RawEvent nRawEventId = edrpm::RawEvent::_Max;
	CMD_TRY
	{
		ProcessMonitorController * pThis = (ProcessMonitorController*)pContext;
		if (pThis == nullptr)
			error::InvalidArgument(SL, "Invalid this pointer").throwException();
		if (pMessageBuf == nullptr)
			error::InvalidArgument(SL, "Invalid incoming buffer for IPC command").throwException();

		ProcmonEvent procmonEvent((Byte*)pMessageBuf, dwMessageLen, (Byte*)pAnswerBuf, dwAnswerLen,
			pThis->m_fInitialized, pThis->m_pReceiver, pThis->m_vEventSchema,
			pThis->m_vInjectionConfig, pThis->m_vConfigSchema, c_nClassId);
		
		procmonEvent.handle(fHasAnswer);
	}
		CMD_PREPARE_CATCH
		catch (error::Exception& e)
	{
		e.log(SL, FMT("Process monitor fail to parse event <" << uint32_t(nRawEventId) << ">"));
		LOGLVL(Trace, string::convertToHex((Byte*)pMessageBuf, (Byte*)pMessageBuf + dwMessageLen));
	}
}

//
//
//
void WINAPI ProcessMonitorController::ipcEventsCallback(const char*, const void* pMessageBuf, 
	unsigned long dwMessageLen, void* pAnswerBuf, unsigned long dwAnswerLen, void* pContext)
{
	bool fHasAnswer;
	ipcEventsCallbackInt(pMessageBuf, dwMessageLen, pAnswerBuf, dwAnswerLen, pContext, fHasAnswer);
}

//
// TODO: Remove this callback in new releases
//
void WINAPI ProcessMonitorController::ipcErrorsCallback(const char*, const void* pMessageBuf, unsigned long dwMessageLen, void*, unsigned long, void* pContext)
{
	CMD_TRY
	{
		if (pMessageBuf == nullptr || dwMessageLen < 2)
			error::InvalidArgument(SL, "Invalid incoming buffer for IPC command").throwException();

		ProcessMonitorController* pThis = (ProcessMonitorController*)pContext;
		if (pThis == nullptr)
			error::InvalidArgument(SL, "Invalid this pointer").throwException();

		uint8_t nType = 'E';
		char* sMsg = (char*)pMessageBuf;
		if (sMsg[dwMessageLen - 2] == '#')
		{
			nType = sMsg[dwMessageLen - 1];
			dwMessageLen -= 2;
		}

		if (nType == 'E')
			error::RuntimeError(SL, std::string(sMsg, sMsg + dwMessageLen)).log();
		else if (nType == 'W')
			LOGWRN(std::string(sMsg, sMsg + dwMessageLen));
		else if (nType == 'I')
			LOGLVL(Debug, std::string(sMsg, sMsg + dwMessageLen));
		else
			LOGWRN("Unknown message type. <" << std::string(sMsg, sMsg + dwMessageLen) << ">");
	}
	CMD_PREPARE_CATCH
	catch (error::Exception& e)
	{
		e.log(SL, "System monitor fail to log error");
	}
	
}

//
//
//
void ProcessMonitorController::copyInjectionDll(const std::wstring& sDllName, const GUID guidFolder)
{
	namespace fs = std::filesystem;
	auto sSrcFile = fs::path(getCatalogData("app.imagePath")) / sDllName;
	if (fs::exists(sSrcFile))
	{
		PWSTR pFolder;
		if (::SHGetKnownFolderPath(guidFolder, 0, NULL, &pFolder) != S_OK)
			error::win::WinApiError(SL, "Fail to get path of system directory").throwException();
		auto sDestFile = fs::path(pFolder) / sDllName;
		::CoTaskMemFree(pFolder);

		std::error_code ec;
		if (fs::copy_file(sSrcFile, sDestFile, fs::copy_options::overwrite_existing, ec))
			return;

		auto sDelFile = sDestFile;
		sDelFile.replace_extension(std::to_wstring(std::rand()) + L".bak");
		fs::rename(sDestFile, sDelFile); // Throw exception if fail
		fs::copy(sSrcFile, sDestFile);
		fs::remove(sDelFile, ec);
		if (ec)
		{
			LOGWRN("Fail remove file <" << sDestFile.u8string() << ">, rename it to <" << sDelFile.u8string() << ">");
			// Register delete-on-reboot
			if (!MoveFileExW(sDelFile.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
				error::win::WinApiError(SL, FMT("Fail to delayed move file <" << sDelFile.u8string() << ">")).log();
		}
	}
	else
		error::InvalidArgument(SL, FMT("Injection DLL <" << sSrcFile.u8string() << "> is not found")).throwException();
}

//
//
//
void ProcessMonitorController::removeInjectionDll(const std::wstring& sDllName, const GUID guidFolder)
{
	namespace fs = std::filesystem;

	PWSTR pFolder;
	if (::SHGetKnownFolderPath(guidFolder, 0, NULL, &pFolder) != S_OK)
		error::win::WinApiError(SL, "Fail to get path of system directory").throwException();
	auto sDestFile = fs::path(pFolder) / sDllName;
	::CoTaskMemFree(pFolder);

	std::error_code ec;
	if (!fs::exists(sDestFile) || fs::remove(sDestFile, ec))
		return;
	
	auto sDelFile = sDestFile;
	sDelFile.replace_extension(std::to_wstring(std::rand()) + L".bak");
	fs::rename(sDestFile, sDelFile); // Throw exception if fail
	fs::remove(sDelFile, ec);
	if (ec)
	{
		LOGWRN("Fail remove file <" << sDestFile.u8string() << ">, rename it to <" << sDelFile.u8string() << ">");
		// Register delete-on-reboot
		if (!MoveFileExW(sDelFile.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
			error::win::WinApiError(SL, FMT("Fail to delayed move file <" << sDelFile.u8string() << ">")).log();
	}
}

//
//
//
void ProcessMonitorController::install(Variant vParams)
{
	if (m_hGlobalEvent && !::ResetEvent(m_hGlobalEvent))
		error::win::WinApiError(SL, "Fail to reset global event").log();
	m_fAllowInjection = true;

	if (vParams.get("useSystemDir", true))
	{
#ifdef _WIN64
		copyInjectionDll(c_sInjDll64, FOLDERID_System);
		copyInjectionDll(c_sInjDll32, FOLDERID_SystemX86);
#else
		copyInjectionDll(c_sInjDll32, FOLDERID_System);
#endif
	}
	else
	{
		std::filesystem::path sBinaryDir(getCatalogData("app.imagePath"));
		if (!std::filesystem::exists(sBinaryDir / c_sInjDll32))
			error::InvalidArgument(SL, FMT("Injection DLL <" << 
			(sBinaryDir / c_sInjDll32).u8string() << "> is not found")).throwException();
#ifdef _WIN64
		if (!std::filesystem::exists(sBinaryDir / c_sInjDll64))
			error::InvalidArgument(SL, FMT("Injection DLL <" <<
			(sBinaryDir / c_sInjDll64).u8string() << "> is not found")).throwException();
#endif
	}
}

//
//
//
void ProcessMonitorController::uninstall(Variant vParams)
{
	if (m_hGlobalEvent && !::ResetEvent(m_hGlobalEvent))
		error::win::WinApiError(SL, "Fail to reset global event").log();
	m_fAllowInjection = true;

#ifdef _WIN64
	removeInjectionDll(c_sInjDll64, FOLDERID_System);
	removeInjectionDll(c_sInjDll32, FOLDERID_SystemX86);
#else
	removeInjectionDll(c_sInjDll32, FOLDERID_System);
#endif

}

//
//
//
void ProcessMonitorController::loadState(Variant vState)
{
}

//
//
//
cmd::Variant ProcessMonitorController::saveState()
{
	return {};
}

//
//
//
void ProcessMonitorController::start()
{
	start({});
}

//
//
//
bool ProcessMonitorController::start(Variant vParams)
{
	LOGLVL(Detailed, "ProcMon controller is being started");

	std::scoped_lock _lock(m_mtxStartStop);
	if (m_fInitialized)
	{
		LOGLVL(Detailed, "ProcMon controller already started");
		return false;
	}

	if (!::SetEvent(m_hGlobalEvent))
		error::win::WinApiError(SL, "Fail to set global event").throwException();
	m_fInitialized = true;
	m_fAllowInjection = true;
	Handler handler = [this](HandlerContext& ctxt) -> HRESULT
	{
		this->ipcEventsCallbackInt(ctxt.pInData, (unsigned long)ctxt.nInDataSize, ctxt.pOutData, (unsigned long)ctxt.nOutDataSize, this, ctxt.fHasResponce);
		return S_OK;
	};
	m_hFltPortReceiver.Start(handler);

	LOGLVL(Detailed, "ProcMon controller is started");
	return true;
}

//
//
//
void ProcessMonitorController::stop()
{
	stop({});
}

//
//
//
bool ProcessMonitorController::stop(Variant vParams)
{
	LOGLVL(Detailed, "ProcMon controller is being stopped");

	std::scoped_lock _lock(m_mtxStartStop);
	if (!m_fInitialized)
	{
		LOGLVL(Detailed, "ProcMon controller already stopped");
		return false;
	}

	if (!::ResetEvent(m_hGlobalEvent))
		error::win::WinApiError(SL, "Fail to reset global event").log();

	m_fInitialized = false;
	m_fAllowInjection = false;
	if (m_pInjectionThread.joinable())
		m_pInjectionThread.join();
	m_hFltPortReceiver.Stop();

	LOGLVL(Detailed, "ProcMon controller is stopped");
	return true;
}

//
//
//
void ProcessMonitorController::shutdown()
{
	LOGLVL(Detailed, "ProcMon controller is being shutdowned");
	if (m_hGlobalEvent && !::ResetEvent(m_hGlobalEvent))
		error::win::WinApiError(SL, "Fail to reset global event").log();

	LOGLVL(Detailed, "Finalize open-source process hook bridge");
	LOGLVL(Detailed, "ProcMon controller is shutdowned");
}

///
/// @copydoc ICommandProcessor::execute() 
///
/// #### Processors
///   * 'objects.ProcessMonitorController'
///
/// #### Supported commands
///
Variant ProcessMonitorController::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN;
	LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	///
	/// @fn Variant ProcessMonitorController::execute()
	///
	/// ##### install()
	/// Installs the injection DLLs into the operating system.
	///   * useSystemDir [bool] - copy/delete files to/from system directory.
	///
	if (vCommand == "install")
	{
		install(vParams);
		return true;
	}

	///
	/// @fn Variant ProcessMonitorController::execute()
	///
	/// ##### uninstall()
	/// Uninstalls the injection DLLs.
	///
	else if (vCommand == "uninstall")
	{
		uninstall(vParams);
		return true;
	}

	///
	/// @fn Variant ProcessMonitorController::execute()
	///
	/// ##### start()
	/// Starts the service.
	/// Returns a status of the operation.
	///
	if (vCommand == "start")
		return start(vParams);

	///
	/// @fn Variant ProcessMonitorController::execute()
	///
	/// ##### stop()
	/// Stops the service.
	/// Returns a status of the operation.
	///
	if (vCommand == "stop")
		return stop(vParams);

	///
	/// @fn Variant ProcessMonitorController::execute()
	///
	/// ##### inject() / uninject()
	/// Inject/uninject DLL into/from process.
	///   * pid [int] - pid of process.
	///   * procName [str] - name of processes.
	/// Returns a status of the operation.
	///
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
	error::InvalidArgument(SL, FMT("ProcessMonitorController doesn't support a command <"
		<< vCommand << ">")).throwException();
}

} // namespace win
} // namespace cmd

/// @}
