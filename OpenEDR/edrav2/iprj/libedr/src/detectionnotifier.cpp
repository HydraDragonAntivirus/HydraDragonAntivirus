//
// edrav2.libedr project
//
// Author: Emirhan Ucan (20.08.2026)
//
///
/// @file DetectionNotifier class implementation
///
/// @addtogroup edr
/// @{
#include "pch.h"
#include "detectionnotifier.h"

#include <deque>

// Set component for logging
#undef CMD_COMPONENT
#define CMD_COMPONENT "detnotif"

namespace cmd {

namespace {

	std::string NtPathToDosPathString(const std::string& sNt)
	{
		if (sNt.empty())
			return sNt;

		int cchW = ::MultiByteToWideChar(CP_UTF8, 0, sNt.c_str(), -1, NULL, 0);
		if (cchW <= 0)
			return sNt;

		std::wstring wsNt(static_cast<size_t>(cchW), 0);
		::MultiByteToWideChar(CP_UTF8, 0, sNt.c_str(), -1, &wsNt[0], cchW);
		if (!wsNt.empty() && wsNt.back() == L'\0')
			wsNt.pop_back();

		wchar_t sDrives[27 * 4] = {};
		if (::GetLogicalDriveStringsW(DWORD(std::size(sDrives)), sDrives) == 0)
			return sNt;

		wchar_t* sDrv = sDrives;
		while (sDrv[0])
		{
			sDrv[2] = 0;
			wchar_t szTarget[MAX_PATH] = {};
			if (::QueryDosDeviceW(sDrv, szTarget, MAX_PATH) > 0)
			{
				std::wstring wsDevice(szTarget);
				if (wsNt.compare(0, wsDevice.size(), wsDevice) == 0 &&
					(wsNt.size() == wsDevice.size() || wsNt[wsDevice.size()] == L'\\'))
				{
					std::wstring sDrive(sDrv);
					sDrive.resize(2); // "C:"
					std::wstring wsRes = sDrive + wsNt.substr(wsDevice.size());

					int cchA = ::WideCharToMultiByte(CP_UTF8, 0, wsRes.c_str(), -1, NULL, 0, NULL, NULL);
					if (cchA > 0)
					{
						std::string sRes(static_cast<size_t>(cchA), 0);
						::WideCharToMultiByte(CP_UTF8, 0, wsRes.c_str(), -1, &sRes[0], cchA, NULL, NULL);
						if (!sRes.empty() && sRes.back() == '\0')
							sRes.pop_back();
						return sRes;
					}
				}
			}
			sDrv += 4;
		}
		return sNt;
	}

} // namespace

//
//
//
void DetectionNotifier::finalConstruct(Variant vConfig)
{
	TRACE_BEGIN;
	if (!vConfig.isDictionaryLike())
		error::InvalidArgument(SL, "finalConstruct() supports only dictionary as a parameter")
		.throwException();

	m_nMaxSize = vConfig.get("maxSize", m_nMaxSize);
	if (m_nMaxSize == 0)
		m_nMaxSize = 1;

	TRACE_END("Error during configuration");
}

//
//
//
bool DetectionNotifier::isDetectionEvent(const Variant& vEvent)
{
	if (!vEvent.isDictionaryLike())
		return false;

	// MLE detection events in the cloud output format have 'baseType' in
	// the MLE range (>= 1000000, see common.src constants).
	auto vBaseType = vEvent.getSafe("baseType");
	if (vBaseType.has_value() && vBaseType->getType() == variant::ValueType::Integer)
		return (static_cast<int64_t>(vBaseType.value()) >= c_nMinMleBaseType);

	// Fallback for non-cloud (raw) events with 'scheme' field.
	auto vScheme = vEvent.getSafe("scheme");
	if (vScheme.has_value() && vScheme->getType() == variant::ValueType::String)
		return (std::string(vScheme.value()) == "mle");

	return false;
}

//
//
//
Variant DetectionNotifier::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN;
	using variant::getByPathSafe;
	LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	if (vCommand == "put")
	{
		if (!vParams.has("data"))
			error::InvalidArgument(SL, "Missing field <data> in parameters").throwException();

		Variant vEvent = vParams["data"];
		if (!isDetectionEvent(vEvent))
			return {};

		// Provide X mark critical severity flag in any detection (that is not a HIPS alert)
		// as requested by the user, so the GUI can parse it as a critical threat.
		vEvent.put("severity", int64_t(3)); // 3 maps to asCritical (X mark)
		vEvent.put("alert_kind", "critical");

		// Auto-generate a human-readable <title> so GUI consumers always have
		// one; neither policy createEvent data nor the FLS verdict path sets
		// it themselves (root cause of "no title" toasts).
		if (!vEvent.has("title") || std::string(vEvent["title"]).empty())
		{
			std::string sTitle = vEvent.get("type", std::string());
			if (sTitle.empty())
			{
				auto optBaseType = getByPathSafe(vEvent, "baseType");
				if (optBaseType.has_value())
					sTitle = std::string(optBaseType.value());
			}

			auto extractValidPath = [&](const std::string_view& pathKey) -> std::string {
				if (auto optP = getByPathSafe(vEvent, pathKey)) {
					std::string str = std::string(optP.value());
					if (!str.empty() && str != "<undefined>" && str != "null")
						return str;
				}
				return {};
			};

			std::string sPath = extractValidPath("quarantineTarget");

			if (sPath.empty())
			{
				if (std::string p = extractValidPath("childProcess.imageFile.abstractPath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("childProcess.imageFile.rawPath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("childProcess.imagePath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("process.imageFile.abstractPath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("process.imageFile.rawPath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("process.imagePath"); !p.empty())
					sPath = p;
				else if (std::string p = extractValidPath("processes[0].imagePath"); !p.empty())
					sPath = p;
				else
				{
					int64_t fv = 0;
					if (auto optVerdictF = getByPathSafe(vEvent, "file.verdict"))
						try { fv = std::stoll(std::string(optVerdictF.value())); } catch (...) {}
					if (fv == 2)
					{
						if (std::string p = extractValidPath("file.abstractPath"); !p.empty())
							sPath = p;
						else if (std::string p = extractValidPath("file.rawPath"); !p.empty())
							sPath = p;
						else if (std::string p = extractValidPath("file.path"); !p.empty())
							sPath = p;
					}
				}
			}


			// Update vEvent so quarantineTarget is explicitly populated in the event JSON dictionary
			if (!sPath.empty())
				vEvent.put("quarantineTarget", sPath);

			if (!sPath.empty())
				sTitle += (sTitle.empty() ? "" : ": ") + sPath;

			if (!sTitle.empty())
				vEvent.put("title", sTitle);
				
			// Determine action based on verdict
			int64_t nVerdict = 0;
			if (auto optVerdict = getByPathSafe(vEvent, "childProcess.verdict"))
			{
				try { nVerdict = std::stoll(std::string(optVerdict.value())); } catch (...) {}
			}
			else if (auto optVerdictP = getByPathSafe(vEvent, "process.imageFile.verdict"))
			{
				try { nVerdict = std::stoll(std::string(optVerdictP.value())); } catch (...) {}
			}
			else if (auto optVerdictF = getByPathSafe(vEvent, "file.verdict"))
			{
				try { nVerdict = std::stoll(std::string(optVerdictF.value())); } catch (...) {}
			}
			
			// Kill the offending process FIRST via kernel driver (edrdrv)
			uint64_t nGid = 0;
			if (auto optGid = getByPathSafe(vEvent, "childProcess.id"))
			{
				try { nGid = std::stoull(std::string(optGid.value())); } catch (...) {}
			}
			else if (auto optGidP = getByPathSafe(vEvent, "process.id"))
			{
				try { nGid = std::stoull(std::string(optGidP.value())); } catch (...) {}
			}
			else if (auto optProcId = getByPathSafe(vEvent, "processes[0].id"))
			{
				try { nGid = std::stoull(std::string(optProcId.value())); } catch (...) {}
			}
			
			if (nGid > 0)
			{
				HANDLE hDev = ::CreateFileW(L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}", 
					GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hDev != INVALID_HANDLE_VALUE)
				{
					#pragma pack(push, 1)
					struct COM_MESSAGE {
						uint32_t msgType;
						uint32_t pid;
						uint64_t gid;
						WCHAR path[260];
						WCHAR quarantinePath[260];
					};
					#pragma pack(pop)
					
					COM_MESSAGE msg = {0};
					msg.msgType = 6; // MESSAGE_KILL_ONLY_GID
					msg.gid = nGid;
					
					DWORD retBytes = 0;
					uint32_t output = 0;
					DWORD IOCTL_OWLY = (0x00000022 << 16) | (0 << 14) | (0x921 << 2) | 0; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)
					
					if (::DeviceIoControl(hDev, IOCTL_OWLY, &msg, sizeof(msg), &output, sizeof(output), &retBytes, NULL))
						LOGLVL(Critical, FMT("detnotif: successfully KILLED malicious process GID=" << nGid << " via edrdrv IOCTL"));
					else
						LOGLVL(Critical, FMT("detnotif: FAILED to kill malicious process GID=" << nGid << " via edrdrv IOCTL. err=" << ::GetLastError()));
						
					::CloseHandle(hDev);
				}
				else
				{
					LOGLVL(Critical, FMT("detnotif: Could not open edrdrv IOCTL device to kill GID=" << nGid));
				}
			}
				
			// Use owlyshield_ransom.dll to quarantine the malicious file ONLY IF verdict != 1
			if (!sPath.empty())
			{
				if (nVerdict == 1)
				{
					LOGLVL(Detailed, FMT("detnotif: Target <" << sPath << "> is Trusted (verdict=1). KILL ONLY. Skipping quarantine."));
				}
				else
				{
					HMODULE hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
					if (hDll != nullptr)
					{
						typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
						auto fnQ = (QuarantineFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file");
						if (fnQ != nullptr)
						{
							std::string sDos = NtPathToDosPathString(sPath);
							int32_t qRes = fnQ(
								reinterpret_cast<const uint8_t*>(sDos.data()),
								static_cast<uint32_t>(sDos.size()));
							if (qRes == 0)
								LOGLVL(Critical, FMT("detnotif: owlyshield quarantined malware <" << sDos << ">"));
							else
								LOGLVL(Critical, FMT("detnotif: owlyshield quarantine FAILED for <" << sDos << "> result=" << qRes));
						}
						else
						{
							LOGLVL(Critical, "detnotif: owlyshield_ransom.dll loaded, but owlyshield_dll_quarantine_file function not found!");
						}
						::FreeLibrary(hDll);
					}
					else
					{
						LOGLVL(Critical, "detnotif: FAILED to load owlyshield_ransom.dll! Cannot quarantine malware.");
					}
				}
			}
			else
			{
				LOGLVL(Critical, "detnotif: quarantineTarget path is empty! Cannot quarantine anything.");
			}
		}

		{
			std::scoped_lock _lock(m_mtxStorage);

			int64_t nId = ++m_nLastId;
		Variant vEntry = Dictionary({ {"id", nId}, {"event", vEvent} });
		m_storage.push_back(std::move(vEntry));


		while (m_storage.size() > m_nMaxSize)
			m_storage.pop_front();
		}

		LOGLVL(Detailed, "Detection event <" << vEvent.get("type", "<undefined>") << "> is stored (id <" << m_nLastId << ">)");
		return {};
	}

	if (vCommand == "getDetections")
	{
		int64_t nLastId = 0;
		if (vParams.isDictionaryLike())
			nLastId = vParams.get("lastId", nLastId);

		Variant vEvents = Sequence();
		{
			std::scoped_lock _lock(m_mtxStorage);
			for (const auto& vEntry : m_storage)
			{
				if (static_cast<int64_t>(vEntry["id"]) > nLastId)
					vEvents.push_back(vEntry);
			}
		}

		LOGLVL(Debug, "Send <" << vEvents.getSize() << "> detection event(s) after id <" << nLastId << ">");
		return Dictionary({ {"lastId", m_nLastId}, {"events", vEvents} });
	}

	if (vCommand == "getLastDetectionId")
	{
		std::scoped_lock _lock(m_mtxStorage);
		return Dictionary({ {"lastId", m_nLastId} });
	}

	error::OperationNotSupported(SL, FMT("Unsupported command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
}

} // namespace cmd

/// @}