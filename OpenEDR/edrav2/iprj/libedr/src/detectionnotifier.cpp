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
#include "eventenricher.h"

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

	// Threat detections MUST have baseType or baseEventType in the MLE detection range (>= 1000000).
	// Raw EVM events (e.g. RF12.11 with baseEventType=11) are telemetry events, not threat detections.
	int64_t nBaseType = 0;
	if (auto optBt = vEvent.getSafe("baseType"))
	{
		try { nBaseType = static_cast<int64_t>(optBt.value()); } catch (...) {}
	}
	else if (auto optBet = vEvent.getSafe("baseEventType"))
	{
		try { nBaseType = static_cast<int64_t>(optBet.value()); } catch (...) {}
	}

	return (nBaseType >= c_nMinMleBaseType);
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
				static const std::string_view candidateKeys[] = {
					"childProcess.imageFile.abstractPath",
					"childProcess.imageFile.rawPath",
					"childProcess.imagePath",
					"process.imageFile.abstractPath",
					"process.imageFile.rawPath",
					"process.imagePath"
				};

				for (const auto& key : candidateKeys)
				{
					sPath = extractValidPath(key);
					if (!sPath.empty())
						break;
				}

				if (sPath.empty() && vEvent.has("processes"))
				{
					try {
						auto vSeq = vEvent.get("processes");
						if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
						{
							auto vLeaf = vSeq[vSeq.getSize() - 1];
							if (vLeaf.has("imagePath"))
							{
								std::string leafPath = std::string(vLeaf["imagePath"]);
								if (!leafPath.empty() && leafPath != "<undefined>" && leafPath != "null")
									sPath = leafPath;
							}
						}
					} catch (...) {}
				}

				if (sPath.empty())
				{
					int64_t fv = 0;
					if (auto optVerdictF = getByPathSafe(vEvent, "file.verdict"))
						try { fv = std::stoll(std::string(optVerdictF.value())); } catch (...) {}
					if (fv == 2)
					{
						static const std::string_view fileKeys[] = {
							"file.abstractPath",
							"file.rawPath",
							"file.path"
						};
						for (const auto& key : fileKeys)
						{
							sPath = extractValidPath(key);
							if (!sPath.empty())
								break;
						}
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
			else if (vEvent.has("processes"))
			{
				try {
					auto vSeq = vEvent.get("processes");
					if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
					{
						auto vLeaf = vSeq[vSeq.getSize() - 1];
						if (vLeaf.has("id"))
							nGid = std::stoull(std::string(vLeaf["id"]));
					}
				} catch (...) {}
			}
			
			if (nGid > 0)
			{
				{
					std::scoped_lock lock(m_mtxKilledGids);
					if (m_killedGids.count(nGid))
					{
						LOGLVL(Detailed, FMT("detnotif: GID=" << nGid << " already killed, skipping duplicate kill"));
						nGid = 0;
					}
					else
					{
						m_killedGids.insert(nGid);
					}
				}
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

			// Execute automatic file rollback for victim files
			int64_t nThreatPid = 0;
			if (auto optPid = getByPathSafe(vEvent, "childProcess.pid"))
				try { nThreatPid = std::stoll(std::string(optPid.value())); } catch (...) {}
			else if (auto optPidP = getByPathSafe(vEvent, "process.pid"))
				try { nThreatPid = std::stoll(std::string(optPidP.value())); } catch (...) {}
			else if (vEvent.has("processes"))
			{
				try {
					auto vSeq = vEvent.get("processes");
					if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
					{
						auto vLeaf = vSeq[vSeq.getSize() - 1];
						if (vLeaf.has("pid"))
							nThreatPid = std::stoll(std::string(vLeaf["pid"]));
					}
				} catch (...) {}
			}

			if (nThreatPid > 0)
			{
				EventEnricher::rollbackRansomBackups(nThreatPid);
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