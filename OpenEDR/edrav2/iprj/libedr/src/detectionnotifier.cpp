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

			std::string sPath;
			static const char* const c_pPaths[] = {
				"processes[0].imagePath",
				"process.imageFile.abstractPath",
				"process.imageFile.path",
				"process.imagePath",
				"target.imageFile.abstractPath",
				"target.imageFile.path",
				"destination.abstractPath",
				"destination.path",
				"file.abstractPath",
				"file.path"
			};
			for (const char* pszField : c_pPaths)
			{
				auto optField = getByPathSafe(vEvent, pszField);
				if (optField.has_value() && !std::string(optField.value()).empty())
				{
					sPath = std::string(optField.value());
					break;
				}
			}

			if (!sPath.empty())
				sTitle += (sTitle.empty() ? "" : ": ") + sPath;

			if (!sTitle.empty())
				vEvent.put("title", sTitle);
		}

		{
			std::scoped_lock _lock(m_mtxStorage);

			int64_t nId = ++m_nLastId;
		Variant vEntry = Dictionary({ {"id", nId}, {"event", vEvent} });
		m_storage.push_back(std::move(vEntry));

		// --- ENFORCEMENT: terminate + quarantine on every detection ---
		{
			std::vector<DWORD> vPidsToKill;

			// Check childProcess.pid
			auto optChildPid = getByPathSafe(vEvent, "childProcess.pid");
			if (optChildPid.has_value())
			{
				int64_t pidVal = (int64_t)optChildPid.value();
				if (pidVal > 4) vPidsToKill.push_back(static_cast<DWORD>(pidVal));
			}

			// Check process.pid
			auto optProcPid = getByPathSafe(vEvent, "process.pid");
			if (optProcPid.has_value())
			{
				int64_t pidVal = (int64_t)optProcPid.value();
				if (pidVal > 4) vPidsToKill.push_back(static_cast<DWORD>(pidVal));
			}

			// Check processes array
			auto optProcesses = getByPathSafe(vEvent, "processes");
			if (optProcesses.has_value() && optProcesses.value().isSequenceLike())
			{
				Variant vProcsSeq = optProcesses.value();
				size_t nSize = vProcsSeq.getSize();
				for (size_t idx = 0; idx < nSize; ++idx)
				{
					Variant vP = vProcsSeq.get(idx);
					int64_t nVerd = (int64_t)vP.get("verdict", int64_t(0));
					int64_t nFlsVerd = (int64_t)vP.get("flsVerdict", int64_t(0));
					int64_t nPidVal = (int64_t)vP.get("pid", int64_t(0));

					// If process verdict is malicious (3) or it's the last process in chain of MLE detection
					if (nPidVal > 4 && (nVerd == 3 || nFlsVerd == 3 || idx == nSize - 1))
					{
						vPidsToKill.push_back(static_cast<DWORD>(nPidVal));
					}
				}
			}

			for (DWORD dwPid : vPidsToKill)
			{
				// Skip system critical PIDs
				if (dwPid <= 4) continue;

				HANDLE hProc = ::OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, dwPid);
				if (hProc != nullptr)
				{
					// Extra safety check: verify image path before killing
					wchar_t szPath[MAX_PATH] = { 0 };
					DWORD dwSize = MAX_PATH;
					if (::QueryFullProcessImageNameW(hProc, 0, szPath, &dwSize))
					{
						std::wstring wsPath(szPath);
						std::string sPathStr(wsPath.begin(), wsPath.end());
						std::transform(sPathStr.begin(), sPathStr.end(), sPathStr.begin(), ::tolower);
						if (sPathStr.find("winlogon.exe") != std::string::npos ||
							sPathStr.find("userinit.exe") != std::string::npos ||
							sPathStr.find("explorer.exe") != std::string::npos ||
							sPathStr.find("svchost.exe") != std::string::npos ||
							sPathStr.find("csrss.exe") != std::string::npos ||
							sPathStr.find("smss.exe") != std::string::npos ||
							sPathStr.find("services.exe") != std::string::npos ||
							sPathStr.find("lsass.exe") != std::string::npos)
						{
							::CloseHandle(hProc);
							continue;
						}
					}
					::TerminateProcess(hProc, 1);
					::WaitForSingleObject(hProc, 3000);
					::CloseHandle(hProc);
					LOGLVL(Critical, FMT("DetectionNotifier: terminated malicious pid=" << dwPid));
				}
			}
		}

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