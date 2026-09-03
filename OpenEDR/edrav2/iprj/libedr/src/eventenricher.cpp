//
// edrav2.libedr project
//
// Event Enricher implementation
//
// Author: Denis Kroshin (09.07.2019)
// Reviewer: Denis Bogdanov (xx.xx.2019)
//
#include "pch.h"
#include "eventenricher.h"
#include "detectionnotifier.h"
#include <fstream>
#include <mutex>
#include <atomic>
#include <chrono>
#include <filesystem>

namespace cmd {

#undef CMD_COMPONENT
#define CMD_COMPONENT "enricher"

namespace {
	bool containsInterpetatorCmd(const std::wstring& cmdLine)
	{
		return (cmdLine.find(L"cmd.exe") != std::string::npos)
			|| (cmdLine.find(L"python.exe") != std::string::npos)
			|| (cmdLine.find(L"py3.exe") != std::string::npos)
			|| (cmdLine.find(L"py.exe") != std::string::npos)
			|| (cmdLine.find(L"powershell.exe") != std::string::npos)
			|| (cmdLine.find(L"powershell_ise.exe") != std::string::npos);
	}

	std::wstring getFilePath(std::wstring str)
	{
		const std::wstring executableExt(L".exe");
		auto commandEnd = str.find(executableExt);

		if (commandEnd == std::wstring::npos)
			return L"";

		str.erase(str.begin(), str.begin() + commandEnd + executableExt.length());

		const std::wregex filePathRegex(LR"([A-Za-z]:.*(\.cmd|\.bat|\.ps1|\.py))");

		str.erase(remove_if(str.begin(), str.end(), [](const wchar_t& sym) {return sym == L'\"'; }), str.end());

		std::wsmatch match;

		const std::wstring& str2 = str;

		if (std::regex_search(str2.begin(), str2.end(), match, filePathRegex))
			return match[0];

		return L"";
	}

	Variant readContent(const std::wstring& filePath)
	{
		std::ifstream fileStream(filePath);

		const uintmax_t fileContentLimit = 100000;
		const uintmax_t size = std::clamp<uintmax_t>(std::filesystem::file_size(filePath), 0, fileContentLimit);

		if (size == 0)
			return {};
		
		std::string content(size, '\0');
		fileStream.read(content.data(), size);

		return content;
	}

	// char-stream friendly narrowing for log lines (lossy beyond ASCII).
	std::string Narrow(const std::wstring& wsIn)
	{
		std::string sOut;
		sOut.reserve(wsIn.size());
		for (wchar_t wc : wsIn)
			sOut.push_back(static_cast<char>(wc));
		return sOut;
	}

	// Converts \Device\HarddiskVolumeN\... to C:\... style DOS path
	// using GetLogicalDriveStringsW + QueryDosDeviceW (same approach as
	// FileDataProvider::convertNtPathToDosPath).
	static std::wstring NtPathToDosPath(const std::wstring& wsNt)
	{
		wchar_t sDrives[27 * 4] = {};
		if (::GetLogicalDriveStringsW(DWORD(std::size(sDrives)), sDrives) == 0)
			return wsNt;

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
					return sDrive + wsNt.substr(wsDevice.size());
				}
			}
			sDrv += 4;
		}
		return wsNt;
	}

	static std::wstring NormalizeToDosPath(std::wstring p)
	{
		if (p.rfind(L"\\??\\", 0) == 0)
			p = p.substr(4);
		else if (p.rfind(L"\\\\?\\", 0) == 0)
			p = p.substr(4);
		return NtPathToDosPath(p);
	}

	// JSON string escape (backslash, quotes, control chars)
	std::string JsonEscape(const std::wstring& wsIn)
	{
		const std::string s = Narrow(wsIn);
		std::string out;
		out.reserve(s.size() + 16);
		char szBuf[8];
		for (char c : s)
		{
			switch (c)
			{
			case '"': out += "\\\""; break;
			case '\\': out += "\\\\"; break;
			case '\b': out += "\\b"; break;
			case '\f': out += "\\f"; break;
			case '\n': out += "\\n"; break;
			case '\r': out += "\\r"; break;
			case '\t': out += "\\t"; break;
			default:
				if ((unsigned char)c < 0x20)
				{
					sprintf_s(szBuf, sizeof(szBuf), "\\u%04x", (unsigned char)c);
					out += szBuf;
				}
				else
					out += c;
			}
		}
		return out;
	}

	// HKLM\SOFTWARE\Owlyshield!VERBOSE_LOGGING ("1") enables verbose
	// diagnostics for this component. Cached, re-read at most once per 2s.
	bool IsVerboseLoggingEnabled()
	{
		static std::atomic<bool> s_cached{ false };
		static std::atomic<uint64_t> s_last{ 0 };

		const uint64_t nNow = (uint64_t)std::chrono::duration_cast<
			std::chrono::milliseconds>(std::chrono::steady_clock::now()
				.time_since_epoch()).count();
		const uint64_t nLast = s_last.load(std::memory_order_relaxed);

		if (nNow - nLast >= 2000)
		{
			s_last.store(nNow, std::memory_order_relaxed);
			char sz[8] = "";
			ULONG cb = sizeof(sz);
			const LONG rc = ::RegGetValueA(HKEY_LOCAL_MACHINE,
				"SOFTWARE\\Owlyshield", "VERBOSE_LOGGING",
				RRF_RT_REG_SZ, nullptr, sz, &cb);
			s_cached.store(rc == ERROR_SUCCESS && std::string(sz) == "1",
				std::memory_order_relaxed);
		}
		return s_cached.load(std::memory_order_relaxed);
	}

	// HKLM\SOFTWARE\Owlyshield\SDK!TRAINING_MODE ("1") enables persistent
	// unknown behavior telemetry recording for offline ML training.
	bool IsTrainingModeEnabled()
	{
		static std::atomic<bool> s_cached{ true };
		static std::atomic<uint64_t> s_last{ 0 };

		const uint64_t nNow = (uint64_t)std::chrono::duration_cast<
			std::chrono::milliseconds>(std::chrono::steady_clock::now()
				.time_since_epoch()).count();
		const uint64_t nLast = s_last.load(std::memory_order_relaxed);

		if (nNow - nLast >= 2000)
		{
			s_last.store(nNow, std::memory_order_relaxed);
			char sz[8] = "";
			ULONG cb = sizeof(sz);
			const LONG rc = ::RegGetValueA(HKEY_LOCAL_MACHINE,
				"SOFTWARE\\Owlyshield\\SDK", "TRAINING_MODE",
				RRF_RT_REG_SZ, nullptr, sz, &cb);
			s_cached.store(rc == ERROR_SUCCESS ? (std::string(sz) == "1") : true,
				std::memory_order_relaxed);
		}
		return s_cached.load(std::memory_order_relaxed);
	}

	// Save unknown process behavior killchain telemetry into training dataset
	void AppendToTrainingDataset(const std::string& sExePath, const std::string& sEventType, const std::string& sDetails, const std::string& sJson)
	{
		char szProgramData[MAX_PATH] = "";
		DWORD nLen = ::GetEnvironmentVariableA("PROGRAMDATA", szProgramData, MAX_PATH);
		if (nLen == 0 || nLen >= MAX_PATH)
			return;

		SYSTEMTIME st = {};
		::GetLocalTime(&st);

		std::filesystem::path dir = std::filesystem::path(szProgramData) /
			"edrsvc" / "training_data";
		std::error_code ec;
		std::filesystem::create_directories(dir, ec);

		wchar_t szFile[64] = L"";
		swprintf_s(szFile, L"unknown_killchain_%04u%02u%02u.jsonl",
			st.wYear, st.wMonth, st.wDay);

		std::ofstream stream(dir / szFile, std::ios::app);
		if (!stream)
			return;

		char szTime[32] = "";
		sprintf_s(szTime, "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

		// Record formatted killchain sequence line
		stream << "{\"time\":\"" << szTime << "\",\"exe\":\"" << sExePath << "\",\"event\":\""
		       << sEventType << "\",\"details\":\"" << sDetails << "\",\"raw\":" << sJson << "}\n";
	}

	// Append a JSON line into ProgramData\edrsvc\log\output_events\
	// (same stream the Owlyshield behavioral alerts use).
	void AppendToOutputEvents(const std::string& sJsonLine)
	{
		char szProgramData[MAX_PATH] = "";
		DWORD nLen = ::GetEnvironmentVariableA("PROGRAMDATA", szProgramData, MAX_PATH);
		if (nLen == 0 || nLen >= MAX_PATH)
			return;

		SYSTEMTIME stToday = {};
		::GetLocalTime(&stToday);

		std::filesystem::path dir = std::filesystem::path(szProgramData) /
			"edrsvc" / "log" / "output_events";
		std::error_code ec;
		std::filesystem::create_directories(dir, ec);

		wchar_t szFile[64] = L"";
		swprintf_s(szFile, L"owlyshield_%04u%02u%02u.log",
			stToday.wYear, stToday.wMonth, stToday.wDay);

		std::ofstream stream(dir / szFile, std::ios::app);
		if (!stream)
			return;
		stream << sJsonLine << "\n";
	}

	// Forward enriched event to Owlyshield FastDetect ML engine
	static void ForwardToOwlyshieldMlEngine(const Variant& vEvent)
	{
		static HMODULE s_hOwlyDll = nullptr;
		typedef int32_t (*IngestOpenedrEventFn)(const uint8_t*, uint32_t);
		static IngestOpenedrEventFn s_fnIngest = nullptr;
		static std::once_flag s_initFlag;

		std::call_once(s_initFlag, []() {
			s_hOwlyDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
			if (s_hOwlyDll != nullptr)
			{
				s_fnIngest = (IngestOpenedrEventFn)::GetProcAddress(s_hOwlyDll, "owlyshield_dll_ingest_openedr_event");
			}
		});

		if (s_fnIngest != nullptr)
		{
			try
			{
				std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
				if (!sJson.empty())
				{
					s_fnIngest(reinterpret_cast<const uint8_t*>(sJson.data()), static_cast<uint32_t>(sJson.size()));
				}
			}
			catch (...) {}
		}

		// Also send rich event telemetry to the Pascal GUI via HydraHipEvent named pipe
		try
		{
			std::string sPath;
			if (auto optP = variant::getByPathSafe(vEvent, "process.imageFile.abstractPath"))
				sPath = std::string(optP.value());
			else if (auto optP2 = variant::getByPathSafe(vEvent, "process.imageFile.rawPath"))
				sPath = std::string(optP2.value());
			else if (auto optP3 = variant::getByPathSafe(vEvent, "childProcess.imageFile.abstractPath"))
				sPath = std::string(optP3.value());

			std::string sType = vEvent.get("type", std::string());
			if (sType.empty()) sType = vEvent.get("eventType", std::string());

			if (!sPath.empty() && !sType.empty())
			{
				std::string sDetails;
				// Extract file target
				if (auto optF = variant::getByPathSafe(vEvent, "file.path"))
					sDetails = " [File: " + std::string(optF.value()) + "]";
				else if (auto optF2 = variant::getByPathSafe(vEvent, "file.rawPath"))
					sDetails = " [File: " + std::string(optF2.value()) + "]";
				// Extract registry target
				else if (auto optR = variant::getByPathSafe(vEvent, "registry.path"))
					sDetails = " [Reg: " + std::string(optR.value()) + "]";
				// Extract API hook function
				else if (auto optA = variant::getByPathSafe(vEvent, "owlyHook.apiFunction"))
					sDetails = " [API: " + std::string(optA.value()) + "]";
				// Extract network destination
				else if (auto optN = variant::getByPathSafe(vEvent, "network.destinationAddress"))
					sDetails = " [Net: " + std::string(optN.value()) + "]";

				// Save telemetry to persistent training dataset for offline Dynamic ML model training
				if (IsTrainingModeEnabled())
				{
					try
					{
						std::string sJson = variant::serializeToJson(vEvent, variant::JsonFormat::SingleLine);
						AppendToTrainingDataset(sPath, sType, sDetails, sJson);
					}
					catch (...) {}
				}

				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string pipeMsg = "BEHAVIOR_EVENT:" + sPath + "|" + sType + sDetails + "\n";
					DWORD written = 0;
					::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}
			}
		}
		catch (...) {}
	}
}

//
//
//
//
// System areas are never backed-up/restored/flagged: services and OS
// components rewrite their own databases/logs constantly and would
// otherwise trip the shield (evtx, EBWebView cache, ...).
//
namespace {
	std::mutex s_mtxRansomShield;
	// pid -> { victim path -> kernel-saved pre-image path }
	std::unordered_map<int64_t, std::unordered_map<std::wstring, std::wstring>> s_readFiles;
	std::unordered_map<std::wstring, std::wstring> s_allPreImages; // global victim path -> backup path
	std::unordered_map<int64_t, std::vector<EventEnricher::ShadowBackupEntry>> s_backups;

	static bool endsWithCaseInsensitive(const std::wstring& str, const std::wstring& suffix)
	{
		if (str.size() < suffix.size()) return false;
		return _wcsicmp(str.c_str() + str.size() - suffix.size(), suffix.c_str()) == 0;
	}

	static bool containsCaseInsensitive(const std::wstring& str, const std::wstring& sub)
	{
		if (sub.empty() || str.empty() || str.size() < sub.size()) return false;
		auto it = std::search(str.begin(), str.end(), sub.begin(), sub.end(),
			[](wchar_t ch1, wchar_t ch2) { return towlower(ch1) == towlower(ch2); });
		return it != str.end();
	}

	static std::wstring findPreImageOnDisk(int64_t nPid, const std::wstring& wsOrig)
	{
		std::wstring wsBaseName = wsOrig;
		auto pos = wsBaseName.find_last_of(L"\\/");
		if (pos != std::wstring::npos)
			wsBaseName = wsBaseName.substr(pos + 1);

		if (wsBaseName.empty())
			return L"";

		std::wstring wsStripped;
		auto dotPos = wsBaseName.find_last_of(L'.');
		if (dotPos != std::wstring::npos && dotPos > 0)
			wsStripped = wsBaseName.substr(0, dotPos);

		// 1. In-memory global pre-image index (case-insensitive)
		{
			std::scoped_lock _lock(s_mtxRansomShield);
			for (const auto& [victim, bk] : s_allPreImages)
			{
				if (_wcsicmp(victim.c_str(), wsOrig.c_str()) == 0 && !bk.empty())
					return bk;
			}

			if (!wsStripped.empty())
			{
				for (const auto& [victim, bk] : s_allPreImages)
				{
					if (containsCaseInsensitive(victim, wsStripped) && !bk.empty())
						return bk;
				}
			}
		}

		// 2. Disk search under C:\ProgramData\HydraDragonBackups
		try
		{
			std::filesystem::path rootDir = L"C:\\ProgramData\\HydraDragonBackups";
			if (!std::filesystem::exists(rootDir))
				return L"";

			auto checkDir = [&](const std::filesystem::path& dirPath) -> std::wstring {
				if (!std::filesystem::exists(dirPath) || !std::filesystem::is_directory(dirPath))
					return L"";

				for (const auto& entry : std::filesystem::directory_iterator(dirPath))
				{
					if (!entry.is_regular_file()) continue;

					std::wstring fn = entry.path().filename().wstring();
					std::wstring target1 = L"_" + wsBaseName;
					if (endsWithCaseInsensitive(fn, target1))
					{
						return entry.path().wstring();
					}
					if (!wsStripped.empty())
					{
						std::wstring target2 = L"_" + wsStripped;
						if (endsWithCaseInsensitive(fn, target2))
						{
							return entry.path().wstring();
						}
					}
				}
				return L"";
			};

			// Primary check: Current PID's backup directory
			std::filesystem::path primaryDir = rootDir / std::to_wstring(nPid);
			std::wstring wsFound = checkDir(primaryDir);
			if (!wsFound.empty())
				return wsFound;

			// Global search: Check all other PID subdirectories
			if (std::filesystem::is_directory(rootDir))
			{
				for (const auto& subDir : std::filesystem::directory_iterator(rootDir))
				{
					if (subDir.is_directory() && subDir.path() != primaryDir)
					{
						std::wstring wsRes = checkDir(subDir.path());
						if (!wsRes.empty())
							return wsRes;
					}
				}
			}
		}
		catch (...)
		{
		}

		return L"";
	}
}

void EventEnricher::recordShadowBackup(int64_t nPid, Event eEventType, const Variant& vEvent)
{
	if (nPid <= 0)
		return;

	switch (eEventType)
	{
	case Event::LLE_PROCESS_DELETE:
	{
		std::scoped_lock _lock(s_mtxRansomShield);
		s_readFiles.erase(nPid);
		s_backups.erase(nPid);
		return;
	}
	default:
		break;
	}

	std::wstring wsFilePath;
	std::wstring wsNewName;
	try
	{
		Variant vFile = vEvent.get("file");
		wsFilePath = vFile.get("path", L"");
		if (wsFilePath.empty())
			wsFilePath = vFile.get("rawPath", L"");
		if (wsFilePath.empty())
			wsFilePath = vFile.get("uniquePath", L"");
		if (wsFilePath.empty())
			wsFilePath = vFile.get("abstractPath", L"");

		wsFilePath = NormalizeToDosPath(wsFilePath);

		if (vFile.has("renameTarget"))
		{
			wsNewName = vFile.get("renameTarget", L"");
			wsNewName = NormalizeToDosPath(wsNewName);
		}
	}
	catch (...)
	{
		return;
	}

	if (wsFilePath.empty())
		return;

	{
		std::scoped_lock _lock(s_mtxRansomShield);
		auto& readMap = s_readFiles[nPid];

		switch (eEventType)
		{
		case Event::LLE_FILE_DATA_READ_FULL:
		case Event::LLE_FILE_MAP_READ:
		{
			std::wstring wsBk;
			try
			{
				Variant vF = vEvent.get("file");
				wsBk = vF.get("backupPath", L"");
				wsBk = NormalizeToDosPath(wsBk);
			}
			catch (...) {}
			if (!wsBk.empty())
				s_allPreImages[wsFilePath] = wsBk;
			readMap[wsFilePath] = std::move(wsBk);
			return;
		}

		case Event::LLE_FILE_CREATE:
		case Event::LLE_FILE_PREIMAGE_SAVED:
		case Event::LLE_FILE_DATA_WRITE_FULL:
		case Event::LLE_FILE_DATA_CHANGE:
		case Event::LLE_FILE_MAP_WRITE:
		case Event::LLE_FILE_DELETE:
		case Event::LLE_FILE_RENAME:
		{
			constexpr size_t c_nMaxBackupsPerProcess = 1000;
			auto& vec = s_backups[nPid];
			if (vec.size() < c_nMaxBackupsPerProcess)
			{
				ShadowBackupEntry entry;
				entry.wsOriginal = wsFilePath;
				entry.nOp = (eEventType == Event::LLE_FILE_CREATE) ? 3 :
					(eEventType == Event::LLE_FILE_DATA_WRITE_FULL ||
					 eEventType == Event::LLE_FILE_DATA_CHANGE ||
					 eEventType == Event::LLE_FILE_MAP_WRITE) ? 0 :
					(eEventType == Event::LLE_FILE_DELETE) ? 1 : 2;
				entry.wsNewName = wsNewName;

				std::wstring wsBkInEvent;
				try {
					wsBkInEvent = vEvent.get("file").get("backupPath", L"");
				} catch (...) {}

				if (!wsBkInEvent.empty())
				{
					entry.wsBackup = NormalizeToDosPath(wsBkInEvent);
					readMap[wsFilePath] = entry.wsBackup;
					s_allPreImages[wsFilePath] = entry.wsBackup;
				}
				else
				{
					auto itBk = readMap.find(wsFilePath);
					if (itBk != readMap.end())
						entry.wsBackup = itBk->second;
					else
					{
						for (const auto& [rf, bk] : readMap)
						{
							if (_wcsicmp(rf.c_str(), wsFilePath.c_str()) == 0 && !bk.empty())
							{
								entry.wsBackup = bk;
								break;
							}
						}
					}
					if (entry.wsBackup.empty())
					{
						auto itGlobal = s_allPreImages.find(wsFilePath);
						if (itGlobal != s_allPreImages.end())
							entry.wsBackup = itGlobal->second;
						else
						{
							for (const auto& [victim, bk] : s_allPreImages)
							{
								if (_wcsicmp(victim.c_str(), wsFilePath.c_str()) == 0 && !bk.empty())
								{
									entry.wsBackup = bk;
									break;
								}
							}
						}
					}
				}
				vec.push_back(std::move(entry));
			}
			break;
		}

		default:
			break;
		}
	}
}

void EventEnricher::handleThreatRemediation(int64_t nPid, const std::wstring& /* sImage */, const std::string& sThreatName)
{
	if (nPid <= 0)
		return;

	LOGLVL(Critical, FMT("ThreatRemediation: executing complete rollback & kill for pid="
		<< nPid << " threat=" << sThreatName));

	// 1. File rollback from pre-images
	rollbackRansomBackups(nPid);

}

//
// Rolls back every captured original of <nPid>: restores modified/deleted
// files from their pre-images and removes rename targets.
//
/*static*/ void EventEnricher::rollbackRansomBackups(int64_t nPid)
{
	if (nPid <= 0)
		return;

	std::vector<ShadowBackupEntry> vec;
	std::unordered_map<std::wstring, std::wstring> readMapCopy;
	{
		std::scoped_lock _lock(s_mtxRansomShield);
		// 1. Drain primary PID backups
		auto it = s_backups.find(nPid);
		if (it != s_backups.end())
		{
			vec.insert(vec.end(), it->second.begin(), it->second.end());
			s_backups.erase(it);
		}
		// 2. Drain ALL other PIDs currently tracked in s_backups (child/helper processes)
		for (auto itOther = s_backups.begin(); itOther != s_backups.end(); )
		{
			vec.insert(vec.end(), itOther->second.begin(), itOther->second.end());
			itOther = s_backups.erase(itOther);
		}
		// 3. Drain all read maps across all PIDs
		for (auto itR = s_readFiles.begin(); itR != s_readFiles.end(); )
		{
			readMapCopy.insert(itR->second.begin(), itR->second.end());
			itR = s_readFiles.erase(itR);
		}
	}

	LOGLVL(Critical, FMT("RansomShield: rolling back " << vec.size() << " recorded victim file(s) across all active PIDs (triggered by PID=" << nPid << ")"));

	// Roll back newest-first so chained renames unwind correctly.
	std::unordered_set<std::wstring> restoredPaths;
	for (auto itEntry = vec.rbegin(); itEntry != vec.rend(); ++itEntry)
	{
		const ShadowBackupEntry& entry = *itEntry;

		if (!entry.wsNewName.empty())
		{
			if (::DeleteFileW(entry.wsNewName.c_str()))
				LOGLVL(Critical, FMT("RansomShield: DELETED ransomware rename target <" << Narrow(entry.wsNewName) << ">"));
			else
				LOGLVL(Detailed, FMT("RansomShield: rollback rename target already gone or delete failed <" << Narrow(entry.wsNewName) << ">"));
		}

		std::wstring wsBackup = entry.wsBackup;
		std::wstring wsRestoreTarget = entry.wsOriginal;

		if (wsBackup.empty())
		{
			auto itR = readMapCopy.find(entry.wsOriginal);
			if (itR != readMapCopy.end() && !itR->second.empty())
				wsBackup = itR->second;
		}

		if (wsBackup.empty())
			wsBackup = findPreImageOnDisk(nPid, entry.wsOriginal);

		if (wsBackup.empty())
		{
			// If no pre-image exists and this file was created by ransomware (e.g. .winball, C:\encrypted.txt, ransom notes), delete it!
			::SetFileAttributesW(entry.wsOriginal.c_str(), FILE_ATTRIBUTE_NORMAL);
			if (::DeleteFileW(entry.wsOriginal.c_str()))
			{
				LOGLVL(Critical, FMT("RansomShield: DELETED newly created ransomware artifact <" << Narrow(entry.wsOriginal) << ">"));
			}
			else
			{
				DWORD err = ::GetLastError();
				if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
				{
					::MoveFileExW(entry.wsOriginal.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
					LOGLVL(Critical, FMT("RansomShield: delete failed for newly created artifact <" << Narrow(entry.wsOriginal) << "> err=" << err << ", scheduled reboot delete"));
				}
			}
			continue;
		}

		// If entry.wsOriginal ends with a ransomware extension and backup exists for stripped path, restore to stripped path
		auto dotPos = wsRestoreTarget.find_last_of(L'.');
		if (dotPos != std::wstring::npos)
		{
			std::wstring wsBeforeDot = wsRestoreTarget.substr(0, dotPos);
			if (wsBeforeDot.find(L'.') != std::wstring::npos)
			{
				// Delete the encrypted file
				::DeleteFileW(wsRestoreTarget.c_str());
				wsRestoreTarget = wsBeforeDot;
			}
		}

		if (restoredPaths.insert(wsRestoreTarget).second)
		{
			// Block restore if the target or backup is known detected malware (e.g. Winball501Ransom.exe)
			std::string sNarrowTarget = Narrow(wsRestoreTarget);
			std::string sNarrowBackup = Narrow(wsBackup);
			if (DetectionNotifier::isKnownMalware(sNarrowTarget, "") || DetectionNotifier::isKnownMalware(sNarrowBackup, ""))
			{
				LOGLVL(Critical, FMT("RansomShield: BLOCKED restore of detected malware binary <" << sNarrowTarget << ">"));
				::SetFileAttributesW(wsRestoreTarget.c_str(), FILE_ATTRIBUTE_NORMAL);
				::DeleteFileW(wsRestoreTarget.c_str());
				continue;
			}

			// Reset readonly/hidden/system attributes on target to prevent ERROR_ACCESS_DENIED (err=5)
			::SetFileAttributesW(wsRestoreTarget.c_str(), FILE_ATTRIBUTE_NORMAL);
			::DeleteFileW(wsRestoreTarget.c_str());

			if (::CopyFileW(wsBackup.c_str(), wsRestoreTarget.c_str(), FALSE))
			{
				LOGLVL(Critical, FMT("RansomShield: restored <" << Narrow(wsRestoreTarget) << "> from <" << Narrow(wsBackup) << ">"));
			}
			else if (::MoveFileExW(wsBackup.c_str(), wsRestoreTarget.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
			{
				LOGLVL(Critical, FMT("RansomShield: restored (via MoveFileEx) <" << Narrow(wsRestoreTarget) << "> from <" << Narrow(wsBackup) << ">"));
			}
			else
			{
				LOGLVL(Critical, FMT("RansomShield: restore FAILED for <" << Narrow(wsRestoreTarget) << "> from <" << Narrow(wsBackup) << "> err=" << ::GetLastError()));
			}
		}
	}

	// Multi-PID disk sweep: Check ALL PID subdirectories in C:\ProgramData\HydraDragonBackups for remaining backups
	try
	{
		std::filesystem::path rootDir = L"C:\\ProgramData\\HydraDragonBackups";
		if (std::filesystem::exists(rootDir) && std::filesystem::is_directory(rootDir))
		{
			for (const auto& pidDir : std::filesystem::directory_iterator(rootDir))
			{
				if (!pidDir.is_directory()) continue;
				for (const auto& entry : std::filesystem::directory_iterator(pidDir.path()))
				{
					if (!entry.is_regular_file()) continue;
					std::wstring bkPath = entry.path().wstring();
					std::wstring fn = entry.path().filename().wstring();

					auto uPos = fn.find(L'_');
					if (uPos == std::wstring::npos || uPos + 1 >= fn.size()) continue;
					std::wstring originalName = fn.substr(uPos + 1);

					std::wstring wsTarget;
					{
						std::scoped_lock _lock(s_mtxRansomShield);
						for (const auto& [vPath, bPath] : s_allPreImages)
						{
							if (_wcsicmp(bPath.c_str(), bkPath.c_str()) == 0 || endsWithCaseInsensitive(vPath, originalName))
							{
								wsTarget = vPath;
								break;
							}
						}
					}

					if (!wsTarget.empty() && restoredPaths.insert(wsTarget).second)
					{
						std::string sNarrowTarget = Narrow(wsTarget);
						std::string sNarrowBk = Narrow(bkPath);
						if (DetectionNotifier::isKnownMalware(sNarrowTarget, "") || DetectionNotifier::isKnownMalware(sNarrowBk, ""))
						{
							LOGLVL(Critical, FMT("RansomShield (Sweep): BLOCKED restore of detected malware binary <" << sNarrowTarget << ">"));
							::SetFileAttributesW(wsTarget.c_str(), FILE_ATTRIBUTE_NORMAL);
							::DeleteFileW(wsTarget.c_str());
							continue;
						}

						::SetFileAttributesW(wsTarget.c_str(), FILE_ATTRIBUTE_NORMAL);
						::DeleteFileW(wsTarget.c_str());
						if (::CopyFileW(bkPath.c_str(), wsTarget.c_str(), FALSE) ||
							::MoveFileExW(bkPath.c_str(), wsTarget.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
						{
							LOGLVL(Critical, FMT("RansomShield (Multi-PID Disk Sweep): restored <" << Narrow(wsTarget) << "> from <" << Narrow(bkPath) << ">"));
						}
					}
				}
			}
		}
	}
	catch (...) {}
}

//
//
//
void EventEnricher::finalConstruct(Variant vConfig)
{
	m_pProcProvider = queryInterface<sys::win::IProcessInformation>(queryService("processDataProvider"));

	Variant vReceiver = vConfig.get("receiver");
	m_pReceiver = queryInterfaceSafe<IDataReceiver>(vReceiver);
	if (m_pReceiver == nullptr)
	{
		auto pCmdReceiver = queryInterfaceSafe<ICommand>(vReceiver);
		if (pCmdReceiver == nullptr)
			error::InvalidArgument(SL, FMT("Invalid 'receiver' parameter: " << vReceiver)).throwException();

		m_pReceiver = queryInterface<IDataReceiver>(createObject(CLSID_CommandDataReceiver,
			Dictionary({ {"command", pCmdReceiver} })));
	}
	
	std::scoped_lock _lock(m_mtxQueue);
	if (m_threadPool.getThreadsCount() == 0)
		m_threadPool.addThreads(1);
}

//
//
//
void EventEnricher::loadState(Variant /*vState*/)
{
}

//
//
//
cmd::Variant EventEnricher::saveState()
{
	return {};
}

//
//
//
void EventEnricher::start()
{
	TRACE_BEGIN
	LOGLVL(Detailed, "Event Enricher is being started");

	std::scoped_lock _lock(m_mtxStartStop);
	if (m_fInitialized)
	{
		LOGINF("Event Enricher already started");
		return;
	}
	m_fInitialized = true;

	LOGLVL(Detailed, "Event Enricher is started");
	TRACE_END("Fail to start Event Enricher");
}

//
//
//
void EventEnricher::stop()
{
	TRACE_BEGIN;
	LOGLVL(Detailed, "Event Enricher is being stopped");

	std::scoped_lock _lock(m_mtxStartStop);
	if (!m_fInitialized)
		return;
	m_fInitialized = false;

	LOGLVL(Detailed, "Event Enricher is stopped");
	TRACE_END("Fail to stop Event Enricher");
}

//
//
//
void EventEnricher::shutdown()
{
	LOGLVL(Detailed, "Event Enricher is being shutdowned");

	{
		std::scoped_lock _lock(m_mtxQueue);
		m_threadPool.stop(true);
		m_pProvider.reset();
		m_pReceiver.reset();
	}

	LOGLVL(Detailed, "Event Enricher is shutdowned");
}

static const wchar_t c_sRegistryUser[] = L"\\REGISTRY\\USER\\";
static const wchar_t c_sRegistryMachine[] = L"\\REGISTRY\\MACHINE\\";

//
//
//
std::wstring EventEnricher::getRegistryPath(std::wstring sPath)
{
	if (string::startsWith(sPath, c_sRegistryUser))
	{
		size_t nSlashPos = sPath.find(L'\\', std::size(c_sRegistryUser) - 1);
		if (nSlashPos == sPath.npos)
			nSlashPos = sPath.length(); // ERD-1957
		if (nSlashPos > 8 &&
			_wcsnicmp(sPath.substr(nSlashPos - 8).c_str(), L"_CLASSES", 8) == 0)
			sPath.replace(0, nSlashPos, L"HKEY_CLASSES_ROOT");
		else
			sPath.replace(0, std::size(c_sRegistryUser) - 1, L"HKEY_USERS\\");
	}
	else if (string::startsWith(sPath, c_sRegistryMachine))
	{
		sPath.replace(0, std::size(c_sRegistryMachine) - 1, L"HKEY_LOCAL_MACHINE\\");
		auto nControlSetPos = sPath.find(L"\\SYSTEM\\ControlSet001\\");
		if (nControlSetPos != sPath.npos)
			sPath.replace(nControlSetPos, 22, L"\\SYSTEM\\CurrentControlSet\\");
	}
	return sPath;
}

static const wchar_t c_sWow6432Node[] = L"\\Wow6432Node";
static const wchar_t c_sWowAA32Node[] = L"\\WowAA32Node";

//
//
//
std::wstring EventEnricher::getRegistryAbstractPath(std::wstring sPath)
{
	// EDR-2257: Cannot match registry rule for 32-bit process on 64-bit OS
	auto itNode = sPath.find(c_sWow6432Node);
	if (itNode == sPath.npos)
		itNode = sPath.find(c_sWowAA32Node);
	if (itNode != sPath.npos)
		sPath.replace(itNode, std::wcslen(c_sWow6432Node), L"");

	if (string::startsWith(sPath, c_sRegistryUser))
	{
		size_t nSlashPos = sPath.find(L'\\', std::size(c_sRegistryUser) - 1);
		if (nSlashPos == sPath.npos)
			nSlashPos = sPath.length(); // ERD-1957
		if (nSlashPos > 8 &&
			_wcsnicmp(sPath.substr(nSlashPos - 8).c_str(), L"_CLASSES", 8) == 0)
			sPath.replace(0, nSlashPos, L"%hkcu%\\Software\\Classes");
		else
			sPath.replace(0, nSlashPos, L"%hkcu%");
	}
	else if (string::startsWith(sPath, c_sRegistryMachine))
	{
		sPath.replace(0, std::size(c_sRegistryMachine) - 1, L"%hklm%\\");
		auto nControlSetPos = sPath.find(L"\\SYSTEM\\ControlSet001\\");
		if (nControlSetPos != sPath.npos)
			sPath.replace(nControlSetPos, 22, L"\\SYSTEM\\CurrentControlSet\\");
	}
	return string::convertToLow(sPath);
}

//
//
//
void EventEnricher::put(const Variant& vEventRef)
{
	Variant vEvent = const_cast<Variant&>(vEventRef);

	TRACE_BEGIN;
	auto pReceiver = m_pReceiver;
	if (!pReceiver)
		error::InvalidArgument(SL, "Receiver interface is undefined").throwException();

	Event eEventType = vEvent.has("baseEventType") && !vEvent.get("baseEventType").isEmpty() ? 
		static_cast<Event>(static_cast<int>(vEvent.get("baseEventType"))) : 
		static_cast<Event>(static_cast<int>(vEvent.get("baseType")));
	vEvent.put("type", getEventTypeString(eEventType));

	// Calculate event "time"
	vEvent.put("time", Time(vEvent["tickTime"]) + (getCurrentTime() - getTickCount()));

	// Put process info to event (prioritize the leaf actor process over parent)
	Variant vRawProcess;
	if (vEvent.has("processes"))
	{
		try
		{
			auto vSeq = vEvent.get("processes");
			if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
			{
				vRawProcess = vSeq[vSeq.getSize() - 1];
			}
		}
		catch (...) {}
	}
	if (vRawProcess.isEmpty() && vEvent.has("childProcess") && !vEvent.get("childProcess").isEmpty())
	{
		vRawProcess = vEvent.get("childProcess");
	}
	if (vRawProcess.isEmpty())
	{
		vRawProcess = vEvent.get("process");
	}

	auto vProcess = m_pProcProvider->enrichProcessInfo(vRawProcess);
	if (vProcess.isEmpty())
	{
		vProcess = vRawProcess;
	}

	std::string sProcPath;
	if (vProcess.has("imagePath")) sProcPath = std::string(vProcess["imagePath"]);
	else if (vProcess.has("path")) sProcPath = std::string(vProcess["path"]);
	else if (vProcess.has("rawPath")) sProcPath = std::string(vProcess["rawPath"]);

	std::string sProcHash;
	if (vProcess.has("imageHash")) sProcHash = std::string(vProcess["imageHash"]);
	else if (vProcess.has("hash")) sProcHash = std::string(vProcess["hash"]);

	if (DetectionNotifier::isKnownMalware(sProcPath, sProcHash))
	{
		vProcess.put("flsVerdict", 3);
		vProcess.put("verdict", 2);
	}

	vEvent.put("process", vProcess);
	Variant vToken = getByPath(vProcess, "token.tokenObj", {});

	// TODO: Please add statistic for each type of processes data
	switch (eEventType)
	{
	case Event::LLE_FILE_CREATE:
	case Event::LLE_FILE_DELETE:
	case Event::LLE_FILE_CLOSE:
	case Event::LLE_FILE_DATA_CHANGE:
	case Event::LLE_FILE_DATA_READ_FULL:
	case Event::LLE_FILE_DATA_WRITE_FULL:
	{
		Dictionary vParams = vEvent.get("file");
		vParams.put("security", vToken);
		if (eEventType == Event::LLE_FILE_DELETE)
			vParams.put("cmdRemove", true);
		if (eEventType == Event::LLE_FILE_DATA_CHANGE)
			vParams.put("cmdModify", true);

		// Update file info with fallback to raw vParams if provider fails (e.g. sharing violation)
		vEvent.put("file", variant::createLambdaProxy([vParams]() -> Variant 
		{
			try
			{
				auto pFileInformation = queryInterface<sys::win::IFileInformation>(queryService("fileDataProvider"));
				auto res = pFileInformation->getFileInfo(vParams);
				if (res.isDictionaryLike() && !res.isEmpty())
				{
					if (!res.has("path") && vParams.has("path"))
						res.put("path", vParams["path"]);
					return res;
				}
			}
			catch (...) {}
			return vParams;
		}, true));

		break;
	}
	case Event::LLE_FILE_RENAME:
	{
		// Enrich renames like other file events so policies can correlate
		// the renamed (pre-rename) file via uniquePath/abstractPath. The new
		// name is hoisted to a top-level <fileRenameTarget> field because
		// the enriched file object below replaces the raw dictionary that
		// carried it.
		Dictionary vParams = vEvent.get("file");
		if (vParams.has("renameTarget"))
			vEvent.put("fileRenameTarget", vParams["renameTarget"]);
		vParams.put("security", vToken);
		vEvent.put("file", variant::createLambdaProxy([vParams]() -> Variant
		{
			try
			{
				auto pFileInformation = queryInterface<sys::win::IFileInformation>(queryService("fileDataProvider"));
				auto res = pFileInformation->getFileInfo(vParams);
				if (res.isDictionaryLike() && !res.isEmpty())
				{
					if (!res.has("path") && vParams.has("path"))
						res.put("path", vParams["path"]);
					return res;
				}
			}
			catch (...) {}
			return vParams;
		}, true));
		break;
	}

	case Event::LLE_FILE_MAP_READ:
	case Event::LLE_FILE_MAP_WRITE:
	{
		// Memory-mapped section I/O: enrich like regular file events so
		// policies can correlate mapped reads/writes via uniquePath.
		Dictionary vParams = vEvent.get("file");
		vParams.put("security", vToken);
		vEvent.put("file", variant::createLambdaProxy([vParams]() -> Variant
		{
			auto pFileInformation = queryInterface<sys::win::IFileInformation>(queryService("fileDataProvider"));
			return pFileInformation->getFileInfo(vParams);
		}, true));
		break;
	}
	case Event::LLE_REGISTRY_KEY_CREATE:
	case Event::LLE_REGISTRY_KEY_NAME_CHANGE:
	case Event::LLE_REGISTRY_KEY_DELETE:
	case Event::LLE_REGISTRY_VALUE_SET:
	case Event::LLE_REGISTRY_VALUE_DELETE:
	{
		// URL: https://blog.not-a-kernel-guy.com/2006/12/25/120/
		// URL: https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/registry-key-object-routines

		Dictionary vRegistry = vEvent.get("registry");
		uint32_t nKeyType = vRegistry.get("rawType", UINT_MAX);
		switch (nKeyType)
		{
		case UINT_MAX:
			break;
		case REG_SZ:
		case REG_EXPAND_SZ:
		case REG_LINK:
		case REG_MULTI_SZ:
		{
			break;
		}
		case REG_DWORD:
		case REG_DWORD_BIG_ENDIAN:
		{
			uint32_t nData = vRegistry.get("data", uint32_t(0));
			vRegistry.put("data", std::to_string(nData));
			break;
		}
		case REG_QWORD:
		{
			uint64_t nData = vRegistry.get("data", uint64_t(0));
			vRegistry.put("data", std::to_string(nData));
			break;
		}
		default:
		{
			ObjPtr<io::IReadableStream> pStream = vRegistry.get("data", nullptr);
			if (pStream == nullptr)
				break;

			auto pMemStream = createObject(CLSID_MemoryStream);
			ObjPtr<io::IRawWritableStream> pB64Stream =
				queryInterface<io::IRawWritableStream>(createObject(CLSID_Base64Encoder,
					Dictionary({ {"stream", pMemStream} })));

			pStream->setPosition(0);
			io::write(pB64Stream, pStream);
			auto oMemInfo = queryInterface<io::IMemoryBuffer>(pMemStream)->getData();
			std::string sData(oMemInfo.second, 0);
			memcpy(sData.data(), oMemInfo.first, oMemInfo.second);

			vRegistry.put("data", sData);
			break;
		}
		}

		// Transform to lowercase
		std::wstring sKeyName(vRegistry.get("rawPath"));
		if (eEventType == Event::LLE_REGISTRY_KEY_NAME_CHANGE)
		{
			vRegistry.put("old", Dictionary({
				{"rawPath", sKeyName},
				{"path", getRegistryPath(sKeyName)},
				{"abstractPath", getRegistryAbstractPath(sKeyName)}
				}));

			std::wstring::size_type pos = sKeyName.rfind(L'\\');
			if (pos == std::wstring::npos)
				error::InvalidFormat(SL, "Fail to parse registry key").throwException();

			sKeyName = sKeyName.substr(0, pos + 1) +
				std::wstring(vRegistry.get("keyNewName"));

		}
		vRegistry.put("rawPath", sKeyName);
		vRegistry.put("path", getRegistryPath(sKeyName));
		vRegistry.put("abstractPath", getRegistryAbstractPath(sKeyName));

		if (vRegistry.has("name"))
		{
			std::wstring sName(vRegistry["name"]);
			vRegistry.put("name", string::convertToLow(sName));
		}

		break;
	}
	case Event::LLE_PROCESS_CREATE:
	{
		auto processInfo = vEvent.get("process");
		auto enrichedProcessInfo = m_pProcProvider->enrichProcessInfo(processInfo);

		std::string sImgPath;
		if (enrichedProcessInfo.has("imagePath")) sImgPath = std::string(enrichedProcessInfo["imagePath"]);
		else if (enrichedProcessInfo.has("path")) sImgPath = std::string(enrichedProcessInfo["path"]);
		else if (enrichedProcessInfo.has("rawPath")) sImgPath = std::string(enrichedProcessInfo["rawPath"]);

		std::string sImgHash;
		if (enrichedProcessInfo.has("imageHash")) sImgHash = std::string(enrichedProcessInfo["imageHash"]);
		else if (enrichedProcessInfo.has("hash")) sImgHash = std::string(enrichedProcessInfo["hash"]);

		if (DetectionNotifier::isKnownMalware(sImgPath, sImgHash))
		{
			LOGLVL(Critical, FMT("enricher: Process <" << sImgPath << "> matches KNOWN MALWARE in persistent database! Stamping Malicious verdict."));
			enrichedProcessInfo.put("flsVerdict", 3);
			enrichedProcessInfo.put("verdict", 2);
		}

		vEvent.put("process", enrichedProcessInfo);

		const std::wstring cmdLine = enrichedProcessInfo["cmdLine"];
		if (containsInterpetatorCmd(cmdLine))
		{
			const std::wstring scriptPath = getFilePath(cmdLine);
			const Variant scriptContent = !scriptPath.empty() ? readContent(scriptPath) : Variant();

			if (!scriptContent.isEmpty())
			{
				vEvent.put("scriptContent", scriptContent);
			}
		}
		break;
	}
	case Event::LLE_PROCESS_OPEN:
	case Event::LLE_PROCESS_MEMORY_READ:
	case Event::LLE_PROCESS_MEMORY_WRITE:
	{
		if (vEvent.has("target"))
		{
			auto vTarget = vEvent["target"];
			auto vTargetInfo = m_pProcProvider->enrichProcessInfo(vTarget);
			if (vTargetInfo.isEmpty())
			{
				LOGLVL(Detailed, "Process <" << vTarget["pid"] << "> not found for target in event <" <<
					Enum(eEventType) << ">, dropping event");
				return;
			}
			vEvent.put("target", vTargetInfo);
		}

		break;
	}
	case Event::LLE_WINDOW_PROC_GLOBAL_HOOK:
	case Event::LLE_KEYBOARD_GLOBAL_READ:
	{
		if (!vEvent.has("module"))
			break;

		Dictionary vParams = vEvent.get("module");
		vParams.put("security", vToken);
		vEvent.put("module", variant::createLambdaProxy([vParams]() -> Variant
		{
			auto pFileInformation = queryInterface<sys::win::IFileInformation>(queryService("fileDataProvider"));
			return pFileInformation->getFileInfo(vParams);
		}, true));
		break;
	}
	case Event::LLE_DISK_RAW_WRITE_ACCESS:
	case Event::LLE_DISK_LINK_CREATE:
	{
		vEvent.put("disk", vEvent.get("path", L""));
// 		vEvent.erase("objectType");
// 		vEvent.erase("path");
		break;
	}
	case Event::LLE_VOLUME_RAW_WRITE_ACCESS:
	case Event::LLE_VOLUME_LINK_CREATE:
	{
		Dictionary vParams({ {"path", vEvent.get("path", L"")} });
		vEvent.put("volume", createCmdProxy(Dictionary({
			{"processor", "objects.fileDataProvider" },
			{"command", "getVolumeInfo"},
			{"params", vParams},
		}), true));
// 		vEvent.erase("objectType");
// 		vEvent.erase("path");
		break;
	}
	case Event::LLE_DEVICE_RAW_WRITE_ACCESS:
	case Event::LLE_DEVICE_LINK_CREATE:
	{
		vEvent.put("device", vEvent.get("path", L""));
// 		vEvent.erase("objectType");
// 		vEvent.erase("path");
		break;
	}
	case Event::LLE_INJECTION_ACTIVITY:
	{
		vProcess.put("hasInjection", true);
		break;
	}
	case Event::LLE_USER_LOGON:
	{
		vProcess.put("interactiveLogon", true);
		break;
	}
	case Event::LLE_USER_IMPERSONATION:
	{
		auto pUserDP = queryInterface<sys::win::IUserInformation>(queryService("userDataProvider"));
		auto vTheadToken = pUserDP->getTokenInfo(vEvent.get("user", {}));
		if (!vTheadToken.isEmpty())
		{
			auto vThread = vEvent["thread"];
			vThread.put("token", vTheadToken);
			vEvent.erase("user");
		}
/*
		auto vTarget = vEvent["target"];
		auto vTargetInfo = m_pProcProvider->enrichProcessInfo(vTarget);
		if (!vTargetInfo.isEmpty())
			vEvent.put("target", vTargetInfo);
*/
		break;
	}
	case Event::LLE_DEVICE_IOCTL:
	{
		// Kernel hook event carrier.
		// owlyHook and owlyHv sub-dicts are already built by controller.cpp::parseEvent.
		//
		// WinAPI usage parsing: the user-mode hook carrier carries the hooked
		// API as "module!Function" (e.g. "advapi32.dll!CryptEncrypt"). Split it
		// into apiModule/apiFunction so edrav2 policies can match either part:
		//   @event.owlyHook.functionName  - full "module!Function" name
		//   @event.owlyHook.apiModule     - "advapi32.dll"
		//   @event.owlyHook.apiFunction   - "CryptEncrypt"
		if (vEvent.has("owlyHook"))
		{
			Variant vHook = vEvent.get("owlyHook");
			uint32_t srcPid = vHook.get("sourcePid", uint32_t(0));
			if (srcPid != 0 && m_pProcProvider)
			{
				auto vProcInfo = m_pProcProvider->enrichProcessInfo(Dictionary({{"pid", srcPid}}));
				if (!vProcInfo.isEmpty())
				{
					vEvent.put("process", vProcInfo);
					if (!vEvent.has("processes") || vEvent.get("processes").isEmpty())
					{
						vEvent.put("processes", Sequence({ vProcInfo }));
					}
				}
			}

			std::wstring sName = vHook.get("functionName", L"");
			auto nPos = sName.rfind(L'!');
			if (!sName.empty())
			{
				if (nPos != std::wstring::npos)
				{
					vHook.put("apiModule", sName.substr(0, nPos));
					vHook.put("apiFunction", sName.substr(nPos + 1));
				}
				else
				{
					vHook.put("apiFunction", sName);
				}
				vEvent.put("owlyHook", vHook);
			}
		}
		break;
	}
	case Event::LLE_SELF_DEFENSE:
	{
		// Self-defense telemetry forwarded from the kernel.
		// Pass through without further enrichment.
		break;
	}
	case Event::LLE_NAMED_PIPE_CREATE:
	{
		// Named-pipe creation event forwarded from the kernel.
		// Pass through without further enrichment.
		break;
	}
	}

	// Shadow-backup shield: record pre-images under %PROGRAMDATA%\HydraDragonBackups\<pid>
	try
	{
		int64_t nShieldPid = getByPath(vEvent, "process.pid", int64_t(0));
		if (nShieldPid <= 0 && vEvent.has("processes"))
		{
			try {
				auto vSeq = vEvent.get("processes");
				if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
				{
					auto vLeaf = vSeq[vSeq.getSize() - 1];
					if (vLeaf.has("pid"))
						nShieldPid = static_cast<int64_t>(vLeaf["pid"]);
					else if (vLeaf.has("id"))
						nShieldPid = static_cast<int64_t>(vLeaf["id"]);
				}
			} catch (...) {}
		}
		recordShadowBackup(nShieldPid, eEventType, vEvent);

		// If policy generated any detection/threat event, execute universal remediation (file rollback + terminate + quarantine)
		const int64_t nBaseType = vEvent.get("baseType", int64_t(0));
		if (nBaseType >= 1000000 || vEvent.has("threat"))
		{
			std::wstring sImage;
			try
			{
				Variant vImage = getByPath(vProcess, "imageFile");
				sImage = vImage.get("uniquePath", L"");
			}
			catch (...) {}
			std::string sThreatName = "THREAT_BASE_TYPE_" + std::to_string(nBaseType);
			handleThreatRemediation(nShieldPid, sImage, sThreatName);
		}
	}
	catch (...)
	{
	}

	// Feed all enriched events (files, processes, registry, etc.) to Owlyshield FastDetect ML engine
	ForwardToOwlyshieldMlEngine(vEvent);

	return pReceiver->put(vEvent);
	TRACE_END(FMT("Fail to parse event <" << vEvent.get("baseType", 0) << ">"))
}

//
//
//
void EventEnricher::processQueueEvent()
{
	CMD_TRY
	{
		if (!m_fInitialized)
			return;

		auto pProvider = m_pProvider.lock();
		if (pProvider == nullptr)
			error::InvalidArgument(SL, "Provider interface is undefined").throwException();
		auto vEvent = pProvider->get();
		if (vEvent)
			put(vEvent.value());
	}
	CMD_PREPARE_CATCH
	catch (error::Exception& e)
	{
		e.log(SL, "Fail to parse event from queue");
	}
	catch (...)
	{
		error::RuntimeError(SL, "Fail to parse event from queue").log();
	}
}

//
//
//
void EventEnricher::notifyAddQueueData(Variant vTag)
{
	std::scoped_lock _lock(m_mtxQueue);
	if (!m_fInitialized)
		return;
	if (m_threadPool.getThreadsCount() == 0)
	{
		error::InvalidUsage(SL, "Thread pool is empty").log();
		return;
	}

	if (m_pProvider.expired())
	{
		auto pQm = queryInterface<IQueueManager>(queryService("queueManager"));
		m_pProvider = queryInterface<IDataProvider>(pQm->getQueue(std::string(vTag)));
	}

	m_threadPool.run(&EventEnricher::processQueueEvent, this);
}

//
//
//
void EventEnricher::notifyQueueOverflowWarning(Variant /*vTag*/)
{
}

//
//
//
Variant EventEnricher::execute(Variant vCommand, Variant vParams)
{
	TRACE_BEGIN;

	LOGLVL(Debug, "Process command <" << vCommand << ">");
	if (!vParams.isEmpty())
		LOGLVL(Trace, "Command parameters:\n" << vParams);

	///
	/// @fn Variant EventEnricher::execute()
	///
	/// ##### put()
	/// Put data to the pattern searcher
	///   * data [var] - data;
	///
	if (vCommand == "put")
	{
		put(vParams["data"]);
		return {};
	}

	///
	/// @fn Variant EventEnricher::execute()
	///
	/// ##### start()
	/// Start driver and controller
	///
	if (vCommand == "start")
	{
		start();
		return {};
	}

	///
	/// @fn Variant EventEnricher::execute()
	///
	/// ##### stop()
	/// Stop controller
	///
	if (vCommand == "stop")
	{
		stop();
		return {};
	}

	error::OperationNotSupported(SL,
		FMT("PatternSeacher doesn't support command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during processing of the command <" << vCommand << ">"));
}

} // namespace cmd 
