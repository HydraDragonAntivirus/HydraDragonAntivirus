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
#include <atomic>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>

// Set component for logging
#undef CMD_COMPONENT
#define CMD_COMPONENT "detnotif"

namespace cmd {

namespace {

	static std::atomic<bool> s_fProtectionPaused = false;
	static std::mutex s_mtxQuarantineLock;
	static std::unordered_map<uint64_t, std::string> s_quarantinedPids; // pid/gid -> original quarantined malware path
	static std::unordered_set<std::string> s_quarantinedPaths;          // lowercase paths already quarantined
	static std::unordered_set<std::string> s_quarantinedHashes;         // lowercase hashes (SHA1/MD5) of detected malware
	static std::mutex s_mtxMalwareDb;
	static std::atomic<bool> s_bMalwareDbLoaded = false;

	static const wchar_t* const c_szMalwareDbDirs[] = {
		L"C:\\ProgramData\\HydraDragonBackups",
		L"C:\\ProgramData\\edrsvc"
	};
	static const wchar_t* const c_szMalwareDbFile = L"detected_malware.db";

	static std::string toLowerStr(std::string s)
	{
		std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return s;
	}

	// Sanitizes C:\Windows\System32\drivers\etc\hosts to ensure it remains 100% clean (comments only).
	// Returns true if active (non-comment) entries were found and sanitized.
	static bool sanitizeHostsFile()
	{
		const wchar_t* wsHostsPath = L"C:\\Windows\\System32\\drivers\\etc\\hosts";
		std::ifstream ifs(wsHostsPath);
		if (!ifs.is_open()) return false;

		std::vector<std::string> cleanLines;
		std::string line;
		bool bModified = false;

		while (std::getline(ifs, line))
		{
			std::string trimmed = line;
			size_t first = trimmed.find_first_not_of(" \t\r\n");
			if (first == std::string::npos) {
				cleanLines.push_back(line);
				continue;
			}
			trimmed = trimmed.substr(first);

			if (trimmed.empty() || trimmed[0] == '#') {
				cleanLines.push_back(line);
			} else {
				// Active mapping entry with 2 entries/tokens (Token 1 = IPv4 '.' or IPv6 ':', Token 2 = Domain)
				std::istringstream iss(trimmed);
				std::string t1, t2;
				if (iss >> t1 && iss >> t2) {
					if (t1.find('.') != std::string::npos || t1.find(':') != std::string::npos) {
						bModified = true;
					} else {
						cleanLines.push_back(line);
					}
				} else {
					cleanLines.push_back(line);
				}
			}
		}
		ifs.close();

		if (bModified)
		{
			std::ofstream ofs(wsHostsPath, std::ios::trunc);
			if (ofs.is_open()) {
				for (const auto& l : cleanLines) {
					ofs << l << "\n";
				}
			}
			LOGLVL(Critical, "detnotif: Sanitized malicious active entry in C:\\Windows\\System32\\drivers\\etc\\hosts");
		}
		return bModified;
	}

	static std::string NtPathToDosPathString(const std::string& sNt)
	{
		if (sNt.empty())
			return sNt;

		std::string sClean = sNt;
		if (sClean.rfind("\\??\\", 0) == 0)
			sClean = sClean.substr(4);

		int cchW = ::MultiByteToWideChar(CP_UTF8, 0, sClean.c_str(), -1, NULL, 0);
		if (cchW <= 0)
			return sClean;

		std::wstring wsNt(static_cast<size_t>(cchW), 0);
		::MultiByteToWideChar(CP_UTF8, 0, sClean.c_str(), -1, &wsNt[0], cchW);
		if (!wsNt.empty() && wsNt.back() == L'\0')
			wsNt.pop_back();

		if (wsNt.find(L'%') != std::wstring::npos)
		{
			wchar_t szExp[MAX_PATH * 2] = {};
			if (::ExpandEnvironmentStringsW(wsNt.c_str(), szExp, static_cast<DWORD>(std::size(szExp))) > 0)
				wsNt = szExp;
		}

		wchar_t sDrives[27 * 4] = {};
		if (::GetLogicalDriveStringsW(DWORD(std::size(sDrives)), sDrives) == 0)
			return sClean;

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
		return sClean;
	}

} // namespace

void DetectionNotifier::loadPersistentMalwareDb()
{
	std::scoped_lock lock(s_mtxMalwareDb);
	if (s_bMalwareDbLoaded.load())
		return;

	HANDLE hDev = ::CreateFileW(L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}", 
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	struct COM_BLOCK_MSG {
		ULONG msgType;
		ULONG pid;
		ULONGLONG gid;
		WCHAR path[520];
		WCHAR quarantinePath[520];
	};
	DWORD IOCTL_OWLY = (0x00000022 << 16) | (0 << 14) | (0x921 << 2) | 0;

	for (const auto* szDir : c_szMalwareDbDirs)
	{
		std::wstring wsDb = std::wstring(szDir) + L"\\" + c_szMalwareDbFile;
		std::ifstream ifs(wsDb);
		if (ifs.is_open())
		{
			std::string line;
			while (std::getline(ifs, line))
			{
				if (line.empty() || line[0] == '#')
					continue;
				size_t sep1 = line.find('|');
				if (sep1 != std::string::npos)
				{
					std::string h = line.substr(0, sep1);
					std::string p = line.substr(sep1 + 1);
					size_t sep2 = p.find('|');
					if (sep2 != std::string::npos)
						p = p.substr(0, sep2);
					if (!h.empty())
						s_quarantinedHashes.insert(toLowerStr(h));
					if (!p.empty())
					{
						s_quarantinedPaths.insert(toLowerStr(p));
						if (hDev != INVALID_HANDLE_VALUE)
						{
							COM_BLOCK_MSG blockMsg = {0};
							blockMsg.msgType = 11; // MESSAGE_ADD_BLOCK_PATH
							if (::MultiByteToWideChar(CP_UTF8, 0, p.c_str(), -1, blockMsg.path, 519) > 0)
							{
								DWORD retBytes = 0;
								uint32_t output = 0;
								::DeviceIoControl(hDev, IOCTL_OWLY, &blockMsg, sizeof(blockMsg), &output, sizeof(output), &retBytes, NULL);
							}
						}
					}
				}
				else
				{
					s_quarantinedPaths.insert(toLowerStr(line));
				}
			}
		}
	}

	if (hDev != INVALID_HANDLE_VALUE)
		::CloseHandle(hDev);

	s_bMalwareDbLoaded.store(true);
}

void DetectionNotifier::recordMalwareDetection(const std::string& sPath, const std::string& sHash)
{
	if (sPath.empty() && sHash.empty())
		return;

	std::string sDos = NtPathToDosPathString(sPath);
	std::string sLowerPath = toLowerStr(sDos);
	std::string sLowerHash = toLowerStr(sHash);

	{
		std::scoped_lock lock(s_mtxMalwareDb);
		if (!sLowerPath.empty())
			s_quarantinedPaths.insert(sLowerPath);
		if (!sLowerHash.empty())
			s_quarantinedHashes.insert(sLowerHash);
	}

	// Blacklist and block the malware file path in the edrdrv kernel driver minifilter
	if (!sDos.empty())
	{
		HANDLE hDevBlock = ::CreateFileW(L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}", 
			GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDevBlock != INVALID_HANDLE_VALUE)
		{
			struct COM_BLOCK_MSG {
				ULONG msgType;
				ULONG pid;
				ULONGLONG gid;
				WCHAR path[520];
				WCHAR quarantinePath[520];
			};
			
			COM_BLOCK_MSG blockMsg = {0};
			blockMsg.msgType = 11; // MESSAGE_ADD_BLOCK_PATH
			
			if (::MultiByteToWideChar(CP_UTF8, 0, sDos.c_str(), -1, blockMsg.path, 519) > 0)
			{
				DWORD retBytes = 0;
				uint32_t output = 0;
				DWORD IOCTL_OWLY = (0x00000022 << 16) | (0 << 14) | (0x921 << 2) | 0;
				if (::DeviceIoControl(hDevBlock, IOCTL_OWLY, &blockMsg, sizeof(blockMsg), &output, sizeof(output), &retBytes, NULL))
				{
					LOGLVL(Critical, FMT("detnotif: successfully added malware path to kernel driver block list <" << sDos << ">"));
				}
			}
			::CloseHandle(hDevBlock);
		}
	}

	::CreateDirectoryW(L"C:\\ProgramData\\HydraDragonBackups", NULL);
	::CreateDirectoryW(L"C:\\ProgramData\\edrsvc", NULL);

	for (const auto* szDir : c_szMalwareDbDirs)
	{
		std::wstring wsDb = std::wstring(szDir) + L"\\" + c_szMalwareDbFile;
		std::ofstream ofs(wsDb, std::ios::app);
		if (ofs.is_open())
		{
			auto now = std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::system_clock::now().time_since_epoch()).count();
			ofs << sLowerHash << "|" << sLowerPath << "|" << now << "\n";
		}
	}
}

bool DetectionNotifier::isKnownMalware(const std::string& sPath, const std::string& sHash)
{
	if (!s_bMalwareDbLoaded.load())
		loadPersistentMalwareDb();

	std::scoped_lock lock(s_mtxMalwareDb);
	if (!sHash.empty() && s_quarantinedHashes.count(toLowerStr(sHash)) > 0)
		return true;

	if (!sPath.empty())
	{
		std::string sDos = NtPathToDosPathString(sPath);
		if (s_quarantinedPaths.count(toLowerStr(sDos)) > 0)
			return true;
	}

	return false;
}

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

	loadPersistentMalwareDb();

	TRACE_END("Error during configuration");
}

//
//
//
bool DetectionNotifier::isDetectionEvent(const Variant& vEvent)
{
	if (!vEvent.isDictionaryLike())
		return false;

	std::string sType = vEvent.get("type", std::string());
	std::string sEventType = vEvent.get("eventType", std::string());

	auto isRawTelemetryPrefix = [](const std::string& s) -> bool {
		if (s.empty())
			return false;
		if (s.compare(0, 2, "RP") == 0 || s.compare(0, 2, "RF") == 0 ||
		    s.compare(0, 2, "RR") == 0 || s.compare(0, 2, "RN") == 0 ||
		    s.compare(0, 2, "RE") == 0 || s.compare(0, 2, "RD") == 0 ||
		    s.compare(0, 2, "RB") == 0 || s.compare(0, 4, "LLE_") == 0)
		{
			return true;
		}
		return false;
	};

	// Raw telemetry events (RP, RF, RR, RN, RE, LLE) are NEVER detections
	if (isRawTelemetryPrefix(sType) || isRawTelemetryPrefix(sEventType))
	{
		return false;
	}

	// 1. Explicit detection type name (MLE_* or any custom policy output rule name)
	if (!sType.empty() || !sEventType.empty())
		return true;

	if (vEvent.has("threat") || vEvent.has("alert") || vEvent.has("detection"))
		return true;

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

		if (s_fProtectionPaused.load())
		{
			LOGLVL(Detailed, "detnotif: Protection is PAUSED. Suppressing all alerts, notifications and storage.");
			return {};
		}

		// Hosts File Self-Defense & Behavioral Protection:
		// Always sanitize Hosts file so active non-comment entries are deleted!
		(void)sanitizeHostsFile();

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
				sTitle = vEvent.get("eventType", std::string());
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

			// Returns the first non-empty valid path among the given keys.
			auto tryPaths = [&](std::initializer_list<const char*> keys) -> std::string {
				for (const char* k : keys)
				{
					std::string v = extractValidPath(k);
					if (!v.empty())
						return v;
				}
				return {};
			};

			auto extractId = [&](const std::string_view& pathKey) -> uint64_t {
				if (auto opt = getByPathSafe(vEvent, pathKey)) {
					try {
						if (opt.value().getType() == variant::ValueType::Integer)
							return static_cast<uint64_t>(opt.value());
						else if (opt.value().getType() == variant::ValueType::String) {
							std::string s = std::string(opt.value());
							if (!s.empty() && s != "<undefined>" && s != "null")
								return std::stoull(s);
						}
						else {
							return static_cast<uint64_t>(opt.value());
						}
					} catch (...) {}
				}
				return 0;
			};

			uint64_t nGid = extractId("childProcess.id");
			if (nGid == 0) nGid = extractId("childProcess.pid");
			if (nGid == 0 && vEvent.has("processes"))
			{
				try {
					auto vSeq = vEvent.get("processes");
					if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
					{
						auto vLeaf = vSeq[vSeq.getSize() - 1];
						if (vLeaf.has("id"))
							nGid = static_cast<uint64_t>(vLeaf["id"]);
						else if (vLeaf.has("pid"))
							nGid = static_cast<uint64_t>(vLeaf["pid"]);
					}
				} catch (...) {}
			}
			if (nGid == 0)
			{
				int64_t nFileVerdict = 0;
				if (auto optVerdictF = getByPathSafe(vEvent, "file.verdict"))
					try { nFileVerdict = std::stoll(std::string(optVerdictF.value())); } catch (...) {}

				if (nFileVerdict != 2)
				{
					nGid = extractId("process.id");
					if (nGid == 0) nGid = extractId("process.pid");
				}
			}

			// Determine initial action based on verdict
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

			int64_t nRootMalwarePid = 0;
			int64_t nRootMalwareVerdict = 0;
			std::string sRootMalwarePath;
			std::string sRootMalwareHash;
			std::string sPath = extractValidPath("quarantineTarget");

			// Check if this process or threat was already quarantined, lock sPath to the original threat
			if (sPath.empty())
			{
				std::scoped_lock _lock(s_mtxQuarantineLock);
				if (nGid != 0)
				{
					auto it = s_quarantinedPids.find(nGid);
					if (it != s_quarantinedPids.end())
						sPath = it->second;
				}
				if (sPath.empty())
				{
					uint64_t procPid = extractId("process.pid");
					if (procPid != 0)
					{
						auto it = s_quarantinedPids.find(procPid);
						if (it != s_quarantinedPids.end())
							sPath = it->second;
					}
				}
			}

			// If quarantineTarget is not set, resolve based on detection type
			if (sPath.empty())
			{
				// 1. If childProcess exists (Process Creation Detection), target the child
				sPath = tryPaths({
					"childProcess.imageFile.rawPath",
					"childProcess.imageFile.path",
					"childProcess.imagePath",
					"childProcess.path",
					"childProcess.imageFile.abstractPath"
				});

				// 2. Deep Process Ancestry Trace (Root Cause & Initial Dropper Discovery)
				//    Walk the processes chain backwards (from leaf to root) to identify:
				//    a) Any explicit malware/untrusted ancestor process (verdict == 3 or verdict == 2, or known malware)
				//    b) If the leaf was a LOLBIN/system proxy (e.g. msiexec, wscript, powershell, cmd), find the non-system user binary that launched it!
				if (sPath.empty() && vEvent.has("processes"))
				{
					try
					{
						auto vSeq = vEvent.get("processes");
						if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
						{
							std::string sLeafPath;
							int64_t nLeafVerdict = 0;

							for (int i = static_cast<int>(vSeq.getSize()) - 1; i >= 0; --i)
							{
								auto vProc = vSeq[i];
								int64_t vVal = 0;
								if (vProc.has("verdict")) {
									try { vVal = static_cast<int64_t>(vProc["verdict"]); } catch (...) {}
								}

								std::string pPath;
								for (const char* field : {"imageFile.rawPath", "imageFile.path", "imagePath", "path", "imageFile.abstractPath"}) {
									if (auto optP = variant::getByPathSafe(vProc, field)) {
										std::string s = std::string(optP.value());
										if (!s.empty() && s != "<undefined>" && s != "null") {
											pPath = s;
											break;
										}
									}
								}

								std::string pHash;
								for (const char* hField : {"imageHash", "hash", "imageFile.imageHash"}) {
									if (auto optH = variant::getByPathSafe(vProc, hField)) {
										std::string h = std::string(optH.value());
										if (!h.empty() && h != "<undefined>" && h != "null") {
											pHash = h;
											break;
										}
									}
								}

								int64_t pPid = 0;
								if (vProc.has("pid")) {
									try { pPid = static_cast<int64_t>(vProc["pid"]); } catch (...) {}
								}

								if (i == static_cast<int>(vSeq.getSize()) - 1)
								{
									sLeafPath = pPath;
									nLeafVerdict = vVal;
								}

								// Check if this ancestor is explicit malware or known malware
								if (vVal == 3 || vVal == 2 || (!pPath.empty() && isKnownMalware(pPath, pHash)))
								{
									sRootMalwarePath = pPath;
									sRootMalwareHash = pHash;
									nRootMalwarePid = pPid;
									nRootMalwareVerdict = (vVal != 0 ? vVal : 3);
									break; // Found root malicious attacker!
								}

								// Check if ancestor is a user/temp/desktop binary launching a LOLBIN
								if (sRootMalwarePath.empty() && !pPath.empty())
								{
									std::string sLower = toLowerStr(pPath);
									if (sLower.find("\\users\\") != std::string::npos ||
										sLower.find("\\temp\\") != std::string::npos ||
										sLower.find("\\appdata\\") != std::string::npos)
									{
										if (sLower.find("explorer.exe") == std::string::npos &&
											sLower.find("svchost.exe") == std::string::npos &&
											sLower.find("winlogon.exe") == std::string::npos &&
											sLower.find("userinit.exe") == std::string::npos)
										{
											sRootMalwarePath = pPath;
											sRootMalwareHash = pHash;
											nRootMalwarePid = pPid;
											nRootMalwareVerdict = 3;
										}
									}
								}
							}

							if (!sRootMalwarePath.empty())
							{
								sPath = sRootMalwarePath;
								if (nVerdict == 0 || nVerdict == 1)
									nVerdict = nRootMalwareVerdict;
								LOGLVL(Critical, FMT("detnotif: Deep Trace identified ROOT MALICIOUS PAYLOAD <" 
									<< sRootMalwarePath << "> (pid=" << nRootMalwarePid << ", verdict=" << nRootMalwareVerdict << ")"));
							}
							else if (sPath.empty() && !sLeafPath.empty())
							{
								sPath = sLeafPath;
								if (nVerdict == 0)
									nVerdict = nLeafVerdict;
							}
						}
					}
					catch (...) {}
				}

				// 3. If it's a File Event or File Detection, resolve target file path
				if (sPath.empty())
				{
					sPath = tryPaths({
						"file.rawPath",
						"file.path",
						"file.abstractPath"
					});
				}

				// 4. Direct process behavioral detection - only if processes sequence was NOT a multi-process chain
				if (sPath.empty())
				{
					bool isMultiProcessChain = false;
					if (vEvent.has("processes"))
					{
						try {
							auto vSeq = vEvent.get("processes");
							if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 1)
								isMultiProcessChain = true;
						} catch (...) {}
					}
					if (!isMultiProcessChain)
					{
						sPath = tryPaths({
							"process.imageFile.rawPath",
							"process.imageFile.path",
							"process.imagePath",
							"process.path",
							"process.imageFile.abstractPath"
						});
					}
				}
			}

			// Sync process verdict to OwlyShield Rust engine
			if (nGid > 0 && nVerdict > 0)
			{
				HMODULE hOwly = ::GetModuleHandleW(L"owlyshield_ransom.dll");
				if (!hOwly) hOwly = ::LoadLibraryW(L"owlyshield_ransom.dll");
				if (hOwly)
				{
					typedef int32_t (*UpdateVerdictFn)(uint32_t, uint8_t);
					auto fnUpdate = (UpdateVerdictFn)::GetProcAddress(hOwly, "owlyshield_update_process_verdict");
					if (fnUpdate)
					{
						fnUpdate(static_cast<uint32_t>(nGid), static_cast<uint8_t>(nVerdict));
					}
				}
			}

			// Check trust flags: should_trust_company_whitelist & should_trust_comodo_fls_cloud
			bool bShouldTrustCompanyWhitelist = true;
			if (auto optTrustCompany = variant::getByPathSafe(vEvent, "should_trust_company_whitelist"))
			{
				try {
					auto vTrust = optTrustCompany.value();
					if (vTrust.getType() == variant::ValueType::Boolean)
						bShouldTrustCompanyWhitelist = static_cast<bool>(vTrust);
				} catch (...) {}
			}

			bool bShouldTrustFlsCloud = true;
			if (auto optTrustFls = variant::getByPathSafe(vEvent, "should_trust_comodo_fls_cloud"))
			{
				try {
					auto vTrust = optTrustFls.value();
					if (vTrust.getType() == variant::ValueType::Boolean)
						bShouldTrustFlsCloud = static_cast<bool>(vTrust);
				} catch (...) {}
			}

			if ((bShouldTrustCompanyWhitelist || bShouldTrustFlsCloud) && !sPath.empty())
			{
				bool bIsTrustedByCompanyWhitelist = false;
				if (bShouldTrustCompanyWhitelist)
				{
					HMODULE hOwly = ::GetModuleHandleW(L"owlyshield_ransom.dll");
					if (!hOwly) hOwly = ::LoadLibraryW(L"owlyshield_ransom.dll");
					if (hOwly)
					{
						typedef int32_t (*IsTrustedSignerFn)(const wchar_t*, uint32_t);
						auto fnCheckTrusted = (IsTrustedSignerFn)::GetProcAddress(hOwly, "owlyshield_is_trusted_company_signer");
						if (fnCheckTrusted)
						{
							std::wstring wsPath;
							int nWideLen = ::MultiByteToWideChar(CP_UTF8, 0, sPath.c_str(), static_cast<int>(sPath.length()), nullptr, 0);
							if (nWideLen > 0)
							{
								wsPath.resize(nWideLen);
								::MultiByteToWideChar(CP_UTF8, 0, sPath.c_str(), static_cast<int>(sPath.length()), &wsPath[0], nWideLen);
							}
							else
							{
								wsPath.assign(sPath.begin(), sPath.end());
							}

							if (fnCheckTrusted(wsPath.c_str(), static_cast<uint32_t>(wsPath.length())) == 1)
							{
								bIsTrustedByCompanyWhitelist = true;
							}
						}
					}
				}

				bool bIsTrustedByFlsCloud = (bShouldTrustFlsCloud && nVerdict == 1);

				if (bIsTrustedByCompanyWhitelist || bIsTrustedByFlsCloud)
				{
					// Do not kill or quarantine the SAFE process! Look for an untrusted ancestor process instead.
					if (!sRootMalwarePath.empty())
					{
						LOGLVL(Critical, FMT("detnotif: Trust check ACTIVE (CompanyWhitelist=" << bIsTrustedByCompanyWhitelist << ", FlsCloud=" << bIsTrustedByFlsCloud << "). Bypassing SAFE target <" 
							<< sPath << "> and redirecting quarantine to untrusted ancestor <" << sRootMalwarePath << ">"));
						sPath = sRootMalwarePath;
						nVerdict = nRootMalwareVerdict;
					}
					else
					{
						LOGLVL(Critical, FMT("detnotif: Trust check ACTIVE (CompanyWhitelist=" << bIsTrustedByCompanyWhitelist << ", FlsCloud=" << bIsTrustedByFlsCloud << "). Suppressing quarantine/kill for SAFE process <" << sPath << ">"));
						sPath.clear();
						nGid = 0;
					}
				}
				else if (bShouldTrustFlsCloud && nVerdict == 4)
				{
					LOGLVL(Critical, FMT("detnotif: FLS Verdict is FAIL/ERROR (4). Suppressing immediate kill/quarantine for <" << sPath << "> until FLS cloud recovers."));
					sPath.clear();
					nGid = 0;
				}
			}

			// Update vEvent so quarantineTarget is explicitly populated in the event JSON dictionary
			if (!sPath.empty())
				vEvent.put("quarantineTarget", sPath);

			if (!sPath.empty())
				sTitle += (sTitle.empty() ? "" : ": ") + sPath;

			if (!sTitle.empty())
				vEvent.put("title", sTitle);
			
			if (!s_fProtectionPaused.load())
			{
				if (nGid > 0)
				{
					HANDLE hDev = ::CreateFileW(L"\\\\.\\{157980D8-09B4-4580-B8B6-D32971D056DA}", 
						GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 
						NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (hDev != INVALID_HANDLE_VALUE)
					{
						struct COM_MESSAGE {
							ULONG msgType;
							ULONG pid;
							ULONGLONG gid;
							WCHAR path[520];
							WCHAR quarantinePath[520];
						};
						
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

				// Restore victim files & delete encrypted ransomware artifacts
				// Use the LEAF process PID (actual malicious actor) for rollback.
				// Prefer: processes[-1] > childProcess > process  (same priority as GID resolution above)
				int64_t nShieldPid = 0;
				if (vEvent.has("processes"))
				{
					try {
						auto vSeq = vEvent.get("processes");
						if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
						{
							auto vLeaf = vSeq[vSeq.getSize() - 1];
							if (vLeaf.has("pid"))
								nShieldPid = static_cast<int64_t>(vLeaf["pid"]);
						}
					} catch (...) {}
				}
				if (nShieldPid <= 0)
				{
					if (auto opt = getByPathSafe(vEvent, "childProcess.pid"))
						try { nShieldPid = static_cast<int64_t>(opt.value()); } catch (...) {}
				}
				if (nShieldPid <= 0)
				{
					if (auto opt = getByPathSafe(vEvent, "process.pid"))
						try { nShieldPid = static_cast<int64_t>(opt.value()); } catch (...) {}
				}

				// 1. First: Quarantine the malicious binary and register it in the malware database
				if (!sPath.empty())
				{
					if (nVerdict == 1)
					{
						LOGLVL(Detailed, FMT("detnotif: Target <" << sPath << "> is Trusted (verdict=1). KILL ONLY. Skipping quarantine."));
					}
					else
					{
						std::string sDos = NtPathToDosPathString(sPath);
						std::string sLower = toLowerStr(sDos);

						std::string sHash;
						for (const char* hField : {
							"childProcess.imageHash",
							"process.imageFile.imageHash",
							"process.imageHash",
							"file.rawHash",
							"file.hash",
							"imageHash",
							"hash"
						})
						{
							if (auto optH = getByPathSafe(vEvent, hField))
							{
								std::string h = std::string(optH.value());
								if (!h.empty() && h != "<undefined>" && h != "null")
								{
									sHash = h;
									break;
								}
							}
						}

						// Persistently remember this malware across restarts & blacklist in driver
						recordMalwareDetection(sDos, sHash);

						{
							std::scoped_lock _lock(s_mtxQuarantineLock);
							s_quarantinedPaths.insert(sLower);
							if (nGid != 0) s_quarantinedPids[nGid] = sDos;
							if (nShieldPid > 0) s_quarantinedPids[static_cast<uint64_t>(nShieldPid)] = sDos;
							if (nRootMalwarePid > 0) s_quarantinedPids[static_cast<uint64_t>(nRootMalwarePid)] = sDos;
						}

						// Always execute quarantine on detected malware
						HMODULE hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
						if (hDll != nullptr)
						{
							typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
							auto fnQ = (QuarantineFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file");
							if (fnQ != nullptr)
							{
								int32_t qRes = fnQ(
									reinterpret_cast<const uint8_t*>(sDos.data()),
									static_cast<uint32_t>(sDos.size()));

								if (qRes == 0)
								{
									LOGLVL(Critical, FMT("detnotif: owlyshield quarantined malware <" << sDos << ">"));
								}
								else
								{
									LOGLVL(Critical, FMT("detnotif: owlyshield quarantine FAILED for <" << sDos << "> result=" << qRes));
								}
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

				// 2. Second: Execute rollback for victim files (now aware that the malware binary is blacklisted)
				if (nRootMalwarePid > 0)
					EventEnricher::rollbackRansomBackups(nRootMalwarePid);
				if (nShieldPid > 0 && nShieldPid != nRootMalwarePid)
					EventEnricher::rollbackRansomBackups(nShieldPid);
				if (nGid > 0 && nGid != static_cast<uint64_t>(nShieldPid) && nGid != static_cast<uint64_t>(nRootMalwarePid))
					EventEnricher::rollbackRansomBackups(static_cast<int64_t>(nGid));
				else
				{
					LOGLVL(Critical, "detnotif: quarantineTarget path is empty! Cannot quarantine anything.");
				}
			}
			else
			{
				LOGLVL(Detailed, "detnotif: Protection is PAUSED. Suppressed kill, quarantine, and rollback.");
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

	if (vCommand == "setProtectionPaused")
	{
		bool fPaused = false;
		if (vParams.isDictionaryLike())
			fPaused = vParams.get("paused", false);

		s_fProtectionPaused.store(fPaused);

		HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (hDll)
		{
			if (fPaused)
			{
				typedef int32_t (*StopFn)();
				if (auto fn = (StopFn)::GetProcAddress(hDll, "owlyshield_dll_stop_protection"))
					fn();
			}
			else
			{
				typedef int32_t (*StartFn)();
				if (auto fn = (StartFn)::GetProcAddress(hDll, "owlyshield_dll_start_protection"))
					fn();
			}
		}

		LOGLVL(Critical, FMT("detnotif RPC: protection PAUSED state set to " << (fPaused ? "TRUE" : "FALSE")));
		return Dictionary({ {"success", true}, {"paused", fPaused} });
	}

	if (vCommand == "getProtectionStatus")
	{
		return Dictionary({ {"paused", s_fProtectionPaused.load()} });
	}

	error::OperationNotSupported(SL, FMT("Unsupported command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
}

} // namespace cmd

/// @}