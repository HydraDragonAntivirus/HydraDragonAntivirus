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

#include <libcore/inc/kstack_resolve.hpp>
#include <libcore/inc/service.hpp>
#include <libcloud/inc/fls.hpp>

#include <deque>
#include <atomic>
#include <fstream>
#include <sstream>
#include <string>
#include <algorithm>
#include <cctype>
#include <mutex>
#include <tlhelp32.h>

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

	// Persistent local-verdict cache: sha1 (lowercase) -> engine verdict.
	// Local engines (ML + ClamAV) cost seconds per file while the cloud is
	// cheap and re-queried every scan — so engine results are remembered
	// across scans AND service restarts. Hash-keyed, therefore
	// self-invalidating on content change. TTL bounds staleness against
	// model/signature updates.
	struct LocalVerdictEntry { int verdict; std::string name; long long timestamp; };
	static std::unordered_map<std::string, LocalVerdictEntry> s_localVerdicts;
	static std::mutex s_mtxLocalVerdicts;
	static std::atomic<bool> s_bLocalVerdictsLoaded = false;
	static size_t s_nLocalVerdictFileLines = 0;
	static const wchar_t* const c_szLocalVerdictFile = L"local_verdicts.db";
	static const size_t kLocalVerdictMaxEntries = 20000;
	static const long long kLocalVerdictTtlSec = 7LL * 24 * 60 * 60;

	static long long localVerdictNow()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();
	}

	static void rewriteLocalVerdictsLocked()
	{
		for (const auto* szDir : c_szMalwareDbDirs)
		{
			std::wstring wsDb = std::wstring(szDir) + L"\\" + c_szLocalVerdictFile;
			std::ofstream ofs(wsDb, std::ios::trunc);
			if (!ofs.is_open())
				continue;
			for (const auto& kv : s_localVerdicts)
				ofs << kv.first << "|" << kv.second.verdict << "|"
					<< kv.second.timestamp << "|" << kv.second.name << "\n";
		}
		s_nLocalVerdictFileLines = s_localVerdicts.size();
	}

	static void loadLocalVerdicts()
	{
		std::scoped_lock lock(s_mtxLocalVerdicts);
		if (s_bLocalVerdictsLoaded.load())
			return;
		s_bLocalVerdictsLoaded.store(true);
		size_t lines = 0;
		for (const auto* szDir : c_szMalwareDbDirs)
		{
			std::wstring wsDb = std::wstring(szDir) + L"\\" + c_szLocalVerdictFile;
			std::ifstream ifs(wsDb);
			if (!ifs.is_open())
				continue;
			std::string line;
			while (std::getline(ifs, line))
			{
				if (line.empty() || line[0] == '#')
					continue;
				++lines;
				size_t p1 = line.find('|');
				if (p1 == std::string::npos)
					continue;
				size_t p2 = line.find('|', p1 + 1);
				if (p2 == std::string::npos)
					continue;
				LocalVerdictEntry e;
				try { e.verdict = std::stoi(line.substr(p1 + 1, p2 - p1 - 1)); }
				catch (...) { continue; }
				if (e.verdict < 0 || e.verdict > 2)
					continue;
				size_t p3 = line.find('|', p2 + 1);
				std::string ts = (p3 == std::string::npos)
					? line.substr(p2 + 1) : line.substr(p2 + 1, p3 - p2 - 1);
				try { e.timestamp = std::stoll(ts); }
				catch (...) { continue; }
				e.name = (p3 == std::string::npos) ? std::string() : line.substr(p3 + 1);
				if (!e.name.empty() && e.name.back() == '\r')
					e.name.pop_back();
				std::string h = toLowerStr(line.substr(0, p1));
				if (!h.empty())
					s_localVerdicts[h] = e; // last wins
			}
		}
		s_nLocalVerdictFileLines = lines;
		// Compact away duplicate/stale lines when the file bloats.
		if (!s_localVerdicts.empty() && lines > 3 * s_localVerdicts.size())
			rewriteLocalVerdictsLocked();
	}

	// Returns true on a fresh cache hit (fills v/name). Misses, expired
	// entries and empty hashes return false (caller runs the engines).
	static bool lookupLocalVerdict(const std::string& sHash, int& v, std::string& name)
	{
		if (sHash.empty())
			return false;
		if (!s_bLocalVerdictsLoaded.load())
			loadLocalVerdicts();
		std::scoped_lock lock(s_mtxLocalVerdicts);
		auto it = s_localVerdicts.find(toLowerStr(sHash));
		if (it == s_localVerdicts.end())
			return false;
		if (localVerdictNow() - it->second.timestamp > kLocalVerdictTtlSec)
		{
			s_localVerdicts.erase(it);
			return false;
		}
		v = it->second.verdict;
		name = it->second.name;
		return true;
	}

	static void storeLocalVerdict(const std::string& sHash, int v, const std::string& name)
	{
		if (sHash.empty())
			return;
		if (!s_bLocalVerdictsLoaded.load())
			loadLocalVerdicts();
		std::scoped_lock lock(s_mtxLocalVerdicts);
		std::string h = toLowerStr(sHash);
		if (s_localVerdicts.size() >= kLocalVerdictMaxEntries
			&& s_localVerdicts.find(h) == s_localVerdicts.end())
			return; // full: degrade gracefully, memory stays bounded
		s_localVerdicts[h] = LocalVerdictEntry{v, name, localVerdictNow()};
		for (const auto* szDir : c_szMalwareDbDirs)
		{
			std::wstring wsDb = std::wstring(szDir) + L"\\" + c_szLocalVerdictFile;
			std::ofstream ofs(wsDb, std::ios::app);
			if (ofs.is_open())
				ofs << h << "|" << v << "|" << localVerdictNow() << "|" << name << "\n";
		}
		if (++s_nLocalVerdictFileLines > 3 * s_localVerdicts.size())
			rewriteLocalVerdictsLocked();
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
// Second-layer PUA or Malware registry cleanup (backstop for cases where
// revert_registry missed the key). Driven solely by the PTM
// "registryDeleteTarget" event field (abstractPath form produced by the
// event enricher, e.g. "%hklm%\software\gameo").
//
// Safety: never acts without that field; never deletes a hive root
// (empty subkey is refused); ERROR_FILE_NOT_FOUND counts as success
// (the key is already gone — exactly the backstop semantic).
//
static std::string toLowerAsciiLocal(const std::string& s)
{
	std::string out(s);
	for (std::string::iterator it = out.begin(); it != out.end(); ++it)
		*it = static_cast<char>(std::tolower(static_cast<unsigned char>(*it)));
	return out;
}

static std::wstring widenUtf8Local(const std::string& s)
{
	if (s.empty())
		return std::wstring();
	const int need = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, NULL, 0);
	if (need <= 0)
		return std::wstring();
	std::wstring out(static_cast<size_t>(need) - 1, L'\0');
	::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], need);
	return out;
}

static bool splitRegDeleteTarget(const std::string& sTarget, HKEY& hRoot, std::wstring& sSubKey)
{
	hRoot = nullptr;
	sSubKey.clear();

	std::string sLow = toLowerAsciiLocal(sTarget);
	// Trim surrounding whitespace.
	const char* ws = " \t\r\n";
	const std::string::size_type b = sLow.find_first_not_of(ws);
	if (b == std::string::npos)
		return false;
	const std::string::size_type e = sLow.find_last_not_of(ws);
	const std::string s = sLow.substr(b, e - b + 1);

	struct PrefixMap { const char* prefix; HKEY root; };
	static const PrefixMap maps[] = {
		{ "%hklm%\\", HKEY_LOCAL_MACHINE },
		{ "%hkcu%\\", HKEY_CURRENT_USER },
		{ "hkey_local_machine\\", HKEY_LOCAL_MACHINE },
		{ "hkey_current_user\\", HKEY_CURRENT_USER },
		{ "hkey_classes_root\\", HKEY_CLASSES_ROOT },
		{ "hkey_users\\", HKEY_USERS },
		{ "hkey_current_config\\", HKEY_CURRENT_CONFIG },
		{ "\\registry\\machine\\", HKEY_LOCAL_MACHINE },
		{ "\\registry\\user\\", HKEY_USERS },
	};

	std::string sRest;
	for (size_t i = 0; i < sizeof(maps) / sizeof(maps[0]); ++i)
	{
		const std::string pre(maps[i].prefix);
		if (s.compare(0, pre.size(), pre) == 0)
		{
			hRoot = maps[i].root;
			sRest = sTarget.substr(b + pre.size());
			break;
		}
	}
	if (hRoot == nullptr)
		return false;

	// Never allow deleting a hive root itself.
	std::string::size_type nb = sRest.find_first_not_of("\\");
	if (nb == std::string::npos)
		return false;
	sSubKey = widenUtf8Local(sRest.substr(nb));
	return !sSubKey.empty();
}

static bool deleteRegistryTreeKey(const std::string& sTarget)
{
	HKEY hRoot = nullptr;
	std::wstring sSubKey;
	if (!splitRegDeleteTarget(sTarget, hRoot, sSubKey))
	{
		LOGLVL(Critical, FMT("detnotif: refusing registry delete of unmapped/empty target <" << sTarget << ">"));
		return false;
	}
	const LSTATUS st = ::RegDeleteTreeW(hRoot, sSubKey.c_str());
	if (st == ERROR_SUCCESS)
	{
		LOGLVL(Critical, FMT("detnotif: deleted PUA or Malware registry key <" << sTarget << ">"));
		return true;
	}
	if (st == ERROR_FILE_NOT_FOUND)
	{
		LOGLVL(Critical, FMT("detnotif: PUA or Malware registry key already gone (revert_registry handled it) <" << sTarget << ">"));
		return true;
	}
	LOGLVL(Critical, FMT("detnotif: FAILED to delete PUA or Malware registry key <" << sTarget << "> err=" << st));
	return false;
}

//
//
//
//
//
// SHA1 hex (lowercase) of a file given as UTF-8 path; "" when unreadable.
//
static std::string sha1HexOfFileUtf8(const std::string& sUtf8Path)
{
	try
	{
		if (sUtf8Path.empty())
			return {};
		int nWide = ::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, nullptr, 0);
		if (nWide <= 1)
			return {};
		std::wstring ws(nWide - 1, L'\0');
		if (::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, &ws[0], nWide) <= 0)
			return {};
		std::ifstream f(ws, std::ios::binary);
		if (!f)
			return {};
		crypt::sha1::Hasher hasher;
		char buf[65536];
		while (f)
		{
			f.read(buf, sizeof(buf));
			std::streamsize n = f.gcount();
			if (n > 0)
				hasher.update(buf, static_cast<size_t>(n));
		}
		if (f.bad())
			return {};
		auto h = hasher.finalize();
		static const char* kHex = "0123456789abcdef";
		std::string out;
		out.reserve(sizeof(h.byte) * 2);
		for (size_t i = 0; i < sizeof(h.byte); ++i)
		{
			unsigned char b = static_cast<unsigned char>(h.byte[i]);
			out.push_back(kHex[b >> 4]);
			out.push_back(kHex[b & 0xF]);
		}
		return out;
	}
	catch (...) { return {}; }
}

// Bulk-screen budget guard: files definitely above the cap skip the
// unbounded parts (full-file SHA1 + cloud lookup) and keep an Unknown row.
// The local engines below are self-capped (ML 64MB, ClamAV 100MB scan) and
// still run. Any lookup failure returns false (attempt as before).
static bool bulkHashOverBudget(const std::string& sUtf8Path)
{
	try
	{
		int nWide = ::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, nullptr, 0);
		if (nWide <= 1)
			return false;
		std::wstring ws(nWide - 1, L'\0');
		if (::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, &ws[0], nWide) <= 0)
			return false;
		WIN32_FILE_ATTRIBUTE_DATA fad = {};
		if (!::GetFileAttributesExW(ws.c_str(), GetFileExInfoStandard, &fad))
			return false;
		ULARGE_INTEGER size;
		size.LowPart = fad.nFileSizeLow;
		size.HighPart = fad.nFileSizeHigh;
		static const unsigned long long kBulkHashMaxBytes = 512ULL * 1024ULL * 1024ULL;
		return size.QuadPart > kBulkHashMaxBytes;
	}
	catch (...) { return false; }
}

// Int-only verdict (kept for compatibility); the name variant below, with
// its legacy-DLL fallback, is the single implementation now.
static int rustScanVerdict(const std::string& sUtf8Path);

// Same as rustScanVerdict, plus the human-readable cause (signature name,
// EICAR-Test-File, Signer:{name}, model detection name) in sNameOut.
// Display-only (reputation screen); verdict semantics identical.
static int rustScanVerdictName(const std::string& sUtf8Path, std::string& sNameOut)
{
	typedef int32_t (*ScanFileNameFn)(const uint16_t*, uint32_t, uint16_t*, uint32_t);
	static HMODULE s_hDllName = nullptr;
	static ScanFileNameFn s_fnName = nullptr;
	static bool s_triedName = false;
	if (!s_triedName)
	{
		s_triedName = true;
		s_hDllName = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (!s_hDllName) s_hDllName = ::LoadLibraryW(L"owlyshield_ransom.dll");
		if (s_hDllName)
			s_fnName = reinterpret_cast<ScanFileNameFn>(
				::GetProcAddress(s_hDllName, "owlyshield_scan_file_name"));
	}
	sNameOut.clear();
	if (sUtf8Path.empty())
		return 0;
	if (!s_fnName)
	{
		// Old DLL without the name export: fall back to the int-only
		// verdict so local scanning still works (just without names).
		// (Rebuild owlyshield_ransom.dll to get names.)
		typedef int32_t (*ScanFileFn)(const uint16_t*, uint32_t);
		static ScanFileFn s_fnLegacy = nullptr;
		static bool s_triedLegacy = false;
		if (!s_triedLegacy)
		{
			s_triedLegacy = true;
			HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
			if (!hDll) hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
			if (hDll)
				s_fnLegacy = reinterpret_cast<ScanFileFn>(
					::GetProcAddress(hDll, "owlyshield_scan_file"));
		}
		if (!s_fnLegacy)
		{
			static bool s_loggedMissing = false;
			if (!s_loggedMissing)
			{
				s_loggedMissing = true;
				LOGLVL(Critical, FMT("detnotif: local engines unavailable, neither owlyshield_scan_file_name nor owlyshield_scan_file exports found (is owlyshield_ransom.dll deployed?)"));
			}
			return 0;
		}
		int nWide = ::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, nullptr, 0);
		if (nWide <= 1)
			return 0;
		std::wstring ws(nWide - 1, L'\0');
		if (::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, &ws[0], nWide) <= 0)
			return 0;
		int r = s_fnLegacy(reinterpret_cast<const uint16_t*>(ws.c_str()),
			static_cast<uint32_t>(ws.size()));
		return (r == 2 || r == 1) ? r : 0;
	}
	int nWide = ::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, nullptr, 0);
	if (nWide <= 1)
		return 0;
	std::wstring ws(nWide - 1, L'\0');
	if (::MultiByteToWideChar(CP_UTF8, 0, sUtf8Path.c_str(), -1, &ws[0], nWide) <= 0)
		return 0;
	static const int kNameCap = 1024;
	WCHAR wszName[kNameCap] = {};
	int r = s_fnName(reinterpret_cast<const uint16_t*>(ws.c_str()),
		static_cast<uint32_t>(ws.size()), reinterpret_cast<uint16_t*>(wszName), kNameCap);
	if (r != 2 && r != 1)
		return 0;
	int nUtf8 = ::WideCharToMultiByte(CP_UTF8, 0, wszName, -1, nullptr, 0, nullptr, nullptr);
	if (nUtf8 > 1)
	{
		std::string s(nUtf8 - 1, '\0');
		if (::WideCharToMultiByte(CP_UTF8, 0, wszName, -1, &s[0], nUtf8, nullptr, nullptr) > 0)
			sNameOut = s;
	}
	return r;
}

static int rustScanVerdict(const std::string& sUtf8Path)
{
	std::string dummy;
	return rustScanVerdictName(sUtf8Path, dummy);
}

// Merged local verdict: enriched verdict (if 1/2), Rust engines, known-DB.
// Malicious (2) always wins; Safe (1) beats unknown; else 0.
// Slow engines (ML + ClamAV) run only while the cloud is undecided
// (nCloudVerdict other than Safe/Malicious); engine results are hash-keyed
// in the persistent cache, so repeat listings skip the engines.
static int mergeLocalVerdict(int enriched, const std::string& sPath, const std::string& sHash,
	int nCloudVerdict, std::string& sLocalName)
{
	int v = (enriched == 1 || enriched == 2) ? enriched : 0;
	try
	{
		if (DetectionNotifier::isKnownMalware(sPath, sHash))
			return 2;
	}
	catch (...) {}
	if (nCloudVerdict == 1 || nCloudVerdict == 2)
		return v;
	int cachedV = 0;
	std::string cachedName;
	if (!sHash.empty() && lookupLocalVerdict(sHash, cachedV, cachedName))
	{
		if (cachedV == 2)
			return 2;
		if (cachedV == 1 && v == 0)
			v = 1;
		sLocalName = cachedName;
		return v;
	}
	int r = rustScanVerdictName(sPath, sLocalName);
	if (r == 2)
		v = 2;
	else if (r == 1 && v == 0)
		v = 1;
	else if (r == 0)
		sLocalName.clear();
	if (!sHash.empty())
		storeLocalVerdict(sHash, (r == 2 || r == 1) ? r : 0, sLocalName);
	return v;
}

Variant DetectionNotifier::execute(Variant vCommand, Variant vParams){
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
			else if (vEvent.has("processes"))
			{
				try
				{
					auto vSeq = vEvent.get("processes");
					if (vSeq.getType() == variant::ValueType::Sequence && vSeq.getSize() > 0)
					{
						auto lastProc = vSeq[vSeq.getSize() - 1];
						if (lastProc.has("verdict"))
						{
							nVerdict = static_cast<int64_t>(lastProc["verdict"]);
						}
					}
				}
				catch (...) {}
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
				//    a) Any explicit malware ancestor process (verdict == 2 ONLY, or known malware).
				//       NOTE: verdict 3 == FileVerdict::Unknown (clean/temiz dosya da 3 verir).
				//       Unknown must NEVER be treated as malware, otherwise every
				//       Explorer copy (flsVerdict 3) becomes "root malware".
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

								// Check if this ancestor is explicit malware or known malware.
								// verdict 2 == MALWARE. verdict 3 == Unknown -> NOT malware.
								if (vVal == 2 || (!pPath.empty() && isKnownMalware(pPath, pHash)))
								{
									sRootMalwarePath = pPath;
									sRootMalwareHash = pHash;
									nRootMalwarePid = pPid;
									nRootMalwareVerdict = 2;
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

			if (!sPath.empty())
			{
				bool bIsTrustedByCompanyWhitelist = false;
				bool bIsMaliciousVendor = false;

				HMODULE hOwly = ::GetModuleHandleW(L"owlyshield_ransom.dll");
				if (!hOwly) hOwly = ::LoadLibraryW(L"owlyshield_ransom.dll");
				if (hOwly)
				{
					std::string sDosCheck = NtPathToDosPathString(sPath);
					const std::string& sPathForSig = sDosCheck.empty() ? sPath : sDosCheck;
					std::wstring wsPath;
					int nWideLen = ::MultiByteToWideChar(CP_UTF8, 0, sPathForSig.c_str(), static_cast<int>(sPathForSig.length()), nullptr, 0);
					if (nWideLen > 0)
					{
						wsPath.resize(nWideLen);
						::MultiByteToWideChar(CP_UTF8, 0, sPathForSig.c_str(), static_cast<int>(sPathForSig.length()), &wsPath[0], nWideLen);
					}
					else
					{
						wsPath.assign(sPathForSig.begin(), sPathForSig.end());
					}

					// 1. Check if the signer belongs to known malicious or PUA or Malware vendors
					typedef int32_t (*IsMaliciousSignerFn)(const wchar_t*, uint32_t);
					auto fnCheckMalicious = (IsMaliciousSignerFn)::GetProcAddress(hOwly, "owlyshield_is_malicious_company_signer");
					if (fnCheckMalicious && fnCheckMalicious(wsPath.c_str(), static_cast<uint32_t>(wsPath.length())) == 1)
					{
						bIsMaliciousVendor = true;
						nVerdict = 2; // Strict malware verdict
						LOGLVL(Critical, FMT("detnotif: MALICIOUS/PUA VENDOR SIGNATURE DETECTED for <" << sPath << ">. Strict enforcement active."));
					}

					// 2. Check if the signer is in trusted company whitelist (only if not malicious and rule permits)
					if (bShouldTrustCompanyWhitelist && !bIsMaliciousVendor)
					{
						typedef int32_t (*IsTrustedSignerFn)(const wchar_t*, uint32_t);
						auto fnCheckTrusted = (IsTrustedSignerFn)::GetProcAddress(hOwly, "owlyshield_is_trusted_company_signer");
						if (fnCheckTrusted && fnCheckTrusted(wsPath.c_str(), static_cast<uint32_t>(wsPath.length())) == 1)
						{
							bIsTrustedByCompanyWhitelist = true;
						}
					}
				}

				bool bIsTrustedByFlsCloud = (bShouldTrustFlsCloud && nVerdict == 1 && !bIsMaliciousVendor);

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

		// Surface the flagged registry key itself (virus/PUA persistence):
		// operators must see WHICH key, not just which process. Primary
		// source is the PTM "registryDeleteTarget" field, but MLE detections
		// (e.g. mle_pua_registry_write) usually don't carry it; fall back to
		// the enriched registry object the event enricher always populates
		// for registry telemetry (abstractPath -> path -> rawPath), plus the
		// value name when present so FP triage can pinpoint the entry.
		{
			try
			{
				std::string sRegTitle;
				if (vEvent.has("registryDeleteTarget"))
					sRegTitle = std::string(vEvent["registryDeleteTarget"]);
				if ((sRegTitle.empty() || sRegTitle == "<undefined>" || sRegTitle == "null")
					&& vEvent.has("registryDeleteTargetRaw"))
				{
					const std::string sRawTitle = std::string(vEvent["registryDeleteTargetRaw"]);
					if (!sRawTitle.empty() && sRawTitle != "<undefined>" && sRawTitle != "null")
						sRegTitle = sRawTitle;
				}
				if (sRegTitle.empty() || sRegTitle == "<undefined>" || sRegTitle == "null")
				{
					sRegTitle = tryPaths({
						"registry.abstractPath",
						"registry.path",
						"registry.rawPath"
					});
				}
				if (!sRegTitle.empty() && sRegTitle != "<undefined>" && sRegTitle != "null")
				{
					const std::string sRegValue = extractValidPath("registry.name");
					if (!sRegValue.empty())
						sRegTitle += " [" + sRegValue + "]";
					sTitle += (sTitle.empty() ? "" : " | reg: ") + sRegTitle;
				}
			}
			catch (...) {}
		}

		// Kernel-stack attribution (stall diagnostics): the driver ships raw
		// return addresses in file.kernelStack; resolve them to
		// module!export chains (no PDB engine needed) so a file stall names
		// its filter right in the title. Raw hex stays in the event for
		// offline forensics; resolution runs only here (detections), never
		// per telemetry packet.
		{
			try
			{
				// Preferred: parse-time resolution (libsysmon) already stored
				// the flat kernelStackSymbols string. Fall back to resolving
				// the raw hex here for events that bypassed parse (e.g.
				// pattern-created or directly injected detections).
				std::string sResolved;
				if (auto optS = variant::getByPathSafe(vEvent, "kernelStackSymbols"))
					sResolved = std::string(optS.value());
				if ((sResolved.empty() || sResolved == "<undefined>" || sResolved == "null"))
				{
					std::string sRawStack;
					if (auto optK = variant::getByPathSafe(vEvent, "file.kernelStack"))
						sRawStack = std::string(optK.value());
					if (!sRawStack.empty() && sRawStack != "<undefined>" && sRawStack != "null")
					{
						uint32_t nStackPid = 0;
						if (nGid != 0)
							nStackPid = static_cast<uint32_t>(nGid);
						else if (auto optPid = variant::getByPathSafe(vEvent, "process.pid"))
						{
							try { nStackPid = static_cast<uint32_t>(optPid.value()); }
							catch (...) {}
						}
						sResolved = kstack::resolveStackForPid(sRawStack, nStackPid, 6);
						if (!sResolved.empty())
							vEvent.put("kernelStackSymbols", sResolved);
					}
				}
				if (!sResolved.empty() && sResolved != "<undefined>" && sResolved != "null")
					sTitle += (sTitle.empty() ? "" : " | kstack: ") + sResolved;
			}
			catch (...) {}
		}

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

			// 1b. Second-layer PUA or Malware registry cleanup: delete the offending key
			// when revert_registry missed it. Driven by the PTM
			// "registryDeleteTarget" event field, falling back to
			// "registryDeleteTargetRaw" when abstractPath is empty;
			// independent of file quarantine.
			if (vEvent.has("registryDeleteTarget") || vEvent.has("registryDeleteTargetRaw"))
			{
				try
				{
					std::string sRegTarget;
					if (vEvent.has("registryDeleteTarget"))
						sRegTarget = std::string(vEvent["registryDeleteTarget"]);
					if ((sRegTarget.empty() || sRegTarget == "<undefined>" || sRegTarget == "null")
						&& vEvent.has("registryDeleteTargetRaw"))
					{
						const std::string sRaw = std::string(vEvent["registryDeleteTargetRaw"]);
						if (!sRaw.empty() && sRaw != "<undefined>" && sRaw != "null")
							sRegTarget = sRaw;
					}
					if (!sRegTarget.empty() && sRegTarget != "<undefined>" && sRegTarget != "null")
						deleteRegistryTreeKey(sRegTarget);
				}
				catch (...) {}
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

	if (vCommand == "getMitmStatus")
	{
		bool fEnabled = false;
		HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (hDll)
		{
			typedef int32_t (*GetMitmFn)();
			if (auto fn = (GetMitmFn)::GetProcAddress(hDll, "owlyshield_firewall_get_mitm_enabled"))
				fEnabled = (fn() == 1);
		}
		return Dictionary({ {"enabled", fEnabled} });
	}

	if (vCommand == "setMitmEnabled")
	{
		bool fEnabled = true;
		if (vParams.isDictionaryLike())
			fEnabled = vParams.get("enabled", true);

		int nResult = 0;
		HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (hDll)
		{
			typedef int32_t (*SetMitmFn)(uint8_t);
			if (auto fn = (SetMitmFn)::GetProcAddress(hDll, "owlyshield_firewall_set_mitm_enabled"))
				nResult = fn(fEnabled ? 1 : 0);
		}

		const bool fApplied = (fEnabled && nResult == 1);
		LOGLVL(Critical, FMT("detnotif RPC: firewall MITM interception set to " << (fApplied ? "ENABLED" : "DISABLED")));
		return Dictionary({ {"success", nResult == 1}, {"enabled", fApplied} });
	}

	// Reputation screen: cloud verdicts for file hashes, display only.
	// No quarantine, no block, no DB writes. Unknown service/hash yields 3.
	if (vCommand == "getFileReputationBulk")
	{
		Variant vOut = Sequence();
		auto pFls = queryInterface<cmd::cloud::fls::IFlsClient>(queryService("flsService"));
		if (vParams.isDictionaryLike() && vParams.has("paths"))
		{
			auto vPaths = vParams.get("paths");
			if (vPaths.getType() == variant::ValueType::Sequence)
			{
				for (size_t i = 0; i < vPaths.getSize() && vOut.getSize() < 200; ++i)
				{
					try
					{
					std::string sPath = vPaths[i];
					if (sPath.empty())
						continue;
					std::string sHash;
					int nVerdict = 3; // Unknown by default
					if (!bulkHashOverBudget(sPath))
					{
						sHash = sha1HexOfFileUtf8(sPath);
						if (!sHash.empty())
						{
							if (pFls)
							{
								try
								{
									auto v = pFls->getFileVerdict(sHash);
									nVerdict = static_cast<int>(v);
								}
								catch (...)
								{
									nVerdict = 4; // Cloud lookup failed
								}
							}
							else
							{
								nVerdict = 4; // Offline / Lookup failed
							}
						}
					}
					int nLocal = 0; // Rust engines + known-malicious DB
					std::string sLocalName;
					try
					{
						// Cheap authoritative list first, always.
						if (DetectionNotifier::isKnownMalware(sPath, sHash))
							nLocal = 2;
						// Slow local engines (ML + ClamAV) only while the cloud
						// is undecided: Safe/Malicious from FLS needs no
						// second opinion. Engine results are hash-keyed in
						// the persistent local_verdicts.db (self-invalidating
						// on content change), so repeat scans skip the engines.
						if (nVerdict != 1 && nVerdict != 2)
						{
							int cachedV = 0;
							std::string cachedName;
							if (!sHash.empty()
								&& lookupLocalVerdict(sHash, cachedV, cachedName))
							{
								if (cachedV == 2)
									nLocal = 2;
								else if (cachedV == 1 && nLocal == 0)
									nLocal = 1;
								sLocalName = cachedName;
							}
							else
							{
								int r = rustScanVerdictName(sPath, sLocalName);
								if (r == 2)
									nLocal = 2;
								else if (r == 1 && nLocal == 0)
									nLocal = 1;
								if (!sHash.empty())
									storeLocalVerdict(sHash, (r == 2 || r == 1) ? r : 0, sLocalName);
							}
						}
					}
					catch (...) {}
					vOut.push_back(Dictionary({
						{"path", sPath}, {"hash", sHash},
						{"verdict", nVerdict}, {"local", nLocal},
						{"local_name", sLocalName} }));
					}
					catch (...) {}
				}
			}
		}
		return Dictionary({ {"results", vOut} });
	}

	// Verdict screen: running processes enriched by every engine
	// (process provider info + FLS cloud verdict). Display only.
	if (vCommand == "getProcessReputation")
	{
		Variant vOut = Sequence();
		auto pProc = queryInterface<sys::win::IProcessInformation>(queryService("processDataProvider"));
		auto pFls = queryInterface<cmd::cloud::fls::IFlsClient>(queryService("flsService"));
		if (pProc)
		{
			HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hSnap != INVALID_HANDLE_VALUE)
			{
				PROCESSENTRY32W pe = {};
				pe.dwSize = sizeof(pe);
				for (BOOL ok = ::Process32FirstW(hSnap, &pe); ok && vOut.getSize() < 400;
					ok = ::Process32NextW(hSnap, &pe))
				{
					try
					{
						auto vInfo = pProc->enrichProcessInfo(
							Dictionary({ {"pid", static_cast<int64_t>(pe.th32ProcessID)} }));
						std::string sPath, sHash, sUser;
						try { sPath = std::string(vInfo["imagePath"]); } catch (...) {}
						if (sPath.empty())
						{
							try { sPath = std::string(vInfo["path"]); } catch (...) {}
						}
						try { sHash = std::string(vInfo["imageHash"]); } catch (...) {}
						if (sHash.empty())
						{
							try { sHash = std::string(vInfo["hash"]); } catch (...) {}
						}
						try { sUser = std::string(vInfo["userName"]); } catch (...) {}
						int nVerdict = 3;
						if (!sHash.empty() && pFls)
						{
							try
							{
								nVerdict = static_cast<int>(pFls->getFileVerdict(sHash));
							}
							catch (...) {}
						}
					int nEnriched = 0;
					try { nEnriched = static_cast<int>(vInfo["verdict"]); } catch (...) {}
					std::string sLocalName;
					int nLocal = mergeLocalVerdict(nEnriched, sPath, sHash, nVerdict, sLocalName);
					vOut.push_back(Dictionary({
						{"pid", static_cast<int64_t>(pe.th32ProcessID)},
						{"path", sPath}, {"hash", sHash},
						{"user", sUser}, {"verdict", nVerdict},
						{"local", nLocal}, {"local_name", sLocalName} }));
					}
					catch (...) {}
				}
				::CloseHandle(hSnap);
			}
		}
		return Dictionary({ {"results", vOut} });
	}

	if (vCommand == "quarantineFile")
	{
		std::string sPath;
		if (vParams.isDictionaryLike())
			sPath = vParams.get("path", sPath);
		if (sPath.empty())
			return Dictionary({ {"success", false}, {"error", "empty path"} });
		std::string sHash = sha1HexOfFileUtf8(sPath);
		int nResult = -1;
		HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (!hDll) hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
		if (hDll)
		{
			typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
			if (auto fn = (QuarantineFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file"))
				nResult = fn(reinterpret_cast<const uint8_t*>(sPath.c_str()), static_cast<uint32_t>(sPath.size()));
		}
		if (nResult == 0)
		{
			DetectionNotifier::recordMalwareDetection(sPath, sHash);
			LOGLVL(Critical, FMT("detnotif RPC: quarantined file <" << sPath << "> on user request"));
			return Dictionary({ {"success", true} });
		}
		return Dictionary({ {"success", false} });
	}

	error::OperationNotSupported(SL, FMT("Unsupported command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during execution of a command <" << vCommand << ">"));
}

} // namespace cmd

/// @}