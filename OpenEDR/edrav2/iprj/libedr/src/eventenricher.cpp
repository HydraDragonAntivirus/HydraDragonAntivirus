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
#include "openedr_static_runtime.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <mutex>
#include <atomic>
#include <chrono>
#include <thread>
#include <filesystem>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <tlhelp32.h>
#include <dbghelp.h>

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

	static std::string ResolveRenameTargetPath(const std::string& sourceRaw, const std::string& targetRaw)
	{
		if (targetRaw.empty()) return "";

		std::string dosTarget = DetectionNotifier::NtPathToDosPathString(targetRaw);
		if (!dosTarget.empty() && (dosTarget.find(":\\") != std::string::npos || dosTarget.rfind("\\\\", 0) == 0))
		{
			return dosTarget;
		}

		// Target is relative or filename-only (e.g. "malware.exe" or "\malware.exe").
		// Combine with the parent directory of the source file.
		if (!sourceRaw.empty())
		{
			std::string dosSource = DetectionNotifier::NtPathToDosPathString(sourceRaw);
			if (!dosSource.empty() && (dosSource.find(":\\") != std::string::npos || dosSource.rfind("\\\\", 0) == 0))
			{
				try
				{
					std::filesystem::path srcP(dosSource);
					std::filesystem::path parentDir = srcP.parent_path();
					if (!parentDir.empty())
					{
						std::string cleanTarget = targetRaw;
						while (!cleanTarget.empty() && (cleanTarget.front() == '\\' || cleanTarget.front() == '/'))
						{
							cleanTarget.erase(cleanTarget.begin());
						}
						std::filesystem::path fullTarget = parentDir / cleanTarget;
						return fullTarget.string();
					}
				}
				catch (...) {}
			}
		}

		return dosTarget;
	}

	static std::wstring ResolveRenameTargetPathW(const std::wstring& sourceRaw, const std::wstring& targetRaw)
	{
		if (targetRaw.empty()) return L"";

		std::wstring dosTarget = NormalizeToDosPath(targetRaw);
		if (!dosTarget.empty() && (dosTarget.find(L":\\") != std::wstring::npos || dosTarget.rfind(L"\\\\", 0) == 0))
		{
			return dosTarget;
		}

		if (!sourceRaw.empty())
		{
			std::wstring dosSource = NormalizeToDosPath(sourceRaw);
			if (!dosSource.empty() && (dosSource.find(L":\\") != std::wstring::npos || dosSource.rfind(L"\\\\", 0) == 0))
			{
				try
				{
					std::filesystem::path srcP(dosSource);
					std::filesystem::path parentDir = srcP.parent_path();
					if (!parentDir.empty())
					{
						std::wstring cleanTarget = targetRaw;
						while (!cleanTarget.empty() && (cleanTarget.front() == L'\\' || cleanTarget.front() == L'/'))
						{
							cleanTarget.erase(cleanTarget.begin());
						}
						std::filesystem::path fullTarget = parentDir / cleanTarget;
						return fullTarget.wstring();
					}
				}
				catch (...) {}
			}
		}

		return dosTarget;
	}

	// JSON string escape for narrow (UTF-8/ANSI) input: backslash, quotes,
	// control chars. Paths like C:\system32 contain \s which is an INVALID
	// JSON escape when written raw (broke 6030/6031 lines of one dataset).
	std::string JsonEscapeA(const std::string& sIn)
	{
		std::string out;
		out.reserve(sIn.size() + 16);
		char szBuf[8];
		for (unsigned char c : sIn)
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
				if (c < 0x20)
				{
					sprintf_s(szBuf, "\\u%04x", (unsigned)c);
					out += szBuf;
				}
				else
					out += (char)c;
			}
		}
		return out;
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

	// Robust SDK boolean read: accepts REG_SZ ("1"/"true", case-insensitive)
	// and REG_DWORD (!=0). regedit users often write DWORD; strict REG_SZ-only
	// reads silently evaluated those as FALSE (training "never starts" bug class).
	bool ReadSdkBool(const char* sValueName, bool bDefault)
	{
		BYTE buf[16] = {};
		ULONG cb = sizeof(buf);
		DWORD dwType = 0;
		const LONG rc = ::RegGetValueA(HKEY_LOCAL_MACHINE,
			"SOFTWARE\\Owlyshield\\SDK", sValueName,
			RRF_RT_ANY, &dwType, buf, &cb);
		if (rc != ERROR_SUCCESS)
			return bDefault;
		if (dwType == REG_DWORD && cb >= sizeof(DWORD))
		{
			DWORD v = 0;
			memcpy(&v, buf, sizeof(v));
			return v != 0;
		}
		buf[sizeof(buf) - 1] = 0;
		std::string s((const char*)buf);
		for (auto& c : s) c = (char)::tolower((unsigned char)c);
		size_t a = s.find_first_not_of(" \t\r\n\"'");
		size_t b = s.find_last_not_of(" \t\r\n\"'");
		if (a == std::string::npos)
			return false;
		s = s.substr(a, b - a + 1);
		return s == "1" || s == "true" || s == "yes" || s == "on";
	}

	// HKLM\SOFTWARE\Owlyshield\SDK!TRAINING_MODE ("1") enables persistent
	// unknown behavior telemetry recording for offline ML training.
	// Defaults to FALSE (disabled) unless explicitly enabled in the registry.
	bool IsTrainingModeEnabled()
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
			s_cached.store(ReadSdkBool("TRAINING_MODE", false), std::memory_order_relaxed);
		}
		return s_cached.load(std::memory_order_relaxed);
	}

	// Read watched training directory from HKLM\SOFTWARE\Owlyshield\SDK!TRAINING_WATCH_DIR
	// Empty / unset means NO path restriction (legacy behavior: TRAINING_MODE=1 records all).
	std::string GetTrainingWatchDir()
	{
		static std::string s_cachedDir = "";
		static std::atomic<uint64_t> s_lastDirCheck{ 0 };

		const uint64_t nNow = (uint64_t)std::chrono::duration_cast<
			std::chrono::milliseconds>(std::chrono::steady_clock::now()
				.time_since_epoch()).count();
		const uint64_t nLast = s_lastDirCheck.load(std::memory_order_relaxed);

		if (nNow - nLast >= 3000)
		{
			s_lastDirCheck.store(nNow, std::memory_order_relaxed);
			char szPath[MAX_PATH] = "";
			ULONG cb = sizeof(szPath);
			const LONG rc = ::RegGetValueA(HKEY_LOCAL_MACHINE,
				"SOFTWARE\\Owlyshield\\SDK", "TRAINING_WATCH_DIR",
				RRF_RT_REG_SZ, nullptr, szPath, &cb);
			if (rc == ERROR_SUCCESS && szPath[0] != '\0')
			{
				std::string s(szPath);
				for (auto& c : s) c = (char)::tolower((unsigned char)c);
				s_cachedDir = s;
			}
			else
			{
				s_cachedDir = "";
			}
		}
		return s_cachedDir;
	}

	// Check if the process path resides within the designated training directory.
	// Empty / unset TRAINING_WATCH_DIR means NO restriction: any process is
	// eligible (legacy behavior where TRAINING_MODE=1 recorded everything).
	bool IsProcessInTrainingDir(const std::string& sExePath)
	{
		if (sExePath.empty())
			return false;

		std::string sWatch = GetTrainingWatchDir();

		// Trim whitespace and quotation marks
		size_t first = sWatch.find_first_not_of(" \t\r\n\"'");
		size_t last = sWatch.find_last_not_of(" \t\r\n\"'");
		std::string sTrimmed = (first != std::string::npos && last != std::string::npos)
			? sWatch.substr(first, last - first + 1)
			: "";

		// Empty means no path restriction: capture all processes in training mode
		if (sTrimmed.empty())
			return true;

		// Wildcard "*.*" or "*" means ignore path restriction and capture all processes in training mode
		if (sTrimmed == "*.*" || sTrimmed == "*" || sTrimmed.find("*.*") != std::string::npos)
			return true;

		std::string sLowerExe = sExePath;
		for (auto& c : sLowerExe) c = (char)::tolower((unsigned char)c);

	// Direct path match or contained inside watched directory
		return (sLowerExe.find(sTrimmed) != std::string::npos);
	}

	// Read watched training DLL directory from HKLM\SOFTWARE\Owlyshield\SDK!TRAINING_WATCH_DLL_DIR
	// Defaults to empty ("") if not explicitly set (meaning no DLL folder restriction).
	std::string GetTrainingWatchDllDir()
	{
		static std::string s_cachedDllDir = "";
		static std::atomic<uint64_t> s_lastDllDirCheck{ 0 };

		const uint64_t nNow = (uint64_t)std::chrono::duration_cast<
			std::chrono::milliseconds>(std::chrono::steady_clock::now()
				.time_since_epoch()).count();
		const uint64_t nLast = s_lastDllDirCheck.load(std::memory_order_relaxed);

		if (nNow - nLast >= 3000)
		{
			s_lastDllDirCheck.store(nNow, std::memory_order_relaxed);
			char szPath[MAX_PATH] = "";
			ULONG cb = sizeof(szPath);
			const LONG rc = ::RegGetValueA(HKEY_LOCAL_MACHINE,
				"SOFTWARE\\Owlyshield\\SDK", "TRAINING_WATCH_DLL_DIR",
				RRF_RT_REG_SZ, nullptr, szPath, &cb);
			if (rc == ERROR_SUCCESS && szPath[0] != '\0')
			{
				std::string s(szPath);
				for (auto& c : s) c = (char)::tolower((unsigned char)c);
				s_cachedDllDir = s;
			}
			else
			{
				s_cachedDllDir = "";
			}
		}
		return s_cachedDllDir;
	}

	// Check if an API hook or module event originated from the watched DLL directory
	bool IsApiDllInTrainingWatchDir(const Variant& vEvent)
	{
		std::string sWatchDll = GetTrainingWatchDllDir();
		if (sWatchDll.empty())
			return true; // No DLL folder restriction specified: allow all

		// Trim whitespace and quotation marks
		size_t first = sWatchDll.find_first_not_of(" \t\r\n\"'");
		size_t last = sWatchDll.find_last_not_of(" \t\r\n\"'");
		std::string sTrimmed = (first != std::string::npos && last != std::string::npos)
			? sWatchDll.substr(first, last - first + 1)
			: sWatchDll;

		// Wildcard "*.*" or "*" means ignore DLL folder restriction
		if (sTrimmed == "*.*" || sTrimmed == "*" || sTrimmed.find("*.*") != std::string::npos)
			return true;

		// Extract DLL / module path or name from the event
		std::string sDll;
		if (auto optM = variant::getByPathSafe(vEvent, "owlyHook.apiModule"))
			sDll = std::string(optM.value());
		else if (auto optFn = variant::getByPathSafe(vEvent, "owlyHook.functionName"))
		{
			std::string sFn = std::string(optFn.value());
			auto pos = sFn.rfind('!');
			if (pos != std::string::npos)
				sDll = sFn.substr(0, pos);
			else
				sDll = sFn;
		}
		else if (auto optModPath = variant::getByPathSafe(vEvent, "module.imageFile.abstractPath"))
			sDll = std::string(optModPath.value());
		else if (auto optModRaw = variant::getByPathSafe(vEvent, "module.imageFile.rawPath"))
			sDll = std::string(optModRaw.value());
		else if (auto optModP = variant::getByPathSafe(vEvent, "module.path"))
			sDll = std::string(optModP.value());

		// If this is not an API hook or module event, pass through
		if (sDll.empty())
			return true;

		std::string sLowerDll = sDll;
		for (auto& c : sLowerDll) c = (char)::tolower((unsigned char)c);

		// Direct substring / folder path match
		if (sLowerDll.find(sTrimmed) != std::string::npos)
			return true;

		// Handle bare system DLL names (e.g. "kernel32.dll", "ntdll.dll") when watching
		// any Windows system dir (System32/SysWOW64 or plain C:\Windows: hook events
		// carry bare "module!Function" names without a path).
		if ((sTrimmed.find("system32") != std::string::npos || sTrimmed.find("syswow64") != std::string::npos
				|| sTrimmed.find("windows") != std::string::npos)
			&& sLowerDll.find('\\') == std::string::npos && sLowerDll.find('/') == std::string::npos)
		{
			return true;
		}

		return false;
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

		// Record formatted killchain sequence line (fields JSON-escaped:
		// raw Windows paths contain \s \t etc. which are invalid escapes raw).
		stream << "{\"time\":\"" << szTime << "\",\"exe\":\"" << JsonEscapeA(sExePath) << "\",\"event\":\""
		       << JsonEscapeA(sEventType) << "\",\"details\":\"" << JsonEscapeA(sDetails) << "\",\"raw\":" << sJson << "}\n";

		// Heartbeat: proves from logs that training is actually recording.
		static std::atomic<uint64_t> s_nTrainingWrites{ 0 };
		const uint64_t nWrites = s_nTrainingWrites.fetch_add(1, std::memory_order_relaxed) + 1;
		if (nWrites == 1 || nWrites % 100 == 0)
			LOGINF(FMT("training: recorded " << nWrites << " event(s) to training_data"));
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

	// HKLM\SOFTWARE\Owlyshield\SDK!THREAD_STACK_CAPTURE ("0" disables)
	// on-alert user-mode thread-stack snapshots. Defaults to TRUE (enabled)
	// when the value is missing; alert path only, so zero hot-path cost.
	bool IsThreadStackCaptureEnabled()
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
			s_cached.store(ReadSdkBool("THREAD_STACK_CAPTURE", true), std::memory_order_relaxed);
		}
		return s_cached.load(std::memory_order_relaxed);
	}

	// dbghelp entry points, loaded dynamically so no linker dependency is added.
	// Explicit W-suffixed import: the undecorated "SymInitialize" export does
	// not exist in dbghelp.dll (only SymInitializeW/A), so decltype(&SymInitialize)
	// + GetProcAddress("SymInitialize") would silently fail under UNICODE.
	typedef BOOL (WINAPI *FnStackWalk64)(DWORD, HANDLE, HANDLE, LPSTACKFRAME64,
		PVOID, PREAD_PROCESS_MEMORY_ROUTINE64, PFUNCTION_TABLE_ACCESS_ROUTINE64,
		PGET_MODULE_BASE_ROUTINE64, PTRANSLATE_ADDRESS_ROUTINE64);
	typedef BOOL (WINAPI *FnSymInitializeW)(HANDLE, PCWSTR, BOOL);
	typedef BOOL (WINAPI *FnSymCleanup)(HANDLE);
	typedef BOOL (WINAPI *FnSymFindFileInPathW)(HANDLE, PCWSTR, PCWSTR, PVOID, DWORD, DWORD, DWORD, PWSTR, PFINDFILEINPATHCALLBACKW, PVOID);
	struct DbgHelpApi
	{
		HMODULE hMod = nullptr;
		FnStackWalk64 pStackWalk64 = nullptr;
		FnSymInitializeW pSymInitialize = nullptr;
		FnSymCleanup pSymCleanup = nullptr;
		FnSymFindFileInPathW pSymFindFileInPath = nullptr;
		PFUNCTION_TABLE_ACCESS_ROUTINE64 pFuncTable = nullptr;
		PGET_MODULE_BASE_ROUTINE64 pGetModBase = nullptr;
	};

	static DbgHelpApi LoadDbgHelpApi()
	{
		DbgHelpApi api;
		api.hMod = ::LoadLibraryW(L"dbghelp.dll");
		if (!api.hMod)
			return api;
		api.pStackWalk64 = (FnStackWalk64)::GetProcAddress(api.hMod, "StackWalk64");
		api.pSymInitialize = (FnSymInitializeW)::GetProcAddress(api.hMod, "SymInitializeW");
		if (!api.pSymInitialize)
			api.pSymInitialize = (FnSymInitializeW)::GetProcAddress(api.hMod, "SymInitializeA");
		api.pSymCleanup = (FnSymCleanup)::GetProcAddress(api.hMod, "SymCleanup");
		api.pSymFindFileInPath = (FnSymFindFileInPathW)::GetProcAddress(api.hMod, "SymFindFileInPathW");
		api.pFuncTable = (PFUNCTION_TABLE_ACCESS_ROUTINE64)::GetProcAddress(api.hMod, "SymFunctionTableAccess64");
		api.pGetModBase = (PGET_MODULE_BASE_ROUTINE64)::GetProcAddress(api.hMod, "SymGetModuleBase64");
		return api;
	}

	// RAII guards: the snapshot below has many best-effort early exits;
	// handles must not leak per alert.
	struct LibGuard { HMODULE h = nullptr; ~LibGuard() { if (h) ::FreeLibrary(h); h = nullptr; } };
	struct HandleGuard { HANDLE h = nullptr; ~HandleGuard() { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); h = nullptr; } };

	// PDB identity from a PE file's CodeView record (RSDS, legacy NB10 fallback).
	// Best-effort file parse: any failure yields false, never throws.
	struct PdbIdentity
	{
		GUID guid = {};
		DWORD timestamp = 0;
		DWORD age = 0;
		bool isRsds = true;
		std::wstring fileName; // leaf only, e.g. L"ntdll.pdb"
	};

	static bool ReadFileAt(HANDLE hFile, uint64_t nOff, void* pBuf, DWORD nWant)
	{
		LARGE_INTEGER li;
		li.QuadPart = (LONGLONG)nOff;
		if (!::SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN))
			return false;
		DWORD nGot = 0;
		return ::ReadFile(hFile, pBuf, nWant, &nGot, nullptr) && nGot == nWant;
	}

	static bool LeafNameFromAnsi(const char* pStr, size_t nMax, std::wstring& wsOut)
	{
		size_t nLen = 0;
		while (nLen < nMax && pStr[nLen] != '\0')
			++nLen;
		if (nLen == 0 || nLen >= nMax)
			return false;
		const char* pLeaf = pStr + nLen;
		while (pLeaf > pStr && pLeaf[-1] != '\\' && pLeaf[-1] != '/')
			--pLeaf;
		if (*pLeaf == '\0')
			return false;
		UINT nCp = CP_UTF8;
		DWORD nFlags = MB_ERR_INVALID_CHARS;
		int nW = ::MultiByteToWideChar(nCp, nFlags, pLeaf, -1, nullptr, 0);
		if (nW <= 0)
		{
			nCp = CP_ACP;
			nFlags = 0;
			nW = ::MultiByteToWideChar(nCp, nFlags, pLeaf, -1, nullptr, 0);
		}
		if (nW <= 0)
			return false;
		wsOut.assign((size_t)nW, L'\0');
		if (!::MultiByteToWideChar(nCp, nFlags, pLeaf, -1, wsOut.data(), nW))
			return false;
		wsOut.resize((size_t)nW - 1);
		return !wsOut.empty();
	}

	static bool ReadPdbIdentity(const std::wstring& wsPath, PdbIdentity& out)
	{
		out = PdbIdentity();
		HandleGuard gFile;
		gFile.h = ::CreateFileW(wsPath.c_str(), GENERIC_READ,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!gFile.h || gFile.h == INVALID_HANDLE_VALUE)
		{
			gFile.h = nullptr;
			return false;
		}

		LARGE_INTEGER nSize = {};
		if (!::GetFileSizeEx(gFile.h, &nSize) || nSize.QuadPart < 0x1000)
			return false;

		uint8_t vHead[0x1000] = {};
		if (!ReadFileAt(gFile.h, 0, vHead, sizeof(vHead)))
			return false;
		auto rd16 = [&](size_t o) -> uint16_t
		{
			return (uint16_t)((uint16_t)vHead[o] | ((uint16_t)vHead[o + 1] << 8));
		};
		auto rd32 = [&](size_t o) -> uint32_t
		{
			return (uint32_t)vHead[o] | ((uint32_t)vHead[o + 1] << 8) |
				((uint32_t)vHead[o + 2] << 16) | ((uint32_t)vHead[o + 3] << 24);
		};

		if (vHead[0] != 'M' || vHead[1] != 'Z')
			return false;
		const uint32_t nPe = rd32(0x3C);
		if (nPe + 6 > sizeof(vHead) || vHead[nPe] != 'P' || vHead[nPe + 1] != 'E' ||
			vHead[nPe + 2] != 0 || vHead[nPe + 3] != 0)
			return false;
		const size_t nCoff = (size_t)nPe + 4;
		const uint16_t nSec = rd16(nCoff + 2);
		const uint16_t nOptSize = rd16(nCoff + 16);
		if (nSec == 0 || nSec > 96)
			return false;
		const size_t nOpt = nCoff + 20;
		if (nOpt + 2 > sizeof(vHead))
			return false;
		const uint16_t nMagic = rd16(nOpt);
		const size_t nDbgEnt = nOpt + (nMagic == 0x20b ? 112 : 96) + 6 * 8; // debug entry
		if (nDbgEnt + 8 > sizeof(vHead))
			return false;
		const uint32_t nDbgRva = rd32(nDbgEnt);
		const uint32_t nDbgSize = rd32(nDbgEnt + 4);
		if (nDbgRva == 0 || nDbgSize == 0 || nDbgSize > 64 * 28)
			return false;

		// RVA -> file offset via section table; headers are file-mapped 1:1 as fallback.
		const size_t nSecTab = nOpt + nOptSize;
		uint64_t nDbgOff = 0;
		if (nSecTab + (size_t)nSec * 40 <= sizeof(vHead))
		{
			for (uint16_t i = 0; i < nSec; ++i)
			{
				const size_t s = nSecTab + (size_t)i * 40;
				const uint32_t nVa = rd32(s + 12);
				uint32_t nSpan = rd32(s + 8); // VirtualSize
				if (rd32(s + 16) > nSpan)
					nSpan = rd32(s + 16); // SizeOfRawData
				if (nSpan > 0 && nDbgRva >= nVa && nDbgRva < nVa + nSpan)
				{
					nDbgOff = (uint64_t)rd32(s + 20) + (nDbgRva - nVa);
					break;
				}
			}
		}
		if (nDbgOff == 0)
		{
			if ((uint64_t)nDbgRva + nDbgSize > (uint64_t)nSize.QuadPart)
				return false;
			nDbgOff = nDbgRva; // inside headers
		}
		if (nDbgOff + nDbgSize > (uint64_t)nSize.QuadPart)
			return false;

		std::vector<uint8_t> vDbg(nDbgSize);
		if (!ReadFileAt(gFile.h, nDbgOff, vDbg.data(), nDbgSize))
			return false;
		auto dd32 = [&](size_t o) -> uint32_t
		{
			return (uint32_t)vDbg[o] | ((uint32_t)vDbg[o + 1] << 8) |
				((uint32_t)vDbg[o + 2] << 16) | ((uint32_t)vDbg[o + 3] << 24);
		};

		const size_t nCount = nDbgSize / 28;
		for (size_t i = 0; i < nCount; ++i)
		{
			const size_t e = i * 28;
			if (dd32(e + 12) != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;
			const uint32_t nDataSize = dd32(e + 16);
			const uint32_t nDataPtr = dd32(e + 20);
			if (nDataSize < 17 || nDataSize > 4356)
				continue;
			if ((uint64_t)nDataPtr + nDataSize > (uint64_t)nSize.QuadPart)
				continue;
			std::vector<uint8_t> vCv(nDataSize);
			if (!ReadFileAt(gFile.h, nDataPtr, vCv.data(), nDataSize))
				continue;
			if (vCv[0] == 'R' && vCv[1] == 'S' && vCv[2] == 'D' && vCv[3] == 'S' && nDataSize >= 25)
			{
				uint8_t* pId = (uint8_t*)&out.guid;
				for (int k = 0; k < 16; ++k)
					pId[k] = vCv[4 + (size_t)k];
				out.age = (uint32_t)vCv[20] | ((uint32_t)vCv[21] << 8) |
					((uint32_t)vCv[22] << 16) | ((uint32_t)vCv[23] << 24);
				out.isRsds = true;
				if (LeafNameFromAnsi((const char*)vCv.data() + 24, (size_t)nDataSize - 24, out.fileName))
					return true;
				out = PdbIdentity();
			}
			else if (vCv[0] == 'N' && vCv[1] == 'B' && vCv[2] == '1' && vCv[3] == '0')
			{
				out.timestamp = (uint32_t)vCv[8] | ((uint32_t)vCv[9] << 8) |
					((uint32_t)vCv[10] << 16) | ((uint32_t)vCv[11] << 24);
				out.age = (uint32_t)vCv[12] | ((uint32_t)vCv[13] << 8) |
					((uint32_t)vCv[14] << 16) | ((uint32_t)vCv[15] << 24);
				out.isRsds = false;
				if (LeafNameFromAnsi((const char*)vCv.data() + 16, (size_t)nDataSize - 16, out.fileName))
					return true;
				out = PdbIdentity();
			}
		}
		return false;
	}

	// On-demand PDB download for a PE file via the symbol server.
	// Explicit command path only: never called from scans or remediation
	// (network I/O can take seconds). Best-effort, never throws.
	static std::wstring FetchModulePdb(const std::wstring& wsModule, const std::wstring& wsSearch)
	{
		static std::mutex s_mtxPdb;
		std::lock_guard<std::mutex> _guard(s_mtxPdb);
		std::wstring sFound;

		PdbIdentity id;
		if (!ReadPdbIdentity(wsModule, id) || id.fileName.empty())
			return sFound;

		DbgHelpApi api = LoadDbgHelpApi();
		LibGuard gDbg;
		gDbg.h = api.hMod;
		if (!api.hMod || !api.pSymInitialize || !api.pSymCleanup || !api.pSymFindFileInPath)
			return sFound;

		const HANDLE hProc = ::GetCurrentProcess();
		if (!api.pSymInitialize(hProc, nullptr, FALSE))
			return sFound;

		std::wstring sSearch = wsSearch;
		if (sSearch.empty())
		{
			wchar_t wzTemp[MAX_PATH] = {};
			std::wstring sCache(L".\\");
			if (::GetTempPathW(MAX_PATH, wzTemp) > 0)
				sCache.assign(wzTemp);
			sCache += L"HydraSymbols";
			::CreateDirectoryW(sCache.c_str(), nullptr);
			sSearch = L"SRV*" + sCache + L"*https://msdl.microsoft.com/download/symbols";
		}

		wchar_t wzFound[1024] = {};
		BOOL fOk = FALSE;
		if (id.isRsds)
		{
			fOk = api.pSymFindFileInPath(hProc, sSearch.c_str(), id.fileName.c_str(),
				(PVOID)&id.guid, id.age, 0, SSRVOPT_GUIDPTR, wzFound, nullptr, nullptr);
		}
		else
		{
			fOk = api.pSymFindFileInPath(hProc, sSearch.c_str(), id.fileName.c_str(),
				(PVOID)&id.timestamp, id.age, 0, SSRVOPT_DWORD, wzFound, nullptr, nullptr);
		}
		api.pSymCleanup(hProc);

		if (fOk && wzFound[0] != L'\0')
			sFound.assign(wzFound);
		return sFound;
	}

	// Fire-and-forget PDB prefetch for a process image into the local symbol
	// cache (see FetchModulePdb). Posted to the pool so event processing never
	// blocks on network I/O; one fetch per image, repeats are DbgHelp cache hits.
	static void QueuePdbPrefetch(ThreadPool& pool, const std::string& sImgPath)
	{
		if (sImgPath.empty())
			return;
		std::wstring wsPath;
		try
		{
			wsPath = string::convertUtf8ToWChar(sImgPath);
		}
		catch (...)
		{
			return;
		}
		if (wsPath.empty())
			return;
		static std::mutex s_mtxSeen;
		static std::unordered_set<std::wstring> s_seen;
		{
			std::lock_guard<std::mutex> _g(s_mtxSeen);
			if (s_seen.size() > 4096)
				s_seen.clear();
			if (!s_seen.insert(string::convertToLow(wsPath)).second)
				return; // already fetched or in flight
		}
		pool.run([wsPath]()
		{
			try
			{
				FetchModulePdb(wsPath, std::wstring());
			}
			catch (...)
			{
			}
		});
	}

	static BOOL CALLBACK ReadProcMemRoutine(HANDLE hProc, DWORD64 nBase, PVOID pBuf, DWORD nSize, LPDWORD pnRead)
	{
		SIZE_T nGot = 0;
		if (!::ReadProcessMemory(hProc, (LPCVOID)(ULONG_PTR)nBase, pBuf, (SIZE_T)nSize, &nGot))
			return FALSE;
		if (pnRead)
			*pnRead = (DWORD)nGot;
		return TRUE;
	}

	// On-demand user-mode thread-stack snapshot, Process-Hacker style:
	// no hooks, no ETW. Enumerates threads of <nPid> via ToolHelp32, suspends
	// each briefly, walks with StackWalk64 and records "module+offset" per
	// frame (raw addresses, symbols resolved offline in the training pipe).
	// Best-effort: any failure yields a partial/empty string, never throws,
	// never blocks remediation (caller runs this before kill, ~ms cost).
	// Caps: max 8 threads x 10 frames, max 8192 chars total.
	std::string CaptureThreadStacks(uint32_t nPid, int nMaxThreads = 8, int nMaxFrames = 10)
	{
		static std::mutex s_mtxWalk;
		std::lock_guard<std::mutex> _guard(s_mtxWalk);

		std::string sOut;
		if (nPid == 0 || nPid == 4)
			return sOut;
		sOut.reserve(4096);

		const size_t c_nMaxChars = 8192;
		LibGuard gDbg, gPsapi;
		HandleGuard gProc;
		DbgHelpApi api;

		try
		{
			api = LoadDbgHelpApi();
			gDbg.h = api.hMod;
			if (!api.hMod || !api.pStackWalk64 || !api.pSymInitialize ||
				!api.pSymCleanup || !api.pFuncTable || !api.pGetModBase)
				return std::string();

			gPsapi.h = ::LoadLibraryW(L"psapi.dll");
			FARPROC fpMapped = gPsapi.h ? ::GetProcAddress(gPsapi.h, "GetMappedFileNameW") : nullptr;
			auto pGetMapped = reinterpret_cast<DWORD(WINAPI*)(HANDLE, LPVOID, LPWSTR, DWORD)>(fpMapped);

			HandleGuard gSnap;
			gSnap.h = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
			if (gSnap.h == INVALID_HANDLE_VALUE)
			{
				gSnap.h = nullptr;
				return std::string();
			}

			const DWORD nSelfTid = ::GetCurrentThreadId();
			const DWORD nSelfPid = ::GetCurrentProcessId();
			std::vector<DWORD> vTids;
			THREADENTRY32 te = {};
			te.dwSize = sizeof(te);
			if (::Thread32First(gSnap.h, &te))
			{
				do
				{
					// Never suspend our own service threads (deadlock risk).
					if (te.th32OwnerProcessID == nPid && te.th32ThreadID != nSelfTid && nPid != nSelfPid)
					{
						vTids.push_back(te.th32ThreadID);
						if ((int)vTids.size() >= nMaxThreads)
							break;
					}
				} while (::Thread32Next(gSnap.h, &te));
			}
			if (vTids.empty())
				return std::string();

			gProc.h = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, nPid);
			if (!gProc.h)
				return std::string();
			HANDLE hProc = gProc.h;

			BOOL bWow = FALSE;
			::IsWow64Process(hProc, &bWow);

			if (!api.pSymInitialize(hProc, NULL, TRUE))
				return std::string();

			wchar_t wszPath[MAX_PATH] = {};
			char szFrame[128] = "";

			for (DWORD nTid : vTids)
			{
				HANDLE hThread = ::OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, nTid);
				if (!hThread)
					continue;
				if (::SuspendThread(hThread) == (DWORD)-1)
				{
					::CloseHandle(hThread);
					continue;
				}

				STACKFRAME64 frame = {};
				DWORD dwMachine = IMAGE_FILE_MACHINE_AMD64;
				union CtxBuf { CONTEXT x64;
#ifdef _WIN64
					WOW64_CONTEXT wow;
#endif
				} ctxBuf = {};
				PCONTEXT pCtx = nullptr;
#ifdef _WIN64
				if (bWow)
				{
					ctxBuf.wow.ContextFlags = WOW64_CONTEXT_FULL;
					if (!::Wow64GetThreadContext(hThread, &ctxBuf.wow))
					{
						::ResumeThread(hThread);
						::CloseHandle(hThread);
						continue;
					}
					dwMachine = IMAGE_FILE_MACHINE_I386;
					frame.AddrPC.Offset = ctxBuf.wow.Eip;
					frame.AddrPC.Mode = AddrModeFlat;
					frame.AddrFrame.Offset = ctxBuf.wow.Ebp;
					frame.AddrFrame.Mode = AddrModeFlat;
					frame.AddrStack.Offset = ctxBuf.wow.Esp;
					frame.AddrStack.Mode = AddrModeFlat;
					pCtx = (PCONTEXT)&ctxBuf.wow;
				}
				else
#endif
				{
					ctxBuf.x64.ContextFlags = CONTEXT_FULL;
					if (!::GetThreadContext(hThread, &ctxBuf.x64))
					{
						::ResumeThread(hThread);
						::CloseHandle(hThread);
						continue;
					}
#ifdef _WIN64
					frame.AddrPC.Offset = ctxBuf.x64.Rip;
					frame.AddrPC.Mode = AddrModeFlat;
					frame.AddrFrame.Offset = ctxBuf.x64.Rbp;
					frame.AddrFrame.Mode = AddrModeFlat;
					frame.AddrStack.Offset = ctxBuf.x64.Rsp;
					frame.AddrStack.Mode = AddrModeFlat;
#else
					dwMachine = IMAGE_FILE_MACHINE_I386;
					frame.AddrPC.Offset = ctxBuf.x64.Eip;
					frame.AddrPC.Mode = AddrModeFlat;
					frame.AddrFrame.Offset = ctxBuf.x64.Ebp;
					frame.AddrFrame.Mode = AddrModeFlat;
					frame.AddrStack.Offset = ctxBuf.x64.Esp;
					frame.AddrStack.Mode = AddrModeFlat;
#endif
					pCtx = &ctxBuf.x64;
				}

				char szTid[32] = "";
				sprintf_s(szTid, "tid=%u:", (unsigned)nTid);
				sOut += szTid;

				for (int f = 0; f < nMaxFrames; ++f)
				{
					if (!api.pStackWalk64(dwMachine, hProc, hThread, &frame, pCtx,
						ReadProcMemRoutine, api.pFuncTable, api.pGetModBase, NULL))
						break;
					if (frame.AddrPC.Offset == 0)
						break;

					DWORD64 nModBase = api.pGetModBase(hProc, frame.AddrPC.Offset);
					if (nModBase != 0 && pGetMapped &&
						pGetMapped(hProc, (LPVOID)(ULONG_PTR)nModBase, wszPath, MAX_PATH) > 0)
					{
						std::wstring ws(wszPath);
						size_t nSlash = ws.find_last_of(L"\\/");
						std::string sMod;
						std::wstring wsBase = (nSlash == std::wstring::npos) ? ws : ws.substr(nSlash + 1);
						sMod.reserve(wsBase.size());
						for (wchar_t wc : wsBase)
							sMod.push_back((char)wc);
						sprintf_s(szFrame, "%s+%llx", sMod.c_str(),
							(unsigned long long)(frame.AddrPC.Offset - nModBase));
					}
					else
					{
						sprintf_s(szFrame, "0x%llx", (unsigned long long)frame.AddrPC.Offset);
					}
					sOut += szFrame;
					sOut += ',';
					if (sOut.size() > c_nMaxChars)
						break;
				}
				if (!sOut.empty() && sOut.back() == ',')
					sOut.back() = ';';

				::ResumeThread(hThread);
				::CloseHandle(hThread);
				if (sOut.size() > c_nMaxChars)
					break;
			}

			api.pSymCleanup(hProc);
		}
		catch (...)
		{
		}

		if (sOut.size() > c_nMaxChars)
			sOut.resize(c_nMaxChars);
		return sOut;
	}

	// Forward enriched event to Owlyshield FastDetect ML engine
	static void ForwardToOwlyshieldMlEngine(const Variant& vEvent)
	{
		static HMODULE s_hOwlyDll = nullptr;
		typedef int32_t (*IngestOpenedrEventFn)(const uint8_t*, uint32_t);
		static IngestOpenedrEventFn s_fnIngest = nullptr;
		typedef int32_t (*RtEnqueueUtf8Fn)(const uint8_t*, uint32_t, uint32_t, uint32_t);
		static RtEnqueueUtf8Fn s_fnEnqueue = nullptr;
		static std::once_flag s_initFlag;

		std::call_once(s_initFlag, []() {
			s_hOwlyDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
			if (!s_hOwlyDll) s_hOwlyDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
			if (!s_hOwlyDll)
			{
				wchar_t szMod[MAX_PATH] = {};
				if (::GetModuleFileNameW(nullptr, szMod, MAX_PATH) > 0)
				{
					std::filesystem::path p(szMod);
					s_hOwlyDll = ::LoadLibraryW((p.parent_path() / L"owlyshield_ransom.dll").c_str());
				}
			}
			if (!s_hOwlyDll)
			{
				s_hOwlyDll = ::LoadLibraryW(L"C:\\Program Files\\HydraDragonAntivirus\\OpenEDR\\owlyshield_ransom.dll");
			}
			if (s_hOwlyDll != nullptr)
			{
				s_fnIngest = (IngestOpenedrEventFn)::GetProcAddress(s_hOwlyDll, "owlyshield_dll_ingest_openedr_event");
				s_fnEnqueue = (RtEnqueueUtf8Fn)::GetProcAddress(s_hOwlyDll, "owlyshield_rt_enqueue_utf8");
			}
		});

		// Real-time zero-latency file & process submission to daemon scan pool
		if (s_fnEnqueue != nullptr)
		{
			try
			{
				auto enqueueIfValid = [](RtEnqueueUtf8Fn fn, const std::string& rawPath, uint32_t isProc, uint32_t pid) {
					if (rawPath.empty()) return;
					std::string dos = DetectionNotifier::NtPathToDosPathString(rawPath);
					if (!dos.empty() && (dos.find(":\\") != std::string::npos || dos.rfind("\\\\", 0) == 0))
					{
						fn(reinterpret_cast<const uint8_t*>(dos.data()), static_cast<uint32_t>(dos.size()), isProc, pid);
					}
				};

				uint32_t nPid = 0;
				if (auto optPid = variant::getByPathSafe(vEvent, "process.id")) {
					try { nPid = static_cast<uint32_t>(optPid.value()); } catch (...) {}
				} else if (auto optPid2 = variant::getByPathSafe(vEvent, "process.pid")) {
					try { nPid = static_cast<uint32_t>(optPid2.value()); } catch (...) {}
				}

				// Real-time zero-latency file & process submission to daemon content scan pool
				// Unfiltered: ALL file events (creates, writes, renames) and process launches are evaluated
				// 1. File targets: handles file creation, modification, and critical file renames (e.g. ren *.vir *.exe)
				std::string sSourceFile;
				if (auto optP = variant::getByPathSafe(vEvent, "file.path"))
					sSourceFile = std::string(optP.value());
				else if (auto optP2 = variant::getByPathSafe(vEvent, "file.rawPath"))
					sSourceFile = std::string(optP2.value());
				else if (auto optP3 = variant::getByPathSafe(vEvent, "file.abstractPath"))
					sSourceFile = std::string(optP3.value());

				if (!sSourceFile.empty())
					enqueueIfValid(s_fnEnqueue, sSourceFile, 0, nPid);

				// Rename target paths: resolve relative filenames against source directory
				if (auto optRT = variant::getByPathSafe(vEvent, "fileRenameTarget"))
				{
					std::string resolvedTarget = ResolveRenameTargetPath(sSourceFile, std::string(optRT.value()));
					if (!resolvedTarget.empty())
						enqueueIfValid(s_fnEnqueue, resolvedTarget, 0, nPid);
				}
				if (auto optRT2 = variant::getByPathSafe(vEvent, "file.renameTarget"))
				{
					std::string resolvedTarget = ResolveRenameTargetPath(sSourceFile, std::string(optRT2.value()));
					if (!resolvedTarget.empty())
						enqueueIfValid(s_fnEnqueue, resolvedTarget, 0, nPid);
				}

				// 2. Process targets (process spawn, executable launching)
				if (auto optProc = variant::getByPathSafe(vEvent, "process.imageFile.abstractPath"))
					enqueueIfValid(s_fnEnqueue, std::string(optProc.value()), 1, nPid);
				else if (auto optProc2 = variant::getByPathSafe(vEvent, "process.imageFile.rawPath"))
					enqueueIfValid(s_fnEnqueue, std::string(optProc2.value()), 1, nPid);
				else if (auto optProc3 = variant::getByPathSafe(vEvent, "process.imagePath"))
					enqueueIfValid(s_fnEnqueue, std::string(optProc3.value()), 1, nPid);

				if (auto optChild = variant::getByPathSafe(vEvent, "childProcess.imageFile.abstractPath"))
					enqueueIfValid(s_fnEnqueue, std::string(optChild.value()), 1, nPid);
			}
			catch (...) {}
		}

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
				// Extract API hook function and module
				else if (auto optA = variant::getByPathSafe(vEvent, "owlyHook.apiFunction"))
				{
					if (auto optM = variant::getByPathSafe(vEvent, "owlyHook.apiModule"))
						sDetails = " [API: " + std::string(optM.value()) + "!" + std::string(optA.value()) + "]";
					else
						sDetails = " [API: " + std::string(optA.value()) + "]";
				}
				// Extract network destination
				else if (auto optN = variant::getByPathSafe(vEvent, "network.destinationAddress"))
					sDetails = " [Net: " + std::string(optN.value()) + "]";

				// Save telemetry to persistent training dataset for offline Dynamic ML model training.
				// TRAINING_MODE=1 records everything by default; TRAINING_WATCH_DIR /
				// TRAINING_WATCH_DLL_DIR only narrow it down when explicitly set.
				if (IsTrainingModeEnabled() && IsProcessInTrainingDir(sPath) && IsApiDllInTrainingWatchDir(vEvent))
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
			wsNewName = ResolveRenameTargetPathW(wsFilePath, wsNewName);
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

// openedr_static.dll scan_pid binding shares the file scanner's loader and init.
// Report JSON: {pid, regions_scanned, bytes_scanned, verdict,
// max_threat_score, detections:[{name...}]}. libedr links no JSON library,
// so verdict/name are extracted with the same tolerant key scan used there.
namespace {

typedef char* (*OpenedrScanPidFn)(uint32_t, uint64_t);
typedef void (*OpenedrPidFreeFn)(char*);

struct OpenedrPidBinding {
	HMODULE hDll = nullptr;
	OpenedrScanPidFn fnScanPid = nullptr;
	OpenedrPidFreeFn fnFree = nullptr;
	bool ready = false;
};

static OpenedrPidBinding s_pidEng;
static std::once_flag s_pidInitFlag;

static void InitOpenedrPid()
{
	std::call_once(s_pidInitFlag, []() {
		DWORD loadError = ERROR_SUCCESS;
		HMODULE hDll = openedr_static::EnsureInitialized("pid-scan", &loadError);
		if (!hDll)
		{
			openedr_static::WriteLog("pid-scan-unavailable", "engine init failed; win32=" + std::to_string(loadError));
			return;
		}
		auto fnScan = reinterpret_cast<OpenedrScanPidFn>(::GetProcAddress(hDll, "openedr_static_scan_pid"));
		auto fnFree = reinterpret_cast<OpenedrPidFreeFn>(::GetProcAddress(hDll, "openedr_static_free_string"));
		if (!fnScan || !fnFree)
		{
			std::string missing;
			if (!fnScan) missing += " openedr_static_scan_pid";
			if (!fnFree) missing += " openedr_static_free_string";
			openedr_static::WriteLog("pid-exports-missing", missing);
			return;
		}
		s_pidEng.hDll = hDll;
		s_pidEng.fnScanPid = fnScan;
		s_pidEng.fnFree = fnFree;
		s_pidEng.ready = true;
	});
}

// Read a JSON string value for "key" starting the search at startPos.
// Tolerates whitespace; skips \" escapes inside other strings.
static bool MemReadKeyString(const std::string& json, const char* key, size_t startPos, std::string& out)
{
	const char* end = json.data() + json.size();
	std::string pat = std::string("\"") + key + "\"";
	size_t at = json.find(pat, startPos);
	if (at == std::string::npos)
		return false;
	const char* p = json.data() + at + pat.size();
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
	if (p >= end || *p != ':')
		return false;
	++p;
	while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
	if (p >= end || *p != '"')
		return false;
	++p;
	out.clear();
	while (p < end)
	{
		char c = *p++;
		if (c == '"')
			return true;
		if (c == '\\' && p < end)
		{
			out.push_back(*p++);
			continue;
		}
		out.push_back(c);
	}
	return false;
}

// Memory-scan verdict with first detection name. 2 malicious, else 0.
// Engine missing/unreadable -> 0 (unknown), never an error verdict.
static int ScanPidWithLocalEngines(uint32_t nPid, uint64_t nMaxMb, std::string& sThreatOut)
{
	sThreatOut.clear();
	if (nPid == 0)
		return 0;
	try
	{
		InitOpenedrPid();
		if (!s_pidEng.ready)
			return 0;
		openedr_static::WriteLog("pid-scan-start", "pid=" + std::to_string(nPid) +
			"; max-mb=" + std::to_string(nMaxMb));
		char* raw = s_pidEng.fnScanPid(nPid, nMaxMb);
		if (!raw)
		{
			openedr_static::WriteLog("pid-scan-failed", "scan_pid returned null; pid=" + std::to_string(nPid));
			return 0;
		}
		std::string report(raw);
		s_pidEng.fnFree(raw);
		std::string verdict;
		if (!MemReadKeyString(report, "verdict", 0, verdict))
		{
			openedr_static::WriteLog("pid-report-invalid", "missing verdict; pid=" + std::to_string(nPid));
			return 0;
		}
		if (verdict != "Malicious")
		{
			openedr_static::WriteLog("pid-scan-result", "pid=" + std::to_string(nPid) +
				"; verdict=" + verdict);
			return 0;
		}
		size_t detAt = report.find("\"detections\"");
		if (detAt != std::string::npos)
		{
			std::string first;
			size_t arr = report.find('[', detAt);
			if (arr != std::string::npos && MemReadKeyString(report, "name", arr, first) && !first.empty())
			{
				if (first.size() > 512)
					first.resize(512);
				sThreatOut = "Memory:" + first;
			}
		}
		openedr_static::WriteLog("pid-scan-result", "pid=" + std::to_string(nPid) +
			"; verdict=Malicious; detection=" + sThreatOut);
		return 2;
	}
	catch (...)
	{
		openedr_static::WriteLog("pid-scan-exception", "pid=" + std::to_string(nPid));
		return 0;
	}
}

// Fire-and-forget rescan OFF the hot path: the enricher worker is single-
// threaded, so it must never sleep (queue backs up -> late events, overflow
// drops -> choppy output). Sleeps on a detached thread, rescans once, and
// convicts exactly like the sync path on Malicious.
//
// Bounded on purpose: Edge/Chromium emits thousands of churn files (.tmp,
// LevelDB LOG) per minute, each Unknown. Unbounded detaches would be a
// thread storm, so we (a) dedup by path, (b) cap concurrent rescans.
static void AsyncRescanAndQuarantine(std::string dos, uint32_t nPid)
{
	constexpr int kMaxConcurrentRescans = 4;
	static std::atomic<int> s_nActiveRescans{ 0 };

	// Path dedup: Create/WriteFull/DataChange/Close all fire per file within
	// milliseconds; only the first Unknown schedules work.
	static std::mutex s_mtxRescanSeen;
	static std::unordered_map<std::string, std::chrono::steady_clock::time_point> s_rescanSeen;
	{
		std::string key = dos;
		for (auto& c : key)
			c = (char)::tolower((unsigned char)c);
		std::scoped_lock lock(s_mtxRescanSeen);
		auto now = std::chrono::steady_clock::now();
		auto it = s_rescanSeen.find(key);
		if (it != s_rescanSeen.end() && (now - it->second) < std::chrono::seconds(10))
			return;
		s_rescanSeen[key] = now;
		if (s_rescanSeen.size() > 20000)
		{
			for (auto itC = s_rescanSeen.begin(); itC != s_rescanSeen.end(); )
			{
				if ((now - itC->second) > std::chrono::seconds(60))
					itC = s_rescanSeen.erase(itC);
				else
					++itC;
			}
		}
	}

	if (s_nActiveRescans.load(std::memory_order_relaxed) >= kMaxConcurrentRescans)
		return;
	if (s_nActiveRescans.fetch_add(1, std::memory_order_acq_rel) >= kMaxConcurrentRescans)
	{
		s_nActiveRescans.fetch_sub(1, std::memory_order_acq_rel);
		return;
	}

	std::thread([dos = std::move(dos), nPid]() {
		struct ActiveGuard {
			~ActiveGuard() { s_nActiveRescans.fetch_sub(1, std::memory_order_acq_rel); }
		} guard;

		std::this_thread::sleep_for(std::chrono::milliseconds(350));
		if (dos.empty())
			return;
		// Sync path (a later Change/Close event) already handled it?
		if (DetectionNotifier::isKnownMalware(dos, ""))
			return;
		std::string sThreat;
		if (DetectionNotifier::scanFileWithLocalEngines(dos, sThreat) != 2)
			return;
		if (sThreat.empty())
			sThreat = "Malware.LocalDetection";

		LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] THREAT DETECTED: <"
			<< sThreat << "> on <" << dos << "> (PID: " << nPid << ")"));

		if (!DetectionNotifier::isProtectionPaused())
		{
			HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
			if (!hDll)
				hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
			if (hDll)
			{
				typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
				auto fnQ = (QuarantineFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file");
				if (fnQ != nullptr)
				{
					int32_t qRes = fnQ(
						reinterpret_cast<const uint8_t*>(dos.data()),
						static_cast<uint32_t>(dos.size()));
					if (qRes == 0)
						LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] quarantined <" << dos << ">"));
					else
						LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] quarantine failed for <" << dos << "> result=" << qRes));
				}
			}
		}

		DetectionNotifier::recordMalwareDetection(dos, "");

		HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
			GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			std::string pipeMsg = "THREAT_ALERT:" + sThreat + "|" + dos + "\n";
			DWORD written = 0;
			::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
			::CloseHandle(hPipe);
		}
	}).detach();
}

} // namespace

void EventEnricher::executeUnfilteredLocalScan(Variant& vEvent, Variant& vProcess, Event eEventType, const std::string& sProcPath)
{
	static HMODULE s_hOwlyDll = nullptr;
	typedef int32_t (*RtEnqueueUtf8Fn)(const uint8_t*, uint32_t, uint32_t, uint32_t);
	static RtEnqueueUtf8Fn s_fnEnqueue = nullptr;
	typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
	static QuarantineFn s_fnQuarantine = nullptr;
	static std::once_flag s_initFlag;

	std::call_once(s_initFlag, []() {
		s_hOwlyDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (!s_hOwlyDll) s_hOwlyDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
		if (!s_hOwlyDll)
		{
			wchar_t szMod[MAX_PATH] = {};
			if (::GetModuleFileNameW(nullptr, szMod, MAX_PATH) > 0)
			{
				std::filesystem::path p(szMod);
				s_hOwlyDll = ::LoadLibraryW((p.parent_path() / L"owlyshield_ransom.dll").c_str());
			}
		}
		if (!s_hOwlyDll)
		{
			s_hOwlyDll = ::LoadLibraryW(L"C:\\Program Files\\HydraDragonAntivirus\\OpenEDR\\owlyshield_ransom.dll");
		}
		if (s_hOwlyDll != nullptr)
		{
			s_fnEnqueue = (RtEnqueueUtf8Fn)::GetProcAddress(s_hOwlyDll, "owlyshield_rt_enqueue_utf8");
			s_fnQuarantine = (QuarantineFn)::GetProcAddress(s_hOwlyDll, "owlyshield_dll_quarantine_file");
		}
	});

	// Extract PID
	uint32_t nPid = 0;
	if (vProcess.has("id")) {
		try { nPid = static_cast<uint32_t>(vProcess["id"]); } catch (...) {}
	} else if (vProcess.has("pid")) {
		try { nPid = static_cast<uint32_t>(vProcess["pid"]); } catch (...) {}
	}

	// 1. Gather all candidate file paths before they are replaced by lambda proxies
	std::vector<std::pair<std::string, bool>> vCandidates; // {rawPath, isProcess}

	std::string sSourceCandidate;
	if (vEvent.has("file"))
	{
		Variant vRawFile = vEvent.get("file");
		if (vRawFile.isDictionaryLike())
		{
			if (vRawFile.has("path")) sSourceCandidate = std::string(vRawFile["path"]);
			else if (vRawFile.has("rawPath")) sSourceCandidate = std::string(vRawFile["rawPath"]);
			else if (vRawFile.has("abstractPath")) sSourceCandidate = std::string(vRawFile["abstractPath"]);

			if (!sSourceCandidate.empty()) vCandidates.emplace_back(sSourceCandidate, false);

			if (vRawFile.has("renameTarget"))
			{
				std::string resolvedTarget = ResolveRenameTargetPath(sSourceCandidate, std::string(vRawFile["renameTarget"]));
				if (!resolvedTarget.empty()) vCandidates.emplace_back(resolvedTarget, false);
			}
		}
		else if (vRawFile.getType() == variant::ValueType::String)
		{
			sSourceCandidate = std::string(vRawFile);
			vCandidates.emplace_back(sSourceCandidate, false);
		}
	}
	if (vEvent.has("fileRenameTarget"))
	{
		std::string resolvedTarget = ResolveRenameTargetPath(sSourceCandidate, std::string(vEvent.get("fileRenameTarget")));
		if (!resolvedTarget.empty()) vCandidates.emplace_back(resolvedTarget, false);
	}
	if (vEvent.has("destination"))
	{
		Variant vDest = vEvent.get("destination");
		if (vDest.isDictionaryLike() && vDest.has("path"))
			vCandidates.emplace_back(std::string(vDest["path"]), false);
		else if (vDest.getType() == variant::ValueType::String)
			vCandidates.emplace_back(std::string(vDest), false);
	}
	if (vEvent.has("source"))
	{
		Variant vSrc = vEvent.get("source");
		if (vSrc.isDictionaryLike() && vSrc.has("path"))
			vCandidates.emplace_back(std::string(vSrc["path"]), false);
		else if (vSrc.getType() == variant::ValueType::String)
			vCandidates.emplace_back(std::string(vSrc), false);
	}

	if (!sProcPath.empty())
	{
		vCandidates.emplace_back(sProcPath, true);
	}

	// Deduplicate normalized paths within the current event
	std::unordered_set<std::string> seenPaths;

	for (const auto& item : vCandidates)
	{
		const std::string& rawPath = item.first;
		const bool isProc = item.second;
		if (rawPath.empty()) continue;

		std::string dos = DetectionNotifier::NtPathToDosPathString(rawPath);
		if (dos.empty() || (dos.find(":\\") == std::string::npos && dos.rfind("\\\\", 0) != 0)) continue;
		if (dos.rfind("\\\\.\\pipe\\", 0) == 0) continue;

		std::string lowerDos = dos;
		for (auto& c : lowerDos) c = (char)::tolower((unsigned char)c);
		if (!seenPaths.insert(lowerDos).second) continue;

		// Fast path: if already cached as Clean, skip heavy static scanning completely
		int cachedVerdict = DetectionNotifier::getCachedFileVerdict(dos);
		if (cachedVerdict == 1)
		{
			continue;
		}

		// Process executable images only need evaluation at process creation or when unknown;
		// do not rescan the already running process image on routine sub-events!
		if (isProc && eEventType != Event::LLE_PROCESS_CREATE && cachedVerdict != 0)
		{
			continue;
		}

		// A. Synchronous Pascal-style scan (ClamAV, YARA-X, ML, Signer, EICAR)
		//
		// Mid-write file events (create / write / data change) skip the inline
		// scan: the buffer is still incomplete or locked, so the verdict is
		// worthless, and the full scan (incl. WinTrust) blocks the single
		// enricher worker. They fall through to the async rescan below.
		// Process image and file CLOSE still scan inline — the handle is
		// released there, so content is final.
		const bool bDeferredFileEvent = !isProc &&
			(eEventType == Event::LLE_FILE_CREATE ||
			 eEventType == Event::LLE_FILE_DATA_WRITE_FULL ||
			 eEventType == Event::LLE_FILE_DATA_CHANGE);

		std::string sThreat;
		int r = 0;
		if (!bDeferredFileEvent)
			r = DetectionNotifier::scanFileWithLocalEngines(dos, sThreat);

		// Rescan race: deferred file events, plus any inline scan that hit
		// Unknown (0 bytes / locked at Create), need one re-read once the
		// writer is done. A locked/unreadable file is exactly that case, so
		// only skip when the file is proven empty; any size error retries.
		if (r == 0 && (bDeferredFileEvent ||
			eEventType == Event::LLE_FILE_CLOSE))
		{
			std::error_code ec;
			uintmax_t nSize = std::filesystem::file_size(dos, ec);
			if (ec || nSize > 0)
				AsyncRescanAndQuarantine(dos, nPid);
		}

		if (r == 2)
		{
			if (sThreat.empty())
				sThreat = "Malware.LocalDetection";

			LOGLVL(Critical, FMT("enricher: [UNFILTERED SCAN] THREAT DETECTED: <"
				<< sThreat << "> on <" << dos << "> (PID: " << nPid << ")"));

			// Stamp verdicts on event & process
			vEvent.put("verdict", 2);
			vEvent.put("flsVerdict", 3); // MALWARE
			vEvent.put("threatName", sThreat);
			vProcess.put("verdict", 2);
			vProcess.put("flsVerdict", 3);

			// Rate limit alerts and remediation per file path (30 second cooldown)
			static std::mutex s_mtxAlertThrottle;
			static std::unordered_map<std::string, std::chrono::steady_clock::time_point> s_recentAlerts;
			bool bShouldAlert = false;
			{
				std::scoped_lock lock(s_mtxAlertThrottle);
				auto now = std::chrono::steady_clock::now();
				auto it = s_recentAlerts.find(lowerDos);
				if (it == s_recentAlerts.end() || (now - it->second) > std::chrono::seconds(30))
				{
					s_recentAlerts[lowerDos] = now;
					bShouldAlert = true;
				}
				// Keep recent alerts map bounded
				if (s_recentAlerts.size() > 5000)
				{
					for (auto itClean = s_recentAlerts.begin(); itClean != s_recentAlerts.end(); )
					{
						if ((now - itClean->second) > std::chrono::seconds(60))
							itClean = s_recentAlerts.erase(itClean);
						else
							++itClean;
					}
				}
			}

			if (bShouldAlert)
			{
				// Quarantine the detected malicious file FIRST, before driver block or rollback deletes it!
				if (!DetectionNotifier::isProtectionPaused() && s_fnQuarantine != nullptr)
				{
					int32_t qRes = s_fnQuarantine(
						reinterpret_cast<const uint8_t*>(dos.data()),
						static_cast<uint32_t>(dos.size()));
					if (qRes == 0)
					{
						LOGLVL(Critical, FMT("enricher: successfully quarantined detected malware <" << dos << ">"));
					}
					else
					{
						LOGLVL(Critical, FMT("enricher: quarantine failed for <" << dos << "> result=" << qRes));
					}
				}

				// Remember detection in persistent DB & driver block list
				DetectionNotifier::recordMalwareDetection(dos, "");

				// File rollback / remediation (skipped while protection is
				// paused so training runs keep samples alive; verdicts,
				// telemetry and training recording continue).
				if (!DetectionNotifier::isProtectionPaused())
					handleThreatRemediation(nPid, L"", sThreat);

				// Send instant alert to Pascal GUI
				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string pipeMsg = "THREAT_ALERT:" + sThreat + "|" + dos + "\n";
					DWORD written = 0;
					::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}
			}
		}

		if (r == 3)
		{
			// Suspicious (was previously collapsed to unknown and silently
			// dropped): stamp + alert + driver block-list + DB record so
			// medium-confidence threats can't run silent. Quarantine stays
			// Malicious-only (manual-scan parity, FPR control).
			if (sThreat.empty())
				sThreat = "Static.Suspicious";

			LOGLVL(Critical, FMT("enricher: [UNFILTERED SCAN] SUSPICIOUS: <"
				<< sThreat << "> on <" << dos << "> (PID: " << nPid << ")"));

			vEvent.put("threatName", sThreat);
			vProcess.put("threatName", sThreat);

			// Remember in persistent DB & driver block list (no quarantine).
			DetectionNotifier::recordMalwareDetection(dos, "");

			// Send instant alert to Pascal GUI
			HANDLE hPipeSusp = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
				GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			if (hPipeSusp != INVALID_HANDLE_VALUE)
			{
				std::string pipeMsg = "THREAT_ALERT:" + sThreat + "|" + dos + "\n";
				DWORD written = 0;
				::WriteFile(hPipeSusp, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
				::CloseHandle(hPipeSusp);
			}
		}

		// B. Also enqueue to daemon scanner pool (for background archive scanning / quarantine vault)
		if (s_fnEnqueue != nullptr)
		{
			s_fnEnqueue(reinterpret_cast<const uint8_t*>(dos.data()),
				static_cast<uint32_t>(dos.size()), isProc ? 1 : 0, nPid);
		}
	}

	// C. Live process-memory scan (real-time): ClamAV + YARA + PE-ML over the
	// event PID's committed readable memory via openedr_static_scan_pid.
	// Skipped when files already convicted this event; per-PID 5-minute
	// cooldown bounds the cost. Detection only (verdict stamp + alert):
	// memory has no file to quarantine or roll back.
	if (nPid > 0)
	{
		int curVerdict = 0;
		try { curVerdict = static_cast<int>(vEvent.get("verdict", 0)); } catch (...) {}
		if (curVerdict != 2)
		{
			static std::mutex s_mtxMemScan;
			static std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> s_recentMemScan;
			static std::chrono::steady_clock::time_point s_lastMemScan{};
			bool bDue = false;
			{
				std::scoped_lock lock(s_mtxMemScan);
				auto now = std::chrono::steady_clock::now();
				auto it = s_recentMemScan.find(nPid);
				if (it == s_recentMemScan.end() || (now - it->second) > std::chrono::minutes(5))
				{
					// Global throttle: one full 128 MB memory scan costs
					// seconds on this single worker thread. Under process-
					// spawn storms (Edge/WebView) back-to-back scans queue
					// up -> output events go late + choppy. Max one scan
					// per 30 s; residents persist and are caught later.
					if (s_lastMemScan == std::chrono::steady_clock::time_point{} ||
						(now - s_lastMemScan) > std::chrono::seconds(30))
					{
						s_lastMemScan = now;
						s_recentMemScan[nPid] = now;
						bDue = true;
					}
				}
				if (s_recentMemScan.size() > 5000)
				{
					for (auto itC = s_recentMemScan.begin(); itC != s_recentMemScan.end(); )
					{
						if ((now - itC->second) > std::chrono::minutes(30))
							itC = s_recentMemScan.erase(itC);
						else
							++itC;
					}
				}
			}
			if (bDue)
			{
				std::string sMemThreat;
				if (ScanPidWithLocalEngines(nPid, 128, sMemThreat) == 2)
				{
					if (sMemThreat.empty())
						sMemThreat = "Malware.MemoryDetection";
					LOGLVL(Critical, FMT("enricher: [MEMORY SCAN] THREAT DETECTED: <" << sMemThreat << "> in PID " << nPid));
					vEvent.put("verdict", 2);
					vEvent.put("threatName", sMemThreat);
					vProcess.put("verdict", 2);
					HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
						GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
					if (hPipe != INVALID_HANDLE_VALUE)
					{
						std::string pipeMsg = "THREAT_ALERT:" + sMemThreat + "|pid:" + std::to_string(nPid) + "\n";
						DWORD written = 0;
						::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
						::CloseHandle(hPipe);
					}
				}
			}
		}
	}
}

//
// Rolls back every captured original of <nPid>: restores modified/deleted
// files from their pre-images and removes rename targets.
//

// SHA-256 hex (lowercase) of a file; "" when unreadable. Stops RansomShield
// from resurrecting quarantined malware bytes under a new name: the restore
// guards below match on path only, so a known-malicious payload restored to
// a fresh path would slip through without this content check.
static std::string sha256HexOfFile(const std::wstring& wsPath)
{
	try
	{
		std::ifstream f(wsPath, std::ios::binary);
		if (!f)
			return {};
		crypt::sha256::Hasher hasher;
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
		std::ostringstream oss;
		oss << std::hex << std::setfill('0');
		for (size_t i = 0; i < sizeof(h.byte); ++i)
			oss << std::setw(2) << static_cast<unsigned>(h.byte[i]);
		return oss.str();
	}
	catch (...) { return {}; }
}

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
			// Block restore if the target or backup is known detected malware (e.g. Winball501Ransom.exe).
			// Hash the backup content: path-only matching misses known-malicious bytes under a fresh name.
			std::string sNarrowTarget = Narrow(wsRestoreTarget);
			std::string sNarrowBackup = Narrow(wsBackup);
			std::string sBackupHash = sha256HexOfFile(wsBackup);
			// Content hit: backup bytes are known-malicious -> never resurrect.
			// Path-only hit with clean readable bytes: same path was tainted
			// before, but THESE bytes were never flagged -> allow restore
			// (protects clean files reusing a previously quarantined path).
			bool bHashHit = !sBackupHash.empty()
				&& DetectionNotifier::isKnownMalware("", sBackupHash);
			bool bPathHit = DetectionNotifier::isKnownMalware(sNarrowTarget, "")
				|| DetectionNotifier::isKnownMalware(sNarrowBackup, "");
			if (bHashHit || (bPathHit && sBackupHash.empty()))
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
						std::string sSweepHash = sha256HexOfFile(bkPath);
						bool bSweepHashHit = !sSweepHash.empty()
							&& DetectionNotifier::isKnownMalware("", sSweepHash);
						bool bSweepPathHit = DetectionNotifier::isKnownMalware(sNarrowTarget, "")
							|| DetectionNotifier::isKnownMalware(sNarrowBk, "");
						if (bSweepHashHit || (bSweepPathHit && sSweepHash.empty()))
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

	// One-line training diagnosis at startup: gates are re-read every 2-3s,
	// so this reflects the registry at service start.
	LOGINF(FMT("Event Enricher is started (trainingMode="
		<< (IsTrainingModeEnabled() ? "ON" : "OFF")
		<< " watchDir=<" << GetTrainingWatchDir() << ">"
		<< " watchDllDir=<" << GetTrainingWatchDllDir() << ">"
		<< " threadStacks=" << (IsThreadStackCaptureEnabled() ? "ON" : "OFF") << ")"));
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

	// UNFILTERED IMMEDIATE LOCAL FILE & PROCESS SCANNING (PASCAL-STYLE):
	executeUnfilteredLocalScan(vEvent, vProcess, eEventType, sProcPath);

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

		// Best-effort PDB warm-up for the offline symbol pipe; async, never blocks.
		QueuePdbPrefetch(m_threadPool, sImgPath);

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
			// Capture-on-alert thread stacks (hooksuz/ETWsiz, Process-Hacker style).
			// Attached to the event, flows into training JSON via whole-event serialize.
			if (nShieldPid > 0 && nShieldPid < 0xFFFFFFFF && IsThreadStackCaptureEnabled())
			{
				try
				{
					std::string sStacks = CaptureThreadStacks((uint32_t)nShieldPid);
					if (!sStacks.empty())
						vEvent.put("threadStacks", sStacks);
				}
				catch (...) {}
			}
			// Paused protection keeps samples alive for training runs:
			// remediation/rollback skipped, capture + recording continue.
			if (!DetectionNotifier::isProtectionPaused())
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
bool EventEnricher::isUnknownOrThreatEvent(const Variant& vEvent)
{
	// 1. Explicit threat or detection alerts have top priority
	if (vEvent.has("threat") || vEvent.has("alert") || vEvent.has("detection") || vEvent.has("threatName"))
		return true;

	Event eEventType = vEvent.has("baseEventType") && !vEvent.get("baseEventType").isEmpty() ?
		static_cast<Event>(static_cast<int>(vEvent.get("baseEventType"))) :
		static_cast<Event>(static_cast<int>(vEvent.get("baseType")));

	// 2. Process creation is ALWAYS treated as unknown until verified
	if (eEventType == Event::LLE_PROCESS_CREATE || vEvent.has("childProcess"))
		return true;

	// 3. Check process verdict
	Variant vProc;
	if (vEvent.has("process")) vProc = vEvent.get("process");
	else if (vEvent.has("childProcess")) vProc = vEvent.get("childProcess");

	if (vProc.isDictionaryLike())
	{
		int64_t nProcVerdict = 0;
		if (vProc.has("verdict")) {
			try { nProcVerdict = static_cast<int64_t>(vProc["verdict"]); } catch (...) {}
		}
		// Any process not verified clean (1) is prioritized as unknown/untrusted
		if (nProcVerdict != 1)
		{
			std::string pPath;
			if (vProc.has("imagePath")) pPath = std::string(vProc["imagePath"]);
			else if (vProc.has("path")) pPath = std::string(vProc["path"]);
			if (!pPath.empty())
			{
				std::string dos = DetectionNotifier::NtPathToDosPathString(pPath);
				if (DetectionNotifier::getCachedFileVerdict(dos) != 1)
					return true;
			}
			else
			{
				return true;
			}
		}
	}

	// 4. Check file verdict for file events
	if (vEvent.has("file"))
	{
		Variant vFile = vEvent.get("file");
		if (vFile.isDictionaryLike())
		{
			int64_t nFileVerdict = 0;
			if (vFile.has("verdict")) {
				try { nFileVerdict = static_cast<int64_t>(vFile["verdict"]); } catch (...) {}
			}
			if (nFileVerdict != 1)
			{
				std::string fPath;
				if (vFile.has("path")) fPath = std::string(vFile["path"]);
				else if (vFile.has("rawPath")) fPath = std::string(vFile["rawPath"]);
				if (!fPath.empty())
				{
					std::string dos = DetectionNotifier::NtPathToDosPathString(fPath);
					if (DetectionNotifier::getCachedFileVerdict(dos) != 1)
						return true;
				}
				else
				{
					return true;
				}
			}
		}
	}

	// Both process and files are verified clean
	return false;
}

void EventEnricher::processQueueEvent()
{
	CMD_TRY
	{
		if (!m_fInitialized)
			return;

		auto pProvider = m_pProvider.lock();
		if (pProvider == nullptr)
			error::InvalidArgument(SL, "Provider interface is undefined").throwException();

		// Drain available events in batches and prioritize into queues
		for (int i = 0; i < 64; ++i)
		{
			auto vOptEvent = pProvider->get();
			if (!vOptEvent)
				break;

			bool bUnknown = isUnknownOrThreatEvent(vOptEvent.value());
			std::scoped_lock lock(m_mtxPriorityQueues);
			if (bUnknown)
			{
				m_unknownQueue.push_back(std::move(vOptEvent.value()));
			}
			else
			{
				if (m_benignQueue.size() < 10000)
					m_benignQueue.push_back(std::move(vOptEvent.value()));
			}
		}

		// ALWAYS DRAIN UNKNOWN QUEUE FIRST (TOP PRIORITY)
		Variant nextEvent;
		{
			std::scoped_lock lock(m_mtxPriorityQueues);
			if (!m_unknownQueue.empty())
			{
				nextEvent = std::move(m_unknownQueue.front());
				m_unknownQueue.pop_front();
			}
			else if (!m_benignQueue.empty())
			{
				nextEvent = std::move(m_benignQueue.front());
				m_benignQueue.pop_front();
			}
		}

		if (!nextEvent.isEmpty())
		{
			put(nextEvent);
		}
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

	///
	/// @fn Variant EventEnricher::execute()
	///
	/// ##### fetchPdb()
	/// Download the matching PDB for a PE file via the symbol server (DbgHelp).
	/// Explicit on-demand command only: network I/O can take seconds, never
	/// called from scans. Returns the local PDB path or empty string.
	///   * path [str] - PE file path;
	///   * search [str] - optional DbgHelp search path (default: MS server
	///     with a temp cache);
	///
	if (vCommand == "fetchPdb")
	{
		const std::wstring sPath(vParams["path"]);
		std::wstring sSearch;
		if (vParams.has("search"))
			sSearch = std::wstring(vParams["search"]);
		return Variant(FetchModulePdb(sPath, sSearch));
	}

	error::OperationNotSupported(SL,
		FMT("PatternSeacher doesn't support command <" << vCommand << ">")).throwException();
	TRACE_END(FMT("Error during processing of the command <" << vCommand << ">"));
}

} // namespace cmd 
