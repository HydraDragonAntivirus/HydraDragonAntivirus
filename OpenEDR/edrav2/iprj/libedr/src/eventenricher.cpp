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
#include <libcore/inc/zerotrust.hpp>
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
#include <deque>
#include <map>
#include <condition_variable>
#include <unordered_map>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <Softpub.h>
#include <wintrust.h>
#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")

namespace cmd {

#undef CMD_COMPONENT
#define CMD_COMPONENT "enricher"

namespace {
	// Steps of EventEnricher::put() timed for the "eventlag" log line. The
	// sub-steps (indented names) are parts of a step above them, timed inside
	// helpers through t_pStageUs, which put() points at its own counters.
	enum EnricherStage { c_stProcInfo, c_stModules, c_stProcCert, c_stTrust, c_stLocalScan,
		c_stShadow, c_stTraining, c_stReceiver,
		c_stModSnapshot, c_stModDotNet, c_stModScan, c_stModCert,
		c_stScanCache, c_stScanSha1, c_stScanFls, c_stScanStatic, c_stScanKillChain, c_stScanAsyncQueue,
		c_stTrainPaths, c_stTrainSerialize, c_stTrainSubmit, c_stTrainGuiPipe,
		c_stCount };
	static const char* const c_szStageNames[c_stCount] = { "processInfo", "moduleInspection",
		"processSignature", "trustCheck", "unfilteredScan", "shadowBackup", "trainingForward", "receiverPut",
		"  modules.snapshot", "  modules.dotNet", "  modules.cloudScan", "  modules.signature",
		"  scan.cache", "  scan.sha1", "  scan.fls", "  scan.static", "  scan.killChain", "  scan.asyncQueue",
		"  training.owlyPaths", "  training.serializeJson", "  training.killchainSubmit", "  training.guiPipe" };
	thread_local uint64_t* t_pStageUs = nullptr;

	// Adds the time of its scope to a step of the current put() (no-op elsewhere).
	struct StageTimer
	{
		EnricherStage st;
		std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
		explicit StageTimer(EnricherStage s) : st(s) {}
		~StageTimer()
		{
			if (t_pStageUs != nullptr)
				t_pStageUs[st] += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
					std::chrono::steady_clock::now() - t0).count());
		}
	};
	//
	// Lowercased directory this module was loaded from, without a trailing
	// separator - i.e. the product install directory. Derived at runtime from this
	// module's own image (edrsvc.exe) rather than hardcoded, so it follows
	// whatever install prefix is in use.
	//
	// Lives in the first anonymous namespace because it is needed both by the
	// module deep-scan (InspectProcessModules) and by the per-event candidate
	// loop, and those sit in different scopes.
	//
	const std::string& GetOwnInstallDirLower()
	{
		static const std::string s_dir = []()
		{
			char szExe[MAX_PATH] = "";
			DWORD nLen = ::GetModuleFileNameA(nullptr, szExe, MAX_PATH);
			if (nLen == 0 || nLen >= MAX_PATH)
				return std::string();

			std::string sPath(szExe, nLen);
			const size_t nSlash = sPath.find_last_of("\\/");
			if (nSlash == std::string::npos)
				return std::string();

			std::string sDir = sPath.substr(0, nSlash);
			for (auto& c : sDir) c = (char)::tolower((unsigned char)c);
			return sDir;
		}();

		return s_dir;
	}

	//
	// True when `sLowerPath` sits inside the product install directory. Compares
	// per path component: the trailing-separator check keeps a sibling such as
	// "...\\OpenEDR2\\x.dll" out.
	//
	bool IsPathUnderOwnInstallDir(const std::string& sLowerPath)
	{
		const std::string& sDir = GetOwnInstallDirLower();
		if (sDir.empty() || sLowerPath.size() <= sDir.size())
			return false;
		if (sLowerPath.compare(0, sDir.size(), sDir) != 0)
			return false;
		const char cNext = sLowerPath[sDir.size()];
		return cNext == '\\' || cNext == '/';
	}

	//
	// True when `sLowerPath` sits under a Windows OS system or Inbox/Store
	// component directory whose passive reads/loads should not flood scanning.
	//
	bool IsWindowsOsComponentPath(const std::string& sLowerPath)
	{
		static const char* const c_kPrefixes[] = {
			"c:\\windows\\system32\\",
			"c:\\windows\\syswow64\\",
			"c:\\windows\\winsxs\\",
			"c:\\windows\\microsoft.net\\",
			"c:\\windows\\systemapps\\",
			"c:\\windows\\shellcomponents\\",
			"c:\\windows\\shellexperiences\\",
			"c:\\windows\\immersivecontrolpanel\\",
			"c:\\windows\\uus\\",
			"c:\\windows\\servicing\\",
			"c:\\windows\\branding\\",
			"c:\\windows\\diagnostics\\",
			"c:\\windows\\inf\\",
			"c:\\windows\\serviceprofiles\\",
			"c:\\windows\\logs\\",
			"c:\\program files\\windowsapps\\microsoft.",
			"c:\\program files\\windowsapps\\microsoftwindows.",
			"c:\\program files (x86)\\microsoft\\edgewebview\\",
			"c:\\program files (x86)\\microsoft\\edge\\",
			"c:\\program files (x86)\\microsoft\\edgeupdate\\",
			"c:\\program files\\common files\\microsoft shared\\",
			"c:\\program files\\common files\\system\\",
			"c:\\programdata\\microsoft\\windows\\apprepository\\",
		};
		for (const char* p : c_kPrefixes)
		{
			if (sLowerPath.find(p) != std::string::npos)
				return true;
		}
		return false;
	}

	// Script hosts and script extensions come from edrsvc.cfg
	// (scanner.scriptInterpreters / scanner.scriptExtensions).
	//
	// The host is decided by the new process' image name, not by searching the
	// command line: argv[0] is whatever the parent wrote and need not name the
	// image at all. Every argument after argv[0] that resolves to an existing
	// file is scanned:
	//  - tokens are split the way the hosts and cmd see them: quotes only
	//    toggle (so `""C:\x.bat" "` and `/c"C:\x.bat"` both yield the path),
	//    cmd's & | < > separate commands and ^ escapes; a quoted token that is
	//    itself a command line (cmd /c "powershell -f x.ps1") is split again;
	//  - switch values are looked at (-File:C:\x.ps1, /cC:\x.bat);
	//  - %VAR% is expanded from the new process' own environment, and relative
	//    paths are resolved against its own current directory (both read from
	//    its process parameters; the parent's are used when it has already
	//    exited, the service's only as a last resort);
	//  - the file's extension does not decide whether it is scanned:
	//    python/node/perl/ruby/php run any file and cscript runs any file with
	//    //E:, so "python C:\x.txt" is scanned like "python C:\x.py". The
	//    extension list only picks which file is attached as scriptContent and
	//    which extensions to try for an extensionless name (cmd /c run).
	namespace ScriptArgs
	{
		constexpr size_t c_nMaxTokens = 64;

		std::wstring baseNameLow(const std::wstring& sPath)
		{
			const size_t nSlash = sPath.find_last_of(L"\\/");
			return string::convertToLow(nSlash == std::wstring::npos ? sPath : sPath.substr(nSlash + 1));
		}

		std::wstring stripExe(const std::wstring& sLowName)
		{
			static const std::wstring c_sExe(L".exe");
			if (sLowName.size() > c_sExe.size() &&
				sLowName.compare(sLowName.size() - c_sExe.size(), c_sExe.size(), c_sExe) == 0)
				return sLowName.substr(0, sLowName.size() - c_sExe.size());
			return sLowName;
		}

		// True when the image (file name, any case, ".exe" optional on either
		// side) is one of scanner.scriptInterpreters.
		bool isScriptHost(const std::wstring& sImageName)
		{
			const std::wstring sBase = stripExe(baseNameLow(sImageName));
			if (sBase.empty())
				return false;
			for (const auto& sHost : DetectionNotifier::getScriptInterpreters())
				if (stripExe(sHost) == sBase)
					return true;
			return false;
		}

		// Command-line tokens: whitespace splits outside quotes, a quote only
		// toggles quoting and is dropped, cmd's & | < > split outside quotes,
		// ^ escapes the next character outside quotes.
		std::vector<std::wstring> tokenize(const std::wstring& s)
		{
			std::vector<std::wstring> vOut;
			std::wstring sCur;
			bool fInQuote = false;
			auto flush = [&]() {
				const size_t b = sCur.find_first_not_of(L" \t");
				if (b != std::wstring::npos)
				{
					const size_t e = sCur.find_last_not_of(L" \t");
					vOut.push_back(sCur.substr(b, e - b + 1));
				}
				sCur.clear();
			};
			for (size_t i = 0; i < s.size(); ++i)
			{
				const wchar_t c = s[i];
				if (c == L'"')
				{
					fInQuote = !fInQuote;
					continue;
				}
				if (!fInQuote)
				{
					if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n')
					{
						flush();
						continue;
					}
					if (c == L'&' || c == L'|' || c == L'<' || c == L'>')
					{
						flush();
						continue;
					}
					if (c == L'^' && i + 1 < s.size())
					{
						sCur.push_back(s[++i]);
						continue;
					}
				}
				sCur.push_back(c);
			}
			flush();
			return vOut;
		}

		struct ProcContext
		{
			std::wstring sCwd; // with trailing separator, or empty
			std::vector<std::pair<std::wstring, std::wstring>> vEnv; // lower-case name, value
			bool fHaveEnv = false;
		};

		// Current directory and environment from a live process' parameters
		// (x64 RTL_USER_PROCESS_PARAMETERS: CurrentDirectory.DosPath at 0x38,
		// Environment at 0x80, EnvironmentSize at 0x3F0).
		bool readProcContext(uint32_t nPid, ProcContext& ctx)
		{
#ifdef _WIN64
			if (nPid <= 4)
				return false;
			typedef LONG(NTAPI * NtQueryInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
			static const auto s_fnQuery = reinterpret_cast<NtQueryInformationProcessFn>(
				::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
			if (!s_fnQuery)
				return false;
			HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, nPid);
			if (!hProc)
				return false;
			struct Pbi
			{
				LONG_PTR ExitStatus;
				ULONG_PTR PebBaseAddress;
				ULONG_PTR AffinityMask;
				LONG_PTR BasePriority;
				ULONG_PTR UniqueProcessId;
				ULONG_PTR InheritedFromUniqueProcessId;
			} pbi = {};
			bool fOk = false;
			auto readMem = [hProc](ULONG_PTR nAddr, void* pBuf, size_t nSize) {
				SIZE_T nGot = 0;
				return nAddr != 0 && ::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(nAddr), pBuf, nSize, &nGot) &&
					nGot == nSize;
			};
			do
			{
				if (s_fnQuery(hProc, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), nullptr) < 0)
					break;
				ULONG_PTR nParams = 0;
				if (!readMem(pbi.PebBaseAddress + 0x20, &nParams, sizeof(nParams)))
					break;
				uint8_t params[0x400] = {};
				if (!readMem(nParams, params, 0x100))
					break;
				const ULONG nLength = *reinterpret_cast<const ULONG*>(params + 0x04);
				const ULONG nFlags = *reinterpret_cast<const ULONG*>(params + 0x08);
				if (nLength >= 0x3F8 && !readMem(nParams + 0x100, params + 0x100, 0x300))
					break;
				// Not yet normalized: string buffers are offsets from the block.
				const ULONG_PTR nBias = (nFlags & 1) ? 0 : nParams;

				const USHORT nCwdLen = *reinterpret_cast<const USHORT*>(params + 0x38);
				const ULONG_PTR nCwdBuf = *reinterpret_cast<const ULONG_PTR*>(params + 0x40);
				if (nCwdLen > 0 && nCwdLen < 0x8000 && nCwdBuf != 0)
				{
					std::wstring sCwd(nCwdLen / sizeof(wchar_t), L'\0');
					if (readMem(nCwdBuf + nBias, sCwd.data(), nCwdLen))
					{
						if (!sCwd.empty() && sCwd.back() != L'\\' && sCwd.back() != L'/')
							sCwd.push_back(L'\\');
						ctx.sCwd = sCwd;
					}
				}

				const ULONG_PTR nEnv = *reinterpret_cast<const ULONG_PTR*>(params + 0x80);
				const ULONG_PTR nEnvSize = nLength >= 0x3F8 ? *reinterpret_cast<const ULONG_PTR*>(params + 0x3F0) : 0;
				if (nEnv != 0 && nEnvSize >= sizeof(wchar_t) && nEnvSize <= 4 * 1024 * 1024)
				{
					std::wstring sBlock(nEnvSize / sizeof(wchar_t), L'\0');
					if (readMem(nEnv, sBlock.data(), sBlock.size() * sizeof(wchar_t)))
					{
						size_t p = 0;
						while (p < sBlock.size() && sBlock[p] != L'\0')
						{
							size_t e = sBlock.find(L'\0', p);
							if (e == std::wstring::npos)
								e = sBlock.size();
							const std::wstring sVar = sBlock.substr(p, e - p);
							// "=C:=C:\dir" entries start with '='; the name is up to the next '='.
							const size_t nEq = sVar.find(L'=', 1);
							if (nEq != std::wstring::npos)
								ctx.vEnv.emplace_back(string::convertToLow(sVar.substr(0, nEq)), sVar.substr(nEq + 1));
							p = e + 1;
						}
						ctx.fHaveEnv = true;
					}
				}
				fOk = !ctx.sCwd.empty() || ctx.fHaveEnv;
			} while (false);
			::CloseHandle(hProc);
			return fOk;
#else
			(void)nPid;
			(void)ctx;
			return false;
#endif
		}

		// %NAME% from the process environment; names it does not have are left
		// for the service's own environment.
		std::wstring expandVars(const std::wstring& s, const ProcContext& ctx)
		{
			if (s.find(L'%') == std::wstring::npos)
				return s;
			std::wstring sOut;
			size_t i = 0;
			while (i < s.size())
			{
				const size_t a = s.find(L'%', i);
				if (a == std::wstring::npos)
				{
					sOut.append(s, i, std::wstring::npos);
					break;
				}
				const size_t b = s.find(L'%', a + 1);
				if (b == std::wstring::npos)
				{
					sOut.append(s, i, std::wstring::npos);
					break;
				}
				sOut.append(s, i, a - i);
				const std::wstring sName = string::convertToLow(s.substr(a + 1, b - a - 1));
				bool fFound = false;
				for (const auto& kv : ctx.vEnv)
				{
					if (kv.first == sName)
					{
						sOut += kv.second;
						fFound = true;
						break;
					}
				}
				if (!fFound)
				{
					wchar_t buf[MAX_PATH * 4] = {};
					const std::wstring sVar = s.substr(a, b - a + 1);
					const DWORD n = ctx.fHaveEnv ? 0 :
						::ExpandEnvironmentStringsW(sVar.c_str(), buf, static_cast<DWORD>(std::size(buf)));
					sOut += (n > 0 && n <= std::size(buf)) ? std::wstring(buf) : sVar;
				}
				i = b + 1;
			}
			return sOut;
		}

		bool isExistingFile(const std::wstring& sPath)
		{
			const DWORD nAttr = ::GetFileAttributesW(sPath.c_str());
			return nAttr != INVALID_FILE_ATTRIBUTES && (nAttr & FILE_ATTRIBUTE_DIRECTORY) == 0;
		}

		bool isDriveAbsolute(const std::wstring& s, size_t k = 0)
		{
			return s.size() >= k + 3 && ::iswalpha(s[k]) && s[k + 1] == L':' && (s[k + 2] == L'\\' || s[k + 2] == L'/');
		}

		// Absolute form of a path, or empty when it is relative and the
		// directory it is relative to is unknown.
		std::wstring makeAbsolute(const std::wstring& s, const ProcContext& ctx)
		{
			if (isDriveAbsolute(s) || (s.size() >= 2 && s[0] == L'\\' && s[1] == L'\\'))
				return s;
			if (ctx.sCwd.empty())
				return L"";
			if (!s.empty() && (s[0] == L'\\' || s[0] == L'/')) // root of the current drive
				return isDriveAbsolute(ctx.sCwd) ? ctx.sCwd.substr(0, 2) + s : L"";
			if (s.size() >= 2 && ::iswalpha(s[0]) && s[1] == L':') // "D:rel"
			{
				if (::towlower(s[0]) == ::towlower(ctx.sCwd[0]))
					return ctx.sCwd + s.substr(2);
				return s.substr(0, 2) + L"\\" + s.substr(2);
			}
			return ctx.sCwd + s;
		}

		bool hasScriptExt(const std::wstring& sPath, const std::vector<std::wstring>& vExt)
		{
			const std::wstring sLow = baseNameLow(sPath);
			const size_t nDot = sLow.find_last_of(L'.');
			if (nDot == std::wstring::npos)
				return false;
			const std::wstring sExt = sLow.substr(nDot + 1);
			for (const auto& e : vExt)
				if (e == sExt)
					return true;
			return false;
		}

		// Path forms a token can stand for: the token itself, a switch value
		// (after ':' or '='), an absolute path embedded after a switch letter
		// (/cC:\x.bat), each also without cmd's ( ) @ , ; decoration.
		std::vector<std::wstring> candidates(const std::wstring& sTok)
		{
			std::vector<std::wstring> vRaw;
			const bool fSwitch = !sTok.empty() && (sTok[0] == L'-' || sTok[0] == L'/');
			if (!fSwitch)
				vRaw.push_back(sTok);
			else
			{
				const size_t nSep = sTok.find_first_of(L":=");
				if (nSep != std::wstring::npos && nSep + 1 < sTok.size())
					vRaw.push_back(sTok.substr(nSep + 1));
			}
			for (size_t k = 1; k + 1 < sTok.size(); ++k)
			{
				if (isDriveAbsolute(sTok, k) || (sTok[k] == L'\\' && sTok[k + 1] == L'\\' && sTok[k - 1] != L'\\'))
				{
					vRaw.push_back(sTok.substr(k));
					break;
				}
			}
			std::vector<std::wstring> vOut;
			for (const auto& r : vRaw)
			{
				vOut.push_back(r);
				const size_t b = r.find_first_not_of(L"(@");
				const size_t e = r.find_last_not_of(L"),;");
				if (b != std::wstring::npos && e != std::wstring::npos && e >= b && (b != 0 || e != r.size() - 1))
					vOut.push_back(r.substr(b, e - b + 1));
			}
			return vOut;
		}

		// Every existing file named after argv[0], first-seen order, no
		// duplicates. sScriptOut gets the first one with a script extension,
		// else the first one.
		std::vector<std::wstring> findFiles(const std::wstring& cmdLine, uint32_t nPid, uint32_t nParentPid,
			std::wstring& sScriptOut)
		{
			sScriptOut.clear();
			std::vector<std::wstring> vFiles;
			std::vector<std::wstring> vTok = tokenize(cmdLine);
			if (vTok.size() <= 1)
				return vFiles;
			vTok.erase(vTok.begin()); // argv[0]
			// A quoted token holding a command line of its own (cmd /c "x y").
			const size_t nTop = vTok.size();
			for (size_t i = 0; i < nTop && vTok.size() < c_nMaxTokens * 2; ++i)
			{
				if (vTok[i].find_first_of(L" \t&|<>") != std::wstring::npos)
				{
					for (auto& t : tokenize(vTok[i]))
						vTok.push_back(t);
				}
			}

			ProcContext ctx;
			if (!readProcContext(nPid, ctx) && nParentPid != 0)
				readProcContext(nParentPid, ctx);

			const auto vExt = DetectionNotifier::getScriptExtensions();
			std::unordered_set<std::wstring> seen;
			size_t nTokens = 0;
			for (const auto& sTok : vTok)
			{
				if (++nTokens > c_nMaxTokens * 2)
					break;
				for (const auto& sCand : candidates(sTok))
				{
					const std::wstring sAbs = makeAbsolute(expandVars(sCand, ctx), ctx);
					if (sAbs.empty())
						continue;
					std::wstring sHit;
					if (isExistingFile(sAbs))
						sHit = sAbs;
					else if (baseNameLow(sAbs).find(L'.') == std::wstring::npos)
					{
						// cmd /c run -> run.cmd / run.bat ...
						for (const auto& e : vExt)
						{
							if (isExistingFile(sAbs + L"." + e))
							{
								sHit = sAbs + L"." + e;
								break;
							}
						}
					}
					if (sHit.empty())
						continue;
					if (seen.insert(string::convertToLow(sHit)).second)
						vFiles.push_back(sHit);
					break;
				}
			}
			for (const auto& f : vFiles)
			{
				if (hasScriptExt(f, vExt))
				{
					sScriptOut = f;
					break;
				}
			}
			if (sScriptOut.empty() && !vFiles.empty())
				sScriptOut = vFiles.front();
			return vFiles;
		}
	} // namespace ScriptArgs

	Variant readContent(const std::wstring& filePath)
	{
		std::ifstream fileStream(filePath, std::ios::binary);

		const uintmax_t fileContentLimit = 100000;
		std::error_code ec;
		const uintmax_t nFileSize = std::filesystem::file_size(filePath, ec);
		if (ec)
			return {};
		const uintmax_t size = std::clamp<uintmax_t>(nFileSize, 0, fileContentLimit);

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

	// Widens UTF-8 std::string to std::wstring.
	static inline std::wstring Widen(const std::string& sIn)
	{
		return string::convertUtf8ToWChar(sIn);
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

	// Shell link (.lnk) content for policy rules: file.shellLink.{isShellLink,
	// target, arguments, iconLocation, workingDirectory}. A file counts as a shell
	// link by its format header (MS-SHLLINK: HeaderSize 0x4C + LinkCLSID
	// 00021401-0000-0000-C000-000000000046), whatever its name; only what the
	// link says is reported, every judgement is left to the policy.
	static bool ReadShellLinkFields(const std::wstring& wsPath, Dictionary& vOut)
	{
		static const unsigned char c_header[20] = {
			0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
			0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 };
		{
			HANDLE h = ::CreateFileW(wsPath.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
			if (h == INVALID_HANDLE_VALUE)
				return false;
			unsigned char head[sizeof(c_header)] = {};
			DWORD nRead = 0;
			const BOOL ok = ::ReadFile(h, head, sizeof(head), &nRead, nullptr);
			::CloseHandle(h);
			if (!ok || nRead != sizeof(head) || memcmp(head, c_header, sizeof(head)) != 0)
				return false;
		}

		// The enricher threads are ours; COM stays initialized on each of them.
		thread_local const HRESULT hrCom = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
		if (FAILED(hrCom) && hrCom != RPC_E_CHANGED_MODE)
			return false;

		IShellLinkW* pLink = nullptr;
		if (FAILED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
			reinterpret_cast<void**>(&pLink))))
			return false;
		bool ok = false;
		IPersistFile* pFile = nullptr;
		if (SUCCEEDED(pLink->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&pFile))))
		{
			if (SUCCEEDED(pFile->Load(wsPath.c_str(), STGM_READ)))
			{
				auto expand = [](const wchar_t* s) {
					wchar_t buf[MAX_PATH * 4] = {};
					DWORD n = ::ExpandEnvironmentStringsW(s, buf, static_cast<DWORD>(std::size(buf)));
					return (n > 0 && n <= std::size(buf)) ? std::wstring(buf) : std::wstring(s);
				};
				wchar_t buf[MAX_PATH * 4] = {};
				std::wstring target;
				if (SUCCEEDED(pLink->GetPath(buf, static_cast<int>(std::size(buf)), nullptr, SLGP_RAWPATH)) && buf[0])
					target = expand(buf);
				buf[0] = 0;
				std::wstring args;
				if (SUCCEEDED(pLink->GetArguments(buf, static_cast<int>(std::size(buf)))))
					args = buf;
				buf[0] = 0;
				std::wstring icon;
				int iconIndex = 0;
				if (SUCCEEDED(pLink->GetIconLocation(buf, static_cast<int>(std::size(buf)), &iconIndex)) && buf[0])
					icon = expand(buf);
				buf[0] = 0;
				std::wstring workDir;
				if (SUCCEEDED(pLink->GetWorkingDirectory(buf, static_cast<int>(std::size(buf)))) && buf[0])
					workDir = expand(buf);

				vOut.put("isShellLink", true);
				vOut.put("target", target);
				vOut.put("arguments", args);
				vOut.put("iconLocation", icon);
				vOut.put("workingDirectory", workDir);
				ok = true;
			}
			pFile->Release();
		}
		pLink->Release();
		return ok;
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

	// HKLM\SOFTWARE\Owlyshield\SDK!TRAINING_SAVE_TO_FILE ("1") keeps the training
	// events in ProgramData\edrsvc\training_data\unknown_killchain_*.jsonl (the
	// uploader reads and uploads that file). Unset / "0": events go straight to the
	// uploader in owlyshield_ransom.dll, nothing is written to disk per event.
	// Re-read every 2 s like TRAINING_MODE, so regedit applies without a restart.
	bool IsTrainingSaveToFileEnabled()
	{
		static std::atomic<bool> s_cached{ false };
		static std::atomic<uint64_t> s_last{ 0 };

		const uint64_t nNow = (uint64_t)std::chrono::duration_cast<
			std::chrono::milliseconds>(std::chrono::steady_clock::now()
				.time_since_epoch()).count();
		if (nNow - s_last.load(std::memory_order_relaxed) >= 2000)
		{
			s_last.store(nNow, std::memory_order_relaxed);
			s_cached.store(ReadSdkBool("TRAINING_SAVE_TO_FILE", false), std::memory_order_relaxed);
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

		std::string sLowerExe = sExePath;
		for (auto& c : sLowerExe) c = (char)::tolower((unsigned char)c);

		// Empty means no explicit path filter: capture all processes (including
		// explorer.exe and system processes) except edrsvc's own install tree.
		if (sTrimmed.empty())
			return !IsPathUnderOwnInstallDir(sLowerExe);

		// Wildcard "*.*" or "*" means ignore path restriction and capture all processes in training mode
		if (sTrimmed == "*.*" || sTrimmed == "*" || sTrimmed.find("*.*") != std::string::npos)
			return true;

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

	static inline bool SuspendProcessByPid(uint32_t pid)
	{
		return cmd::zerotrust::SuspendProcessByPid(pid);
	}

	static inline bool ResumeProcessByPid(uint32_t pid)
	{
		return cmd::zerotrust::ResumeProcessByPid(pid);
	}

	namespace ZeroTrust
	{
		static inline bool isEnabled()
		{
			return cmd::zerotrust::ZeroTrustManager::instance().isEnabled();
		}

		static inline void setEnabled(bool enabled)
		{
			cmd::zerotrust::ZeroTrustManager::instance().setEnabled(enabled);
		}

		static inline void recordThreatDetection()
		{
			cmd::zerotrust::ZeroTrustManager::instance().recordThreatDetection();
		}

		static inline void addSessionWhitelist(const std::string& path)
		{
			cmd::zerotrust::ZeroTrustManager::instance().addSessionWhitelist(path);
		}

		static inline bool isSessionWhitelisted(const std::string& path)
		{
			return cmd::zerotrust::ZeroTrustManager::instance().isSessionWhitelisted(path);
		}

		static inline void addRestrictedProcess(uint32_t pid)
		{
			cmd::zerotrust::ZeroTrustManager::instance().addRestrictedPid(pid);
		}

		static inline bool isRestricted(uint32_t pid)
		{
			return cmd::zerotrust::ZeroTrustManager::instance().isRestricted(pid);
		}

		static inline void onProcessFileModification(uint32_t pid, const std::string& filePath)
		{
			cmd::zerotrust::ZeroTrustManager::instance().onProcessFileModification(pid, filePath);
		}
	}

	namespace UsbWormDetection
	{
		// Calculates similarity ratio [0..100] between running process binary and destination file written to USB
		static int calculateExeSimilarity(const std::wstring& srcPath, const std::wstring& dstPath)
		{
			if (srcPath.empty() || dstPath.empty())
				return 0;

			// If paths are identical, ignore
			if (_wcsicmp(srcPath.c_str(), dstPath.c_str()) == 0)
				return 100;

			HANDLE hSrc = ::CreateFileW(srcPath.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (hSrc == INVALID_HANDLE_VALUE)
				return 0;

			HANDLE hDst = ::CreateFileW(dstPath.c_str(), GENERIC_READ,
				FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
				nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (hDst == INVALID_HANDLE_VALUE)
			{
				::CloseHandle(hSrc);
				return 0;
			}

			LARGE_INTEGER liSrcSize = {}, liDstSize = {};
			::GetFileSizeEx(hSrc, &liSrcSize);
			::GetFileSizeEx(hDst, &liDstSize);

			uint64_t s1 = static_cast<uint64_t>(liSrcSize.QuadPart);
			uint64_t s2 = static_cast<uint64_t>(liDstSize.QuadPart);

			if (s1 == 0 || s2 == 0)
			{
				::CloseHandle(hSrc);
				::CloseHandle(hDst);
				return 0;
			}

			// 1. Size ratio score (0 - 100)
			double minSize = static_cast<double>(std::min(s1, s2));
			double maxSize = static_cast<double>(std::max(s1, s2));
			double sizeRatio = minSize / maxSize;
			if (sizeRatio < 0.35)
			{
				::CloseHandle(hSrc);
				::CloseHandle(hDst);
				return 0; // Sizes too different to be a self-replicating worm
			}
			int sizeScore = static_cast<int>(sizeRatio * 100.0);

			// 2. PE Header & Section Comparison
			int peScore = 0;
			IMAGE_DOS_HEADER dosSrc = {}, dosDst = {};
			DWORD dwRead = 0;
			bool bReadSrc = ::ReadFile(hSrc, &dosSrc, sizeof(dosSrc), &dwRead, nullptr) && dwRead == sizeof(dosSrc);
			bool bReadDst = ::ReadFile(hDst, &dosDst, sizeof(dosDst), &dwRead, nullptr) && dwRead == sizeof(dosDst);

			bool bothPe = false;
			if (bReadSrc && bReadDst && dosSrc.e_magic == IMAGE_DOS_SIGNATURE && dosDst.e_magic == IMAGE_DOS_SIGNATURE)
			{
				IMAGE_NT_HEADERS ntSrc = {}, ntDst = {};
				::SetFilePointer(hSrc, dosSrc.e_lfanew, nullptr, FILE_BEGIN);
				::SetFilePointer(hDst, dosDst.e_lfanew, nullptr, FILE_BEGIN);

				bool bNtSrc = ::ReadFile(hSrc, &ntSrc, sizeof(ntSrc), &dwRead, nullptr) && dwRead >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
				bool bNtDst = ::ReadFile(hDst, &ntDst, sizeof(ntDst), &dwRead, nullptr) && dwRead >= sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

				if (bNtSrc && bNtDst && ntSrc.Signature == IMAGE_NT_SIGNATURE && ntDst.Signature == IMAGE_NT_SIGNATURE)
				{
					bothPe = true;
					int partialPe = 0;
					if (ntSrc.OptionalHeader.Subsystem == ntDst.OptionalHeader.Subsystem)
						partialPe += 15;
					if (ntSrc.FileHeader.Machine == ntDst.FileHeader.Machine)
						partialPe += 15;
					if (ntSrc.FileHeader.NumberOfSections == ntDst.FileHeader.NumberOfSections)
						partialPe += 20;
					else if (std::abs(static_cast<int>(ntSrc.FileHeader.NumberOfSections) - static_cast<int>(ntDst.FileHeader.NumberOfSections)) <= 1)
						partialPe += 10;

					// Compare section names
					WORD nSecSrc = std::min<WORD>(ntSrc.FileHeader.NumberOfSections, 16);
					WORD nSecDst = std::min<WORD>(ntDst.FileHeader.NumberOfSections, 16);
					std::vector<IMAGE_SECTION_HEADER> secSrc(nSecSrc), secDst(nSecDst);

					::SetFilePointer(hSrc, dosSrc.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntSrc.FileHeader.SizeOfOptionalHeader, nullptr, FILE_BEGIN);
					::SetFilePointer(hDst, dosDst.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + ntDst.FileHeader.SizeOfOptionalHeader, nullptr, FILE_BEGIN);

					::ReadFile(hSrc, secSrc.data(), nSecSrc * sizeof(IMAGE_SECTION_HEADER), &dwRead, nullptr);
					::ReadFile(hDst, secDst.data(), nSecDst * sizeof(IMAGE_SECTION_HEADER), &dwRead, nullptr);

					int matchingSecs = 0;
					for (const auto& ss : secSrc)
					{
						for (const auto& sd : secDst)
						{
							if (memcmp(ss.Name, sd.Name, IMAGE_SIZEOF_SHORT_NAME) == 0)
							{
								matchingSecs++;
								break;
							}
						}
					}
					int maxSec = std::max(nSecSrc, nSecDst);
					if (maxSec > 0)
					{
						double secRatio = static_cast<double>(matchingSecs) / static_cast<double>(maxSec);
						partialPe += static_cast<int>(secRatio * 50.0);
					}
					peScore = std::min(partialPe, 100);
				}
			}

			// 3. Chunk Sampling & Block Jaccard Similarity (up to 32KB)
			const DWORD CHUNK_SIZE = 32768;
			std::vector<uint8_t> bufSrc(CHUNK_SIZE, 0), bufDst(CHUNK_SIZE, 0);
			DWORD readSrc = 0, readDst = 0;

			::SetFilePointer(hSrc, 0, nullptr, FILE_BEGIN);
			::SetFilePointer(hDst, 0, nullptr, FILE_BEGIN);
			::ReadFile(hSrc, bufSrc.data(), CHUNK_SIZE, &readSrc, nullptr);
			::ReadFile(hDst, bufDst.data(), CHUNK_SIZE, &readDst, nullptr);

			::CloseHandle(hSrc);
			::CloseHandle(hDst);

			int chunkScore = 0;
			if (readSrc > 0 && readDst > 0)
			{
				auto hashBlocks = [](const uint8_t* data, DWORD len) -> std::unordered_set<uint32_t>
				{
					std::unordered_set<uint32_t> hashes;
					const DWORD BLOCK_SIZE = 64;
					for (DWORD i = 0; i + BLOCK_SIZE <= len; i += 32)
					{
						uint32_t fnv = 2166136261u;
						for (DWORD b = 0; b < BLOCK_SIZE; ++b)
						{
							fnv ^= data[i + b];
							fnv *= 16777619u;
						}
						hashes.insert(fnv);
					}
					return hashes;
				};

				auto setSrc = hashBlocks(bufSrc.data(), readSrc);
				auto setDst = hashBlocks(bufDst.data(), readDst);

				if (!setSrc.empty() && !setDst.empty())
				{
					int intersectionCount = 0;
					for (auto h : setSrc)
					{
						if (setDst.find(h) != setDst.end())
							intersectionCount++;
					}
					int unionCount = static_cast<int>(setSrc.size() + setDst.size()) - intersectionCount;
					if (unionCount > 0)
					{
						chunkScore = static_cast<int>((static_cast<double>(intersectionCount) / static_cast<double>(unionCount)) * 100.0);
					}
				}
			}

			// Composite Score (Size 20%, PE 30%, Chunk 50%)
			double finalScore = 0.0;
			if (bothPe)
			{
				finalScore = (sizeScore * 0.20) + (peScore * 0.30) + (chunkScore * 0.50);
			}
			else
			{
				finalScore = (sizeScore * 0.30) + (chunkScore * 0.70);
			}

			return std::clamp(static_cast<int>(finalScore), 0, 100);
		}
	}

	static void AsyncRescanAndQuarantine(std::string dos, uint32_t nPid, bool fHighPriority = false);

	namespace DriverPortHips
	{
		static std::mutex s_portMutex;
		static std::atomic<bool> s_loadedFromPtm{false};
		static std::atomic<int> s_configuredTrustMode{3}; // 1: COMODO_FLS, 2: VIRUSKOV_CLOUD, 3: BOTH
		static std::atomic<bool> s_scanUnknownModules{true};
		static std::atomic<bool> s_enableDotNetLoaderDetection{true};
		static std::atomic<bool> s_enableDllAttackChain{true};
		static std::atomic<bool> s_quarantineUnknownDll{true};
		static std::atomic<bool> s_scanAllModulesIndiscriminately{false};
		// Per-process reuse of InspectProcessModules (ptm moduleInspectionCache*);
		// 0 = inspect on every event, as before.
		static std::atomic<int> s_moduleInspectionCacheSeconds{0};
		static std::atomic<int> s_moduleInspectionCacheMaxEntries{0};
		// Event rate log (ptm eventRate*); 0 seconds = off.
		static std::atomic<int> s_eventRateLogSeconds{0};
		static std::atomic<int> s_eventRateTopTypes{0};
		static std::atomic<int> s_eventRateTopProcesses{0};
		static std::atomic<bool> s_enableCloud{true};
		static std::atomic<bool> s_cloudFirst{true};
		// MegaDumper.dll process dumps (DumpQueue): untrusted processes, native or
		// managed; one dump per process per dumpCooldownSeconds; images that are
		// the process' genuinely loaded Windows modules scanned too or not; clean
		// dumps kept or removed after the scan.
		static std::atomic<bool> s_dumpUntrusted{true};
		static std::atomic<int> s_dumpCooldownSeconds{600};
		static std::atomic<bool> s_dumpScanSystemModules{false};
		static std::atomic<bool> s_dumpKeepClean{false};
		static std::atomic<int> s_cleanVerdict{1};
		static std::atomic<int> s_malwareVerdict{2};
		static std::atomic<int> s_unknownVerdictDefault{0};
		static std::atomic<int> s_unknownReputationVerdict{3};
		static std::atomic<int> s_staticUnknownVerdict{4};
		static std::vector<int> s_unknownVerdicts{0, 3, 4};
		static std::mutex s_unknownVerdictsMutex;

		static bool isUnknownVerdict(int v)
		{
			{
				std::lock_guard<std::mutex> lock(s_unknownVerdictsMutex);
				for (int uv : s_unknownVerdicts)
				{
					if (v == uv) return true;
				}
			}
			return (v != s_cleanVerdict.load(std::memory_order_relaxed) &&
			        v != s_malwareVerdict.load(std::memory_order_relaxed));
		}
		static std::vector<std::wstring> s_vulnerablePortFragments;
		static std::unordered_set<std::wstring> s_knownPorts;

		static inline std::wstring toLower(std::wstring s)
		{
			for (auto& c : s) c = static_cast<wchar_t>(std::tolower(static_cast<wint_t>(c)));
			return s;
		}

		static inline std::string toHex(uintptr_t val)
		{
			std::stringstream ss;
			ss << std::hex << std::uppercase << val;
			return ss.str();
		}

		static std::vector<std::wstring> edrsvcCandidatePaths()
		{
			std::vector<std::wstring> out;
			wchar_t mod[MAX_PATH] = {};
			if (::GetModuleFileNameW(nullptr, mod, MAX_PATH) > 0)
			{
				std::wstring s(mod);
				auto pos = s.find_last_of(L"\\/");
				if (pos != std::wstring::npos)
				{
					out.push_back(s.substr(0, pos + 1) + L"edrsvc.cfg");
					out.push_back(s.substr(0, pos + 1) + L"..\\data\\edrsvc.cfg");
					out.push_back(s.substr(0, pos + 1) + L"data\\edrsvc.cfg");
				}
			}
			out.push_back(L"edrsvc.cfg");
			out.push_back(L"data\\edrsvc.cfg");
			out.push_back(L"..\\data\\edrsvc.cfg");
			out.push_back(L"OpenEDR\\edrav2\\iprj\\edrsvc\\data\\edrsvc.cfg");
			out.push_back(L"C:\\Program Files\\OpenEDR\\edrsvc.cfg");
			out.push_back(L"C:\\Program Files\\HydraDragonAntivirus\\OpenEDR\\edrsvc.cfg");
			return out;
		}

		static bool extractBoolFromCfg(const std::string& content, const std::string& key, bool defaultVal)
		{
			size_t keyPos = content.find("\"" + key + "\"");
			if (keyPos == std::string::npos) return defaultVal;
			size_t colon = content.find(':', keyPos);
			if (colon == std::string::npos) return defaultVal;
			size_t valPos = content.find_first_not_of(" \t\r\n", colon + 1);
			if (valPos == std::string::npos) return defaultVal;
			if (content.compare(valPos, 4, "true") == 0) return true;
			if (content.compare(valPos, 5, "false") == 0) return false;
			return defaultVal;
		}

		static std::vector<std::wstring> ptmCandidatePaths()
		{
			std::vector<std::wstring> out;
			wchar_t mod[MAX_PATH] = {};
			if (::GetModuleFileNameW(nullptr, mod, MAX_PATH) > 0)
			{
				std::wstring s(mod);
				auto pos = s.find_last_of(L"\\/");
				if (pos != std::wstring::npos)
					out.push_back(s.substr(0, pos + 1) + L"ptm.local.src");
			}
			out.push_back(L"C:\\Program Files\\HydraDragonAntivirus\\OpenEDR\\ptm.local.src");
			out.push_back(L"ptm.local.src");
			out.push_back(L"OpenEDR\\edrav2\\iprj\\edrdata\\ptm.local.src");
			return out;
		}

		static int extractIntFromPtm(const std::string& content, const std::string& key, int defaultVal)
		{
			size_t keyPos = content.find("\"" + key + "\"");
			if (keyPos == std::string::npos) return defaultVal;
			size_t colon = content.find(':', keyPos);
			if (colon == std::string::npos) return defaultVal;
			size_t numStart = content.find_first_of("0123456789-", colon);
			if (numStart == std::string::npos) return defaultVal;
			return std::atoi(content.c_str() + numStart);
		}

		static std::vector<int> extractIntArrayFromCfg(const std::string& content, const std::string& key, const std::vector<int>& defaultVal)
		{
			size_t keyPos = content.find("\"" + key + "\"");
			if (keyPos == std::string::npos) return defaultVal;
			size_t openB = content.find('[', keyPos);
			if (openB == std::string::npos) return defaultVal;
			size_t closeB = content.find(']', openB);
			if (closeB == std::string::npos) return defaultVal;
			std::string sub = content.substr(openB + 1, closeB - openB - 1);
			std::vector<int> res;
			std::stringstream ss(sub);
			std::string item;
			while (std::getline(ss, item, ','))
			{
				size_t pos = item.find_first_of("0123456789-");
				if (pos != std::string::npos)
					res.push_back(std::atoi(item.c_str() + pos));
			}
			return res.empty() ? defaultVal : res;
		}

		static std::vector<std::wstring> extractArrayFromPtm(const std::string& content, const std::string& arrayKey)
		{
			std::vector<std::wstring> result;
			size_t keyPos = content.find("\"" + arrayKey + "\"");
			if (keyPos == std::string::npos)
				return result;

			size_t openBracket = content.find('[', keyPos);
			if (openBracket == std::string::npos)
				return result;

			size_t closeBracket = content.find(']', openBracket);
			if (closeBracket == std::string::npos)
				return result;

			std::string arrBlock = content.substr(openBracket + 1, closeBracket - openBracket - 1);
			std::string cur;
			bool inStr = false;
			for (size_t i = 0; i < arrBlock.size(); ++i)
			{
				char c = arrBlock[i];
				if (inStr)
				{
					if (c == '"')
					{
						inStr = false;
						if (!cur.empty())
						{
							std::wstring w(cur.begin(), cur.end());
							std::wstring cleaned;
							for (wchar_t wc : w)
							{
								if (wc != L'*')
									cleaned.push_back(static_cast<wchar_t>(std::tolower(static_cast<wint_t>(wc))));
							}
							if (!cleaned.empty())
								result.push_back(cleaned);
							cur.clear();
						}
					}
					else if (c == '\\' && i + 1 < arrBlock.size())
					{
						cur.push_back(arrBlock[++i]);
					}
					else
					{
						cur.push_back(c);
					}
				}
				else if (c == '"')
				{
					inStr = true;
					cur.clear();
				}
			}
			return result;
		}

		static void EnsurePtmLoaded()
		{
			if (s_loadedFromPtm.load(std::memory_order_relaxed))
				return;

			std::lock_guard<std::mutex> lock(s_portMutex);
			if (s_loadedFromPtm.load(std::memory_order_relaxed))
				return;

			// 1. Read scanner settings from edrsvc.cfg (avoids hardcoding unknown scanning & trust options)
			for (const auto& path : edrsvcCandidatePaths())
			{
				// Installed copies are AES-packed: read them decrypted (a raw read
				// found no key and silently kept the built-in defaults).
				std::string content = io::readConfigText(path);
				if (content.empty()) continue;

				int cfgTrust = extractIntFromPtm(content, "trustMode", 0);
				if (cfgTrust >= 1 && cfgTrust <= 3)
					s_configuredTrustMode.store(cfgTrust, std::memory_order_relaxed);

				s_scanUnknownModules.store(extractBoolFromCfg(content, "scanUnknownModules", true), std::memory_order_relaxed);
				s_enableDotNetLoaderDetection.store(extractBoolFromCfg(content, "enableDotNetLoaderDetection", true), std::memory_order_relaxed);
				s_enableDllAttackChain.store(extractBoolFromCfg(content, "enableDllAttackChain", true), std::memory_order_relaxed);
				s_quarantineUnknownDll.store(extractBoolFromCfg(content, "quarantineUnknownDll", true), std::memory_order_relaxed);
				s_scanAllModulesIndiscriminately.store(extractBoolFromCfg(content, "scanAllModulesIndiscriminately", false), std::memory_order_relaxed);
				s_enableCloud.store(extractBoolFromCfg(content, "enableCloud", true), std::memory_order_relaxed);
				s_cloudFirst.store(extractBoolFromCfg(content, "cloudFirst", true) || extractBoolFromCfg(content, "preferCloudScan", true), std::memory_order_relaxed);
				s_dumpUntrusted.store(extractBoolFromCfg(content, "dumpUntrusted", true), std::memory_order_relaxed);
				s_dumpCooldownSeconds.store((std::max)(0, extractIntFromPtm(content, "dumpCooldownSeconds", 600)), std::memory_order_relaxed);
				s_dumpScanSystemModules.store(extractBoolFromCfg(content, "dumpScanSystemModules", false), std::memory_order_relaxed);
				s_dumpKeepClean.store(extractBoolFromCfg(content, "dumpKeepClean", false), std::memory_order_relaxed);

				s_cleanVerdict.store(extractIntFromPtm(content, "cleanVerdict", 1), std::memory_order_relaxed);
				s_malwareVerdict.store(extractIntFromPtm(content, "malwareVerdict", 2), std::memory_order_relaxed);
				s_unknownVerdictDefault.store(extractIntFromPtm(content, "unknownVerdictDefault", 0), std::memory_order_relaxed);
				s_unknownReputationVerdict.store(extractIntFromPtm(content, "unknownReputationVerdict", 3), std::memory_order_relaxed);
				s_staticUnknownVerdict.store(extractIntFromPtm(content, "staticUnknownVerdict", 4), std::memory_order_relaxed);
				{
					std::lock_guard<std::mutex> lockVerdicts(s_unknownVerdictsMutex);
					s_unknownVerdicts = extractIntArrayFromCfg(content, "unknownVerdicts", {0, 3, 4});
				}

				LOGLVL(Detailed, FMT("enricher: Dynamically loaded scanner config from edrsvc.cfg: trustMode="
					<< s_configuredTrustMode.load()
					<< ", scanUnknownModules=" << s_scanUnknownModules.load()
					<< ", dotNetLoader=" << s_enableDotNetLoaderDetection.load()
					<< ", cloudFirst=" << s_cloudFirst.load()
					<< ", cleanVerdict=" << s_cleanVerdict.load()
					<< ", unknownDefault=" << s_unknownVerdictDefault.load()));
				break;
			}

			// 2. Read driver port rules & PTM trust options from ptm.local.src
			for (const auto& path : ptmCandidatePaths())
			{
				// Installed copies are AES-packed: read them decrypted (a raw read
				// found no key and silently kept the built-in defaults).
				std::string content = io::readConfigText(path);
				if (content.empty()) continue;

				int ptmTrust = extractIntFromPtm(content, "configuredTrustMode", 0);
				if (ptmTrust >= 1 && ptmTrust <= 3)
					s_configuredTrustMode.store(ptmTrust, std::memory_order_relaxed);

				s_moduleInspectionCacheSeconds.store(
					(std::max)(0, extractIntFromPtm(content, "moduleInspectionCacheSeconds", 0)), std::memory_order_relaxed);
				s_moduleInspectionCacheMaxEntries.store(
					(std::max)(0, extractIntFromPtm(content, "moduleInspectionCacheMaxEntries", 0)), std::memory_order_relaxed);
				s_eventRateLogSeconds.store(
					(std::max)(0, extractIntFromPtm(content, "eventRateLogSeconds", 0)), std::memory_order_relaxed);
				s_eventRateTopTypes.store(
					(std::max)(0, extractIntFromPtm(content, "eventRateTopTypes", 0)), std::memory_order_relaxed);
				s_eventRateTopProcesses.store(
					(std::max)(0, extractIntFromPtm(content, "eventRateTopProcesses", 0)), std::memory_order_relaxed);

				auto vuln = extractArrayFromPtm(content, "vulnerableDriverPorts");
				if (!vuln.empty())
				{
					s_vulnerablePortFragments = std::move(vuln);
				}

				auto white = extractArrayFromPtm(content, "whitelistedDriverPorts");
				if (!white.empty())
				{
					for (auto& w : white) s_knownPorts.insert(w);
				}

				LOGLVL(Detailed, FMT("enricher: Dynamically loaded trustMode=" << s_configuredTrustMode.load()
					<< ", " << s_vulnerablePortFragments.size() << " vulnerable ports, "
					<< s_knownPorts.size() << " whitelisted ports from ptm.local.src"));
				s_loadedFromPtm.store(true, std::memory_order_release);
				return;
			}
		}

		static inline bool isPathDriverOrMinifilterPort(const std::wstring& wsPath, std::wstring& outPortName)
		{
			if (wsPath.empty()) return false;
			EnsurePtmLoaded();

			std::wstring p = toLower(wsPath);

			// Check vulnerable ports loaded from ptm.local.src
			{
				std::lock_guard<std::mutex> lock(s_portMutex);
				for (const auto& frag : s_vulnerablePortFragments)
				{
					if (p.find(frag) != std::wstring::npos)
					{
						outPortName = wsPath;
						return true;
					}
				}
			}

			// Filter out standard disk/filesystem file paths (C:\..., \\?\Volume...)
			if (p.size() >= 2 && p[1] == L':') return false; // C:\...
			if (p.find(L"\\device\\harddiskvolume") != std::wstring::npos) return false;
			if (p.find(L"\\device\\cdrom") != std::wstring::npos) return false;
			if (p.find(L"\\device\\mup") != std::wstring::npos) return false;
			if (p.find(L"\\device\\lanmanredirector") != std::wstring::npos) return false;
			if (p.find(L"\\volume{") != std::wstring::npos) return false;

			// Check if it's a device or minifilter communication port pattern
			if (p.rfind(L"\\\\.\\", 0) == 0 ||
			    p.rfind(L"\\??\\", 0) == 0 ||
			    p.rfind(L"\\device\\", 0) == 0 ||
			    p.find(L"filtermanager") != std::wstring::npos ||
			    (p.size() > 1 && p[0] == L'\\' && p.find(L'\\', 1) == std::wstring::npos)) // Root object like \RWFilter
			{
				outPortName = wsPath;
				return true;
			}

			return false;
		}


		// ── MegaDumper .NET Inspection Logic (translated to C++) ───────────────
		// Detects .NET managed assemblies, native loaders, and CLR runtimes even
		// under heavy obfuscation, packers, or stripped headers.
		namespace MegaDumperNet
		{
			// 1. Checks COM descriptor / CLI header (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14)
			static inline bool HasCliHeader(const unsigned char* pHeader, size_t headerSize)
			{
				if (!pHeader || headerSize < 0x80) return false;
				if (pHeader[0] != 0x4D || pHeader[1] != 0x5A) return false; // MZ
				uint32_t peOffset = *reinterpret_cast<const uint32_t*>(pHeader + 0x3C);
				if (peOffset == 0 || peOffset + 0x18 > headerSize) return false;
				if (pHeader[peOffset] != 0x50 || pHeader[peOffset + 1] != 0x45 ||
				    pHeader[peOffset + 2] != 0 || pHeader[peOffset + 3] != 0) return false; // PE\0\0

				if (peOffset + 26 > headerSize) return false;
				uint16_t magic = *reinterpret_cast<const uint16_t*>(pHeader + peOffset + 24);
				bool is64 = (magic == 0x20B);
				if (magic != 0x10B && magic != 0x20B) return false;

				size_t dataDirBase = peOffset + 4 + 20 + (is64 ? 112 : 96);
				size_t cliOffset = dataDirBase + (14 * 8);
				if (cliOffset + 4 > headerSize) return false;

				uint32_t cliRva = *reinterpret_cast<const uint32_t*>(pHeader + cliOffset);
				return (cliRva != 0);
			}

			// 2. Centralised list of CLR runtime modules across all generations (from MegaDumper IsClrModuleName)
			static inline bool IsClrModuleName(const std::string& lowerName)
			{
				if (lowerName.find("mscorwks.dll") != std::string::npos) return true; // .NET 2.0-3.5
				if (lowerName.find("clr.dll") != std::string::npos) return true;      // .NET 4.x
				if (lowerName.find("mscorlib.dll") != std::string::npos) return true;
				if (lowerName.find("coreclr.dll") != std::string::npos) return true;  // .NET Core / 5+
				if (lowerName.find("clrjit.dll") != std::string::npos) return true;
				return false;
			}

			// 3. MegaDumper BSJB Signature Scanner
			// Scans for the .NET Metadata Root Magic: 0x424A5342 ("BSJB" in little endian: 0x42, 0x53, 0x4A, 0x42)
			// MegaDumper uses this to find .NET metadata in memory even if PE headers are stripped/erased
			static inline bool HasBsjbSignature(const unsigned char* pData, size_t dataSize)
			{
				if (!pData || dataSize < 16) return false;
				for (size_t i = 0; i + 16 <= dataSize; ++i)
				{
					if (pData[i] == 0x42 && pData[i+1] == 0x53 && pData[i+2] == 0x4A && pData[i+3] == 0x42)
					{
						uint32_t versionLength = *reinterpret_cast<const uint32_t*>(pData + i + 12);
						if (versionLength > 0 && versionLength < 256 && (i + 16 + versionLength <= dataSize))
						{
							if (pData[i + 16] == 'v') // "v4.0.30319", "v2.0.50727", etc.
							{
								return true;
							}
						}
					}
				}
				return false;
			}

			// 4. Scans import descriptors or binary strings for mscoree.dll and _CorExeMain / _CorDllMain
			static inline bool HasClrImports(const unsigned char* pData, size_t dataSize)
			{
				if (!pData || dataSize < 0x200) return false;
				std::string s(reinterpret_cast<const char*>(pData), dataSize);
				std::string lowerS;
				lowerS.reserve(s.size());
				for (char c : s) lowerS.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

				if (lowerS.find("mscoree.dll") != std::string::npos)
				{
					if (s.find("_CorExeMain") != std::string::npos ||
					    s.find("_CorDllMain") != std::string::npos)
					{
						return true;
					}
				}
				return false;
			}

			// 5. Check if file on disk is .NET (PE header CLI, BSJB magic, or mscoree import)
			// fRead: the header could be read (false: no such file, locked, short).
			static inline bool ReadFileIsDotNet(const std::wstring& wsFilePath, bool& fRead)
			{
				fRead = false;
				if (wsFilePath.empty()) return false;
				HANDLE hFile = ::CreateFileW(wsFilePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (hFile == INVALID_HANDLE_VALUE) return false;

				unsigned char buf[8192] = {};
				DWORD bytesRead = 0;
				bool isNet = false;
				if (::ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL))
				{
					fRead = true;
					if (bytesRead >= 0x100 &&
						(HasCliHeader(buf, bytesRead) || HasBsjbSignature(buf, bytesRead) || HasClrImports(buf, bytesRead)))
					{
						isNet = true;
					}
				}
				::CloseHandle(hFile);
				return isNet;
			}

			static inline bool CheckFileIsDotNet(const std::wstring& wsFilePath)
			{
				bool fRead = false;
				return ReadFileIsDotNet(wsFilePath, fRead);
			}

			// CheckFileIsDotNet, with the header read once per file content (path +
			// size + last write time). The module inspection asks this for every
			// DLL of a process each time it runs; the answer only changes when the
			// file does. A header that could not be read is not kept.
			static inline bool CheckFileIsDotNetCached(const std::wstring& wsFilePath)
			{
				if (wsFilePath.empty())
					return false;
				std::wstring sKey = wsFilePath;
				for (auto& c : sKey) c = static_cast<wchar_t>(::towlower(c));

				struct Entry
				{
					uint64_t nSize;
					uint64_t nTime;
					bool fNet;
					std::chrono::steady_clock::time_point lastStatCheck{};
				};
				static std::mutex s_mtx;
				static std::unordered_map<std::wstring, Entry> s_cache;
				constexpr size_t c_nMaxEntries = 4096;
				const auto now = std::chrono::steady_clock::now();
				{
					std::scoped_lock lock(s_mtx);
					auto it = s_cache.find(sKey);
					if (it != s_cache.end() && now - it->second.lastStatCheck < std::chrono::seconds(5))
						return it->second.fNet;
				}

				WIN32_FILE_ATTRIBUTE_DATA fa = {};
				if (!::GetFileAttributesExW(wsFilePath.c_str(), GetFileExInfoStandard, &fa))
					return CheckFileIsDotNet(wsFilePath);
				const uint64_t nSize = (uint64_t(fa.nFileSizeHigh) << 32) | fa.nFileSizeLow;
				const uint64_t nTime = (uint64_t(fa.ftLastWriteTime.dwHighDateTime) << 32) | fa.ftLastWriteTime.dwLowDateTime;
				{
					std::scoped_lock lock(s_mtx);
					auto it = s_cache.find(sKey);
					if (it != s_cache.end() && it->second.nSize == nSize && it->second.nTime == nTime)
					{
						it->second.lastStatCheck = now;
						return it->second.fNet;
					}
				}
				bool fRead = false;
				const bool fNet = ReadFileIsDotNet(wsFilePath, fRead);
				if (fRead)
				{
					std::scoped_lock lock(s_mtx);
					if (s_cache.size() >= c_nMaxEntries)
					{
						auto it = s_cache.begin();
						for (size_t i = 0; i < c_nMaxEntries / 2 && it != s_cache.end(); ++i)
							it = s_cache.erase(it);
					}
					s_cache[sKey] = Entry{ nSize, nTime, fNet, now };
				}
				return fNet;
			}

			// 6. Name similarity check between executable stem and DLL stem
			static inline bool HasNameSimilarity(const std::string& exeName, const std::string& dllName)
			{
				std::string stemExe = exeName;
				size_t slashE = stemExe.find_last_of("\\/");
				if (slashE != std::string::npos) stemExe = stemExe.substr(slashE + 1);
				size_t dotExe = stemExe.rfind('.');
				if (dotExe != std::string::npos) stemExe = stemExe.substr(0, dotExe);

				std::string stemDll = dllName;
				size_t slashD = stemDll.find_last_of("\\/");
				if (slashD != std::string::npos) stemDll = stemDll.substr(slashD + 1);
				size_t dotDll = stemDll.rfind('.');
				if (dotDll != std::string::npos) stemDll = stemDll.substr(0, dotDll);

				for (auto& c : stemExe) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
				for (auto& c : stemDll) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

				if (stemExe.empty() || stemDll.empty()) return false;
				if (stemExe == stemDll) return true;
				if (stemDll.find(stemExe) != std::string::npos || stemExe.find(stemDll) != std::string::npos) return true;

				size_t minLen = (stemExe.size() < stemDll.size()) ? stemExe.size() : stemDll.size();
				if (minLen >= 4)
				{
					size_t prefixLen = 0;
					while (prefixLen < minLen && stemExe[prefixLen] == stemDll[prefixLen])
						prefixLen++;
					if (prefixLen >= 4) return true;
				}
				return false;
			}
		}

		struct ModuleInspectionResult
		{
			bool hasUnknownDllComodo = false;
			bool hasUnknownDllCertificate = false;
			bool hasUnknownDll = false;
			bool hasEvaluatedUnknownDll = false;
			bool isDotNet = false;
			bool isDotNetLoader = false;
			std::string firstUnknownDllComodo;
			std::string firstUnknownDllCert;
			std::string loaderTargetDll;
			std::string loaderTargetDllName;
			std::string loaderStartFunction;
			std::string dllAttackChain;
			std::string dllMapping;
		};

		// Inspects all loaded modules in process memory:
		// Checks Comodo FLS verdict AND offline Microsoft/Trusted Certificate verdict separately,
		// detects .NET loaders via MegaDumper logic, and builds full DLL attack chain & mapping.
		static ModuleInspectionResult InspectProcessModules(uint32_t nPid, const std::string& sProcPath)
		{
			ModuleInspectionResult res;
			if (nPid <= 4) return res;

			EnsurePtmLoaded();

			std::string sProcName = sProcPath;
			size_t pS = sProcName.find_last_of("\\/");
			if (pS != std::string::npos) sProcName = sProcName.substr(pS + 1);

			// Check if host process binary is .NET
			bool mainIsNet = MegaDumperNet::CheckFileIsDotNetCached(Widen(sProcPath));
			if (mainIsNet) res.isDotNet = true;

			HANDLE hSnap = INVALID_HANDLE_VALUE;
			{
				StageTimer stSnap(c_stModSnapshot);
				hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, nPid);
			}
			if (hSnap == INVALID_HANDLE_VALUE) return res;

			MODULEENTRY32W me = {};
			me.dwSize = sizeof(MODULEENTRY32W);

			std::wstring wsProc = Widen(sProcPath);
			bool clrLoaded = false;
			std::string primaryNetDllPath;
			std::string primaryNetDllName;
			std::vector<std::string> moduleEntries;

			if (::Module32FirstW(hSnap, &me))
			{
				do
				{
					// Skip the main process executable itself (checked separately)
					if (_wcsicmp(me.szExePath, wsProc.c_str()) == 0)
						continue;

					std::string modPath = Narrow(me.szExePath);
					std::string modName = Narrow(me.szModule);
					std::string modLower = modPath;
					for (auto& c : modLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
					std::string modNameLower = modName;
					for (auto& c : modNameLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

					// Check CLR runtime module presence
					if (MegaDumperNet::IsClrModuleName(modNameLower))
					{
						clrLoaded = true;
						res.isDotNet = true;
					}

					// Two separate reasons not to deep-scan or read PE headers, deliberately not merged:
					//   isSystemDll - lives in the Windows tree; scanning or opening every system DLL on
					//                 every process is prohibitive (CLR runtime DLLs are already matched above).
					//   isOwnModule - one of our own components (see IsPathUnderOwnInstallDir).
					//                 These carry the signature tables and constant pools the
					//                 engines search for, so scanning them both guarantees
					//                 self-detection and re-enters the self-scan loop.
					bool isSystemDll = IsWindowsOsComponentPath(modLower);
					bool isOwnModule = IsPathUnderOwnInstallDir(modLower);

					bool modIsNet = false;
					if (!isSystemDll && !isOwnModule)
					{
						StageTimer stNet(c_stModDotNet);
						modIsNet = MegaDumperNet::CheckFileIsDotNetCached(me.szExePath);
					}
					if (modIsNet) res.isDotNet = true;

					bool modFlsClean = true;
					bool modViruskovClean = true;

					bool forceScanAll = s_scanAllModulesIndiscriminately.load(std::memory_order_relaxed);
					bool shouldDeepScan = forceScanAll || (!isSystemDll && !isOwnModule);

					if (shouldDeepScan)
					{
						StageTimer stScan(c_stModScan);
						DetectionNotifier::CloudScanDetail modDetail;
						int cachedVerdict = DetectionNotifier::getCachedFileVerdict(modPath, &modDetail);
						if (isUnknownVerdict(cachedVerdict))
						{
							AsyncRescanAndQuarantine(modPath, nPid, false);
							modFlsClean = false;
							modViruskovClean = false;
							const bool bNotEvaluatedYet =
								(cachedVerdict == 0 && modDetail.sFls.empty() && modDetail.sViruskov.empty());
							if (!bNotEvaluatedYet)
								res.hasEvaluatedUnknownDll = true;
						}
						else
						{
							const int cleanVal = s_cleanVerdict.load(std::memory_order_relaxed);
							modFlsClean = (modDetail.sFls == "Safe") || (modDetail.sFls.empty() && cachedVerdict == cleanVal);
							modViruskovClean = (modDetail.sViruskov == "Clean") || (modDetail.sViruskov.empty() && cachedVerdict == cleanVal);
							if (!modFlsClean || !modViruskovClean)
								res.hasEvaluatedUnknownDll = true;
						}
						if (!modFlsClean)
						{
							res.hasUnknownDllComodo = true;
							if (res.firstUnknownDllComodo.empty())
								res.firstUnknownDllComodo = modPath;
						}
						if (!modViruskovClean)
						{
							res.hasUnknownDllCertificate = true;
							if (res.firstUnknownDllCert.empty())
								res.firstUnknownDllCert = modPath;
						}
					}

					int trustMode = s_configuredTrustMode.load(std::memory_order_relaxed);
					bool isModTrusted = (trustMode == 1) ? modFlsClean
					                  : (trustMode == 2) ? modViruskovClean
					                  : (modFlsClean && modViruskovClean);
					std::string startFunc = modIsNet ? "_CorDllMain" : "DllMain";

					if (moduleEntries.size() < 12)
					{
						moduleEntries.push_back(modName + "[0x" + toHex(reinterpret_cast<uintptr_t>(me.modBaseAddr)) +
							(modIsNet ? ",.NET" : ",Native") +
							(isModTrusted ? ",Trusted" : ",Unknown") +
							",Start:" + startFunc + "]");
					}

					// Loader Candidate Detection
					if (s_enableDotNetLoaderDetection.load(std::memory_order_relaxed))
					{
						if (modIsNet)
						{
							bool nameSimilar = MegaDumperNet::HasNameSimilarity(sProcName, modName);
							bool isNonSystem = !IsWindowsOsComponentPath(modLower);

							if (nameSimilar)
							{
								primaryNetDllPath = modPath;
								primaryNetDllName = modName;
							}
							else if (isNonSystem && primaryNetDllPath.empty())
							{
								primaryNetDllPath = modPath;
								primaryNetDllName = modName;
							}
						}
					}
				} while (::Module32NextW(hSnap, &me));
			}
			::CloseHandle(hSnap);

			res.hasUnknownDll = (res.hasUnknownDllComodo || res.hasUnknownDllCertificate);

			// Determine .NET Loader status
			if (!primaryNetDllPath.empty())
			{
				res.isDotNetLoader = true;
				res.isDotNet = true;
				res.loaderTargetDll = primaryNetDllPath;
				res.loaderTargetDllName = primaryNetDllName;
				res.loaderStartFunction = "_CorDllMain";
			}

			// Build dllMapping string
			std::string mappingStr;
			for (size_t i = 0; i < moduleEntries.size(); ++i)
			{
				if (i > 0) mappingStr += " -> ";
				mappingStr += moduleEntries[i];
			}
			res.dllMapping = mappingStr;

			// Build dllAttackChain string
			if (res.isDotNetLoader)
			{
				res.dllAttackChain = "[Loader: " + sProcName + " (PID: " + std::to_string(nPid) + ")] -> [Target DLL: " +
					res.loaderTargetDllName + " (Start: " + res.loaderStartFunction + ", .NET: YES, Trust: " +
					(res.hasUnknownDll ? "UNKNOWN/UNTRUSTED" : "TRUSTED") + ")]";
			}
			else if (res.hasUnknownDll)
			{
				std::string unk = !res.firstUnknownDllComodo.empty() ? res.firstUnknownDllComodo : res.firstUnknownDllCert;
				size_t uS = unk.find_last_of("\\/");
				if (uS != std::string::npos) unk = unk.substr(uS + 1);
				res.dllAttackChain = "[Process: " + sProcName + " (PID: " + std::to_string(nPid) + ")] -> [Injected DLL: " + unk + " (Trust: UNKNOWN)]";
			}
			else
			{
				res.dllAttackChain = "[Process: " + sProcName + " (PID: " + std::to_string(nPid) + ")]";
			}

			return res;
		}

		// InspectProcessModules, reused per process for moduleInspectionCacheSeconds.
		// It used to run on every event: a module snapshot plus, per loaded DLL, a
		// .NET header read, an FLS cache lookup and a signature check - hundreds of
		// file operations per event for a browser, on the single enricher thread,
		// so under an event flood the queue (and every detection in it) fell
		// behind. A reused PID with a different image path is inspected afresh.
		static ModuleInspectionResult InspectProcessModulesCached(uint32_t nPid, const std::string& sProcPath)
		{
			if (nPid <= 4)
				return InspectProcessModules(nPid, sProcPath);

			EnsurePtmLoaded();
			std::string sProcLower = sProcPath;
			for (auto& c : sProcLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
			const int ttl = s_moduleInspectionCacheSeconds.load(std::memory_order_relaxed);
			const int effectiveTtl = (std::max)(ttl, IsWindowsOsComponentPath(sProcLower) ? 300 : 30);
			if (effectiveTtl <= 0)
				return InspectProcessModules(nPid, sProcPath);

			struct Entry
			{
				std::string procPath;
				std::chrono::steady_clock::time_point at;
				ModuleInspectionResult res;
			};
			static std::mutex s_mtx;
			static std::unordered_map<uint32_t, Entry> s_cache;

			const auto now = std::chrono::steady_clock::now();
			const auto maxAge = std::chrono::seconds(effectiveTtl);
			{
				std::scoped_lock lock(s_mtx);
				auto it = s_cache.find(nPid);
				if (it != s_cache.end() && it->second.procPath == sProcPath && now - it->second.at < maxAge)
					return it->second.res;
			}

			ModuleInspectionResult res = InspectProcessModules(nPid, sProcPath);

			std::scoped_lock lock(s_mtx);
			const size_t maxEntries = static_cast<size_t>(s_moduleInspectionCacheMaxEntries.load(std::memory_order_relaxed));
			const size_t effectiveMax = (std::max)(maxEntries, size_t(4096));
			if (s_cache.size() >= effectiveMax)
			{
				// Expired entries first; if all are fresh, start over.
				for (auto it = s_cache.begin(); it != s_cache.end(); )
					it = (now - it->second.at >= maxAge) ? s_cache.erase(it) : std::next(it);
				if (s_cache.size() >= effectiveMax)
					s_cache.clear();
			}
			s_cache[nPid] = Entry{ sProcPath, now, res };
			return res;
		}

		// Checks whether process is trusted based on configurable mode:
		// Mode 1: Comodo FLS Only
		// Mode 2: VirusKov Cloud Only
		// Mode 3: Both (Must pass Comodo FLS AND VirusKov Cloud verification)
		static bool IsProcessTrustedConfigurable(
			const Variant& vProcess,
			const std::string& sProcPath,
			uint32_t nPid,
			const ModuleInspectionResult& modRes,
			std::string& outUntrustedReason,
			const DetectionNotifier::CloudScanDetail* pPreProcDetail = nullptr,
			int nPreProcCached = -1)
		{
			if (sProcPath.empty() || nPid <= 4) return false;

			if (ZeroTrust::isRestricted(nPid))
			{
				outUntrustedReason = "Process is restricted by ZeroTrust policy";
				return false;
			}

			DetectionNotifier::CloudScanDetail localDetail;
			int procCached = nPreProcCached;
			const DetectionNotifier::CloudScanDetail* pDetail = pPreProcDetail;
			if (!pDetail || procCached < 0)
			{
				procCached = DetectionNotifier::getCachedFileVerdict(sProcPath, &localDetail);
				pDetail = &localDetail;
			}
			const int cleanVal = s_cleanVerdict.load(std::memory_order_relaxed);
			bool isProcFlsClean = (pDetail->sFls == "Safe") ||
			                      (vProcess.has("flsVerdict") && static_cast<int64_t>(vProcess["flsVerdict"]) == cleanVal);
			bool isProcViruskovClean = (pDetail->sViruskov == "Clean") ||
			                           (pDetail->sFls.empty() && procCached == cleanVal);

			EnsurePtmLoaded();
			int mode = s_configuredTrustMode.load(std::memory_order_relaxed);

			// Mode 1: Comodo FLS Only
			if (mode == 1)
			{
				if (!isProcFlsClean)
				{
					outUntrustedReason = "Process is not Clean according to Comodo FLS";
					return false;
				}
				if (modRes.hasUnknownDllComodo)
				{
					outUntrustedReason = "Process contains unknown DLL according to Comodo FLS: " + modRes.firstUnknownDllComodo;
					return false;
				}
				return true;
			}

			// Mode 2: VirusKov Cloud Only
			if (mode == 2)
			{
				if (!isProcViruskovClean)
				{
					outUntrustedReason = "Process is not Clean according to VirusKov Cloud";
					return false;
				}
				if (modRes.hasUnknownDllCertificate)
				{
					outUntrustedReason = "Process contains unknown DLL according to VirusKov Cloud: " + modRes.firstUnknownDllCert;
					return false;
				}
				return true;
			}

			// Mode 3: BOTH (Must pass both Comodo FLS AND VirusKov Cloud verification)
			if (!isProcFlsClean)
			{
				outUntrustedReason = "Process is not Clean according to Comodo FLS";
				return false;
			}
			if (!isProcViruskovClean)
			{
				outUntrustedReason = "Process is not Clean according to VirusKov Cloud";
				return false;
			}
			if (modRes.hasUnknownDllComodo)
			{
				outUntrustedReason = "Process contains unknown DLL according to Comodo FLS: " + modRes.firstUnknownDllComodo;
				return false;
			}
			if (modRes.hasUnknownDllCertificate)
			{
				outUntrustedReason = "Process contains unknown DLL according to VirusKov Cloud: " + modRes.firstUnknownDllCert;
				return false;
			}

			return true;
		}

		// Inspects file create events for unauthorized connections to driver communication ports
		static bool InspectPortAccess(
			const std::wstring& wsDestPath,
			const Variant& vProcess,
			const std::string& sProcPath,
			uint32_t nPid,
			const ModuleInspectionResult& modRes,
			std::string& outThreatReason,
			bool& outIsKnownVulnerable,
			std::string& outUnknownDllToQuarantine)
		{
			outIsKnownVulnerable = false;
			outUnknownDllToQuarantine.clear();
			if (nPid <= 4) return false; // System idle / kernel

			std::wstring wsPortName;
			if (!isPathDriverOrMinifilterPort(wsDestPath, wsPortName))
				return false;

			std::wstring p = toLower(wsPortName);

			// Check whitelisted benign ports loaded from ptm.local.src (e.g. named pipe, null device)
			{
				std::lock_guard<std::mutex> lock(s_portMutex);
				for (const auto& kp : s_knownPorts)
				{
					if (p == kp || p.rfind(kp + L"\\", 0) == 0)
						return false; // Whitelisted benign port
				}
			}

			// Check if this matches a known vulnerable BYOVD port from ptm.local.src (\RWFilter, \RTCore64, etc.)
			{
				std::lock_guard<std::mutex> lock(s_portMutex);
				for (const auto& frag : s_vulnerablePortFragments)
				{
					if (p.find(frag) != std::wstring::npos)
					{
						outIsKnownVulnerable = true;
						if (modRes.hasUnknownDllComodo || modRes.hasUnknownDllCertificate)
						{
							std::string targetDll = !modRes.firstUnknownDllComodo.empty() ? modRes.firstUnknownDllComodo : modRes.firstUnknownDllCert;
							outUnknownDllToQuarantine = targetDll;
							outThreatReason = "CRITICAL BYOVD EXPLOITATION with Injected/Unknown DLL (" + targetDll + ") targeting port: " + Narrow(wsPortName);
						}
						else
						{
							outThreatReason = "CRITICAL BYOVD EXPLOITATION: Vulnerable Driver/Minifilter Port Detected (" + Narrow(wsPortName) + ")";
						}
						return true;
					}
				}
			}

			// Special Port Rule Check: If process has unknown DLLs attempting kernel driver port access
			if (modRes.hasUnknownDllComodo || modRes.hasUnknownDllCertificate)
			{
				std::string targetDll = !modRes.firstUnknownDllComodo.empty() ? modRes.firstUnknownDllComodo : modRes.firstUnknownDllCert;
				outUnknownDllToQuarantine = targetDll;
				outThreatReason = "HIPS Warning: Driver Port Access with Unknown/Injected DLL (" + targetDll + ")";
				return true;
			}

			// Configurable Trust Evaluation (Mode 1, 2, or 3)
			std::string untrustedReason;
			bool isStrict = IsProcessTrustedConfigurable(vProcess, sProcPath, nPid, modRes, untrustedReason);
			if (isStrict)
			{
				return false; // Verified clean according to configured policy
			}

			// If untrusted process connects to a new or unknown driver port:
			{
				std::lock_guard<std::mutex> lock(s_portMutex);
				if (s_knownPorts.find(p) == s_knownPorts.end())
				{
					s_knownPorts.insert(p);
					if (!untrustedReason.empty())
						outThreatReason = "HIPS Warning: " + untrustedReason + " accessing driver port (" + Narrow(wsPortName) + ")";
					else
						outThreatReason = "HIPS Warning: Untrusted process attempting connection to kernel driver port (ptm.local.src)";
					return true;
				}
			}

			return false;
		}
	}

	// Save unknown process behavior killchain telemetry into training dataset
	void AppendToTrainingDataset(const std::string& sExePath, const std::string& sEventType, const std::string& sDetails, const std::string& sJson)
	{
		SYSTEMTIME st = {};
		::GetLocalTime(&st);

		char szTime[32] = "";
		sprintf_s(szTime, "%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

		// Formatted killchain sequence line (fields JSON-escaped: raw Windows
		// paths contain \s \t etc. which are invalid escapes raw).
		std::string sLine = "{\"time\":\"" + std::string(szTime) + "\",\"exe\":\"" + JsonEscapeA(sExePath)
			+ "\",\"event\":\"" + JsonEscapeA(sEventType) + "\",\"details\":\"" + JsonEscapeA(sDetails)
			+ "\",\"raw\":" + sJson + "}";

		static std::atomic<uint64_t> s_nTrainingEvents{ 0 };
		const uint64_t nEvents = s_nTrainingEvents.fetch_add(1, std::memory_order_relaxed) + 1;

		// Straight to owlyshield's kill chain uploader, which deduplicates and
		// uploads from memory, unless TRAINING_SAVE_TO_FILE asks for the file. One
		// or the other, never both: the uploader also reads the file, so both
		// would count every event twice.
		typedef int32_t (*KillchainSubmitFn)(const uint8_t*, uint32_t);
		static KillchainSubmitFn s_fnSubmit = []() -> KillchainSubmitFn {
			HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
			if (!hDll)
				hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
			return hDll ? reinterpret_cast<KillchainSubmitFn>(::GetProcAddress(hDll, "owlyshield_killchain_submit")) : nullptr;
		}();
		if (s_fnSubmit != nullptr && !IsTrainingSaveToFileEnabled())
		{
			s_fnSubmit(reinterpret_cast<const uint8_t*>(sLine.data()), static_cast<uint32_t>(sLine.size()));
			if (nEvents == 1 || nEvents % 1000 == 0)
				LOGINF(FMT("training: handed " << nEvents << " event(s) to the kill chain uploader"));
			return;
		}

		// TRAINING_SAVE_TO_FILE on, or an owlyshield_ransom.dll without the export:
		// the file, which the uploader reads and uploads.
		char szProgramData[MAX_PATH] = "";
		DWORD nLen = ::GetEnvironmentVariableA("PROGRAMDATA", szProgramData, MAX_PATH);
		if (nLen == 0 || nLen >= MAX_PATH)
			return;
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
		stream << sLine << "\n";

		if (nEvents == 1 || nEvents % 100 == 0)
			LOGINF(FMT("training: recorded " << nEvents << " event(s) to training_data"));
	}

	// One scan's result in the kill chain stream, with what Comodo FLS and
	// VirusKov each said. Scan results were only in the stream as the merged
	// verdict stamped on the scanned event, and only for an inline Malicious /
	// Suspicious; queued scans finish after their event is recorded and were
	// never in it. Field names avoid "verdict" / "threat" / "hash": the
	// uploader drops those from an event's shape, so different results would
	// collapse into one record. sha1 keeps each file its own record.
	void RecordScanResultForKillChain(const std::string& sDos, uint32_t nPid, int nResult,
		const DetectionNotifier::CloudScanDetail& detail, const char* szTrigger)
	{
		if (!IsTrainingModeEnabled() || sDos.empty())
			return;
		// The process the scan belongs to (who opened / wrote / ran the file).
		std::string sExe;
		if (nPid > 4)
		{
			HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, nPid);
			if (hProc)
			{
				wchar_t szImage[MAX_PATH * 4] = {};
				DWORD nLen = static_cast<DWORD>(std::size(szImage));
				if (::QueryFullProcessImageNameW(hProc, 0, szImage, &nLen))
				{
					try { sExe = string::convertWCharToUtf8(std::wstring(szImage, nLen)); } catch (...) {}
				}
				::CloseHandle(hProc);
			}
		}
		if (sExe.empty())
			sExe = sDos;
		if (!IsProcessInTrainingDir(sExe))
			return;
		const char* szResult = nResult == 2 ? "Malicious" : nResult == 3 ? "Suspicious" :
			nResult == 1 ? "Clean" : "Unknown";
		const std::string sJson = std::string("{\"type\":\"SCAN_RESULT\",\"trigger\":\"") + szTrigger +
			"\",\"process\":{\"pid\":" + std::to_string(nPid) + "}" +
			",\"file\":{\"path\":\"" + JsonEscapeA(sDos) + "\",\"sha1\":\"" + JsonEscapeA(detail.sSha1) + "\"}" +
			",\"scanResult\":\"" + szResult + "\"" +
			",\"comodoFls\":\"" + JsonEscapeA(detail.sFls.empty() ? "NotAsked" : detail.sFls) + "\"" +
			",\"viruskov\":\"" + JsonEscapeA(detail.sViruskov.empty() ? "NotAsked" : detail.sViruskov) + "\"" +
			",\"viruskovName\":\"" + JsonEscapeA(detail.sViruskovName) + "\"" +
			",\"fromCache\":" + (detail.fFromCache ? "true" : "false") + "}";
		AppendToTrainingDataset(sExe, "SCAN_RESULT", " [File: " + sDos + "]", sJson);
	}

	//
	// Cloud verdict for the owlyshield firewall (owlyshield_ransom.dll runs in this
	// process). The firewall asks it, on its own verification thread, what the
	// clouds say about the executable behind a connection. It is the same scan
	// and cache the enricher uses (FLS first, then VirusKov), so an app edrsvc
	// already scanned is answered from the cache and nothing is asked twice.
	//
	// Returns 1 clean, 2 malicious, 3 suspicious, 0 answered but unknown, -1 no
	// answer yet (cloud unreachable): the firewall does not keep a -1 and asks
	// again. pViruskov receives VirusKov's own word (Clean / Malicious /
	// Suspicious / Unknown / Error; empty when FLS settled it alone).
	//
	static int32_t OwlyshieldCloudVerdictProvider(const wchar_t* pPath, char* pViruskov, uint32_t nViruskovCap)
	{
		if (pViruskov != nullptr && nViruskovCap != 0)
			pViruskov[0] = '\0';
		if (pPath == nullptr || *pPath == L'\0')
			return -1;
		try
		{
			std::string sThreat;
			DetectionNotifier::CloudScanDetail detail;
			const std::string sPath = string::convertWCharToUtf8(pPath);
			int nVerdict = DetectionNotifier::scanFileWithLocalEngines(sPath, sThreat, &detail);
			// Kill chain record like the enricher's own scans. No pid: the file is
			// the connecting app's image, which is what the training-dir check needs.
			RecordScanResultForKillChain(sPath, 0, nVerdict, detail, "firewall");
			if (pViruskov != nullptr && nViruskovCap != 0)
			{
				size_t nLen = (std::min)(detail.sViruskov.size(), size_t(nViruskovCap - 1));
				memcpy(pViruskov, detail.sViruskov.data(), nLen);
				pViruskov[nLen] = '\0';
			}
			if (nVerdict == 1 || nVerdict == 2 || nVerdict == 3)
				return nVerdict;
			// Unknown: an answer only if VirusKov gave one ("Error" = it did not
			// answer; with FLS unknown too, nobody has).
			return detail.sViruskov == "Error" ? -1 : 0;
		}
		catch (...)
		{
			return -1;
		}
	}

	void RegisterOwlyshieldCloudVerdictProvider()
	{
		HMODULE hOwly = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (!hOwly) hOwly = ::LoadLibraryW(L"owlyshield_ransom.dll");
		if (!hOwly)
			return;
		typedef int32_t (*CloudVerdictProviderFn)(const wchar_t*, char*, uint32_t);
		typedef void (*SetCloudVerdictProviderFn)(CloudVerdictProviderFn);
		if (auto fnSet = (SetCloudVerdictProviderFn)::GetProcAddress(hOwly, "owlyshield_set_cloud_verdict_provider"))
			fnSet(&OwlyshieldCloudVerdictProvider);
		else
			LOGLVL(Critical, "owlyshield_ransom.dll has no owlyshield_set_cloud_verdict_provider: the firewall gets no cloud verdicts");
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
	// cache (see FetchModulePdb); one fetch per image, repeats are DbgHelp cache
	// hits. It runs on its own thread. It used to be posted to the enricher's
	// pool, which has exactly one thread - the one that processes every event -
	// so each new process image put a symbol-server download in front of all the
	// events behind it. The pool is never destroyed, so service shutdown does not
	// wait on a download in flight.
	static ThreadPool& PdbPrefetchPool()
	{
		static ThreadPool* s_pPool = []() {
			auto* p = new ThreadPool("PdbPrefetch");
			p->addThreads(1);
			return p;
		}();
		return *s_pPool;
	}

	static void QueuePdbPrefetch(const std::string& sImgPath)
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
		PdbPrefetchPool().run([wsPath]()
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

	extern "C" __declspec(dllexport) uint32_t OwlyCaptureThreadStacks(uint32_t nPid, char* pszOut, uint32_t nMaxLen)
	{
		if (!pszOut || nMaxLen == 0) return 0;
		std::string s = CaptureThreadStacks(nPid);
		if (s.empty()) { pszOut[0] = 0; return 0; }
		uint32_t nCopy = (uint32_t)std::min<size_t>(s.size(), (size_t)(nMaxLen - 1));
		memcpy(pszOut, s.data(), nCopy);
		pszOut[nCopy] = 0;
		return nCopy;
	}

	// Forward enriched event to training dataset / GUI behavior pipe.
	// Uses already-extracted paths from EventEnricher::put so lazy file/process
	// lambda proxies are never triggered here, and avoids duplicating the
	// s_fnEnqueue submission already executed by executeUnfilteredLocalScan.
	static void ForwardToOwlyshieldMlEngine(const Variant& vEvent,
		const std::string& sProcPath,
		const std::string& sFilePath)
	{
		try
		{
			std::string sPath = sProcPath;
			if (!sPath.empty() && sPath.find(":\\") == std::string::npos)
			{
				std::string dosProc = DetectionNotifier::NtPathToDosPathString(sPath);
				if (!dosProc.empty())
					sPath = std::move(dosProc);
			}

			std::string sType = vEvent.get("type", std::string());
			if (sType.empty()) sType = vEvent.get("eventType", std::string());

			if (!sPath.empty() && !sType.empty())
			{
				std::string sDetails;
				// Extract file target from pre-extracted raw path (no lazy proxy evaluation)
				if (!sFilePath.empty())
					sDetails = " [File: " + sFilePath + "]";
				// Extract registry target
				else if (vEvent.has("registry"))
				{
					if (auto optR = variant::getByPathSafe(vEvent, "registry.path"))
						sDetails = " [Reg: " + std::string(optR.value()) + "]";
				}
				// Extract API hook function and module
				else if (vEvent.has("owlyHook"))
				{
					if (auto optA = variant::getByPathSafe(vEvent, "owlyHook.apiFunction"))
					{
						if (auto optM = variant::getByPathSafe(vEvent, "owlyHook.apiModule"))
							sDetails = " [API: " + std::string(optM.value()) + "!" + std::string(optA.value()) + "]";
						else
							sDetails = " [API: " + std::string(optA.value()) + "]";
					}
				}
				// Extract network destination
				else if (vEvent.has("network"))
				{
					if (auto optN = variant::getByPathSafe(vEvent, "network.destinationAddress"))
						sDetails = " [Net: " + std::string(optN.value()) + "]";
				}

				// Offload training serialization/submission and GUI pipe I/O to a
				// background thread so they never stall the enricher queue.
				struct TrainingPipeItem
				{
					bool fDoTraining = false;
					Variant vEvent;
					std::string sPath;
					std::string sType;
					std::string sDetails;
				};
				struct TrainingPipeWorker
				{
					std::mutex mtx;
					std::condition_variable cv;
					std::deque<TrainingPipeItem> queue;
					bool fStop = false;
					std::thread thr;

					TrainingPipeWorker()
					{
						thr = std::thread([this]() { run(); });
					}

					~TrainingPipeWorker()
					{
						{
							std::lock_guard<std::mutex> lk(mtx);
							fStop = true;
						}
						cv.notify_all();
						if (thr.joinable())
							thr.join();
					}

					void push(TrainingPipeItem&& item)
					{
						std::lock_guard<std::mutex> lk(mtx);
						if (queue.size() >= 512)
							queue.pop_front();
						queue.push_back(std::move(item));
						cv.notify_one();
					}

					void run()
					{
						HANDLE hPipe = INVALID_HANDLE_VALUE;
						while (true)
						{
							TrainingPipeItem item;
							{
								std::unique_lock<std::mutex> lk(mtx);
								cv.wait(lk, [this]() { return fStop || !queue.empty(); });
								if (fStop && queue.empty())
									break;
								item = std::move(queue.front());
								queue.pop_front();
							}

							if (item.fDoTraining)
							{
								try
								{
									std::string sJson = variant::serializeToJson(item.vEvent, variant::JsonFormat::SingleLine);
									AppendToTrainingDataset(item.sPath, item.sType, item.sDetails, sJson);
								}
								catch (...) {}
							}

							if (hPipe == INVALID_HANDLE_VALUE)
							{
								hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
									GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
							}
							if (hPipe != INVALID_HANDLE_VALUE)
							{
								std::string pipeMsg = "BEHAVIOR_EVENT:" + item.sPath + "|" + item.sType + item.sDetails + "\n";
								DWORD written = 0;
								if (!::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL))
								{
									::CloseHandle(hPipe);
									hPipe = INVALID_HANDLE_VALUE;
								}
							}
						}
						if (hPipe != INVALID_HANDLE_VALUE)
							::CloseHandle(hPipe);
					}
				};
				static TrainingPipeWorker s_worker;

				const bool fDoTraining = IsTrainingModeEnabled() && IsProcessInTrainingDir(sPath) && IsApiDllInTrainingWatchDir(vEvent);
				TrainingPipeItem item;
				item.fDoTraining = fDoTraining;
				if (fDoTraining)
					item.vEvent = vEvent.clone();
				item.sPath = std::move(sPath);
				item.sType = std::move(sType);
				item.sDetails = std::move(sDetails);
				s_worker.push(std::move(item));
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

	// ------------------------------------------------------------------
	// Process lineage for rollback scoping ("taint").
	//
	// Rollback used to undo every recorded change of EVERY process, so a
	// detection rolled back unrelated software (Edge WebView's own update,
	// system logs). Rolling back only the detected PID is no better: the
	// threat simply works through other processes. So a detection taints
	// its process and, transitively:
	//  - every process it created. The creator is the driver's creator PID
	//    when it differs from the parent (PPID spoofing sets only the parent);
	//  - every process it opened with thread-creation / memory-write access
	//    or hooked with a remote-write / remote-thread API, from that moment;
	// and only changes made after a process was tainted are undone. Records
	// of exited processes are kept (c_nDeadKeepMs) so a child that did its
	// work and exited is still rolled back.
	// All of this is guarded by s_mtxRansomShield.
	// ------------------------------------------------------------------
	namespace Lineage
	{
		struct Proc
		{
			int64_t nPid = 0;
			int64_t nCreator = 0;
			uint64_t nCreateTick = 0; // 0 = started before it was seen
			uint64_t nExitTick = 0;   // 0 = alive
			std::vector<std::pair<int64_t, uint64_t>> vInjectors; // (source pid, tick)
		};

		struct Dead
		{
			Proc proc;
			std::vector<EventEnricher::ShadowBackupEntry> vBackups;
			std::unordered_map<std::wstring, std::wstring> mReads;
		};

		std::unordered_map<int64_t, Proc> s_live;
		std::deque<Dead> s_dead;
		constexpr uint64_t c_nDeadKeepMs = 5ull * 60 * 1000;
		constexpr size_t c_nMaxDead = 1024;
		constexpr size_t c_nMaxInjectorsPerProc = 64;

		Proc& liveProc(int64_t nPid)
		{
			Proc& p = s_live[nPid];
			p.nPid = nPid;
			return p;
		}

		bool aliveAt(const Proc& p, uint64_t nTick)
		{
			return (p.nCreateTick == 0 || p.nCreateTick <= nTick) &&
				(p.nExitTick == 0 || p.nExitTick >= nTick);
		}

		// Moves a process' lineage and recorded changes to the exited list.
		void retireLocked(int64_t nPid, uint64_t nTick)
		{
			Dead d;
			auto it = s_live.find(nPid);
			if (it != s_live.end())
			{
				d.proc = std::move(it->second);
				s_live.erase(it);
			}
			d.proc.nPid = nPid;
			d.proc.nExitTick = nTick != 0 ? nTick : 1;
			auto itB = s_backups.find(nPid);
			if (itB != s_backups.end())
			{
				d.vBackups = std::move(itB->second);
				s_backups.erase(itB);
			}
			auto itR = s_readFiles.find(nPid);
			if (itR != s_readFiles.end())
			{
				d.mReads = std::move(itR->second);
				s_readFiles.erase(itR);
			}
			s_dead.push_back(std::move(d));
			while (!s_dead.empty() && (s_dead.size() > c_nMaxDead ||
				(nTick > c_nDeadKeepMs && s_dead.front().proc.nExitTick + c_nDeadKeepMs < nTick)))
				s_dead.pop_front();
		}
	} // namespace Lineage

	// Records creator / injection relations from the raw driver event.
	void ObserveLineage(Event eEventType, const Variant& vEvent)
	{
		try
		{
			const uint64_t nTick = getByPath(vEvent, "tickTime", uint64_t(0));
			auto addInjector = [nTick](int64_t nSrc, int64_t nTgt) {
				if (nSrc <= 4 || nTgt <= 4 || nSrc == nTgt)
					return;
				std::scoped_lock _lock(s_mtxRansomShield);
				auto& v = Lineage::liveProc(nTgt).vInjectors;
				for (const auto& inj : v)
					if (inj.first == nSrc)
						return; // the first contact counts
				if (v.size() < Lineage::c_nMaxInjectorsPerProc)
					v.emplace_back(nSrc, nTick);
			};

			switch (eEventType)
			{
			case Event::LLE_PROCESS_CREATE:
			{
				const int64_t nPid = getByPath(vEvent, "process.pid", int64_t(0));
				if (nPid <= 0)
					return;
				int64_t nCreator = getByPath(vEvent, "process.creatorPid", int64_t(0));
				if (nCreator <= 0)
					nCreator = getByPath(vEvent, "process.parent.pid", int64_t(0));
				std::scoped_lock _lock(s_mtxRansomShield);
				auto it = Lineage::s_live.find(nPid);
				if (it != Lineage::s_live.end() && it->second.nCreateTick != 0)
					Lineage::retireLocked(nPid, nTick); // stale record of an earlier process with this PID
				Lineage::Proc& p = Lineage::liveProc(nPid);
				p.nCreator = nCreator;
				p.nCreateTick = nTick;
				return;
			}
			case Event::LLE_PROCESS_OPEN:
			{
				// PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
				const uint32_t nAccess = getByPath(vEvent, "accessMask", uint32_t(0));
				if ((nAccess & (0x0002 | 0x0008 | 0x0020)) == 0)
					return;
				addInjector(getByPath(vEvent, "process.pid", int64_t(0)), getByPath(vEvent, "target.pid", int64_t(0)));
				return;
			}
			case Event::LLE_PROCESS_MEMORY_WRITE:
				addInjector(getByPath(vEvent, "process.pid", int64_t(0)), getByPath(vEvent, "target.pid", int64_t(0)));
				return;
			default:
				break;
			}

			if (vEvent.has("owlyHook"))
			{
				std::wstring wsFn = string::convertToLow(getByPath(vEvent, "owlyHook.functionName", std::wstring()));
				if (wsFn.find(L"writeprocessmemory") != std::wstring::npos ||
					wsFn.find(L"createremotethread") != std::wstring::npos ||
					wsFn.find(L"ntcreatethreadex") != std::wstring::npos ||
					wsFn.find(L"virtualallocex") != std::wstring::npos)
				{
					addInjector(getByPath(vEvent, "owlyHook.sourcePid", int64_t(0)),
						getByPath(vEvent, "owlyHook.targetPid", int64_t(0)));
				}
			}
		}
		catch (...)
		{
		}
	}

	// Takes the recorded changes of every process tainted by nRoot (see
	// Lineage) that were made after it was tainted, oldest first, out of the
	// records. Changes of other processes stay recorded. Lock held.
	void CollectTaintedChangesLocked(int64_t nRoot, std::vector<EventEnricher::ShadowBackupEntry>& vOut,
		std::unordered_map<std::wstring, std::wstring>& mReadsOut, std::vector<int64_t>& vPidsOut)
	{
		struct Node
		{
			const Lineage::Proc* p = nullptr;
			std::vector<EventEnricher::ShadowBackupEntry>* pBackups = nullptr;
			std::unordered_map<std::wstring, std::wstring>* pReads = nullptr;
			uint64_t nFrom = UINT64_MAX; // tainted from this tick; MAX = not tainted
		};
		std::vector<Node> nodes;
		std::deque<Lineage::Proc> tmpProcs; // live PIDs with changes but no lineage record

		std::unordered_set<int64_t> livePids;
		for (const auto& kv : Lineage::s_live)
			livePids.insert(kv.first);
		for (const auto& kv : s_backups)
			livePids.insert(kv.first);
		for (int64_t nPid : livePids)
		{
			Node n;
			auto itL = Lineage::s_live.find(nPid);
			if (itL != Lineage::s_live.end())
				n.p = &itL->second;
			else
			{
				tmpProcs.emplace_back();
				tmpProcs.back().nPid = nPid;
				n.p = &tmpProcs.back();
			}
			auto itB = s_backups.find(nPid);
			if (itB != s_backups.end())
				n.pBackups = &itB->second;
			auto itR = s_readFiles.find(nPid);
			if (itR != s_readFiles.end())
				n.pReads = &itR->second;
			nodes.push_back(n);
		}
		const size_t nLive = nodes.size();
		for (auto& d : Lineage::s_dead)
		{
			Node n;
			n.p = &d.proc;
			n.pBackups = &d.vBackups;
			n.pReads = &d.mReads;
			nodes.push_back(n);
		}

		// Root: the live process with this PID, else the latest exited one.
		size_t iRoot = SIZE_MAX;
		for (size_t i = 0; i < nLive; ++i)
			if (nodes[i].p->nPid == nRoot)
				iRoot = i;
		for (size_t i = nodes.size(); iRoot == SIZE_MAX && i > nLive; --i)
			if (nodes[i - 1].p->nPid == nRoot)
				iRoot = i - 1;
		if (iRoot == SIZE_MAX)
			return;
		nodes[iRoot].nFrom = 0; // everything the threat's own process did

		std::unordered_map<int64_t, std::vector<size_t>> byPid;
		for (size_t i = 0; i < nodes.size(); ++i)
			byPid[nodes[i].p->nPid].push_back(i);

		for (int nPass = 0; nPass < 64; ++nPass)
		{
			bool fChanged = false;
			for (size_t j = 0; j < nodes.size(); ++j)
			{
				const Lineage::Proc& pj = *nodes[j].p;
				uint64_t nCand = nodes[j].nFrom;
				if (pj.nCreator > 0)
				{
					auto it = byPid.find(pj.nCreator);
					if (it != byPid.end())
						for (size_t i : it->second)
							if (i != j && nodes[i].nFrom != UINT64_MAX && nodes[i].nFrom <= pj.nCreateTick &&
								Lineage::aliveAt(*nodes[i].p, pj.nCreateTick))
								nCand = (std::min)(nCand, pj.nCreateTick);
				}
				for (const auto& inj : pj.vInjectors)
				{
					auto it = byPid.find(inj.first);
					if (it == byPid.end())
						continue;
					for (size_t i : it->second)
						if (i != j && nodes[i].nFrom != UINT64_MAX && nodes[i].nFrom <= inj.second &&
							Lineage::aliveAt(*nodes[i].p, inj.second))
							nCand = (std::min)(nCand, inj.second);
				}
				if (nCand < nodes[j].nFrom)
				{
					nodes[j].nFrom = nCand;
					fChanged = true;
				}
			}
			if (!fChanged)
				break;
		}

		for (auto& n : nodes)
		{
			if (n.nFrom == UINT64_MAX)
				continue;
			vPidsOut.push_back(n.p->nPid);
			if (n.pReads)
				mReadsOut.insert(n.pReads->begin(), n.pReads->end());
			if (!n.pBackups)
				continue;
			std::vector<EventEnricher::ShadowBackupEntry> vKeep;
			for (auto& e : *n.pBackups)
			{
				if (e.nTick >= n.nFrom)
					vOut.push_back(std::move(e));
				else
					vKeep.push_back(std::move(e));
			}
			*n.pBackups = std::move(vKeep);
		}
		std::stable_sort(vOut.begin(), vOut.end(),
			[](const EventEnricher::ShadowBackupEntry& a, const EventEnricher::ShadowBackupEntry& b) { return a.nTick < b.nTick; });
	}
}

static void recordShadowBackupImpl(int64_t nPid, Event eEventType, const Variant& vEvent,
	const std::wstring* pWsRawFilePath, const std::wstring* pWsRawRenameTarget,
	const std::wstring* pWsRawBackupPath, int64_t nRawCreationStatus, bool fHasRawFileInfo)
{
	if (nPid <= 0)
		return;

	switch (eEventType)
	{
	case Event::LLE_PROCESS_DELETE:
	{
		uint64_t nTick = 0;
		try { nTick = getByPath(vEvent, "tickTime", uint64_t(0)); } catch (...) {}
		// Kept (with its lineage) for a while instead of dropped, so a
		// process that made its changes and exited is still rolled back
		// when the process that started it is convicted.
		std::scoped_lock _lock(s_mtxRansomShield);
		Lineage::retireLocked(nPid, nTick);
		return;
	}
	case Event::LLE_FILE_CREATE:
		if (fHasRawFileInfo && nRawCreationStatus != 1 && nRawCreationStatus != 3)
			return;
		break;
	case Event::LLE_FILE_DATA_READ_FULL:
	case Event::LLE_FILE_MAP_READ:
	case Event::LLE_FILE_PREIMAGE_SAVED:
	case Event::LLE_FILE_DATA_WRITE_FULL:
	case Event::LLE_FILE_DATA_CHANGE:
	case Event::LLE_FILE_MAP_WRITE:
	case Event::LLE_FILE_DELETE:
	case Event::LLE_FILE_RENAME:
		break;
	default:
		return;
	}

	uint64_t nTick = 0;
	try
	{
		nTick = getByPath(vEvent, "tickTime", uint64_t(0));
	}
	catch (...) {}

	std::wstring wsFilePath;
	std::wstring wsNewName;
	std::wstring wsBkInEvent;
	int64_t nCreationStatus = nRawCreationStatus;
	if (fHasRawFileInfo)
	{
		if (pWsRawFilePath && !pWsRawFilePath->empty())
			wsFilePath = NormalizeToDosPath(*pWsRawFilePath);
		if (!wsFilePath.empty() && pWsRawRenameTarget && !pWsRawRenameTarget->empty())
			wsNewName = ResolveRenameTargetPathW(wsFilePath, *pWsRawRenameTarget);
		if (pWsRawBackupPath && !pWsRawBackupPath->empty())
			wsBkInEvent = *pWsRawBackupPath;
	}
	else
	{
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
			wsBkInEvent = vFile.get("backupPath", L"");
			if (eEventType == Event::LLE_FILE_CREATE)
				nCreationStatus = vFile.get("creationStatus", int64_t(0));
		}
		catch (...)
		{
			return;
		}
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
			if (!wsBkInEvent.empty())
				wsBk = NormalizeToDosPath(wsBkInEvent);
			if (!wsBk.empty())
			{
				if (s_allPreImages.size() >= 4096)
				{
					auto it = s_allPreImages.begin();
					for (size_t i = 0; i < 2048 && it != s_allPreImages.end(); ++i)
						it = s_allPreImages.erase(it);
				}
				s_allPreImages[wsFilePath] = wsBk;
			}
			if (readMap.size() < 512 || readMap.count(wsFilePath))
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
			if (eEventType == Event::LLE_FILE_CREATE && nCreationStatus != 1 && nCreationStatus != 3)
				break;
			ZeroTrust::onProcessFileModification(static_cast<uint32_t>(nPid), string::convertWCharToUtf8(wsFilePath));
			constexpr size_t c_nMaxBackupsPerProcess = 256;
			auto& vec = s_backups[nPid];
			if (vec.size() < c_nMaxBackupsPerProcess)
			{
				EventEnricher::ShadowBackupEntry entry;
				entry.wsOriginal = wsFilePath;
				entry.nTick = nTick;
				entry.nOp = (eEventType == Event::LLE_FILE_CREATE) ? (nCreationStatus == 1 ? 3 : 0) :
					(eEventType == Event::LLE_FILE_DATA_WRITE_FULL ||
					 eEventType == Event::LLE_FILE_DATA_CHANGE ||
					 eEventType == Event::LLE_FILE_MAP_WRITE) ? 0 :
					(eEventType == Event::LLE_FILE_DELETE) ? 1 : 2;
				entry.wsNewName = wsNewName;

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

void EventEnricher::recordShadowBackup(int64_t nPid, Event eEventType, const Variant& vEvent)
{
	recordShadowBackupImpl(nPid, eEventType, vEvent, nullptr, nullptr, nullptr, 0, false);
}

void EventEnricher::handleThreatRemediation(int64_t nPid, const std::wstring& /* sImage */, const std::string& sThreatName)
{
	if (nPid <= 0)
		return;

	LOGLVL(Critical, FMT("ThreatRemediation: executing complete rollback & kill for pid="
		<< nPid << " threat=" << sThreatName));

	// 1. File rollback from pre-images
	rollbackRansomBackups(nPid);

	// Notify GUI that system remediation has executed
	HANDLE hPipeClean = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipeClean != INVALID_HANDLE_VALUE)
	{
		std::string pipeMsg = "SYSTEM_CLEANED_NOTICE:REMEDIATED\n";
		DWORD written = 0;
		::WriteFile(hPipeClean, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
		::CloseHandle(hPipeClean);
	}
}

namespace {

// Terminates every running process whose image is sDos and waits briefly for
// each to exit, so the image is no longer locked when it is quarantined. A
// convicted file was only ever quarantined: a running image cannot be moved or
// deleted, so the quarantine failed and the program (dControl, which also
// relaunches itself elevated under a new PID) kept running. Matched by full
// image path, never by name alone, and never this service or System.
static void SendThreatAlertToGuiEarly(const std::string& sThreat, const std::string& sWhere)
{
	HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
		return;
	std::string pipeMsg = "THREAT_ALERT:" + sThreat + "|" + sWhere + "\n";
	DWORD written = 0;
	::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
	::CloseHandle(hPipe);
}

static int TerminateProcessesRunningImage(const std::string& sDos, std::vector<uint32_t>* pKilled = nullptr)
{
	if (sDos.empty())
		return 0;
	std::wstring wsTarget;
	try
	{
		wsTarget = string::convertToLow(Widen(sDos));
	}
	catch (...)
	{
		return 0;
	}
	const size_t nSlash = wsTarget.find_last_of(L"\\/");
	const std::wstring wsTargetName = nSlash == std::wstring::npos ? wsTarget : wsTarget.substr(nSlash + 1);

	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return 0;
	int nKilled = 0;
	const DWORD nSelf = ::GetCurrentProcessId();
	PROCESSENTRY32W pe = {};
	pe.dwSize = sizeof(pe);
	for (BOOL fOk = ::Process32FirstW(hSnap, &pe); fOk; fOk = ::Process32NextW(hSnap, &pe))
	{
		if (pe.th32ProcessID <= 4 || pe.th32ProcessID == nSelf)
			continue;
		// The snapshot name is the image's file name; the full path decides.
		if (string::convertToLow(std::wstring(pe.szExeFile)) != wsTargetName)
			continue;
		HANDLE hProc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
			FALSE, pe.th32ProcessID);
		if (!hProc)
			continue;
		wchar_t szImage[MAX_PATH * 4] = {};
		DWORD nLen = static_cast<DWORD>(std::size(szImage));
		BOOL fCritical = FALSE;
		if (::QueryFullProcessImageNameW(hProc, 0, szImage, &nLen) &&
			string::convertToLow(std::wstring(szImage, nLen)) == wsTarget)
		{
			// A critical process takes the system down with it (bugcheck);
			// a false positive on one must never become a crash.
			typedef BOOL(WINAPI * IsProcessCriticalFn)(HANDLE, PBOOL);
			static const auto s_fnIsCritical = reinterpret_cast<IsProcessCriticalFn>(
				::GetProcAddress(::GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
			if (s_fnIsCritical && s_fnIsCritical(hProc, &fCritical) && fCritical)
				LOGLVL(Critical, FMT("enricher: not terminating critical PID " << pe.th32ProcessID << " running <" << sDos << ">"));
			else if (::TerminateProcess(hProc, 1))
			{
				::WaitForSingleObject(hProc, 3000);
				++nKilled;
				if (pKilled)
					pKilled->push_back(pe.th32ProcessID);
				LOGLVL(Critical, FMT("enricher: terminated PID " << pe.th32ProcessID << " running convicted image <" << sDos << ">"));
			}
			else
				LOGLVL(Critical, FMT("enricher: could not terminate PID " << pe.th32ProcessID << " running <" << sDos
					<< "> error=" << ::GetLastError()));
		}
		::CloseHandle(hProc);
	}
	::CloseHandle(hSnap);
	return nKilled;
}

// Rescan OFF the hot path: the enricher worker is single-threaded, so it must
// never sleep or scan a file that is still being written. Deferred file events
// (FileDataChange / FileDataWriteFull / a PROCESS_CREATE whose FLS answer came
// late) are queued here and scanned by a fixed set of workers once the writer
// has had time to finish, then convicted exactly like the sync path.
//
// Nothing is dropped. This used to start a detached thread per file with at
// most 4 at a time and simply return when all 4 were busy, and it skipped any
// path seen in the last 10 s. Under file churn (browsers write thousands of
// .tmp / LevelDB files a minute) the slots were always busy, so a dropped file
// got no scan at all, and new content written to a path within 10 s of the
// last look was never scanned. Now:
//  - a path waits in the queue until a worker takes it (one entry per path;
//    it is scanned with whatever content it has by then);
//  - a path is skipped only when it was scanned within the last minute with
//    the same size and last-write time, i.e. the same content;
//  - a scan that gets no verdict (cloud timeout or unreachable, file locked)
//    is tried again later instead of being the last look. A file the cloud
//    was slow to answer for (FLS/VirusKov past their wait) used to get exactly
//    one more try 350 ms later and was then never looked at again.
namespace RescanQueue {

// Delays before each further try of an undecided scan (cloud answers that
// arrive late are cached by both clients, so a later try reads them).
static const std::chrono::milliseconds c_retryDelays[] = {
	std::chrono::milliseconds(500), std::chrono::milliseconds(1000), std::chrono::milliseconds(2000),
	std::chrono::milliseconds(3000), std::chrono::milliseconds(5000), std::chrono::milliseconds(10000) };

// Checks of a file written through a mapped section (LLE_FILE_MAP_WRITE). The
// event comes when the section is created, before anything is written, and
// the data reaches the disk later through paging I/O, which raises no
// FileDataChange. The file is looked at again after each delay and scanned
// whenever its size or last-write time changed since the last look.
static const std::chrono::seconds c_watchDelays[] = {
	std::chrono::seconds(2), std::chrono::seconds(5), std::chrono::seconds(15), std::chrono::seconds(30),
	std::chrono::seconds(60), std::chrono::seconds(120), std::chrono::seconds(300) };

constexpr int c_nWorkers = 4;
constexpr auto c_sameContentWindow = std::chrono::seconds(60);
constexpr size_t c_nWarnPending = 100000;

struct Item
{
	std::string sKey;
	std::string sDos;
	uint32_t nPid = 0;
	std::chrono::steady_clock::time_point due;
	size_t nAttempt = 0; // 0 = first look; >0 = retry of an undecided scan
	bool fWatch = false; // mapped-write content watch (see c_watchDelays)
	uint64_t nSeenSize = 0;
	uint64_t nSeenMtime = 0;
};

struct Scanned
{
	uint64_t nSize = 0;
	uint64_t nMtime = 0;
	std::chrono::steady_clock::time_point at;
};

struct State
{
	std::mutex mtx;
	std::condition_variable cv;
	std::deque<Item> queue;
	std::unordered_set<std::string> pending;
	std::unordered_map<std::string, Scanned> scanned;
	std::multimap<std::chrono::steady_clock::time_point, Item> delayed; // retries, watches
	std::unordered_set<std::string> watching; // paths with a watch chain
	std::condition_variable cvDelayed;
	std::chrono::steady_clock::time_point lastWarn;
	bool fStarted = false;
};

// Never destroyed: workers are detached and may still be running at exit.
static State& state()
{
	static State* s_p = new State();
	return *s_p;
}

static std::string toKey(const std::string& sDos)
{
	std::string key = sDos;
	for (auto& c : key)
		c = (char)::tolower((unsigned char)c);
	return key;
}

static bool fileIdentity(const std::string& sDos, uint64_t& nSize, uint64_t& nMtime)
{
	WIN32_FILE_ATTRIBUTE_DATA fad = {};
	if (!::GetFileAttributesExW(Widen(sDos).c_str(), GetFileExInfoStandard, &fad))
		return false;
	nSize = (uint64_t(fad.nFileSizeHigh) << 32) | fad.nFileSizeLow;
	nMtime = (uint64_t(fad.ftLastWriteTime.dwHighDateTime) << 32) | fad.ftLastWriteTime.dwLowDateTime;
	return true;
}

static void forgetScanned(const std::string& sDos)
{
	auto& st = state();
	std::scoped_lock lock(st.mtx);
	st.scanned.erase(toKey(sDos));
}

// True when the scan reached a verdict (or there is nothing left to scan);
// false when it should be tried again later.
static bool rescanOne(const std::string& dos, uint32_t nPid)
{
	if (dos.empty())
		return true;
	// Nothing on disk: already quarantined (sync path, or an earlier rescan).
	if (::GetFileAttributesW(Widen(dos).c_str()) == INVALID_FILE_ATTRIBUTES)
		return true;

	// A blacklisted path holding a file again is the malware coming back.
	// This used to return early ("sync path already handled it"), so a
	// re-dropped file at a known path was never quarantined again. It is
	// now convicted unless the engines positively vouch for the new content
	// (Clean = FLS clean / trusted signer), whatever its hash is.
	const bool bKnownPath = DetectionNotifier::isKnownMalware(dos, "");
	if (bKnownPath && DetectionNotifier::isProtectionPaused())
		return true; // training: keep the sample, and don't re-alert every event
	std::string sThreat;
	DetectionNotifier::CloudScanDetail detail;
	const int nScan = DetectionNotifier::scanFileWithLocalEngines(dos, sThreat, &detail);
	RecordScanResultForKillChain(dos, nPid, nScan, detail, "queued");
	const int nClean = DetectionNotifier::s_cleanVerdict.load(std::memory_order_relaxed);
	if (bKnownPath)
	{
		if (nScan == nClean)
		{
			LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] blacklisted path <" << dos
				<< "> now holds clean content (" << sThreat << "); not quarantining"));
			return true;
		}
		if ((nScan != 2 && nScan != 3) || sThreat.empty())
			sThreat = "Blacklist.KnownMalwarePath";
	}
	// Suspicious (3) goes on like Malicious, as on the sync path.
	else if (nScan != 2 && nScan != 3)
	{
		// Already confirmed Clean (e.g. Comodo FLS Safe) - finish immediately
		// without looping even if VirusKov timed out (Deferred).
		if (nScan == nClean)
			return true;
		if (DriverPortHips::s_configuredTrustMode.load(std::memory_order_relaxed) != 1 && detail.sViruskov == "Deferred")
			return false;
		// Decided when VirusKov answered "unknown" (it looked and cannot tell;
		// asking again gets the same answer). Only a scan that got no answer
		// (deferred: connection error, timeout, locked file) is tried again.
		return detail.sViruskov == "Unknown";
	}
	if (sThreat.empty())
		sThreat = "Malware.LocalDetection";

	LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] THREAT DETECTED: <"
		<< sThreat << "> on <" << dos << "> (PID: " << nPid << ")"));

	if (!DetectionNotifier::isProtectionPaused())
	{
		// Stop whatever runs this image first: a running image is locked and
		// its quarantine fails.
		std::vector<uint32_t> vKilled;
		const int nKilled = TerminateProcessesRunningImage(dos, &vKilled);
		// Undo what those processes (and the ones they tainted) changed.
		for (uint32_t nKilledPid : vKilled)
			EventEnricher::rollbackRansomBackups(nKilledPid);

		HMODULE hDll = ::GetModuleHandleW(L"owlyshield_ransom.dll");
		if (!hDll)
			hDll = ::LoadLibraryW(L"owlyshield_ransom.dll");
		if (hDll)
		{
			typedef int32_t (*QuarantineFn)(const uint8_t*, uint32_t);
			auto fnQ = (QuarantineFn)::GetProcAddress(hDll, "owlyshield_dll_quarantine_file");
			if (fnQ != nullptr)
			{
				int32_t qRes = -1;
				// The image stays mapped for a moment after its last process
				// exits; try again briefly before giving up.
				for (int nTry = 0; nTry < (nKilled > 0 ? 5 : 1); ++nTry)
				{
					if (nTry > 0)
						std::this_thread::sleep_for(std::chrono::milliseconds(400));
					qRes = fnQ(reinterpret_cast<const uint8_t*>(dos.data()), static_cast<uint32_t>(dos.size()));
					if (qRes == 0)
						break;
				}
				if (qRes == 0)
				{
					LOGLVL(Critical, FMT("enricher: [ASYNC RESCAN] quarantined <" << dos << ">"));
					// The path is empty now; a re-drop must be scanned even
					// if it has the same size and time stamp.
					RescanQueue::forgetScanned(dos);
				}
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
	return true;
}

// Moves retries that are due back into the work queue.
static void retryPump()
{
	auto& st = state();
	std::unique_lock lock(st.mtx);
	for (;;)
	{
		if (st.delayed.empty())
		{
			st.cvDelayed.wait(lock);
			continue;
		}
		const auto due = st.delayed.begin()->first;
		if (std::chrono::steady_clock::now() < due)
		{
			st.cvDelayed.wait_until(lock, due);
			continue;
		}
		Item item = std::move(st.delayed.begin()->second);
		st.delayed.erase(st.delayed.begin());
		if (item.fWatch)
		{
			// File attributes are read without the lock.
			lock.unlock();
			uint64_t nSize = 0, nMtime = 0;
			const bool fHasId = fileIdentity(item.sDos, nSize, nMtime);
			lock.lock();
			if (!fHasId)
			{
				st.watching.erase(item.sKey); // gone: quarantined or deleted
				continue;
			}
			if (nSize != item.nSeenSize || nMtime != item.nSeenMtime)
			{
				item.nSeenSize = nSize;
				item.nSeenMtime = nMtime;
				if (st.pending.insert(item.sKey).second)
				{
					Item scan{ item.sKey, item.sDos, item.nPid, std::chrono::steady_clock::now() };
					st.queue.push_back(std::move(scan));
					st.cv.notify_one();
				}
			}
			if (item.nAttempt >= std::size(c_watchDelays))
			{
				st.watching.erase(item.sKey);
				continue;
			}
			const auto next = std::chrono::steady_clock::now() + c_watchDelays[item.nAttempt];
			++item.nAttempt;
			st.delayed.emplace(next, std::move(item));
			continue;
		}
		if (!st.pending.insert(item.sKey).second)
			continue; // a new event already queued this path
		item.due = std::chrono::steady_clock::now();
		st.queue.push_back(std::move(item));
		st.cv.notify_one();
	}
}

static void scheduleRetry(Item item)
{
	if (item.nAttempt >= std::size(c_retryDelays))
	{
		LOGWRN(FMT("enricher: [ASYNC RESCAN] still no verdict for <" << item.sDos << "> after "
			<< item.nAttempt << " retries; it is scanned again on its next event"));
		return;
	}
	const auto delay = c_retryDelays[item.nAttempt];
	++item.nAttempt;
	LOGLVL(Detailed, FMT("enricher: [ASYNC RESCAN] no verdict yet for <" << item.sDos << ">; try "
		<< item.nAttempt << " in " << delay.count() << " ms"));
	auto& st = state();
	{
		std::scoped_lock lock(st.mtx);
		const auto due = std::chrono::steady_clock::now() + delay;
		st.delayed.emplace(due, std::move(item));
	}
	st.cvDelayed.notify_one();
}

static void worker()
{
	auto& st = state();
	for (;;)
	{
		Item item;
		{
			std::unique_lock lock(st.mtx);
			st.cv.wait(lock, [&st] { return !st.queue.empty(); });
			item = std::move(st.queue.front());
			st.queue.pop_front();
		}
		// Items are queued in time order, so the head is always the next due.
		std::this_thread::sleep_until(item.due);

		uint64_t nSize = 0, nMtime = 0;
		const bool fHasId = fileIdentity(item.sDos, nSize, nMtime);
		{
			std::scoped_lock lock(st.mtx);
			// Released before the scan: a write that lands during the scan
			// queues the path again instead of being folded into this look.
			st.pending.erase(item.sKey);
			if (fHasId)
			{
				const auto now = std::chrono::steady_clock::now();
				auto it = st.scanned.find(item.sKey);
				if (item.nAttempt == 0 && it != st.scanned.end() && it->second.nSize == nSize &&
					it->second.nMtime == nMtime && now - it->second.at < c_sameContentWindow)
					continue; // same content, already scanned
				if (st.scanned.size() > 50000)
				{
					for (auto itC = st.scanned.begin(); itC != st.scanned.end(); )
					{
						if (now - itC->second.at >= c_sameContentWindow)
							itC = st.scanned.erase(itC);
						else
							++itC;
					}
				}
				st.scanned[item.sKey] = Scanned{ nSize, nMtime, now };
			}
		}
		if (!fHasId)
			continue; // gone: quarantined already, or a temp file deleted

		bool fDecided = true;
		try
		{
			fDecided = rescanOne(item.sDos, item.nPid);
		}
		catch (...)
		{
		}
		if (!fDecided)
			scheduleRetry(std::move(item));
	}
}

static void enqueue(std::string dos, uint32_t nPid, bool fHighPriority = false)
{
	if (dos.empty())
		return;
	auto& st = state();
	std::string key = toKey(dos);
	bool fWarn = false;
	size_t nPending = 0;
	{
		std::scoped_lock lock(st.mtx);
		if (!st.fStarted)
		{
			st.fStarted = true;
			for (int i = 0; i < c_nWorkers; ++i)
				std::thread(worker).detach();
			std::thread(retryPump).detach();
		}
		if (!st.pending.insert(key).second)
		{
			if (fHighPriority)
			{
				for (auto it = st.queue.begin(); it != st.queue.end(); ++it)
				{
					if (it->sKey == key)
					{
						if (it != st.queue.begin())
						{
							Item promoted = std::move(*it);
							st.queue.erase(it);
							promoted.due = std::chrono::steady_clock::now();
							st.queue.push_front(std::move(promoted));
							st.cv.notify_one();
						}
						break;
					}
				}
			}
			return; // already waiting; it is scanned with its latest content
		}
		const auto now = std::chrono::steady_clock::now();
		// No wait before the scan: a file still being written raises
		// FileDataChange / WriteFull again at its handle cleanup and is
		// queued again with its final content.
		Item item{ std::move(key), std::move(dos), nPid, now };
		if (fHighPriority)
			st.queue.push_front(std::move(item));
		else
			st.queue.push_back(std::move(item));
		nPending = st.queue.size();
		if (nPending >= c_nWarnPending && now - st.lastWarn > std::chrono::seconds(60))
		{
			st.lastWarn = now;
			fWarn = true;
		}
	}
	st.cv.notify_one();
	if (fWarn)
		LOGWRN(FMT("enricher: rescan queue is long (" << nPending << " paths waiting); files are scanned late, none are dropped"));
}

// A mapped-write target: one look now (like any deferred file event), then a
// watch that scans it again each time its content changes. One watch per path;
// a new mapping of a path already watched only gets the look.
static void enqueueWatch(std::string dos, uint32_t nPid)
{
	if (dos.empty())
		return;
	enqueue(dos, nPid);
	auto& st = state();
	std::string key = toKey(dos);
	uint64_t nSize = 0, nMtime = 0;
	fileIdentity(dos, nSize, nMtime);
	{
		std::scoped_lock lock(st.mtx);
		if (!st.watching.insert(key).second)
			return;
		Item watch{ key, std::move(dos), nPid, {} };
		watch.fWatch = true;
		watch.nSeenSize = nSize;
		watch.nSeenMtime = nMtime;
		watch.nAttempt = 1;
		st.delayed.emplace(std::chrono::steady_clock::now() + c_watchDelays[0], std::move(watch));
	}
	st.cvDelayed.notify_one();
}

} // namespace RescanQueue

static void AsyncRescanAndQuarantine(std::string dos, uint32_t nPid, bool fHighPriority)
{
	RescanQueue::enqueue(std::move(dos), nPid, fHighPriority);
}

static void SendThreatAlertToGui(const std::string& sThreat, const std::string& sWhere)
{
	HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
		GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hPipe == INVALID_HANDLE_VALUE)
		return;
	std::string pipeMsg = "THREAT_ALERT:" + sThreat + "|" + sWhere + "\n";
	DWORD written = 0;
	::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
	::CloseHandle(hPipe);
}

// Command-line scans of new processes on their own workers. The scan goes
// through openedr_static_scan_bytes, which in the shipped engine
// (openedr_cloud.dll) is a cloud request - inline it would put a network round
// trip on the single enricher thread for every process start.
//
// The engines get a virtual file name with the image's script extension from
// scanner.cmdlineScanNames so script rules apply (powershell -> .ps1, cmd ->
// .cmd, wscript/cscript -> .vbs, mshta -> .hta ...).
// Malicious: that process is terminated. Its image is NOT quarantined or
// blacklisted - for a command-line hit it is usually a system binary
// (powershell.exe, mshta.exe) and the threat is the arguments. The process
// handle is opened when the scan is queued, so a late verdict can only ever
// terminate that process, never a newer one that reused its PID.
// Suspicious: the same.
namespace CmdScanQueue {

constexpr int c_nWorkers = 2;
constexpr size_t c_nWarnPending = 5000;

struct Item
{
	std::string sCmd;
	std::string sName;
	uint32_t nPid = 0;
	HANDLE hProcess = nullptr; // PROCESS_TERMINATE, or null
};

struct State
{
	std::mutex mtx;
	std::condition_variable cv;
	std::deque<Item> queue;
	std::chrono::steady_clock::time_point lastWarn;
	bool fStarted = false;
};

static State& state()
{
	static State* s_p = new State(); // never destroyed: workers are detached
	return *s_p;
}

static void scanOne(const Item& item)
{
	std::string sThreat;
	const int r = DetectionNotifier::scanBufferWithLocalEngines(item.sCmd, item.sName, sThreat);
	if (r != 2 && r != 3)
		return;
	if (sThreat.empty())
		sThreat = (r == 2) ? "Malware.CommandLine" : "Suspicious.CommandLine";

	LOGLVL(Critical, FMT("enricher: [COMMAND LINE] " << (r == 2 ? "THREAT" : "SUSPICIOUS") << ": <"
		<< sThreat << "> PID " << item.nPid << " cmd <" << item.sCmd << ">"));
	if ((r == 2 || r == 3) && item.hProcess != nullptr && !DetectionNotifier::isProtectionPaused())
	{
		if (::TerminateProcess(item.hProcess, 1))
			LOGLVL(Critical, FMT("enricher: [COMMAND LINE] terminated PID " << item.nPid));
	}
	SendThreatAlertToGui(sThreat, "cmdline pid:" + std::to_string(item.nPid));
	ZeroTrust::recordThreatDetection();
}

static void worker()
{
	auto& st = state();
	for (;;)
	{
		Item item;
		{
			std::unique_lock lock(st.mtx);
			st.cv.wait(lock, [&st] { return !st.queue.empty(); });
			item = std::move(st.queue.front());
			st.queue.pop_front();
		}
		try
		{
			scanOne(item);
		}
		catch (...)
		{
		}
		if (item.hProcess != nullptr)
			::CloseHandle(item.hProcess);
	}
}

// "cmdline.<ext>" for the image's entry in scanner.cmdlineScanNames
// ("host=ext"), "cmdline.txt" when it has none.
static std::string virtualName(const std::wstring& wsImage, const std::wstring& wsCmd)
{
	std::wstring sName = wsImage;
	if (sName.empty())
	{
		const auto vArgv = ScriptArgs::tokenize(wsCmd);
		if (!vArgv.empty())
			sName = vArgv.front();
	}
	const std::wstring sBase = ScriptArgs::stripExe(ScriptArgs::baseNameLow(sName));
	for (const auto& sEntry : DetectionNotifier::getCmdlineScanNames())
	{
		const size_t nEq = sEntry.find(L'=');
		if (nEq == std::wstring::npos || nEq + 1 >= sEntry.size())
			continue;
		if (ScriptArgs::stripExe(sEntry.substr(0, nEq)) == sBase)
		{
			std::string sExt;
			for (wchar_t c : sEntry.substr(nEq + 1))
				sExt.push_back(static_cast<char>(c));
			return "cmdline." + sExt;
		}
	}
	return "cmdline.txt";
}

static void enqueue(const std::wstring& wsCmd, uint32_t nPid, const std::wstring& wsImage)
{
	if (wsCmd.empty())
		return;
	Item item;
	try
	{
		item.sCmd = string::convertWCharToUtf8(wsCmd);
	}
	catch (...)
	{
		return;
	}
	item.sName = virtualName(wsImage, wsCmd);
	item.nPid = nPid;
	if (nPid > 4)
		item.hProcess = ::OpenProcess(PROCESS_TERMINATE, FALSE, nPid);

	auto& st = state();
	bool fWarn = false;
	size_t nPending = 0;
	{
		std::scoped_lock lock(st.mtx);
		if (!st.fStarted)
		{
			st.fStarted = true;
			for (int i = 0; i < c_nWorkers; ++i)
				std::thread(worker).detach();
		}
		st.queue.push_back(std::move(item));
		nPending = st.queue.size();
		const auto now = std::chrono::steady_clock::now();
		if (nPending >= c_nWarnPending && now - st.lastWarn > std::chrono::seconds(60))
		{
			st.lastWarn = now;
			fWarn = true;
		}
	}
	st.cv.notify_one();
	if (fWarn)
		LOGWRN(FMT("enricher: command-line scan queue is long (" << nPending << " waiting); scans run late, none are dropped"));
}

} // namespace CmdScanQueue

// Process dumps with MegaDumper.dll (MegaDumperNative: NativeAOT, no .NET
// runtime) for processes that are not trusted, native and managed alike. A
// packer - native or .NET - or a loader that decrypts its payload in memory
// leaves the file on disk harmless-looking; the dump has the unpacked images
// (native PEs and .NET assemblies found in memory), and those are scanned like
// dropped files.
// One background worker: a dump reads the whole process, so nothing waits on
// it. A malicious or suspicious image in the dump: alert, kill chain record, and the
// process is stopped (unless protection is paused for training). Dumps with a
// detection are kept under ProgramData\edrsvc\dumps as evidence; clean ones
// are removed unless dumpKeepClean.
namespace DumpQueue {

typedef int (*MegaDumperEnablePrivFn)();
typedef int (*MegaDumperDumpFn)(uint32_t, const wchar_t*, int, int, wchar_t*, uint32_t);

struct Binding
{
	MegaDumperDumpFn fnDump = nullptr;
	bool fReady = false;
};

static Binding& binding()
{
	static Binding s_b;
	static std::once_flag s_once;
	std::call_once(s_once, [] {
		HMODULE hDll = ::LoadLibraryW(L"MegaDumper.dll");
		if (hDll == nullptr)
		{
			LOGLVL(Critical, "enricher: [DUMP] MegaDumper.dll not loaded (error " << ::GetLastError() << "); process dumps are off");
			return;
		}
		auto fnPriv = reinterpret_cast<MegaDumperEnablePrivFn>(::GetProcAddress(hDll, "megadumper_enable_debug_privilege"));
		s_b.fnDump = reinterpret_cast<MegaDumperDumpFn>(::GetProcAddress(hDll, "megadumper_dump_process"));
		if (s_b.fnDump == nullptr)
		{
			LOGLVL(Critical, "enricher: [DUMP] MegaDumper.dll has no megadumper_dump_process; process dumps are off");
			return;
		}
		if (fnPriv != nullptr)
			fnPriv();
		s_b.fReady = true;
	});
	return s_b;
}

struct Item
{
	uint32_t nPid = 0;
	std::string sImage;
	std::string sReason;
};

struct State
{
	std::mutex mtx;
	std::condition_variable cv;
	std::deque<Item> queue;
	std::unordered_set<uint32_t> pending;
	std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> recent;
	bool fStarted = false;
};

static State& state()
{
	static State* s_p = new State(); // never destroyed: the worker is detached
	return *s_p;
}

static std::filesystem::path dumpRoot()
{
	wchar_t szProgramData[MAX_PATH] = L"";
	DWORD nLen = ::GetEnvironmentVariableW(L"ProgramData", szProgramData, MAX_PATH);
	if (nLen == 0 || nLen >= MAX_PATH)
		return {};
	return std::filesystem::path(szProgramData) / L"edrsvc" / L"dumps";
}

// The process' modules that are genuine loaded Windows modules: base address
// -> path, for those loaded from the Windows system directories. Read after the
// dump, from the module list (the loader's record, not the image's own claims).
static std::unordered_map<uint64_t, std::wstring> loadedSystemModules(uint32_t nPid)
{
	std::unordered_map<uint64_t, std::wstring> out;
	wchar_t szWin[MAX_PATH] = L"";
	const UINT nWin = ::GetWindowsDirectoryW(szWin, MAX_PATH);
	if (nWin == 0 || nWin >= MAX_PATH)
		return out;
	std::wstring sWin(szWin, nWin);
	for (auto& c : sWin) c = static_cast<wchar_t>(::towlower(c));
	const std::wstring dirs[] = { sWin + L"\\system32\\", sWin + L"\\syswow64\\", sWin + L"\\winsxs\\" };

	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, nPid);
	if (hSnap == INVALID_HANDLE_VALUE)
		return out;
	MODULEENTRY32W me = {};
	me.dwSize = sizeof(me);
	if (::Module32FirstW(hSnap, &me))
	{
		do
		{
			std::wstring sPath = me.szExePath;
			for (auto& c : sPath) c = static_cast<wchar_t>(::towlower(c));
			bool isSysMod = false;
			for (const auto& d : dirs)
			{
				if (sPath.rfind(d, 0) == 0)
				{
					isSysMod = true;
					break;
				}
			}
			if (!isSysMod)
			{
				try
				{
					isSysMod = IsWindowsOsComponentPath(string::convertWCharToUtf8(sPath));
				}
				catch (...) {}
			}
			// Skip disk-backed modules under Program Files / Program Files (x86) whose on-disk
			// file exists; InspectProcessModules scans those exact files from disk with intact
			// Authenticode/hashes, whereas dumping relocated in-RAM pages breaks hashes/signatures.
			if (!isSysMod && sWin.size() >= 2)
			{
				const std::wstring sDrive = sWin.substr(0, 2);
				const std::wstring pfDirs[] = {
					sDrive + L"\\program files\\",
					sDrive + L"\\program files (x86)\\"
				};
				for (const auto& d : pfDirs)
				{
					if (sPath.rfind(d, 0) == 0)
					{
						const DWORD dwAttr = ::GetFileAttributesW(me.szExePath);
						if (dwAttr != INVALID_FILE_ATTRIBUTES && (dwAttr & FILE_ATTRIBUTE_DIRECTORY) == 0)
							isSysMod = true;
						break;
					}
				}
			}
			if (isSysMod)
				out[reinterpret_cast<uint64_t>(me.modBaseAddr)] = me.szExePath;
		} while (::Module32NextW(hSnap, &me));
	}
	::CloseHandle(hSnap);
	return out;
}

// The image base in a dump file name: vdump_<hex>.dll / .exe, rawdump_<hex>.
static bool dumpFileAddress(const std::wstring& sName, uint64_t& nAddr)
{
	size_t nStart = std::wstring::npos;
	if (_wcsnicmp(sName.c_str(), L"vdump_", 6) == 0)
		nStart = 6;
	else if (_wcsnicmp(sName.c_str(), L"rawdump_", 8) == 0)
		nStart = 8;
	if (nStart == std::wstring::npos)
		return false;
	wchar_t* pEnd = nullptr;
	nAddr = ::wcstoull(sName.c_str() + nStart, &pEnd, 16);
	return pEnd != sName.c_str() + nStart;
}

// Scans every file of one dump; returns how many were malicious or suspicious.
// Images that are a genuine Windows module of the process - one the loader
// mapped at that exact address from the Windows system directories - are
// skipped unless dumpScanSystemModules: hundreds per process, each a cloud
// upload, and their on-disk files are scanned and signature-checked anyway.
// Everything else is scanned: a copy of a system module mapped by hand (no
// loader record at its address), an image claiming a Microsoft name or
// version info, raw executable regions, and modules from other directories.
// (The dumper's own System folder sorted by the image's version info, which
// any payload can fill in with "Microsoft Corporation".)
static int scanDump(const std::filesystem::path& dir, const Item& item, std::string& sFirstThreat)
{
	const bool fScanSystem = DriverPortHips::s_dumpScanSystemModules.load(std::memory_order_relaxed);
	const auto systemModules = fScanSystem ? std::unordered_map<uint64_t, std::wstring>{} : loadedSystemModules(item.nPid);
	int nMalicious = 0;
	size_t nSkipped = 0;
	std::error_code ec;
	for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
		!ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
	{
		if (!it->is_regular_file(ec))
			continue;
		uint64_t nAddr = 0;
		std::wstring sModule;
		if (dumpFileAddress(it->path().filename().wstring(), nAddr))
		{
			auto itMod = systemModules.find(nAddr);
			if (itMod != systemModules.end())
			{
				++nSkipped;
				continue;
			}
		}
		std::string sFile;
		try { sFile = string::convertWCharToUtf8(it->path().wstring()); } catch (...) { continue; }
		std::string sThreat;
		DetectionNotifier::CloudScanDetail detail;
		const int r = DetectionNotifier::scanFileWithLocalEngines(sFile, sThreat, &detail);
		RecordScanResultForKillChain(sFile, item.nPid, r, detail, "dump");
		if (r == 2 || r == 3)
		{
			if (sThreat.empty())
				sThreat = r == 2 ? "Malware.DumpDetection" : "Suspicious.DumpDetection";
			LOGLVL(Critical, FMT("enricher: [DUMP] " << (r == 2 ? "MALICIOUS" : "SUSPICIOUS") << " <" << sThreat
				<< "> in the memory of PID " << item.nPid << " <" << item.sImage << ">: " << sFile));
			SendThreatAlertToGui(sThreat, "pid:" + std::to_string(item.nPid) + " " + item.sImage);
			// Suspicious stops the process too, like Malicious.
			if (sFirstThreat.empty())
				sFirstThreat = sThreat;
			++nMalicious;
		}
	}
	LOGLVL(Detailed, FMT("enricher: [DUMP] PID " << item.nPid << ": " << nSkipped
		<< " loaded Windows module(s) skipped, the rest scanned"));
	return nMalicious;
}

static void dumpOne(const Item& item)
{
	auto& b = binding();
	if (!b.fReady)
		return;
	const auto root = dumpRoot();
	if (root.empty())
		return;
	const auto dir = root / (L"pid_" + std::to_wstring(item.nPid) + L"_" +
		std::to_wstring(std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count()));
	std::error_code ec;
	std::filesystem::create_directories(dir, ec);

	wchar_t szResult[512] = L"";
	// Names not restored: the files keep the image base in their name
	// (vdump_<addr>), which is what scanDump checks against the loader's
	// module list.
	const int rc = b.fnDump(item.nPid, dir.c_str(), 1 /*native too*/, 0 /*keep addresses*/, szResult, 512);
	std::string sResult;
	try { sResult = string::convertWCharToUtf8(szResult); } catch (...) {}
	LOGLVL(Detailed, FMT("enricher: [DUMP] PID " << item.nPid << " <" << item.sImage << "> (" << item.sReason
		<< "): rc=" << rc << " " << sResult));
	if (rc != 0)
	{
		std::filesystem::remove_all(dir, ec);
		return;
	}

	std::string sThreat;
	const int nMalicious = scanDump(dir, item, sThreat);
	if (nMalicious > 0)
	{
		LOGLVL(Critical, FMT("enricher: [DUMP] " << nMalicious << " malicious image(s) in PID " << item.nPid
			<< " <" << item.sImage << ">; dump kept in " << string::convertWCharToUtf8(dir.wstring())));
		ZeroTrust::recordThreatDetection();
		if (!DetectionNotifier::isProtectionPaused())
		{
			HANDLE hProc = ::OpenProcess(PROCESS_TERMINATE, FALSE, item.nPid);
			if (hProc != nullptr)
			{
				const BOOL fKilled = ::TerminateProcess(hProc, 1);
				::CloseHandle(hProc);
				LOGLVL(Critical, FMT("enricher: [DUMP] " << (fKilled ? "terminated" : "could not terminate")
					<< " PID " << item.nPid << " (" << sThreat << ")"));
			}
		}
		return;
	}
	if (!DriverPortHips::s_dumpKeepClean.load(std::memory_order_relaxed))
		std::filesystem::remove_all(dir, ec);
}

static void worker()
{
	auto& st = state();
	for (;;)
	{
		Item item;
		{
			std::unique_lock lock(st.mtx);
			st.cv.wait(lock, [&st] { return !st.queue.empty(); });
			item = std::move(st.queue.front());
			st.queue.pop_front();
			st.pending.erase(item.nPid);
		}
		try { dumpOne(item); } catch (...) {}
	}
}

static void enqueue(uint32_t nPid, const std::string& sImage, const char* szReason)
{
	if (nPid <= 4 || nPid == ::GetCurrentProcessId())
		return;
	std::string sLower = sImage;
	for (auto& c : sLower) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
	if (IsPathUnderOwnInstallDir(sLower))
		return;
	auto& st = state();
	{
		std::scoped_lock lock(st.mtx);
		const auto now = std::chrono::steady_clock::now();
		const auto cooldown = std::chrono::seconds(DriverPortHips::s_dumpCooldownSeconds.load(std::memory_order_relaxed));
		auto it = st.recent.find(nPid);
		if (it != st.recent.end() && now - it->second < cooldown)
			return;
		if (!st.pending.insert(nPid).second)
			return;
		st.recent[nPid] = now;
		if (st.recent.size() > 20000)
		{
			for (auto itC = st.recent.begin(); itC != st.recent.end(); )
				itC = (now - itC->second >= cooldown) ? st.recent.erase(itC) : std::next(itC);
		}
		if (!st.fStarted)
		{
			st.fStarted = true;
			std::thread(worker).detach();
		}
		st.queue.push_back(Item{ nPid, sImage, szReason });
	}
	st.cv.notify_one();
}

} // namespace DumpQueue
} // namespace

void EventEnricher::executeUnfilteredLocalScan(Variant& vEvent, Variant& vProcess, Event eEventType, const std::string& sProcPath)
{
	// FileClose is not a scan trigger: the driver sends it for every handle
	// close, and a handle that wrote already produces FileDataChange /
	// FileDataWriteFull at its cleanup, which are scanned.
	//
	// FileCreate (every open) IS one again, for the opened file only and only
	// through the rescan queue (never inline, never the actor's image). An open
	// is often the first look at a file that already sits on disk: Windows
	// opens an exe to show its UAC prompt, before any process exists, and that
	// is where dControl.exe used to be caught. Dropping FileCreate lost that
	// look. Files cached Clean are skipped below before queueing, and the queue
	// keeps one entry per path and skips content it scanned in the last minute.
	if (eEventType == Event::LLE_FILE_CLOSE)
		return;

	// No event-level "benign" gate here. isUnknownOrThreatEvent used to skip the
	// whole event when the process and event.file looked clean, but it never
	// looked at destination / source / rename targets, so a clean process
	// copying or renaming a file left the new file unscanned. Each path below is
	// checked on its own against the verdict cache (size + last-write time), so
	// files that are really clean are still not scanned twice.
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

		// Product self-exclusion: never scan our own install tree.
		//
		// The component binaries ARE the detection material: openedr_static.dll
		// carries the published Wang MD5-collision block that
		// Crypto.MD5.CollisionAttack.Wang2004 matches, and the engines search
		// every rule table, signature and constant pool the product ships. Worse,
		// scanning a file reads it, which raises a fresh file-create event, which
		// re-enqueues the same scan - a self-feeding loop that buried real
		// telemetry (output_events appearing minutes late).
		//
		// This is a path-prefix exclusion: anything dropped into our own install
		// directory is not scanned. The directory is expected to be admin-writable
		// only, the same assumption the driver's hook-exclude rules already make.
		if (IsPathUnderOwnInstallDir(lowerDos))
			continue;

		if (!isProc && eEventType == Event::LLE_FILE_DELETE)
			continue;

		// Skip non-executable OS log/index/locale/PNF/perf/font/telemetry files on
		// file I/O events so AsyncRescan is not flooded and cache/stat calls are avoided.
		if (!isProc)
		{
			auto endsWith = [&lowerDos](const char* sfx) {
				const size_t n = std::strlen(sfx);
				return lowerDos.size() >= n && lowerDos.compare(lowerDos.size() - n, n, sfx) == 0;
			};
			const bool isPerfDat =
				(endsWith(".dat") &&
				(lowerDos.find("\\windows\\system32\\perfc") != std::string::npos ||
				 lowerDos.find("\\windows\\system32\\perfh") != std::string::npos ||
				 lowerDos.find("\\webcachev01.dat") != std::string::npos ||
				 lowerDos.find("\\staticcache.dat") != std::string::npos ||
				 lowerDos.find("\\activationstore.dat") != std::string::npos ||
				 lowerDos.find("\\fontcache") != std::string::npos ||
				 endsWith("\\settings.dat") ||
				 endsWith("\\icudtl.dat") ||
				 endsWith("\\icudt44l.dat") ||
				 endsWith("\\discovercachedata.dat"))) ||
				endsWith("\\structuredqueryschema.bin") ||
				endsWith("\\knowngamelist.bin") ||
				endsWith("\\start2.bin") ||
				endsWith("\\v8_context_snapshot.bin") ||
				(lowerDos.find(":streamedfilestate") != std::string::npos);
			const bool isOsMetaFile =
				endsWith("\\desktop.ini") || endsWith("\\appxblockmap.xml") ||
				endsWith("\\transcodedwallpaper") ||
				endsWith(".dat.log1") || endsWith(".dat.log2");

			static const char* const c_kOsCacheDirs[] = {
				"\\cryptneturlcache\\",
				"\\ebwebview\\",
				"\\crashpad\\",
				"\\windows\\fonts\\",
				"\\windows\\diagtrack\\",
				"\\windows\\panther\\",
				"\\windows\\appcompat\\",
				"\\windows\\wdi\\",
				"\\windows\\csc\\",
				"\\windows\\bcastdvr\\",
				"\\windows\\logs\\",
				"\\windows\\system32\\tasks\\microsoft\\",
				"\\programdata\\microsoft\\diagnosis\\",
				"\\programdata\\microsoft\\windows\\wer\\",
				"\\programdata\\microsoft\\windows\\onesettings\\",
				"\\programdata\\microsoft\\edgeupdate\\log\\",
				"\\programdata\\microsoft\\search\\",
				"\\programdata\\microsoft\\windows\\powergrid\\",
				"\\programdata\\microsoft\\windows\\apprepository\\",
				"\\appdata\\roaming\\microsoft\\protect\\",
				"\\targetedcontentcache\\",
				"\\trust protection lists\\",
				"\\system volume information\\",
				"\\onedrive\\logs\\",
				"\\onedrive\\settings\\",
				"\\localcache\\",
				"\\inetcache\\",
				"\\tempstate\\",
				"\\systemappdata\\helium\\",
				"\\ac\\tokenbroker\\cache\\",
			};
			bool isOsCachePath = false;
			for (const char* dir : c_kOsCacheDirs)
			{
				if (lowerDos.find(dir) != std::string::npos)
				{
					isOsCachePath = true;
					break;
				}
			}

			static const char* const c_kSkipExts[] = {
				".evtx", ".pnf", ".nls", ".inf_loc", ".ebd", ".jfm",
				".chk", ".blf", ".regtrans-ms", ".lex", ".mui", ".clb", ".etl",
				"\\edb.log", "\\edb00001.log", "\\edb00002.log", "\\edbtmp.log",
				".db", ".db-wal", ".db-shm", ".srd", ".srd-wal", ".srd-shm",
				".pri", ".pckgdep", ".cur", ".ani", ".sst", ".cdpresource",
				".mkd", ".pf", ".sdb", ".mun",
				".ttf", ".ttc", ".otf", ".fon",
				".log", ".log1", ".log2", ".aodl", ".odl", ".wer",
				".dmp", ".hdmp", ".mdmp",
				".pak", ".dxcache", ".tbres", ".cdp", ".hve",
				".automaticdestinations-ms", ".customdestinations-ms",
				".winmd", ".msstyles", ".dic", ".nlp", ".uce",
				".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
				".diffbase", ".uusver", ".pcpkey", ".gthr", ".bk",
				".txt", ".ini", ".json", ".otc", ".otc-wal", ".otc-shm",
				".keystore", ".crwl", ".checkpoint", ".ses", ".pb", ".inf", ".manifest",
			};
			bool hasSkipExt = false;
			for (const char* ext : c_kSkipExts)
			{
				if (endsWith(ext))
				{
					hasSkipExt = true;
					break;
				}
			}
			if (isPerfDat || isOsMetaFile || isOsCachePath || hasSkipExt)
				continue;
		}

		// FileCreate / Close / read / map-read look at the target file only; the actor's
		// image was looked at when that process started. Run before getCachedFileVerdict
		// to skip redundant stat/cache lookups on every file I/O event.
		if (isProc && (eEventType == Event::LLE_FILE_CREATE ||
			eEventType == Event::LLE_FILE_CLOSE ||
			eEventType == Event::LLE_FILE_DATA_READ_FULL ||
			eEventType == Event::LLE_FILE_MAP_READ || eEventType == Event::LLE_FILE_MAP_WRITE))
			continue;

		// Passive opens/reads/closes of Windows system/InboxApp paths (wmiprvse/svchost
		// touching System32/SysWOW64/WinSxS/.NET/SystemApps/Servicing/WindowsApps) must
		// not trigger stat/cache lookups or flood AsyncRescan; real writes emit
		// WriteFull/DataChange/MapWrite/Rename and are still scanned.
		if (!isProc && (eEventType == Event::LLE_FILE_MAP_READ ||
			eEventType == Event::LLE_FILE_DATA_READ_FULL ||
			eEventType == Event::LLE_FILE_CREATE ||
			eEventType == Event::LLE_FILE_CLOSE))
		{
			if (IsWindowsOsComponentPath(lowerDos))
				continue;
		}

		// Fast path: if already cached as Clean, skip heavy static scanning completely
		int cachedVerdict = 0;
		{
			StageTimer _stCache(c_stScanCache);
			cachedVerdict = DetectionNotifier::getCachedFileVerdict(dos);
		}
		// Not for a mapped write: the cached Clean is the content from before
		// the mapping, and the new content reaches the disk later.
		if (cachedVerdict == 1 && eEventType != Event::LLE_FILE_MAP_WRITE)
		{
			continue;
		}

		bool bKnownBlacklisted = false;
		{
			StageTimer _stCache(c_stScanCache);
			bKnownBlacklisted = (cachedVerdict == 2 || cachedVerdict == 3 || DetectionNotifier::isKnownMalware(dos, ""));
		}
		if (bKnownBlacklisted)
		{
			// Already known malware: flag immediately without re-scanning
			vEvent.put("verdict", 2);
			vEvent.put("flsVerdict", 3);
			vProcess.put("verdict", 2);
			vProcess.put("flsVerdict", 3);
			// Only when the path is this process' image. For a file event nPid is
			// whoever opened or wrote the file (explorer, a browser); processes
			// running the image are stopped and rolled back by the rescan below.
			if (isProc)
				handleThreatRemediation(nPid, L"", "Malware.LocalDetection");
			// The file is back at a blacklisted path: this branch used to only
			// stamp the event, so the re-dropped copy stayed on disk and ran.
			// Hand it to the rescan worker (deduped, off the hot path, waits for
			// the writer to finish) to quarantine it again.
			if (::GetFileAttributesW(Widen(dos).c_str()) != INVALID_FILE_ATTRIBUTES)
				AsyncRescanAndQuarantine(dos, nPid, true);
			continue;
		}

		// No skip on a verdict stamped on the event (file.verdict / file.flsVerdict).
		// That stamp comes from an earlier look at the path, possibly at other
		// content (an overwrite keeps the path), and skipping on it let new content
		// at a once-clean path go unscanned. scanFileWithLocalEngines keys its cache
		// on size + last-write time, and the FLS client caches by hash, so a file
		// that really is clean costs no extra scan.

		// Process executable images only need evaluation at process creation; on
		// routine sub-events (registry, thread/desktop open, etc.), never run a
		// blocking synchronous scan on the single enricher thread, and never queue
		// Windows/OS component images onto RescanQueue on sub-events.
		if (isProc && eEventType != Event::LLE_PROCESS_CREATE)
		{
			if (!IsWindowsOsComponentPath(lowerDos) && cachedVerdict == 0)
			{
				StageTimer _stQ(c_stScanAsyncQueue);
				AsyncRescanAndQuarantine(dos, nPid, true);
			}
			continue;
		}

		// A. Defer heavy scans off the single EventEnricher thread so arrival lag
		// stays near 0 ms: mid-write/rename/preimage/open/close/read file events AND
		// uncached process creation events are queued to RescanQueue's worker pool
		// (process-create and writes at high priority, opens/reads at normal priority).
		const bool bDeferredFileEvent = !isProc &&
			(eEventType == Event::LLE_FILE_DATA_WRITE_FULL ||
			 eEventType == Event::LLE_FILE_DATA_CHANGE ||
			 eEventType == Event::LLE_FILE_CREATE ||
			 eEventType == Event::LLE_FILE_CLOSE ||
			 eEventType == Event::LLE_FILE_RENAME ||
			 eEventType == Event::LLE_FILE_PREIMAGE_SAVED ||
			 eEventType == Event::LLE_FILE_DATA_READ_FULL ||
			 eEventType == Event::LLE_FILE_MAP_READ ||
			 eEventType == Event::LLE_FILE_MAP_WRITE);
		const bool bDeferScan = bDeferredFileEvent ||
			(isProc && eEventType == Event::LLE_PROCESS_CREATE && IsWindowsOsComponentPath(lowerDos));

		std::string sThreat;
		int r = 0;
		if (!bDeferScan)
		{
			DetectionNotifier::CloudScanDetail detail;
			r = DetectionNotifier::scanFileWithLocalEngines(dos, sThreat, &detail);
			if (t_pStageUs != nullptr && !detail.fFromCache)
			{
				t_pStageUs[c_stScanSha1] += detail.nSha1Us;
				t_pStageUs[c_stScanFls] += detail.nFlsUs;
				t_pStageUs[c_stScanStatic] += detail.nStaticUs;
			}
			{
				StageTimer _stKc(c_stScanKillChain);
				RecordScanResultForKillChain(dos, nPid, r, detail, isProc ? "process" : "inline");
			}
		}

		// Rescan race / Deferred scans: queue onto RescanQueue worker pool.
		if (r == 0 && (bDeferScan || (isProc && eEventType == Event::LLE_PROCESS_CREATE)))
		{
			StageTimer _stQ(c_stScanAsyncQueue);
			std::error_code ec;
			uintmax_t nSize = std::filesystem::file_size(dos, ec);
			if (eEventType == Event::LLE_FILE_MAP_WRITE)
				RescanQueue::enqueueWatch(dos, nPid); // content arrives later
			else if (ec || nSize > 0)
			{
				const bool bHighPriority =
					(isProc && !IsWindowsOsComponentPath(lowerDos)) ||
					eEventType == Event::LLE_FILE_DATA_WRITE_FULL ||
					eEventType == Event::LLE_FILE_DATA_CHANGE ||
					eEventType == Event::LLE_FILE_RENAME;
				AsyncRescanAndQuarantine(dos, nPid, bHighPriority);
			}
		}

		// Suspicious is acted on like Malicious: stop, quarantine, roll back.
		// (It used to be alert + driver block-list only, leaving the file on
		// disk.) The name keeps saying which one it was.
		if (r == 2 || r == 3)
		{
			if (sThreat.empty())
				sThreat = r == 2 ? "Malware.LocalDetection" : "Static.Suspicious";

			LOGLVL(Critical, FMT("enricher: [UNFILTERED SCAN] THREAT DETECTED (" << (r == 2 ? "Malicious" : "Suspicious") << "): <"
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
				// Whatever runs this image is stopped first: a running image is
				// locked and its quarantine fails (a process image convicted at
				// its start was left running and on disk).
				std::vector<uint32_t> vKilled;
				if (!DetectionNotifier::isProtectionPaused() && s_fnQuarantine != nullptr)
				{
					const int nKilled = TerminateProcessesRunningImage(dos, &vKilled);
					int32_t qRes = -1;
					for (int nTry = 0; nTry < (nKilled > 0 ? 5 : 1); ++nTry)
					{
						if (nTry > 0)
							std::this_thread::sleep_for(std::chrono::milliseconds(400));
						qRes = s_fnQuarantine(
							reinterpret_cast<const uint8_t*>(dos.data()),
							static_cast<uint32_t>(dos.size()));
						if (qRes == 0)
							break;
					}
					if (qRes == 0)
					{
						LOGLVL(Critical, FMT("enricher: successfully quarantined detected malware <" << dos << ">"));
						// The path is empty now, so the 30 s cooldown must not
						// swallow the malware coming back to it.
						std::scoped_lock lock(s_mtxAlertThrottle);
						s_recentAlerts.erase(lowerDos);
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
				{
					// Roll back the threat's processes: the one running this image
					// (isProc) and every process stopped for running it - not the
					// actor of a file event, which is whoever opened or wrote it.
					if (isProc)
						handleThreatRemediation(nPid, L"", sThreat);
					for (uint32_t nKilledPid : vKilled)
						if (!(isProc && static_cast<int64_t>(nKilledPid) == static_cast<int64_t>(nPid)))
							handleThreatRemediation(nKilledPid, L"", sThreat);
				}

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

				ZeroTrust::recordThreatDetection();
			}
		}


		// B. Also enqueue to daemon scanner pool (for background archive scanning / quarantine vault)
		if (s_fnEnqueue != nullptr)
		{
			s_fnEnqueue(reinterpret_cast<const uint8_t*>(dos.data()),
				static_cast<uint32_t>(dos.size()), isProc ? 1 : 0, nPid);
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
	std::vector<int64_t> vTainted;
	{
		std::scoped_lock _lock(s_mtxRansomShield);
		CollectTaintedChangesLocked(nPid, vec, readMapCopy, vTainted);
	}
	const std::unordered_set<int64_t> taintedSet(vTainted.begin(), vTainted.end());
	std::string sTainted;
	for (int64_t nT : vTainted)
		sTainted += (sTainted.empty() ? "" : ",") + std::to_string(nT);

	LOGLVL(Critical, FMT("RansomShield: rolling back " << vec.size() << " file change(s) of " << vTainted.size()
		<< " tainted process(es) (root PID " << nPid << "; pids " << sTainted << ")"));

	// Roll back newest-first so chained renames unwind correctly.
	std::unordered_set<std::wstring> restoredPaths;
	for (auto itEntry = vec.rbegin(); itEntry != vec.rend(); ++itEntry)
	{
		const ShadowBackupEntry& entry = *itEntry;

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

		if (!entry.wsNewName.empty())
		{
			if (!wsBackup.empty())
			{
				if (::DeleteFileW(entry.wsNewName.c_str()))
					LOGLVL(Critical, FMT("RansomShield: DELETED ransomware rename target <" << Narrow(entry.wsNewName) << ">"));
				else
					LOGLVL(Detailed, FMT("RansomShield: rollback rename target already gone or delete failed <" << Narrow(entry.wsNewName) << ">"));
			}
			else
			{
				// No pre-image: the renamed file is the only copy, so it is
				// renamed back instead of deleted.
				if (::MoveFileExW(entry.wsNewName.c_str(), entry.wsOriginal.c_str(), MOVEFILE_REPLACE_EXISTING))
					LOGLVL(Critical, FMT("RansomShield: renamed <" << Narrow(entry.wsNewName) << "> back to <" << Narrow(entry.wsOriginal) << ">"));
				else
					LOGLVL(Detailed, FMT("RansomShield: could not rename <" << Narrow(entry.wsNewName) << "> back; err=" << ::GetLastError()));
				continue;
			}
		}

		if (wsBackup.empty() && entry.nOp != 3)
		{
			// Changed but not created by the tainted process, and no pre-image:
			// deleting it would destroy the only copy.
			LOGLVL(Detailed, FMT("RansomShield: no pre-image for changed file <" << Narrow(entry.wsOriginal) << ">; left in place"));
			continue;
		}

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
					LOGLVL(Critical, FMT("RansomShield: delete failed for newly created artifact <" << Narrow(entry.wsOriginal) << "> err=" << err << "; delegated to kernel driver"));
				}
			}
			continue;
		}

		// A ransomware-style extra extension (file.doc -> file.doc.locked): the
		// file goes back under its earlier name only when the pre-image is that
		// file's (backups are named "<id>_<original name>", reads "read_<id>_...").
		// This used to strip the last extension whenever the PATH had a second
		// dot anywhere - a directory such as "v1.0" or "151.0.4129.72", or a
		// name such as "twinapi.appcore.dll" - deleting the file and restoring
		// it under the wrong name.
		{
			const size_t nSlash = wsRestoreTarget.find_last_of(L"\\/");
			const std::wstring wsName = nSlash == std::wstring::npos ? wsRestoreTarget : wsRestoreTarget.substr(nSlash + 1);
			const size_t nDot = wsName.find_last_of(L'.');
			const size_t nBkSlash = wsBackup.find_last_of(L"\\/");
			std::wstring wsBkName = nBkSlash == std::wstring::npos ? wsBackup : wsBackup.substr(nBkSlash + 1);
			if (wsBkName.rfind(L"read_", 0) == 0)
				wsBkName = wsBkName.substr(5);
			const size_t nUs = wsBkName.find(L'_');
			wsBkName = nUs == std::wstring::npos ? std::wstring() : wsBkName.substr(nUs + 1);
			if (nDot != std::wstring::npos && nDot > 0 && !wsBkName.empty())
			{
				const std::wstring wsStripped = wsName.substr(0, nDot);
				if (_wcsicmp(wsBkName.c_str(), wsStripped.c_str()) == 0 &&
					_wcsicmp(wsBkName.c_str(), wsName.c_str()) != 0)
				{
					// The encrypted copy goes; the original name comes back.
					::DeleteFileW(wsRestoreTarget.c_str());
					wsRestoreTarget.resize(wsRestoreTarget.size() - (wsName.size() - nDot));
				}
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
				// Only the tainted processes' backup folders (named by PID).
				if (taintedSet.count(_wtoi64(pidDir.path().filename().c_str())) == 0) continue;
				for (const auto& entry : std::filesystem::directory_iterator(pidDir.path()))
				{
					if (!entry.is_regular_file()) continue;
					std::wstring bkPath = entry.path().wstring();
					std::wstring fn = entry.path().filename().wstring();
					// read_* are copies taken when a file was READ, not changed:
					// restoring them would revert later legitimate edits.
					if (fn.rfind(L"read_", 0) == 0) continue;

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

	// The firewall's cloud verdicts come from the enricher's own scan + cache.
	RegisterOwlyshieldCloudVerdictProvider();

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
namespace {
	// Event rate diagnostics: counts every event the enricher receives by type
	// (API hook events by hooked function) and by acting process, and logs the
	// totals every ptm eventRateLogSeconds (0 = off), so the source of an event
	// flood can be seen instead of guessed. Costs one map increment per event.
	struct EventRateStats
	{
		std::mutex mtx;
		std::chrono::steady_clock::time_point windowStart = std::chrono::steady_clock::now();
		uint64_t total = 0;
		std::unordered_map<std::string, uint64_t> byType;
		std::unordered_map<std::string, uint64_t> byProcess;
	};

	std::string TopEntries(const std::unordered_map<std::string, uint64_t>& counts, size_t limit)
	{
		std::vector<std::pair<std::string, uint64_t>> v(counts.begin(), counts.end());
		std::sort(v.begin(), v.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
		std::string out;
		for (size_t i = 0; i < v.size() && i < limit; ++i)
			out += (out.empty() ? "" : ", ") + v[i].first + "=" + std::to_string(v[i].second);
		if (v.size() > limit)
			out += ", ... (" + std::to_string(v.size() - limit) + " more)";
		return out;
	}

	void RecordEventRate(const Variant& vEvent, const std::string& sType, const std::string& sProcPath)
	{
		DriverPortHips::EnsurePtmLoaded();
		const int nSeconds = DriverPortHips::s_eventRateLogSeconds.load(std::memory_order_relaxed);
		if (nSeconds <= 0)
			return;

		std::string sKey = sType;
		if (auto optApi = variant::getByPathSafe(vEvent, "owlyHook.apiFunction"))
		{
			try { sKey += ":" + std::string(optApi.value()); } catch (...) {}
		}
		std::string sProc = sProcPath;
		const size_t slash = sProc.find_last_of("\\/");
		if (slash != std::string::npos)
			sProc = sProc.substr(slash + 1);
		for (auto& c : sProc)
			c = (char)::tolower((unsigned char)c);
		if (sProc.empty())
			sProc = "<unknown>";

		static EventRateStats s_stats;
		uint64_t nTotal = 0;
		std::unordered_map<std::string, uint64_t> byType, byProcess;
		std::chrono::steady_clock::duration elapsed{};
		{
			std::scoped_lock lock(s_stats.mtx);
			++s_stats.total;
			++s_stats.byType[sKey];
			++s_stats.byProcess[sProc];
			const auto now = std::chrono::steady_clock::now();
			elapsed = now - s_stats.windowStart;
			if (elapsed < std::chrono::seconds(nSeconds))
				return;
			nTotal = s_stats.total;
			byType.swap(s_stats.byType);
			byProcess.swap(s_stats.byProcess);
			s_stats.total = 0;
			s_stats.windowStart = now;
		}

		const auto nTopTypes = static_cast<size_t>((std::max)(1, DriverPortHips::s_eventRateTopTypes.load(std::memory_order_relaxed)));
		const auto nTopProcs = static_cast<size_t>((std::max)(1, DriverPortHips::s_eventRateTopProcesses.load(std::memory_order_relaxed)));
		const double dSecs = std::chrono::duration<double>(elapsed).count();
		LOGLVL(Critical, FMT("eventrate: " << nTotal << " events in " << static_cast<int>(dSecs) << " s ("
			<< static_cast<uint64_t>(dSecs > 0 ? nTotal / dSecs : 0) << "/s) | by type: " << TopEntries(byType, nTopTypes)
			<< " | by process: " << TopEntries(byProcess, nTopProcs)));
	}

	// Event lag diagnostics, logged with the event rate (ptm eventRateLogSeconds):
	// how late events reach the enricher (now - event time: the driver and the
	// queue before it), how long the enricher spends on one, and the slowest
	// event of the window with its type and process. Where output_events falls
	// behind is then read off the log instead of guessed.
	struct EnricherLagStats
	{
		std::mutex mtx;
		std::chrono::steady_clock::time_point windowStart = std::chrono::steady_clock::now();
		uint64_t n = 0;
		uint64_t sumEntryLag = 0, maxEntryLag = 0;
		uint64_t sumWork = 0, maxWork = 0;
		std::string slowest;
		std::unordered_map<std::string, uint64_t> workByType; // total ms per type
		std::unordered_map<std::string, uint64_t> workByStage; // total ms per step of put()
	};

	// The steps of EventEnricher::put() that are timed (EnricherLagScope::mark).

	void RecordEnricherLag(uint64_t nEntryLagMs, uint64_t nWorkMs, const std::string& sType, const std::string& sProc,
		const uint64_t (&stageUs)[c_stCount])
	{
		const int nSeconds = DriverPortHips::s_eventRateLogSeconds.load(std::memory_order_relaxed);
		if (nSeconds <= 0)
			return;
		static EnricherLagStats s;
		EnricherLagStats snap;
		std::chrono::steady_clock::duration elapsed{};
		{
			std::scoped_lock lock(s.mtx);
			++s.n;
			s.sumEntryLag += nEntryLagMs;
			s.maxEntryLag = (std::max)(s.maxEntryLag, nEntryLagMs);
			s.sumWork += nWorkMs;
			s.workByType[sType] += nWorkMs;
			uint64_t nStagedUs = 0;
			for (int i = 0; i < c_stCount; ++i)
			{
				if (stageUs[i] != 0)
					s.workByStage[c_szStageNames[i]] += stageUs[i];
				if (i < c_stModSnapshot)
					nStagedUs += stageUs[i];
			}
			const uint64_t nWorkUs = nWorkMs * 1000;
			if (nWorkUs > nStagedUs)
				s.workByStage["other"] += nWorkUs - nStagedUs;
			if (nWorkMs > s.maxWork)
			{
				s.maxWork = nWorkMs;
				s.slowest = sType + " " + sProc;
			}
			const auto now = std::chrono::steady_clock::now();
			elapsed = now - s.windowStart;
			if (elapsed < std::chrono::seconds(nSeconds))
				return;
			snap.n = s.n; snap.sumEntryLag = s.sumEntryLag; snap.maxEntryLag = s.maxEntryLag;
			snap.sumWork = s.sumWork; snap.maxWork = s.maxWork; snap.slowest.swap(s.slowest);
			snap.workByType.swap(s.workByType);
			snap.workByStage.swap(s.workByStage);
			s.n = s.sumEntryLag = s.maxEntryLag = s.sumWork = s.maxWork = 0;
			s.windowStart = now;
		}
		if (snap.n == 0)
			return;
		const double dSecs = std::chrono::duration<double>(elapsed).count();
		std::unordered_map<std::string, uint64_t> stepMs;
		for (const auto& [k, us] : snap.workByStage)
			stepMs[k] = us / 1000;
		const std::string sSteps = TopEntries(stepMs, c_stCount + 1);
		LOGLVL(Critical, FMT("eventlag: " << snap.n << " events in " << static_cast<int>(dSecs) << " s"
			<< " | arrival lag avg " << snap.sumEntryLag / snap.n << " ms, max " << snap.maxEntryLag << " ms"
			<< " | enricher time total " << snap.sumWork << " ms (" << static_cast<int>(dSecs > 0 ? snap.sumWork / (dSecs * 10.0) : 0)
			<< "% busy), avg " << snap.sumWork / snap.n << " ms, max " << snap.maxWork << " ms <" << snap.slowest << ">"
			<< " | time by type (ms): " << TopEntries(snap.workByType, 8)
			<< " | time by step (ms): " << sSteps));
	}

	struct EnricherLagScope
	{
		std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
		uint64_t nEntryLag = 0;
		std::string sType;
		std::string sProc;
		uint64_t stageUs[c_stCount] = {};
		// Adds the time since t0 to a step and returns now (the next step's t0).
		std::chrono::steady_clock::time_point mark(EnricherStage st, std::chrono::steady_clock::time_point t0)
		{
			const auto now = std::chrono::steady_clock::now();
			stageUs[st] += static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(now - t0).count());
			return now;
		}
		~EnricherLagScope()
		{
			try
			{
				const auto nWork = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
					std::chrono::steady_clock::now() - start).count());
				RecordEnricherLag(nEntryLag, nWork, sType, sProc, stageUs);
			}
			catch (...) {}
		}
	};
} // namespace

void EventEnricher::put(const Variant& vEventRef)
{
	EnricherLagScope lagScope;
	t_pStageUs = lagScope.stageUs;
	struct StageReset { ~StageReset() { t_pStageUs = nullptr; } } stageReset;
	Variant vEvent = const_cast<Variant&>(vEventRef);

	TRACE_BEGIN;
	auto pReceiver = m_pReceiver;
	if (!pReceiver)
		error::InvalidArgument(SL, "Receiver interface is undefined").throwException();

	Event eEventType = vEvent.has("baseEventType") && !vEvent.get("baseEventType").isEmpty() ? 
		static_cast<Event>(static_cast<int>(vEvent.get("baseEventType"))) : 
		static_cast<Event>(static_cast<int>(vEvent.get("baseType")));
	vEvent.put("type", getEventTypeString(eEventType));
	ObserveLineage(eEventType, vEvent);

	// Calculate event "time"
	vEvent.put("time", Time(vEvent["tickTime"]) + (getCurrentTime() - getTickCount()));
	{
		const Time nEventTime = vEvent["time"];
		const Time nNow = getCurrentTime();
		lagScope.nEntryLag = nNow > nEventTime ? static_cast<uint64_t>(nNow - nEventTime) : 0;
		lagScope.sType = getEventTypeString(eEventType);
	}

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

	auto tStc_stProcInfo = std::chrono::steady_clock::now();
	auto vProcess = m_pProcProvider->enrichProcessInfo(vRawProcess);
	lagScope.mark(c_stProcInfo, tStc_stProcInfo);
	if (vProcess.isEmpty())
	{
		vProcess = vRawProcess;
	}

	std::string sProcPath;
	if (vProcess.has("imagePath")) sProcPath = std::string(vProcess["imagePath"]);
	else if (vProcess.has("path")) sProcPath = std::string(vProcess["path"]);
	else if (vProcess.has("rawPath")) sProcPath = std::string(vProcess["rawPath"]);
	// The process data provider keeps the image under "imageFile" (rawPath, and
	// path / abstractPath resolved on first use) - the keys above never exist on
	// an enriched process, so the actor's path was always empty here: no
	// known-malware match, no signature / trust check, no module inspection and
	// no scan of the process image. The event rate log showed it (<unknown>).
	if (sProcPath.empty())
	{
		try
		{
			if (auto optPath = variant::getByPathSafe(vProcess, "imageFile.path"))
				sProcPath = std::string(optPath.value());
			if (sProcPath.empty())
				if (auto optRaw = variant::getByPathSafe(vProcess, "imageFile.rawPath"))
					sProcPath = DetectionNotifier::NtPathToDosPathString(std::string(optRaw.value()));
		}
		catch (...) {}
	}

	std::string sProcHash;
	if (vProcess.has("imageHash")) sProcHash = std::string(vProcess["imageHash"]);
	else if (vProcess.has("hash")) sProcHash = std::string(vProcess["hash"]);

	RecordEventRate(vEvent, getEventTypeString(eEventType), sProcPath);
	{
		const size_t nSlash = sProcPath.find_last_of("\\/");
		lagScope.sProc = nSlash == std::string::npos ? sProcPath : sProcPath.substr(nSlash + 1);
	}

	if (DetectionNotifier::isKnownMalware(sProcPath, sProcHash))
	{
		vProcess.put("flsVerdict", 3);
		vProcess.put("verdict", 2);
	}

	uint32_t nActorPid = 0;
	if (vProcess.has("pid")) nActorPid = static_cast<uint32_t>(vProcess["pid"]);
	else if (vProcess.has("id")) nActorPid = static_cast<uint32_t>(vProcess["id"]);

	// UNFILTERED IMMEDIATE LOCAL FILE & PROCESS SCANNING (PASCAL-STYLE):
	// Run before InspectProcessModulesCached / IsProcessTrustedConfigurable so
	// LLE_PROCESS_CREATE caches the process image verdict & VirusKov detail first.
	auto tStc_stLocalScan = std::chrono::steady_clock::now();
	executeUnfilteredLocalScan(vEvent, vProcess, eEventType, sProcPath);
	lagScope.mark(c_stLocalScan, tStc_stLocalScan);

	// Dual Trust & Unknown DLL Evaluation (Comodo FLS vs VirusKov Cloud):
	auto tStc_stModules = std::chrono::steady_clock::now();
	auto modRes = DriverPortHips::InspectProcessModulesCached(nActorPid, sProcPath);
	lagScope.mark(c_stModules, tStc_stModules);
	int cleanCode = DriverPortHips::s_cleanVerdict.load(std::memory_order_relaxed);
	auto tStc_stProcCert = std::chrono::steady_clock::now();
	DetectionNotifier::CloudScanDetail procDetail;
	int procCached = DetectionNotifier::getCachedFileVerdict(sProcPath, &procDetail);
	bool isProcFlsClean = (procDetail.sFls == "Safe") ||
	                      (vProcess.has("flsVerdict") && static_cast<int64_t>(vProcess["flsVerdict"]) == cleanCode);
	bool isProcViruskovClean = (procDetail.sViruskov == "Clean") ||
	                           (procDetail.sFls.empty() && procCached == cleanCode);
	lagScope.mark(c_stProcCert, tStc_stProcCert);

	vProcess.put("hasUnknownDllComodo", modRes.hasUnknownDllComodo);
	vProcess.put("hasUnknownDllCertificate", modRes.hasUnknownDllCertificate);
	vProcess.put("hasUnknownDll", modRes.hasUnknownDllComodo || modRes.hasUnknownDllCertificate);
	std::string primaryUnknownDll = !modRes.firstUnknownDllComodo.empty() ? modRes.firstUnknownDllComodo : modRes.firstUnknownDllCert;
	vProcess.put("unknownDllPath", primaryUnknownDll);
	vProcess.put("isTrustedAccordingToFls", isProcFlsClean && !modRes.hasUnknownDllComodo);
	vProcess.put("isTrustedAccordingToViruskov", isProcViruskovClean && !modRes.hasUnknownDllCertificate);
	vProcess.put("isTrustedAccordingToCertificate", isProcViruskovClean && !modRes.hasUnknownDllCertificate);

	vProcess.put("isDotNet", modRes.isDotNet);
	vProcess.put("isDotNetLoader", modRes.isDotNetLoader);
	vProcess.put("loaderTargetDll", modRes.loaderTargetDll);
	vProcess.put("loaderTargetDllName", modRes.loaderTargetDllName);
	vProcess.put("loaderStartFunction", modRes.loaderStartFunction);
	vProcess.put("dllAttackChain", modRes.dllAttackChain);
	vProcess.put("dllMapping", modRes.dllMapping);
	vEvent.put("dllAttackChain", modRes.dllAttackChain);
	vEvent.put("dllMapping", modRes.dllMapping);
	vEvent.put("isDotNetLoader", modRes.isDotNetLoader);
	if (modRes.isDotNetLoader && !modRes.loaderTargetDll.empty())
	{
		vEvent.put("loaderTargetDll", modRes.loaderTargetDll);
		vEvent.put("startFunction", modRes.loaderStartFunction);
		if (modRes.hasUnknownDll)
		{
			vEvent.put("quarantineTarget", modRes.loaderTargetDll);
		}
	}

	std::string untrustedReason;
	auto tStc_stTrust = std::chrono::steady_clock::now();
	bool isProcessTrusted = DriverPortHips::IsProcessTrustedConfigurable(
		vProcess, sProcPath, nActorPid, modRes, untrustedReason, &procDetail, procCached);
	lagScope.mark(c_stTrust, tStc_stTrust);
	vProcess.put("isTrusted", isProcessTrusted);

	// An untrusted process (native or managed - MegaDumper unpacks both), or a
	// .NET loader with an unknown DLL: dump it (MegaDumper.dll) and scan what
	// was unpacked in memory. Wait until sProcPath or one of its DLLs actually
	// finished evaluation so clean processes aren't dumped before first scan.
	const int trustMode = DriverPortHips::s_configuredTrustMode.load(std::memory_order_relaxed);
	const bool isProcImageSelfTrusted = (trustMode == 1) ? isProcFlsClean
	                                  : (trustMode == 2) ? isProcViruskovClean
	                                  : (isProcFlsClean && isProcViruskovClean);
	const bool shouldDumpUntrusted =
		(procCached != 0 && !isProcImageSelfTrusted) || modRes.hasEvaluatedUnknownDll;
	if (modRes.isDotNetLoader && modRes.hasUnknownDll)
		DumpQueue::enqueue(nActorPid, sProcPath, ".NET loader with an unknown DLL");
	else if (!isProcessTrusted && DriverPortHips::s_dumpUntrusted.load(std::memory_order_relaxed) &&
		shouldDumpUntrusted)
		DumpQueue::enqueue(nActorPid, sProcPath, modRes.isDotNet ? "untrusted managed process" : "untrusted native process");

	// Alert on .NET loader with unknown DLL in attack chain
	if (modRes.isDotNetLoader && modRes.hasUnknownDll)
	{
		LOGLVL(Critical, FMT("enricher: [.NET LOADER ATTACK CHAIN DETECTED] Process <" << sProcPath
			<< "> (PID: " << nActorPid << ") loaded untrusted target DLL <"
			<< modRes.loaderTargetDll << "> (Start: " << modRes.loaderStartFunction << ")"));

		HANDLE hPipeAlert = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
			GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipeAlert != INVALID_HANDLE_VALUE)
		{
			std::string alertMsg = "THREAT_ALERT:Exploit.Win32.DotNetLoader.AttackChain|" +
				sProcPath + "|0|" + modRes.dllAttackChain + "\n";
			DWORD written = 0;
			::WriteFile(hPipeAlert, alertMsg.data(), static_cast<DWORD>(alertMsg.size()), &written, NULL);
			::CloseHandle(hPipeAlert);
		}
	}

	vEvent.put("process", vProcess);
	Variant vToken = getByPath(vProcess, "token.tokenObj", {});

	// Pre-extract raw file properties before createLambdaProxy replaces vEvent["file"],
	// so recordShadowBackupImpl and ForwardToOwlyshieldMlEngine never evaluate lazy proxies.
	std::string sRawFilePathUtf8;
	std::wstring wsRawFilePath;
	std::wstring wsRawRenameTarget;
	std::wstring wsRawBackupPath;
	int64_t nRawCreationStatus = 0;
	bool fHasRawFileSnapshot = false;

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
		{
			try
			{
				wsRawFilePath = vParams.get("path", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("rawPath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("uniquePath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("abstractPath", L"");
				if (!wsRawFilePath.empty())
					sRawFilePathUtf8 = string::convertWCharToUtf8(wsRawFilePath);
			}
			catch (...) {}
			try { wsRawRenameTarget = vParams.get("renameTarget", L""); } catch (...) {}
			try { wsRawBackupPath = vParams.get("backupPath", L""); } catch (...) {}
			try { nRawCreationStatus = vParams.get("creationStatus", int64_t(0)); } catch (...) {}
			fHasRawFileSnapshot = true;
		}
		vParams.put("security", vToken);
		if (eEventType == Event::LLE_FILE_DELETE)
			vParams.put("cmdRemove", true);
		if (eEventType == Event::LLE_FILE_DATA_CHANGE)
			vParams.put("cmdModify", true);

		// Enrich File Trust (Comodo FLS vs VirusKov Cloud):
		std::string sFilePathCheck;
		if (vParams.has("path")) sFilePathCheck = Narrow(vParams.get("path", L""));
		else if (vParams.has("rawPath")) sFilePathCheck = Narrow(vParams.get("rawPath", L""));
		if (!sFilePathCheck.empty())
		{
			DetectionNotifier::CloudScanDetail fileDetail;
			int fileFlsVerdict = DetectionNotifier::getCachedFileVerdict(sFilePathCheck, &fileDetail);
			const int cleanVal = DriverPortHips::s_cleanVerdict.load(std::memory_order_relaxed);
			bool isFileFlsClean = (fileFlsVerdict == cleanVal) || (fileDetail.sFls == "Safe");
			bool isFileUnknown = DriverPortHips::isUnknownVerdict(fileFlsVerdict);

			vParams.put("isTrustedAccordingToFls", isFileFlsClean);
			vParams.put("isUnknownAccordingToComodo", isFileUnknown);
			vEvent.put("isUnknownAccordingToComodo", isFileUnknown);

			if (eEventType == Event::LLE_FILE_DATA_WRITE_FULL)
			{
				bool isFileViruskovClean = (fileDetail.sViruskov == "Clean") ||
					(fileDetail.sFls.empty() && fileFlsVerdict == cleanVal);
				vParams.put("isTrustedAccordingToViruskov", isFileViruskovClean);
				vParams.put("isTrustedAccordingToCertificate", isFileViruskovClean);
				vParams.put("isUnknownAccordingToCertificate", !isFileViruskovClean);
				vEvent.put("isUnknownAccordingToCertificate", !isFileViruskovClean);
			}
		}

		// Shell link content (file.shellLink.*) once the file is fully written, for
		// the policy's shortcut rules. Not on FileClose: the driver sends that for
		// every handle, reads included, and the shell reads shortcuts constantly to
		// draw icons. Windows treats a file as a link by its .lnk extension, so only
		// those are opened (no extra I/O for other files); ReadShellLinkFields then
		// confirms the format header.
		if (eEventType == Event::LLE_FILE_DATA_WRITE_FULL)
		{
			std::wstring wsLnk;
			if (vParams.has("path")) wsLnk = vParams.get("path", L"");
			if (wsLnk.empty() && vParams.has("rawPath")) wsLnk = vParams.get("rawPath", L"");
			if (endsWithCaseInsensitive(wsLnk, L".lnk"))
			{
				Dictionary vLink;
				if (ReadShellLinkFields(NormalizeToDosPath(wsLnk), vLink))
					vParams.put("shellLink", vLink);
			}
		}

		// USB Self-Replication Worm Detection:
		// When an executable (.exe, .scr, .pif, .com) is written to a removable drive,
		// compute hybrid PE & chunk similarity ratio [0..100%] against the writing process binary.
		// Exclude Comodo cloud clean and digitally signed trusted processes to prevent false positives.
		if (eEventType == Event::LLE_FILE_CREATE || eEventType == Event::LLE_FILE_DATA_WRITE_FULL)
		{
			std::wstring wsDestPath;
			if (vParams.has("path")) wsDestPath = vParams.get("path", L"");
			if (wsDestPath.empty() && vParams.has("rawPath")) wsDestPath = vParams.get("rawPath", L"");
			if (wsDestPath.empty() && vParams.has("uniquePath")) wsDestPath = vParams.get("uniquePath", L"");
			if (wsDestPath.empty() && vParams.has("abstractPath")) wsDestPath = vParams.get("abstractPath", L"");

			wsDestPath = NormalizeToDosPath(wsDestPath);

			bool isRemovable = false;
			if (wsDestPath.size() >= 2 && wsDestPath[1] == L':')
			{
				std::wstring sRoot = wsDestPath.substr(0, 2) + L"\\";
				UINT dt = ::GetDriveTypeW(sRoot.c_str());
				if (dt == DRIVE_REMOVABLE || dt == DRIVE_CDROM || dt == DRIVE_RAMDISK)
					isRemovable = true;
			}
			if (!isRemovable && vParams.has("volume"))
			{
				try {
					Variant vVol = vParams.get("volume", {});
					if (vVol.has("type") && std::string(vVol["type"]) == "REMOVABLE")
						isRemovable = true;
				} catch (...) {}
			}

			if (isRemovable)
			{
				vEvent.put("isRemovableDrive", true);
				vParams.put("isRemovableDrive", true);

				bool isExecutable = endsWithCaseInsensitive(wsDestPath, L".exe") ||
				                    endsWithCaseInsensitive(wsDestPath, L".scr") ||
				                    endsWithCaseInsensitive(wsDestPath, L".pif") ||
				                    endsWithCaseInsensitive(wsDestPath, L".com");

				if (isExecutable)
				{
					vEvent.put("usbWriteExecutable", true);
					vParams.put("usbWriteExecutable", true);

					// Check Process Trust: Comodo Cloud Clean + Valid Digital Signature
					bool isCloudClean = (vProcess.has("verdict") && static_cast<int64_t>(vProcess["verdict"]) == 1) ||
					                    (vProcess.has("flsVerdict") && static_cast<int64_t>(vProcess["flsVerdict"]) == 1) ||
					                    (DetectionNotifier::getCachedFileVerdict(sProcPath) == 1);
					bool isSignedTrusted = false;
					if (vProcess.has("signature"))
					{
						try {
							auto vSig = vProcess["signature"];
							if (vSig.has("status") && static_cast<int64_t>(vSig["status"]) == 0)
								isSignedTrusted = true;
						} catch (...) {}
					}
					bool isUsbSrcTrusted = isCloudClean || isSignedTrusted;

					if (!isUsbSrcTrusted && !sProcPath.empty())
					{
						std::wstring wsSrcProc = NormalizeToDosPath(Widen(sProcPath));
						int similarity = UsbWormDetection::calculateExeSimilarity(wsSrcProc, wsDestPath);

						vEvent.put("usbSimilarityRatio", similarity);
						vParams.put("usbSimilarityRatio", similarity);

						if (similarity >= 75)
						{
							LOGLVL(Critical, FMT("enricher: [USB WORM DETECTED] Process <" << sProcPath
								<< "> replicated to USB <" << Narrow(wsDestPath)
								<< "> with similarity " << similarity << "%!"));

							vProcess.put("flsVerdict", 2);
							vProcess.put("verdict", 2);
							vProcess.put("threatName", "Worm.Win32.UsbReplication");
							vEvent.put("threatName", "Worm.Win32.UsbReplication");
							vEvent.put("baseType", 1000025);
							vEvent.put("quarantineTarget", wsDestPath);

							// Immediate quarantine & alert
							// UTF-8, not Narrow(): a lossy path blacklists the wrong name.
							DetectionNotifier::recordMalwareDetection(string::convertWCharToUtf8(wsDestPath), "");
							DetectionNotifier::recordMalwareDetection(sProcPath, "");

							HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
								GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
							if (hPipe != INVALID_HANDLE_VALUE)
							{
								std::string pipeMsg = "THREAT_ALERT:Worm.Win32.UsbReplication|" + Narrow(wsDestPath) + "\n";
								DWORD written = 0;
								::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
								::CloseHandle(hPipe);
							}

							ZeroTrust::recordThreatDetection();

							if (nActorPid > 0 && !DetectionNotifier::isProtectionPaused())
							{
								handleThreatRemediation(nActorPid, wsDestPath, "Worm.Win32.UsbReplication");
							}
						}
					}
				}
			}
		}

		// ── Driver & Minifilter Port HIPS Guard ──────────────────────────────
		// Monitors process connection attempts to kernel driver devices and minifilter
		// communication ports (e.g. \RWFilter, \GIO, \RTCore64, or unknown new ports).
		if (eEventType == Event::LLE_FILE_CREATE)
		{
			std::string threatReason;
			bool isKnownVulnerable = false;
			std::string unknownDllToQuarantine;

			std::wstring wsRawCheck;
			if (vParams.has("path")) wsRawCheck = vParams.get("path", L"");
			if (wsRawCheck.empty() && vParams.has("rawPath")) wsRawCheck = vParams.get("rawPath", L"");
			if (wsRawCheck.empty() && vParams.has("uniquePath")) wsRawCheck = vParams.get("uniquePath", L"");
			if (wsRawCheck.empty() && vParams.has("abstractPath")) wsRawCheck = vParams.get("abstractPath", L"");

			if (DriverPortHips::InspectPortAccess(wsRawCheck, vProcess, sProcPath, nActorPid, modRes, threatReason, isKnownVulnerable, unknownDllToQuarantine))
			{
				std::string portNarrow = Narrow(wsRawCheck);
				LOGLVL(Critical, FMT("enricher: [DRIVER PORT HIPS ALERT] Process <" << sProcPath
					<< "> (PID: " << nActorPid << ") attempted access to kernel driver port <"
					<< portNarrow << "> - " << threatReason));

				if (!unknownDllToQuarantine.empty())
				{
					vEvent.put("quarantineTarget", unknownDllToQuarantine);
					vEvent.put("unknownDllPath", unknownDllToQuarantine);
					vProcess.put("unknownDllPath", unknownDllToQuarantine);
				}

				// If it's a known vulnerable BYOVD port (like \RWFilter), suspend immediately to prevent exploit
				if (isKnownVulnerable && nActorPid > 4)
				{
					SuspendProcessByPid(nActorPid);
					LOGLVL(Critical, FMT("enricher: [BYOVD MITIGATION] Suspended exploiting PID " << nActorPid << " targeting " << portNarrow));
				}

				// Forward HIPS_ASK interactive prompt to edrgui via HydraHipEvent pipe
				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string appName = sProcPath;
					size_t pSlash = appName.find_last_of("\\/");
					if (pSlash != std::string::npos) appName = appName.substr(pSlash + 1);

					std::string reqId = "port_" + std::to_string(nActorPid) + "_" + std::to_string(::GetTickCount64());
					std::string targetDesc = portNarrow;
					if (!unknownDllToQuarantine.empty())
					{
						targetDesc += " [Unknown DLL: " + unknownDllToQuarantine + "]";
					}

					// 9-field HIPS_ASK protocol expected by edrgui/unit1.pas:
					// HIPS_ASK:<req_id>|<pid>|<app_name>|<exe_path>|<target>|<verdict>|<sig_status>|<reason>|<dll_attack_chain>
					std::string askMsg = "HIPS_ASK:" + reqId + "|" + std::to_string(nActorPid) + "|" +
						appName + "|" + sProcPath + "|" + targetDesc + "|" +
						(isKnownVulnerable ? "malicious" : "suspicious") + "|" +
						(isProcViruskovClean ? "valid" : "unsigned") + "|" +
						threatReason + "|" +
						modRes.dllAttackChain + "\n";
					DWORD written = 0;
					::WriteFile(hPipe, askMsg.data(), static_cast<DWORD>(askMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}

				ZeroTrust::recordThreatDetection();
			}
		}

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
					if (vParams.has("isRemovableDrive"))
						res.put("isRemovableDrive", vParams["isRemovableDrive"]);
					if (vParams.has("usbSimilarityRatio"))
						res.put("usbSimilarityRatio", vParams["usbSimilarityRatio"]);
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
		{
			try
			{
				wsRawFilePath = vParams.get("path", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("rawPath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("uniquePath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("abstractPath", L"");
				if (!wsRawFilePath.empty())
					sRawFilePathUtf8 = string::convertWCharToUtf8(wsRawFilePath);
			}
			catch (...) {}
			try { wsRawRenameTarget = vParams.get("renameTarget", L""); } catch (...) {}
			try { wsRawBackupPath = vParams.get("backupPath", L""); } catch (...) {}
			fHasRawFileSnapshot = true;
		}
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
		{
			try
			{
				wsRawFilePath = vParams.get("path", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("rawPath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("uniquePath", L"");
				if (wsRawFilePath.empty()) wsRawFilePath = vParams.get("abstractPath", L"");
				if (!wsRawFilePath.empty())
					sRawFilePathUtf8 = string::convertWCharToUtf8(wsRawFilePath);
			}
			catch (...) {}
			try { wsRawBackupPath = vParams.get("backupPath", L""); } catch (...) {}
			fHasRawFileSnapshot = true;
		}
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

		// Zero Trust Lockdown Mode: if enabled (manually or via >=20 threat detections),
		// all unknown executable launches are suspended and prompted to the user via edrgui.
		if (ZeroTrust::isEnabled())
		{
			std::string dosPath = DetectionNotifier::NtPathToDosPathString(sImgPath);
			uint32_t nPid = enrichedProcessInfo.has("pid") ? static_cast<uint32_t>(enrichedProcessInfo["pid"]) : 0;
			bool bWhitelisted = ZeroTrust::isSessionWhitelisted(dosPath);
			bool bClean = (enrichedProcessInfo.has("verdict") && static_cast<int64_t>(enrichedProcessInfo["verdict"]) == 1) ||
			              (DetectionNotifier::getCachedFileVerdict(dosPath) == 1);

			if (!bWhitelisted && !bClean && nPid > 4 && nPid != ::GetCurrentProcessId())
			{
				if (SuspendProcessByPid(nPid))
				{
					LOGLVL(Critical, FMT("enricher: [ZERO TRUST LOCKDOWN] Suspended unknown executable launch <"
						<< dosPath << "> (PID: " << nPid << ") awaiting user decision from edrgui"));

					std::string appName = dosPath;
					size_t pSlash = appName.find_last_of("\\/");
					if (pSlash != std::string::npos) appName = appName.substr(pSlash + 1);

					HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
						GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
					if (hPipe != INVALID_HANDLE_VALUE)
					{
						std::string reqId = "zt_" + std::to_string(nPid) + "_" + std::to_string(::GetTickCount64());
						std::string askMsg = "HIPS_ASK:" + reqId + "|" + std::to_string(nPid) + "|" +
							appName + "|" + dosPath + "|zero_trust|process_launch|Zero Trust Lockdown: 20+ tehdit nedeniyle bilinmeyen uygulama askiya alindi.\n";
						DWORD written = 0;
						::WriteFile(hPipe, askMsg.data(), static_cast<DWORD>(askMsg.size()), &written, NULL);
						::CloseHandle(hPipe);
					}
				}
			}
		}

		// VirusKov Restricted Mode: block UAC elevation attempts by restricted processes
		uint32_t nParentPid = enrichedProcessInfo.has("parentPid") ? static_cast<uint32_t>(enrichedProcessInfo["parentPid"]) : 0;
		if (nParentPid != 0 && ZeroTrust::isRestricted(nParentPid))
		{
			bool isElevated = enrichedProcessInfo.has("isElevated") ? static_cast<bool>(enrichedProcessInfo["isElevated"]) : false;
			std::string cmd = enrichedProcessInfo.has("cmdLine") ? std::string(enrichedProcessInfo["cmdLine"]) : "";
			if (isElevated || cmd.find("runas") != std::string::npos)
			{
				uint32_t nPid = enrichedProcessInfo.has("pid") ? static_cast<uint32_t>(enrichedProcessInfo["pid"]) : 0;
				if (nPid > 0)
				{
					HANDLE hKill = ::OpenProcess(PROCESS_TERMINATE, FALSE, nPid);
					if (hKill) { ::TerminateProcess(hKill, 1); ::CloseHandle(hKill); }
				}
				LOGLVL(Critical, FMT("enricher: [VIRUSKOV RESTRICTED MODE] Blocked UAC elevation attempt by restricted PID " << nParentPid));
			}
		}

		// Best-effort PDB warm-up for the offline symbol pipe; async, never blocks.
		QueuePdbPrefetch(sImgPath);

		const std::wstring cmdLine = enrichedProcessInfo["cmdLine"];
		const uint32_t nNewPid = enrichedProcessInfo.has("pid") ? static_cast<uint32_t>(enrichedProcessInfo["pid"]) : 0;

		// The command line itself through ClamAV / YARA-X / ML (queued, see
		// CmdScanQueue). It only ever reached the policy rules, so an encoded
		// PowerShell or a mshta/rundll32 one-liner never met the signatures.
		std::wstring wsImgPath;
		try
		{
			wsImgPath = string::convertUtf8ToWChar(sImgPath);
		}
		catch (...) {}
		CmdScanQueue::enqueue(cmdLine, nNewPid, wsImgPath);

		// Script host by its image (scanner.scriptInterpreters); argv[0] only
		// when the image path is unknown.
		bool fScriptHost = false;
		if (!wsImgPath.empty())
			fScriptHost = ScriptArgs::isScriptHost(wsImgPath);
		else
		{
			const auto vArgv = ScriptArgs::tokenize(cmdLine);
			fScriptHost = !vArgv.empty() && ScriptArgs::isScriptHost(vArgv.front());
		}
		if (fScriptHost)
		{
			std::wstring scriptPath;
			std::vector<std::wstring> vFiles;
			try
			{
				vFiles = ScriptArgs::findFiles(cmdLine, nNewPid, nParentPid, scriptPath);
			}
			catch (...) {}

			if (!scriptPath.empty())
			{
				try
				{
					const Variant scriptContent = readContent(scriptPath);
					if (!scriptContent.isEmpty())
						vEvent.put("scriptContent", scriptContent);
				}
				catch (...) {}
			}

			// Every file the host was handed is scanned like a dropped file
			// (full engines, quarantined when Malicious).
			for (const auto& sFile : vFiles)
			{
				try
				{
					AsyncRescanAndQuarantine(string::convertWCharToUtf8(sFile), nNewPid);
				}
				catch (...) {}
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
		if (DriverPortHips::s_dumpUntrusted.load(std::memory_order_relaxed))
		{
			uint32_t targetPid = 0;
			if (vEvent.has("target"))
			{
				try
				{
					auto vTarget = vEvent.get("target");
					if (vTarget.has("pid")) targetPid = static_cast<uint32_t>(vTarget["pid"]);
					else if (vTarget.has("id")) targetPid = static_cast<uint32_t>(vTarget["id"]);
				}
				catch (...) {}
			}
			if (targetPid > 4)
				DumpQueue::enqueue(targetPid, "", "injection target");
			else if (nActorPid > 4)
				DumpQueue::enqueue(nActorPid, sProcPath, "injection activity");
		}
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
					std::wstring wsApiFunc = sName.substr(nPos + 1);
					vHook.put("apiModule", sName.substr(0, nPos));
					vHook.put("apiFunction", wsApiFunc);
					if (DriverPortHips::s_dumpUntrusted.load(std::memory_order_relaxed) && srcPid > 4 &&
						(_wcsicmp(wsApiFunc.c_str(), L"VirtualAllocEx") == 0 ||
						 _wcsicmp(wsApiFunc.c_str(), L"WriteProcessMemory") == 0 ||
						 _wcsicmp(wsApiFunc.c_str(), L"CreateRemoteThread") == 0 ||
						 _wcsicmp(wsApiFunc.c_str(), L"NtCreateThreadEx") == 0))
					{
						DumpQueue::enqueue(srcPid, sProcPath, "injection API hook");
					}
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
		auto tStc_stShadow = std::chrono::steady_clock::now();
		recordShadowBackupImpl(nShieldPid, eEventType, vEvent,
			&wsRawFilePath, &wsRawRenameTarget, &wsRawBackupPath,
			nRawCreationStatus, fHasRawFileSnapshot);
		lagScope.mark(c_stShadow, tStc_stShadow);

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
			std::string sThreatName = vEvent.has("threatName") ? std::string(vEvent.get("threatName")) : ("THREAT_BASE_TYPE_" + std::to_string(nBaseType));
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

	// Feed enriched events to training dataset / GUI pipe without triggering lazy proxies
	auto tStTraining = std::chrono::steady_clock::now();
	ForwardToOwlyshieldMlEngine(vEvent, sProcPath, sRawFilePathUtf8);
	auto tStReceiver = lagScope.mark(c_stTraining, tStTraining);

	pReceiver->put(vEvent);
	lagScope.mark(c_stReceiver, tStReceiver);
	TRACE_END(FMT("Fail to parse event <" << vEvent.get("baseType", 0) << ">"))
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

		// One event in, one event out, in arrival order.
		//
		// This is the shape from before d9d8dd218, restored on purpose. That commit
		// added two staging queues (Unknown and Benign) drained under a ratio, and
		// 497d8bcc6 turned the ratio into ten-to-one. Under load the staging queues
		// absorbed up to 64 events per call while only one left per call, and the
		// ratio then held Benign events back behind the Unknown backlog, so
		// output_events went quiet while the enricher was still busy. There is no
		// backlog here to starve anything: the provider queue is the only queue.
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
