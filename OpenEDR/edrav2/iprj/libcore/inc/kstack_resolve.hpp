#pragma once
//
// Kernel/usermode stack symbolization WITHOUT a PDB engine.
//
// The driver ships raw return addresses (file.kernelStack, comma separated
// hex). This header resolves them to "module!Export+0xoffset" exactly like
// System Informer / Process Explorer do without PDBs:
//   1. Module ranges: EnumDeviceDrivers for kernel addresses (no symbols
//      needed, just base addresses + sizes); EnumProcessModules(pid) for
//      usermode addresses below the kernel canonical range.
//      -> "module+0xaddr" always works.
//   2. Export names: each SYS/DLL/EXE file's own PE export table parsed off
//      disk (IMAGE_EXPORT_DIRECTORY, embedded in every image) -> nearest
//      export at or below the address wins.
// Full PDB function names are NOT available this way (only exports), but
// naming the blocking filter/driver never needs PDBs. Unowned addresses
// surface as "unknown!0x..." — the rootkit/manual-mapper signal that
// ptm.local.src patterns match on.
//
// Header-only + ODR-safe (inline functions, function-local statics) so any
// static lib can include it with zero build-system changes. psapi is loaded
// dynamically (no link dependency).
//
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace cmd {
namespace kstack {

typedef BOOL (WINAPI* EnumDeviceDriversFn)(LPVOID*, DWORD, LPDWORD);
typedef DWORD (WINAPI* GetDeviceDriverBaseNameWFn)(LPVOID, LPWSTR, DWORD);
typedef BOOL (WINAPI* EnumProcessModulesFn)(HANDLE, HMODULE*, DWORD, LPDWORD);
typedef DWORD (WINAPI* GetModuleFileNameExWFn)(HANDLE, HMODULE, LPWSTR, DWORD);

struct DriverModule
{
	uint64_t base = 0;
	uint64_t size = 0; // best-effort (next base - base), 0 = unknown
	std::wstring path; // as reported (\\SystemRoot\\... form)
	std::string baseName; // lowercased file name for display
};

struct ExportEntry
{
	uint64_t rva = 0;
	std::string name;
};

struct CachedModule
{
	DriverModule mod;
	std::vector<ExportEntry> exports; // sorted by rva
	bool exportsLoaded = false;
};

inline std::mutex& modulesMutex()
{
	static std::mutex m;
	return m;
}

inline std::vector<CachedModule>& driverModules()
{
	static std::vector<CachedModule> v;
	return v;
}

inline uint64_t& driverModulesStamp()
{
	static uint64_t t = 0;
	return t;
}

struct ProcCacheEntry
{
	uint32_t pid = 0;
	uint64_t stampMs = 0;
	std::vector<CachedModule> modules; // sorted by base; size = next-base
};

inline std::vector<ProcCacheEntry>& procCache()
{
	static std::vector<ProcCacheEntry> v;
	return v;
}

inline uint64_t nowMs()
{
	return GetTickCount64();
}

inline std::string narrowLowerFileName(const std::wstring& ws)
{
	size_t pos = ws.find_last_of(L"\\/");
	std::wstring name = (pos == std::wstring::npos) ? ws : ws.substr(pos + 1);
	std::string out;
	out.reserve(name.size());
	for (wchar_t c : name)
		out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
	return out;
}

inline std::wstring expandSystemRoot(const std::wstring& ws)
{
	const wchar_t* const kPrefix = L"\\SystemRoot\\";
	if (ws.compare(0, 12, kPrefix) == 0)
	{
		wchar_t wsWinDir[MAX_PATH] = {};
		if (GetWindowsDirectoryW(wsWinDir, MAX_PATH) > 0)
			return std::wstring(wsWinDir) + L"\\" + ws.substr(12);
	}
	return ws;
}

inline HMODULE loadPsapi()
{
	static HMODULE h = ::LoadLibraryW(L"psapi.dll");
	return h;
}

// Refresh the loaded-driver list at most once per minute. Caller holds modulesMutex().
inline void refreshModulesLocked()
{
	const uint64_t now = nowMs();
	if (!driverModules().empty() && now - driverModulesStamp() < 60000)
		return;
	driverModulesStamp() = now;

	HMODULE hPsapi = loadPsapi();
	if (hPsapi == nullptr)
		return;
	auto fnEnum = (EnumDeviceDriversFn)::GetProcAddress(hPsapi, "EnumDeviceDrivers");
	auto fnName = (GetDeviceDriverBaseNameWFn)::GetProcAddress(hPsapi, "GetDeviceDriverBaseNameW");
	if (fnEnum == nullptr || fnName == nullptr)
		return;

	DWORD nNeeded = 0;
	if (!fnEnum(nullptr, 0, &nNeeded) || nNeeded == 0)
		return;
	if (nNeeded > 4096 * sizeof(LPVOID))
		return; // sanity cap
	std::vector<uint8_t> buf(nNeeded, 0);
	LPVOID* pBases = (LPVOID*)buf.data();
	const DWORD nCount = nNeeded / sizeof(LPVOID);
	if (!fnEnum(pBases, nNeeded, &nNeeded))
		return;

	std::vector<CachedModule> fresh;
	fresh.reserve(nCount);
	wchar_t wsName[MAX_PATH] = {};
	for (DWORD i = 0; i < nCount; ++i)
	{
		if (pBases[i] == nullptr)
			continue;
		wsName[0] = 0;
		if (fnName(pBases[i], wsName, MAX_PATH) == 0)
			continue;
		CachedModule m;
		m.mod.base = (uint64_t)pBases[i];
		m.mod.path = wsName;
		m.mod.baseName = narrowLowerFileName(wsName);
		fresh.push_back(std::move(m));
	}
	// Best-effort sizes: sorted by base, size = next base - base.
	std::sort(fresh.begin(), fresh.end(), [](const CachedModule& a, const CachedModule& b) {
		return a.mod.base < b.mod.base;
	});
	for (size_t i = 0; i + 1 < fresh.size(); ++i)
		fresh[i].mod.size = fresh[i + 1].mod.base - fresh[i].mod.base;
	driverModules().swap(fresh);
}

// Parse IMAGE_EXPORT_DIRECTORY of an on-disk image. Fully bounds-checked,
// no SEH needed: a corrupt/unreadable file just yields no exports.
inline void loadExportsLocked(CachedModule& m, const std::wstring& explicitPath = L"")
{
	if (m.exportsLoaded)
		return;
	m.exportsLoaded = true;

	std::wstring wsPath = explicitPath.empty() ? expandSystemRoot(m.mod.path) : explicitPath;
	if (wsPath.find(L':') == std::wstring::npos)
	{
		// Base name only: assume drivers dir (kernel side) — callers pass an
		// explicit full path for usermode modules, so this is the fallback.
		wchar_t wsWinDir[MAX_PATH] = {};
		if (GetWindowsDirectoryW(wsWinDir, MAX_PATH) == 0)
			return;
		wsPath = std::wstring(wsWinDir) + L"\\System32\\drivers\\" + wsPath;
	}
	HANDLE hFile = ::CreateFileW(wsPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
		return;
	LARGE_INTEGER fileSize = {};
	if (!::GetFileSizeEx(hFile, &fileSize) || fileSize.QuadPart <= 0
		|| fileSize.QuadPart > 256 * 1024 * 1024)
	{
		::CloseHandle(hFile);
		return;
	}
	const uint64_t nSize = (uint64_t)fileSize.QuadPart;
	HANDLE hMap = ::CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
	::CloseHandle(hFile);
	if (hMap == nullptr)
		return;
	const uint8_t* pBase = (const uint8_t*)::MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
	::CloseHandle(hMap);
	if (pBase == nullptr)
		return;

	struct Reader
	{
		const uint8_t* base;
		uint64_t size;
		bool u16(uint64_t off, uint16_t& out) const
		{
			if (off + 2 > size) return false;
			out = *(const uint16_t*)(base + off);
			return true;
		}
		bool u32(uint64_t off, uint32_t& out) const
		{
			if (off + 4 > size) return false;
			out = *(const uint32_t*)(base + off);
			return true;
		}
	};
	const Reader rd{ pBase, nSize };

	uint16_t mz = 0;
	uint32_t e_lfanew = 0, peSig = 0;
	uint16_t nSections = 0, nOptSize = 0, magic = 0;
	if (!rd.u16(0, mz) || mz != 0x5A4D) { ::UnmapViewOfFile(pBase); return; }
	if (!rd.u32(0x3C, e_lfanew) || e_lfanew > 1024 * 1024) { ::UnmapViewOfFile(pBase); return; }
	if (!rd.u32(e_lfanew, peSig) || peSig != 0x00004550) { ::UnmapViewOfFile(pBase); return; }
	if (!rd.u16((uint64_t)e_lfanew + 6, nSections) || nSections == 0 || nSections > 96) { ::UnmapViewOfFile(pBase); return; }
	if (!rd.u16((uint64_t)e_lfanew + 20, nOptSize)) { ::UnmapViewOfFile(pBase); return; }
	const uint64_t optOff = (uint64_t)e_lfanew + 24;
	if (!rd.u16(optOff, magic)) { ::UnmapViewOfFile(pBase); return; }
	const bool f64 = (magic == 0x20b);
	uint32_t expRva = 0, expSize = 0;
	if (!rd.u32(optOff + (f64 ? 112 : 96), expRva) || !rd.u32(optOff + (f64 ? 112 : 96) + 4, expSize)
		|| expRva == 0 || expSize == 0 || expSize > 1024 * 1024) { ::UnmapViewOfFile(pBase); return; }

	// RVA -> file offset via section table (immediately after optional header).
	const uint64_t secOff = optOff + nOptSize;
	auto rvaToOffset = [&](uint32_t rva, uint64_t need) -> uint64_t {
		for (uint16_t s = 0; s < nSections; ++s)
		{
			const uint64_t e = secOff + (uint64_t)s * 40;
			uint32_t vAddr = 0, vSize = 0, rawPtr = 0, rawSize = 0;
			if (!rd.u32(e + 8, vSize) || !rd.u32(e + 12, vAddr) || !rd.u32(e + 16, rawSize) || !rd.u32(e + 20, rawPtr))
				return UINT64_MAX;
			if (vSize == 0 || rawSize == 0)
				continue;
			const uint64_t span = vSize < rawSize ? vSize : rawSize;
			if (rva >= vAddr && (uint64_t)(rva - vAddr) + need <= span
				&& (uint64_t)rawPtr + (rva - vAddr) + need <= nSize)
				return (uint64_t)rawPtr + (rva - vAddr);
		}
		return UINT64_MAX;
	};
	const uint64_t expOff = rvaToOffset(expRva, 40);
	if (expOff == UINT64_MAX) { ::UnmapViewOfFile(pBase); return; }
	uint32_t nNames = 0, nFuncs = 0, addrNames = 0, addrOrdinals = 0, addrFuncs = 0;
	if (!rd.u32(expOff + 20, nFuncs) || !rd.u32(expOff + 24, nNames) || !rd.u32(expOff + 32, addrNames)
		|| !rd.u32(expOff + 36, addrOrdinals) || !rd.u32(expOff + 28, addrFuncs)
		|| nNames == 0 || nNames > 200000 || nFuncs == 0 || nFuncs > 200000) { ::UnmapViewOfFile(pBase); return; }
	const uint64_t namesOff = rvaToOffset(addrNames, (uint64_t)nNames * 4);
	const uint64_t ordinalsOff = rvaToOffset(addrOrdinals, (uint64_t)nNames * 2);
	const uint64_t funcsOff = rvaToOffset(addrFuncs, 4);
	if (namesOff == UINT64_MAX || ordinalsOff == UINT64_MAX || funcsOff == UINT64_MAX)
	{
		::UnmapViewOfFile(pBase);
		return;
	}
	for (uint32_t i = 0; i < nNames; ++i)
	{
		uint32_t nameRva = 0;
		uint16_t ord = 0;
		if (!rd.u32(namesOff + (uint64_t)i * 4, nameRva)) break;
		if (!rd.u16(ordinalsOff + (uint64_t)i * 2, ord)) break;
		if ((uint64_t)ord >= nFuncs) continue;
		const uint64_t nameOff = rvaToOffset(nameRva, 1);
		if (nameOff == UINT64_MAX) continue;
		size_t nLen = 0;
		while (nLen < 256 && nameOff + nLen < nSize && pBase[nameOff + nLen] != 0)
			++nLen;
		if (nLen == 0 || nLen >= 256 || nameOff + nLen >= nSize) continue;
		const uint64_t funcEntry = funcsOff + (uint64_t)ord * 4;
		if (funcEntry + 4 > nSize) continue;
		uint32_t funcRva = 0;
		if (!rd.u32(funcEntry, funcRva) || funcRva == 0) continue; // forwarded: skip
		ExportEntry e;
		e.rva = funcRva;
		e.name.assign((const char*)(pBase + nameOff), nLen);
		m.exports.push_back(std::move(e));
		if (m.exports.size() >= 200000)
			break;
	}
	std::sort(m.exports.begin(), m.exports.end(), [](const ExportEntry& a, const ExportEntry& b) {
		return a.rva < b.rva;
	});
	::UnmapViewOfFile(pBase);
}

inline std::string formatAddr(uint64_t addr)
{
	char buf[32] = {};
	_snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%llx", (unsigned long long)addr);
	return buf;
}

// Resolve one kernel address. Unknown owner -> "unknown!0x..." (the
// rootkit/manual-mapper signal ptm.local.src patterns match on).
inline std::string resolveOne(uint64_t addr)
{
	std::scoped_lock _lock(modulesMutex());
	refreshModulesLocked();
	const CachedModule* pFound = nullptr;
	for (auto& m : driverModules())
	{
		const uint64_t end = (m.mod.size != 0) ? (m.mod.base + m.mod.size) : (m.mod.base + 0x1000000);
		if (addr >= m.mod.base && addr < end)
		{
			pFound = &m;
			break;
		}
	}
	if (pFound == nullptr)
		return std::string("unknown!") + formatAddr(addr);
	loadExportsLocked(const_cast<CachedModule&>(*pFound));
	const uint64_t rva = addr - pFound->mod.base;
	const std::string& mod = pFound->mod.baseName.empty() ? std::string("driver") : pFound->mod.baseName;
	const ExportEntry* pBest = nullptr;
	for (const auto& e : pFound->exports)
	{
		if (e.rva > rva)
			break;
		pBest = &e;
	}
	char buf[320] = {};
	if (pBest != nullptr)
		_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s!%s+0x%llx", mod.c_str(), pBest->name.c_str(),
			(unsigned long long)(rva - pBest->rva));
	else
		_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s+0x%llx", mod.c_str(), (unsigned long long)rva);
	return buf;
}

inline void refreshProcLocked(uint32_t pid)
{
	const uint64_t now = nowMs();
	for (auto& e : procCache())
	{
		if (e.pid == pid)
		{
			if (now - e.stampMs < 60000)
				return;
			e.modules.clear();
			e.stampMs = now;
			break;
		}
	}
	HMODULE hPsapi = loadPsapi();
	if (hPsapi == nullptr)
		return;
	auto fnMods = (EnumProcessModulesFn)::GetProcAddress(hPsapi, "EnumProcessModules");
	auto fnName = (GetModuleFileNameExWFn)::GetProcAddress(hPsapi, "GetModuleFileNameExW");
	if (fnMods == nullptr || fnName == nullptr)
		return;
	HANDLE hProc = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProc == nullptr)
		return;
	DWORD nNeeded = 0;
	if (!fnMods(hProc, nullptr, 0, &nNeeded) || nNeeded == 0
		|| nNeeded > 8192 * sizeof(HMODULE))
	{
		::CloseHandle(hProc);
		return;
	}
	std::vector<uint8_t> buf(nNeeded, 0);
	HMODULE* pMods = (HMODULE*)buf.data();
	const DWORD nCount = nNeeded / sizeof(HMODULE);
	if (!fnMods(hProc, pMods, nNeeded, &nNeeded))
	{
		::CloseHandle(hProc);
		return;
	}
	ProcCacheEntry entry;
	entry.pid = pid;
	entry.stampMs = now;
	wchar_t wsPath[MAX_PATH] = {};
	for (DWORD i = 0; i < nCount; ++i)
	{
		if (pMods[i] == nullptr)
			continue;
		wsPath[0] = 0;
		if (fnName(hProc, pMods[i], wsPath, MAX_PATH) == 0)
			continue;
		CachedModule m;
		m.mod.base = (uint64_t)pMods[i];
		m.mod.path = wsPath;
		m.mod.baseName = narrowLowerFileName(wsPath);
		entry.modules.push_back(std::move(m));
	}
	::CloseHandle(hProc);
	std::sort(entry.modules.begin(), entry.modules.end(),
		[](const CachedModule& a, const CachedModule& b) { return a.mod.base < b.mod.base; });
	for (size_t i = 0; i + 1 < entry.modules.size(); ++i)
		entry.modules[i].mod.size = entry.modules[i + 1].mod.base - entry.modules[i].mod.base;
	bool replaced = false;
	for (auto& e : procCache())
	{
		if (e.pid == pid)
		{
			e = std::move(entry);
			replaced = true;
			break;
		}
	}
	if (!replaced)
	{
		if (procCache().size() >= 64)
			procCache().erase(procCache().begin());
		procCache().push_back(std::move(entry));
	}
}

// Resolve one usermode address inside the source pid. Unbacked memory
// (injected shellcode has no module) surfaces as unknown!... like kernel.
inline std::string resolveUserOne(uint64_t addr, uint32_t pid)
{
	if (pid == 0)
		return std::string("unknown!") + formatAddr(addr);
	std::scoped_lock _lock(modulesMutex());
	refreshProcLocked(pid);
	const std::vector<CachedModule>* pList = nullptr;
	for (auto& e : procCache())
	{
		if (e.pid == pid)
		{
			pList = &e.modules;
			break;
		}
	}
	if (pList == nullptr)
		return std::string("unknown!") + formatAddr(addr);
	const CachedModule* pFound = nullptr;
	for (auto& m : *pList)
	{
		const uint64_t end = (m.mod.size != 0) ? (m.mod.base + m.mod.size) : (m.mod.base + 0x1000000);
		if (addr >= m.mod.base && addr < end)
		{
			pFound = &m;
			break;
		}
	}
	if (pFound == nullptr)
		return std::string("unknown!") + formatAddr(addr);
	// Usemmode modules resolve by explicit on-disk path (never the drivers dir).
	loadExportsLocked(const_cast<CachedModule&>(*pFound), pFound->mod.path);
	const uint64_t rva = addr - pFound->mod.base;
	const std::string& mod = pFound->mod.baseName.empty() ? std::string("module") : pFound->mod.baseName;
	const ExportEntry* pBest = nullptr;
	for (const auto& e : pFound->exports)
	{
		if (e.rva > rva)
			break;
		pBest = &e;
	}
	char buf[320] = {};
	if (pBest != nullptr)
		_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s!%s+0x%llx", mod.c_str(), pBest->name.c_str(),
			(unsigned long long)(rva - pBest->rva));
	else
		_snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s+0x%llx", mod.c_str(), (unsigned long long)rva);
	return buf;
}

inline bool isKernelAddr(uint64_t addr)
{
	return addr >= 0x800000000000ULL; // x64 canonical higher half
}

inline std::string resolveStack(const std::string& csvHex, size_t nMax = 6)
{
	std::string out;
	size_t pos = 0, done = 0;
	while (done < nMax)
	{
		size_t comma = csvHex.find(',', pos);
		std::string tok = (comma == std::string::npos) ? csvHex.substr(pos) : csvHex.substr(pos, comma - pos);
		size_t b = tok.find_first_not_of(" \t\r\n");
		if (b == std::string::npos)
		{
			if (comma == std::string::npos)
				break;
			pos = comma + 1;
			continue;
		}
		size_t e = tok.find_last_not_of(" \t\r\n");
		tok = tok.substr(b, e - b + 1);
		uint64_t addr = 0;
		try { addr = std::stoull(tok, nullptr, 16); }
		catch (...) { addr = 0; }
		if (addr == 0)
		{
			if (comma == std::string::npos)
				break;
			pos = comma + 1;
			continue;
		}
		if (!out.empty())
			out += "; ";
		out += resolveOne(addr);
		++done;
		if (comma == std::string::npos)
			break;
		pos = comma + 1;
	}
	return out;
}

// Pid-aware entry: kernel-canonical addresses resolve against loaded drivers,
// everything else against the source pid's modules (future usermode reporters
// share this pipeline and format).
inline std::string resolveStackForPid(const std::string& csvHex, uint32_t pid, size_t nMax = 6)
{
	bool hasUser = false;
	{
		size_t pos = 0;
		while (true)
		{
			size_t comma = csvHex.find(',', pos);
			std::string tok = (comma == std::string::npos) ? csvHex.substr(pos) : csvHex.substr(pos, comma - pos);
			size_t b = tok.find_first_not_of(" \t\r\n");
			if (b != std::string::npos)
			{
				size_t e = tok.find_last_not_of(" \t\r\n");
				try
				{
					if (std::stoull(tok.substr(b, e - b + 1), nullptr, 16) < 0x800000000000ULL)
						hasUser = true;
				}
				catch (...) {}
			}
			if (hasUser || comma == std::string::npos)
				break;
			pos = comma + 1;
		}
	}
	if (!hasUser || pid == 0)
		return resolveStack(csvHex, nMax);

	std::string out;
	size_t pos = 0, done = 0;
	while (done < nMax)
	{
		size_t comma = csvHex.find(',', pos);
		std::string tok = (comma == std::string::npos) ? csvHex.substr(pos) : csvHex.substr(pos, comma - pos);
		size_t b = tok.find_first_not_of(" \t\r\n");
		if (b == std::string::npos)
		{
			if (comma == std::string::npos)
				break;
			pos = comma + 1;
			continue;
		}
		size_t e = tok.find_last_not_of(" \t\r\n");
		tok = tok.substr(b, e - b + 1);
		uint64_t addr = 0;
		try { addr = std::stoull(tok, nullptr, 16); }
		catch (...) { addr = 0; }
		if (addr == 0)
		{
			if (comma == std::string::npos)
				break;
			pos = comma + 1;
			continue;
		}
		if (!out.empty())
			out += "; ";
		out += isKernelAddr(addr) ? resolveOne(addr) : resolveUserOne(addr, pid);
		++done;
		if (comma == std::string::npos)
			break;
		pos = comma + 1;
	}
	return out;
}

} // namespace kstack
} // namespace cmd
