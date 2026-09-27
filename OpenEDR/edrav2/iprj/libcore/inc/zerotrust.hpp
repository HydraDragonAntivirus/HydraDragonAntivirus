//
// edrav2.libcore project
//
// Zero Trust Lockdown and Process Suspend/Resume Shared State
//
#pragma once
#include <atomic>
#include <mutex>
#include <string>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <windows.h>

namespace cmd {
namespace zerotrust {

	typedef NTSTATUS(NTAPI* pfnZwSuspendProcess)(HANDLE ProcessHandle);
	typedef NTSTATUS(NTAPI* pfnZwResumeProcess)(HANDLE ProcessHandle);

	inline bool SuspendProcessByPid(uint32_t pid)
	{
		if (pid == 0 || pid == 4 || pid == ::GetCurrentProcessId())
			return false;
		HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
		if (!hNtdll) return false;
		auto fnSuspend = (pfnZwSuspendProcess)::GetProcAddress(hNtdll, "ZwSuspendProcess");
		if (!fnSuspend) fnSuspend = (pfnZwSuspendProcess)::GetProcAddress(hNtdll, "NtSuspendProcess");
		if (!fnSuspend) return false;
		HANDLE hProc = ::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
		if (!hProc) return false;
		NTSTATUS st = fnSuspend(hProc);
		::CloseHandle(hProc);
		return st == 0;
	}

	inline bool ResumeProcessByPid(uint32_t pid)
	{
		if (pid == 0 || pid == 4)
			return false;
		HMODULE hNtdll = ::GetModuleHandleW(L"ntdll.dll");
		if (!hNtdll) return false;
		auto fnResume = (pfnZwResumeProcess)::GetProcAddress(hNtdll, "ZwResumeProcess");
		if (!fnResume) fnResume = (pfnZwResumeProcess)::GetProcAddress(hNtdll, "NtResumeProcess");
		if (!fnResume) return false;
		HANDLE hProc = ::OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
		if (!hProc) return false;
		NTSTATUS st = fnResume(hProc);
		::CloseHandle(hProc);
		return st == 0;
	}

	class ZeroTrustManager
	{
	private:
		ZeroTrustManager() = default;

		std::atomic<uint32_t> m_threatDetectionsCount{ 0 };
		std::atomic<bool> m_zeroTrustEnabled{ false };
		std::mutex m_mtxState;
		std::unordered_set<std::string> m_sessionWhitelist;
		std::unordered_set<uint32_t> m_restrictedPids;

		struct FileModWindow {
			uint64_t windowStartMs = 0;
			std::unordered_set<std::string> modifiedFiles;
		};
		std::unordered_map<uint32_t, FileModWindow> m_pidFileMods;

		static inline std::string toLowerPath(std::string s)
		{
			for (auto& c : s) c = (char)::tolower((unsigned char)c);
			return s;
		}

	public:
		static ZeroTrustManager& instance()
		{
			static ZeroTrustManager s_inst;
			return s_inst;
		}

		bool isEnabled() const
		{
			return m_zeroTrustEnabled.load(std::memory_order_relaxed);
		}

		void setEnabled(bool enabled)
		{
			m_zeroTrustEnabled.store(enabled, std::memory_order_relaxed);
		}

		void recordThreatDetection()
		{
			uint32_t current = m_threatDetectionsCount.fetch_add(1, std::memory_order_relaxed) + 1;
			if (current >= 20 && !isEnabled())
			{
				setEnabled(true);
				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string pipeMsg = "ZERO_TRUST_TRIGGERED:20 threats detected in system. Lockdown mode activated.\n";
					DWORD written = 0;
					::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}
			}
		}

		void addSessionWhitelist(const std::string& path)
		{
			if (path.empty()) return;
			std::lock_guard<std::mutex> lock(m_mtxState);
			m_sessionWhitelist.insert(toLowerPath(path));
		}

		bool isSessionWhitelisted(const std::string& path)
		{
			if (path.empty()) return false;
			std::lock_guard<std::mutex> lock(m_mtxState);
			return m_sessionWhitelist.find(toLowerPath(path)) != m_sessionWhitelist.end();
		}

		void addRestrictedPid(uint32_t pid)
		{
			if (pid <= 4) return;
			std::lock_guard<std::mutex> lock(m_mtxState);
			m_restrictedPids.insert(pid);
		}

		bool isRestricted(uint32_t pid)
		{
			if (pid <= 4) return false;
			std::lock_guard<std::mutex> lock(m_mtxState);
			return m_restrictedPids.find(pid) != m_restrictedPids.end();
		}

		void onProcessFileModification(uint32_t pid, const std::string& filePath)
		{
			if (pid <= 4 || filePath.empty()) return;
			std::lock_guard<std::mutex> lock(m_mtxState);
			if (m_restrictedPids.find(pid) == m_restrictedPids.end())
				return;

			uint64_t nowMs = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count();

			auto& win = m_pidFileMods[pid];
			if (win.windowStartMs == 0 || (nowMs - win.windowStartMs) > 1000)
			{
				win.windowStartMs = nowMs;
				win.modifiedFiles.clear();
			}
			win.modifiedFiles.insert(toLowerPath(filePath));

			// Guard: if modifying > 5 distinct files within 1 second -> SUSPEND IMMEDIATELY!
			if (win.modifiedFiles.size() > 5)
			{
				SuspendProcessByPid(pid);
				HANDLE hPipe = ::CreateFileW(L"\\\\.\\pipe\\HydraHipEvent",
					GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
				if (hPipe != INVALID_HANDLE_VALUE)
				{
					std::string pipeMsg = "THREAT_ALERT:VirusKov.RansomwareGuard.MassFileMod|" + filePath + "\n";
					DWORD written = 0;
					::WriteFile(hPipe, pipeMsg.data(), static_cast<DWORD>(pipeMsg.size()), &written, NULL);
					::CloseHandle(hPipe);
				}
			}
		}
	};

} // namespace zerotrust
} // namespace cmd
