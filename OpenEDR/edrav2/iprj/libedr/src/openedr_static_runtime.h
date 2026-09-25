#pragma once

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace cmd::openedr_static
{
	inline std::string ToUtf8(const std::wstring& value)
	{
		if (value.empty())
			return {};
		int size = ::WideCharToMultiByte(CP_UTF8, 0, value.data(),
			static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
		if (size <= 0)
			return "<path conversion failed>";
		std::string result(static_cast<size_t>(size), '\0');
		::WideCharToMultiByte(CP_UTF8, 0, value.data(),
			static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
		return result;
	}

	inline bool WriteLog(const char* event, const std::string& details) noexcept
	{
		try
		{
			wchar_t programData[MAX_PATH] = {};
			DWORD length = ::GetEnvironmentVariableW(L"ProgramData", programData, MAX_PATH);
			if (length == 0 || length >= MAX_PATH)
				return false;

			const std::filesystem::path dir = std::filesystem::path(programData) / L"edrsvc" / L"log";
			std::error_code ec;
			std::filesystem::create_directories(dir, ec);
			if (ec)
				return false;

			static std::mutex mutex;
			std::lock_guard<std::mutex> lock(mutex);
			const auto path = dir / L"openedr_static.log";
			bool rotate = false;
			WIN32_FILE_ATTRIBUTE_DATA attributes = {};
			if (::GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
			{
				ULARGE_INTEGER size = {};
				size.LowPart = attributes.nFileSizeLow;
				size.HighPart = attributes.nFileSizeHigh;
				rotate = size.QuadPart >= 8ULL * 1024 * 1024;
			}

			SYSTEMTIME now = {};
			::GetLocalTime(&now);
			std::ofstream output(path, std::ios::binary |
				(rotate ? std::ios::trunc : std::ios::app));
			if (!output)
				return false;

			if (rotate)
				output << "log rotated at 8 MiB\n";
			output << now.wYear << '-';
			output.width(2); output.fill('0'); output << now.wMonth << '-';
			output.width(2); output << now.wDay << ' ';
			output.width(2); output << now.wHour << ':';
			output.width(2); output << now.wMinute << ':';
			output.width(2); output << now.wSecond << '.';
			output.width(3); output << now.wMilliseconds;
			output << " [" << event << "] ";
			for (char ch : details)
				output.put((ch == '\r' || ch == '\n') ? ' ' : ch);
			output << '\n';
			return output.good();
		}
		catch (...)
		{
			return false;
		}
	}

	inline HMODULE LoadModule(const char* caller, DWORD* errorOut = nullptr) noexcept
	{
		try
		{
			if (HMODULE loaded = ::GetModuleHandleW(L"openedr_static.dll"))
			{
				if (errorOut)
					*errorOut = ERROR_SUCCESS;
				wchar_t modulePath[MAX_PATH] = {};
				DWORD length = ::GetModuleFileNameW(loaded, modulePath, MAX_PATH);
				WriteLog("load", std::string(caller) + " already loaded: " +
					(length > 0 && length < MAX_PATH ? ToUtf8(modulePath) : "<path unavailable>"));
				return loaded;
			}

			std::vector<std::pair<std::wstring, DWORD>> failures;
			auto tryPath = [&failures](const std::wstring& path) -> HMODULE
			{
				if (path.empty())
					return nullptr;
				HMODULE module = ::LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
				if (!module)
				{
					const DWORD error = ::GetLastError();
					failures.emplace_back(path, error);
				}
				return module;
			};

			std::wstring exePath(MAX_PATH, L'\0');
			DWORD exeLength = ::GetModuleFileNameW(nullptr, exePath.data(), MAX_PATH);
			if (exeLength > 0 && exeLength < MAX_PATH)
			{
				exePath.resize(exeLength);
				HMODULE module = tryPath((std::filesystem::path(exePath).parent_path() /
					L"openedr_static.dll").wstring());
				if (module)
				{
					if (errorOut)
						*errorOut = ERROR_SUCCESS;
					wchar_t modulePath[MAX_PATH] = {};
					DWORD length = ::GetModuleFileNameW(module, modulePath, MAX_PATH);
					WriteLog("load", std::string(caller) + " loaded: " +
						(length > 0 && length < MAX_PATH ? ToUtf8(modulePath) : "<path unavailable>"));
					return module;
				}
			}
			else
				failures.emplace_back(L"<service executable path>", ::GetLastError());

			wchar_t programFiles[MAX_PATH] = {};
			DWORD pfLength = ::GetEnvironmentVariableW(L"ProgramFiles", programFiles, MAX_PATH);
			if (pfLength > 0 && pfLength < MAX_PATH)
			{
				const auto path = (std::filesystem::path(programFiles) /
					L"HydraDragonAntivirus" / L"OpenEDR" / L"openedr_static.dll").wstring();
				HMODULE module = tryPath(path);
				if (module)
				{
					if (errorOut)
						*errorOut = ERROR_SUCCESS;
					wchar_t modulePath[MAX_PATH] = {};
					DWORD length = ::GetModuleFileNameW(module, modulePath, MAX_PATH);
					WriteLog("load", std::string(caller) + " loaded: " +
						(length > 0 && length < MAX_PATH ? ToUtf8(modulePath) : "<path unavailable>"));
					return module;
				}
			}
			else
				failures.emplace_back(L"%ProgramFiles%", ::GetLastError());

			std::ostringstream message;
			message << caller << " failed to load openedr_static.dll";
			for (const auto& failure : failures)
				message << "; path=" << ToUtf8(failure.first) << " win32=" << failure.second;
			static std::atomic<bool> failureLogged{ false };
			if (!failureLogged.exchange(true))
				WriteLog("load-failed", message.str());
			if (errorOut)
				*errorOut = failures.empty() ? ERROR_MOD_NOT_FOUND : failures.back().second;
		}
		catch (...)
		{
			WriteLog("load-failed", std::string(caller) + " loader raised an exception");
			if (errorOut)
				*errorOut = ERROR_GEN_FAILURE;
		}
		return nullptr;
	}

	inline HMODULE EnsureInitialized(const char* caller, DWORD* errorOut = nullptr) noexcept
	{
		static std::mutex mutex;
		static HMODULE module = nullptr;
		static DWORD lastError = ERROR_SUCCESS;
		static ULONGLONG lastAttempt = 0;
		std::lock_guard<std::mutex> lock(mutex);
		if (module)
		{
			if (errorOut)
				*errorOut = ERROR_SUCCESS;
			return module;
		}

		const ULONGLONG now = ::GetTickCount64();
		if (lastAttempt != 0 && now - lastAttempt < 5000)
		{
			if (errorOut)
				*errorOut = lastError;
			return nullptr;
		}
		lastAttempt = now;

		module = LoadModule(caller, &lastError);
		if (!module)
		{
			if (errorOut)
				*errorOut = lastError;
			return nullptr;
		}

		auto init = reinterpret_cast<int32_t (*)(const char*)>(
			::GetProcAddress(module, "openedr_static_init"));
		if (!init)
		{
			lastError = ERROR_PROC_NOT_FOUND;
			WriteLog("exports-missing", std::string(caller) + " missing openedr_static_init");
			module = nullptr;
			if (errorOut)
				*errorOut = lastError;
			return nullptr;
		}

		const int result = init(nullptr);
		if (result != 0)
		{
			lastError = ERROR_DLL_INIT_FAILED;
			WriteLog("init-failed", std::string(caller) + " openedr_static_init returned " + std::to_string(result));
			module = nullptr;
			if (errorOut)
				*errorOut = lastError;
			return nullptr;
		}

		lastError = ERROR_SUCCESS;
		WriteLog("init", std::string(caller) + " engine initialized; default rules path is DLL directory");
		if (errorOut)
			*errorOut = ERROR_SUCCESS;
		return module;
	}
}
