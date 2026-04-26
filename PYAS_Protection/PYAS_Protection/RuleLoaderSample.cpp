// RuleLoaderSample.cpp
//
// User-mode rule loader for the fixed kernel driver.
// Build as a service/helper and run after the filesystem is available.
//
// It reads:
//   <base>\Process\*
//   <base>\File\*
//   <base>\Registry\*
// concatenates text files per category, and sends them through
// IOCTL_HYDRADRAGON_SET_RULES.
//
// Compile example:
//   cl /EHsc /std:c++17 RuleLoaderSample.cpp

#include <windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#define HYDRADRAGON_RULE_BLOB_MAGIC   0x48594452UL // 'HYDR'
#define HYDRADRAGON_RULE_BLOB_VERSION 1
#define HYDRADRAGON_RULES_FLAG_UTF16LE 0x00000001UL

#define IOCTL_HYDRADRAGON_SET_RULES \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

#pragma pack(push, 1)
struct HYDRADRAGON_RULE_BLOB {
    ULONG Magic;
    ULONG Version;
    ULONG Flags;
    ULONG ProcessRulesBytes;
    ULONG FileRulesBytes;
    ULONG RegistryRulesBytes;
};
#pragma pack(pop)

static std::wstring ReadCategory(const std::filesystem::path& dir)
{
    std::wstring result;

    if (!std::filesystem::exists(dir))
        return result;

    for (const auto& entry : std::filesystem::directory_iterator(dir))
    {
        if (!entry.is_regular_file())
            continue;

        std::wifstream file(entry.path());
        if (!file)
            continue;

        std::wstring line;
        while (std::getline(file, line))
        {
            result.append(line);
            result.push_back(L'\n');
        }
    }

    return result;
}

static void AppendBytes(std::vector<BYTE>& out, const std::wstring& text)
{
    const BYTE* begin = reinterpret_cast<const BYTE*>(text.data());
    const BYTE* end = begin + (text.size() * sizeof(wchar_t));
    out.insert(out.end(), begin, end);
}

int wmain(int argc, wchar_t** argv)
{
    std::filesystem::path base =
        L"C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\HydraDragon_Protection_Rules\\PYAS";

    if (argc >= 2)
        base = argv[1];

    std::wstring processRules = ReadCategory(base / L"Process");
    std::wstring fileRules = ReadCategory(base / L"File");
    std::wstring registryRules = ReadCategory(base / L"Registry");

    HYDRADRAGON_RULE_BLOB header = {};
    header.Magic = HYDRADRAGON_RULE_BLOB_MAGIC;
    header.Version = HYDRADRAGON_RULE_BLOB_VERSION;
    header.Flags = HYDRADRAGON_RULES_FLAG_UTF16LE;
    header.ProcessRulesBytes = static_cast<ULONG>(processRules.size() * sizeof(wchar_t));
    header.FileRulesBytes = static_cast<ULONG>(fileRules.size() * sizeof(wchar_t));
    header.RegistryRulesBytes = static_cast<ULONG>(registryRules.size() * sizeof(wchar_t));

    std::vector<BYTE> payload(sizeof(header));
    memcpy(payload.data(), &header, sizeof(header));
    AppendBytes(payload, processRules);
    AppendBytes(payload, fileRules);
    AppendBytes(payload, registryRules);

    HANDLE device = CreateFileW(
        L"\\\\.\\HydraDragonProtection",
        GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (device == INVALID_HANDLE_VALUE)
    {
        std::wcerr << L"CreateFileW failed: " << GetLastError() << L"\n";
        return 1;
    }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        device,
        IOCTL_HYDRADRAGON_SET_RULES,
        payload.data(),
        static_cast<DWORD>(payload.size()),
        nullptr,
        0,
        &bytesReturned,
        nullptr);

    DWORD err = GetLastError();
    CloseHandle(device);

    if (!ok)
    {
        std::wcerr << L"DeviceIoControl(IOCTL_HYDRADRAGON_SET_RULES) failed: " << err << L"\n";
        return 2;
    }

    std::wcout << L"Rules loaded. Process bytes=" << header.ProcessRulesBytes
               << L", File bytes=" << header.FileRulesBytes
               << L", Registry bytes=" << header.RegistryRulesBytes << L"\n";
    return 0;
}
