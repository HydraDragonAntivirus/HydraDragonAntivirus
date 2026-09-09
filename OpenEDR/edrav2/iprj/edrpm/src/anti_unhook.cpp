#include "pch.h"
#include "anti_unhook.h"
#include "clr_hook.h"
#include "injection.h"
#include "hookapi.h"
#include <vector>
#include <mutex>

namespace cmd {
namespace edrpm {

struct WatchedHook
{
    std::string moduleName;
    std::string funcName;
    PVOID address = nullptr;
    uint8_t expectedBytes[16] = {0};
    size_t checkSize = 16;
    bool hasBaseline = false;
};

static HANDLE g_hWatchdogThread = nullptr;
static HANDLE g_hStopWatchdogEvent = nullptr;
static std::atomic<bool> g_isWatchdogRunning = false;

// Thread-safe list of watched hooks
static CRITICAL_SECTION g_csWatchedHooks;
static std::vector<WatchedHook> g_watchedHooks;

// ntdll.dll .text section integrity baseline (Sanctum model)
static const uint8_t* g_pNtdllTextBase = nullptr;
static size_t g_ntdllTextSize = 0;
static std::string g_baselineNtdllHash;
static bool g_hasNtdllBaseline = false;

static bool InitializeNtdllBaseline()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
        return false;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return false;

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (strncmp((const char*)sec->Name, ".text", 5) == 0)
            {
                g_pNtdllTextBase = (const uint8_t*)((BYTE*)hNtdll + sec->VirtualAddress);
                g_ntdllTextSize = sec->Misc.VirtualSize;
                break;
            }
        }

        if (g_pNtdllTextBase && g_ntdllTextSize > 0)
        {
            g_baselineNtdllHash = ComputeSha1(g_pNtdllTextBase, g_ntdllTextSize);
            g_hasNtdllBaseline = true;
            dbgPrint("[OpenEDR::ANTI_UNHOOK] NTDLL .text baseline hash: " + g_baselineNtdllHash);
            return true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        g_hasNtdllBaseline = false;
    }

    return false;
}

std::string GetNtdllTextHash()
{
    return g_baselineNtdllHash;
}

bool RegisterHookToWatch(const char* moduleName, const char* funcName, PVOID address, size_t checkSize)
{
    if (!address || !funcName || !moduleName)
        return false;

    WatchedHook hook;
    hook.moduleName = moduleName;
    hook.funcName = funcName;
    hook.address = address;
    hook.checkSize = (checkSize > 16) ? 16 : checkSize;

    __try
    {
        memcpy(hook.expectedBytes, address, hook.checkSize);
        hook.hasBaseline = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        hook.hasBaseline = false;
        return false;
    }

    EnterCriticalSection(&g_csWatchedHooks);
    // Avoid duplicate registration for same address
    for (auto& existing : g_watchedHooks)
    {
        if (existing.address == address)
        {
            memcpy(existing.expectedBytes, hook.expectedBytes, hook.checkSize);
            existing.hasBaseline = true;
            LeaveCriticalSection(&g_csWatchedHooks);
            return true;
        }
    }
    g_watchedHooks.push_back(hook);
    LeaveCriticalSection(&g_csWatchedHooks);

    dbgPrint(std::string("[OpenEDR::ANTI_UNHOOK] Registered watchdog for <") + moduleName + "!" + funcName + ">");
    return true;
}

static void PopulateDefaultWatchedHooks()
{
    // 1. CLR nLoadImage
    PVOID pClrLoadImage = GetHookedLoadImageAddress();
    if (pClrLoadImage)
    {
        RegisterHookToWatch("clr.dll", "nLoadImage", pClrLoadImage, 16);
    }

    // 2. Critical NTDLL Hooks
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        static const char* ntdllApis[] = {
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtCreateFile",
            "NtSetInformationThread"
        };
        for (const auto& apiName : ntdllApis)
        {
            FARPROC pfn = GetProcAddress(hNtdll, apiName);
            if (pfn)
            {
                RegisterHookToWatch("ntdll.dll", apiName, (PVOID)pfn, 16);
            }
        }
    }

    // 3. User32 / Injection Hooks
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32)
    {
        static const char* user32Apis[] = {
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "GetKeyboardState",
            "GetKeyState",
            "GetAsyncKeyState"
        };
        for (const auto& apiName : user32Apis)
        {
            FARPROC pfn = GetProcAddress(hUser32, apiName);
            if (pfn)
            {
                RegisterHookToWatch("user32.dll", apiName, (PVOID)pfn, 16);
            }
        }
    }
}

static DWORD WINAPI AntiUnhookWatchdogWorker(LPVOID /*param*/)
{
    dbgPrint("[OpenEDR] Universal Anti-Unhook Watchdog thread started.");

    // Initial baseline capture
    InitializeNtdllBaseline();
    PopulateDefaultWatchedHooks();

    while (g_isWatchdogRunning)
    {
        DWORD waitRes = WaitForSingleObject(g_hStopWatchdogEvent, 1000); // 1-second integrity check interval
        if (waitRes == WAIT_OBJECT_0)
        {
            break; // Stop event signaled
        }

        // Dynamically track clr.dll if it was loaded later
        PVOID pClrLoadImage = GetHookedLoadImageAddress();
        if (pClrLoadImage)
        {
            bool alreadyRegistered = false;
            EnterCriticalSection(&g_csWatchedHooks);
            for (const auto& h : g_watchedHooks)
            {
                if (h.address == pClrLoadImage)
                {
                    alreadyRegistered = true;
                    break;
                }
            }
            LeaveCriticalSection(&g_csWatchedHooks);

            if (!alreadyRegistered)
            {
                RegisterHookToWatch("clr.dll", "nLoadImage", pClrLoadImage, 16);
            }
        }

        //
        // 1. NTDLL .text Section Hash Check (Sanctum Model)
        // Detects full/partial module unhooking via disk reload (Perun's Fart, Tartarus Gate, etc.)
        //
        if (g_hasNtdllBaseline && g_pNtdllTextBase && g_ntdllTextSize > 0)
        {
            __try
            {
                std::string currentNtdllHash = ComputeSha1(g_pNtdllTextBase, g_ntdllTextSize);
                if (!currentNtdllHash.empty() && currentNtdllHash != g_baselineNtdllHash)
                {
                    std::string alert = "[OpenEDR::ANTI_UNHOOK] CRITICAL: ntdll.dll .text section modification detected! "
                                        "(Malware unhooking or module remapping attempt). Baseline: " +
                                        g_baselineNtdllHash + ", Current: " + currentNtdllHash;
                    logError(alert, ErrorType::Warning);

                    // Re-baseline to avoid spamming alerts in infinite loop
                    g_baselineNtdllHash = currentNtdllHash;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }

        //
        // 2. Individual Hook Bytes Integrity Check & Self-Healing
        // Checks whether detour jump opcodes were overwritten
        //
        EnterCriticalSection(&g_csWatchedHooks);
        for (auto& hook : g_watchedHooks)
        {
            if (!hook.hasBaseline || !hook.address)
                continue;

            bool isTampered = false;
            __try
            {
                if (memcmp(hook.address, hook.expectedBytes, hook.checkSize) != 0)
                {
                    isTampered = true;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                isTampered = false;
            }

            if (isTampered)
            {
                std::string errMsg = "[OpenEDR::ANTI_UNHOOK] CRITICAL: Hook tampering detected on <" +
                                     hook.moduleName + "!" + hook.funcName +
                                     ">! Evasive unhooking attempt in progress. Initiating Self-Healing...";
                logError(errMsg, ErrorType::Warning);

                // Self-Healing Logic:
                if (hook.funcName == "nLoadImage")
                {
                    if (RehookLoadImage())
                    {
                        __try
                        {
                            memcpy(hook.expectedBytes, hook.address, hook.checkSize);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {}
                        logError("[OpenEDR::ANTI_UNHOOK] Self-healing succeeded: clr.dll!nLoadImage re-hooked!", ErrorType::Info);
                    }
                }
                else
                {
                    // Restore the expected detour bytes directly in memory
                    DWORD oldProtect = 0;
                    if (VirtualProtect(hook.address, hook.checkSize, PAGE_EXECUTE_READWRITE, &oldProtect))
                    {
                        __try
                        {
                            memcpy(hook.address, hook.expectedBytes, hook.checkSize);
                            FlushInstructionCache(GetCurrentProcess(), hook.address, hook.checkSize);
                            logError("[OpenEDR::ANTI_UNHOOK] Self-healing succeeded: Restored detour bytes for <" +
                                     hook.moduleName + "!" + hook.funcName + ">!", ErrorType::Info);
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER)
                        {
                            logError("[OpenEDR::ANTI_UNHOOK] Failed to write self-healing bytes for <" +
                                     hook.moduleName + "!" + hook.funcName + ">!", ErrorType::Error);
                        }
                        VirtualProtect(hook.address, hook.checkSize, oldProtect, &oldProtect);
                    }
                }
            }
        }
        LeaveCriticalSection(&g_csWatchedHooks);
    }

    dbgPrint("[OpenEDR] Universal Anti-Unhook Watchdog thread exiting.");
    return 0;
}

bool StartAntiUnhookWatchdog()
{
    if (g_isWatchdogRunning.exchange(true))
    {
        return true;
    }

    InitializeCriticalSection(&g_csWatchedHooks);

    g_hStopWatchdogEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g_hStopWatchdogEvent)
    {
        DeleteCriticalSection(&g_csWatchedHooks);
        g_isWatchdogRunning = false;
        return false;
    }

    g_hWatchdogThread = CreateThread(NULL, 0, AntiUnhookWatchdogWorker, NULL, 0, NULL);
    if (!g_hWatchdogThread)
    {
        CloseHandle(g_hStopWatchdogEvent);
        g_hStopWatchdogEvent = nullptr;
        DeleteCriticalSection(&g_csWatchedHooks);
        g_isWatchdogRunning = false;
        return false;
    }

    return true;
}

void StopAntiUnhookWatchdog()
{
    if (g_isWatchdogRunning.exchange(false))
    {
        if (g_hStopWatchdogEvent)
        {
            SetEvent(g_hStopWatchdogEvent);
        }

        if (g_hWatchdogThread)
        {
            WaitForSingleObject(g_hWatchdogThread, 2000);
            CloseHandle(g_hWatchdogThread);
            g_hWatchdogThread = nullptr;
        }

        if (g_hStopWatchdogEvent)
        {
            CloseHandle(g_hStopWatchdogEvent);
            g_hStopWatchdogEvent = nullptr;
        }

        EnterCriticalSection(&g_csWatchedHooks);
        g_watchedHooks.clear();
        LeaveCriticalSection(&g_csWatchedHooks);
        DeleteCriticalSection(&g_csWatchedHooks);

        g_hasNtdllBaseline = false;
        g_pNtdllTextBase = nullptr;
        g_ntdllTextSize = 0;
        g_baselineNtdllHash.clear();
    }
}

bool IsAntiUnhookWatchdogRunning()
{
    return g_isWatchdogRunning;
}

} // namespace edrpm
} // namespace cmd
