#include "pch.h"
#include "clr_hook.h"
#include "hookapi.h"
#include "injection.h"
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace cmd {
namespace edrpm {

//
// Standalone, zero-dependency SHA-1 Implementation (RFC 3174)
//
namespace sha1 {

struct Sha1Context
{
    uint32_t state[5];
    uint32_t count[2];
    uint8_t buffer[64];
};

#define SHA1_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void Sha1Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];
    uint32_t w[80];

    for (int i = 0; i < 16; i++)
    {
        w[i] = ((uint32_t)buffer[i * 4] << 24) |
               ((uint32_t)buffer[i * 4 + 1] << 16) |
               ((uint32_t)buffer[i * 4 + 2] << 8) |
               ((uint32_t)buffer[i * 4 + 3]);
    }

    for (int i = 16; i < 80; i++)
    {
        w[i] = SHA1_ROL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)
        {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }

        uint32_t temp = SHA1_ROL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = SHA1_ROL(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

static void Sha1Init(Sha1Context* context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

static void Sha1Update(Sha1Context* context, const uint8_t* data, size_t len)
{
    size_t i = 0;
    size_t j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += (uint32_t)(len << 3)) < (len << 3))
        context->count[1]++;
    context->count[1] += (uint32_t)(len >> 29);

    if ((j + len) > 63)
    {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        Sha1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
        {
            Sha1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    memcpy(&context->buffer[j], &data[i], len - i);
}

static void Sha1Final(uint8_t digest[20], Sha1Context* context)
{
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++)
    {
        finalcount[i] = (uint8_t)((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    }
    uint8_t c = 0x80;
    Sha1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0x00;
        Sha1Update(context, &c, 1);
    }
    Sha1Update(context, finalcount, 8);
    for (int i = 0; i < 20; i++)
    {
        digest[i] = (uint8_t)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    }
}

} // namespace sha1

std::string ComputeSha1(const uint8_t* data, size_t size)
{
    if (!data || size == 0)
        return "";

    sha1::Sha1Context ctx;
    sha1::Sha1Init(&ctx);
    sha1::Sha1Update(&ctx, data, size);
    uint8_t digest[20] = {0};
    sha1::Sha1Final(digest, &ctx);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 20; i++)
    {
        ss << std::setw(2) << (int)digest[i];
    }
    return ss.str();
}

//
// Typedef for AssemblyNative::LoadImage
//
typedef LPVOID (*FnAssemblyNative_LoadImage)(
    LPVOID pBytesUNSAFE,
    LPVOID pEvidenceUNSAFE,
    LPVOID stackMark,
    BOOL fIntrospection,
    BOOL fSecurityCheck,
    DWORD securityContextSource,
    LPVOID pDomainPair
);

static FnAssemblyNative_LoadImage g_fnRawLoadImage = nullptr;
static PVOID g_pTargetLoadImage = nullptr;
static std::atomic<bool> g_isClrHooked = false;
static PVOID g_pLdrCookie = nullptr;

//
// Memory scan helper
//
static LPVOID ScanMemoryForPattern(LPVOID startAddr, DWORD searchSize, const BYTE* pattern, DWORD patternLen)
{
    __try
    {
        for (DWORD offset = 0; offset <= searchSize - patternLen; offset++)
        {
            BOOL match = TRUE;
            for (DWORD idx = 0; idx < patternLen; idx++)
            {
                if (*((const BYTE*)startAddr + offset + idx) != pattern[idx])
                {
                    match = FALSE;
                    break;
                }
            }
            if (match)
            {
                return (LPVOID)((DWORD_PTR)startAddr + offset);
            }
        }
        return nullptr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }
}

//
// Resolve unexported AssemblyNative::LoadImage via ECall method table scanning
// (Technique documented by Matthew Graeber & hwbp)
//
static LPVOID ResolveInternalCallFromClr(HMODULE hClr, const char* funcName)
{
    if (!hClr || !funcName)
        return nullptr;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hClr;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hClr + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        DWORD modSize = nt->OptionalHeader.SizeOfImage;
        DWORD nameLen = (DWORD)strlen(funcName) + 1;

        // 1. Scan for the ASCII string ("nLoadImage\0")
        LPVOID nameLocation = ScanMemoryForPattern((LPVOID)hClr, modSize, (const BYTE*)funcName, nameLen);
        if (!nameLocation)
        {
            return nullptr;
        }

        DWORD_PTR searchPointer = (DWORD_PTR)nameLocation;

        // 2. Scan for a pointer to that string in the ECall table
        for (DWORD i = 0; i < modSize - sizeof(DWORD_PTR); i += sizeof(DWORD_PTR))
        {
            DWORD_PTR* currentPtr = (DWORD_PTR*)((BYTE*)hClr + i);
            if (*currentPtr == searchPointer)
            {
                // In CLR ECall table entry, the function pointer is immediately before the string pointer
                if (i >= sizeof(DWORD_PTR))
                {
                    DWORD_PTR* prevPtr = currentPtr - 1;
                    DWORD_PTR funcCandidate = *prevPtr;

                    DWORD_PTR minAddr = (DWORD_PTR)hClr;
                    DWORD_PTR maxAddr = minAddr + modSize;

                    if (funcCandidate >= minAddr && funcCandidate < maxAddr)
                    {
                        return (LPVOID)funcCandidate;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return nullptr;
    }

    return nullptr;
}

//
// Inspection & Active Blocking Logic
//
static ClrScanVerdict InspectDotNetAssembly(
    const uint8_t* peData,
    size_t peSize,
    DotNetAssemblyInfo& outInfo)
{
    outInfo.dataSize = peSize;
    outInfo.isPeValid = false;
    outInfo.isBlocked = false;

    if (!peData || peSize < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32))
    {
        return ClrScanVerdict::Clean;
    }

    // Validate DOS & NT PE headers
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return ClrScanVerdict::Clean;
    }

    if (dos->e_lfanew < sizeof(IMAGE_DOS_HEADER) || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > peSize)
    {
        return ClrScanVerdict::Clean;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        return ClrScanVerdict::Clean;
    }

    outInfo.isPeValid = true;
    outInfo.sha1Hash = ComputeSha1(peData, peSize);

    // Heuristic & Known Evasive Pattern Checks
    // Search for AMSI patching and well-known evasive offensive tools
    static const char* s_knownMaliciousIndicators[] = {
        "AmsiScanBuffer",
        "amsiInitFailed",
        "AmsiUtils",
        "PatchAmsi",
        "CobaltStrike",
        "Rubeus",
        "Mimikatz",
        "SafetyKatz",
        "SharpKatz",
        "SharpDump",
        "Seatbelt",
        "GhostPack"
    };

    std::string peString((const char*)peData, std::min<size_t>(peSize, 0x100000)); // scan up to 1MB
    for (const auto& indicator : s_knownMaliciousIndicators)
    {
        if (peString.find(indicator) != std::string::npos)
        {
            outInfo.detectedReason = std::string("Heuristic.EvasiveDotNet.") + indicator;
            outInfo.isBlocked = true;
            return ClrScanVerdict::Malicious;
        }
    }

    return ClrScanVerdict::Clean;
}

//
// Safe extraction helper (contains __try, NO C++ objects with destructors to avoid C2712)
//
static bool TryExtractByteArray(LPVOID pBytesUNSAFE, const uint8_t*& outData, DWORD& outLength)
{
    if (!pBytesUNSAFE)
        return false;

    __try
    {
        const size_t lengthOffset = (sizeof(void*) == 8) ? 8 : 4;
        const size_t dataOffset   = (sizeof(void*) == 8) ? 16 : 8;

        DWORD arrayLength = *(DWORD*)((BYTE*)pBytesUNSAFE + lengthOffset);
        const uint8_t* arrayData = (const uint8_t*)((BYTE*)pBytesUNSAFE + dataOffset);

        if (arrayLength > 0 && arrayLength < 0x20000000) // Sanity check: < 512 MB
        {
            outData = arrayData;
            outLength = arrayLength;
            return true;
        }
        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

//
// Detour Callback for nLoadImage
//
static LPVOID Detour_nLoadImage(
    LPVOID pBytesUNSAFE,
    LPVOID pEvidenceUNSAFE,
    LPVOID stackMark,
    BOOL fIntrospection,
    BOOL fSecurityCheck,
    DWORD securityContextSource,
    LPVOID pDomainPair)
{
    DotNetAssemblyInfo info;
    bool shouldBlock = false;

    const uint8_t* arrayData = nullptr;
    DWORD arrayLength = 0;
    if (TryExtractByteArray(pBytesUNSAFE, arrayData, arrayLength))
    {
        ClrScanVerdict verdict = InspectDotNetAssembly(arrayData, arrayLength, info);
        if (verdict == ClrScanVerdict::Malicious)
        {
            shouldBlock = true;
        }
    }

    if (shouldBlock)
    {
        // Log telemetry and detection event
        std::string alert = "[OpenEDR::CLR_HOOK] BLOCKED malicious in-memory .NET assembly load! SHA1: " +
                            info.sha1Hash + ", Reason: " + info.detectedReason;
        logError(alert, ErrorType::Warning);

        // ACTIVE BLOCKING: Return NULL to fail the assembly load cleanly inside CLR!
        // The .NET runtime will throw BadImageFormatException / FileLoadException to caller.
        return nullptr;
    }

    // Pass through to original AssemblyNative::LoadImage
    if (g_fnRawLoadImage)
    {
        return g_fnRawLoadImage(
            pBytesUNSAFE,
            pEvidenceUNSAFE,
            stackMark,
            fIntrospection,
            fSecurityCheck,
            securityContextSource,
            pDomainPair
        );
    }

    return nullptr;
}

static bool ApplyHookToLoadImage(LPVOID fnAddress)
{
    if (!fnAddress)
        return false;

    if (g_isClrHooked.exchange(true))
        return true;

    g_pTargetLoadImage = fnAddress;
    g_fnRawLoadImage = (FnAssemblyNative_LoadImage)fnAddress;

    bool attached = detours::HookCode(g_pTargetLoadImage, (LPVOID)&Detour_nLoadImage, (LPVOID*)&g_fnRawLoadImage);

    if (attached)
    {
        dbgPrint("[OpenEDR] Successfully hooked clr.dll!nLoadImage at " + std::to_string((uintptr_t)fnAddress));
        return true;
    }
    else
    {
        g_isClrHooked = false;
        logError("[OpenEDR] Failed to hook clr.dll!nLoadImage", ErrorType::Error);
        return false;
    }
}

//
// DLL notification callback for dynamically loaded clr.dll
//
typedef struct _LDR_DLL_NOTIFICATION_DATA_LOADED {
    ULONG Flags;
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_NOTIFICATION_DATA_LOADED, *PLDR_DLL_NOTIFICATION_DATA_LOADED;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_NOTIFICATION_DATA_LOADED Loaded;
    struct {
        ULONG Flags;
        PCUNICODE_STRING FullDllName;
        PCUNICODE_STRING BaseDllName;
        PVOID DllBase;
    } Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID(CALLBACK* PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    PLDR_DLL_NOTIFICATION_DATA NotificationData,
    PVOID Context
);

typedef NTSTATUS(NTAPI* pfnLdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID* Cookie
);

typedef NTSTATUS(NTAPI* pfnLdrUnregisterDllNotification)(
    PVOID Cookie
);

#define LDR_DLL_NOTIFICATION_REASON_LOADED 1

static VOID CALLBACK ClrLdrNotificationCallback(
    ULONG notificationReason,
    PLDR_DLL_NOTIFICATION_DATA notificationData,
    PVOID /*context*/)
{
    if (notificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED && notificationData)
    {
        if (notificationData->Loaded.BaseDllName && notificationData->Loaded.BaseDllName->Buffer)
        {
            if (_wcsicmp(notificationData->Loaded.BaseDllName->Buffer, L"clr.dll") == 0)
            {
                HMODULE hClr = (HMODULE)notificationData->Loaded.DllBase;
                LPVOID pLoadImage = ResolveInternalCallFromClr(hClr, "nLoadImage");
                if (pLoadImage)
                {
                    ApplyHookToLoadImage(pLoadImage);
                }
            }
        }
    }
}

bool InitClrHookEngine()
{
    // 1. Check if clr.dll is already loaded
    HMODULE hClr = GetModuleHandleA("clr.dll");
    if (hClr)
    {
        LPVOID pLoadImage = ResolveInternalCallFromClr(hClr, "nLoadImage");
        if (pLoadImage)
        {
            ApplyHookToLoadImage(pLoadImage);
        }
    }

    // 2. Register DLL notification for future clr.dll loads
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll && !g_pLdrCookie)
    {
        auto pfnRegister = (pfnLdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
        if (pfnRegister)
        {
            pfnRegister(0, ClrLdrNotificationCallback, nullptr, &g_pLdrCookie);
        }
    }

    return true;
}

void ShutdownClrHookEngine()
{
    if (g_pLdrCookie)
    {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (hNtdll)
        {
            auto pfnUnregister = (pfnLdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");
            if (pfnUnregister)
            {
                pfnUnregister(g_pLdrCookie);
                g_pLdrCookie = nullptr;
            }
        }
    }

    if (g_isClrHooked.exchange(false))
    {
        detours::UnhookAPI((LPVOID*)&g_fnRawLoadImage, (LPVOID)&Detour_nLoadImage);
        g_fnRawLoadImage = nullptr;
        g_pTargetLoadImage = nullptr;
    }
}

PVOID GetHookedLoadImageAddress()
{
    return g_pTargetLoadImage;
}

bool RehookLoadImage()
{
    if (!g_pTargetLoadImage)
        return false;

    bool attached = detours::HookCode(g_pTargetLoadImage, (LPVOID)&Detour_nLoadImage, (LPVOID*)&g_fnRawLoadImage);
    if (attached)
    {
        g_isClrHooked = true;
        return true;
    }
    return false;
}

} // namespace edrpm
} // namespace cmd
