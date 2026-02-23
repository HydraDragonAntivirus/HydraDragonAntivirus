/*++

Module Name:

    UserModeHookEngine.cpp

Abstract:

    Implementation of user-mode ntdll.dll hooking engine.
    FIXED: Complete NtDeviceIoControlFile call with all 10 parameters.

Environment:

    Kernel mode

--*/

#include "UserModeHookEngine.h"
#include <ntimage.h>

// -------------------------------------------------------------------------
// DYNAMIC IMPORT DEFINITIONS
// -------------------------------------------------------------------------

// Function pointer typedefs live in UserModeHookEngine.h (single source of truth).

//
// Global Function Pointers
//
PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory = NULL;
PZW_ALLOCATE_VIRTUAL_MEMORY fnZwAllocateVirtualMemory = NULL;
PZW_DUPLICATE_OBJECT fnZwDuplicateObject = NULL;
PZW_FREE_VIRTUAL_MEMORY fnZwFreeVirtualMemory = NULL;
PPS_GET_PROCESS_PEB fnPsGetProcessPeb = NULL;

PUSERMODE_HOOK_ENGINE g_UserHookEngine = NULL;
extern PDEVICE_OBJECT g_HookDeviceObject;

// Dynamic Configuration
HOOK_CONFIG_DATA g_GlobalCustomHooks[MAX_CUSTOM_HOOKS];
ULONG g_CustomHookCount = 0;
FAST_MUTEX g_ConfigMutex;

// Global safety mode:
// - Disable all per-process API hooking uniformly.
// - No whitelist/blacklist decisions are used.
// - Fail-open behavior prevents process crashes from hook injection attempts.
static const BOOLEAN g_DisableAllProcessHooking = TRUE;

static BOOLEAN IsProcessHookingEnabled(VOID)
{
    return (g_DisableAllProcessHooking == FALSE);
}

// Forward Declarations
NTSTATUS ResolveAndHook(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry, _In_ PCWSTR ModuleName,
                        _In_ PCSTR FunctionName, _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId,
                        _In_ PVOID TargetNtDeviceIo, _In_opt_ PVOID NewModuleBase);

static VOID CleanupPartialHookEntry(_In_opt_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    if (HookEntry == NULL)
        return;

    if (HookEntry->DriverDeviceHandle)
    {
        ZwClose(HookEntry->DriverDeviceHandle);
        HookEntry->DriverDeviceHandle = NULL;
    }

    if (Process != NULL && HookEntry->ShellcodeBase && fnZwFreeVirtualMemory)
    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        SIZE_T freeSize = 0;
        fnZwFreeVirtualMemory(ZwCurrentProcess(), &HookEntry->ShellcodeBase, &freeSize, MEM_RELEASE);
        KeUnstackDetachProcess(&apcState);
    }

    if (HookEntry->CustomHooks)
    {
        ExFreePoolWithTag(HookEntry->CustomHooks, 'UMHd');
        HookEntry->CustomHooks = NULL;
    }

    RtlZeroMemory(HookEntry, sizeof(PROCESS_HOOK_ENTRY));
}

VOID ApplyHooksInternal(PEPROCESS Process, PPROCESS_HOOK_ENTRY HookEntry, PVOID TargetNtDeviceIo, PVOID NewModuleBase)
{
    if (!IsProcessHookingEnabled())
    {
        UNREFERENCED_PARAMETER(Process);
        UNREFERENCED_PARAMETER(HookEntry);
        UNREFERENCED_PARAMETER(TargetNtDeviceIo);
        UNREFERENCED_PARAMETER(NewModuleBase);
        return;
    }

    NTSTATUS st = STATUS_SUCCESS;
    auto dump_hook_bytes = [&](PCSTR hookName, PHOOK_DEF hookDef) {
        UCHAR bytes[6] = {0};

        if (hookDef == NULL || hookDef->Address == NULL)
        {
            DbgPrint("UserModeHook: %s address is NULL\n", hookName);
            return;
        }

        KAPC_STATE vs;
        KeStackAttachProcess((PRKPROCESS)Process, &vs);
        __try
        {
            RtlCopyMemory(bytes, hookDef->Address, sizeof(bytes));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            RtlZeroMemory(bytes, sizeof(bytes));
        }
        KeUnstackDetachProcess(&vs);

        DbgPrint("UserModeHook: %s bytes: %02X %02X %02X %02X %02X %02X\n", hookName, bytes[0], bytes[1], bytes[2],
                 bytes[3], bytes[4], bytes[5]);
    };

    // NTDLL Hooks (Default)
    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtWriteVirtualMemory", &HookEntry->NtWriteVirtualMemory, 13,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtWriteVirtualMemory (id=13) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtWriteVirtualMemory", &HookEntry->NtWriteVirtualMemory);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtAllocateVirtualMemory",
                        &HookEntry->NtAllocateVirtualMemory, 14, TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtAllocateVirtualMemory (id=14) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtAllocateVirtualMemory", &HookEntry->NtAllocateVirtualMemory);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtProtectVirtualMemory", &HookEntry->NtProtectVirtualMemory,
                        15, TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtProtectVirtualMemory (id=15) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtProtectVirtualMemory", &HookEntry->NtProtectVirtualMemory);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtCreateThreadEx", &HookEntry->NtCreateThreadEx, 16,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtCreateThreadEx (id=16) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtCreateThreadEx", &HookEntry->NtCreateThreadEx);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtMapViewOfSection", &HookEntry->NtMapViewOfSection, 20,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtMapViewOfSection (id=20) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtMapViewOfSection", &HookEntry->NtMapViewOfSection);

    // Custom Hooks (Dynamic)
    if (HookEntry->CustomHooks == NULL)
    {
        HookEntry->CustomHooks =
            (PHOOK_DEF)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HOOK_DEF) * MAX_CUSTOM_HOOKS, 'UMHd');
        if (HookEntry->CustomHooks)
        {
            RtlZeroMemory(HookEntry->CustomHooks, sizeof(HOOK_DEF) * MAX_CUSTOM_HOOKS);
        }
    }

    if (HookEntry->CustomHooks)
    {
        ExAcquireFastMutex(&g_ConfigMutex);
        for (ULONG i = 0; i < g_CustomHookCount; i++)
        {
            if (i < MAX_CUSTOM_HOOKS)
            {
                st = ResolveAndHook(Process, HookEntry, g_GlobalCustomHooks[i].ModuleName,
                                    g_GlobalCustomHooks[i].FunctionName, &HookEntry->CustomHooks[i],
                                    g_GlobalCustomHooks[i].EventId, TargetNtDeviceIo, NewModuleBase);
                DbgPrint("UserModeHook: PID %lu hook %ws!%s (id=%lu) -> 0x%08X\n", HookEntry->ProcessId,
                         g_GlobalCustomHooks[i].ModuleName, g_GlobalCustomHooks[i].FunctionName,
                         g_GlobalCustomHooks[i].EventId, st);
            }
        }
        ExReleaseFastMutex(&g_ConfigMutex);
    }
}

VOID ApplyGlobalHooksToAll()
{
    if (!IsProcessHookingEnabled())
        return;

    if (g_UserHookEngine == NULL)
        return;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId != 0)
        {
            PPROCESS_HOOK_ENTRY hookEntry = &g_UserHookEngine->Processes[i];

            // Re-apply hooks (Generic logic will skip if already hooked)
            if (hookEntry->ProcessObject && hookEntry->NtDeviceIoControlFileAddr)
            {
                ApplyHooksInternal(hookEntry->ProcessObject, hookEntry, hookEntry->NtDeviceIoControlFileAddr, NULL);
            }
        }
    }
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
}

NTSTATUS AddCustomHook(_In_ PHOOK_CONFIG_DATA Config)
{
    if (!IsProcessHookingEnabled())
    {
        UNREFERENCED_PARAMETER(Config);
        DbgPrint("UserModeHook: custom hook request ignored because process hooking is disabled globally\n");
        return STATUS_SUCCESS;
    }

    ExAcquireFastMutex(&g_ConfigMutex);

    // Idempotent add: skip duplicates instead of consuming hook slots.
    for (ULONG i = 0; i < g_CustomHookCount; i++)
    {
        if (_wcsicmp(g_GlobalCustomHooks[i].ModuleName, Config->ModuleName) == 0 &&
            _stricmp(g_GlobalCustomHooks[i].FunctionName, Config->FunctionName) == 0)
        {
            ExReleaseFastMutex(&g_ConfigMutex);
            return STATUS_SUCCESS;
        }
    }

    if (g_CustomHookCount >= MAX_CUSTOM_HOOKS)
    {
        ExReleaseFastMutex(&g_ConfigMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(&g_GlobalCustomHooks[g_CustomHookCount], Config, sizeof(HOOK_CONFIG_DATA));
    g_CustomHookCount++;
    ExReleaseFastMutex(&g_ConfigMutex);

    // Trigger retroactive application to all processes
    ApplyGlobalHooksToAll();

    return STATUS_SUCCESS;
}

// =============================================================================
// Shellcode design: struct-based layout so ALL patchable field offsets are
// computed by the compiler via offsetof(). No more manual byte counting.
//
// Stack state when shellcode fires (entered via JMP FF 25, not CALL):
//   - Caller's CALL pushed the return address, so entry RSP is 8-misaligned.
//   - We push rax,rcx,rdx,rbx,r8,r9,r10,r11 (8 pushes = 64 bytes)
//   - Then push rbp + mov rbp,rsp  → rbp anchors the unaligned frame
//   - Then and rsp,-16             → RSP forced to 16-byte alignment
//   - Then sub rsp,0xF8            → working area allocated
//
// After and+sub, saved registers are accessed via rbp:
//   [rbp+0]  = saved rbp
//   [rbp+8]  = saved r11
//   [rbp+16] = saved r10
//   [rbp+24] = saved r9
//   [rbp+32] = saved r8
//   [rbp+40] = saved rbx
//   [rbp+48] = saved rdx  (= original Arg2/RDX of hooked function)
//   [rbp+56] = saved rcx  (= original Arg1/RCX of hooked function)
//   [rbp+64] = saved rax
//
// Stack layout within the 0xF8 allocation (relative to aligned RSP):
//   [rsp+00..1F] shadow space (32 bytes)
//   [rsp+20]     Arg5  = &IoStatusBlock
//   [rsp+28]     Arg6  = IoControlCode (ULONG in 8-byte slot)
//   [rsp+30]     Arg7  = &HOOK_EVENT_DATA
//   [rsp+38]     Arg8  = sizeof(HOOK_EVENT_DATA) = 88
//   [rsp+40]     Arg9  = NULL (OutputBuffer)
//   [rsp+48]     Arg10 = 0   (OutputBufferLength)
//   [rsp+50..5F] IoStatusBlock (16 bytes, zeroed, kernel writes here)
//   [rsp+60..B7] HOOK_EVENT_DATA (88 bytes = 0x58)
// =============================================================================

#pragma pack(push, 1)

// FunctionName chunk: mov rax,imm64 / mov [rsp+disp8],rax  (15 bytes)
// Used for [rsp+68h], [rsp+70h], [rsp+78h] (displacements 104,112,120 < 128)
struct FNCHUNK_SMALL {
    UCHAR     op[2];        // 48 B8
    ULONGLONG imm;          // [PATCH: 8 bytes of function name]
    UCHAR     store[5];     // 48 89 44 24 <disp8>
};
static_assert(sizeof(FNCHUNK_SMALL) == 15, "FNCHUNK_SMALL size");

// FunctionName chunk: mov rax,imm64 / mov [rsp+disp32],rax (18 bytes)
// Used for [rsp+80h+] (displacements >= 128, require disp32)
struct FNCHUNK_LARGE {
    UCHAR     op[2];        // 48 B8
    ULONGLONG imm;          // [PATCH: 8 bytes of function name]
    UCHAR     store[8];     // 48 89 84 24 <disp32>
};
static_assert(sizeof(FNCHUNK_LARGE) == 18, "FNCHUNK_LARGE size");

// 5-byte store instruction wrapper (for zero-init array)
struct STORE5 { UCHAR b[5]; };

struct SHELLCODE_LAYOUT {
    // ===== RE-ENTRANCY GUARD =====
    // Per-thread safe: busy flag lives in first 8 bytes of shellcode allocation.
    // Guard reads flag, skips to SKIP_TARGET if busy, otherwise sets flag.
    UCHAR     grd_push;          // 50          push rax
    UCHAR     grd_rptr[2];       // 48 A1       mov rax, [mem64]
    PVOID     grd_read_addr;     // [PATCH: &flag]
    UCHAR     grd_test[3];       // 48 85 C0    test rax, rax
    UCHAR     grd_jnz[2];        // 0F 85       jnz rel32
    LONG      grd_jnz_rel32;     // [COMPUTED: offset to skip_pop]
    UCHAR     grd_pop1;          // 58          pop rax   (flag=0, restore)
    UCHAR     grd_push2;         // 50          push rax  (will be saved below)
    UCHAR     grd_wimm[2];       // 48 B8       mov rax, imm64
    PVOID     grd_write_addr;    // [PATCH: &flag]
    UCHAR     grd_set1[7];       // 48 C7 00 01 00 00 00   mov [rax], 1
    UCHAR     grd_pop2;          // 58          pop rax

    // ===== SAVE VOLATILE REGISTERS =====
    UCHAR     s_rax;             // 50
    UCHAR     s_rcx;             // 51
    UCHAR     s_rdx;             // 52
    UCHAR     s_rbx;             // 53
    UCHAR     s_r8[2];           // 41 50
    UCHAR     s_r9[2];           // 41 51
    UCHAR     s_r10[2];          // 41 52
    UCHAR     s_r11[2];          // 41 53

    // ===== STACK ALIGNMENT (FIX: was missing, caused SSE crashes) =====
    // push rbp saves the current (unaligned) rsp so we can restore it exactly.
    // and rsp,-16 forces 16-byte alignment required by x64 ABI for any CALL.
    UCHAR     push_rbp;          // 55          push rbp
    UCHAR     mov_rbp_rsp[3];    // 48 89 E5    mov rbp, rsp
    UCHAR     and_rsp_16[4];     // 48 83 E4 F0 and rsp, -16

    // ===== ALLOCATE STACK FRAME =====
    UCHAR     sub_op[3];         // 48 81 EC    sub rsp, imm32
    ULONG     sub_imm;           // 00 01 00 00 (0x100 = 256 bytes)

    // ===== FILL HOOK_EVENT_DATA at [rsp+60h] =====
    UCHAR     et_op[4];          // C7 44 24 60
    ULONG     event_type;        // [PATCH: EventId]

    UCHAR     pid_op[4];         // C7 44 24 64
    ULONG     process_id;        // [PATCH: ProcessId]

    // FunctionName: 8 chunks × 8 bytes = 64 bytes
    // Chunks 0-2 → [rsp+68h/70h/78h] (disp8, 15 bytes each)
    FNCHUNK_SMALL fn[3];
    // Chunks 3-7 → [rsp+80h..A0h] (disp32, 18 bytes each)
    FNCHUNK_LARGE fn_l[5];

    // ===== Arg1/Arg2 from saved registers (FIX: use rbp, not fixed RSP offset) =====
    // Original RCX (Arg1 of hooked fn) is at [rbp+56]. See stack diagram above.
    UCHAR     a1_load[4];        // 48 8B 45 38   mov rax, [rbp+56]
    UCHAR     a1_store[8];       // 48 89 84 24 A8 00 00 00  → HOOK_EVENT_DATA.Arg1

    // Original RDX (Arg2) is at [rbp+48]
    UCHAR     a2_load[4];        // 48 8B 45 30   mov rax, [rbp+48]
    UCHAR     a2_store[8];       // 48 89 84 24 B0 00 00 00  → HOOK_EVENT_DATA.Arg2

    // ===== ZERO STACK PARAMS =====
    UCHAR     xrax[3];           // 48 31 C0    xor rax, rax
    STORE5    zero_s[8];         // zero [rsp+20h]..[rsp+58h]

    // ===== NtDeviceIoControlFile CALL SETUP =====
    // Arg1 (rcx) = FileHandle
    UCHAR     mov_rcx[2];        // 48 B9
    HANDLE    file_handle;       // [PATCH: DriverDeviceHandle]

    // Arg2/3/4 = NULL
    UCHAR     xrdx[3];           // 48 31 D2    xor rdx, rdx
    UCHAR     xr8[3];            // 4D 31 C0    xor r8, r8
    UCHAR     xr9[3];            // 4D 31 C9    xor r9, r9

    // Arg5 [rsp+20h] = &IoStatusBlock (Persistent IOSB at end of shellcode)
    UCHAR     mov_arg5_op[2];    // 48 B8
    PVOID     arg5_iosb_addr;    // [PATCH: &this->Iosb]
    UCHAR     mov_arg5[5];       // 48 89 44 24 20   mov [rsp+20h], rax

    // Arg6 [rsp+28h] = IoControlCode
    UCHAR     ioctl_op[4];       // C7 44 24 28
    ULONG     ioctl_code;        // [PATCH: IoControlCode]

    // Arg7 [rsp+30h] = &HOOK_EVENT_DATA (InputBuffer)
    UCHAR     lea_input[5];      // 48 8D 44 24 60   lea rax, [rsp+60h]
    UCHAR     mov_arg7[5];       // 48 89 44 24 30   mov [rsp+30h], rax

    // Arg8 [rsp+38h] = sizeof(HOOK_EVENT_DATA) = 88
    UCHAR     ilen_op[4];        // C7 44 24 38
    ULONG     input_len;         // 0x00000058

    // Call NtDeviceIoControlFile via rax (preserves rcx from file_handle patch)
    UCHAR     mov_ntdev[2];      // 48 B8
    PVOID     ntdeviceio;        // [PATCH: NtDeviceIoControlFile address]
    UCHAR     call_rax[2];       // FF D0

    // ===== CLEAR BUSY FLAG =====
    UCHAR     clr_push;          // 50
    UCHAR     clr_mov[2];        // 48 B8
    PVOID     clr_addr;          // [PATCH: &flag]
    UCHAR     clr_zero[7];       // 48 C7 00 00 00 00 00   mov [rax], 0
    UCHAR     clr_pop;           // 58

    // ===== RESTORE STACK (FIX: use rbp instead of add rsp,0xF8) =====
    // mov rsp,rbp undoes BOTH the sub and the and, restoring exact pre-alignment RSP.
    UCHAR     rst_rsp[3];        // 48 89 EC    mov rsp, rbp
    UCHAR     pop_rbp;           // 5D          pop rbp

    // ===== RESTORE VOLATILE REGISTERS =====
    UCHAR     r_r11[2];          // 41 5B
    UCHAR     r_r10[2];          // 41 5A
    UCHAR     r_r9[2];           // 41 59
    UCHAR     r_r8[2];           // 41 58
    UCHAR     r_rbx;             // 5B
    UCHAR     r_rdx;             // 5A
    UCHAR     r_rcx;             // 59
    UCHAR     r_rax;             // 58

    // ===== JUMP TO GATEWAY (splits 64-bit address, avoids register clobber) =====
    UCHAR     gw_push;           // 68
    ULONG     gw_low;            // [PATCH: gatewayAddress & 0xFFFFFFFF]
    UCHAR     gw_hi_op[4];       // C7 44 24 04
    ULONG     gw_high;           // [PATCH: gatewayAddress >> 32]
    UCHAR     gw_ret;            // C3

    // ===== SKIP TARGET (jnz lands here when busy) =====
    // Pop the rax we pushed at guard entry, then jump to gateway anyway.
    UCHAR     skip_pop;          // 58          pop rax (undo guard_push)
    UCHAR     skip_push;         // 68
    ULONG     skip_low;          // [PATCH: same as gw_low]
    UCHAR     skip_hi_op[4];     // C7 44 24 04
    ULONG     skip_high;         // [PATCH: same as gw_high]
    UCHAR     skip_ret;          // C3

    // ===== PERSISTENT IOSB (Non-blocking I/O safety) =====
    IO_STATUS_BLOCK Iosb;
};
#pragma pack(pop)

// ---------------------------------------------------------------------------
// g_ShellcodeTemplate is a zero-initialized global filled once at driver load
// by BuildShellcodeTemplate(). No static-const aggregate initializer is used
// because MSVC kernel-mode compilation rejects nested-struct brace-init and
// constexpr offsetof on incomplete types.
// ---------------------------------------------------------------------------
static SHELLCODE_LAYOUT g_ShellcodeTemplate;
static BOOLEAN g_ShellcodeTemplateBuilt = FALSE;

// Helper: set N bytes starting at p
static FORCEINLINE VOID SetBytes(PUCHAR p, const UCHAR* src, ULONG n)
{
    for (ULONG i = 0; i < n; i++) p[i] = src[i];
}
#define SB(field, ...) do { const UCHAR _b[] = {__VA_ARGS__}; \
    SetBytes((PUCHAR)&(sc->field), _b, sizeof(_b)); } while(0)

static VOID BuildShellcodeTemplate(VOID)
{
    SHELLCODE_LAYOUT* sc = &g_ShellcodeTemplate;
    RtlZeroMemory(sc, sizeof(*sc));

    // jnz rel32 displacement = distance from grd_pop1 to skip_pop.
    // Computed here with FIELD_OFFSET (ntddk.h) which is always available
    // at runtime in kernel mode even without stddef.h.
    LONG jnzRel = (LONG)(
        FIELD_OFFSET(SHELLCODE_LAYOUT, skip_pop) -
        FIELD_OFFSET(SHELLCODE_LAYOUT, grd_pop1));

    // -----------------------------------------------------------------------
    // RE-ENTRANCY GUARD
    // -----------------------------------------------------------------------
    sc->grd_push = 0x50;
    SB(grd_rptr,  0x48, 0xA1);
    sc->grd_read_addr  = (PVOID)(ULONG_PTR)0xEEEEEEEEEEEEEEEEULL;
    SB(grd_test,  0x48, 0x85, 0xC0);
    SB(grd_jnz,   0x0F, 0x85);
    sc->grd_jnz_rel32  = jnzRel;
    sc->grd_pop1  = 0x58;
    sc->grd_push2 = 0x50;
    SB(grd_wimm,  0x48, 0xB8);
    sc->grd_write_addr = (PVOID)(ULONG_PTR)0xEEEEEEEEEEEEEEEEULL;
    SB(grd_set1,  0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00);
    sc->grd_pop2  = 0x58;

    // -----------------------------------------------------------------------
    // SAVE VOLATILE REGISTERS
    // -----------------------------------------------------------------------
    sc->s_rax = 0x50; sc->s_rcx = 0x51; sc->s_rdx = 0x52; sc->s_rbx = 0x53;
    SB(s_r8,  0x41, 0x50);
    SB(s_r9,  0x41, 0x51);
    SB(s_r10, 0x41, 0x52);
    SB(s_r11, 0x41, 0x53);

    // -----------------------------------------------------------------------
    // STACK ALIGNMENT
    // -----------------------------------------------------------------------
    sc->push_rbp = 0x55;
    SB(mov_rbp_rsp, 0x48, 0x89, 0xE5);
    SB(and_rsp_16,  0x48, 0x83, 0xE4, 0xF0);

    // -----------------------------------------------------------------------
    // ALLOCATE STACK FRAME
    // -----------------------------------------------------------------------
    SB(sub_op, 0x48, 0x81, 0xEC);
    sc->sub_imm = 0x00000100;

    // -----------------------------------------------------------------------
    // FILL HOOK_EVENT_DATA
    // -----------------------------------------------------------------------
    SB(et_op,  0xC7, 0x44, 0x24, 0x60);
    sc->event_type = 0x11111111;          // patched per hook
    SB(pid_op, 0xC7, 0x44, 0x24, 0x64);
    sc->process_id = 0x22222222;          // patched per hook

    // FunctionName chunks 0-2: mov rax,imm64 / mov [rsp+disp8],rax
    SB(fn[0].op,    0x48, 0xB8);
    sc->fn[0].imm = 0x6666666666666666ULL;
    SB(fn[0].store, 0x48, 0x89, 0x44, 0x24, 0x68);

    SB(fn[1].op,    0x48, 0xB8);
    sc->fn[1].imm = 0x7777777777777777ULL;
    SB(fn[1].store, 0x48, 0x89, 0x44, 0x24, 0x70);

    SB(fn[2].op,    0x48, 0xB8);
    sc->fn[2].imm = 0x8888888888888888ULL;
    SB(fn[2].store, 0x48, 0x89, 0x44, 0x24, 0x78);

    // FunctionName chunks 3-7: mov rax,imm64 / mov [rsp+disp32],rax
    SB(fn_l[0].op,    0x48, 0xB8);
    sc->fn_l[0].imm = 0x9999999999999999ULL;
    SB(fn_l[0].store, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00);

    SB(fn_l[1].op,    0x48, 0xB8);
    sc->fn_l[1].imm = 0xAAAAAAAAAAAAAAAAULL;
    SB(fn_l[1].store, 0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00);

    SB(fn_l[2].op,    0x48, 0xB8);
    sc->fn_l[2].imm = 0xBBBBBBBBBBBBBBBBULL;
    SB(fn_l[2].store, 0x48, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00);

    SB(fn_l[3].op,    0x48, 0xB8);
    sc->fn_l[3].imm = 0xCCCCCCCCCCCCCCCCULL;
    SB(fn_l[3].store, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00);

    SB(fn_l[4].op,    0x48, 0xB8);
    sc->fn_l[4].imm = 0xDDDDDDDDDDDDDDDDULL;
    SB(fn_l[4].store, 0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00);

    // -----------------------------------------------------------------------
    // ARG1/ARG2 CAPTURE (via rbp)
    // -----------------------------------------------------------------------
    // Original RCX at [rbp+0x38], original RDX at [rbp+0x30]
    SB(a1_load,  0x48, 0x8B, 0x45, 0x38);
    SB(a1_store, 0x48, 0x89, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00);
    SB(a2_load,  0x48, 0x8B, 0x45, 0x30);
    SB(a2_store, 0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00);

    // -----------------------------------------------------------------------
    // ZERO STACK PARAMS
    // -----------------------------------------------------------------------
    SB(xrax, 0x48, 0x31, 0xC0);
    SB(zero_s[0].b, 0x48, 0x89, 0x44, 0x24, 0x20);
    SB(zero_s[1].b, 0x48, 0x89, 0x44, 0x24, 0x28);
    SB(zero_s[2].b, 0x48, 0x89, 0x44, 0x24, 0x30);
    SB(zero_s[3].b, 0x48, 0x89, 0x44, 0x24, 0x38);
    SB(zero_s[4].b, 0x48, 0x89, 0x44, 0x24, 0x40);
    SB(zero_s[5].b, 0x48, 0x89, 0x44, 0x24, 0x48);
    SB(zero_s[6].b, 0x48, 0x89, 0x44, 0x24, 0x50);
    SB(zero_s[7].b, 0x48, 0x89, 0x44, 0x24, 0x58);

    // -----------------------------------------------------------------------
    // NtDeviceIoControlFile CALL
    // -----------------------------------------------------------------------
    SB(mov_rcx, 0x48, 0xB9);
    sc->file_handle = NULL;                         // patched per hook
    SB(xrdx, 0x48, 0x31, 0xD2);
    SB(xr8,  0x4D, 0x31, 0xC0);
    SB(xr9,  0x4D, 0x31, 0xC9);
    // Arg5 [rsp+20h] = &PersistentIosb (Shellcode relative address)
    SB(mov_arg5_op, 0x48, 0xB8);
    sc->arg5_iosb_addr = (PVOID)(ULONG_PTR)0xEEEEEEEEEEEEEEEEULL; // patched per hook
    SB(mov_arg5,  0x48, 0x89, 0x44, 0x24, 0x20);
    SB(ioctl_op,  0xC7, 0x44, 0x24, 0x28);
    sc->ioctl_code = 0xAAAAAAAA;                    // patched per hook
    SB(lea_input, 0x48, 0x8D, 0x44, 0x24, 0x60);
    SB(mov_arg7,  0x48, 0x89, 0x44, 0x24, 0x30);
    SB(ilen_op,   0xC7, 0x44, 0x24, 0x38);
    sc->input_len = 0x00000058;                     // sizeof(HOOK_EVENT_DATA) = 88
    SB(mov_ntdev, 0x48, 0xB8);
    sc->ntdeviceio = NULL;                          // patched per hook
    SB(call_rax, 0xFF, 0xD0);

    // -----------------------------------------------------------------------
    // CLEAR BUSY FLAG
    // -----------------------------------------------------------------------
    sc->clr_push = 0x50;
    SB(clr_mov, 0x48, 0xB8);
    sc->clr_addr = (PVOID)(ULONG_PTR)0xEEEEEEEEEEEEEEEEULL;  // patched per hook
    SB(clr_zero, 0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00);
    sc->clr_pop = 0x58;

    // -----------------------------------------------------------------------
    // RESTORE STACK (mov rsp,rbp undoes both sub AND and-alignment)
    // -----------------------------------------------------------------------
    SB(rst_rsp, 0x48, 0x89, 0xEC);
    sc->pop_rbp = 0x5D;

    // -----------------------------------------------------------------------
    // RESTORE VOLATILE REGISTERS
    // -----------------------------------------------------------------------
    SB(r_r11, 0x41, 0x5B);
    SB(r_r10, 0x41, 0x5A);
    SB(r_r9,  0x41, 0x59);
    SB(r_r8,  0x41, 0x58);
    sc->r_rbx = 0x5B; sc->r_rdx = 0x5A; sc->r_rcx = 0x59; sc->r_rax = 0x58;

    // -----------------------------------------------------------------------
    // GATEWAY JUMP (push low32 / mov [rsp+4],high32 / ret)
    // -----------------------------------------------------------------------
    sc->gw_push  = 0x68;
    sc->gw_low   = 0x55555555;                      // patched per hook
    SB(gw_hi_op, 0xC7, 0x44, 0x24, 0x04);
    sc->gw_high  = 0x55555555;                      // patched per hook
    sc->gw_ret   = 0xC3;

    // -----------------------------------------------------------------------
    // SKIP TARGET (busy path: pop rax then jump to gateway)
    // -----------------------------------------------------------------------
    sc->skip_pop  = 0x58;
    sc->skip_push = 0x68;
    sc->skip_low  = 0xBBBBBBBB;                     // patched per hook
    SB(skip_hi_op, 0xC7, 0x44, 0x24, 0x04);
    sc->skip_high = 0xBBBBBBBB;                     // patched per hook
    sc->skip_ret  = 0xC3;

    g_ShellcodeTemplateBuilt = TRUE;

    DbgPrint("UserModeHook: shellcode template built, size=%lu bytes, jnzRel32=%ld\n",
             (ULONG)sizeof(SHELLCODE_LAYOUT), jnzRel);
}

#undef SB

//
// Initialize the user-mode hooking engine
//

NTSTATUS UserModeHookEngineInitialize(VOID)
{
    DbgPrint("!!! UserModeHook: Initializing user-mode hooking engine...\n");

    if (g_UserHookEngine && g_UserHookEngine->IsInitialized)
    {
        return STATUS_SUCCESS;
    }

    if (!IsProcessHookingEnabled())
    {
        g_UserHookEngine =
            (PUSERMODE_HOOK_ENGINE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(USERMODE_HOOK_ENGINE), 'UMHk');
        if (g_UserHookEngine == NULL)
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(g_UserHookEngine, sizeof(USERMODE_HOOK_ENGINE));
        ExInitializeFastMutex(&g_UserHookEngine->EngineMutex);
        ExInitializeFastMutex(&g_ConfigMutex);
        g_UserHookEngine->IsInitialized = TRUE;

        DbgPrint("!!! UserModeHook: Process API hooking is disabled globally (no whitelist/blacklist mode)\n");
        DbgPrint("!!! UserModeHook: Running in read-only/no-op safety mode to avoid process crashes and BSOD risk\n");
        return STATUS_SUCCESS;
    }

    // ---------------------------------------------------------------------
    // FIX: Resolve system routines dynamically to avoid Linker Errors
    // ---------------------------------------------------------------------
    UNICODE_STRING routineName;

    // Resolve ZwProtectVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwProtectVirtualMemory");
    fnZwProtectVirtualMemory = (PZW_PROTECT_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);

    if (!fnZwProtectVirtualMemory)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve ZwProtectVirtualMemory\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve PsGetProcessPeb
    RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
    fnPsGetProcessPeb = (PPS_GET_PROCESS_PEB)MmGetSystemRoutineAddress(&routineName);

    if (!fnPsGetProcessPeb)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve PsGetProcessPeb\n");
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Resolve ZwAllocateVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwAllocateVirtualMemory");
    fnZwAllocateVirtualMemory = (PZW_ALLOCATE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    if (!fnZwAllocateVirtualMemory)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve ZwAllocateVirtualMemory\n");
    }

    // Resolve ZwDuplicateObject
    RtlInitUnicodeString(&routineName, L"ZwDuplicateObject");
    fnZwDuplicateObject = (PZW_DUPLICATE_OBJECT)MmGetSystemRoutineAddress(&routineName);

    // Resolve ZwFreeVirtualMemory
    RtlInitUnicodeString(&routineName, L"ZwFreeVirtualMemory");
    fnZwFreeVirtualMemory = (PZW_FREE_VIRTUAL_MEMORY)MmGetSystemRoutineAddress(&routineName);
    if (!fnZwDuplicateObject)
    {
        DbgPrint("!!! UserModeHook: Failed to resolve ZwDuplicateObject\n");
    }

    // ---------------------------------------------------------------------
    // Allocate Engine
    // ---------------------------------------------------------------------

    g_UserHookEngine =
        (PUSERMODE_HOOK_ENGINE)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(USERMODE_HOOK_ENGINE), 'UMHk');

    if (g_UserHookEngine == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_UserHookEngine, sizeof(USERMODE_HOOK_ENGINE));
    ExInitializeFastMutex(&g_UserHookEngine->EngineMutex);
    ExInitializeFastMutex(&g_ConfigMutex);
    g_UserHookEngine->IsInitialized = TRUE;

    // Build the shellcode template (fills opcodes + placeholder values)
    BuildShellcodeTemplate();

    return STATUS_SUCCESS;
}

//
// Cleanup
//

VOID UserModeHookEngineCleanup(VOID)
{
    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked || g_UserHookEngine->Processes[i].ProcessId != 0)
        {
            UserModeUnhookProcessInternal(&g_UserHookEngine->Processes[i]);
        }
    }

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    ExFreePoolWithTag(g_UserHookEngine, 'UMHk');
    g_UserHookEngine = NULL;
}

//
// Find module base address
//

PVOID FindModuleBaseAddress(_In_ PEPROCESS Process, _In_ PCWSTR ModuleName, _Out_opt_ PSIZE_T ModuleSize)
{
    PVOID moduleBase = NULL;
    KAPC_STATE apcState;

    if (ModuleSize != NULL)
        *ModuleSize = 0;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try
    {
        // FIX: Use the function pointer
        PPEB peb = fnPsGetProcessPeb(Process);

        if (peb)
        {
            ProbeForRead(peb, sizeof(PEB), 1);
            PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
            if (ldr)
            {
                ProbeForRead(ldr, sizeof(PEB_LDR_DATA), 1);
                PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
                PLIST_ENTRY listEntry = listHead->Flink;

                while (listEntry != listHead)
                {
                    PLDR_DATA_TABLE_ENTRY ldrEntry =
                        CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

                    if (ldrEntry->BaseDllName.Buffer && ldrEntry->BaseDllName.Length > 0)
                    {
                        ProbeForRead(ldrEntry->BaseDllName.Buffer, ldrEntry->BaseDllName.Length, 1);
                        if (_wcsicmp(ldrEntry->BaseDllName.Buffer, ModuleName) == 0)
                        {
                            moduleBase = ldrEntry->DllBase;
                            if (ModuleSize)
                                *ModuleSize = ldrEntry->SizeOfImage;
                            break;
                        }
                    }
                    listEntry = listEntry->Flink;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        moduleBase = NULL;
    }

    KeUnstackDetachProcess(&apcState);
    return moduleBase;
}

//
// Find exported function
//

PVOID FindExportedFunction(_In_ PVOID ModuleBase, _In_ PCSTR FunctionName)
{
    PVOID functionAddress = NULL;
    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ModuleBase + dosHeader->e_lfanew);
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), 1);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir =
            (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase +
                                      ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                          .VirtualAddress);
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);

        PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        PULONG addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
        PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);

        for (ULONG i = 0; i < exportDir->NumberOfNames; i++)
        {
            PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
            ProbeForRead((PVOID)currentName, strlen(FunctionName) + 1, 1);

            if (strcmp(currentName, FunctionName) == 0)
            {
                USHORT ordinal = addressOfNameOrdinals[i];
                ULONG rva = addressOfFunctions[ordinal];
                functionAddress = (PVOID)((PUCHAR)ModuleBase + rva);
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        functionAddress = NULL;
    }
    return functionAddress;
}

//
// Install a hook in user-mode memory
//

NTSTATUS InstallUsermodeHook(_In_ PEPROCESS Process, _In_ PVOID TargetAddress, _In_ PVOID DetourAddress,
                             _Out_writes_bytes_(USERMODE_HOOK_SIZE) PUCHAR OriginalBytes)
{
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    PVOID baseAddress = TargetAddress;
    SIZE_T regionSize = USERMODE_HOOK_SIZE;
    ULONG oldProtect = 0;
    ULONG newProtect = PAGE_EXECUTE_READWRITE;

    if (!DetourAddress)
        return STATUS_INVALID_PARAMETER;

    DbgPrint("!!! UserModeHook: Hooking %p -> Detour %p\n", TargetAddress, DetourAddress);

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    __try
    {
        // 1. Change Protection to RWX so we can write the JMP
        // FIX: Use the function pointer
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddress, &regionSize, newProtect, &oldProtect);

        if (!NT_SUCCESS(status))
        {
            DbgPrint("!!! UserModeHook: Protect failed: 0x%X\n", status);
            __leave;
        }

        // 2. Save original bytes
        ProbeForRead(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(OriginalBytes, TargetAddress, USERMODE_HOOK_SIZE);

        // 3. Build hook shellcode (Absolute JMP to DetourAddress)
        // FF 25 00 00 00 00 [8 byte address]
        UCHAR hookShellcode[USERMODE_HOOK_SIZE];
        hookShellcode[0] = 0xFF;
        hookShellcode[1] = 0x25;
        *(PULONG)&hookShellcode[2] = 0x00000000;
        *(PVOID *)&hookShellcode[6] = DetourAddress;

        // 4. Write hook
        ProbeForWrite(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(TargetAddress, hookShellcode, USERMODE_HOOK_SIZE);

        // 5. Restore Protection
        // FIX: Use the function pointer
        fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddress, &regionSize, oldProtect, &oldProtect);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apcState);
    return status;
}

//
// Hook a specific process
//

NTSTATUS InjectSingleHook(_In_ PEPROCESS Process, _In_ ULONG ProcessId, _Inout_ PPROCESS_HOOK_ENTRY HookEntry,
                          _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId, _In_opt_ PCSTR FunctionName,
                          _In_ PVOID TargetNtDeviceIo, _In_ ULONG IoControlCode)
{
    NTSTATUS status;
    KAPC_STATE apcState;

    if (!HookDef->Address)
        return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked)
        return STATUS_SUCCESS;
    if (!g_ShellcodeTemplateBuilt)
        return STATUS_DRIVER_UNABLE_TO_LOAD;

    // -----------------------------------------------------------------------
    // Each hook consumes sizeof(SHELLCODE_LAYOUT) + 64 bytes for the gateway.
    // The busy flag lives at offset 0 of the FIRST hook's shellcode (shared).
    // -----------------------------------------------------------------------
    SIZE_T totalSize = sizeof(SHELLCODE_LAYOUT) + 64;
    if (HookEntry->ShellcodeUsed + totalSize > HookEntry->ShellcodeSize)
        return STATUS_INSUFFICIENT_RESOURCES;

    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);
    PVOID gatewayAddress     = (PVOID)((ULONG_PTR)myShellcodeAddress + sizeof(SHELLCODE_LAYOUT));

    // flagAddr points to the first 8 bytes of the entire shellcode region.
    // All hooks for this process share one re-entrancy flag so any hook
    // can prevent a second hook from firing recursively.
    PVOID flagAddr = HookEntry->ShellcodeBase;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // -------------------------------------------------------------------
    // 1. Build gateway trampoline (64 bytes, written into user-mode alloc)
    //
    //    Copies the first 16 bytes of the target function verbatim, then
    //    appends: mov rax, <target+16> ; jmp rax
    //
    //    Safe for all ntdll syscall stubs (14-byte pattern:
    //      mov r10,rcx / mov eax,N / syscall / ret — 14 bytes total),
    //    so byte 16 is always the start of the next function or padding.
    // -------------------------------------------------------------------
    UCHAR gateway[64];
    RtlZeroMemory(gateway, sizeof(gateway));
    __try
    {
        ProbeForRead(HookDef->Address, 16, 1);
        RtlCopyMemory(gateway, HookDef->Address, 16);
        RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, 16);
        // Append: mov rax, <target+16> ; jmp rax
        gateway[16] = 0x48; gateway[17] = 0xB8;
        *(PVOID*)(gateway + 18) = (PVOID)((ULONG_PTR)HookDef->Address + 16);
        gateway[26] = 0xFF; gateway[27] = 0xE0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&apcState);
        return STATUS_ACCESS_VIOLATION;
    }
    __try
    {
        RtlCopyMemory(gatewayAddress, gateway, sizeof(gateway));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("UserModeHook: gateway write failed PID=%lu EventId=%lu\n", ProcessId, EventId);
        return STATUS_ACCESS_VIOLATION;
    }

    // -------------------------------------------------------------------
    // 2. Build shellcode by copying the const template then patching named
    //    struct fields. The compiler knows every offset via sizeof/offsetof.
    //    Zero manual byte arithmetic. Zero sentinel value checks.
    // -------------------------------------------------------------------
    SHELLCODE_LAYOUT sc;
    RtlCopyMemory(&sc, &g_ShellcodeTemplate, sizeof(sc));

    // Patch re-entrancy flag address (three references inside the shellcode)
    sc.grd_read_addr  = flagAddr;
    sc.grd_write_addr = flagAddr;
    sc.clr_addr       = flagAddr;

    // Patch event metadata
    sc.event_type = EventId;
    sc.process_id = ProcessId;

    // Patch FunctionName: 64-byte ANSI string split into 8 × 8-byte chunks
    // embedded as mov rax,imm64 immediates.
    // Use RtlCopyMemory into the imm fields to avoid packed-struct unaligned UB.
    CHAR fnBuf[64];
    RtlZeroMemory(fnBuf, sizeof(fnBuf));
    if (FunctionName != NULL)
    {
        SIZE_T i = 0;
        while (i < 63 && FunctionName[i] != '\0') { fnBuf[i] = FunctionName[i]; i++; }
    }
    RtlCopyMemory(&sc.fn[0].imm,   fnBuf +  0, 8);
    RtlCopyMemory(&sc.fn[1].imm,   fnBuf +  8, 8);
    RtlCopyMemory(&sc.fn[2].imm,   fnBuf + 16, 8);
    RtlCopyMemory(&sc.fn_l[0].imm, fnBuf + 24, 8);
    RtlCopyMemory(&sc.fn_l[1].imm, fnBuf + 32, 8);
    RtlCopyMemory(&sc.fn_l[2].imm, fnBuf + 40, 8);
    RtlCopyMemory(&sc.fn_l[3].imm, fnBuf + 48, 8);
    RtlCopyMemory(&sc.fn_l[4].imm, fnBuf + 56, 8);

    // Patch NtDeviceIoControlFile call arguments
    sc.file_handle = HookEntry->DriverDeviceHandle;
    sc.ioctl_code  = IoControlCode;
    sc.ntdeviceio  = TargetNtDeviceIo;

    // Patch Arg5 to point to the persistent IOSB inside the shellcode layout
    sc.arg5_iosb_addr = (PVOID)&((SHELLCODE_LAYOUT*)myShellcodeAddress)->Iosb;


    // Patch gateway jump: split 64-bit address into two 32-bit halves.
    // push imm32 + mov dword[rsp+4],imm32 + ret reconstructs the full
    // 64-bit return address without touching any general-purpose register.
    ULONG gatewayLow  = (ULONG)((ULONG_PTR)gatewayAddress & 0xFFFFFFFF);
    ULONG gatewayHigh = (ULONG)((ULONG_PTR)gatewayAddress >> 32);
    sc.gw_low    = gatewayLow;
    sc.gw_high   = gatewayHigh;
    // SKIP path (busy flag was set) also jumps to the gateway so execution
    // reaches the original function regardless.
    sc.skip_low  = gatewayLow;
    sc.skip_high = gatewayHigh;

    // Write the fully-patched shellcode into the user-mode allocation
    __try
    {
        RtlCopyMemory(myShellcodeAddress, &sc, sizeof(sc));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("UserModeHook: shellcode write failed PID=%lu EventId=%lu\n", ProcessId, EventId);
        return STATUS_ACCESS_VIOLATION;
    }

    // -------------------------------------------------------------------
    // 3. Install the hook: overwrite the first 16 bytes of the target
    //    function with an absolute indirect JMP (FF 25 00000000 <addr64>).
    //    Two trailing NOPs pad to 16 bytes so we always overwrite complete
    //    instruction boundaries for standard ntdll stubs.
    // -------------------------------------------------------------------
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 16;
    ULONG oldProt;

    status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize,
                                      PAGE_EXECUTE_READWRITE, &oldProt);
    if (NT_SUCCESS(status))
    {
        UCHAR jmp[16];
        RtlZeroMemory(jmp, 16);
        jmp[0] = 0xFF; jmp[1] = 0x25;           // FF 25 <rel32=0>
        *(PULONG)&jmp[2]  = 0;                   // RIP-relative offset = 0 → pointer follows immediately
        *(PVOID*)&jmp[6]  = myShellcodeAddress;  // absolute target
        jmp[14] = 0x90; jmp[15] = 0x90;          // NOP NOP

        RtlCopyMemory(HookDef->Address, jmp, 16);
        fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);

        HookEntry->ShellcodeUsed += totalSize;
        HookDef->IsHooked = TRUE;

        DbgPrint("UserModeHook: hooked %s PID=%lu shellcode=%p gateway=%p\n",
                 FunctionName ? FunctionName : "(null)", ProcessId,
                 myShellcodeAddress, gatewayAddress);
    }
    else
    {
        DbgPrint("UserModeHook: ZwProtectVirtualMemory failed PID=%lu EventId=%lu "
                 "status=0x%08X target=%p\n",
                 ProcessId, EventId, status, HookDef->Address);
    }

    KeUnstackDetachProcess(&apcState);
    if (!NT_SUCCESS(status))
        return status;
    if (!HookDef->IsHooked)
        return STATUS_UNSUCCESSFUL;
    return STATUS_SUCCESS;
}

//
// Inject Shellcode Initialization (Alloc + Handle)
//
NTSTATUS InitializeShellcodeInfrastructure(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    NTSTATUS status;
    KAPC_STATE apcState;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = 4096 * 2; // 2 Pages to be safe
    ULONG pid = HandleToULong(PsGetProcessId(Process));

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // 1. Allocate Shellcode Memory
    if (fnZwAllocateVirtualMemory)
    {
        status = fnZwAllocateVirtualMemory(ZwCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
    }
    else
    {
        status = STATUS_NOT_IMPLEMENTED;
    }

    if (!NT_SUCCESS(status))
    {
        DbgPrint("UserModeHook: ZwAllocateVirtualMemory failed PID=%lu status=0x%08X protect=RWX\n", pid, status);
        if (status == (NTSTATUS)0xC0000604)
        {
            DbgPrint("UserModeHook: PID %lu appears to block dynamic executable memory (ACG/DynamicCode policy)\n",
                     pid);
        }
        KeUnstackDetachProcess(&apcState);
        return status;
    }

    HookEntry->ShellcodeBase = baseAddress;
    HookEntry->ShellcodeSize = regionSize;
    HookEntry->ShellcodeUsed = 8;  // Reserve first 8 bytes for busy flag
    RtlZeroMemory(baseAddress, 8); // Zero the flag

    // 2. Create per-process device handle used by shellcode NtDeviceIoControlFile calls.
    // Open by name inside the attached process context so the handle lives in that process handle table.
    HANDLE targetHandle = NULL;
    UNICODE_STRING hookDevicePath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;

    // 1. Target the Global namespace so all sessions can resolve the object
    RtlInitUnicodeString(&hookDevicePath, L"\\DosDevices\\Global\\OwlyshieldHook");
    InitializeObjectAttributes(&objAttr, &hookDevicePath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    RtlZeroMemory(&ioStatus, sizeof(ioStatus));

    // 2. Open handle for ASYNCHRONOUS (non-blocking) communication.
    // READ ONLY: Minimal access and no SYNC flags to avoid blocking application threads.
    status = ZwCreateFile(&targetHandle, GENERIC_READ, &objAttr, &ioStatus, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
                          FILE_NON_DIRECTORY_FILE, 
                          NULL, 0);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("UserModeHook: ZwCreateFile(\\\\??\\\\OwlyshieldHook) failed PID=%lu status=0x%08X iosb=0x%08X\n", pid,
                 status, ioStatus.Status);
        if (fnZwFreeVirtualMemory)
        {
            SIZE_T freeSize = 0;
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &baseAddress, &freeSize, MEM_RELEASE);
        }
        KeUnstackDetachProcess(&apcState);
        return status;
    }

    HookEntry->DriverDeviceHandle = targetHandle;
    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}

//
// Helper: Resolve and Prepare Hook
//
NTSTATUS ResolveAndHook(_In_ PEPROCESS Process, _Inout_ PPROCESS_HOOK_ENTRY HookEntry, _In_ PCWSTR ModuleName,
                        _In_ PCSTR FunctionName, _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId,
                        _In_ PVOID TargetNtDeviceIo, _In_opt_ PVOID NewModuleBase)
{
    if (HookDef->IsHooked)
        return STATUS_SUCCESS;

    PVOID modBase = NULL;
    SIZE_T modSize = 0;

    // Stop blind arbitrary hooking until a proper Length Disassembler Engine (LDE) is added.
    // Blindly overwriting 16 bytes causes 0xc0000005 in complex functions (like igfxCUIService.exe internals or kernel32).
    // Syscalls in ntdll.dll are perfectly structured for 16-byte tramplines, so we restrict to ntdll.dll.
    if (_wcsicmp(ModuleName, L"ntdll.dll") != 0) {
        return STATUS_NOT_SUPPORTED;
    }

    // Explicit module check
    if (NewModuleBase)
    {
        // If NewModuleBase is provided, we only check if it matches the target ModuleName
        modBase = FindModuleBaseAddress(Process, ModuleName, &modSize);
        if (modBase != NewModuleBase)
            modBase = NULL; // Only hook if it's the module that just loaded
    }
    else
    {
        modBase = FindModuleBaseAddress(Process, ModuleName, &modSize);
    }

    if (modBase)
    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);
        HookDef->Address = FindExportedFunction(modBase, FunctionName);
        KeUnstackDetachProcess(&apcState);
    }

    if (!HookDef->Address)
        return STATUS_PROCEDURE_NOT_FOUND;

    ULONG ioControlCode = (ULONG)IOCTL_REPORT_HOOK_EVENT;

    return InjectSingleHook(Process, HookEntry->ProcessId, HookEntry, HookDef, EventId, FunctionName, TargetNtDeviceIo,
                            ioControlCode);
}

// ---------------------------------------------------------------------------
// PsGetProcessImageFileName and SeLocateProcessImageName are available
// via ntifs.h. No manual declarations are needed.
// ---------------------------------------------------------------------------

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId, _In_opt_ PVOID ImageBase)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;

    if (!IsProcessHookingEnabled())
    {
        UNREFERENCED_PARAMETER(ProcessId);
        UNREFERENCED_PARAMETER(ImageBase);
        return STATUS_SUCCESS;
    }

    DbgPrint("UserModeHook: UserModeHookProcess enter PID=%lu ImageBase=%p\n", ProcessId, ImageBase);

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
    {
        DbgPrint("UserModeHook: engine not initialized for PID %lu\n", ProcessId);
        return STATUS_DEVICE_NOT_READY;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("UserModeHook: PsLookupProcessByProcessId failed PID=%lu status=0x%08X\n", ProcessId, status);
        return status;
    }

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    // Check if already tracked
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry && hookEntry->IsHooked)
    {
        // Already tracked. Just apply any missing/newly added hooks.
        if (hookEntry->NtDeviceIoControlFileAddr)
        {
            ApplyHooksInternal(process, hookEntry, hookEntry->NtDeviceIoControlFileAddr, ImageBase);
        }
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }

    // Retry path for previously failed/partial slot.
    if (hookEntry && !hookEntry->IsHooked)
    {
        CleanupPartialHookEntry(process, hookEntry);
    }

    // Find free slot if process did not already have one
    if (hookEntry == NULL)
    {
        for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
        {
            if (!g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == 0)
            {
                hookEntry = &g_UserHookEngine->Processes[i];
                break;
            }
        }
    }

    if (hookEntry == NULL)
    {
        DbgPrint("UserModeHook: no free hook slot for PID %lu\n", ProcessId);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY)); // Clear it
    hookEntry->ProcessId = ProcessId;
    hookEntry->ProcessObject = process;

    // 1. Initialize Infrastructure (Alloc + Handle)
    status = InitializeShellcodeInfrastructure(process, hookEntry);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("UserModeHook: InitializeShellcodeInfrastructure failed PID=%lu status=0x%08X\n", ProcessId, status);
        CleanupPartialHookEntry(process, hookEntry);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return status;
    }

    // 2. Resolve NtDeviceIoControlFile (Needed for communication)
    SIZE_T ntdllSize = 0;
    PVOID ntdllBase = FindModuleBaseAddress(process, L"ntdll.dll", &ntdllSize);
    if (!ntdllBase)
    {
        DbgPrint("UserModeHook: FindModuleBaseAddress(ntdll.dll) failed PID=%lu\n", ProcessId);
        CleanupPartialHookEntry(process, hookEntry);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    PVOID targetNtDeviceIo = FindExportedFunction(ntdllBase, "NtDeviceIoControlFile");
    KeUnstackDetachProcess(&apcState);

    if (!targetNtDeviceIo)
    {
        DbgPrint("UserModeHook: FindExportedFunction(NtDeviceIoControlFile) failed PID=%lu\n", ProcessId);
        CleanupPartialHookEntry(process, hookEntry);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    hookEntry->NtDeviceIoControlFileAddr = targetNtDeviceIo;

    // 3. Inject Hooks (Generic!)
    // When initializing a new process entry, we pass NULL as NewModuleBase to trigger a FULL scan
    ApplyHooksInternal(process, hookEntry, targetNtDeviceIo, NULL);

    hookEntry->IsHooked = TRUE;
    g_UserHookEngine->HookedProcessCount++;
    DbgPrint("UserModeHook: Shellcodes Injected into PID %lu (Generic + %lu Custom)\n", ProcessId, g_CustomHookCount);

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Unhook
//

//
// Helper to Unhook Single Function
//
VOID UnhookSingleFunction(_In_ PEPROCESS Process, _Inout_ PHOOK_DEF HookDef)
{
    NTSTATUS status;
    KAPC_STATE apcState;
    if (!HookDef->IsHooked || !HookDef->Address)
        return;

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // Restore Original Bytes
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14;
    ULONG oldProt;

    if (fnZwProtectVirtualMemory)
    {
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (NT_SUCCESS(status))
        {
            RtlCopyMemory(HookDef->Address, HookDef->OriginalBytes, 16);
            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);
            HookDef->IsHooked = FALSE;
        }
    }

    KeUnstackDetachProcess(&apcState);
}

NTSTATUS UserModeUnhookProcessInternal(_Inout_ PPROCESS_HOOK_ENTRY HookEntry)
{
    PEPROCESS process = NULL;
    NTSTATUS status;
    ULONG processId = HookEntry->ProcessId;

    if (!HookEntry->IsHooked && HookEntry->ProcessId == 0)
        return STATUS_SUCCESS;

    DbgPrint("!!! UserModeHook: Unhooking process %lu\n", processId);

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)processId, &process);
    if (NT_SUCCESS(status))
    {
        // Unhook all functions
        UnhookSingleFunction(process, &HookEntry->NtWriteVirtualMemory);
        UnhookSingleFunction(process, &HookEntry->NtAllocateVirtualMemory);
        UnhookSingleFunction(process, &HookEntry->NtProtectVirtualMemory);
        UnhookSingleFunction(process, &HookEntry->NtCreateThreadEx);
        UnhookSingleFunction(process, &HookEntry->NtMapViewOfSection);

        // Unhook dynamic hooks
        if (HookEntry->CustomHooks)
        {
            for (ULONG i = 0; i < MAX_CUSTOM_HOOKS; i++)
            {
                UnhookSingleFunction(process, &HookEntry->CustomHooks[i]);
            }
        }

        // Free Shellcode Memory using ZwFreeVirtualMemory
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)process, &apcState);

        if (HookEntry->ShellcodeBase && fnZwFreeVirtualMemory)
        {
            SIZE_T size = 0;
            fnZwFreeVirtualMemory(ZwCurrentProcess(), &HookEntry->ShellcodeBase, &size, MEM_RELEASE);
            HookEntry->ShellcodeBase = NULL;
        }

        // Close Handle
        if (HookEntry->DriverDeviceHandle)
        {
            ZwClose(HookEntry->DriverDeviceHandle);
            HookEntry->DriverDeviceHandle = NULL;
        }

        KeUnstackDetachProcess(&apcState);

        // Free dynamically allocated hooks
        if (HookEntry->CustomHooks)
        {
            ExFreePoolWithTag(HookEntry->CustomHooks, 'UMHd');
            HookEntry->CustomHooks = NULL;
        }

        ObDereferenceObject(process);
    }

    // Always free the pool memory if it exists
    if (HookEntry->CustomHooks)
    {
        ExFreePoolWithTag(HookEntry->CustomHooks, 'UMHd');
        HookEntry->CustomHooks = NULL;
    }

    HookEntry->IsHooked = FALSE;
    HookEntry->ProcessId = 0;
    HookEntry->ProcessObject = NULL;
    if (g_UserHookEngine)
        g_UserHookEngine->HookedProcessCount--;

    return STATUS_SUCCESS;
}

NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    PPROCESS_HOOK_ENTRY hookEntry = NULL;

    if (!IsProcessHookingEnabled())
    {
        UNREFERENCED_PARAMETER(ProcessId);
        return STATUS_SUCCESS;
    }

    if (g_UserHookEngine == NULL)
        return STATUS_DEVICE_NOT_READY;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry == NULL)
    {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }

    NTSTATUS status = UserModeUnhookProcessInternal(hookEntry);

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    return status;
}
