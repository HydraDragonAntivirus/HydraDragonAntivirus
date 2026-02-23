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
    NTSTATUS st = STATUS_SUCCESS;
    auto dump_hook_bytes = [&](PCSTR hookName, PHOOK_DEF hookDef) {
        UCHAR bytes[6] = {0};

        if (hookDef == NULL || hookDef->Address == NULL) {
            DbgPrint("UserModeHook: %s address is NULL\n", hookName);
            return;
        }

        KAPC_STATE vs;
        KeStackAttachProcess((PRKPROCESS)Process, &vs);
        __try {
            RtlCopyMemory(bytes, hookDef->Address, sizeof(bytes));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            RtlZeroMemory(bytes, sizeof(bytes));
        }
        KeUnstackDetachProcess(&vs);

        DbgPrint("UserModeHook: %s bytes: %02X %02X %02X %02X %02X %02X\n",
            hookName, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
    };

    // NTDLL Hooks (Default)
    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtWriteVirtualMemory", &HookEntry->NtWriteVirtualMemory, 13,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtWriteVirtualMemory (id=13) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtWriteVirtualMemory", &HookEntry->NtWriteVirtualMemory);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtAllocateVirtualMemory", &HookEntry->NtAllocateVirtualMemory, 14,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtAllocateVirtualMemory (id=14) -> 0x%08X\n", HookEntry->ProcessId, st);
    dump_hook_bytes("NtAllocateVirtualMemory", &HookEntry->NtAllocateVirtualMemory);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtProtectVirtualMemory", &HookEntry->NtProtectVirtualMemory, 15,
                        TargetNtDeviceIo, NewModuleBase);
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
                DbgPrint("UserModeHook: PID %lu hook %ws!%s (id=%lu) -> 0x%08X\n",
                    HookEntry->ProcessId,
                    g_GlobalCustomHooks[i].ModuleName,
                    g_GlobalCustomHooks[i].FunctionName,
                    g_GlobalCustomHooks[i].EventId,
                    st);
            }
        }
        ExReleaseFastMutex(&g_ConfigMutex);
    }
}

VOID ApplyGlobalHooksToAll()
{
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

// Complete x64 Shellcode for API Hooking
// Properly calls NtDeviceIoControlFile with all 10 parameters
// Stack Layout (after register saves and sub rsp):
// [RSP+0x00]  = HOOK_EVENT_DATA (88 bytes)
// [RSP+0x50]  = Arg2 storage (8 bytes)
// [RSP+0x58]  = IO_STATUS_BLOCK (16 bytes)
// [RSP+0x68]  = Shadow space + stack params (80 bytes)
// [RSP+0xB8]  = Return to saved registers
// Total stack allocation: 0xF0 (240 bytes)

UCHAR g_ShellcodeTemplate[] = {
    // ===== RE-ENTRANCY GUARD =====
    0x50,                                                       // push rax
    0x48, 0xA1, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, // mov rax, [FLAG_ADDR]
    0x48, 0x85, 0xC0,                                           // test rax, rax
    0x0F, 0x85, 0x76, 0x01, 0x00, 0x00,                         // jnz SKIP (offset 394)
    0x58,                                                       // pop rax
    0x50,                                                       // push rax
    0x48, 0xB8, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, // mov rax, FLAG_ADDR
    0x48, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00,                   // mov qword [rax], 1
    0x58,                                                       // pop rax

    // ===== SAVE VOLATILE REGISTERS =====
    0x50, 0x51, 0x52, 0x53,                                     // push rax, rcx, rdx, rbx
    0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,             // push r8, r9, r10, r11

    // ===== ALLOCATE ALIGNED STACK SPACE =====
    0x48, 0x81, 0xEC, 0xF8, 0x00, 0x00, 0x00,                   // sub rsp, 0xF8

    // ===== FILL HOOK_EVENT_DATA (RSP+0x60) =====
    0xC7, 0x44, 0x24, 0x60, 0x11, 0x11, 0x11, 0x11,             // EventType (Offset 63)
    0xC7, 0x44, 0x24, 0x64, 0x22, 0x22, 0x22, 0x22,             // ProcessId (Offset 71)
    
    // FunctionName (64 bytes)
    0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x48, 0x89, 0x44, 0x24, 0x68,
    0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x48, 0x89, 0x44, 0x24, 0x70,
    0x48, 0xB8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x48, 0x89, 0x44, 0x24, 0x78,
    0x48, 0xB8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0x48, 0x89, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0x48, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0x48, 0x89, 0x84, 0x24, 0x98, 0x00, 0x00, 0x00,
    0x48, 0xB8, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0x48, 0x89, 0x84, 0x24, 0xA0, 0x00, 0x00, 0x00,
    
    // Arg1 = RCX
    0x48, 0x8B, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xA8, 0x00, 0x00, 0x00,
    // Arg2 = RDX
    0x48, 0x8B, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, 0x48, 0x89, 0x84, 0x24, 0xB0, 0x00, 0x00, 0x00,

    // ===== PREPARE STACK PARAMS (ZERO THEM FIRST) =====
    0x48, 0x31, 0xC0,                                           // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x20,                               // mov [rsp+20h], rax (Arg5/Shadow)
    0x48, 0x89, 0x44, 0x24, 0x28,                               // mov [rsp+28h], rax (Arg6)
    0x48, 0x89, 0x44, 0x24, 0x30,                               // mov [rsp+30h], rax (Arg7)
    0x48, 0x89, 0x44, 0x24, 0x38,                               // mov [rsp+38h], rax (Arg8)
    0x48, 0x89, 0x44, 0x24, 0x40,                               // mov [rsp+40h], rax (Arg9)
    0x48, 0x89, 0x44, 0x24, 0x48,                               // mov [rsp+48h], rax (Arg10)
    0x48, 0x89, 0x44, 0x24, 0x50,                               // mov [rsp+50h], rax (IO_STATUS_BLOCK)
    0x48, 0x89, 0x44, 0x24, 0x58,                               // mov [rsp+58h], rax (IO_STATUS_BLOCK)

    // ===== SETUP NtDeviceIoControlFile =====
    0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // FileHandle (Offset 277)
    0x48, 0x31, 0xD2,                                           // xor rdx, rdx 
    0x4D, 0x31, 0xC0,                                           // xor r8, r8   
    0x4D, 0x31, 0xC9,                                           // xor r9, r9   
    
    0x48, 0x8D, 0x44, 0x24, 0x50,                               // lea rax, [rsp+50h] -> IoStatusBlock
    0x48, 0x89, 0x44, 0x24, 0x20,                               // mov [rsp+20h], rax
    
    0xC7, 0x44, 0x24, 0x28, 0xAA, 0xAA, 0xAA, 0xAA,             // IoControlCode (Offset 308)
    
    0x48, 0x8D, 0x44, 0x24, 0x60,                               // lea rax, [rsp+60h] -> InputBuffer
    0x48, 0x89, 0x44, 0x24, 0x30,                               // mov [rsp+30h], rax
    
    0xC7, 0x44, 0x24, 0x38, 0x58, 0x00, 0x00, 0x00,             // InputBufferLength = 88 bytes

    0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // NtDeviceIoControlFile (Offset 332)
    0xFF, 0xD0,                                                 // call rax

    // ===== CLEAR BUSY FLAG =====
    0x50,                                                       // push rax
    0x48, 0xB8, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, // mov rax, FLAG_ADDR (Offset 345)
    0x48, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,                   // mov qword [rax], 0
    0x58,                                                       // pop rax

    // ===== RESTORE STACK & REGISTERS =====
    0x48, 0x81, 0xC4, 0xF8, 0x00, 0x00, 0x00,                   // add rsp, 0xF8
    0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,             // pop r11, r10, r9, r8
    0x5B, 0x5A, 0x59, 0x58,                                     // pop rbx, rdx, rcx, rax

    // ===== SAFE JUMP TO GATEWAY (Preserves RAX) =====
    0x68, 0x55, 0x55, 0x55, 0x55,                               // push LOW_32_BITS (Offset 381)
    0xC7, 0x44, 0x24, 0x04, 0x55, 0x55, 0x55, 0x55,             // mov dword [rsp+4], HIGH_32_BITS (Offset 389)
    0xC3,                                                       // ret

    // ===== SKIP TARGET: busy path =====
    0x58,                                                       // pop rax
    0x68, 0xBB, 0xBB, 0xBB, 0xBB,                               // push LOW_32_BITS (Offset 396)
    0xC7, 0x44, 0x24, 0x04, 0xBB, 0xBB, 0xBB, 0xBB,             // mov dword [rsp+4], HIGH_32_BITS (Offset 404)
    0xC3                                                        // ret
};

//
// Initialize the user-mode hooking engine
//

NTSTATUS UserModeHookEngineInitialize(VOID)
{
    DbgPrint("!!! UserModeHook: Initializing user-mode hooking engine...\n");

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

    SIZE_T totalSize = sizeof(g_ShellcodeTemplate) + 64;
    if (HookEntry->ShellcodeUsed + totalSize > HookEntry->ShellcodeSize)
        return STATUS_INSUFFICIENT_RESOURCES;

    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);
    PVOID gatewayAddress = (PVOID)((ULONG_PTR)myShellcodeAddress + sizeof(g_ShellcodeTemplate));
    PVOID flagAddr = HookEntry->ShellcodeBase; // First 8 bytes = busy flag

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // 1. Create gateway trampoline
    UCHAR gateway[64];
    RtlZeroMemory(gateway, sizeof(gateway));
    __try
    {
        ProbeForRead(HookDef->Address, 16, 1);
        RtlCopyMemory(gateway, HookDef->Address, 16);
        RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, 16);
        gateway[16] = 0x48;
        gateway[17] = 0xB8;
        *(PVOID*)(gateway + 18) = (PVOID)((ULONG_PTR)HookDef->Address + 16);
        gateway[26] = 0xFF;
        gateway[27] = 0xE0;
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

    // 2. Prepare shellcode
    UCHAR shellcode[sizeof(g_ShellcodeTemplate)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, sizeof(shellcode));

    // Safety checks (Updated for new precise shellcode lengths)
    if (*(PULONG)(shellcode + 63) != 0x11111111 || *(PULONG)(shellcode + 71) != 0x22222222 ||
        *(PULONGLONG)(shellcode + 277) != 0x3333333333333333ULL || *(PULONG)(shellcode + 308) != 0xAAAAAAAA ||
        *(PULONGLONG)(shellcode + 332) != 0x4444444444444444ULL)
    {
        KeUnstackDetachProcess(&apcState);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // Patch FLAG_ADDR
    *(PVOID *)(shellcode + 3) = flagAddr;
    *(PVOID *)(shellcode + 24) = flagAddr;
    *(PVOID *)(shellcode + 345) = flagAddr;

    // Patch EventType and ProcessId
    *(PULONG)(shellcode + 63) = EventId;
    *(PULONG)(shellcode + 71) = ProcessId;

    // Patch FunctionName 
    const ULONG fnImmOffsets[8] = {77, 92, 107, 122, 140, 158, 176, 194};
    CHAR fnBuf[64];
    RtlZeroMemory(fnBuf, sizeof(fnBuf));
    if (FunctionName != NULL)
    {
        for (SIZE_T i = 0; i < 63 && FunctionName[i] != '\0'; i++)
            fnBuf[i] = FunctionName[i];
    }
    for (ULONG i = 0; i < 8; i++)
    {
        ULONGLONG chunk = 0;
        RtlCopyMemory(&chunk, fnBuf + (i * 8), sizeof(chunk));
        *(PULONGLONG)(shellcode + fnImmOffsets[i]) = chunk;
    }

    // Patch API Control blocks
    *(PHANDLE)(shellcode + 277) = HookEntry->DriverDeviceHandle;
    *(PULONG)(shellcode + 308) = IoControlCode;
    *(PVOID *)(shellcode + 332) = TargetNtDeviceIo;

    // Patch the safe Gateway jumps (Splitting 64-bit addresses to avoid register clobbering)
    ULONG gatewayLow = (ULONG)((ULONG_PTR)gatewayAddress & 0xFFFFFFFF);
    ULONG gatewayHigh = (ULONG)(((ULONG_PTR)gatewayAddress >> 32) & 0xFFFFFFFF);

    *(PULONG)(shellcode + 381) = gatewayLow;
    *(PULONG)(shellcode + 389) = gatewayHigh;
    *(PULONG)(shellcode + 396) = gatewayLow;
    *(PULONG)(shellcode + 404) = gatewayHigh;

    // Write shellcode
    __try
    {
        RtlCopyMemory(myShellcodeAddress, shellcode, sizeof(shellcode));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        KeUnstackDetachProcess(&apcState);
        DbgPrint("UserModeHook: shellcode write failed PID=%lu EventId=%lu\n", ProcessId, EventId);
        return STATUS_ACCESS_VIOLATION;
    }

    // 3. Install hook (JMP to shellcode)
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14;
    ULONG oldProt;

    status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
    if (NT_SUCCESS(status))
    {
        UCHAR jmp[16];
        RtlZeroMemory(jmp, 16);
        jmp[0] = 0xFF;
        jmp[1] = 0x25;
        *(PULONG)&jmp[2] = 0;
        *(PVOID*)&jmp[6] = myShellcodeAddress;
        jmp[14] = 0x90;
        jmp[15] = 0x90;
        RtlCopyMemory(HookDef->Address, jmp, 16);
        fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);

        HookEntry->ShellcodeUsed += totalSize;
        HookDef->IsHooked = TRUE;
    }
    else
    {
        DbgPrint("UserModeHook: ZwProtectVirtualMemory failed PID=%lu EventId=%lu status=0x%08X target=%p\n",
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
        if (status == (NTSTATUS)0xC0000604) {
            DbgPrint("UserModeHook: PID %lu appears to block dynamic executable memory (ACG/DynamicCode policy)\n", pid);
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

    // 2. Add FILE_SYNCHRONOUS_IO_NONALERT to enforce blocking I/O
    status = ZwCreateFile(&targetHandle, 
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, 
                        &objAttr, &ioStatus, NULL,
                        FILE_ATTRIBUTE_NORMAL, 
                        FILE_SHARE_READ | FILE_SHARE_WRITE, 
                        FILE_OPEN, 
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, // CRITICAL FIX
                        NULL, 0);

    if (!NT_SUCCESS(status))
    {
        DbgPrint("UserModeHook: ZwCreateFile(\\\\??\\\\OwlyshieldHook) failed PID=%lu status=0x%08X iosb=0x%08X\n",
                 pid, status, ioStatus.Status);
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

    // Wildcard Module Search
    if (ModuleName[0] == L'*' && ModuleName[1] == L'\0')
    {
        KAPC_STATE apcState;
        KeStackAttachProcess((PRKPROCESS)Process, &apcState);

        if (NewModuleBase)
        {
            // Targeted scan of newly loaded module
            HookDef->Address = FindExportedFunction(NewModuleBase, FunctionName);
            if (HookDef->Address)
                modBase = NewModuleBase;
        }
        else
        {
            // Full scan of all modules (Initial hook or retroactive)
            __try
            {
                PPEB peb = fnPsGetProcessPeb(Process);
                if (peb && peb->Ldr)
                {
                    PLIST_ENTRY listHead = &peb->Ldr->InLoadOrderModuleList;
                    for (PLIST_ENTRY entry = listHead->Flink; entry != listHead; entry = entry->Flink)
                    {
                        PLDR_DATA_TABLE_ENTRY ldrEntry =
                            CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                        if (ldrEntry->DllBase)
                        {
                            HookDef->Address = FindExportedFunction(ldrEntry->DllBase, FunctionName);
                            if (HookDef->Address)
                            {
                                modBase = ldrEntry->DllBase;
                                break;
                            }
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
            }
        }
        KeUnstackDetachProcess(&apcState);
    }
    else
    {
        // Explicit module check
        if (NewModuleBase)
        {
            // If NewModuleBase is provided, we only check if it matches the target ModuleName
            // Note: FindModuleBaseAddress handles string comparison
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
    }

    if (!HookDef->Address)
        return STATUS_PROCEDURE_NOT_FOUND;

    ULONG ioControlCode = (ULONG)IOCTL_REPORT_HOOK_EVENT;

    return InjectSingleHook(Process, HookEntry->ProcessId, HookEntry, HookDef, EventId, FunctionName, TargetNtDeviceIo,
                            ioControlCode);
}

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId, _In_opt_ PVOID ImageBase)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;

    DbgPrint("UserModeHook: UserModeHookProcess enter PID=%lu ImageBase=%p\n", ProcessId, ImageBase);

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized) {
        DbgPrint("UserModeHook: engine not initialized for PID %lu\n", ProcessId);
        return STATUS_DEVICE_NOT_READY;
    }

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
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
