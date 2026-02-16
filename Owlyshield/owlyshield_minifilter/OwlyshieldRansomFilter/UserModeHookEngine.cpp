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

VOID ApplyHooksInternal(PEPROCESS Process, PPROCESS_HOOK_ENTRY HookEntry, PVOID TargetNtDeviceIo, PVOID NewModuleBase)
{
    NTSTATUS st = STATUS_SUCCESS;

    // NTDLL Hooks (Default)
    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtWriteVirtualMemory", &HookEntry->NtWriteVirtualMemory, 12,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtWriteVirtualMemory (id=12) -> 0x%08X\n", HookEntry->ProcessId, st);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtAllocateVirtualMemory", &HookEntry->NtAllocateVirtualMemory, 13,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtAllocateVirtualMemory (id=13) -> 0x%08X\n", HookEntry->ProcessId, st);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtProtectVirtualMemory", &HookEntry->NtProtectVirtualMemory, 14,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtProtectVirtualMemory (id=14) -> 0x%08X\n", HookEntry->ProcessId, st);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtCreateThreadEx", &HookEntry->NtCreateThreadEx, 15,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtCreateThreadEx (id=15) -> 0x%08X\n", HookEntry->ProcessId, st);

    st = ResolveAndHook(Process, HookEntry, L"ntdll.dll", "NtMapViewOfSection", &HookEntry->NtMapViewOfSection, 19,
                        TargetNtDeviceIo, NewModuleBase);
    DbgPrint("UserModeHook: PID %lu hook NtMapViewOfSection (id=19) -> 0x%08X\n", HookEntry->ProcessId, st);

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
    // ===== SAVE VOLATILE REGISTERS =====
    0x50,       // push rax
    0x51,       // push rcx
    0x52,       // push rdx
    0x53,       // push rbx
    0x41, 0x50, // push r8
    0x41, 0x51, // push r9
    0x41, 0x52, // push r10
    0x41, 0x53, // push r11

    // ===== ALLOCATE STACK SPACE =====
    // 240 bytes: HOOK_EVENT_DATA(80) + storage(8) + IO_STATUS_BLOCK(16) + params(80) + shadow(32) + align
    0x48, 0x81, 0xEC, 0xF0, 0x00, 0x00, 0x00, // sub rsp, 0xF0 (240 bytes)

    // ===== FILL HOOK_EVENT_DATA at [RSP+0x00] =====

    // EventType (DWORD at offset 0) - PATCHED at offset 21 in shellcode array
    0xC7, 0x04, 0x24, 0x11, 0x11, 0x11, 0x11, // mov dword [rsp], 0x11111111

    // ProcessId (DWORD at offset 4) - PATCHED at offset 28 in shellcode array
    0xC7, 0x44, 0x24, 0x04, 0x22, 0x22, 0x22, 0x22, // mov dword [rsp+4], 0x22222222

    // FunctionName (64 bytes at offset 8): 8 x qword stores.
    // Immediates are patched by InjectSingleHook from the target API name.
    // [rsp+0x08]
    0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x48, 0x89, 0x44, 0x24, 0x08,
    // [rsp+0x10]
    0x48, 0xB8, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x48, 0x89, 0x44, 0x24, 0x10,
    // [rsp+0x18]
    0x48, 0xB8, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x48, 0x89, 0x44, 0x24, 0x18,
    // [rsp+0x20]
    0x48, 0xB8, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99,
    0x48, 0x89, 0x44, 0x24, 0x20,
    // [rsp+0x28]
    0x48, 0xB8, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
    0x48, 0x89, 0x44, 0x24, 0x28,
    // [rsp+0x30]
    0x48, 0xB8, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC, 0xBC,
    0x48, 0x89, 0x44, 0x24, 0x30,
    // [rsp+0x38]
    0x48, 0xB8, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
    0x48, 0x89, 0x44, 0x24, 0x38,
    // [rsp+0x40]
    0x48, 0xB8, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE, 0xDE,
    0x48, 0x89, 0x44, 0x24, 0x40,

    // Arg1 (ULONG_PTR at offset 72 = 0x48)
    // Saved RCX is at: [current_RSP + 0xF0 (our alloc) + 56 (7th of 8 pushes)] = [RSP + 0x128]
    0x48, 0x8B, 0x84, 0x24, 0x28, 0x01, 0x00, 0x00, // mov rax, [rsp+0x128]
    0x48, 0x89, 0x44, 0x24, 0x48,                   // mov [rsp+0x48], rax

    // Arg2 (ULONG_PTR at offset 80 = 0x50)
    // Saved RDX is at: [RSP + 0xF0 + 48] = [RSP + 0x120]
    0x48, 0x8B, 0x84, 0x24, 0x20, 0x01, 0x00, 0x00, // mov rax, [rsp+0x120]
    0x48, 0x89, 0x44, 0x24, 0x50,                   // mov [rsp+0x50], rax

    // Zero out IO_STATUS_BLOCK at [RSP+0x58] (16 bytes)
    0x48, 0x31, 0xC0,             // xor rax, rax
    0x48, 0x89, 0x44, 0x24, 0x58, // mov [rsp+0x58], rax
    0x48, 0x89, 0x44, 0x24, 0x60, // mov [rsp+0x60], rax

    // ===== PREPARE NtDeviceIoControlFile CALL =====

    // RCX = FileHandle - PATCHED at offset 83 in shellcode array
    0x48, 0xB9, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // mov rcx, 0x3333333333333333

    // RDX = Event = NULL
    0x48, 0x31, 0xD2, // xor rdx, rdx

    // R8 = ApcRoutine = NULL
    0x4D, 0x31, 0xC0, // xor r8, r8

    // R9 = ApcContext = NULL
    0x4D, 0x31, 0xC9, // xor r9, r9

    // Stack Parameter 1 (5th param): IoStatusBlock pointer at [RSP+0x20]
    0x48, 0x8D, 0x44, 0x24, 0x58, // lea rax, [rsp+0x58]
    0x48, 0x89, 0x44, 0x24, 0x20, // mov [rsp+0x20], rax

    // Stack Parameter 2 (6th param): IoControlCode at [RSP+0x28] - PATCHED at offset 126
    // This needs to be your driver's IOCTL code (e.g., CTL_CODE value)
    0xC7, 0x44, 0x24, 0x28, 0xAA, 0xAA, 0xAA, 0xAA, // mov dword [rsp+0x28], 0xAAAAAAAA

    // Stack Parameter 3 (7th param): InputBuffer (pointer to HOOK_EVENT_DATA) at [RSP+0x30]
    0x48, 0x8D, 0x04, 0x24,       // lea rax, [rsp] (HOOK_EVENT_DATA at base)
    0x48, 0x89, 0x44, 0x24, 0x30, // mov [rsp+0x30], rax

    // Stack Parameter 4 (8th param): InputBufferLength at [RSP+0x38]
    0xC7, 0x44, 0x24, 0x38, 0x58, 0x00, 0x00, 0x00, // mov dword [rsp+0x38], 88 (sizeof HOOK_EVENT_DATA)

    // Stack Parameter 5 (9th param): OutputBuffer at [RSP+0x40] = NULL
    0x48, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, // mov qword [rsp+0x40], 0

    // Stack Parameter 6 (10th param): OutputBufferLength at [RSP+0x48] = 0
    0xC7, 0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, // mov dword [rsp+0x48], 0

    // ===== CALL NtDeviceIoControlFile =====
    // Function address PATCHED at offset 171 in shellcode array
    0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, // mov rax, 0x4444444444444444
    0xFF, 0xD0,                                                 // call rax

    // ===== RESTORE STACK =====
    0x48, 0x81, 0xC4, 0xF0, 0x00, 0x00, 0x00, // add rsp, 0xF0

    // ===== RESTORE REGISTERS =====
    0x41, 0x5B, // pop r11
    0x41, 0x5A, // pop r10
    0x41, 0x59, // pop r9
    0x41, 0x58, // pop r8
    0x5B,       // pop rbx
    0x5A,       // pop rdx
    0x59,       // pop rcx
    0x58,       // pop rax

    // ===== EXECUTE ORIGINAL INSTRUCTION (14 bytes) =====
    // PATCHED at offset 197 in shellcode array - stolen bytes from hooked function
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,

    // ===== JUMP BACK TO ORIGINAL CODE =====
    // Return address PATCHED at offset 213 in shellcode array (original function + 14)
    0x48, 0xB8, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, // mov rax, 0x5555555555555555
    0xFF, 0xE0,                                                 // jmp rax

    // ===== PADDING =====
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90};

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

//
// Helper to Inject a Single Hook
//
NTSTATUS InjectSingleHook(_In_ PEPROCESS Process, _In_ ULONG ProcessId, _Inout_ PPROCESS_HOOK_ENTRY HookEntry,
                          _Inout_ PHOOK_DEF HookDef, _In_ ULONG EventId, _In_opt_ PCSTR FunctionName, _In_ PVOID TargetNtDeviceIo,
                          _In_ ULONG IoControlCode)
{
    NTSTATUS status;
    KAPC_STATE apcState;

    if (!HookDef->Address)
        return STATUS_INVALID_PARAMETER;
    if (HookDef->IsHooked)
        return STATUS_SUCCESS; // Already hooked

    // Calculate Offset
    if (HookEntry->ShellcodeUsed + sizeof(g_ShellcodeTemplate) > HookEntry->ShellcodeSize)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PVOID myShellcodeAddress = (PVOID)((ULONG_PTR)HookEntry->ShellcodeBase + HookEntry->ShellcodeUsed);

    KeStackAttachProcess((PRKPROCESS)Process, &apcState);

    // 1. Prepare Shellcode (Copy and Patch)
    UCHAR shellcode[sizeof(g_ShellcodeTemplate)];
    RtlCopyMemory(shellcode, g_ShellcodeTemplate, sizeof(shellcode));

    // Safety checks for patch markers in the template.
    if (*(PULONG)(shellcode + 22) != 0x11111111 ||
        *(PULONG)(shellcode + 30) != 0x22222222 ||
        *(PULONGLONG)(shellcode + 195) != 0x3333333333333333ULL ||
        *(PULONG)(shellcode + 226) != 0xAAAAAAAA ||
        *(PULONGLONG)(shellcode + 266) != 0x4444444444444444ULL ||
        *(PULONGLONG)(shellcode + 311) != 0x5555555555555555ULL) {
        KeUnstackDetachProcess(&apcState);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    // NEW (CORRECT):
    *(PULONG)(shellcode + 22) = EventId;
    *(PULONG)(shellcode + 30) = ProcessId;

    // Patch FunctionName in payload region (8x8 bytes, ANSI).
    // FunctionName immediates start at these offsets.
    const ULONG fnImmOffsets[8] = {36, 51, 66, 81, 96, 111, 126, 141};
    CHAR fnBuf[64];
    RtlZeroMemory(fnBuf, sizeof(fnBuf));
    if (FunctionName != NULL) {
        SIZE_T i = 0;
        for (; i < (sizeof(fnBuf) - 1) && FunctionName[i] != '\0'; i++) {
            fnBuf[i] = FunctionName[i];
        }
    }
    for (ULONG i = 0; i < RTL_NUMBER_OF(fnImmOffsets); i++) {
        ULONGLONG chunk = 0;
        RtlCopyMemory(&chunk, fnBuf + (i * 8), sizeof(chunk));
        *(PULONGLONG)(shellcode + fnImmOffsets[i]) = chunk;
    }

    // Patch FileHandle at offset 195
    *(PHANDLE)(shellcode + 195) = HookEntry->DriverDeviceHandle;

    // Patch IoControlCode at offset 226
    *(PULONG)(shellcode + 226) = IoControlCode;

    // Patch NtDeviceIoControlFile Address at offset 266
    *(PVOID *)(shellcode + 266) = TargetNtDeviceIo;

    // Patch Stolen Bytes at offset 295 (14 bytes from original function)
    RtlCopyMemory(shellcode + 295, HookDef->Address, 14);

    // Save original bytes locally (for unhooking later)
    RtlCopyMemory(HookDef->OriginalBytes, HookDef->Address, 14);

    // Patch Return Address at offset 311 -> Original Addr + 14
    *(PVOID *)(shellcode + 311) = (PVOID)((ULONG_PTR)HookDef->Address + 14);

    // Write Shellcode to Target Process Memory
    RtlCopyMemory(myShellcodeAddress, shellcode, sizeof(shellcode));

    // 2. Install Hook (JMP to Shellcode)
    PVOID pageAddr = HookDef->Address;
    SIZE_T pageSize = 14;
    ULONG oldProt;
    if (fnZwProtectVirtualMemory)
    {
        status = fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, PAGE_EXECUTE_READWRITE, &oldProt);
        if (NT_SUCCESS(status))
        {
            // Write JMP [RIP+0] -> Shellcode Address
            // FF 25 00 00 00 00 [8-byte Address]
            UCHAR jmp[14];
            RtlZeroMemory(jmp, 14);
            jmp[0] = 0xFF;
            jmp[1] = 0x25;
            *(PULONG)&jmp[2] = 0;
            *(PVOID *)&jmp[6] = myShellcodeAddress;

            RtlCopyMemory(HookDef->Address, jmp, 14);

            fnZwProtectVirtualMemory(ZwCurrentProcess(), &pageAddr, &pageSize, oldProt, &oldProt);

            HookEntry->ShellcodeUsed += sizeof(g_ShellcodeTemplate);
            HookDef->IsHooked = TRUE;
        }
    }

    KeUnstackDetachProcess(&apcState);
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
        KeUnstackDetachProcess(&apcState);
        return status;
    }

    HookEntry->ShellcodeBase = baseAddress;
    HookEntry->ShellcodeSize = regionSize;
    HookEntry->ShellcodeUsed = 0;

    // 2. Create Handle
    HANDLE targetHandle = NULL;
    status = ObOpenObjectByPointer(g_HookDeviceObject, OBJ_CASE_INSENSITIVE, NULL, GENERIC_READ | GENERIC_WRITE,
                                   *IoFileObjectType, KernelMode, &targetHandle);

    if (!NT_SUCCESS(status))
    {
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

    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status))
        return status;

    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);

    // Check if already being monitored
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == ProcessId)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry)
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

    // Find free slot
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (!g_UserHookEngine->Processes[i].IsHooked && g_UserHookEngine->Processes[i].ProcessId == 0)
        {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }

    if (hookEntry == NULL)
    {
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
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return status;
    }

    // 2. Resolve NtDeviceIoControlFile (Needed for communication)
    SIZE_T ntdllSize = 0;
    PVOID ntdllBase = FindModuleBaseAddress(process, L"ntdll.dll", &ntdllSize);
    if (!ntdllBase)
    {
        UserModeUnhookProcess(ProcessId);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }

    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);
    PVOID targetNtDeviceIo = FindExportedFunction(ntdllBase, "NtDeviceIoControlFile");
    KeUnstackDetachProcess(&apcState);

    if (!targetNtDeviceIo)
    {
        UserModeUnhookProcess(ProcessId);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
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
            RtlCopyMemory(HookDef->Address, HookDef->OriginalBytes, 14);
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
