/*++

Module Name:

    UserModeHookEngine.cpp

Abstract:

    Implementation of user-mode ntdll.dll hooking engine.
    FIXED: Uses dynamic resolution for PsGetProcessPeb and ZwProtectVirtualMemory.

Environment:

    Kernel mode

--*/

#include "UserModeHookEngine.h"
#include <ntimage.h>

// -------------------------------------------------------------------------
// DYNAMIC IMPORT DEFINITIONS
// -------------------------------------------------------------------------

// Function Pointer Types
typedef NTSTATUS(NTAPI *PZW_PROTECT_VIRTUAL_MEMORY)(_In_ HANDLE ProcessHandle, _Inout_ PVOID *BaseAddress,
                                                    _Inout_ PSIZE_T RegionSize, _In_ ULONG NewProtect,
                                                    _Out_ PULONG OldProtect);

typedef PPEB(NTAPI *PPS_GET_PROCESS_PEB)(_In_ PEPROCESS Process);

// Global Function Pointers
static PZW_PROTECT_VIRTUAL_MEMORY fnZwProtectVirtualMemory = NULL;
static PPS_GET_PROCESS_PEB fnPsGetProcessPeb = NULL;

PUSERMODE_HOOK_ENGINE g_UserHookEngine = NULL;

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
        if (g_UserHookEngine->Processes[i].IsHooked)
        {
            UserModeUnhookProcess(g_UserHookEngine->Processes[i].ProcessId);
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

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId, _In_opt_ PVOID DetourAddress_NtWrite,
                             _In_opt_ PVOID DetourAddress_NtAlloc)
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

    // Find free slot
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++)
    {
        if (!g_UserHookEngine->Processes[i].IsHooked)
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

    hookEntry->ProcessId = ProcessId;
    hookEntry->ProcessObject = process;

    // Find ntdll.dll
    hookEntry->NtdllBase = FindModuleBaseAddress(process, L"ntdll.dll", &hookEntry->NtdllSize);
    if (!hookEntry->NtdllBase)
    {
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    // Resolve Addresses
    KAPC_STATE apcState;
    KeStackAttachProcess((PRKPROCESS)process, &apcState);

    hookEntry->NtWriteVirtualMemory_Addr = FindExportedFunction(hookEntry->NtdllBase, "NtWriteVirtualMemory");
    hookEntry->NtAllocateVirtualMemory_Addr = FindExportedFunction(hookEntry->NtdllBase, "NtAllocateVirtualMemory");

    KeUnstackDetachProcess(&apcState);

    // Install hooks ONLY if DetourAddress provided
    if (DetourAddress_NtWrite && hookEntry->NtWriteVirtualMemory_Addr)
    {
        status = InstallUsermodeHook(process, hookEntry->NtWriteVirtualMemory_Addr, DetourAddress_NtWrite,
                                     hookEntry->NtWriteVirtualMemory_Original);
    }

    if (DetourAddress_NtAlloc && hookEntry->NtAllocateVirtualMemory_Addr)
    {
        status = InstallUsermodeHook(process, hookEntry->NtAllocateVirtualMemory_Addr, DetourAddress_NtAlloc,
                                     hookEntry->NtAllocateVirtualMemory_Original);
    }

    hookEntry->IsHooked = TRUE;
    g_UserHookEngine->HookedProcessCount++;

    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Unhook
//

NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    KAPC_STATE apcState;

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

    DbgPrint("!!! UserModeHook: Unhooking process %lu\n", ProcessId);

    KeStackAttachProcess((PRKPROCESS)hookEntry->ProcessObject, &apcState);

    __try
    {
        // Restore NtWriteVirtualMemory
        if (hookEntry->NtWriteVirtualMemory_Addr)
        {
            PVOID baseAddr = hookEntry->NtWriteVirtualMemory_Addr;
            SIZE_T size = USERMODE_HOOK_SIZE;
            ULONG oldProt, newProt = PAGE_EXECUTE_READWRITE;

            // FIX: Use function pointer
            if (NT_SUCCESS(fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &size, newProt, &oldProt)))
            {
                RtlCopyMemory(hookEntry->NtWriteVirtualMemory_Addr, hookEntry->NtWriteVirtualMemory_Original,
                              USERMODE_HOOK_SIZE);
                fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &size, oldProt, &oldProt);
            }
        }

        // Restore NtAllocateVirtualMemory
        if (hookEntry->NtAllocateVirtualMemory_Addr)
        {
            PVOID baseAddr = hookEntry->NtAllocateVirtualMemory_Addr;
            SIZE_T size = USERMODE_HOOK_SIZE;
            ULONG oldProt, newProt = PAGE_EXECUTE_READWRITE;

            // FIX: Use function pointer
            if (NT_SUCCESS(fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &size, newProt, &oldProt)))
            {
                RtlCopyMemory(hookEntry->NtAllocateVirtualMemory_Addr, hookEntry->NtAllocateVirtualMemory_Original,
                              USERMODE_HOOK_SIZE);
                fnZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &size, oldProt, &oldProt);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }

    KeUnstackDetachProcess(&apcState);

    ObDereferenceObject(hookEntry->ProcessObject);
    RtlZeroMemory(hookEntry, sizeof(PROCESS_HOOK_ENTRY));
    g_UserHookEngine->HookedProcessCount--;
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);

    return STATUS_SUCCESS;
}
