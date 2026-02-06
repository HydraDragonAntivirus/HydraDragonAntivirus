/*++

Module Name:

    UserModeHookEngine.cpp

Abstract:

    Implementation of user-mode ntdll.dll hooking engine.
    
    This hooks ntdll.dll syscall stubs in user-mode instead of
    kernel functions, bypassing PatchGuard entirely.
    
    HOW IT WORKS:
    1. When a new process is created, find its ntdll.dll base address
    2. Parse ntdll.dll PE exports to find NtWriteVirtualMemory, etc.
    3. Attach to process address space with KeStackAttachProcess
    4. Patch the ntdll function stubs to jump to our kernel hooks
    5. Our kernel hooks can inspect/block/modify before syscall executes

Environment:

    Kernel mode

--*/

#include "UserModeHookEngine.h"
#include <ntimage.h>

//
// Global hook engine instance
//

PUSERMODE_HOOK_ENGINE g_UserHookEngine = NULL;

//
// Forward declarations for hook handlers
//

NTSTATUS NTAPI UserHook_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS NTAPI UserHook_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

//
// Initialize the user-mode hooking engine
//

NTSTATUS UserModeHookEngineInitialize(VOID)
{
    DbgPrint("!!! UserModeHook: Initializing user-mode hooking engine...\n");
    
    g_UserHookEngine = (PUSERMODE_HOOK_ENGINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(USERMODE_HOOK_ENGINE),
        'UMHk'
    );
    
    if (g_UserHookEngine == NULL) {
        DbgPrint("!!! UserModeHook: Failed to allocate engine structure\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(g_UserHookEngine, sizeof(USERMODE_HOOK_ENGINE));
    ExInitializeFastMutex(&g_UserHookEngine->EngineMutex);
    g_UserHookEngine->IsInitialized = TRUE;
    
    DbgPrint("!!! UserModeHook: Engine initialized successfully\n");
    return STATUS_SUCCESS;
}

//
// Cleanup the user-mode hooking engine
//

VOID UserModeHookEngineCleanup(VOID)
{
    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return;
    
    DbgPrint("!!! UserModeHook: Cleaning up...\n");
    
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    
    // Unhook all processes
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++) {
        if (g_UserHookEngine->Processes[i].IsHooked) {
            UserModeUnhookProcess(g_UserHookEngine->Processes[i].ProcessId);
        }
    }
    
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    
    ExFreePoolWithTag(g_UserHookEngine, 'UMHk');
    g_UserHookEngine = NULL;
    
    DbgPrint("!!! UserModeHook: Cleanup complete\n");
}

//
// Find module base address in target process
//

PVOID FindModuleBaseAddress(
    _In_ PEPROCESS Process,
    _In_ PCWSTR ModuleName,
    _Out_opt_ PSIZE_T ModuleSize
)
{
    PVOID moduleBase = NULL;
    KAPC_STATE apcState;
    
    if (ModuleSize != NULL) {
        *ModuleSize = 0;
    }
    
    // Attach to target process
    KeStackAttachProcess(Process, &apcState);
    
    __try {
        // Get PEB address
        PPEB peb = PsGetProcessPeb(Process);
        if (peb == NULL) {
            DbgPrint("!!! UserModeHook: Cannot get PEB\n");
            __leave;
        }
        
        // Probe PEB for read access
        ProbeForRead(peb, sizeof(PEB), 1);
        
        // Get LDR data
        PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
        if (ldr == NULL) {
            DbgPrint("!!! UserModeHook: PEB->Ldr is NULL\n");
            __leave;
        }
        
        ProbeForRead(ldr, sizeof(PEB_LDR_DATA), 1);
        
        // Walk the loaded module list
        PLIST_ENTRY listHead = &ldr->InLoadOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;
        
        while (listEntry != listHead) {
            PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(
                listEntry,
                LDR_DATA_TABLE_ENTRY,
                InLoadOrderLinks
            );
            
            ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);
            
            if (ldrEntry->BaseDllName.Buffer != NULL &&
                ldrEntry->BaseDllName.Length > 0) {
                
                ProbeForRead(
                    ldrEntry->BaseDllName.Buffer,
                    ldrEntry->BaseDllName.Length,
                    1
                );
                
                // Compare module name (case-insensitive)
                if (_wcsicmp(ldrEntry->BaseDllName.Buffer, ModuleName) == 0) {
                    moduleBase = ldrEntry->DllBase;
                    if (ModuleSize != NULL) {
                        *ModuleSize = ldrEntry->SizeOfImage;
                    }
                    DbgPrint("!!! UserModeHook: Found %wS at %p (size: 0x%zX)\n",
                             ModuleName, moduleBase, ldrEntry->SizeOfImage);
                    break;
                }
            }
            
            listEntry = listEntry->Flink;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("!!! UserModeHook: Exception while finding module: 0x%X\n",
                 GetExceptionCode());
        moduleBase = NULL;
    }
    
    KeUnstackDetachProcess(&apcState);
    return moduleBase;
}

//
// Find exported function in PE module
//

PVOID FindExportedFunction(
    _In_ PVOID ModuleBase,
    _In_ PCSTR FunctionName
)
{
    PVOID functionAddress = NULL;
    
    __try {
        // Probe DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dosHeader, sizeof(IMAGE_DOS_HEADER), 1);
        
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            DbgPrint("!!! UserModeHook: Invalid DOS signature\n");
            return NULL;
        }
        
        // Get NT headers
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
            (PUCHAR)ModuleBase + dosHeader->e_lfanew
        );
        ProbeForRead(ntHeaders, sizeof(IMAGE_NT_HEADERS), 1);
        
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            DbgPrint("!!! UserModeHook: Invalid NT signature\n");
            return NULL;
        }
        
        // Get export directory
        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(
            (PUCHAR)ModuleBase +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
        );
        ProbeForRead(exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), 1);
        
        PULONG addressOfFunctions = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfFunctions);
        PULONG addressOfNames = (PULONG)((PUCHAR)ModuleBase + exportDir->AddressOfNames);
        PUSHORT addressOfNameOrdinals = (PUSHORT)((PUCHAR)ModuleBase + exportDir->AddressOfNameOrdinals);
        
        // Search for function name
        for (ULONG i = 0; i < exportDir->NumberOfNames; i++) {
            PCSTR currentName = (PCSTR)((PUCHAR)ModuleBase + addressOfNames[i]);
            ProbeForRead((PVOID)currentName, strlen(FunctionName) + 1, 1);
            
            if (strcmp(currentName, FunctionName) == 0) {
                USHORT ordinal = addressOfNameOrdinals[i];
                ULONG rva = addressOfFunctions[ordinal];
                functionAddress = (PVOID)((PUCHAR)ModuleBase + rva);
                
                DbgPrint("!!! UserModeHook: Found %s at %p (RVA: 0x%X)\n",
                         FunctionName, functionAddress, rva);
                break;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("!!! UserModeHook: Exception while parsing exports: 0x%X\n",
                 GetExceptionCode());
        functionAddress = NULL;
    }
    
    return functionAddress;
}

//
// Install a hook in user-mode memory
//

NTSTATUS InstallUsermodeHook(
    _In_ PEPROCESS Process,
    _In_ PVOID TargetAddress,
    _In_ PVOID HookRoutine,
    _Out_writes_bytes_(USERMODE_HOOK_SIZE) PUCHAR OriginalBytes
)
{
    KAPC_STATE apcState;
    NTSTATUS status = STATUS_SUCCESS;
    
    DbgPrint("!!! UserModeHook: Installing hook at %p -> %p\n",
             TargetAddress, HookRoutine);
    
    // Attach to target process
    KeStackAttachProcess(Process, &apcState);
    
    __try {
        // Save original bytes
        ProbeForRead(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(OriginalBytes, TargetAddress, USERMODE_HOOK_SIZE);
        
        // Build hook shellcode: JMP [RIP+0]; [8-byte address]
        UCHAR hookShellcode[USERMODE_HOOK_SIZE];
        hookShellcode[0] = 0xFF;  // JMP
        hookShellcode[1] = 0x25;  // [RIP+disp32]
        *(PULONG)&hookShellcode[2] = 0x00000000;  // disp32 = 0
        *(PVOID*)&hookShellcode[6] = HookRoutine;  // Target address
        
        // Write hook
        ProbeForWrite(TargetAddress, USERMODE_HOOK_SIZE, 1);
        RtlCopyMemory(TargetAddress, hookShellcode, USERMODE_HOOK_SIZE);
        
        DbgPrint("!!! UserModeHook: Hook installed successfully\n");
        DbgPrint("!!!   Original bytes: %02X %02X %02X %02X %02X %02X\n",
                 OriginalBytes[0], OriginalBytes[1], OriginalBytes[2],
                 OriginalBytes[3], OriginalBytes[4], OriginalBytes[5]);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("!!! UserModeHook: Exception during hook installation: 0x%X\n",
                 GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
    }
    
    KeUnstackDetachProcess(&apcState);
    return status;
}

//
// Hook a specific process
//

NTSTATUS UserModeHookProcess(_In_ ULONG ProcessId)
{
    NTSTATUS status;
    PEPROCESS process = NULL;
    PPROCESS_HOOK_ENTRY hookEntry = NULL;
    
    if (g_UserHookEngine == NULL || !g_UserHookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    // Get process object
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! UserModeHook: Cannot find process %lu: 0x%X\n", ProcessId, status);
        return status;
    }
    
    ExAcquireFastMutex(&g_UserHookEngine->EngineMutex);
    
    // Find free slot
    for (ULONG i = 0; i < MAX_HOOKED_PROCESSES; i++) {
        if (!g_UserHookEngine->Processes[i].IsHooked) {
            hookEntry = &g_UserHookEngine->Processes[i];
            break;
        }
    }
    
    if (hookEntry == NULL) {
        DbgPrint("!!! UserModeHook: No free slots for process %lu\n", ProcessId);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    hookEntry->ProcessId = ProcessId;
    hookEntry->ProcessObject = process;
    
    // Find ntdll.dll in target process
    hookEntry->NtdllBase = FindModuleBaseAddress(
        process,
        L"ntdll.dll",
        &hookEntry->NtdllSize
    );
    
    if (hookEntry->NtdllBase == NULL) {
        DbgPrint("!!! UserModeHook: Cannot find ntdll.dll in process %lu\n", ProcessId);
        ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
        ObDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }
    
    // Attach to process to parse exports
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);
    
    // Find function addresses
    hookEntry->NtWriteVirtualMemory_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtWriteVirtualMemory"
    );
    
    hookEntry->NtAllocateVirtualMemory_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtAllocateVirtualMemory"
    );
    
    hookEntry->NtProtectVirtualMemory_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtProtectVirtualMemory"
    );
    
    hookEntry->NtCreateThreadEx_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtCreateThreadEx"
    );
    
    hookEntry->NtQueueApcThread_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtQueueApcThread"
    );
    
    hookEntry->NtSetContextThread_Addr = FindExportedFunction(
        hookEntry->NtdllBase,
        "NtSetContextThread"
    );
    
    KeUnstackDetachProcess(&apcState);
    
    // Install hooks (example for NtWriteVirtualMemory)
    if (hookEntry->NtWriteVirtualMemory_Addr != NULL) {
        status = InstallUsermodeHook(
            process,
            hookEntry->NtWriteVirtualMemory_Addr,
            (PVOID)UserHook_NtWriteVirtualMemory,
            hookEntry->NtWriteVirtualMemory_Original
        );
        
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! UserModeHook: Failed to hook NtWriteVirtualMemory\n");
        }
    }
    
    // TODO: Install other hooks similarly
    
    hookEntry->IsHooked = TRUE;
    g_UserHookEngine->HookedProcessCount++;
    
    DbgPrint("!!! UserModeHook: Successfully hooked process %lu\n", ProcessId);
    
    ExReleaseFastMutex(&g_UserHookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Unhook a process
//

NTSTATUS UserModeUnhookProcess(_In_ ULONG ProcessId)
{
    // TODO: Implement unhooking
    return STATUS_SUCCESS;
}

//
// Example hook handler
//

NTSTATUS NTAPI UserHook_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    DbgPrint("!!! UserModeHook: NtWriteVirtualMemory called from PID %lu\n",
             (ULONG)(ULONG_PTR)PsGetCurrentProcessId());
    
    // TODO: Inspect parameters, log to usermode, potentially block
    
    // Call original function (need to restore original bytes temporarily)
    // For now, just return success
    return STATUS_SUCCESS;
}
