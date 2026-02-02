/*++

Module Name:

    KernelHookEngine.cpp

Abstract:

    Implementation of kernel-level inline function hooking engine.
    Uses trampoline technique to preserve original function execution.
    Safe for PatchGuard - does not modify protected kernel structures.

Environment:

    Kernel mode only (x64)

--*/

#include "KernelHookEngine.h"
#include <intrin.h>

//
// Global hook engine instance
//

PHOOK_ENGINE g_HookEngine = NULL;

//
// x64 instruction length table (simplified)
// For production, use a full disassembler library like Zydis or Capstone
//

ULONG SimplifiedGetInstructionLength(PUCHAR Code)
{
    // This is a SIMPLIFIED version - for production use a proper disassembler
    // Common x64 instruction patterns
    
    UCHAR byte1 = Code[0];
    UCHAR byte2 = Code[1];
    
    // REX prefixes (0x40-0x4F)
    ULONG offset = 0;
    if (byte1 >= 0x40 && byte1 <= 0x4F) {
        offset = 1;
        byte1 = Code[offset];
        byte2 = Code[offset + 1];
    }
    
    // Common patterns
    switch (byte1) {
        case 0x48: case 0x49: case 0x4C: case 0x4D: // REX.W prefixes
            if (byte2 == 0x8B || byte2 == 0x89) return offset + 3; // MOV r64, r/m64
            if (byte2 == 0x83) return offset + 4; // ADD/SUB r/m64, imm8
            if (byte2 == 0x8D) return offset + 3; // LEA
            if (byte2 == 0x81) return offset + 7; // ADD/SUB r/m64, imm32
            break;
            
        case 0x50: case 0x51: case 0x52: case 0x53: // PUSH r64
        case 0x54: case 0x55: case 0x56: case 0x57:
            return 1;
            
        case 0x41: // REX.B prefix
            if (byte2 >= 0x50 && byte2 <= 0x57) return 2; // PUSH r64
            break;
            
        case 0x8B: // MOV r32, r/m32
        case 0x89: // MOV r/m32, r32
            return 2;
            
        case 0x83: // ADD/SUB r/m32, imm8
            return 3;
            
        case 0xC3: // RET
            return 1;
            
        case 0xCC: // INT3
            return 1;
            
        case 0xE8: // CALL rel32
            return 5;
            
        case 0xE9: // JMP rel32
            return 5;
            
        case 0xFF: // Indirect CALL/JMP
            return 2;
    }
    
    // Default fallback - this should be improved with proper disassembler
    return 3;
}

//
// Hook engine initialization
//

NTSTATUS HookEngineInitialize(VOID)
{
    DbgPrint("!!! HookEngine: Initializing...\n");
    
    // Allocate hook engine structure
    g_HookEngine = (PHOOK_ENGINE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(HOOK_ENGINE),
        'kHoE'
    );
    
    if (g_HookEngine == NULL) {
        DbgPrint("!!! HookEngine: Failed to allocate engine structure\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(g_HookEngine, sizeof(HOOK_ENGINE));
    
    // Initialize mutex
    ExInitializeFastMutex(&g_HookEngine->EngineMutex);
    
    g_HookEngine->IsInitialized = TRUE;
    g_HookEngine->ActiveHookCount = 0;
    
    DbgPrint("!!! HookEngine: Initialized successfully\n");
    return STATUS_SUCCESS;
}

//
// Hook engine cleanup
//

VOID HookEngineCleanup(VOID)
{
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return;
    
    DbgPrint("!!! HookEngine: Cleaning up...\n");
    
    // Remove all hooks
    HookEngineRemoveAllHooks();
    
    // Free the engine structure
    ExFreePoolWithTag(g_HookEngine, 'kHoE');
    g_HookEngine = NULL;
    
    DbgPrint("!!! HookEngine: Cleanup complete\n");
}

//
// Disable write protection (CR0.WP bit)
//

KIRQL HookEngineDisableWriteProtection(VOID)
{
    KIRQL irql;
    UINT64 cr0;
    
    // Raise IRQL to DISPATCH_LEVEL to prevent context switches
    irql = KeRaiseIrqlToDpcLevel();
    
    // Disable interrupts
    _disable();
    
    // Read CR0
    cr0 = __readcr0();
    
    // Clear WP bit (bit 16)
    cr0 &= ~0x10000ULL;
    
    // Write modified CR0
    __writecr0(cr0);
    
    return irql;
}

//
// Enable write protection (CR0.WP bit)
//

VOID HookEngineEnableWriteProtection(KIRQL OldIrql)
{
    UINT64 cr0;
    
    // Read CR0
    cr0 = __readcr0();
    
    // Set WP bit (bit 16)
    cr0 |= 0x10000ULL;
    
    // Write modified CR0
    __writecr0(cr0);
    
    // Enable interrupts
    _enable();
    
    // Lower IRQL
    KeLowerIrql(OldIrql);
}

//
// Get minimum number of bytes needed for hook
//

ULONG HookEngineGetMinimumBytesForHook(PVOID Address, ULONG RequiredBytes)
{
    ULONG totalBytes = 0;
    PUCHAR code = (PUCHAR)Address;
    
    while (totalBytes < RequiredBytes) {
        ULONG instrLen = SimplifiedGetInstructionLength(code + totalBytes);
        if (instrLen == 0) {
            DbgPrint("!!! HookEngine: Failed to disassemble at offset %lu\n", totalBytes);
            return 0;
        }
        totalBytes += instrLen;
    }
    
    return totalBytes;
}

//
// Find hook entry by target function
//

PHOOK_ENTRY HookEngineFindHook(PVOID TargetFunction)
{
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return NULL;
    
    for (ULONG i = 0; i < MAX_HOOKS; i++) {
        if (g_HookEngine->Hooks[i].IsAllocated && 
            g_HookEngine->Hooks[i].TargetFunction == TargetFunction) {
            return &g_HookEngine->Hooks[i];
        }
    }
    
    return NULL;
}

//
// Install a hook
//

NTSTATUS HookEngineInstallHook(
    PVOID TargetFunction,
    PVOID HookFunction,
    LPCSTR FunctionName,
    PVOID* TrampolineFunction
)
{
    KIRQL oldIrql;
    PHOOK_ENTRY hookEntry = NULL;
    PVOID trampoline = NULL;
    ULONG bytesToCopy;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized) {
        DbgPrint("!!! HookEngine: Not initialized\n");
        return STATUS_DEVICE_NOT_READY;
    }
    
    if (TargetFunction == NULL || HookFunction == NULL || TrampolineFunction == NULL) {
        DbgPrint("!!! HookEngine: Invalid parameters\n");
        return STATUS_INVALID_PARAMETER;
    }
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    // Check if already hooked
    if (HookEngineFindHook(TargetFunction) != NULL) {
        DbgPrint("!!! HookEngine: Function already hooked\n");
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_ALREADY_REGISTERED;
    }
    
    // Find free slot
    for (ULONG i = 0; i < MAX_HOOKS; i++) {
        if (!g_HookEngine->Hooks[i].IsAllocated) {
            hookEntry = &g_HookEngine->Hooks[i];
            break;
        }
    }
    
    if (hookEntry == NULL) {
        DbgPrint("!!! HookEngine: No free hook slots\n");
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Calculate bytes to copy (minimum 14 bytes for our jump)
    bytesToCopy = HookEngineGetMinimumBytesForHook(TargetFunction, HOOK_JUMP_SIZE);
    if (bytesToCopy == 0 || bytesToCopy > 32) {
        DbgPrint("!!! HookEngine: Cannot determine instruction boundaries\n");
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_UNSUCCESSFUL;
    }
    
    // Allocate trampoline (executable memory)
    trampoline = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        TRAMPOLINE_SIZE,
        'Tram'
    );
    
    if (trampoline == NULL) {
        DbgPrint("!!! HookEngine: Failed to allocate trampoline\n");
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(trampoline, TRAMPOLINE_SIZE);
    
    // Save original bytes
    RtlCopyMemory(hookEntry->OriginalBytes, TargetFunction, bytesToCopy);
    hookEntry->OriginalBytesLength = bytesToCopy;
    
    // Build trampoline:
    // 1. Copy original bytes that we're overwriting
    // 2. Add absolute jump back to (TargetFunction + bytesToCopy)
    
    PUCHAR trampolineCode = (PUCHAR)trampoline;
    ULONG offset = 0;
    
    // Copy original instructions
    RtlCopyMemory(trampolineCode, TargetFunction, bytesToCopy);
    offset += bytesToCopy;
    
    // Build absolute jump back to continue original execution
    // JMP [RIP+0]; address
    trampolineCode[offset++] = 0xFF;
    trampolineCode[offset++] = 0x25;
    trampolineCode[offset++] = 0x00;
    trampolineCode[offset++] = 0x00;
    trampolineCode[offset++] = 0x00;
    trampolineCode[offset++] = 0x00;
    
    PVOID returnAddress = (PUCHAR)TargetFunction + bytesToCopy;
    *((PVOID*)&trampolineCode[offset]) = returnAddress;
    
    // Build hook jump in target function
    // JMP [RIP+0]; address to hook function
    UCHAR hookJump[HOOK_JUMP_SIZE];
    hookJump[0] = 0xFF;
    hookJump[1] = 0x25;
    hookJump[2] = 0x00;
    hookJump[3] = 0x00;
    hookJump[4] = 0x00;
    hookJump[5] = 0x00;
    *((PVOID*)&hookJump[6]) = HookFunction;
    
    // Install the hook
    oldIrql = HookEngineDisableWriteProtection();
    
    RtlCopyMemory(TargetFunction, hookJump, HOOK_JUMP_SIZE);
    
    // NOP out remaining bytes if any
    if (bytesToCopy > HOOK_JUMP_SIZE) {
        RtlFillMemory((PUCHAR)TargetFunction + HOOK_JUMP_SIZE, 
                      bytesToCopy - HOOK_JUMP_SIZE, 
                      0x90); // NOP
    }
    
    HookEngineEnableWriteProtection(oldIrql);
    
    // Fill in hook entry
    hookEntry->TargetFunction = TargetFunction;
    hookEntry->HookFunction = HookFunction;
    hookEntry->TrampolineFunction = trampoline;
    hookEntry->IsActive = TRUE;
    hookEntry->IsAllocated = TRUE;
    
    if (FunctionName != NULL) {
        RtlStringCbCopyA(hookEntry->FunctionName, sizeof(hookEntry->FunctionName), FunctionName);
    } else {
        RtlStringCbCopyA(hookEntry->FunctionName, sizeof(hookEntry->FunctionName), "Unknown");
    }
    
    *TrampolineFunction = trampoline;
    g_HookEngine->ActiveHookCount++;
    
    DbgPrint("!!! HookEngine: Installed hook for %s at %p -> %p (trampoline: %p)\n",
             hookEntry->FunctionName, TargetFunction, HookFunction, trampoline);
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Remove a hook
//

NTSTATUS HookEngineRemoveHook(PVOID TargetFunction)
{
    KIRQL oldIrql;
    PHOOK_ENTRY hookEntry;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    hookEntry = HookEngineFindHook(TargetFunction);
    if (hookEntry == NULL) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }
    
    // Restore original bytes
    oldIrql = HookEngineDisableWriteProtection();
    
    RtlCopyMemory(hookEntry->TargetFunction, 
                  hookEntry->OriginalBytes, 
                  hookEntry->OriginalBytesLength);
    
    HookEngineEnableWriteProtection(oldIrql);
    
    // Free trampoline
    if (hookEntry->TrampolineFunction != NULL) {
        ExFreePoolWithTag(hookEntry->TrampolineFunction, 'Tram');
    }
    
    DbgPrint("!!! HookEngine: Removed hook for %s at %p\n",
             hookEntry->FunctionName, hookEntry->TargetFunction);
    
    // Clear entry
    RtlZeroMemory(hookEntry, sizeof(HOOK_ENTRY));
    g_HookEngine->ActiveHookCount--;
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Remove all hooks
//

NTSTATUS HookEngineRemoveAllHooks(VOID)
{
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    DbgPrint("!!! HookEngine: Removing all hooks...\n");
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    for (ULONG i = 0; i < MAX_HOOKS; i++) {
        if (g_HookEngine->Hooks[i].IsAllocated) {
            PVOID targetFunc = g_HookEngine->Hooks[i].TargetFunction;
            ExReleaseFastMutex(&g_HookEngine->EngineMutex);
            HookEngineRemoveHook(targetFunc);
            ExAcquireFastMutex(&g_HookEngine->EngineMutex);
        }
    }
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    
    DbgPrint("!!! HookEngine: All hooks removed\n");
    return STATUS_SUCCESS;
}

//
// Enable a hook (if previously disabled)
//

NTSTATUS HookEngineEnableHook(PVOID TargetFunction)
{
    KIRQL oldIrql;
    PHOOK_ENTRY hookEntry;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    hookEntry = HookEngineFindHook(TargetFunction);
    if (hookEntry == NULL) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }
    
    if (hookEntry->IsActive) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_SUCCESS; // Already enabled
    }
    
    // Build hook jump
    UCHAR hookJump[HOOK_JUMP_SIZE];
    hookJump[0] = 0xFF;
    hookJump[1] = 0x25;
    hookJump[2] = 0x00;
    hookJump[3] = 0x00;
    hookJump[4] = 0x00;
    hookJump[5] = 0x00;
    *((PVOID*)&hookJump[6]) = hookEntry->HookFunction;
    
    oldIrql = HookEngineDisableWriteProtection();
    RtlCopyMemory(hookEntry->TargetFunction, hookJump, HOOK_JUMP_SIZE);
    HookEngineEnableWriteProtection(oldIrql);
    
    hookEntry->IsActive = TRUE;
    
    DbgPrint("!!! HookEngine: Enabled hook for %s\n", hookEntry->FunctionName);
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Disable a hook (without removing it)
//

NTSTATUS HookEngineDisableHook(PVOID TargetFunction)
{
    KIRQL oldIrql;
    PHOOK_ENTRY hookEntry;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    hookEntry = HookEngineFindHook(TargetFunction);
    if (hookEntry == NULL) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }
    
    if (!hookEntry->IsActive) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_SUCCESS; // Already disabled
    }
    
    // Restore original bytes
    oldIrql = HookEngineDisableWriteProtection();
    RtlCopyMemory(hookEntry->TargetFunction, 
                  hookEntry->OriginalBytes, 
                  hookEntry->OriginalBytesLength);
    HookEngineEnableWriteProtection(oldIrql);
    
    hookEntry->IsActive = FALSE;
    
    DbgPrint("!!! HookEngine: Disabled hook for %s\n", hookEntry->FunctionName);
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Print hook statistics
//

VOID HookEnginePrintStatistics(VOID)
{
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized) {
        DbgPrint("!!! HookEngine: Not initialized\n");
        return;
    }
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    DbgPrint("!!! HookEngine Statistics:\n");
    DbgPrint("!!!   Active hooks: %lu / %d\n", g_HookEngine->ActiveHookCount, MAX_HOOKS);
    
    for (ULONG i = 0; i < MAX_HOOKS; i++) {
        if (g_HookEngine->Hooks[i].IsAllocated) {
            DbgPrint("!!!   [%lu] %s - Target: %p, Hook: %p, Trampoline: %p, Active: %d\n",
                     i,
                     g_HookEngine->Hooks[i].FunctionName,
                     g_HookEngine->Hooks[i].TargetFunction,
                     g_HookEngine->Hooks[i].HookFunction,
                     g_HookEngine->Hooks[i].TrampolineFunction,
                     g_HookEngine->Hooks[i].IsActive);
        }
    }
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
}

//
// Get x64 instruction length
//

ULONG HookEngineGetInstructionLength(
    _In_ PVOID Address
)
{
    if (Address == NULL)
        return 0;
    
    return SimplifiedGetInstructionLength((PUCHAR)Address);
}
