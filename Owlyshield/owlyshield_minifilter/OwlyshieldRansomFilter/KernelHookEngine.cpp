/*++

Module Name:

    KernelHookEngine.cpp

Abstract:

    Implementation of kernel-level inline function hooking engine.
    Uses trampoline technique to preserve original function execution.
    
    FIXES APPLIED:
    1. Executable memory allocation for trampolines (NX fix)
    2. Enhanced instruction length detection
    3. Multi-processor synchronization for atomic patching

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
// Multi-processor patch synchronization context
//

typedef struct _PATCH_CONTEXT {
    volatile LONG BarrierCount;
    volatile LONG PatchComplete;
    PVOID TargetAddress;
    PVOID PatchData;
    ULONG PatchSize;
    KIRQL SavedIrql;
} PATCH_CONTEXT, *PPATCH_CONTEXT;

//
// Enhanced x64 instruction length detection
// Still simplified - for production use Zydis or Capstone
//

ULONG SimplifiedGetInstructionLength(PUCHAR Code)
{
    ULONG offset = 0;
    UCHAR byte = Code[offset];
    BOOLEAN hasModRM = FALSE;
    ULONG dispSize = 0;
    
    // Skip legacy prefixes
    while (TRUE) {
        switch (byte) {
            // Legacy prefixes
            case 0xF0: case 0xF2: case 0xF3: // LOCK, REPNE, REP
            case 0x2E: case 0x36: case 0x3E: case 0x26: case 0x64: case 0x65: // Segment
            case 0x66: case 0x67: // Operand/Address size
                offset++;
                byte = Code[offset];
                continue;
            
            // REX prefixes (0x40-0x4F)
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                offset++;
                byte = Code[offset];
                continue;
        }
        break;
    }
    
    // Handle opcode
    if (byte == 0x0F) { // Two-byte opcode
        offset++;
        byte = Code[offset];
        offset++;
        hasModRM = TRUE; // Most two-byte opcodes have ModR/M
    } else {
        // Single-byte opcode
        switch (byte) {
            // Instructions without ModR/M
            case 0x50: case 0x51: case 0x52: case 0x53: // PUSH reg
            case 0x54: case 0x55: case 0x56: case 0x57:
            case 0x58: case 0x59: case 0x5A: case 0x5B: // POP reg
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
            case 0x90: case 0x91: case 0x92: case 0x93: // XCHG/NOP
            case 0x94: case 0x95: case 0x96: case 0x97:
            case 0x98: case 0x99: // CBW/CWD
            case 0x9C: case 0x9D: case 0x9E: case 0x9F: // PUSHF/POPF/SAHF/LAHF
            case 0xC3: // RET near
            case 0xC9: // LEAVE
            case 0xCC: // INT3
            case 0xF4: // HLT
                return offset + 1;
            
            // Immediate operands without ModR/M
            case 0x6A: // PUSH imm8
                return offset + 2;
            
            case 0x68: // PUSH imm32
            case 0xE8: // CALL rel32
            case 0xE9: // JMP rel32
                return offset + 5;
            
            case 0xB8: case 0xB9: case 0xBA: case 0xBB: // MOV reg, imm32/64
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                return offset + 5; // Simplified - could be 9 with REX.W
            
            // Instructions with ModR/M
            case 0x00: case 0x01: case 0x02: case 0x03: // ADD
            case 0x08: case 0x09: case 0x0A: case 0x0B: // OR
            case 0x10: case 0x11: case 0x12: case 0x13: // ADC
            case 0x18: case 0x19: case 0x1A: case 0x1B: // SBB
            case 0x20: case 0x21: case 0x22: case 0x23: // AND
            case 0x28: case 0x29: case 0x2A: case 0x2B: // SUB
            case 0x30: case 0x31: case 0x32: case 0x33: // XOR
            case 0x38: case 0x39: case 0x3A: case 0x3B: // CMP
            case 0x84: case 0x85: case 0x86: case 0x87: // TEST/XCHG
            case 0x88: case 0x89: case 0x8A: case 0x8B: // MOV
            case 0x8D: // LEA
            case 0x8F: // POP r/m
            case 0xC0: case 0xC1: // Shift with imm8
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: // Shift
            case 0xF6: case 0xF7: // TEST/NOT/NEG/MUL/DIV
            case 0xFE: case 0xFF: // INC/DEC/CALL/JMP
                hasModRM = TRUE;
                offset++;
                break;
            
            // Group instructions with immediate
            case 0x80: case 0x81: case 0x82: case 0x83: // ALU with immediate
            case 0xC6: case 0xC7: // MOV with immediate
                hasModRM = TRUE;
                offset++;
                break;
            
            default:
                // Unknown - return safe default
                return offset + 3;
        }
    }
    
    // Process ModR/M and SIB if present
    if (hasModRM) {
        UCHAR modrm = Code[offset];
        offset++;
        
        UCHAR mod = (modrm >> 6) & 3;
        UCHAR rm = modrm & 7;
        
        // Check for SIB byte
        if (mod != 3 && rm == 4) {
            offset++; // SIB byte
        }
        
        // Displacement
        if (mod == 1) {
            dispSize = 1; // disp8
        } else if (mod == 2) {
            dispSize = 4; // disp32
        } else if (mod == 0 && rm == 5) {
            dispSize = 4; // RIP-relative or disp32
        }
        offset += dispSize;
        
        // Handle immediate values for specific opcodes
        UCHAR opcode = Code[0];
        if (opcode == 0x80 || opcode == 0x82 || opcode == 0xC6) {
            offset += 1; // imm8
        } else if (opcode == 0x81 || opcode == 0xC7) {
            offset += 4; // imm32
        } else if (opcode == 0x83) {
            offset += 1; // imm8
        }
    }
    
    return offset;
}

//
// Allocate executable memory for trampoline
//

PVOID HookEngineAllocateExecutableMemory(SIZE_T Size, PMDL* OutMdl, PVOID* OutPhysical)
{
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;
    PVOID physicalAddress = NULL;
    PHYSICAL_ADDRESS highAddress = {0};
    NTSTATUS status;
    
    if (OutMdl == NULL || OutPhysical == NULL) {
        return NULL;
    }
    
    *OutMdl = NULL;
    *OutPhysical = NULL;
    
    highAddress.QuadPart = MAXULONG64;
    
    // Allocate contiguous physical memory
    physicalAddress = MmAllocateContiguousMemory(Size, highAddress);
    if (physicalAddress == NULL) {
        DbgPrint("!!! HookEngine: Failed to allocate physical memory\n");
        return NULL;
    }
    
    // Create MDL
    mdl = IoAllocateMdl(physicalAddress, (ULONG)Size, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        DbgPrint("!!! HookEngine: Failed to allocate MDL\n");
        MmFreeContiguousMemory(physicalAddress);
        return NULL;
    }
    
    // Build MDL for nonpaged pool
    MmBuildMdlForNonPagedPool(mdl);
    
    // Map with caching
    mappedAddress = MmMapLockedPagesSpecifyCache(
        mdl,
        KernelMode,
        MmCached,
        NULL,
        FALSE,
        NormalPagePriority
    );
    
    if (mappedAddress == NULL) {
        DbgPrint("!!! HookEngine: Failed to map memory\n");
        IoFreeMdl(mdl);
        MmFreeContiguousMemory(physicalAddress);
        return NULL;
    }
    
    // Set page protection to RWX
    status = MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("!!! HookEngine: Failed to set RWX protection: 0x%X\n", status);
        MmUnmapLockedPages(mappedAddress, mdl);
        IoFreeMdl(mdl);
        MmFreeContiguousMemory(physicalAddress);
        return NULL;
    }
    
    *OutMdl = mdl;
    *OutPhysical = physicalAddress;
    
    DbgPrint("!!! HookEngine: Allocated executable memory at %p\n", mappedAddress);
    return mappedAddress;
}

//
// Free executable memory
//

VOID HookEngineFreeExecutableMemory(PVOID MappedAddress, PMDL Mdl, PVOID PhysicalAddress)
{
    if (MappedAddress != NULL && Mdl != NULL) {
        MmUnmapLockedPages(MappedAddress, Mdl);
    }
    
    if (Mdl != NULL) {
        IoFreeMdl(Mdl);
    }
    
    if (PhysicalAddress != NULL) {
        MmFreeContiguousMemory(PhysicalAddress);
    }
}

//
// Multi-processor synchronization callback
//

ULONG_PTR NTAPI HookEngineSyncCallback(ULONG_PTR Context)
{
    PPATCH_CONTEXT patchCtx = (PPATCH_CONTEXT)Context;
    
    // Increment barrier counter
    InterlockedIncrement(&patchCtx->BarrierCount);
    
    // Wait for patch to complete
    while (InterlockedCompareExchange(&patchCtx->PatchComplete, 0, 0) == 0) {
        _mm_pause();
        KeYieldProcessor();
    }
    
    // Memory barrier
    _ReadWriteBarrier();
    
    return 0;
}

//
// Atomic patch across all processors
//

VOID HookEngineAtomicPatch(PVOID Target, PVOID PatchData, ULONG Size)
{
    PATCH_CONTEXT patchCtx = {0};
    ULONG processorCount;
    KIRQL oldIrql;
    UINT64 cr0;
    
    // Get processor count
    processorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    
    patchCtx.TargetAddress = Target;
    patchCtx.PatchData = PatchData;
    patchCtx.PatchSize = Size;
    patchCtx.BarrierCount = 0;
    patchCtx.PatchComplete = 0;
    
    // Raise IRQL and disable interrupts on current CPU
    oldIrql = KeRaiseIrqlToDpcLevel();
    _disable();
    
    // Execute callback on all processors (including this one)
    KeIpiGenericCall(HookEngineSyncCallback, (ULONG_PTR)&patchCtx);
    
    // Wait for all CPUs to reach barrier
    while ((ULONG)InterlockedCompareExchange(&patchCtx.BarrierCount, 0, 0) < processorCount) {
        _mm_pause();
    }
    
    // Disable write protection
    cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);
    
    // Perform the actual patch
    RtlCopyMemory(Target, PatchData, Size);
    
    // Re-enable write protection
    cr0 = __readcr0();
    __writecr0(cr0 | 0x10000ULL);
    
    // Memory barrier
    _ReadWriteBarrier();
    
    // Signal completion
    InterlockedExchange(&patchCtx.PatchComplete, 1);
    
    // Re-enable interrupts and lower IRQL
    _enable();
    KeLowerIrql(oldIrql);
    
    // Invalidate instruction caches on all CPUs
    KeInvalidateAllCaches();
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
// NOTE: Only used for non-atomic operations
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
    ULONG maxAttempts = 20; // Safety limit
    ULONG attempts = 0;
    
    while (totalBytes < RequiredBytes && attempts < maxAttempts) {
        ULONG instrLen = SimplifiedGetInstructionLength(code + totalBytes);
        if (instrLen == 0 || instrLen > 15) {
            DbgPrint("!!! HookEngine: Invalid instruction length %lu at offset %lu\n", 
                     instrLen, totalBytes);
            return 0;
        }
        totalBytes += instrLen;
        attempts++;
    }
    
    if (attempts >= maxAttempts) {
        DbgPrint("!!! HookEngine: Too many instructions, possible infinite loop\n");
        return 0;
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
    PHOOK_ENTRY hookEntry = NULL;
    PVOID trampoline = NULL;
    PMDL trampolineMdl = NULL;
    PVOID trampolinePhysical = NULL;
    ULONG bytesToCopy;
    NTSTATUS status;
    
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
        DbgPrint("!!! HookEngine: Cannot determine instruction boundaries (bytes=%lu)\n", bytesToCopy);
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_UNSUCCESSFUL;
    }
    
    DbgPrint("!!! HookEngine: Will copy %lu bytes from target\n", bytesToCopy);
    
    // Allocate executable trampoline memory
    trampoline = HookEngineAllocateExecutableMemory(
        TRAMPOLINE_SIZE,
        &trampolineMdl,
        &trampolinePhysical
    );
    
    if (trampoline == NULL) {
        DbgPrint("!!! HookEngine: Failed to allocate executable trampoline\n");
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlZeroMemory(trampoline, TRAMPOLINE_SIZE);
    
    // Save original bytes
    __try {
        RtlCopyMemory(hookEntry->OriginalBytes, TargetFunction, bytesToCopy);
        hookEntry->OriginalBytesLength = bytesToCopy;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("!!! HookEngine: Exception reading target function\n");
        HookEngineFreeExecutableMemory(trampoline, trampolineMdl, trampolinePhysical);
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_ACCESS_VIOLATION;
    }
    
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
    
    // Log what we're doing
    DbgPrint("!!! HookEngine: Installing hook jump...\n");
    DbgPrint("!!!   Original bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
             hookEntry->OriginalBytes[0], hookEntry->OriginalBytes[1],
             hookEntry->OriginalBytes[2], hookEntry->OriginalBytes[3],
             hookEntry->OriginalBytes[4], hookEntry->OriginalBytes[5],
             hookEntry->OriginalBytes[6], hookEntry->OriginalBytes[7]);
    
    // Install the hook atomically across all CPUs
    HookEngineAtomicPatch(TargetFunction, hookJump, HOOK_JUMP_SIZE);
    
    // NOP out remaining bytes if any
    if (bytesToCopy > HOOK_JUMP_SIZE) {
        UCHAR nops[32];
        RtlFillMemory(nops, bytesToCopy - HOOK_JUMP_SIZE, 0x90);
        HookEngineAtomicPatch(
            (PUCHAR)TargetFunction + HOOK_JUMP_SIZE,
            nops,
            bytesToCopy - HOOK_JUMP_SIZE
        );
    }
    
    // Fill in hook entry
    hookEntry->TargetFunction = TargetFunction;
    hookEntry->HookFunction = HookFunction;
    hookEntry->TrampolineFunction = trampoline;
    hookEntry->TrampolineMdl = trampolineMdl;
    hookEntry->TrampolinePhysical = trampolinePhysical;
    hookEntry->IsActive = TRUE;
    hookEntry->IsAllocated = TRUE;
    
    if (FunctionName != NULL) {
        RtlStringCbCopyA(hookEntry->FunctionName, sizeof(hookEntry->FunctionName), FunctionName);
    } else {
        RtlStringCbCopyA(hookEntry->FunctionName, sizeof(hookEntry->FunctionName), "Unknown");
    }
    
    *TrampolineFunction = trampoline;
    g_HookEngine->ActiveHookCount++;
    
    DbgPrint("!!! HookEngine: Successfully installed hook for %s\n", hookEntry->FunctionName);
    DbgPrint("!!!   Target: %p -> Hook: %p -> Trampoline: %p\n",
             TargetFunction, HookFunction, trampoline);
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    return STATUS_SUCCESS;
}

//
// Remove a hook
//

NTSTATUS HookEngineRemoveHook(PVOID TargetFunction)
{
    PHOOK_ENTRY hookEntry;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    hookEntry = HookEngineFindHook(TargetFunction);
    if (hookEntry == NULL) {
        ExReleaseFastMutex(&g_HookEngine->EngineMutex);
        return STATUS_NOT_FOUND;
    }
    
    // Restore original bytes atomically
    HookEngineAtomicPatch(
        hookEntry->TargetFunction,
        hookEntry->OriginalBytes,
        hookEntry->OriginalBytesLength
    );
    
    // Free trampoline with proper cleanup
    if (hookEntry->TrampolineFunction != NULL) {
        HookEngineFreeExecutableMemory(
            hookEntry->TrampolineFunction,
            hookEntry->TrampolineMdl,
            hookEntry->TrampolinePhysical
        );
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
    PVOID targetFunctions[MAX_HOOKS];
    ULONG hookCount = 0;
    
    if (g_HookEngine == NULL || !g_HookEngine->IsInitialized)
        return STATUS_DEVICE_NOT_READY;
    
    DbgPrint("!!! HookEngine: Removing all hooks...\n");
    
    // First pass: collect all target functions while holding mutex
    ExAcquireFastMutex(&g_HookEngine->EngineMutex);
    
    for (ULONG i = 0; i < MAX_HOOKS; i++) {
        if (g_HookEngine->Hooks[i].IsAllocated) {
            targetFunctions[hookCount++] = g_HookEngine->Hooks[i].TargetFunction;
        }
    }
    
    ExReleaseFastMutex(&g_HookEngine->EngineMutex);
    
    // Second pass: remove each hook (this will re-acquire mutex internally)
    for (ULONG i = 0; i < hookCount; i++) {
        HookEngineRemoveHook(targetFunctions[i]);
    }
    
    DbgPrint("!!! HookEngine: All hooks removed (%lu total)\n", hookCount);
    return STATUS_SUCCESS;
}

//
// Enable a hook (if previously disabled)
//

NTSTATUS HookEngineEnableHook(PVOID TargetFunction)
{
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
    
    HookEngineAtomicPatch(hookEntry->TargetFunction, hookJump, HOOK_JUMP_SIZE);
    
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
    
    // Restore original bytes atomically
    HookEngineAtomicPatch(
        hookEntry->TargetFunction,
        hookEntry->OriginalBytes,
        hookEntry->OriginalBytesLength
    );
    
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
