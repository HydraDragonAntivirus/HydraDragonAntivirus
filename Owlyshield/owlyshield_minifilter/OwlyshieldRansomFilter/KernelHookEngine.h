#pragma once

/*++

Module Name:

    KernelHookEngine.h

Abstract:

    Kernel-level inline function hooking engine for x64 Windows.
    Provides trampoline-based hooking without touching protected structures (SSDT/IDT).
    PatchGuard compliant - only modifies regular kernel function prologues.

Environment:

    Kernel mode only (x64)

--*/

#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

//
// Hook engine configuration
//

#define MAX_HOOKS 32
#define HOOK_JUMP_SIZE 14       // Size of x64 absolute jump (FF 25 + 8-byte address)
#define TRAMPOLINE_SIZE 64      // Size of trampoline buffer

//
// Hook status codes
//

#define HOOK_STATUS_SUCCESS         0
#define HOOK_STATUS_ALREADY_HOOKED  1
#define HOOK_STATUS_NOT_HOOKED      2
#define HOOK_STATUS_INVALID_TARGET  3
#define HOOK_STATUS_NO_SLOTS        4

//
// Structure to store hook information
//

typedef struct _HOOK_ENTRY {
    PVOID TargetFunction;           // Original function address
    PVOID HookFunction;             // Our hook function address
    PVOID TrampolineFunction;       // Allocated trampoline to call original
    UCHAR OriginalBytes[32];        // Saved original function bytes
    ULONG OriginalBytesLength;      // How many bytes we backed up
    BOOLEAN IsActive;               // Is this hook currently active
    BOOLEAN IsAllocated;            // Is this slot in use
    CHAR FunctionName[64];          // For debugging/logging
} HOOK_ENTRY, *PHOOK_ENTRY;

//
// Hook engine state
//

typedef struct _HOOK_ENGINE {
    HOOK_ENTRY Hooks[MAX_HOOKS];
    FAST_MUTEX EngineMutex;
    BOOLEAN IsInitialized;
    ULONG ActiveHookCount;
} HOOK_ENGINE, *PHOOK_ENGINE;

//
// Global hook engine instance
//

extern PHOOK_ENGINE g_HookEngine;

//
// Hook engine management functions
//

NTSTATUS HookEngineInitialize(VOID);
VOID HookEngineCleanup(VOID);

//
// Hook installation/removal
//

NTSTATUS HookEngineInstallHook(
    _In_ PVOID TargetFunction,
    _In_ PVOID HookFunction,
    _In_opt_ LPCSTR FunctionName,
    _Out_ PVOID* TrampolineFunction
);

NTSTATUS HookEngineRemoveHook(
    _In_ PVOID TargetFunction
);

NTSTATUS HookEngineRemoveAllHooks(VOID);

//
// Hook state management
//

NTSTATUS HookEngineEnableHook(
    _In_ PVOID TargetFunction
);

NTSTATUS HookEngineDisableHook(
    _In_ PVOID TargetFunction
);

//
// Utility functions
//

PHOOK_ENTRY HookEngineFindHook(
    _In_ PVOID TargetFunction
);

VOID HookEnginePrintStatistics(VOID);

//
// Low-level memory protection functions
//

KIRQL HookEngineDisableWriteProtection(VOID);
VOID HookEngineEnableWriteProtection(_In_ KIRQL OldIrql);

//
// Disassembly helper for instruction length detection
//

ULONG HookEngineGetInstructionLength(
    _In_ PVOID Address
);

ULONG HookEngineGetMinimumBytesForHook(
    _In_ PVOID Address,
    _In_ ULONG RequiredBytes
);

#endif // KERNEL_HOOK_ENGINE_H
