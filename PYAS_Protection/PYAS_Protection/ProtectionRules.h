#pragma once

#include <ntifs.h>

// Pool tag used for rule allocations
#define RULE_POOL_TAG 'lueR'

// Structure holding the in-memory rule strings loaded from disk
typedef struct _PROTECTION_RULE_SET {
    PWSTR* Rules;      // Array of null-terminated rule strings (NonPagedPool)
    ULONG Count;       // Number of valid entries in Rules
    ULONG Capacity;    // Allocated size of Rules array
} PROTECTION_RULE_SET, *PPROTECTION_RULE_SET;

// Initializes the rule engine and loads rules from disk once per boot.
NTSTATUS InitializeProtectionRules();

// Frees any allocated rule strings and resets state. Safe to call multiple times.
VOID CleanupProtectionRules();

// Checks whether the provided path should be protected.
// This enforces the hardcoded kernel root (\\Program Files\\HydraDragonAntivirus)
// and then consults dynamically loaded rules from the rules directory.
BOOLEAN IsPathProtected(_In_ PCWSTR Path);

