#pragma once

#include <ntifs.h>

// Pool tag used for rule allocations
#define RULE_POOL_TAG 'lueR'

// Rule categories
typedef enum _RULE_TYPE {
    RuleTypeProcess = 0,
    RuleTypeFile,
    RuleTypeRegistry,
    RuleTypeMax
} RULE_TYPE;

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

// Checks whether the provided path should be protected for a specific type.
BOOLEAN IsPathProtectedByType(_In_ PCWSTR Path, _In_ RULE_TYPE RuleType);

// Checks whether the provided path should be protected (legacy/default to File).
BOOLEAN IsPathProtected(_In_ PCWSTR Path);

VOID NormalizeDevicePathToDos(PUNICODE_STRING Path);
