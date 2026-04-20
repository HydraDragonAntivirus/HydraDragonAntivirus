#pragma once
#include <ntddk.h>

// Matches OwlyshieldRansomFilter definition
typedef struct _OWLY_HV_EVENT_DETAILS
{
    ULONG RawEventType;
    ULONG SourceProcessId;
    ULONG TargetProcessId;
    PVOID MemoryAddress;
    SIZE_T MemorySize;
    ULONG MemoryProtection;
    BOOLEAN IsExecutableMemory;
    HANDLE ThreadHandle;
    PVOID ThreadStartRoutine;
    ULONG_PTR RawArgument1;
    ULONG_PTR RawArgument2;
    ULONG_PTR RawArgument3;
    ULONG_PTR RawArgument4;
    ACCESS_MASK AccessMask;
    NTSTATUS OperationStatus;
    _Field_z_ PCWSTR EventName;

    ULONG CoreId;
    ULONG ThreadId;
    ULONGLONG Context;
} OWLY_HV_EVENT_DETAILS, *POWLY_HV_EVENT_DETAILS;

typedef VOID (NTAPI *POWLY_HV_CALLBACK)(POWLY_HV_EVENT_DETAILS EventDetails);

extern POWLY_HV_CALLBACK g_OwlyCallback;

// Helper to notify Owlyshield from RedDbg context
void RedDbgNotifyOwly(POWLY_HV_EVENT_DETAILS Details);
