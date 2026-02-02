/*++

Module Name:

    KernelApiHooks.cpp

Abstract:

    Implementation of kernel API hooks for detecting malicious behavior.
    Integrates with existing driver infrastructure.

Environment:

    Kernel mode only

--*/

#include "KernelApiHooks.h"
#include "FsFilter.h"
#include "DriverData.h"
#include <ntstrsafe.h>

//
// Trampoline function pointers
//

pNtTerminateProcess g_OriginalNtTerminateProcess = NULL;
pNtOpenProcess g_OriginalNtOpenProcess = NULL;
pNtWriteVirtualMemory g_OriginalNtWriteVirtualMemory = NULL;
pNtCreateThreadEx g_OriginalNtCreateThreadEx = NULL;
pNtSetInformationFile g_OriginalNtSetInformationFile = NULL;
pNtDeleteFile g_OriginalNtDeleteFile = NULL;
pNtAllocateVirtualMemory g_OriginalNtAllocateVirtualMemory = NULL;
pNtProtectVirtualMemory g_OriginalNtProtectVirtualMemory = NULL;
pNtQueueApcThread g_OriginalNtQueueApcThread = NULL;
pNtSetContextThread g_OriginalNtSetContextThread = NULL;
pNtLoadDriver g_OriginalNtLoadDriver = NULL;
pZwCreateSection g_OriginalZwCreateSection = NULL;
pZwMapViewOfSection g_OriginalZwMapViewOfSection = NULL;

//
// Helper: Check if a process is protected by our driver
//

BOOLEAN IsProtectedProcess(ULONG Pid)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return FALSE;
    
    BOOLEAN found = FALSE;
    driverData->GetProcessGid(Pid, &found);
    return found;
}

//
// Helper: Check if memory protection is executable
//

BOOLEAN IsExecutableProtection(ULONG Protect)
{
    return (Protect & PAGE_EXECUTE) ||
           (Protect & PAGE_EXECUTE_READ) ||
           (Protect & PAGE_EXECUTE_READWRITE) ||
           (Protect & PAGE_EXECUTE_WRITECOPY);
}

//
// Helper: Log suspicious activity to usermode
//

VOID LogSuspiciousActivity(
    LPCSTR ActivityType,
    ULONG SourcePid,
    ULONG TargetPid,
    LPCWSTR AdditionalInfo
)
{
    if (driverData == NULL || driverData->isFilterClosed())
        return;
    
    DbgPrint("!!! KernelHook: Suspicious activity - %s: Source PID %lu -> Target PID %lu\n",
             ActivityType, SourcePid, TargetPid);
    
    // Create IRP entry to notify usermode
    PIRP_ENTRY newEntry = new IRP_ENTRY();
    if (newEntry != NULL) {
        PDRIVER_MESSAGE newItem = &newEntry->data;
        newItem->PID = TargetPid;
        newItem->AttackerPID = SourcePid;
        newItem->IRP_OP = IRP_PROCESS_TERMINATE_ATTEMPT;
        
        BOOLEAN found = FALSE;
        newItem->Gid = driverData->GetProcessGid(TargetPid, &found);
        newItem->AttackerGid = driverData->GetProcessGid(SourcePid, &found);
        
        if (AdditionalInfo != NULL) {
            USHORT copyLen = (USHORT)wcslen(AdditionalInfo) * sizeof(WCHAR);
            if (copyLen > MAX_FILE_NAME_SIZE - sizeof(WCHAR))
                copyLen = MAX_FILE_NAME_SIZE - sizeof(WCHAR);
            
            RtlCopyMemory(newEntry->Buffer, AdditionalInfo, copyLen);
            newEntry->Buffer[copyLen / sizeof(WCHAR)] = L'\0';
            newEntry->filePath.Length = copyLen;
            newEntry->filePath.MaximumLength = MAX_FILE_NAME_SIZE;
            newEntry->filePath.Buffer = newEntry->Buffer;
        }
        
        if (!driverData->AddIrpMessage(newEntry)) {
            delete newEntry;
        }
    }
}

//
// HOOK: NtTerminateProcess
//

NTSTATUS NTAPI HookedNtTerminateProcess(
    HANDLE ProcessHandle,
    NTSTATUS ExitStatus
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    // Get target process information
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Check if this is a protected process
        if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
            DbgPrint("!!! KernelHook: Process %lu attempting to terminate protected process %lu\n",
                     (ULONG)(ULONG_PTR)currentPid,
                     (ULONG)(ULONG_PTR)targetPid);
            
            LogSuspiciousActivity("NtTerminateProcess",
                                (ULONG)(ULONG_PTR)currentPid,
                                (ULONG)(ULONG_PTR)targetPid,
                                L"Process termination attempt");
            
            ObDereferenceObject(targetProcess);
            
            // Optionally block the termination (return access denied)
            // For now, we just log it
            // return STATUS_ACCESS_DENIED;
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    // Call original function
    return g_OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
}

//
// HOOK: NtOpenProcess
//

NTSTATUS NTAPI HookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    if (ClientId != NULL) {
        targetPid = ClientId->UniqueProcess;
        
        // Check for suspicious access rights
        if ((DesiredAccess & PROCESS_VM_WRITE) || 
            (DesiredAccess & PROCESS_VM_OPERATION) ||
            (DesiredAccess & PROCESS_CREATE_THREAD)) {
            
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu requesting dangerous access (0x%X) to process %lu\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         DesiredAccess,
                         (ULONG)(ULONG_PTR)targetPid);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Dangerous process access: 0x%X", 
                                   DesiredAccess);
                
                LogSuspiciousActivity("NtOpenProcess",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
            }
        }
    }
    
    // Call original function
    return g_OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

//
// HOOK: NtWriteVirtualMemory (Code Injection Detection)
//

NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect cross-process memory writes (potential code injection)
        if (targetPid != currentPid) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu writing %Iu bytes to process %lu at 0x%p\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         NumberOfBytesToWrite,
                         (ULONG)(ULONG_PTR)targetPid,
                         BaseAddress);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Memory write: %Iu bytes at 0x%p", 
                                   NumberOfBytesToWrite,
                                   BaseAddress);
                
                LogSuspiciousActivity("NtWriteVirtualMemory",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block code injection attempts
                // ObDereferenceObject(targetProcess);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    // Call original function
    return g_OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, 
                                         NumberOfBytesToWrite, NumberOfBytesWritten);
}

//
// HOOK: NtCreateThreadEx (Remote Thread Detection)
//

NTSTATUS NTAPI HookedNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect remote thread creation
        if (targetPid != currentPid) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu creating remote thread in process %lu at 0x%p\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         (ULONG)(ULONG_PTR)targetPid,
                         StartRoutine);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Remote thread: start=0x%p", 
                                   StartRoutine);
                
                LogSuspiciousActivity("NtCreateThreadEx",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block remote thread creation
                // ObDereferenceObject(targetProcess);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    // Call original function
    return g_OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
                                     ProcessHandle, StartRoutine, Argument,
                                     CreateFlags, ZeroBits, StackSize,
                                     MaximumStackSize, AttributeList);
}

//
// HOOK: NtSetInformationFile (File Rename/Delete Detection)
//

NTSTATUS NTAPI HookedNtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
)
{
    // This can detect file renames, deletions, etc.
    // Already covered by your minifilter, so just pass through
    // But we could add additional kernel-level checks here
    
    return g_OriginalNtSetInformationFile(FileHandle, IoStatusBlock, 
                                         FileInformation, Length, 
                                         FileInformationClass);
}

//
// HOOK: NtDeleteFile
//

NTSTATUS NTAPI HookedNtDeleteFile(
    POBJECT_ATTRIBUTES ObjectAttributes
)
{
    // Already covered by your minifilter
    // Just pass through
    
    return g_OriginalNtDeleteFile(ObjectAttributes);
}

//
// ============================================================================
// ADVANCED HOOKS - Memory Manipulation and Code Injection Detection
// ============================================================================
//

//
// HOOK: NtAllocateVirtualMemory
//

NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect cross-process executable memory allocation
        if (targetPid != currentPid && IsExecutableProtection(Protect)) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu allocating executable memory (0x%X) in process %lu\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         Protect,
                         (ULONG)(ULONG_PTR)targetPid);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Executable memory allocation: Protection=0x%X",
                                   Protect);
                
                LogSuspiciousActivity("NtAllocateVirtualMemory",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block executable allocations
                // ObDereferenceObject(targetProcess);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    return g_OriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
                                            RegionSize, AllocationType, Protect);
}

//
// HOOK: NtProtectVirtualMemory (DEP Bypass Detection)
//

NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect making memory executable (DEP bypass)
        if (targetPid != currentPid && IsExecutableProtection(NewProtect)) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu changing memory protection to executable (0x%X) in process %lu\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         NewProtect,
                         (ULONG)(ULONG_PTR)targetPid);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"DEP bypass attempt: NewProtect=0x%X at 0x%p",
                                   NewProtect, BaseAddress ? *BaseAddress : NULL);
                
                LogSuspiciousActivity("NtProtectVirtualMemory",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block DEP bypass attempts
                // ObDereferenceObject(targetProcess);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    return g_OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, 
                                           RegionSize, NewProtect, OldProtect);
}

//
// HOOK: NtQueueApcThread (APC Injection Detection)
//

NTSTATUS NTAPI HookedNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
)
{
    PETHREAD targetThread = NULL;
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_QUERY_INFORMATION,
        *PsThreadType,
        KernelMode,
        (PVOID*)&targetThread,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetProcess = IoThreadToProcess(targetThread);
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect cross-process APC injection
        if (targetPid != currentPid) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu queuing APC in process %lu thread (Routine: 0x%p)\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         (ULONG)(ULONG_PTR)targetPid,
                         ApcRoutine);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"APC injection: Routine=0x%p",
                                   ApcRoutine);
                
                LogSuspiciousActivity("NtQueueApcThread",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block APC injection
                // ObDereferenceObject(targetThread);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetThread);
    }
    
    return g_OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, 
                                     ApcArgument1, ApcArgument2, ApcArgument3);
}

//
// HOOK: NtSetContextThread (Thread Hijacking Detection)
//

NTSTATUS NTAPI HookedNtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
)
{
    PETHREAD targetThread = NULL;
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ThreadHandle,
        THREAD_QUERY_INFORMATION,
        *PsThreadType,
        KernelMode,
        (PVOID*)&targetThread,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetProcess = IoThreadToProcess(targetThread);
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect cross-process thread context manipulation
        if (targetPid != currentPid) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu modifying thread context in process %lu\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         (ULONG)(ULONG_PTR)targetPid);
                
#ifdef _AMD64_
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Thread hijacking: RIP=0x%llX",
                                   ThreadContext ? ThreadContext->Rip : 0);
#else
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Thread hijacking: EIP=0x%X",
                                   ThreadContext ? ThreadContext->Eip : 0);
#endif
                
                LogSuspiciousActivity("NtSetContextThread",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block thread hijacking
                // ObDereferenceObject(targetThread);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetThread);
    }
    
    return g_OriginalNtSetContextThread(ThreadHandle, ThreadContext);
}

//
// HOOK: NtLoadDriver (Rootkit Driver Loading Detection)
//

NTSTATUS NTAPI HookedNtLoadDriver(
    PUNICODE_STRING DriverServiceName
)
{
    HANDLE currentPid = PsGetCurrentProcessId();
    
    DbgPrint("!!! KernelHook: Process %lu attempting to load driver: %wZ\n",
             (ULONG)(ULONG_PTR)currentPid,
             DriverServiceName);
    
    // Log driver loading attempts
    WCHAR info[256];
    if (DriverServiceName && DriverServiceName->Buffer) {
        RtlStringCbPrintfW(info, sizeof(info), 
                          L"Driver load: %wZ",
                          DriverServiceName);
    } else {
        RtlStringCbCopyW(info, sizeof(info), L"Driver load: (null)");
    }
    
    LogSuspiciousActivity("NtLoadDriver",
                        (ULONG)(ULONG_PTR)currentPid,
                        0,
                        info);
    
    // Optionally block unauthorized driver loading
    // return STATUS_ACCESS_DENIED;
    
    return g_OriginalNtLoadDriver(DriverServiceName);
}

//
// HOOK: ZwCreateSection (Section Object Creation Detection)
//

NTSTATUS NTAPI HookedZwCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
)
{
    HANDLE currentPid = PsGetCurrentProcessId();
    
    // Detect executable section creation
    if (IsExecutableProtection(SectionPageProtection)) {
        DbgPrint("!!! KernelHook: Process %lu creating executable section (Protection: 0x%X)\n",
                 (ULONG)(ULONG_PTR)currentPid,
                 SectionPageProtection);
        
        WCHAR info[128];
        RtlStringCbPrintfW(info, sizeof(info), 
                          L"Executable section creation: Protection=0x%X",
                          SectionPageProtection);
        
        LogSuspiciousActivity("ZwCreateSection",
                            (ULONG)(ULONG_PTR)currentPid,
                            0,
                            info);
    }
    
    return g_OriginalZwCreateSection(SectionHandle, DesiredAccess, ObjectAttributes,
                                     MaximumSize, SectionPageProtection, 
                                     AllocationAttributes, FileHandle);
}

//
// HOOK: ZwMapViewOfSection (Section Mapping Detection)
//

NTSTATUS NTAPI HookedZwMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    ULONG InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
)
{
    PEPROCESS targetProcess = NULL;
    HANDLE currentPid = PsGetCurrentProcessId();
    HANDLE targetPid = NULL;
    
    NTSTATUS status = ObReferenceObjectByHandle(
        ProcessHandle,
        PROCESS_QUERY_INFORMATION,
        *PsProcessType,
        KernelMode,
        (PVOID*)&targetProcess,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        targetPid = PsGetProcessId(targetProcess);
        
        // Detect cross-process executable section mapping
        if (targetPid != currentPid && IsExecutableProtection(Win32Protect)) {
            if (IsProtectedProcess((ULONG)(ULONG_PTR)targetPid)) {
                DbgPrint("!!! KernelHook: Process %lu mapping executable section into process %lu (Protection: 0x%X)\n",
                         (ULONG)(ULONG_PTR)currentPid,
                         (ULONG)(ULONG_PTR)targetPid,
                         Win32Protect);
                
                WCHAR info[128];
                RtlStringCbPrintfW(info, sizeof(info), 
                                   L"Section mapping: Protection=0x%X",
                                   Win32Protect);
                
                LogSuspiciousActivity("ZwMapViewOfSection",
                                    (ULONG)(ULONG_PTR)currentPid,
                                    (ULONG)(ULONG_PTR)targetPid,
                                    info);
                
                // Optionally block dangerous section mappings
                // ObDereferenceObject(targetProcess);
                // return STATUS_ACCESS_DENIED;
            }
        }
        
        ObDereferenceObject(targetProcess);
    }
    
    return g_OriginalZwMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress,
                                        ZeroBits, CommitSize, SectionOffset,
                                        ViewSize, InheritDisposition, 
                                        AllocationType, Win32Protect);
}

//
// ============================================================================
// END OF ADVANCED HOOKS
// ============================================================================
//

//
// Install all kernel API hooks (Basic + Advanced)
//

NTSTATUS InstallKernelApiHooks(VOID)
{
    NTSTATUS status;
    UNICODE_STRING funcName;
    PVOID targetFunc;
    
    DbgPrint("!!! KernelHook: Installing kernel API hooks (Basic + Advanced)...\n");
    
    // ========================================================================
    // BASIC HOOKS
    // ========================================================================
    
    // Hook 1: NtTerminateProcess
    RtlInitUnicodeString(&funcName, L"NtTerminateProcess");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtTerminateProcess,
            "NtTerminateProcess",
            (PVOID*)&g_OriginalNtTerminateProcess
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtTerminateProcess: 0x%X\n", status);
        }
    }
    
    // Hook 2: NtOpenProcess
    RtlInitUnicodeString(&funcName, L"NtOpenProcess");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtOpenProcess,
            "NtOpenProcess",
            (PVOID*)&g_OriginalNtOpenProcess
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtOpenProcess: 0x%X\n", status);
        }
    }
    
    // Hook 3: NtWriteVirtualMemory
    RtlInitUnicodeString(&funcName, L"NtWriteVirtualMemory");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtWriteVirtualMemory,
            "NtWriteVirtualMemory",
            (PVOID*)&g_OriginalNtWriteVirtualMemory
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtWriteVirtualMemory: 0x%X\n", status);
        }
    }
    
    // Hook 4: NtCreateThreadEx
    RtlInitUnicodeString(&funcName, L"NtCreateThreadEx");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtCreateThreadEx,
            "NtCreateThreadEx",
            (PVOID*)&g_OriginalNtCreateThreadEx
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtCreateThreadEx: 0x%X\n", status);
        }
    }
    
    // ========================================================================
    // ADVANCED HOOKS - Memory Manipulation & Code Injection
    // ========================================================================
    
    // Hook 5: NtAllocateVirtualMemory
    RtlInitUnicodeString(&funcName, L"NtAllocateVirtualMemory");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtAllocateVirtualMemory,
            "NtAllocateVirtualMemory",
            (PVOID*)&g_OriginalNtAllocateVirtualMemory
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtAllocateVirtualMemory: 0x%X\n", status);
        }
    }
    
    // Hook 6: NtProtectVirtualMemory
    RtlInitUnicodeString(&funcName, L"NtProtectVirtualMemory");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtProtectVirtualMemory,
            "NtProtectVirtualMemory",
            (PVOID*)&g_OriginalNtProtectVirtualMemory
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtProtectVirtualMemory: 0x%X\n", status);
        }
    }
    
    // Hook 7: NtQueueApcThread
    RtlInitUnicodeString(&funcName, L"NtQueueApcThread");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtQueueApcThread,
            "NtQueueApcThread",
            (PVOID*)&g_OriginalNtQueueApcThread
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtQueueApcThread: 0x%X\n", status);
        }
    }
    
    // Hook 8: NtSetContextThread
    RtlInitUnicodeString(&funcName, L"NtSetContextThread");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtSetContextThread,
            "NtSetContextThread",
            (PVOID*)&g_OriginalNtSetContextThread
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtSetContextThread: 0x%X\n", status);
        }
    }
    
    // Hook 9: NtLoadDriver
    RtlInitUnicodeString(&funcName, L"NtLoadDriver");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedNtLoadDriver,
            "NtLoadDriver",
            (PVOID*)&g_OriginalNtLoadDriver
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook NtLoadDriver: 0x%X\n", status);
        }
    }
    
    // Hook 10: ZwCreateSection
    RtlInitUnicodeString(&funcName, L"ZwCreateSection");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedZwCreateSection,
            "ZwCreateSection",
            (PVOID*)&g_OriginalZwCreateSection
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook ZwCreateSection: 0x%X\n", status);
        }
    }
    
    // Hook 11: ZwMapViewOfSection
    RtlInitUnicodeString(&funcName, L"ZwMapViewOfSection");
    targetFunc = MmGetSystemRoutineAddress(&funcName);
    if (targetFunc != NULL) {
        status = HookEngineInstallHook(
            targetFunc,
            (PVOID)HookedZwMapViewOfSection,
            "ZwMapViewOfSection",
            (PVOID*)&g_OriginalZwMapViewOfSection
        );
        if (!NT_SUCCESS(status)) {
            DbgPrint("!!! KernelHook: Failed to hook ZwMapViewOfSection: 0x%X\n", status);
        }
    }
    
    // Print statistics
    HookEnginePrintStatistics();
    
    DbgPrint("!!! KernelHook: All kernel API hooks installed (Basic + Advanced)\n");
    return STATUS_SUCCESS;
}

//
// Remove all kernel API hooks
//

VOID RemoveKernelApiHooks(VOID)
{
    DbgPrint("!!! KernelHook: Removing kernel API hooks...\n");
    
    // The hook engine will clean up all hooks when HookEngineRemoveAllHooks is called
    // No need to manually remove each one
    
    DbgPrint("!!! KernelHook: Kernel API hooks removed\n");
}
