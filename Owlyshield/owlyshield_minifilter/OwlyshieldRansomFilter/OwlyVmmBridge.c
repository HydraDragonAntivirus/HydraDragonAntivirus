#include "OwlyVmmBridge.h"
#include "Communication.h"
#include <ntstrsafe.h>

static BOOLEAN g_OwlyVmmInitialized = FALSE;
static UINT32  g_OwlyVmmLastError   = 0;

#if defined(_M_AMD64)
static BOOLEAN g_OwlyVmmFallbackActive = FALSE;

BOOLEAN
OwlyVmFuncInitVmmFallback(VMM_CALLBACKS * VmmCallbacks)
{
    UNREFERENCED_PARAMETER(VmmCallbacks);
    g_OwlyVmmFallbackActive = TRUE;
    return FALSE;
}

VOID
OwlyVmFuncUninitVmmFallback(VOID)
{
}

// Use HyperDbg exports when they are linked; otherwise resolve to local fallbacks.
#pragma comment(linker, "/alternatename:VmFuncInitVmm=OwlyVmFuncInitVmmFallback")
#pragma comment(linker, "/alternatename:VmFuncUninitVmm=OwlyVmFuncUninitVmmFallback")
#endif

static NTSTATUS
OwlyNormalizeVmmInitFailure(UINT32 LastError)
{
    if (LastError == 0 || LastError == 0xFFFFFFFFu)
    {
        return STATUS_NOT_SUPPORTED;
    }

    // Map generic/user-facing initialization failures to NOT_SUPPORTED so
    // startup logs reflect environmental limitations instead of hard failures.
    if (LastError == (UINT32)STATUS_UNSUCCESSFUL || LastError == (UINT32)STATUS_INVALID_PARAMETER)
    {
        return STATUS_NOT_SUPPORTED;
    }

    // HyperDbg SDK error codes are reported as 0xC00000xx and are not precise
    // NTSTATUS values for this driver startup path.
    if ((LastError & 0xFFFFFF00u) == 0xC0000000u)
    {
        return STATUS_NOT_SUPPORTED;
    }

    return (NTSTATUS)LastError;
}

static BOOLEAN
OwlyReportHyperDbgEvent(_In_ const OWLY_HYPERDBG_EVENT_DETAILS * EventDetails)
{
    OWLY_HV_EVENT_DETAILS queueDetails;

    if (EventDetails == NULL)
    {
        return FALSE;
    }

    RtlZeroMemory(&queueDetails, sizeof(queueDetails));
    queueDetails.RawEventType = EventDetails->RawEventType;
    queueDetails.SourceProcessId = EventDetails->SourceProcessId;
    queueDetails.TargetProcessId = EventDetails->TargetProcessId;
    queueDetails.MemoryAddress = (PVOID)(ULONG_PTR)EventDetails->MemoryAddress;
    queueDetails.MemorySize = (SIZE_T)EventDetails->MemorySize;
    queueDetails.MemoryProtection = EventDetails->MemoryProtection;
    queueDetails.IsExecutableMemory = EventDetails->IsExecutableMemory;
    queueDetails.ThreadHandle = (HANDLE)(ULONG_PTR)EventDetails->ThreadHandle;
    queueDetails.ThreadStartRoutine = (PVOID)(ULONG_PTR)EventDetails->ThreadStartRoutine;
    queueDetails.RawArgument1 = (ULONG_PTR)EventDetails->RawArgument1;
    queueDetails.RawArgument2 = (ULONG_PTR)EventDetails->RawArgument2;
    queueDetails.RawArgument3 = (ULONG_PTR)EventDetails->RawArgument3;
    queueDetails.RawArgument4 = (ULONG_PTR)EventDetails->RawArgument4;
    queueDetails.AccessMask = (ACCESS_MASK)EventDetails->AccessMask;
    queueDetails.OperationStatus = (NTSTATUS)EventDetails->OperationStatus;
    queueDetails.EventName = EventDetails->EventName;
    queueDetails.CoreId = EventDetails->CoreId;
    queueDetails.ThreadId = EventDetails->ThreadId;
    queueDetails.Context = EventDetails->Context;

    return QueueHypervisorEvent(&queueDetails);
}

static VOID
OwlyInitializeBridgeEvent(_Out_ POWLY_HYPERDBG_EVENT_DETAILS EventDetails,
                          _In_ ULONG                         RawEventType,
                          _In_opt_ PCWSTR                    EventName)
{
    ULONG currentProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    RtlZeroMemory(EventDetails, sizeof(*EventDetails));
    EventDetails->RawEventType = RawEventType;
    EventDetails->SourceProcessId = currentProcessId;
    EventDetails->TargetProcessId = currentProcessId;
    EventDetails->ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    EventDetails->OperationStatus = STATUS_SUCCESS;
    EventDetails->EventName = EventName;
}

static VOID
OwlyForwardKernelEvent(_In_ ULONG RawEventType, _In_ PCWSTR EventName, _In_ ULONG_PTR Arg1, _In_ ULONG_PTR Arg2)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, RawEventType, EventName);
    eventDetails.RawArgument1 = Arg1;
    eventDetails.RawArgument2 = Arg2;

    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static VOID
OwlyForwardAfterSyscallEvent(_In_opt_ GUEST_REGS * Regs,
                             _In_ UINT32           ProcessId,
                             _In_ UINT32           ThreadId,
                             _In_ UINT64           Context,
                             _In_opt_ SYSCALL_CALLBACK_CONTEXT_PARAMS * Params)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;
    ULONG                 sourceProcessId = ProcessId;

    if (sourceProcessId == 0)
    {
        sourceProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    }

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_HYPEREVADE_BASE + 8u, L"TRANSPARENT_AFTER_SYSCALL");
    eventDetails.SourceProcessId = sourceProcessId;
    eventDetails.TargetProcessId = sourceProcessId;
    eventDetails.ThreadId = ThreadId;
    eventDetails.Context = Context;
    eventDetails.RawArgument1 = (Params != NULL) ? (ULONG_PTR)Params->OptionalParam1 : 0;
    eventDetails.RawArgument2 = (Params != NULL) ? (ULONG_PTR)Params->OptionalParam2 : 0;
    eventDetails.RawArgument3 = (Params != NULL) ? (ULONG_PTR)Params->OptionalParam3 : 0;
    eventDetails.RawArgument4 = (Params != NULL) ? (ULONG_PTR)Params->OptionalParam4 : 0;
    eventDetails.MemoryAddress = (Params != NULL) ? Params->OptionalParam3 : 0;
    eventDetails.MemorySize = (Params != NULL) ? Params->OptionalParam4 : 0;
    eventDetails.OperationStatus = (Regs != NULL) ? (NTSTATUS)(ULONG_PTR)Regs->rax : STATUS_SUCCESS;

    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static VOID
OwlyForwardVmcallEvent(_In_ UINT32 CoreId,
                       _In_ UINT64 VmcallNumber,
                       _In_ UINT64 OptionalParam1,
                       _In_ UINT64 OptionalParam2,
                       _In_ UINT64 OptionalParam3)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_VMCALL_EVENT, L"VMMCALL");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = VmcallNumber;
    eventDetails.RawArgument2 = OptionalParam1;
    eventDetails.RawArgument3 = OptionalParam2;
    eventDetails.RawArgument4 = OptionalParam3;

    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static VOID
OwlyForwardProtectedResourceEvent(_In_ UINT32                               CoreId,
                                  _In_ PROTECTED_HV_RESOURCES_TYPE          ResourceType,
                                  _In_opt_ PVOID                            Context,
                                  _In_ PROTECTED_HV_RESOURCES_PASSING_OVERS PassOver)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_PROTECTED_EVENT, L"QUERY_TERMINATE_PROTECTED_RESOURCE");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = (ULONG_PTR)ResourceType;
    eventDetails.RawArgument2 = (ULONG_PTR)PassOver;
    eventDetails.MemoryAddress = (UINT64)(ULONG_PTR)Context;

    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static VOID
OwlyForwardUnhandledEptEvent(_In_ UINT32 CoreId, _In_ UINT64 ViolationQualification,
                             _In_ UINT64 GuestPhysicalAddr)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_UNHANDLED_EPT, L"UNHANDLED_EPT_VIOLATION");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = (ULONG_PTR)ViolationQualification;
    eventDetails.MemoryAddress = GuestPhysicalAddr;

    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static PCWSTR
OwlyVmmEventTypeName(VMM_EVENT_TYPE_ENUM EventType)
{
    switch (EventType)
    {
    case HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE:
        return L"HIDDEN_HOOK_READ_AND_WRITE_AND_EXECUTE";
    case HIDDEN_HOOK_READ_AND_WRITE:
        return L"HIDDEN_HOOK_READ_AND_WRITE";
    case HIDDEN_HOOK_READ_AND_EXECUTE:
        return L"HIDDEN_HOOK_READ_AND_EXECUTE";
    case HIDDEN_HOOK_WRITE_AND_EXECUTE:
        return L"HIDDEN_HOOK_WRITE_AND_EXECUTE";
    case HIDDEN_HOOK_READ:
        return L"HIDDEN_HOOK_READ";
    case HIDDEN_HOOK_WRITE:
        return L"HIDDEN_HOOK_WRITE";
    case HIDDEN_HOOK_EXECUTE:
        return L"HIDDEN_HOOK_EXECUTE";
    case HIDDEN_HOOK_EXEC_DETOURS:
        return L"HIDDEN_HOOK_EXEC_DETOURS";
    case HIDDEN_HOOK_EXEC_CC:
        return L"HIDDEN_HOOK_EXEC_CC";
    case SYSCALL_HOOK_EFER_SYSCALL:
        return L"SYSCALL_HOOK_EFER_SYSCALL";
    case SYSCALL_HOOK_EFER_SYSRET:
        return L"SYSCALL_HOOK_EFER_SYSRET";
    case CPUID_INSTRUCTION_EXECUTION:
        return L"CPUID_INSTRUCTION_EXECUTION";
    case RDMSR_INSTRUCTION_EXECUTION:
        return L"RDMSR_INSTRUCTION_EXECUTION";
    case WRMSR_INSTRUCTION_EXECUTION:
        return L"WRMSR_INSTRUCTION_EXECUTION";
    case IN_INSTRUCTION_EXECUTION:
        return L"IN_INSTRUCTION_EXECUTION";
    case OUT_INSTRUCTION_EXECUTION:
        return L"OUT_INSTRUCTION_EXECUTION";
    case EXCEPTION_OCCURRED:
        return L"EXCEPTION_OCCURRED";
    case EXTERNAL_INTERRUPT_OCCURRED:
        return L"EXTERNAL_INTERRUPT_OCCURRED";
    case DEBUG_REGISTERS_ACCESSED:
        return L"DEBUG_REGISTERS_ACCESSED";
    case TSC_INSTRUCTION_EXECUTION:
        return L"TSC_INSTRUCTION_EXECUTION";
    case PMC_INSTRUCTION_EXECUTION:
        return L"PMC_INSTRUCTION_EXECUTION";
    case VMCALL_INSTRUCTION_EXECUTION:
        return L"VMCALL_INSTRUCTION_EXECUTION";
    case CONTROL_REGISTER_MODIFIED:
        return L"CONTROL_REGISTER_MODIFIED";
    case CONTROL_REGISTER_READ:
        return L"CONTROL_REGISTER_READ";
    case CONTROL_REGISTER_3_MODIFIED:
        return L"CONTROL_REGISTER_3_MODIFIED";
    case TRAP_EXECUTION_MODE_CHANGED:
        return L"TRAP_EXECUTION_MODE_CHANGED";
    case TRAP_EXECUTION_INSTRUCTION_TRACE:
        return L"TRAP_EXECUTION_INSTRUCTION_TRACE";
    case XSETBV_INSTRUCTION_EXECUTION:
        return L"XSETBV_INSTRUCTION_EXECUTION";
    default:
        return L"UNKNOWN_VMM_EVENT";
    }
}

static PCWSTR
OwlyStageName(VMM_CALLBACK_EVENT_CALLING_STAGE_TYPE Stage)
{
    switch (Stage)
    {
    case VMM_CALLBACK_CALLING_STAGE_PRE_EVENT_EMULATION:
        return L"PRE";
    case VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION:
        return L"POST";
    case VMM_CALLBACK_CALLING_STAGE_ALL_EVENT_EMULATION:
        return L"ALL";
    default:
        return L"INVALID";
    }
}

static BOOLEAN
OwlyLogCallbackPrepareAndSendMessageToQueueWrapper(UINT32       OperationCode,
                                                    BOOLEAN      IsImmediateMessage,
                                                    BOOLEAN      ShowCurrentSystemTime,
                                                    BOOLEAN      Priority,
                                                    const char * Fmt,
                                                    va_list      ArgList)
{
    UNREFERENCED_PARAMETER(OperationCode);
    UNREFERENCED_PARAMETER(IsImmediateMessage);
    UNREFERENCED_PARAMETER(ShowCurrentSystemTime);
    UNREFERENCED_PARAMETER(Priority);
    UNREFERENCED_PARAMETER(Fmt);
    UNREFERENCED_PARAMETER(ArgList);
    return FALSE;
}

static BOOLEAN
OwlyLogCallbackSendMessageToQueue(UINT32  OperationCode,
                                  BOOLEAN IsImmediateMessage,
                                  CHAR *  LogMessage,
                                  UINT32  BufferLen,
                                  BOOLEAN Priority)
{
    UNREFERENCED_PARAMETER(OperationCode);
    UNREFERENCED_PARAMETER(IsImmediateMessage);
    UNREFERENCED_PARAMETER(LogMessage);
    UNREFERENCED_PARAMETER(BufferLen);
    UNREFERENCED_PARAMETER(Priority);
    return FALSE;
}

static BOOLEAN
OwlyLogCallbackSendBuffer(_In_ UINT32                          OperationCode,
                          _In_reads_bytes_(BufferLength) PVOID Buffer,
                          _In_ UINT32                          BufferLength,
                          _In_ BOOLEAN                         Priority)
{
    UNREFERENCED_PARAMETER(OperationCode);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Priority);
    return FALSE;
}

static BOOLEAN
OwlyLogCallbackCheckIfBufferIsFull(BOOLEAN Priority)
{
    UNREFERENCED_PARAMETER(Priority);
    return FALSE;
}

static VMM_CALLBACK_TRIGGERING_EVENT_STATUS_TYPE
OwlyVmmCallbackTriggerEvents(VMM_EVENT_TYPE_ENUM                   EventType,
                             VMM_CALLBACK_EVENT_CALLING_STAGE_TYPE CallingStage,
                             PVOID                                 Context,
                             BOOLEAN *                             PostEventRequired,
                             GUEST_REGS *                          Regs)
{
    if (PostEventRequired != NULL)
    {
        *PostEventRequired = FALSE;
    }

    {
        OWLY_HYPERDBG_EVENT_DETAILS eventDetails;
        WCHAR     eventLabel[128] = {0};
        ULONG     rawEventType    = OWLY_VMM_RAW_EVENT_BASE + (((ULONG)CallingStage & 0xffu) << 8) + ((ULONG)EventType & 0xffu);
        ULONG_PTR arg1            = (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0;
        ULONG_PTR arg2            = (Context != NULL) ? (ULONG_PTR)Context : ((Regs != NULL) ? (ULONG_PTR)Regs->rcx : 0);

        if (!NT_SUCCESS(RtlStringCchPrintfW(eventLabel,
                                            RTL_NUMBER_OF(eventLabel),
                                            L"%ws:%ws",
                                            OwlyVmmEventTypeName(EventType),
                                            OwlyStageName(CallingStage))))
        {
            RtlStringCchCopyW(eventLabel, RTL_NUMBER_OF(eventLabel), L"VMM_EVENT");
        }

        OwlyInitializeBridgeEvent(&eventDetails, rawEventType, eventLabel);
        eventDetails.Context = (UINT64)(ULONG_PTR)Context;
        eventDetails.RawArgument1 = arg1;
        eventDetails.RawArgument2 = arg2;
        eventDetails.RawArgument3 = (Regs != NULL) ? (ULONG_PTR)Regs->rdx : 0;
        eventDetails.RawArgument4 = (Regs != NULL) ? (ULONG_PTR)Regs->r8 : 0;
        if (Regs != NULL &&
            (EventType == SYSCALL_HOOK_EFER_SYSCALL || EventType == SYSCALL_HOOK_EFER_SYSRET) &&
            CallingStage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
        {
            eventDetails.OperationStatus = (NTSTATUS)(ULONG_PTR)Regs->rax;
        }

        (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    }

    return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_SUCCESSFUL_NO_INITIALIZED;
}

static VOID
OwlyVmmCallbackSetLastError(UINT32 LastError)
{
    g_OwlyVmmLastError = LastError;
}

static BOOLEAN
OwlyVmmCallbackVmcallHandler(UINT32 CoreId,
                             UINT64 VmcallNumber,
                             UINT64 OptionalParam1,
                             UINT64 OptionalParam2,
                             UINT64 OptionalParam3)
{
    OwlyForwardVmcallEvent(CoreId, VmcallNumber, OptionalParam1, OptionalParam2, OptionalParam3);
    return FALSE;
}

static VOID
OwlyVmmCallbackNmiBroadcastRequestHandler(UINT32 CoreId, BOOLEAN IsOnVmxNmiHandler)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_NMI_EVENT, L"NMI_BROADCAST");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = IsOnVmxNmiHandler ? 1u : 0u;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static BOOLEAN
OwlyVmmCallbackQueryTerminateProtectedResource(UINT32                               CoreId,
                                               PROTECTED_HV_RESOURCES_TYPE          ResourceType,
                                               PVOID                                Context,
                                               PROTECTED_HV_RESOURCES_PASSING_OVERS PassOver)
{
    OwlyForwardProtectedResourceEvent(CoreId, ResourceType, Context, PassOver);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackRestoreEptState(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_RESTORE_EPT, L"RESTORE_EPT_STATE");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackCheckUnhandledEptViolations(UINT32 CoreId, UINT64 ViolationQualification, UINT64 GuestPhysicalAddr)
{
    OwlyForwardUnhandledEptEvent(CoreId, ViolationQualification, GuestPhysicalAddr);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleBreakpointException(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_BP_EVENT, L"DEBUG_BREAKPOINT_EXCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleDebugBreakpointException(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_DBG_BP_EVENT, L"DEBUG_DEBUG_BREAKPOINT_EXCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackCheckThreadInterception(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_THREAD_INT_EVENT, L"DEBUG_THREAD_INTERCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static VOID
OwlyInterceptionCallbackTriggerCr3ProcessChange(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_CR3_EVENT, L"CR3_PROCESS_CHANGE");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static BOOLEAN
OwlyBreakpointCheckAndHandleReApplyingBreakpoint(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_REAPPLY_BP_EVENT, L"REAPPLY_BREAKPOINT");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static BOOLEAN
OwlyKdCheckAndHandleNmiCallback(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_KD_NMI_EVENT, L"KD_NMI_CALLBACK");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static VOID
OwlyVmmCallbackRegisteredMtfHandler(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_MTF_EVENT, L"REGISTERED_MTF_HANDLER");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
}

static BOOLEAN
OwlyDebuggerCheckProcessOrThreadChange(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_PROC_THR_EVENT, L"DEBUGGER_PROCESS_OR_THREAD_CHANGE");
    eventDetails.CoreId = CoreId;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

static BOOLEAN
OwlyKdQueryDebuggerThreadOrProcessTracingDetailsByCoreId(UINT32 CoreId, DEBUGGER_THREAD_PROCESS_TRACING TracingType)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    OwlyInitializeBridgeEvent(&eventDetails, OWLY_VMM_RAW_TRACING_EVENT, L"KD_QUERY_THREAD_OR_PROCESS_TRACING");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = (ULONG_PTR)TracingType;
    (VOID)OwlyReportHyperDbgEvent(&eventDetails);
    return FALSE;
}

NTSTATUS
OwlyVmmInitialize(VOID)
{
    VMM_CALLBACKS callbacks;
    BOOLEAN       initResult = FALSE;

    if (g_OwlyVmmInitialized)
    {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&callbacks, sizeof(callbacks));

    callbacks.LogCallbackPrepareAndSendMessageToQueueWrapper = OwlyLogCallbackPrepareAndSendMessageToQueueWrapper;
    callbacks.LogCallbackSendMessageToQueue                  = OwlyLogCallbackSendMessageToQueue;
    callbacks.LogCallbackSendBuffer                          = OwlyLogCallbackSendBuffer;
    callbacks.LogCallbackCheckIfBufferIsFull                 = OwlyLogCallbackCheckIfBufferIsFull;
    callbacks.ReportOwlyEvent                                = OwlyReportHyperDbgEvent;
    callbacks.VmmCallbackTriggerEvents                       = OwlyVmmCallbackTriggerEvents;
    callbacks.VmmCallbackSetLastError                        = OwlyVmmCallbackSetLastError;
    callbacks.VmmCallbackVmcallHandler                       = OwlyVmmCallbackVmcallHandler;
    callbacks.VmmCallbackNmiBroadcastRequestHandler          = OwlyVmmCallbackNmiBroadcastRequestHandler;
    callbacks.VmmCallbackQueryTerminateProtectedResource     = OwlyVmmCallbackQueryTerminateProtectedResource;
    callbacks.VmmCallbackRestoreEptState                     = OwlyVmmCallbackRestoreEptState;
    callbacks.VmmCallbackCheckUnhandledEptViolations         = OwlyVmmCallbackCheckUnhandledEptViolations;
    callbacks.DebuggingCallbackHandleBreakpointException     = OwlyDebuggingCallbackHandleBreakpointException;
    callbacks.DebuggingCallbackHandleDebugBreakpointException = OwlyDebuggingCallbackHandleDebugBreakpointException;
    callbacks.DebuggingCallbackCheckThreadInterception        = OwlyDebuggingCallbackCheckThreadInterception;
    callbacks.InterceptionCallbackTriggerCr3ProcessChange     = OwlyInterceptionCallbackTriggerCr3ProcessChange;
    callbacks.BreakpointCheckAndHandleReApplyingBreakpoint    = OwlyBreakpointCheckAndHandleReApplyingBreakpoint;
    callbacks.KdCheckAndHandleNmiCallback                     = OwlyKdCheckAndHandleNmiCallback;
    callbacks.VmmCallbackRegisteredMtfHandler                 = OwlyVmmCallbackRegisteredMtfHandler;
    callbacks.DebuggerCheckProcessOrThreadChange              = OwlyDebuggerCheckProcessOrThreadChange;
    callbacks.KdQueryDebuggerQueryThreadOrProcessTracingDetailsByCoreId =
        OwlyKdQueryDebuggerThreadOrProcessTracingDetailsByCoreId;

#if defined(_M_AMD64)
    g_OwlyVmmFallbackActive = FALSE;
#endif
    g_OwlyVmmLastError = 0;

    initResult = VmFuncInitVmm(&callbacks);
    if (!initResult)
    {
#if defined(_M_AMD64)
        if (g_OwlyVmmFallbackActive)
        {
            return STATUS_NOT_SUPPORTED;
        }
#endif
        if (g_OwlyVmmLastError != 0)
        {
            return OwlyNormalizeVmmInitFailure(g_OwlyVmmLastError);
        }

        // VmFuncInitVmm can fail without setting a specific error (e.g., no VT-x /
        // unsupported runtime environment). Report this as NOT_SUPPORTED so caller
        // can log "skipped" instead of generic unsuccessful.
        return STATUS_NOT_SUPPORTED;
    }

    g_OwlyVmmInitialized = TRUE;
    return STATUS_SUCCESS;
}

VOID
OwlyVmmUninitialize(VOID)
{
    if (!g_OwlyVmmInitialized)
    {
        return;
    }

    VmFuncUninitVmm();
    g_OwlyVmmInitialized = FALSE;
}

//
// Stubs for optional components we intentionally keep disabled.
// They preserve VMM core behavior while avoiding unrelated module dependencies.
//

BOOLEAN
TransparentHideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 1u,
                           L"TRANSPARENT_HIDE_DEBUGGER",
                           (ULONG_PTR)TransparentModeRequest,
                           0);
    return FALSE;
}

BOOLEAN
TransparentUnhideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 2u,
                           L"TRANSPARENT_UNHIDE_DEBUGGER",
                           (ULONG_PTR)TransparentModeRequest,
                           0);
    return TRUE;
}

VOID
TransparentCheckAndModifyCpuid(PGUEST_REGS Regs, INT32 CpuInfo[])
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 3u,
                           L"TRANSPARENT_CPUID",
                           (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0,
                           (CpuInfo != NULL) ? (ULONG_PTR)(ULONG)CpuInfo[0] : 0);
}

VOID
TransparentCheckAndTrapFlagAfterVmexit(VOID)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 4u, L"TRANSPARENT_TRAP_FLAG_AFTER_VMEXIT", 0, 0);
}

BOOLEAN
TransparentCheckAndModifyMsrRead(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 5u,
                           L"TRANSPARENT_MSR_READ",
                           (ULONG_PTR)TargetMsr,
                           (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0);
    return FALSE;
}

BOOLEAN
TransparentCheckAndModifyMsrWrite(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 6u,
                           L"TRANSPARENT_MSR_WRITE",
                           (ULONG_PTR)TargetMsr,
                           (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0);
    return FALSE;
}

VOID
TransparentHandleSystemCallHook(GUEST_REGS * Regs)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 7u,
                           L"TRANSPARENT_SYSCALL_HOOK",
                           (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0,
                           (Regs != NULL) ? (ULONG_PTR)Regs->rcx : 0);
}

VOID
TransparentCallbackHandleAfterSyscall(GUEST_REGS *                      Regs,
                                      UINT32                            ProcessId,
                                      UINT32                            ThreadId,
                                      UINT64                            Context,
                                      SYSCALL_CALLBACK_CONTEXT_PARAMS * Params)
{
    OwlyForwardAfterSyscallEvent(Regs, ProcessId, ThreadId, Context, Params);
}

BOOLEAN
DisassemblerShowInstructionsInVmxNonRootMode(PVOID Address, UINT32 Length, BOOLEAN Is32Bit)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 1u,
                           L"DISASM_SHOW_INSTR_NONROOT",
                           ((ULONG_PTR)Length << 32) | (ULONG_PTR)Is32Bit,
                           (ULONG_PTR)Address);
    return FALSE;
}

BOOLEAN
DisassemblerShowOneInstructionInVmxNonRootMode(PVOID Address, UINT64 ActualRip, BOOLEAN Is32Bit)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 2u,
                           L"DISASM_ONE_INSTR_NONROOT",
                           (ULONG_PTR)ActualRip,
                           ((ULONG_PTR)Is32Bit << 63) | ((ULONG_PTR)Address & 0x7fffffffffffffffull));
    return FALSE;
}

UINT32
DisassemblerShowOneInstructionInVmxRootMode(PVOID Address, BOOLEAN Is32Bit)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 3u,
                           L"DISASM_ONE_INSTR_ROOT",
                           (ULONG_PTR)Is32Bit,
                           (ULONG_PTR)Address);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngine(PVOID Address, BOOLEAN Is32Bit)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 4u,
                           L"DISASM_LENGTH_ENGINE",
                           (ULONG_PTR)Is32Bit,
                           (ULONG_PTR)Address);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngineInVmxRootOnTargetProcess(PVOID Address, BOOLEAN Is32Bit)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 5u,
                           L"DISASM_LENGTH_ENGINE_ROOT_TARGET",
                           (ULONG_PTR)Is32Bit,
                           (ULONG_PTR)Address);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngineByProcessId(PVOID Address, BOOLEAN Is32Bit, UINT32 ProcessId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DISASM_BASE + 6u,
                           L"DISASM_LENGTH_ENGINE_BY_PID",
                           ((ULONG_PTR)ProcessId << 32) | (ULONG_PTR)Is32Bit,
                           (ULONG_PTR)Address);
    return 1;
}
