#include "OwlyVmmBridge.h"
#include "Communication.h"
#include <ntstrsafe.h>

#if defined(_M_AMD64)
BOOLEAN
OwlyVmFuncInitVmmFallback(VMM_CALLBACKS * VmmCallbacks)
{
    UNREFERENCED_PARAMETER(VmmCallbacks);
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

static BOOLEAN g_OwlyVmmInitialized = FALSE;

#define OWLY_VMM_RAW_EVENT_BASE       0x1000u
#define OWLY_VMM_RAW_CALLBACK_BASE    0x1200u
#define OWLY_VMM_RAW_VMCALL_EVENT     (OWLY_VMM_RAW_CALLBACK_BASE + 1u)
#define OWLY_VMM_RAW_VMCALL_EXTRA     (OWLY_VMM_RAW_CALLBACK_BASE + 2u)
#define OWLY_VMM_RAW_NMI_EVENT        (OWLY_VMM_RAW_CALLBACK_BASE + 3u)
#define OWLY_VMM_RAW_PROTECTED_EVENT  (OWLY_VMM_RAW_CALLBACK_BASE + 4u)
#define OWLY_VMM_RAW_RESTORE_EPT      (OWLY_VMM_RAW_CALLBACK_BASE + 5u)
#define OWLY_VMM_RAW_UNHANDLED_EPT    (OWLY_VMM_RAW_CALLBACK_BASE + 6u)
#define OWLY_VMM_RAW_BP_EVENT         (OWLY_VMM_RAW_CALLBACK_BASE + 7u)
#define OWLY_VMM_RAW_DBG_BP_EVENT     (OWLY_VMM_RAW_CALLBACK_BASE + 8u)
#define OWLY_VMM_RAW_THREAD_INT_EVENT (OWLY_VMM_RAW_CALLBACK_BASE + 9u)
#define OWLY_VMM_RAW_CR3_EVENT        (OWLY_VMM_RAW_CALLBACK_BASE + 10u)
#define OWLY_VMM_RAW_REAPPLY_BP_EVENT (OWLY_VMM_RAW_CALLBACK_BASE + 11u)
#define OWLY_VMM_RAW_KD_NMI_EVENT     (OWLY_VMM_RAW_CALLBACK_BASE + 12u)
#define OWLY_VMM_RAW_MTF_EVENT        (OWLY_VMM_RAW_CALLBACK_BASE + 13u)
#define OWLY_VMM_RAW_PROC_THR_EVENT   (OWLY_VMM_RAW_CALLBACK_BASE + 14u)
#define OWLY_VMM_RAW_TRACING_EVENT    (OWLY_VMM_RAW_CALLBACK_BASE + 15u)
#define OWLY_VMM_RAW_HYPEREVADE_BASE  0x1300u
#define OWLY_VMM_RAW_DISASM_BASE      0x1400u

static VOID
OwlyForwardKernelEvent(_In_ ULONG RawEventType, _In_ PCWSTR EventName, _In_ ULONG_PTR Arg1, _In_ ULONG_PTR Arg2)
{
    (VOID)QueueHypervisorEvent(RawEventType, EventName, Arg1, Arg2);
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
        WCHAR     eventLabel[128] = {0};
        ULONG_PTR arg1            = (Regs != NULL) ? (ULONG_PTR)Regs->rax : 0;
        ULONG_PTR arg2            = (Context != NULL) ? (ULONG_PTR)Context : ((Regs != NULL) ? (ULONG_PTR)Regs->rcx : 0);
        ULONG     rawEventType    = OWLY_VMM_RAW_EVENT_BASE + (((ULONG)CallingStage & 0xffu) << 8) + ((ULONG)EventType & 0xffu);

        if (!NT_SUCCESS(RtlStringCchPrintfW(eventLabel,
                                            RTL_NUMBER_OF(eventLabel),
                                            L"%ws:%ws",
                                            OwlyVmmEventTypeName(EventType),
                                            OwlyStageName(CallingStage))))
        {
            RtlStringCchCopyW(eventLabel, RTL_NUMBER_OF(eventLabel), L"VMM_EVENT");
        }

        OwlyForwardKernelEvent(rawEventType, eventLabel, arg1, arg2);
    }

    return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_SUCCESSFUL_NO_INITIALIZED;
}

static VOID
OwlyVmmCallbackSetLastError(UINT32 LastError)
{
    UNREFERENCED_PARAMETER(LastError);
}

static BOOLEAN
OwlyVmmCallbackVmcallHandler(UINT32 CoreId,
                             UINT64 VmcallNumber,
                             UINT64 OptionalParam1,
                             UINT64 OptionalParam2,
                             UINT64 OptionalParam3)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_VMCALL_EVENT, L"VMMCALL", (ULONG_PTR)VmcallNumber, (ULONG_PTR)OptionalParam1);
    OwlyForwardKernelEvent(OWLY_VMM_RAW_VMCALL_EXTRA,
                           L"VMMCALL_EXTRA",
                           ((ULONG_PTR)CoreId << 32) | ((ULONG_PTR)OptionalParam2 & 0xffffffffull),
                           (ULONG_PTR)OptionalParam3);
    return FALSE;
}

static VOID
OwlyVmmCallbackNmiBroadcastRequestHandler(UINT32 CoreId, BOOLEAN IsOnVmxNmiHandler)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_NMI_EVENT, L"NMI_BROADCAST", (ULONG_PTR)CoreId, (ULONG_PTR)IsOnVmxNmiHandler);
}

static BOOLEAN
OwlyVmmCallbackQueryTerminateProtectedResource(UINT32                               CoreId,
                                               PROTECTED_HV_RESOURCES_TYPE          ResourceType,
                                               PVOID                                Context,
                                               PROTECTED_HV_RESOURCES_PASSING_OVERS PassOver)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_PROTECTED_EVENT,
                           L"QUERY_TERMINATE_PROTECTED_RESOURCE",
                           ((ULONG_PTR)CoreId << 32) | ((ULONG_PTR)ResourceType & 0xffffffffull),
                           (ULONG_PTR)Context);
    OwlyForwardKernelEvent(OWLY_VMM_RAW_PROTECTED_EVENT + 1u, L"QUERY_TERMINATE_PROTECTED_RESOURCE_PASSOVER", (ULONG_PTR)PassOver, 0);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackRestoreEptState(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_RESTORE_EPT, L"RESTORE_EPT_STATE", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackCheckUnhandledEptViolations(UINT32 CoreId, UINT64 ViolationQualification, UINT64 GuestPhysicalAddr)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_UNHANDLED_EPT, L"UNHANDLED_EPT_VIOLATION", (ULONG_PTR)ViolationQualification, (ULONG_PTR)GuestPhysicalAddr);
    OwlyForwardKernelEvent(OWLY_VMM_RAW_UNHANDLED_EPT + 1u, L"UNHANDLED_EPT_CORE", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleBreakpointException(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_BP_EVENT, L"DEBUG_BREAKPOINT_EXCEPTION", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleDebugBreakpointException(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_DBG_BP_EVENT, L"DEBUG_DEBUG_BREAKPOINT_EXCEPTION", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackCheckThreadInterception(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_THREAD_INT_EVENT, L"DEBUG_THREAD_INTERCEPTION", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static VOID
OwlyInterceptionCallbackTriggerCr3ProcessChange(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_CR3_EVENT, L"CR3_PROCESS_CHANGE", (ULONG_PTR)CoreId, 0);
}

static BOOLEAN
OwlyBreakpointCheckAndHandleReApplyingBreakpoint(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_REAPPLY_BP_EVENT, L"REAPPLY_BREAKPOINT", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyKdCheckAndHandleNmiCallback(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_KD_NMI_EVENT, L"KD_NMI_CALLBACK", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static VOID
OwlyVmmCallbackRegisteredMtfHandler(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_MTF_EVENT, L"REGISTERED_MTF_HANDLER", (ULONG_PTR)CoreId, 0);
}

static BOOLEAN
OwlyDebuggerCheckProcessOrThreadChange(UINT32 CoreId)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_PROC_THR_EVENT, L"DEBUGGER_PROCESS_OR_THREAD_CHANGE", (ULONG_PTR)CoreId, 0);
    return FALSE;
}

static BOOLEAN
OwlyKdQueryDebuggerThreadOrProcessTracingDetailsByCoreId(UINT32 CoreId, DEBUGGER_THREAD_PROCESS_TRACING TracingType)
{
    OwlyForwardKernelEvent(OWLY_VMM_RAW_TRACING_EVENT,
                           L"KD_QUERY_THREAD_OR_PROCESS_TRACING",
                           (ULONG_PTR)CoreId,
                           (ULONG_PTR)TracingType);
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

    initResult = VmFuncInitVmm(&callbacks);
    if (!initResult)
    {
        return STATUS_UNSUCCESSFUL;
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
    OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 8u,
                           L"TRANSPARENT_AFTER_SYSCALL",
                           ((ULONG_PTR)ProcessId << 32) | (ULONG_PTR)ThreadId,
                           (ULONG_PTR)Context);
    if (Params != NULL)
    {
        OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 9u,
                               L"TRANSPARENT_AFTER_SYSCALL_PARAMS12",
                               (ULONG_PTR)Params->OptionalParam1,
                               (ULONG_PTR)Params->OptionalParam2);
        OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 10u,
                               L"TRANSPARENT_AFTER_SYSCALL_PARAMS34",
                               (ULONG_PTR)Params->OptionalParam3,
                               (ULONG_PTR)Params->OptionalParam4);
    }
    if (Regs != NULL)
    {
        OwlyForwardKernelEvent(OWLY_VMM_RAW_HYPEREVADE_BASE + 11u,
                               L"TRANSPARENT_AFTER_SYSCALL_REGS",
                               (ULONG_PTR)Regs->rax,
                               (ULONG_PTR)Regs->rcx);
    }
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
