#include "OwlyVmmBridge.h"

#if defined(_M_AMD64) && defined(OWLY_HYPERDBG_VMM_AVAILABLE)

//
// Force local definitions for transparency symbols, we provide local safe stubs.
//
#ifndef HYPERDBG_HYPEREVADE
#define HYPERDBG_HYPEREVADE
#endif

#include "pch.h"
#include "vmm/vmx/Hv.h"
#include "vmm/vmx/Vmx.h"

static BOOLEAN g_OwlyVmmInitialized = FALSE;

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
    UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(CallingStage);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Regs);

    if (PostEventRequired != NULL)
    {
        *PostEventRequired = FALSE;
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
    UNREFERENCED_PARAMETER(CoreId);
    UNREFERENCED_PARAMETER(VmcallNumber);
    UNREFERENCED_PARAMETER(OptionalParam1);
    UNREFERENCED_PARAMETER(OptionalParam2);
    UNREFERENCED_PARAMETER(OptionalParam3);
    return FALSE;
}

static VOID
OwlyVmmCallbackNmiBroadcastRequestHandler(UINT32 CoreId, BOOLEAN IsOnVmxNmiHandler)
{
    UNREFERENCED_PARAMETER(CoreId);
    UNREFERENCED_PARAMETER(IsOnVmxNmiHandler);
}

static BOOLEAN
OwlyVmmCallbackQueryTerminateProtectedResource(UINT32                               CoreId,
                                               PROTECTED_HV_RESOURCES_TYPE          ResourceType,
                                               PVOID                                Context,
                                               PROTECTED_HV_RESOURCES_PASSING_OVERS PassOver)
{
    UNREFERENCED_PARAMETER(CoreId);
    UNREFERENCED_PARAMETER(ResourceType);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(PassOver);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackRestoreEptState(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static BOOLEAN
OwlyVmmCallbackCheckUnhandledEptViolations(UINT32 CoreId, UINT64 ViolationQualification, UINT64 GuestPhysicalAddr)
{
    UNREFERENCED_PARAMETER(CoreId);
    UNREFERENCED_PARAMETER(ViolationQualification);
    UNREFERENCED_PARAMETER(GuestPhysicalAddr);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleBreakpointException(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackHandleDebugBreakpointException(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static BOOLEAN
OwlyDebuggingCallbackCheckThreadInterception(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static VOID
OwlyInterceptionCallbackTriggerCr3ProcessChange(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
}

static BOOLEAN
OwlyBreakpointCheckAndHandleReApplyingBreakpoint(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static BOOLEAN
OwlyKdCheckAndHandleNmiCallback(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static VOID
OwlyVmmCallbackRegisteredMtfHandler(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
}

static BOOLEAN
OwlyDebuggerCheckProcessOrThreadChange(UINT32 CoreId)
{
    UNREFERENCED_PARAMETER(CoreId);
    return FALSE;
}

static BOOLEAN
OwlyKdQueryDebuggerThreadOrProcessTracingDetailsByCoreId(UINT32 CoreId, DEBUGGER_THREAD_PROCESS_TRACING TracingType)
{
    UNREFERENCED_PARAMETER(CoreId);
    UNREFERENCED_PARAMETER(TracingType);
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

    initResult = HvInitVmm(&callbacks);
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

    VmxPerformTermination();
    g_OwlyVmmInitialized = FALSE;
}

//
// Stubs for optional components we intentionally keep disabled.
// They preserve VMM core behavior while avoiding unrelated module dependencies.
//

BOOLEAN
TransparentHideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    UNREFERENCED_PARAMETER(TransparentModeRequest);
    return FALSE;
}

BOOLEAN
TransparentUnhideDebuggerWrapper(DEBUGGER_HIDE_AND_TRANSPARENT_DEBUGGER_MODE * TransparentModeRequest)
{
    UNREFERENCED_PARAMETER(TransparentModeRequest);
    return TRUE;
}

VOID
TransparentCheckAndModifyCpuid(PGUEST_REGS Regs, INT32 CpuInfo[])
{
    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(CpuInfo);
}

VOID
TransparentCheckAndTrapFlagAfterVmexit(VOID)
{
}

BOOLEAN
TransparentCheckAndModifyMsrRead(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(TargetMsr);
    return FALSE;
}

BOOLEAN
TransparentCheckAndModifyMsrWrite(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(TargetMsr);
    return FALSE;
}

VOID
TransparentHandleSystemCallHook(GUEST_REGS * Regs)
{
    UNREFERENCED_PARAMETER(Regs);
}

VOID
TransparentCallbackHandleAfterSyscall(GUEST_REGS *                      Regs,
                                      UINT32                            ProcessId,
                                      UINT32                            ThreadId,
                                      UINT64                            Context,
                                      SYSCALL_CALLBACK_CONTEXT_PARAMS * Params)
{
    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Params);
}

BOOLEAN
DisassemblerShowInstructionsInVmxNonRootMode(PVOID Address, UINT32 Length, BOOLEAN Is32Bit)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Is32Bit);
    return FALSE;
}

BOOLEAN
DisassemblerShowOneInstructionInVmxNonRootMode(PVOID Address, UINT64 ActualRip, BOOLEAN Is32Bit)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(ActualRip);
    UNREFERENCED_PARAMETER(Is32Bit);
    return FALSE;
}

UINT32
DisassemblerShowOneInstructionInVmxRootMode(PVOID Address, BOOLEAN Is32Bit)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Is32Bit);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngine(PVOID Address, BOOLEAN Is32Bit)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Is32Bit);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngineInVmxRootOnTargetProcess(PVOID Address, BOOLEAN Is32Bit)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Is32Bit);
    return 1;
}

UINT32
DisassemblerLengthDisassembleEngineByProcessId(PVOID Address, BOOLEAN Is32Bit, UINT32 ProcessId)
{
    UNREFERENCED_PARAMETER(Address);
    UNREFERENCED_PARAMETER(Is32Bit);
    UNREFERENCED_PARAMETER(ProcessId);
    return 1;
}

#else

NTSTATUS
OwlyVmmInitialize(VOID)
{
    return STATUS_NOT_SUPPORTED;
}

VOID
OwlyVmmUninitialize(VOID)
{
}

#endif
