/**
 * @file Callback.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief VMM callback interface routines
 * @details
 *
 * @version 0.2
 * @date 2023-01-29
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

static VOID
VmmInitializeOwlyEvent(_Out_ POWLY_HYPERDBG_EVENT_DETAILS EventDetails, _In_ UINT32 RawEventType,
                       _In_opt_ const WCHAR * EventName)
{
    UINT32 currentProcessId = (UINT32)(ULONG_PTR)PsGetCurrentProcessId();

    RtlZeroMemory(EventDetails, sizeof(*EventDetails));
    EventDetails->RawEventType = RawEventType;
    EventDetails->SourceProcessId = currentProcessId;
    EventDetails->TargetProcessId = currentProcessId;
    EventDetails->ThreadId = (UINT32)(ULONG_PTR)PsGetCurrentThreadId();
    EventDetails->OperationStatus = STATUS_SUCCESS;
    EventDetails->EventName = EventName;
}

static const WCHAR *
VmmEventTypeName(VMM_EVENT_TYPE_ENUM EventType)
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

static const WCHAR *
VmmCallingStageName(VMM_CALLBACK_EVENT_CALLING_STAGE_TYPE CallingStage)
{
    switch (CallingStage)
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

BOOLEAN
VmmCallbackReportOwlyEvent(_In_ const OWLY_HYPERDBG_EVENT_DETAILS * EventDetails)
{
    if (EventDetails == NULL || g_Callbacks.ReportOwlyEvent == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.ReportOwlyEvent(EventDetails);
}

/**
 * @brief routines callback to trigger events
 * @param EventType
 * @param CallingStage
 * @param Context
 * @param PostEventRequired
 * @param Regs
 *
 * @return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_TYPE
 */
VMM_CALLBACK_TRIGGERING_EVENT_STATUS_TYPE
VmmCallbackTriggerEvents(VMM_EVENT_TYPE_ENUM                   EventType,
                         VMM_CALLBACK_EVENT_CALLING_STAGE_TYPE CallingStage,
                         PVOID                                 Context,
                         BOOLEAN *                             PostEventRequired,
                         GUEST_REGS *                          Regs)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;
    WCHAR                       eventLabel[128] = {0};

    VmmInitializeOwlyEvent(&eventDetails,
                           OWLY_VMM_RAW_EVENT_BASE + (((UINT32)CallingStage & 0xffu) << 8) +
                               ((UINT32)EventType & 0xffu),
                           NULL);
    eventDetails.Context = (UINT64)(ULONG_PTR)Context;
    eventDetails.RawArgument1 = (Regs != NULL) ? Regs->rax : 0;
    eventDetails.RawArgument2 = (Context != NULL) ? (UINT64)(ULONG_PTR)Context : ((Regs != NULL) ? Regs->rcx : 0);
    eventDetails.RawArgument3 = (Regs != NULL) ? Regs->rdx : 0;
    eventDetails.RawArgument4 = (Regs != NULL) ? Regs->r8 : 0;
    if (Regs != NULL &&
        (EventType == SYSCALL_HOOK_EFER_SYSCALL || EventType == SYSCALL_HOOK_EFER_SYSRET) &&
        CallingStage == VMM_CALLBACK_CALLING_STAGE_POST_EVENT_EMULATION)
    {
        eventDetails.OperationStatus = (INT32)Regs->rax;
    }

    if (NT_SUCCESS(RtlStringCchPrintfW(eventLabel,
                                       RTL_NUMBER_OF(eventLabel),
                                       L"%ws:%ws",
                                       VmmEventTypeName(EventType),
                                       VmmCallingStageName(CallingStage))))
    {
        eventDetails.EventName = eventLabel;
    }
    else
    {
        eventDetails.EventName = L"VMM_EVENT";
    }

    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (PostEventRequired != NULL && g_Callbacks.ReportOwlyEvent != NULL)
    {
        *PostEventRequired = FALSE;
    }

    if (g_Callbacks.ReportOwlyEvent != NULL || g_Callbacks.VmmCallbackTriggerEvents == NULL)
    {
        return VMM_CALLBACK_TRIGGERING_EVENT_STATUS_SUCCESSFUL_NO_INITIALIZED;
    }

    return g_Callbacks.VmmCallbackTriggerEvents(EventType, CallingStage, Context, PostEventRequired, Regs);
}

/**
 * @brief routine callback to set last error
 * @param LastError
 *
 * @return VOID
 */
VOID
VmmCallbackSetLastError(UINT32 LastError)
{
    if (g_Callbacks.VmmCallbackSetLastError == NULL)
    {
        //
        // Ignore setting the last error
        //
        return;
    }

    g_Callbacks.VmmCallbackSetLastError(LastError);
}

/**
 * @brief routine callback to handle external VMCALLs
 *
 * @param CoreId
 * @param VmcallNumber
 * @param OptionalParam1
 * @param OptionalParam2
 * @param OptionalParam3
 *
 * @return BOOLEAN
 */
BOOLEAN
VmmCallbackVmcallHandler(UINT32 CoreId,
                         UINT64 VmcallNumber,
                         UINT64 OptionalParam1,
                         UINT64 OptionalParam2,
                         UINT64 OptionalParam3)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_VMCALL_EVENT, L"VMMCALL");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = VmcallNumber;
    eventDetails.RawArgument2 = OptionalParam1;
    eventDetails.RawArgument3 = OptionalParam2;
    eventDetails.RawArgument4 = OptionalParam3;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL || g_Callbacks.VmmCallbackVmcallHandler == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.VmmCallbackVmcallHandler(CoreId, VmcallNumber, OptionalParam1, OptionalParam2, OptionalParam3);
}

/**
 * @brief routine callback to handle registered MTF
 *
 * @param CoreId
 *
 * @return VOID
 */
VOID
VmmCallbackRegisteredMtfHandler(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_MTF_EVENT, L"REGISTERED_MTF_HANDLER");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL || g_Callbacks.VmmCallbackRegisteredMtfHandler == NULL)
    {
        return;
    }

    g_Callbacks.VmmCallbackRegisteredMtfHandler(CoreId);
}

/**
 * @brief routine callback to handle NMI requests
 *
 * @param CoreId
 * @param IsOnVmxNmiHandler
 *
 * @return VOID
 */
VOID
VmmCallbackNmiBroadcastRequestHandler(UINT32 CoreId, BOOLEAN IsOnVmxNmiHandler)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_NMI_EVENT, L"NMI_BROADCAST");
    eventDetails.CoreId = CoreId;
    eventDetails.RawArgument1 = IsOnVmxNmiHandler ? 1 : 0;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL || g_Callbacks.VmmCallbackNmiBroadcastRequestHandler == NULL)
    {
        return;
    }

    g_Callbacks.VmmCallbackNmiBroadcastRequestHandler(CoreId, IsOnVmxNmiHandler);
}

/**
 * @brief routine callback to query for termination of protected resources
 *
 * @param CoreId
 * @param ResourceType
 * @param Context
 * @param PassOver
 *
 * @return BOOLEAN
 */
BOOLEAN
VmmCallbackQueryTerminateProtectedResource(UINT32                               CoreId,
                                           PROTECTED_HV_RESOURCES_TYPE          ResourceType,
                                           PVOID                                Context,
                                           PROTECTED_HV_RESOURCES_PASSING_OVERS PassOver)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_PROTECTED_EVENT, L"QUERY_TERMINATE_PROTECTED_RESOURCE");
    eventDetails.CoreId = CoreId;
    eventDetails.MemoryAddress = (UINT64)(ULONG_PTR)Context;
    eventDetails.RawArgument1 = (UINT64)ResourceType;
    eventDetails.RawArgument2 = (UINT64)PassOver;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.VmmCallbackQueryTerminateProtectedResource == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.VmmCallbackQueryTerminateProtectedResource(CoreId, ResourceType, Context, PassOver);
}

/**
 * @brief routine callback to restore EPT state
 * @param CoreId
 *
 * @return BOOLEAN
 */
BOOLEAN
VmmCallbackRestoreEptState(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_RESTORE_EPT, L"RESTORE_EPT_STATE");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL || g_Callbacks.VmmCallbackRestoreEptState == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.VmmCallbackRestoreEptState(CoreId);
}

/**
 * @brief routine callback to handle unhandled EPT violations
 * @param CoreId
 * @param ViolationQualification
 * @param GuestPhysicalAddr
 *
 * @return BOOLEAN
 */
BOOLEAN
VmmCallbackUnhandledEptViolation(UINT32 CoreId,
                                 UINT64 ViolationQualification,
                                 UINT64 GuestPhysicalAddr)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_UNHANDLED_EPT, L"UNHANDLED_EPT_VIOLATION");
    eventDetails.CoreId = CoreId;
    eventDetails.MemoryAddress = GuestPhysicalAddr;
    eventDetails.RawArgument1 = ViolationQualification;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.VmmCallbackCheckUnhandledEptViolations == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.VmmCallbackCheckUnhandledEptViolations(CoreId, ViolationQualification, GuestPhysicalAddr);
}

/**
 * @brief routine callback to handle breakpoint exception
 *
 * @param CoreId
 *
 * @return BOOLEAN
 */
BOOLEAN
DebuggingCallbackHandleBreakpointException(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_BP_EVENT, L"DEBUG_BREAKPOINT_EXCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.DebuggingCallbackHandleBreakpointException == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.DebuggingCallbackHandleBreakpointException(CoreId);
}

/**
 * @brief routine callback to handle debug breakpoint exception
 *
 * @param CoreId
 *
 * @return BOOLEAN
 */
BOOLEAN
DebuggingCallbackHandleDebugBreakpointException(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails,
                           OWLY_VMM_RAW_DBG_BP_EVENT,
                           L"DEBUG_DEBUG_BREAKPOINT_EXCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.DebuggingCallbackHandleDebugBreakpointException == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.DebuggingCallbackHandleDebugBreakpointException(CoreId);
}

/**
 * @brief routine callback to handle thread interception
 *
 * @param CoreId
 *
 * @return BOOLEAN
 */
BOOLEAN
DebuggingCallbackCheckThreadInterception(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails,
                           OWLY_VMM_RAW_THREAD_INT_EVENT,
                           L"DEBUG_THREAD_INTERCEPTION");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.DebuggingCallbackCheckThreadInterception == NULL)
    {
        return FALSE;
    }

    return g_Callbacks.DebuggingCallbackCheckThreadInterception(CoreId);
}

/**
 * @brief routine callback to handle cr3 process change
 *
 * @param CoreId
 *
 * @return VOID
 */
VOID
InterceptionCallbackTriggerCr3ProcessChange(UINT32 CoreId)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    VmmInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_CR3_EVENT, L"CR3_PROCESS_CHANGE");
    eventDetails.CoreId = CoreId;
    (VOID)VmmCallbackReportOwlyEvent(&eventDetails);

    if (g_Callbacks.ReportOwlyEvent != NULL ||
        g_Callbacks.InterceptionCallbackTriggerCr3ProcessChange == NULL)
    {
        return;
    }

    g_Callbacks.InterceptionCallbackTriggerCr3ProcessChange(CoreId);
}
