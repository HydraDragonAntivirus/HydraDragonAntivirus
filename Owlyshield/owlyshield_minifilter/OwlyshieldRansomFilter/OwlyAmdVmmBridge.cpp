#include "OwlyAmdVmmBridge.h"
#include "Communication.h"

#include "SDK/headers/ErrorCodes.h"
#include "SDK/modules/OwlyEvent.h"

#include "Debugger/Driver/GuestContext.hpp"
#include "HyperVisor/HyperVisor.hpp"

#include <intrin.h>

extern "C" void SvmVmmRun(_In_ void* InitialVmmStackPointer);

namespace
{
    HyperVisorSvm g_OwlyAmdHyperVisor = {};
    bool          g_OwlyAmdInitialized = false;

    constexpr ULONG kOwlyAmdVmexitOffsetCpuid = static_cast<ULONG>(SVM::SVM_EXIT_CODE::VMEXIT_CPUID);
    constexpr ULONG kOwlyAmdVmexitOffsetVmrun = static_cast<ULONG>(SVM::SVM_EXIT_CODE::VMEXIT_VMRUN);

    static CpuVendor
    OwlyAmdQueryCpuVendor()
    {
        CPUID_REGS regs = {};

        __cpuid(regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
        if (regs.Regs.Ebx == AmdEnc::AEbx && regs.Regs.Edx == AmdEnc::AEdx &&
            regs.Regs.Ecx == AmdEnc::AEcx)
        {
            return CpuVendor::CpuAmd;
        }

        if (regs.Regs.Ebx == IntelEnc::IEbx && regs.Regs.Edx == IntelEnc::IEdx &&
            regs.Regs.Ecx == IntelEnc::IEcx)
        {
            return CpuVendor::CpuIntel;
        }

        return CpuVendor::CpuUnknown;
    }

    static UINT32
    OwlyAmdQuerySupportError()
    {
        CPUID_REGS regs = {};

        if (KD_DEBUGGER_ENABLED != FALSE && KD_DEBUGGER_NOT_PRESENT == FALSE)
        {
            return DEBUGGER_ERROR_SVM_INITIALIZATION_STAGE_FAILED;
        }

        if (OwlyAmdQueryCpuVendor() != CpuVendor::CpuAmd)
        {
            return DEBUGGER_ERROR_SVM_UNSUPPORTED_CPU_VENDOR;
        }

        __cpuid(regs.Raw, CPUID::Generic::CPUID_FEATURE_INFORMATION);
        if ((regs.Regs.Ecx & (1u << 31)) != 0)
        {
            return DEBUGGER_ERROR_SVM_INITIALIZATION_STAGE_FAILED;
        }

        __cpuid(regs.Raw, CPUID::AMD::CPUID_EXTENDED_FEATURE_INFORMATION);
        if ((regs.Regs.Ecx & (1u << 2)) == 0)
        {
            return DEBUGGER_ERROR_SVM_NOT_SUPPORTED_BY_PROCESSOR;
        }

        __cpuid(regs.Raw, CPUID::AMD::CPUID_SVM_FEATURES);
        if ((regs.Regs.Edx & 0x1u) == 0)
        {
            return DEBUGGER_ERROR_SVM_NPT_NOT_SUPPORTED;
        }

        AMD::VM_CR vmCr = {};
        vmCr.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_VM_CR));
        if (vmCr.Bitmap.SVMDIS)
        {
            return DEBUGGER_ERROR_SVM_DISABLED_IN_BIOS;
        }

        return DEBUGGER_OPERATION_WAS_SUCCESSFUL;
    }

    static VOID
    OwlyAmdInitializeEvent(_Out_ POWLY_HV_EVENT_DETAILS EventDetails,
                           _In_ ULONG                  RawEventType,
                           _In_opt_ PCWSTR             EventName)
    {
        RtlZeroMemory(EventDetails, sizeof(*EventDetails));
        EventDetails->RawEventType = RawEventType;
        EventDetails->SourceProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
        EventDetails->TargetProcessId = EventDetails->SourceProcessId;
        EventDetails->OperationStatus = STATUS_SUCCESS;
        EventDetails->EventName = EventName;
        EventDetails->CoreId = KeGetCurrentProcessorNumberEx(NULL);
        EventDetails->ThreadId = (ULONG)(ULONG_PTR)PsGetCurrentThreadId();
    }

    static VOID
    OwlyAmdQueueVmexitEvent(_In_ ULONG                 RawEventType,
                            _In_opt_ PCWSTR            EventName,
                            _In_ SVM::PRIVATE_VM_DATA* Private,
                            _In_ GuestContext*         Context,
                            _In_ ULONG_PTR             Arg1,
                            _In_ ULONG_PTR             Arg2,
                            _In_ ULONG_PTR             Arg3,
                            _In_ ULONG_PTR             Arg4,
                            _In_ NTSTATUS              OperationStatus)
    {
        OWLY_HV_EVENT_DETAILS eventDetails = {};

        OwlyAmdInitializeEvent(&eventDetails, RawEventType, EventName);
        eventDetails.Context = Private != nullptr ? Private->Guest.StateSaveArea.Rip : 0;
        eventDetails.RawArgument1 = Arg1;
        eventDetails.RawArgument2 = Arg2;
        eventDetails.RawArgument3 = Arg3;
        eventDetails.RawArgument4 = Arg4;
        eventDetails.OperationStatus = OperationStatus;
        eventDetails.MemoryAddress =
            reinterpret_cast<PVOID>(Private != nullptr ? Private->Guest.StateSaveArea.Rip : 0);
        eventDetails.ThreadHandle = reinterpret_cast<HANDLE>(
            Context != nullptr ? static_cast<ULONG_PTR>(Context->Rcx) : 0);

        (void)QueueHypervisorEvent(&eventDetails);
    }

    static VOID
    OwlyAmdInjectGeneralProtection(_Inout_ SVM::VMCB* Guest)
    {
        SVM::EVENTINJ event = {};

        event.Bitmap.Vector = INTERRUPT_VECTOR::GeneralProtection;
        event.Bitmap.Type = EXCEPTION_VECTOR::FaultTrapException;
        event.Bitmap.ErrorCodeValid = TRUE;
        event.Bitmap.Valid = TRUE;
        event.Bitmap.ErrorCode = 0;
        Guest->ControlArea.EventInjection = event.Value;
    }

    static VOID
    OwlyAmdHideHypervisorPresence(_In_ UINT32 Function, _Inout_ CPUID_REGS* Regs)
    {
        if (Regs == nullptr)
        {
            return;
        }

        if (Function == CPUID::Generic::CPUID_FEATURE_INFORMATION)
        {
            Regs->Regs.Ecx &= ~(1u << 31);
        }
    }

    static SVM::PRIVATE_VM_DATA*
    OwlyAmdInterceptions(_Inout_ SVM::PRIVATE_VM_DATA* Private)
    {
        if (Private == nullptr)
        {
            return nullptr;
        }

        Private->Guest.ControlArea.InterceptCpuid = TRUE;
        Private->Guest.ControlArea.InterceptVmrun = TRUE;
        return Private;
    }
}

extern "C" SVM::VMM_STATUS
SvmVmexitHandler(_In_ SVM::PRIVATE_VM_DATA* Private, _In_ GuestContext* Context)
{
    SVM::VMM_STATUS status = SVM::VMM_STATUS::VMM_CONTINUE;

    if (Private == nullptr || Context == nullptr)
    {
        return SVM::VMM_STATUS::VMM_SHUTDOWN;
    }

    Context->Rax = Private->Guest.StateSaveArea.Rax;

    switch (Private->Guest.ControlArea.ExitCode)
    {
    case SVM::SVM_EXIT_CODE::VMEXIT_CPUID:
    {
        CPUID_REGS regs = {};
        const UINT32 function = static_cast<UINT32>(Context->Rax);
        const UINT32 subleaf = static_cast<UINT32>(Context->Rcx);

        __cpuidex(regs.Raw, static_cast<int>(function), static_cast<int>(subleaf));
        OwlyAmdHideHypervisorPresence(function, &regs);

        OwlyAmdQueueVmexitEvent(OWLY_VMM_RAW_EVENT_BASE + kOwlyAmdVmexitOffsetCpuid,
                                L"SVM_CPUID",
                                Private,
                                Context,
                                function,
                                subleaf,
                                regs.Regs.Eax,
                                regs.Regs.Ebx,
                                STATUS_SUCCESS);

        if (function == CPUID_VMM_SHUTDOWN)
        {
            status = SVM::VMM_STATUS::VMM_SHUTDOWN;
        }
        else
        {
            Context->Rax = regs.Regs.Eax;
            Context->Rbx = regs.Regs.Ebx;
            Context->Rcx = regs.Regs.Ecx;
            Context->Rdx = regs.Regs.Edx;
        }
        break;
    }
    case SVM::SVM_EXIT_CODE::VMEXIT_VMRUN:
        OwlyAmdQueueVmexitEvent(OWLY_VMM_RAW_EVENT_BASE + kOwlyAmdVmexitOffsetVmrun,
                                L"SVM_VMRUN",
                                Private,
                                Context,
                                static_cast<ULONG_PTR>(Context->Rax),
                                static_cast<ULONG_PTR>(Context->Rcx),
                                0,
                                0,
                                STATUS_PRIVILEGED_INSTRUCTION);
        OwlyAmdInjectGeneralProtection(&Private->Guest);
        break;
    default:
        OwlyAmdQueueVmexitEvent(OWLY_VMM_RAW_EVENT_BASE +
                                    static_cast<ULONG>(Private->Guest.ControlArea.ExitCode & 0xFFu),
                                L"SVM_VMEXIT",
                                Private,
                                Context,
                                static_cast<ULONG_PTR>(Private->Guest.ControlArea.ExitCode),
                                static_cast<ULONG_PTR>(Private->Guest.ControlArea.ExitInfo1),
                                static_cast<ULONG_PTR>(Private->Guest.ControlArea.ExitInfo2),
                                0,
                                STATUS_UNSUCCESSFUL);
        break;
    }

    if (status == SVM::VMM_STATUS::VMM_SHUTDOWN)
    {
        Context->Rax = reinterpret_cast<UINT64>(Private) & MAXUINT32;
        Context->Rbx = Private->Guest.ControlArea.NextRip;
        Context->Rcx = Private->Guest.StateSaveArea.Rsp;
        Context->Rdx = reinterpret_cast<UINT64>(Private) >> 32;

        __svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.GuestVmcbPa));

        _disable();
        __svm_stgi();

        AMD::EFER efer = {};
        efer.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER));
        efer.Bitmap.SecureVirtualMachineEnable = FALSE;
        __writemsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER), efer.Value);

        __writeeflags(Private->Guest.StateSaveArea.Rflags.Value);
    }

    Private->Guest.StateSaveArea.Rax = Context->Rax;
    if (Private->Guest.ControlArea.NextRip != 0)
    {
        Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;
    }

    return status;
}

BOOLEAN
OwlyAmdVmmShouldUseBackend(VOID)
{
    return OwlyAmdQueryCpuVendor() == CpuVendor::CpuAmd;
}

NTSTATUS
OwlyAmdVmmInitialize(_Out_opt_ UINT32* LastError)
{
    UINT32 supportError = DEBUGGER_OPERATION_WAS_SUCCESSFUL;

    if (LastError != nullptr)
    {
        *LastError = DEBUGGER_OPERATION_WAS_SUCCESSFUL;
    }

    if (g_OwlyAmdInitialized)
    {
        return STATUS_SUCCESS;
    }

    supportError = OwlyAmdQuerySupportError();
    if (supportError != DEBUGGER_OPERATION_WAS_SUCCESSFUL)
    {
        if (LastError != nullptr)
        {
            *LastError = supportError;
        }
        return STATUS_NOT_SUPPORTED;
    }

    g_OwlyAmdHyperVisor.PInterceptions = reinterpret_cast<PVOID>(&OwlyAmdInterceptions);
    g_OwlyAmdHyperVisor.PSvmVmmRun = reinterpret_cast<PVOID>(&SvmVmmRun);

    if (!g_OwlyAmdHyperVisor.IsSvmSupported())
    {
        if (LastError != nullptr)
        {
            *LastError = DEBUGGER_ERROR_SVM_INITIALIZATION_STAGE_FAILED;
        }
        return STATUS_NOT_SUPPORTED;
    }

    if (!g_OwlyAmdHyperVisor.VirtualizeAllProcessors())
    {
        if (LastError != nullptr)
        {
            *LastError = DEBUGGER_ERROR_SVM_INITIALIZATION_STAGE_FAILED;
        }
        return STATUS_UNSUCCESSFUL;
    }

    g_OwlyAmdInitialized = true;
    return STATUS_SUCCESS;
}

VOID
OwlyAmdVmmUninitialize(VOID)
{
    if (!g_OwlyAmdInitialized)
    {
        return;
    }

    (void)g_OwlyAmdHyperVisor.DevirtualizeAllProcessors();
    g_OwlyAmdInitialized = false;
}
