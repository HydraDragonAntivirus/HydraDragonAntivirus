/**
 * @file VmxFootprints.c
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Try to hide VMX methods from anti-debugging and anti-hypervisor
 * @details
 * @version 0.14
 * @date 2025-06-08
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

/**
 * @brief Handle Cpuid Vmexits when the Transparent mode is enabled
 *
 * @param Regs The virtual processor's state of registers
 * @param CpuInfo The temporary logical processor registers
 *
 * @return VOID
 */
VOID
TransparentCheckAndModifyCpuid(PGUEST_REGS Regs, INT32 CpuInfo[])
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    TransparentInitializeOwlyEvent(&eventDetails, OWLY_VMM_RAW_HYPEREVADE_BASE + 3u, L"TRANSPARENT_CPUID");
    eventDetails.RawArgument1 = (Regs != NULL) ? Regs->rax : 0;
    eventDetails.RawArgument2 = (CpuInfo != NULL) ? (UINT64)(UINT32)CpuInfo[0] : 0;
    (VOID)TransparentReportOwlyEvent(&eventDetails);

    if (Regs->rax == CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS)
    {
        //
        // Unset the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] &= ~HYPERV_HYPERVISOR_PRESENT_BIT;
    }
    else if (Regs->rax == CPUID_HV_VENDOR_AND_MAX_FUNCTIONS || Regs->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // When transparent, all CPUID leaves in the 0x40000000+ range should contain no usable data
        //
        CpuInfo[0] = CpuInfo[1] = CpuInfo[2] = CpuInfo[3] = 0x40000000;
    }
}

/**
 * @brief Handle RDMSR VM exits when the Transparent mode is enabled
 *
 * @param Regs The virtual processor's state of registers
 * @param TargetMsr Target MSR in ECX register
 *
 * @return BOOLEAN Whether the emulation should be further continued or not
 */
BOOLEAN
TransparentCheckAndModifyMsrRead(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    TransparentInitializeOwlyEvent(&eventDetails,
                                   OWLY_VMM_RAW_HYPEREVADE_BASE + 5u,
                                   L"TRANSPARENT_MSR_READ");
    eventDetails.RawArgument1 = TargetMsr;
    eventDetails.RawArgument2 = (Regs != NULL) ? Regs->rax : 0;
    (VOID)TransparentReportOwlyEvent(&eventDetails);

    //
    // The MSR range between 40000000H and 400000F0H is reserved and usually used by hypervisors
    // when the guest operating system is Windows to indicate the OS identifier
    //
    // Sina: Needs more investigation since injecting #GP on Nested-virtualization environments
    // will crash the VM on Meteor Lake processors since the OS expects to use synthetic timers
    // (HV_REGISTER_STIMER0_CONFIG and HV_REGISTER_STIMER0_COUNT) to receive interrupts
    // Ref: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/timers
    //
    // if (TargetMsr >= RESERVED_MSR_RANGE_LOW && TargetMsr <= RESERVED_MSR_RANGE_HI)
    // {
    //     LogInfo("RDMSR attempts to write to a reserved MSR range. MSR: %x",
    //             TargetMsr);
    //
    //     g_Callbacks.EventInjectGeneralProtection();
    //     return TRUE; // Should not emulate further
    // }
    // else
    // {
    //     //
    //     // Not handled in the transparent-mode
    //     //
    //     return FALSE;
    // }

    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(TargetMsr);

    return FALSE;
}

/**
 * @brief Handle WRMSR VM exits when the Transparent mode is enabled
 *
 * @param Regs The virtual processor's state of registers
 * @param TargetMsr Target MSR in ECX register
 *
 * @return BOOLEAN Whether the emulation should be further continued or not
 */
BOOLEAN
TransparentCheckAndModifyMsrWrite(PGUEST_REGS Regs, UINT32 TargetMsr)
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    TransparentInitializeOwlyEvent(&eventDetails,
                                   OWLY_VMM_RAW_HYPEREVADE_BASE + 6u,
                                   L"TRANSPARENT_MSR_WRITE");
    eventDetails.RawArgument1 = TargetMsr;
    eventDetails.RawArgument2 = (Regs != NULL) ? Regs->rax : 0;
    (VOID)TransparentReportOwlyEvent(&eventDetails);

    // if (TargetMsr >= RESERVED_MSR_RANGE_LOW && TargetMsr <= RESERVED_MSR_RANGE_HI)
    // {
    //     //
    //     // The MSR range between 40000000H and 400000F0H is reserved and usually used by hypervisors
    //     // when the guest operating system is Windows to indicate the OS identifier
    //     //
    //
    //     LogInfo("WRMSR attempts to write to a reserved MSR range. MSR: %x, rax: %llx, rdx: %llx",
    //             TargetMsr,
    //             Regs->rax,
    //             Regs->rdx);
    //
    //     g_Callbacks.EventInjectGeneralProtection();
    //
    //     return TRUE; // Should not emulate further
    // }
    // else
    // {
    //     //
    //     // Not handled in the transparent-mode
    //     //
    //     return FALSE;
    // }

    UNREFERENCED_PARAMETER(Regs);
    UNREFERENCED_PARAMETER(TargetMsr);

    return FALSE;
}

/**
 * @brief Handle anti-debugging method of a trap flag after a VM exit
 *
 * @return VOID
 */
VOID
TransparentCheckAndTrapFlagAfterVmexit()
{
    OWLY_HYPERDBG_EVENT_DETAILS eventDetails;

    TransparentInitializeOwlyEvent(&eventDetails,
                                   OWLY_VMM_RAW_HYPEREVADE_BASE + 4u,
                                   L"TRANSPARENT_TRAP_FLAG_AFTER_VMEXIT");
    (VOID)TransparentReportOwlyEvent(&eventDetails);

    //
    // If RIP is incremented, then we emulate an instruction, and then
    // we need to handle the trap flag if it is set in a guest
    //
    g_Callbacks.HvHandleTrapFlag();
}
