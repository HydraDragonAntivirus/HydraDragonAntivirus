#pragma once

namespace AMD
{
    enum class AMD_MSR : const unsigned int {
        MSR_PAT = 0x00000277, // Extension of the page tables in SVM (nested paging)
        MSR_EFER = 0xC0000080, // Etended Feature Enable Register
        MSR_STAR = 0xC0000081, // Legacy mode: address of a SYSCALL instruction
        MSR_LSTAR = 0xC0000081, // Long mode: address of a SYSCALL instruction
        MSR_CSTAR = 0xC0000081, // Compatibility mode: address of a SYSCALL instruction
        MSR_VM_CR = 0xC0010114, // Controls global aspects of SVM
        MSR_VM_HSAVE_PA = 0xC0010117, // Physical address of a 4KB block of memory where VMRUN saves host state, and from which #VMEXIT reloads host state
    };

    union EFER {
        unsigned long long Value;
        struct {
            unsigned long long SystemCallExtensions : 1; // 1 = enable SYSCALL/SYSRET support
            unsigned long long Reserved0 : 7;
            unsigned long long LongModeEnable : 1;
            unsigned long long Reserved1 : 1;
            unsigned long long LongModeActive : 1;
            unsigned long long NoExecuteEnable : 1;
            unsigned long long SecureVirtualMachineEnable : 1;
            unsigned long long LongModeSegmentLimitEnable : 1;
            unsigned long long FastFxsaveFxrstor : 1;
            unsigned long long TranslationCacheExtension : 1;
            unsigned long long Reserved2 : 48;
        } Bitmap;
    };
    static_assert(sizeof(EFER) == sizeof(unsigned long long), "Size of EFER != sizeof(unsigned long long)");

    union VM_CR {
        unsigned long long Value;
        struct {
            unsigned long long DPD : 1;
            unsigned long long R_INIT : 1;
            unsigned long long DIS_A20M : 1;
            unsigned long long LOCK : 1;
            unsigned long long SVMDIS : 1; // When set, EFER.SVME must be zero
            unsigned long long Reserved : 59;
        } Bitmap;
    };
    static_assert(sizeof(VM_CR) == sizeof(unsigned long long), "Size of VM_CR != sizeof(unsigned long long)");
}