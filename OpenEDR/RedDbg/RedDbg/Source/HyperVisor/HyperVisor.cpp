#include "HyperVisor/HyperVisor.hpp"

PVOID HyperVisorSvm::AllocPhys(
    _In_ SIZE_T Size, 
    _In_ MEMORY_CACHING_TYPE CachingType = MmCached,
    _In_ ULONG MaxPhysBits = 0)
{
    PVOID64 HighestAcceptableAddress = MaxPhysBits
        ? reinterpret_cast<PVOID64>((1ULL << MaxPhysBits) - 1)
        : reinterpret_cast<PVOID64>((1ULL << 48) - 1);

    PVOID Memory = PhysicalMemory::AllocPhysicalMemorySpecifyCache(
        0,
        HighestAcceptableAddress,
        0,
        Size,
        CachingType
    );
    if (Memory) RtlSecureZeroMemory(Memory, Size);
    return Memory;
}

CpuVendor HyperVisorSvm::GetCpuVendor()
{
    static CpuVendor CpuVendor; CPUID_REGS Regs;
    __cpuid(Regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
    if (Regs.Regs.Ebx == IntelEnc::IEbx && Regs.Regs.Edx == IntelEnc::IEdx && Regs.Regs.Ecx == IntelEnc::IEcx) { CpuVendor = CpuVendor::CpuIntel; }
    else if (Regs.Regs.Ebx == AmdEnc::AEbx && Regs.Regs.Edx == AmdEnc::AEdx && Regs.Regs.Ecx == AmdEnc::AEcx) { CpuVendor = CpuVendor::CpuAmd; }
    else { CpuVendor = CpuVendor::CpuUnknown; }
    return CpuVendor;
}

bool HyperVisorSvm::DevirtualizeProcessor(
    __out PVOID &PrivateVmData)
{
    PrivateVmData = NULL; CPUID_REGS Regs = {};
    __cpuid(Regs.Raw, CPUID_VMM_SHUTDOWN);
    if (Regs.Regs.Ecx != CPUID_VMM_SHUTDOWN) { return false; }// Processor not virtualized!

    // Processor is devirtualized now:
    //  Info.Eax -> PRIVATE_VM_DATA* Private LOW
    //  Info.Ebx -> Vmexit RIP
    //  Info.Ecx -> VMEXIT_SIGNATURE
    //  Info.Edx -> PRIVATE_VM_DATA* Private HIGH

    PrivateVmData = reinterpret_cast<void*>(
        (static_cast<UINT64>(Regs.Regs.Edx) << 32u) |
        (static_cast<UINT64>(Regs.Regs.Eax))
        );

    return true;
}

bool HyperVisorSvm::DevirtualizeAllProcessors()
{
    ULONG ProcessorsCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    PVOID* PrivateVmDataArray = VirtualMemory::AllocArray<PVOID>(ProcessorsCount);

    struct Callable {
        static ULONG_PTR BroadCast(void* Arg, void* Class)
        {
            PVOID* PrivateVmDataArray = reinterpret_cast<PVOID*>(Arg);
            ULONG CurrentProcessor = KeGetCurrentProcessorNumber();
            PVOID PrivateVmData = NULL;
            bool Status = static_cast<HyperVisorSvm*>(Class)->DevirtualizeProcessor(OUT PrivateVmData);
            PrivateVmDataArray[CurrentProcessor] = PrivateVmData; // Data buffer to free
            return static_cast<ULONG_PTR>(Status);
        }
    };

    KeIpiGenericCall(reinterpret_cast<PKIPI_BROADCAST_WORKER>(Callable::BroadCast), reinterpret_cast<ULONG_PTR>(PrivateVmDataArray));
    
    for (ULONG i = 0; i < ProcessorsCount; ++i)
    {
        if (PrivateVmDataArray[i])
        {
            PhysicalMemory::FreePhysicalMemory(PrivateVmDataArray[i]);
        }
    }

    VirtualMemory::FreePoolMemory(PrivateVmDataArray);

    g_IsVirtualized = false;

    return true;
}

void HyperVisorSvm::BuildNestedPagingTables(
    __out SVM::NESTED_PAGING_TABLES* Npt)
{
    using namespace PhysicalMemory;

    if (!Npt) return;

    // One PML4 entry maps 512 GB; SVM::NPT_PML4E_COUNT of them are identity-mapped
    // with 2 MB pages (see SvBuildNestedPageTables in Source/Deps/SimpleSvm):
    for (unsigned int k = 0; k < SVM::NPT_PML4E_COUNT; ++k)
    {
        Npt->Pml4e[k].x64.Page2Mb.P = TRUE; // Present
        Npt->Pml4e[k].x64.Page2Mb.RW = TRUE; // Writeable
        Npt->Pml4e[k].x64.Page2Mb.US = TRUE; // User
        Npt->Pml4e[k].x64.Page2Mb.PDP = PAGE_TO_PFN(reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pdpe[k][0])));

        for (int i = 0; i < _ARRAYSIZE(Npt->Pdpe[k]); ++i)
        {
            Npt->Pdpe[k][i].x64.NonPageSize.Page2Mb.P = TRUE; // Present
            Npt->Pdpe[k][i].x64.NonPageSize.Page2Mb.RW = TRUE; // Writeable
            Npt->Pdpe[k][i].x64.NonPageSize.Page2Mb.US = TRUE; // User
            Npt->Pdpe[k][i].x64.NonPageSize.Page2Mb.PD = PAGE_TO_PFN(reinterpret_cast<UINT64>(GetPhysicalAddress(&Npt->Pde[k][i][0])));

            for (int j = 0; j < _ARRAYSIZE(Npt->Pde[k][i]); ++j)
            {
                Npt->Pde[k][i][j].x64.Page2Mb.P = TRUE; // Present
                Npt->Pde[k][i][j].x64.Page2Mb.RW = TRUE; // Writeable
                Npt->Pde[k][i][j].x64.Page2Mb.US = TRUE; // User
                Npt->Pde[k][i][j].x64.Page2Mb.PS = TRUE; // Large page
                Npt->Pde[k][i][j].x64.Page2Mb.PhysicalPageFrameNumber =
                    (static_cast<unsigned long long>(k) * _ARRAYSIZE(Npt->Pdpe[k]) + i) * _ARRAYSIZE(Npt->Pde[k][i]) + j;
            }
        }
    }
}

// Builds the MSR permissions map so that only a write to EFER causes #VMEXIT
// (ported from SvBuildMsrPermissionsMap in Source/Deps/SimpleSvm). Without the
// bit below the VMEXIT_MSR handler never sees the EFER write and the guest is
// able to clear EFER.SVME while it is running:
void HyperVisorSvm::BuildMsrPermissionsMap(
    __out SVM::MSRPM* Msrpm)
{
    constexpr unsigned int BitsPerMsr = 2; // Bit 0 - RDMSR intercept, bit 1 - WRMSR intercept
    constexpr unsigned int SecondMsrRangeBase = 0xC0000000; // Covered by the Msrpm1 vector
    constexpr unsigned int BitsPerByte = 8;

    if (!Msrpm) return;

    // The map comes zeroed from AllocPhys (no intercepts); bits that the
    // Interceptions callback could have set are preserved.
    const unsigned int Offset = (static_cast<unsigned int>(AMD::AMD_MSR::MSR_EFER) - SecondMsrRangeBase) * BitsPerMsr + 1;
    Msrpm->Vectors.Msrpm1[Offset / BitsPerByte] |= static_cast<unsigned char>(1u << (Offset % BitsPerByte));
}

void HyperVisorSvm::FillVmcbSegmentAttributes(
    _Out_ SVM::VMCB_STATE_SAVE_AREA::VMCB_SEGMENT_ATTRIBUTE* Attribute,
    _In_ const SEGMENT_SELECTOR* Selector,
    _In_ const DESCRIPTOR_TABLE_REGISTER_LONG* Gdtr
) {
    auto Gdt = reinterpret_cast<SEGMENT_DESCRIPTOR_LONG*>(Gdtr->BaseAddress);
    auto Descriptor = reinterpret_cast<USER_SEGMENT_DESCRIPTOR_LONG*>(&Gdt[Selector->Bitmap.SelectorIndex]);

    Attribute->Value = 0;
    Attribute->Bitmap.Type = Descriptor->Generic.Type;
    Attribute->Bitmap.System = Descriptor->Generic.System;
    Attribute->Bitmap.Dpl = Descriptor->Generic.Dpl;
    Attribute->Bitmap.Present = Descriptor->Generic.Present;
    Attribute->Bitmap.Available = Descriptor->Generic.Available;
    Attribute->Bitmap.LongMode = Descriptor->Generic.LongMode;
    Attribute->Bitmap.DefaultOperandSize = Descriptor->Generic.DefaultOperandSize;
    Attribute->Bitmap.Granularity = Descriptor->Generic.Granularity;
}

bool HyperVisorSvm::VirtualizeProcessor(unsigned int ProcessorNumber)
{
    static volatile bool IsVirtualized = false;
    IsVirtualized = false;
    CONTEXT Context = {};
    Context.ContextFlags = CONTEXT_ALL;
    RtlCaptureContext(&Context);

    if (IsVirtualized) { return true; }

    AMD::EFER Efer = {};
    Efer.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER));
    Efer.Bitmap.SecureVirtualMachineEnable = TRUE;
    __writemsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER), Efer.Value);

    SVM::PRIVATE_VM_DATA* Private = reinterpret_cast<SVM::PRIVATE_VM_DATA*>(AllocPhys(sizeof(*Private)));
    if (!Private) { return false; } // Insufficient memory
    if (ProcessorNumber < 64) {
        g_ProcessorVmData[ProcessorNumber] = Private;
    }

    // Callback
    Interceptions = reinterpret_cast<_Interceptions>(PInterceptions);
    Private = Interceptions(Private);

    // Guest Address Space ID:
    Private->Guest.ControlArea.GuestAsid = 1;

    // Nested paging:
    BuildNestedPagingTables(&Private->Npt);
    Private->Guest.ControlArea.NpEnable = TRUE;
    Private->Guest.ControlArea.NestedPageTableCr3 = reinterpret_cast<UINT64>(PhysicalMemory::GetPhysicalAddress(&Private->Npt.Pml4e));

    // MSR permissions map (intercepts the EFER write only):
    BuildMsrPermissionsMap(&Private->Msrpm);

    DESCRIPTOR_TABLE_REGISTER_LONG Gdtr = {}, Idtr = {}; _sgdt(&Gdtr); __sidt(&Idtr);

    // Setting up the initial guest state to the current system state:
    Private->Guest.StateSaveArea.Gdtr.Base = Gdtr.BaseAddress;
    Private->Guest.StateSaveArea.Gdtr.Limit = Gdtr.Limit;
    Private->Guest.StateSaveArea.Idtr.Base = Idtr.BaseAddress;
    Private->Guest.StateSaveArea.Idtr.Limit = Idtr.Limit;

    Private->Guest.StateSaveArea.Cs.Limit = GetSegmentLimit(Context.SegCs);
    Private->Guest.StateSaveArea.Ds.Limit = GetSegmentLimit(Context.SegDs);
    Private->Guest.StateSaveArea.Es.Limit = GetSegmentLimit(Context.SegEs);
    Private->Guest.StateSaveArea.Ss.Limit = GetSegmentLimit(Context.SegSs);
    
    Private->Guest.StateSaveArea.Cs.Selector = Context.SegCs;
    Private->Guest.StateSaveArea.Ds.Selector = Context.SegDs;
    Private->Guest.StateSaveArea.Es.Selector = Context.SegEs;
    Private->Guest.StateSaveArea.Ss.Selector = Context.SegSs;

    FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Cs.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegCs), &Gdtr);
    FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Ds.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegDs), &Gdtr);
    FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Es.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegEs), &Gdtr);
    FillVmcbSegmentAttributes(&Private->Guest.StateSaveArea.Ss.Attrib, reinterpret_cast<const SEGMENT_SELECTOR*>(&Context.SegSs), &Gdtr);

    Private->Guest.StateSaveArea.Efer = Efer.Value;
    Private->Guest.StateSaveArea.Cr0 = __readcr0();
    Private->Guest.StateSaveArea.Cr2 = __readcr2();
    Private->Guest.StateSaveArea.Cr3 = __readcr3();
    Private->Guest.StateSaveArea.Cr4 = __readcr4();
    Private->Guest.StateSaveArea.Rflags.Value = Context.EFlags;
    Private->Guest.StateSaveArea.Rsp = Context.Rsp;
    Private->Guest.StateSaveArea.Rip = Context.Rip;
    Private->Guest.StateSaveArea.GuestPat = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_PAT));

    PVOID GuestVmcbPa = PhysicalMemory::GetPhysicalAddress(&Private->Guest);
    PVOID HostVmcbPa = PhysicalMemory::GetPhysicalAddress(&Private->Host);

    // Store state to the guest VMCB:
    __svm_vmsave(reinterpret_cast<size_t>(GuestVmcbPa));

    // Store the address of the HostStateArea:
    __writemsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_VM_HSAVE_PA), reinterpret_cast<UINT64>(PhysicalMemory::GetPhysicalAddress(Private->HostStateArea)));

    // Store state to the host VMCB to load it after the #VMEXIT:
    __svm_vmsave(reinterpret_cast<size_t>(HostVmcbPa));

    IsVirtualized = true;

    Private->VmmStack.Layout.InitialStack.GuestVmcbPa = GuestVmcbPa;
    Private->VmmStack.Layout.InitialStack.HostVmcbPa = HostVmcbPa;
    Private->VmmStack.Layout.InitialStack.Private = Private;

    // Callback
    SvmVmmRun = reinterpret_cast<_SvmVmmRun>(PSvmVmmRun);
    SvmVmmRun(&Private->VmmStack.Layout.InitialStack);

    // If SvmVmmRun returns to here, something went wrong:
    PhysicalMemory::FreePhysicalMemory(Private);
    return false;
}

bool HyperVisorSvm::VirtualizeAllProcessors()
{
    // Virtualizing an already virtualized processor executes VMRUN in the guest,
    // which is intercepted and answered with #GP. SimpleSvm refuses to install
    // twice by its CPUID vendor leaf; here the state is tracked instead to
    // not expose the hypervisor to the guest (transparent mode):
    if (g_IsVirtualized) { return true; }

    struct Callback_ {
        static bool inForEachCpu(void* Arg, unsigned int ProcessorNumber) {
            return static_cast<HyperVisorSvm*>(Arg)->VirtualizeProcessor(ProcessorNumber);
        }
        static bool inSystemContext(void* Arg) {
            return Callable::ForEachCpu(&Callback_::inForEachCpu, Arg);
        }
    };
    bool Status = Callable::CallInSystemContext(&Callback_::inSystemContext, this);
    if (!Status) { DevirtualizeAllProcessors(); }
    else { g_IsVirtualized = true; }
    return Status;
}

bool HyperVisorSvm::IsSvmSupported()
{
    CPUID_REGS Regs = {};

    // Check the 'AuthenticAMD' vendor name:
    __cpuid(Regs.Raw, CPUID::Generic::CPUID_MAXIMUM_FUNCTION_NUMBER_AND_VENDOR_ID);
    if (Regs.Regs.Ebx != AmdEnc::AEbx || Regs.Regs.Edx != AmdEnc::AEdx || Regs.Regs.Ecx != AmdEnc::AEcx) return false;

    // Check the AMD SVM (AMD-V) support:
    constexpr unsigned int CPUID_FN80000001_ECX_SVM = 1 << 2;
    __cpuid(Regs.Raw, CPUID::Generic::CPUID_EXTENDED_FEATURE_INFORMATION);
    if ((Regs.Regs.Ecx & CPUID_FN80000001_ECX_SVM) == 0) return false;

    // Check the Nested Paging support (AMD-RVI):
    constexpr unsigned int CPUID_FN8000000A_EDX_NESTED_PAGING = 1 << 0;
    __cpuid(Regs.Raw, CPUID::AMD::CPUID_SVM_FEATURES);
    if ((Regs.Regs.Edx & CPUID_FN8000000A_EDX_NESTED_PAGING) == 0) return false;

    // Check that the EFER.SVME is writeable (we can enable the SVM):
    AMD::VM_CR VmCr = {};
    VmCr.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_VM_CR));
    if (VmCr.Bitmap.SVMDIS) return false;

    return true;
}