#pragma once 
#include "CppSupport/CppSupport.hpp"
#include "TransparentMode/TransparentMode.hpp"
#include "HyperVisor/CommonTypes/CPUID.hpp"
#include "HyperVisor/CommonTypes/MSR.hpp"
#include "HyperVisor/CommonTypes/Segmentation.hpp"
#include "HyperVisor/CommonTypes/Registers.hpp"
#include "HyperVisor/CommonTypes/SVM.hpp"
#include "HyperVisor/CommonTypes/Exception.hpp"
#include "HyperVisor/CommonTypes/Interrupts.hpp"
#include "HyperVisor/CommonApi/Callable.hpp"
#include "HyperVisor/CommonApi/MemoryUtils.hpp"

#include <fltKernel.h>
#include <intrin.h>

extern "C" typedef void(*_SvmVmmRun)(
	_In_ void* InitialVmmStackPointer);

extern "C" typedef SVM::PRIVATE_VM_DATA* (*_Interceptions)(
	_Inout_ SVM::PRIVATE_VM_DATA* Private);

enum IntelEnc : unsigned int { IEbx = 'uneG', IEdx = 'Ieni', IEcx = 'letn' };
enum AmdEnc : unsigned int { AEbx = 'htuA', AEdx = 'itne', AEcx = 'DMAc' };

enum class CpuVendor { CpuUnknown, CpuIntel, CpuAmd};

// Magic value, defined by hypervisor, triggers #VMEXIT and VMM shutdown:
constexpr unsigned int HyperSign = 0x1EE7C0DE;
constexpr unsigned int CPUID_VMM_SHUTDOWN = HyperSign;

class HyperVisorSvm {
private:
	CpuVendor GetCpuVendor();
	bool VirtualizeProcessor();
	bool DevirtualizeProcessor(__out PVOID& PrivateVmData);

	PVOID AllocPhys(
		_In_ SIZE_T Size,
		_In_ MEMORY_CACHING_TYPE CachingType,
		_In_ ULONG MaxPhysBits);

	void BuildNestedPagingTables(
		__out SVM::NESTED_PAGING_TABLES* Npt);

	void FillVmcbSegmentAttributes(
		_Out_ SVM::VMCB_STATE_SAVE_AREA::VMCB_SEGMENT_ATTRIBUTE* Attribute,
		_In_ const SEGMENT_SELECTOR* Selector,
		_In_ const DESCRIPTOR_TABLE_REGISTER_LONG* Gdtr);
private:
	static inline volatile bool g_IsVirtualized;
	_SvmVmmRun SvmVmmRun; _Interceptions Interceptions;
public:
	PVOID PSvmVmmRun = nullptr, PInterceptions = nullptr;
public:
	bool DevirtualizeAllProcessors();
	bool VirtualizeAllProcessors();
	bool IsSvmSupported();
};