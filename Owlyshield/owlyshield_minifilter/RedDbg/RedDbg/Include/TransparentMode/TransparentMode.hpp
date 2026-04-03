#pragma once 
#include "HyperVisor/CommonTypes/CPUID.hpp"
#include "Debugger/Driver/GuestContext.hpp"

#include <ntddk.h>

class Transparent {
public:
	GuestContext* InvisibleCpuid(_In_ CPUID::FEATURE_INFORMATION Regs, _Inout_ GuestContext* Context);
	void InvisibleRdtsc();
	void InvisibleRdtscp();
};