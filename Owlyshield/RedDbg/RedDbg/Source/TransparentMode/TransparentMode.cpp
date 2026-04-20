#include "TransparentMode/TransparentMode.hpp"

GuestContext* Transparent::InvisibleCpuid(_In_ CPUID::FEATURE_INFORMATION Regs, _Inout_ GuestContext* Context)
{
	Regs.AMD.ReservedForHvGuestStatus = 0;
	Context->Rax = Regs.Regs.Regs.Eax;
	Context->Rbx = Regs.Regs.Regs.Ebx;
	Context->Rcx = Regs.Regs.Regs.Ecx;
	Context->Rdx = Regs.Regs.Regs.Edx;

	return Context;
}