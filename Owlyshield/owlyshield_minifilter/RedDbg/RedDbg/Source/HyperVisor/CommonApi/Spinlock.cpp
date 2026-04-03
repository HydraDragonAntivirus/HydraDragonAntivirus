#include "HyperVisor/CommonApi/Spinlock.hpp"

#include <ntddk.h>

//----------------------------------------------------------------------------------------------
BOOLEAN Spinlock::SpinlockTryLock(volatile LONG * Lock) { return (!(*Lock) && !_interlockedbittestandset(Lock, 0)); }
//----------------------------------------------------------------------------------------------
void Spinlock::SpinlockLock(volatile LONG * Lock)
{
	unsigned wait = 1;
	while (!SpinlockTryLock(Lock))
	{
		for (unsigned i = 0; i < wait; ++i) { _mm_pause(); }

		if (wait * 2 > max_wait) { wait = max_wait; }
		else { wait = wait * 2; }
	}
}
//----------------------------------------------------------------------------------------------
void Spinlock::SpinlockUnlock(volatile LONG* Lock) { *Lock = 0; }
//----------------------------------------------------------------------------------------------