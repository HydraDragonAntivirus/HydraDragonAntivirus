#pragma once
#include <ntifs.h>

class Spinlock {
private:
	unsigned max_wait = 65536;
public:
	BOOLEAN SpinlockTryLock(volatile LONG* Lock);
	void SpinlockLock(volatile LONG* Lock);
	void SpinlockUnlock(volatile LONG* Lock);
};