#ifndef THREAD_H
#define THREAD_H

#pragma once
#include "Delegate.h"

namespace Zillya
{
	class Thread
	{
	private:
		HANDLE				_thread;
		HANDLE				_semaphore_wake, _semaphore_sleep;
		LONG				_semaphore_wake_count, _semaphore_sleep_count;
		CRITICAL_SECTION	_critical_section;
		bool				_exit, _sleeping;
		bool				_auto_sleep;
	public:
		Thread();
		~Thread();

		Delegate<Thread *>	OnThread;

		void AutoSleep(bool);
		bool Wake();
		bool Sleep();
		bool IsSleeping();

		friend DWORD WINAPI ThreadCallback(LPVOID);
	};

	DWORD WINAPI ThreadCallback(LPVOID);
}

#endif //THREAD_H