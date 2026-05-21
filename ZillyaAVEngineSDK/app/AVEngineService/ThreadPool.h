#ifndef THREADPOOL_H
#define THREADPOOL_H

#pragma once
#include "Thread.h"
#include <set>

namespace Zillya
{
	#define MAX_THREAD_COUNT		64

	class ThreadPool
	{
	private:
		CRITICAL_SECTION			_critical_section;
		std::set<Thread *>			_thread_pool;
		size_t						_thread_count;
	public:
		ThreadPool(size_t);
		ThreadPool();
		~ThreadPool();

		Thread *GetThread();
		void ReleaseThread(Thread **);
	};
}

#endif //THREADPOOL_H