#include "ThreadPool.h"
using namespace Zillya;

ThreadPool::ThreadPool(size_t initial_count)
{
	this->_thread_count = initial_count;

	InitializeCriticalSection(&this->_critical_section);

	EnterCriticalSection(&this->_critical_section);
	for(size_t i = 0; i < initial_count; ++i) {
		this->_thread_pool.insert(new Thread());
	}
	LeaveCriticalSection(&this->_critical_section);
}

ThreadPool::ThreadPool()
{
	SYSTEM_INFO sys_info;
	GetSystemInfo(&sys_info);

	//ThreadPool((size_t)sys_info.dwNumberOfProcessors);

	this->_thread_count = (size_t)sys_info.dwNumberOfProcessors;

	InitializeCriticalSection(&this->_critical_section);

	EnterCriticalSection(&this->_critical_section);
	for(size_t i = 0; i < (size_t)sys_info.dwNumberOfProcessors; ++i) {
		this->_thread_pool.insert(new Thread());
	}
	LeaveCriticalSection(&this->_critical_section);
}

ThreadPool::~ThreadPool()
{
	std::set<Thread *>::iterator it;

	EnterCriticalSection(&this->_critical_section);
	for(it = this->_thread_pool.begin(); it != this->_thread_pool.end(); ++it) {
		delete (*it);
	}
	this->_thread_pool.clear();
	LeaveCriticalSection(&this->_critical_section);

	DeleteCriticalSection(&this->_critical_section);
}

Thread *ThreadPool::GetThread()
{
	std::set<Thread *>::iterator it;
	Thread *thread;
	
	EnterCriticalSection(&this->_critical_section);
	if(this->_thread_pool.size() == 0)
	{
		if(this->_thread_count < MAX_THREAD_COUNT)
		{
			//If no sleeping threads in thread pool return new thread
			thread = new Thread();
			++this->_thread_count;
		}
		else { thread = 0; }
	}
	else
	{
		//Return sleeping thread
		it = this->_thread_pool.begin();
		thread = (*it);
		this->_thread_pool.erase(it);
	}
	LeaveCriticalSection(&this->_critical_section);

	return thread;
}

void ThreadPool::ReleaseThread(Thread **thread)
{
	EnterCriticalSection(&this->_critical_section);
	this->_thread_pool.insert((*thread));
	LeaveCriticalSection(&this->_critical_section);
	
	(*thread) = 0;
}