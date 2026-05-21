#include "Thread.h"
using namespace Zillya;

Thread::Thread()
{
	this->_exit		= false;
	this->_sleeping = true;

	this->_semaphore_sleep_count	= 0;
	this->_semaphore_wake_count		= 0;

	//Init critical section and semaphores
	InitializeCriticalSection(&this->_critical_section);
	this->_semaphore_sleep	= CreateSemaphore(0, this->_semaphore_sleep_count, 64, 0);
	this->_semaphore_wake	= CreateSemaphore(0, this->_semaphore_wake_count, 64, 0);

	//Create thread
	this->_thread = CreateThread(0, 0, Zillya::ThreadCallback, (LPVOID)this, 0, 0);

	//Sleep thread
	WaitForSingleObject(this->_semaphore_sleep, INFINITE);
	InterlockedDecrement(&this->_semaphore_sleep_count);
}

Thread::~Thread()
{
	EnterCriticalSection(&this->_critical_section);
	this->_exit = true;
	LeaveCriticalSection(&this->_critical_section);
	
	//Wake thread to exit
	if(this->_sleeping == true) {
		this->Wake();
	}

	//Wait for thread exit
	WaitForSingleObject(this->_thread, INFINITE);

	//Remove critical section and semaphores
	CloseHandle(this->_semaphore_wake);
	CloseHandle(this->_semaphore_sleep);
	DeleteCriticalSection(&this->_critical_section);
}

void Thread::AutoSleep(bool auto_sleep)
{
	EnterCriticalSection(&this->_critical_section);
	this->_auto_sleep = auto_sleep;
	LeaveCriticalSection(&this->_critical_section);
}

bool Thread::Wake()
{
	EnterCriticalSection(&this->_critical_section);
	if(!this->_sleeping)
	{
		LeaveCriticalSection(&this->_critical_section);
		return false;
	}
	this->_sleeping = false;
	LeaveCriticalSection(&this->_critical_section);

	//Wake thread
	InterlockedIncrement(&this->_semaphore_wake_count);
	ReleaseSemaphore(this->_semaphore_wake, 1, 0);

	return true;
}

bool Thread::Sleep()
{
	EnterCriticalSection(&this->_critical_section);
	if(this->_sleeping == true)
	{
		LeaveCriticalSection(&this->_critical_section);
		return false;
	}
	this->_sleeping = true;
	LeaveCriticalSection(&this->_critical_section);
	
	//Sleep thread
	WaitForSingleObject(this->_semaphore_sleep, INFINITE);
	InterlockedDecrement(&this->_semaphore_sleep_count);

	return true;
}

bool Thread::IsSleeping()
{
	bool result;

	EnterCriticalSection(&this->_critical_section);
	result = this->_sleeping;
	LeaveCriticalSection(&this->_critical_section);

	return result;
}

DWORD WINAPI Zillya::ThreadCallback(LPVOID lpParam)
{
	Thread *thread = (Thread *)lpParam;

	bool exit, sleeping, auto_sleep;

	EnterCriticalSection(&thread->_critical_section);
	exit		= thread->_exit;
	sleeping	= thread->_sleeping;
	auto_sleep	= thread->_auto_sleep;
	LeaveCriticalSection(&thread->_critical_section);

	while(!exit)
	{
		if(sleeping)
		{
			//Release sleep semaphore
			InterlockedIncrement(&thread->_semaphore_sleep_count);
			ReleaseSemaphore(thread->_semaphore_sleep,1,NULL);

			//Waiting for wake
			WaitForSingleObject(thread->_semaphore_wake, INFINITE);
			InterlockedDecrement(&thread->_semaphore_wake_count);
		}
		else
		{
			//Call UserCallback function
			thread->OnThread(thread);
		}

		EnterCriticalSection(&thread->_critical_section);
		exit		= thread->_exit;
		sleeping	= thread->_sleeping;
		auto_sleep	= thread->_auto_sleep;
		LeaveCriticalSection(&thread->_critical_section);

		if(auto_sleep == true)
		{
			EnterCriticalSection(&thread->_critical_section);
			thread->_sleeping = true;
			LeaveCriticalSection(&thread->_critical_section);
		}
	}

	return 0;
}