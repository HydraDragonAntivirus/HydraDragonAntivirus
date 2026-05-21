#include "RpcServer.h"
using namespace Zillya;

RpcServer::RpcServer()
{
	this->_thread = new Thread();
	this->_thread->OnThread.Connect<RpcServer>(this, &RpcServer::Listen);

	this->_mutex			= CreateMutex(0, FALSE, 0);

	WaitForSingleObject(this->_mutex, INFINITE);
	this->_thread_pool		= new ThreadPool();
	ReleaseMutex(this->_mutex);
}

RpcServer::~RpcServer()
{
	std::map<Thread *, CoreInterface *>::iterator it;

	this->_thread->Sleep();
	delete this->_thread_pool;

	WaitForSingleObject(this->_mutex, INFINITE);
	for(it = this->_threads.begin(); it != this->_threads.end(); ++it)
	{
		delete (*it).first;
		delete (*it).second;
	}
	this->_threads.clear();
	ReleaseMutex(this->_mutex);

	CloseHandle(this->_mutex);
	delete this->_thread;
}

void RpcServer::Start()
{
	this->_thread->Wake();
}

bool RpcServer::ReadRequest(HANDLE hPipe, struct RpcRequest &request, DWORD &dwStatus)
{
	DWORD dwBytes;

	if(ReadFile(hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(DWORD))
	{
		return false;
	}

	if(ReadFile(hPipe, (LPVOID)&request, sizeof(struct RpcRequest), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(struct RpcRequest))
	{
		return false;
	}

	return true;
}

bool RpcServer::WriteResponse(HANDLE hPipe, struct RpcResponse responce, DWORD dwStatus)
{
	DWORD dwBytes;

	if(WriteFile(hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(DWORD))
	{
		return false;
	}		

	if(WriteFile( hPipe, (LPVOID)&responce, sizeof(struct RpcResponse), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(struct RpcResponse))
	{
		return false;
	}

	return true;
}

void RpcServer::Listen(Thread *)
{
	HANDLE	hPipe;
	DWORD	dwSizeInBuffer	= sizeof(struct RpcRequest)	+ sizeof(DWORD) + 128;
	DWORD	dwSizeOutBuffer = sizeof(struct RpcResponse) + sizeof(DWORD) + 128;

	hPipe = CreateNamedPipe(RPC_PIPE_NAME, PIPE_ACCESS_DUPLEX, 
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES, dwSizeInBuffer, dwSizeOutBuffer, 0, 0);	

	if(hPipe == INVALID_HANDLE_VALUE) { return; }

	if(ConnectNamedPipe(hPipe, NULL) == FALSE &&
		GetLastError() != ERROR_PIPE_CONNECTED)
	{
		CloseHandle(hPipe);
		return;
	}

	if(!Connect(hPipe))
	{
		DWORD	dwError = -1;
		struct	RpcResponse response;
		memset(&response, 0, sizeof(struct RpcResponse));

		WriteResponse(hPipe, response, dwError);
		CloseHandle(hPipe);
	}
}

bool RpcServer::Connect(HANDLE hPipe)
{
	DWORD dwRequest;
	struct RpcRequest request;
	memset(&request, 0, sizeof(struct RpcRequest));

	if(!ReadRequest(hPipe, request, dwRequest)) { return false; }

	Thread			*thread; 
	CoreInterface	*coreInterface; 
	
	thread = this->_thread_pool->GetThread();
	thread->AutoSleep(true);
	thread->OnThread.Connect<RpcServer>(this, &RpcServer::ScanThread);

	coreInterface = new CoreInterface();
	coreInterface->OnScanResponse.Connect<RpcServer>(this, &RpcServer::ScanResponse);
	coreInterface->SetScanPathAndPipe(request.szScanPath, hPipe);

	WaitForSingleObject(this->_mutex, INFINITE);
	this->_threads.insert(std::make_pair(thread, coreInterface));
	ReleaseMutex(this->_mutex);

	thread->Wake();
	return true;
}

void RpcServer::ScanResponse(HANDLE hPipe, struct RpcResponse response, DWORD dwStatus)
{
	WriteResponse(hPipe, response, dwStatus);
}

void RpcServer::ScanThread(Thread *thread)
{
	CoreInterface *coreInterface;
	std::map<Thread *, CoreInterface *>::iterator it;

	WaitForSingleObject(this->_mutex, INFINITE);
	it = this->_threads.find(thread);
	ReleaseMutex(this->_mutex);

	if(it == this->_threads.end())
		return;

	coreInterface = (*it).second;

	if(coreInterface->Init() == false)
	{
		struct RpcResponse response;
		memset(&response, 0, sizeof(struct RpcResponse));
		WriteResponse(coreInterface->_hPipe, response, -1);
		return;
	}

	DWORD dwScanResult = coreInterface->Scan();

	struct RpcResponse response;
	memset(&response, 0, sizeof(struct RpcResponse));
	ScanResponse(coreInterface->_hPipe, response, dwScanResult);

	WaitForSingleObject(this->_mutex, INFINITE);
	
	this->_thread_pool->ReleaseThread(&thread);
	delete coreInterface;
	_threads.erase(it);

	ReleaseMutex(this->_mutex);
}