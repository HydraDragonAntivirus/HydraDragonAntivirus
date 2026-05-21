#ifndef RPCSERVER_H
#define RPCSERVER_H

#pragma once
#include "CoreInterface.h"
#include <map>

namespace Zillya
{	
	#define RPC_PIPE_NAME	L"\\\\.\\pipe\\ZSDK-{F671A1CA-7BA6-4e57-9E98-0D2AE0985A42}"

	class RpcServer
	{
	private:
		Thread			*_thread;
		ThreadPool		*_thread_pool;

		HANDLE								_mutex;
		std::map<Thread *, CoreInterface *>	_threads;
	public:
		RpcServer();
		~RpcServer();
		
		void Start();
	protected:
		bool RpcServer::ReadRequest(HANDLE, struct RpcRequest &, DWORD &);
		bool RpcServer::WriteResponse(HANDLE, struct RpcResponse, DWORD);
	private:
		void Listen(Thread *);
		bool Connect(HANDLE);
		void ScanResponse(HANDLE, struct RpcResponse, DWORD);
		void ScanThread(Thread *);
	};
}

#endif //RPCSERVER_H