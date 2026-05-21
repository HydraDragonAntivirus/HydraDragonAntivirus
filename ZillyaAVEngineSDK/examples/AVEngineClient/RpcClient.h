#ifndef RPCCLIENT_H
#define RPCCLIENT_H

#pragma once
#include "CoreSDK.h"

namespace Zillya
{
	#define RPC_PIPE_NAME	L"\\\\.\\pipe\\ZSDK-{F671A1CA-7BA6-4e57-9E98-0D2AE0985A42}"

	class RpcClient
	{
	private:
		HANDLE			_pipe;
		bool			_connected;
	public:
		RpcClient();
		~RpcClient();

		bool Connect();
		bool Close();

		inline bool Connected();

		DWORD SendRequest(struct RpcRequest, struct RpcResponse &);
		DWORD GetNextAnswer(struct RpcResponse &);
	private:
		bool WriteRequest(struct RpcRequest, DWORD);
		bool ReadResponce(struct RpcResponse &, DWORD &);
	};
}

#endif //RPCCLIENT_H