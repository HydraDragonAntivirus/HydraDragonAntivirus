#pragma once
#include "rpcserver.h"

class PipeRPCServer : public RPCServer
{
private:
	BOOL ProcessConnection(HANDLE hPipe);
	static BOOL ReadRequest(HANDLE hPipe, zRPCRequest &request, DWORD &dwStatus);
	static BOOL WriteResponce(HANDLE hPipe, zRPCAnswer responce, DWORD dwStatus);

	static DWORD WINAPI InstanceThreadProc(LPVOID lpParam);
public:
	PipeRPCServer(void);
	virtual ~PipeRPCServer(void);

	void Listen();
	static DWORD GetRequestAnswer(zRPCRequest request, zRPCAnswer &responce, DWORD dwStatus);
};
