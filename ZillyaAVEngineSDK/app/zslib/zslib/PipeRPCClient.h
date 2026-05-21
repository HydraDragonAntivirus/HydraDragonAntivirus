#pragma once
#include "rpcclient.h"

class PipeRPCClient : public RPCClient
{
private:
	HANDLE m_hPipe;

	BOOL WriteRequest(zRPCRequest request, DWORD dwStatus);
	BOOL ReadResponce(zRPCAnswer &answer, DWORD &dwStatus);

public:
	PipeRPCClient(void);
	virtual ~PipeRPCClient(void);

	BOOL Connect();
	DWORD SendRequest(zRPCRequest request/*, zRPCAnswer &answer*/);
	DWORD GetNextAnswer(zRPCAnswer &answer);
	BOOL Close();
};
