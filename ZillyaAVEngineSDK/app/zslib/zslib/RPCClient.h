#pragma once

#include "zsdk_def.h"

class RPCClient
{
public:
	virtual ~RPCClient(void);

	virtual BOOL Connect() = 0;
	virtual DWORD SendRequest(zRPCRequest request/*, zRPCAnswer &answer*/) = 0;
	virtual BOOL Close() = 0;
};
