#pragma once

#include "PipeRPCClient.h"

#include <map>

typedef std::map<DWORD, PipeRPCClient*> CLIENT_MAP;

class ConnectionManager
{
	CLIENT_MAP m_ClientMap;
	DWORD m_dwClientInc;

public:
	ConnectionManager(void);
	~ConnectionManager(void);

	DWORD AddClient();
	PipeRPCClient* getClient(DWORD hScan);
	DWORD DeleteClient(DWORD hScan);

	DWORD StartScan(LPWSTR szPath);
	DWORD GetScanData(DWORD hScan, zRPCAnswer &answer);
};

extern ConnectionManager g_ConnectionManager;