#include "ConnectionManager.h"

ConnectionManager g_ConnectionManager;

ConnectionManager::ConnectionManager(void) :
	m_dwClientInc(0)
{
}

ConnectionManager::~ConnectionManager(void)
{
}

DWORD ConnectionManager::AddClient()
{
	m_dwClientInc++;

	m_ClientMap[m_dwClientInc] = new PipeRPCClient();

	return m_dwClientInc;
}

PipeRPCClient* ConnectionManager::getClient(DWORD hScan)
{
	return m_ClientMap[hScan];
}

DWORD ConnectionManager::DeleteClient(DWORD hScan)
{
	CLIENT_MAP::iterator iter = m_ClientMap.find(hScan);

	if(iter == m_ClientMap.end())
		return ZSDK_REQUEST_ERROR;

	iter->second->Close();

	delete iter->second;

	m_ClientMap.erase(iter);

	return ZSDK_REQUEST_OK;
}

DWORD ConnectionManager::StartScan(LPWSTR szPath)
{
	DWORD hScan;
	zRPCRequest request;

	hScan = AddClient();

	if(!hScan)
		return ZSDK_REQUEST_ERROR;

	if(!getClient(hScan)->Connect())
		return ZSDK_REQUEST_ERROR;

	wcscpy_s(request.szScanPath, MAX_PATH, szPath);
	if(getClient(hScan)->SendRequest(request) == ZSDK_REQUEST_ERROR)
		return ZSDK_REQUEST_ERROR;

	return hScan;
}

DWORD ConnectionManager::GetScanData(DWORD hScan, zRPCAnswer &answer)
{
	DWORD dwScanResult;
	CLIENT_MAP::iterator iter = m_ClientMap.find(hScan);

	if(iter == m_ClientMap.end())
		return ZSDK_REQUEST_ERROR;

	dwScanResult = iter->second->GetNextAnswer(answer);

	if(dwScanResult != ZSDK_REQUEST_MORE_DATA)
		DeleteClient(hScan);

	return dwScanResult;
}
