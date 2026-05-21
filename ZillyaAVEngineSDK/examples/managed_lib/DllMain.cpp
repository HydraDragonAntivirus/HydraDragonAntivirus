#include "RpcClient.h"
using namespace Zillya;
#include <string>

#define DLLEXPORT	extern "C" __declspec(dllexport)
#define CALLBACK	__stdcall

RpcClient			client;
struct RpcResponse	response;

DLLEXPORT bool CALLBACK Init();
DLLEXPORT bool CALLBACK	Free();
DLLEXPORT INT  CALLBACK	SendRequest(const wchar_t *);
DLLEXPORT INT  CALLBACK	GetNextAnswer(struct RpcResponseManaged *);

BOOL WINAPI DllMain(HMODULE, INT)
{
	return TRUE;
}

DLLEXPORT bool CALLBACK Init()
{
	if(client.Connect() == false) {	return false; }
	memset(&response, 0, sizeof(struct RpcResponse));
	return true;
}

DLLEXPORT bool CALLBACK Free()
{
	return client.Close();
}

DLLEXPORT INT CALLBACK SendRequest(const wchar_t *scan_path)
{
	struct RpcRequest request;
	memset(&request, 0, sizeof(struct RpcRequest));
	wcscpy_s(request.szScanPath, MAX_PATH, scan_path);

	return (INT)client.SendRequest(request, response);
}

DLLEXPORT INT CALLBACK GetNextAnswer(struct RpcResponseManaged *m_response)
{
	INT return_value = (INT)client.GetNextAnswer(response);

	m_response->fileName		= response.szFileName;
	m_response->virtusName		= response.szVirusName;


	m_response->scanStatus		= response.dwScanStatus;
	m_response->scanFilesCount	= response.dwFilesScanned;
	m_response->scanVirusCount	= response.dwVirusCount;
	m_response->scanAction		= response.dwAction;

	return return_value;
}