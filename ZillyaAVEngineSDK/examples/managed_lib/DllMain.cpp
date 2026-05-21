#include "RpcClient.h"
using namespace Zillya;
#include <string>

#define DLLEXPORT	extern "C" __declspec(dllexport)
#define SDKCALL	__stdcall

RpcClient			client;
struct RpcResponse	response;

DLLEXPORT bool SDKCALL Init();
DLLEXPORT bool SDKCALL	Free();
DLLEXPORT INT  SDKCALL	SendRequest(const wchar_t *);
DLLEXPORT INT  SDKCALL	GetNextAnswer(struct RpcResponseManaged *);

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
	return TRUE;
}

DLLEXPORT bool SDKCALL Init()
{
	if(client.Connect() == false) {	return false; }
	memset(&response, 0, sizeof(struct RpcResponse));
	return true;
}

DLLEXPORT bool SDKCALL Free()
{
	return client.Close();
}

DLLEXPORT INT SDKCALL SendRequest(const wchar_t *scan_path)
{
	struct RpcRequest request;
	memset(&request, 0, sizeof(struct RpcRequest));
	wcscpy_s(request.szScanPath, MAX_PATH, scan_path);

	return (INT)client.SendRequest(request, response);
}

DLLEXPORT INT SDKCALL GetNextAnswer(struct RpcResponseManaged *m_response)
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
