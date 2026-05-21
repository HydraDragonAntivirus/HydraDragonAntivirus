#include "PipeRPCServer.h"

const LPWSTR lpszPipeName = L"\\\\.\\pipe\\ZSDK-{F671A1CA-7BA6-4e57-9E98-0D2AE0985A42}"; 

PipeRPCServer::PipeRPCServer(void)
{
}

PipeRPCServer::~PipeRPCServer(void)
{
}

BOOL PipeRPCServer::ReadRequest(HANDLE hPipe, zRPCRequest &request, DWORD &dwStatus)
{
	BOOL bResult;
	DWORD cbBytesRead;

	bResult = ReadFile(hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &cbBytesRead, NULL);

	if (!bResult || cbBytesRead != sizeof(DWORD))
		return FALSE;

	bResult = ReadFile(hPipe, (LPVOID)&request, sizeof(zRPCRequest), &cbBytesRead, NULL);

	if (!bResult || cbBytesRead != sizeof(zRPCRequest))
		return FALSE;

	return TRUE;
}

BOOL PipeRPCServer::WriteResponce(HANDLE hPipe, zRPCAnswer responce, DWORD dwStatus)
{
	BOOL bResult;
	DWORD cbWritten;

	bResult = WriteFile( hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &cbWritten, NULL);

	if (!bResult || cbWritten != sizeof(DWORD))
		return FALSE;

	bResult = WriteFile( hPipe, (LPVOID)&responce, sizeof(zRPCAnswer), &cbWritten, NULL);

	if (!bResult || cbWritten != sizeof(zRPCAnswer))
		return FALSE;

	return TRUE;
}

DWORD PipeRPCServer::GetRequestAnswer(zRPCRequest request, zRPCAnswer &responce, DWORD dwStatus)
{
	// in this place run scan
	static int i=10;

	//printf("get request %S\n", request.szScanPath);

	i--;

	if(i){
		return ZSDK_REQUEST_MORE_DATA;
	}
	i=10;
	return ZSDK_REQUEST_OK;
}

DWORD WINAPI PipeRPCServer::InstanceThreadProc(LPVOID lpParam)
{
	HANDLE hPipe = (HANDLE) lpParam;
	DWORD dwRequestStatus;
	BOOL bReadMore = TRUE;
	
	zRPCRequest request;
	zRPCAnswer answer;

	memset(&request, 0, sizeof(zRPCRequest));

	while (bReadMore) 
	{
		if(!ReadRequest(hPipe, request, dwRequestStatus))
			break;

		do {
			memset(&answer, 0, sizeof(zRPCAnswer));

			if((dwRequestStatus = GetRequestAnswer(request, answer, dwRequestStatus)) == ZSDK_REQUEST_ERROR) 
			{
				bReadMore = FALSE;
				break;
			}
	 
			if(!WriteResponce(hPipe, answer, dwRequestStatus))
			{
				bReadMore = FALSE;
				break;
			}
	
		} while(dwRequestStatus == ZSDK_REQUEST_MORE_DATA);
	}

	FlushFileBuffers(hPipe); 
	DisconnectNamedPipe(hPipe); 
	CloseHandle(hPipe); 

	return 0;
}


BOOL PipeRPCServer::ProcessConnection(HANDLE hPipe)
{
	HANDLE hThread;
	DWORD dwThreadId;

	hThread = CreateThread(NULL, 0, PipeRPCServer::InstanceThreadProc, (LPVOID) hPipe, 0, &dwThreadId);

	if (!hThread) 
		return FALSE;
         
	CloseHandle(hThread); 

	return TRUE;
}

void PipeRPCServer::Listen()
{
	HANDLE hPipe;
	BOOL bConnected;
	DWORD dwSizeOfInBuffer = sizeof(zRPCRequest) + sizeof(DWORD) + 128;
	DWORD dwSizeOfOutBuffer = sizeof(zRPCAnswer) + sizeof(DWORD) + 128;

	for(;;)
	{
		hPipe = CreateNamedPipe(lpszPipeName, PIPE_ACCESS_DUPLEX, 
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES, dwSizeOfInBuffer, dwSizeOfOutBuffer, 0, NULL);	

		if( hPipe == INVALID_HANDLE_VALUE )
			return;

		bConnected = ConnectNamedPipe(hPipe, NULL);
		
		if(!bConnected && GetLastError() != ERROR_PIPE_CONNECTED)
		{
			CloseHandle(hPipe); 		
			continue;
		}

		if(!ProcessConnection(hPipe)) 
		{
		}
	}
}