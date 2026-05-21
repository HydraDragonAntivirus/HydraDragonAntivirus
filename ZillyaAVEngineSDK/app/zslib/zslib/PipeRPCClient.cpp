#include "PipeRPCClient.h"

const LPWSTR lpszPipeName = L"\\\\.\\pipe\\ZSDK-{F671A1CA-7BA6-4e57-9E98-0D2AE0985A42}"; 

PipeRPCClient::PipeRPCClient(void) :
	m_hPipe(NULL)
{
}

PipeRPCClient::~PipeRPCClient(void)
{
	Close();
}

BOOL PipeRPCClient::Connect()
{
	DWORD dwMode;

	while(1) 
	{ 
		m_hPipe = CreateFile(lpszPipeName, GENERIC_READ | GENERIC_WRITE, 0,
							 NULL, OPEN_EXISTING, 0, NULL);
 
		if(m_hPipe == INVALID_HANDLE_VALUE)
		{
			if(GetLastError() == ERROR_PIPE_BUSY)
				if (WaitNamedPipe(lpszPipeName, NMPWAIT_WAIT_FOREVER)) 
					continue;
			
			return FALSE;
		}
			
		break;
   } 

   dwMode = PIPE_READMODE_MESSAGE; 
   if(!SetNamedPipeHandleState(m_hPipe, &dwMode, NULL, NULL))
	   return FALSE;  

   return TRUE;
}

BOOL PipeRPCClient::Close()
{
	if(m_hPipe)
		CloseHandle(m_hPipe);

	m_hPipe = NULL;

	return TRUE;
}

DWORD PipeRPCClient::SendRequest(zRPCRequest request/*, zRPCAnswer &answer*/)
{
	DWORD dwStatus = ZSDK_REQUEST_OK;

	if(!WriteRequest(request, dwStatus))
		return ZSDK_REQUEST_ERROR;

	//if(!ReadResponce(answer, dwStatus))
	//	return ZSDK_REQUEST_ERROR;

	return dwStatus;
}

DWORD PipeRPCClient::GetNextAnswer(zRPCAnswer &answer)
{
	DWORD dwStatus = ZSDK_REQUEST_OK;

	if(!ReadResponce(answer, dwStatus))
		return ZSDK_REQUEST_ERROR;

	return dwStatus;
}

BOOL PipeRPCClient::WriteRequest(zRPCRequest request, DWORD dwStatus)
{
	BOOL bResult;
	DWORD cbWritten;

	if(!m_hPipe)
		return FALSE;

	bResult = WriteFile(m_hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &cbWritten, NULL);

	if (!bResult || cbWritten != sizeof(DWORD)) 
		return FALSE;

	bResult = WriteFile(m_hPipe, (LPVOID)&request, sizeof(zRPCRequest), &cbWritten, NULL);

	if (!bResult || cbWritten != sizeof(request)) 
		return FALSE;

	return TRUE;
}

BOOL PipeRPCClient::ReadResponce(zRPCAnswer &answer, DWORD &dwStatus)
{
	BOOL bResult;
	DWORD cbBytesRead;

	if(!m_hPipe)
		return FALSE;

	bResult = ReadFile(m_hPipe, (LPVOID)&dwStatus, sizeof(DWORD), &cbBytesRead, NULL);
	DWORD err = GetLastError();
	if(!bResult || cbBytesRead != sizeof(DWORD))
		return FALSE; 

	bResult = ReadFile(m_hPipe, (LPVOID)&answer, sizeof(zRPCAnswer), &cbBytesRead, NULL);

	if(!bResult || cbBytesRead != sizeof(zRPCAnswer))
		return FALSE; 

	return TRUE;
}
