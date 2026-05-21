#include "RpcClient.h"
using namespace Zillya;

RpcClient::RpcClient()
{
	this->_connected = false;
}

RpcClient::~RpcClient()
{
	this->Close();
}

bool RpcClient::Connect()
{
	this->_pipe = CreateFile(RPC_PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
 
	if(this->_pipe == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY)
	{
		if(WaitNamedPipe(RPC_PIPE_NAME, NMPWAIT_WAIT_FOREVER)) {
			return this->Connect();
		}
		return false;
	}

	DWORD dwMode = PIPE_READMODE_MESSAGE; 
	if(SetNamedPipeHandleState(this->_pipe, &dwMode, 0, 0) == FALSE) {
		return false;
	}

	this->_connected = true;
	return true;
}

bool RpcClient::Close()
{
	if(!this->_connected)
		return false;

	if(CloseHandle(this->_pipe) == FALSE)
		return false;

	this->_connected = false;
	return true;
}

bool RpcClient::Connected() { return this->_connected; }

DWORD RpcClient::SendRequest(struct RpcRequest request, struct RpcResponse &response)
{
	DWORD dwStatus = RPC_REQUEST_OK;

	if(!WriteRequest(request, dwStatus))
		return RPC_REQUEST_ERROR;
	if(!ReadResponce(response, dwStatus))
		return RPC_REQUEST_ERROR;
	return dwStatus;
}

DWORD RpcClient::GetNextAnswer(struct RpcResponse &response)
{
	DWORD dwStatus = RPC_REQUEST_OK;

	if(!ReadResponce(response, dwStatus))
		return RPC_REQUEST_ERROR;
	return dwStatus;
}

bool RpcClient::WriteRequest(struct RpcRequest request, DWORD dwStatus)
{
	DWORD dwBytes;

	if(WriteFile(this->_pipe, (LPVOID)&dwStatus, sizeof(DWORD), &dwBytes, 0) == FALSE || 
		dwBytes != sizeof(DWORD))
	{
		return false;
	}

	if(WriteFile(this->_pipe, (LPVOID)&request, sizeof(struct RpcRequest), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(struct RpcRequest))
	{
		return false;
	}

	return true;
}

bool RpcClient::ReadResponce(struct RpcResponse &response, DWORD &dwStatus)
{
	DWORD dwBytes;

	if(ReadFile(this->_pipe, (LPVOID)&dwStatus, sizeof(DWORD), &dwBytes, 0) == FALSE || 
		dwBytes != sizeof(DWORD))
	{
		return false;
	}

	if(ReadFile(this->_pipe, (LPVOID)&response, sizeof(struct RpcResponse), &dwBytes, 0) == FALSE ||
		dwBytes != sizeof(struct RpcResponse))
	{
		return false;
	}

	return true;
}