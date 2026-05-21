#ifndef CORESDK_H
#define CORESDK_H

#pragma once
#include <Windows.h>
#include <string>

namespace Zillya
{
	#define MAX_VIRUS_NAME_LEN		64

	#define RPC_REQUEST_OK			 0
	#define RPC_REQUEST_MORE_DATA	 1
	#define RPC_REQUEST_ERROR		-1

	typedef struct RpcRequest {
		wchar_t		szScanPath[MAX_PATH];
	} *lpRpcRequest;

	typedef struct RpcResponse {
		wchar_t		szFileName[MAX_PATH];
		wchar_t		szVirusName[MAX_VIRUS_NAME_LEN];
		DWORD		dwScanStatus;
		DWORD		dwFilesScanned;
		DWORD		dwVirusCount;
		DWORD		dwAction;
	} *lpRpcResponse;

	typedef struct RpcResponseManaged {
		LPWSTR			fileName;
		LPWSTR			virtusName;
		unsigned long	scanStatus;
		unsigned long	scanFilesCount;
		unsigned long	scanVirusCount;
		unsigned long	scanAction;
	} *lpRpcResponseManaged;
}

#endif //CORESDK_H