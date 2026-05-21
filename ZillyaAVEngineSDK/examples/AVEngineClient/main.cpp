#include <iostream>
#include <string>
#include "RpcClient.h"
using namespace Zillya;

int main(int argc, char **argv)
{
	if(argc != 2)
	{
		std::cout << "Usage: AVEngineClient.exe <string>" << std::endl;
		std::cout << "       <string> path for scan" << std::endl;
		return -1;
	}

	RpcClient client;
	if(!client.Connect())
	{
		std::cout << "Error: cannot connect to server!" << std::endl;
		return -2;
	}

	std::string	path	= argv[1];
	std::wstring wpath	= std::wstring(path.begin(), path.end());

	struct RpcRequest request;
	memset(&request, 0, sizeof(struct RpcRequest));
	swprintf_s(request.szScanPath, MAX_PATH, L"%s", wpath.data());

	struct RpcResponse response;
	memset(&response, 0, sizeof(struct RpcResponse));

	unsigned int total_files	= 0;
	unsigned int total_viruses	= 0;

	DWORD dwStatus = client.SendRequest(request, response);

	if(dwStatus == RPC_REQUEST_ERROR)
	{
		std::cout << "Error: cannot send request!" << std::endl;
		return -3;
	}	

	do
	{
		if(dwStatus == RPC_REQUEST_ERROR) 
		{ 
			std::cout << "Error: response status is error status!" << std::endl;
			return -4; 
		}

		std::wstring wfilename	= response.szFileName;
		std::string filename	= std::string(wfilename.begin(), wfilename.end());

		std::cout << "Scanned file      : " << filename.data() << std::endl;
		std::cout << "    Virus count   : " << response.dwVirusCount << std::endl;
		std::cout << "    Files scanned : " << response.dwFilesScanned << std::endl;
		std::cout << "    Scan status   : " << response.dwScanStatus << std::endl;

		total_files		+= response.dwFilesScanned;
		total_viruses	+= response.dwVirusCount;
		
	} while((dwStatus = client.GetNextAnswer(response)) != RPC_REQUEST_OK);

	std::cout << std::endl;
	std::cout << "----------------------------------------" << std::endl;
	std::cout << "TOTAL RESULT: " << std::endl;
	std::cout << "      FILES SCANNED: " << total_files << std::endl;
	std::cout << "      VIRUSES FOUND: " << total_viruses << std::endl;
	std::cout << "----------------------------------------" << std::endl;
	
	std::cin.get();
	return 0;
}