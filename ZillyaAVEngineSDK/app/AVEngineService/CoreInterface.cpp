#include "CoreInterface.h"
using namespace Zillya;

CoreInterface::CoreInterface()
{	
}

CoreInterface::~CoreInterface()
{
}

bool CoreInterface::Init()
{
	//this->_thread_pool		= new ThreadPool();
	this->_core_library		= 0;

	TCHAR szCorePath[MAX_PATH];
	TCHAR* pTemp;

	if(!GetModuleFileName(NULL, szCorePath, ARRAYSIZE(szCorePath))) 
	{
		printf("error getting current path");
		return false;
	}

	if((pTemp = wcsrchr(szCorePath, '\\')) != NULL)
	{
		wcscpy_s(pTemp, (szCorePath + ARRAYSIZE(szCorePath)) - pTemp, L"\\aveng");
	}

	SetCurrentDirectory(szCorePath);

	std::wstring wpath = std::wstring(szCorePath);
	if(wpath[wpath.size() - 1] != L'\\') {
		wpath += L"\\";
	}
	wpath += CORE_LIBRARY_NAME;

	/* Load core library */
	this->_core_library = LoadLibrary(wpath.data());
	if(!this->_core_library) { return false; }

	/* Load functions from core library */
	this->_CoreInit = (PCoreInit)GetProcAddress(this->_core_library, "CoreInit");
	if(!this->_CoreInit) { return false; }

	this->_CoreFree = (PCoreFree)GetProcAddress(this->_core_library, "CoreFree");
	if(!this->_CoreFree) { return false; }

	this->_CoreFScan = (PCoreFScan)GetProcAddress(this->_core_library, "CoreFScan");
	if(!this->_CoreFScan) { return false; }

	/* Clear memory in structures */
	memset(&this->_core_data, 0, sizeof(struct TCoreData));
	memset(&this->_core_init_interface, 0, sizeof(struct TCoreInit_Interface));
	memset(&this->_core_fscan_interface, 0, sizeof(struct TCoreFScan_Interface));
	memset(&this->_core_unpack_mode, 0, sizeof(struct TCoreUnpackMode));

	/* Setup core options */
	this->_core_init_interface.CoreData		= &this->_core_data;
	this->_core_init_interface.EPath		= szCorePath;
	this->_core_init_interface.VPath		= szCorePath;

	this->_core_fscan_interface.BaseMode	= 0xffffffff;

	this->_core_unpack_mode.MaxArchSize		= 0;
	this->_core_unpack_mode.MaxArchDept		= 0;
	this->_core_unpack_mode.ArchMode		= 0xffffffffffffffff;
	this->_core_unpack_mode.InstMode		= 0xffffffffffffffff;
	this->_core_unpack_mode.ContMode		= 0xffffffffffffffff;
	
	this->_core = this->_CoreInit(&this->_core_init_interface);
	if(this->_core < 1 || this->_core > 64) { return false; }
	
	return true;
}

void CoreInterface::Free()
{
	if(this->_core >= 1 && this->_core <= 64)
		this->_CoreFree(this->_core);
	if(this->_core_library != 0)
		FreeLibrary(this->_core_library);
	//if(this->_thread_pool != 0)
	//	delete this->_thread_pool;
}

DWORD CoreInterface::ScanPath(LPCWSTR szPath, HANDLE hPipe)
{
	static const wchar_t  szMask[] = L"*";
	static const wchar_t *strErrorDirectories[2] = { L".", L".." };

	WIN32_FIND_DATA findData;
	std::list<std::wstring> directories;
	std::list<std::wstring>::iterator it;

	std::wstring path = szPath;
	if(path[path.size() - 1] != L'\\')
		path += L"\\";
	path += szMask;

	HANDLE hFile = FindFirstFile(path.data(), &findData);
	if(hFile == INVALID_HANDLE_VALUE) {
		return -1; 
	}

	do
	{
		if(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if(wcscmp(strErrorDirectories[0], findData.cFileName) != 0 &&
				wcscmp(strErrorDirectories[1], findData.cFileName) != 0)
			{
				directories.push_back(findData.cFileName);
			}
		}
		else
		{
			std::wstring file_path = szPath;
			if(file_path[file_path.size() - 1] != L'\\')
				file_path += L"\\";
			file_path += findData.cFileName;

			struct TCoreResult result;
			CHAR szVirusName[MAX_VIRUS_NAME_LEN];

			this->_core_fscan_interface.FName		= file_path.data();
			this->_core_fscan_interface.CoreResult	= &result;
			this->_core_fscan_interface.VName		= szVirusName;
			
			int scan_status = 0;
			scan_status = this->_CoreFScan(this->_core, &this->_core_fscan_interface);

			struct RpcResponse response;
			memset(&response, 0, sizeof(struct RpcResponse));
			response.dwFilesScanned		= result.FilesCount;
			response.dwVirusCount		= result.VirCount;
			response.dwAction			= result.ActionRes;
			response.dwScanStatus		= (DWORD)scan_status;
			wcscpy_s(response.szFileName, MAX_PATH, file_path.data());
	
			if(response.dwVirusCount > 0)
			{
				std::string virus_name_a = szVirusName;
				std::wstring virus_name = std::wstring(virus_name_a.begin(), virus_name_a.end());
				wcscpy_s(response.szVirusName, MAX_VIRUS_NAME_LEN, virus_name.data());
			}

			OnScanResponse(hPipe, response, 1);
		}
	} while(FindNextFile(hFile, &findData) != FALSE);

	FindClose(hFile);

	for(it = directories.begin(); it != directories.end(); ++it)
	{
		std::wstring new_path = szPath;

		if(new_path[new_path.size() - 1] != L'\\')
			new_path += L"\\";

		new_path += (*it);
		new_path += L"\\";

		Scan(new_path.data(), hPipe);
	}

	return 0;
}

DWORD CoreInterface::ScanFile(LPCWSTR szPath, HANDLE hPipe)
{
	struct TCoreResult result;
	CHAR szVirusName[MAX_VIRUS_NAME_LEN];

	this->_core_fscan_interface.FName		= szPath;
	this->_core_fscan_interface.CoreResult	= &result;
	this->_core_fscan_interface.VName		= szVirusName;
	
	int scan_status = 0;
	scan_status = this->_CoreFScan(this->_core, &this->_core_fscan_interface);

	struct RpcResponse response;
	memset(&response, 0, sizeof(struct RpcResponse));
	response.dwFilesScanned		= result.FilesCount;
	response.dwVirusCount		= result.VirCount;
	response.dwAction			= result.ActionRes;
	response.dwScanStatus		= (DWORD)scan_status;
	mbstowcs(response.szVirusName, szVirusName, MAX_VIRUS_NAME_LEN);
	wcscpy_s(response.szFileName, MAX_PATH, szPath);
	
	if(response.dwVirusCount > 0)
	{
		std::string virus_name_a = szVirusName;
		std::wstring virus_name = std::wstring(virus_name_a.begin(), virus_name_a.end());
		wcscpy_s(response.szVirusName, MAX_VIRUS_NAME_LEN, virus_name.data());
	}

	OnScanResponse(hPipe, response, 0);

	return 0;
}

DWORD CoreInterface::Scan(LPCWSTR szPath, HANDLE hPipe)
{
	DWORD dwAttributes = GetFileAttributes(szPath);
	
	if(dwAttributes == INVALID_FILE_ATTRIBUTES) {
		return ScanPath(szPath, hPipe);
	}
	
	if(dwAttributes & FILE_ATTRIBUTE_DIRECTORY){
		return ScanPath(szPath, hPipe);
	}

	return ScanFile(szPath, hPipe);
}

void CoreInterface::SetScanPathAndPipe(LPCWSTR szScanPath, HANDLE hPipe)
{
	this->_scan_path	= szScanPath;
	this->_hPipe		= hPipe;
}

DWORD CoreInterface::Scan()
{
	return Scan(this->_scan_path.data(), this->_hPipe);
}
