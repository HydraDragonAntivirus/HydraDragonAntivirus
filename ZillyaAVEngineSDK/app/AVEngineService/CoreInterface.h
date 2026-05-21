#ifndef COREINTERFACE_H
#define COREINTERFACE_H

#pragma once
#include "ThreadPool.h"
#include <list>

namespace Zillya
{
	#define	CORE_LIBRARY_NAME	L"CoreMain.DLL"

	class CoreInterface
	{
	private:
		HMODULE			_core_library;
		DWORD			_core;
		std::wstring	_scan_path;
		HANDLE			_hPipe;
		
		/* Members for work with core library */
		struct TCoreData				_core_data;
		struct TCoreInit_Interface		_core_init_interface;
		struct TCoreFScan_Interface		_core_fscan_interface;
		struct TCoreUnpackMode			_core_unpack_mode;
		struct TCoreResult				_core_result;

		PCoreInit						_CoreInit;
		PCoreFree						_CoreFree;
		PCoreFScan						_CoreFScan;
	public:
		CoreInterface();
		~CoreInterface();

		DelegateParam<HANDLE, struct RpcResponse, DWORD> OnScanResponse;

		bool Init();
		void Free();

		DWORD Scan(LPCWSTR, HANDLE);
		DWORD Scan();
		void  SetScanPathAndPipe(LPCWSTR, HANDLE);

	private:
		DWORD ScanPath(LPCWSTR, HANDLE);
		DWORD ScanFile(LPCWSTR, HANDLE);
		void ScanThreadCallback();

		friend class RpcServer;
	};
}

#endif //COREINTERFACE_H