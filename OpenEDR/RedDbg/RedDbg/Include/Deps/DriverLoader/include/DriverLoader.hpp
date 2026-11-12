#pragma once
#include <Windows.h>
#include <exception>

#define SVC_OK 0x01
class DRIVER {
private:
    LPTSTR mDriverPath, mServiceName, mDosServiceName;
    DWORD mStartType;
    SC_HANDLE mhService;
private:
    bool Init, Loaded, Started;
public:
    inline bool IsInit() const { return Init; }
    inline bool IsLoaded() const { return Loaded; }
    inline bool IsStarted() const { return Started; }
public:

    DRIVER(); // Default constructor
    DRIVER(LPTSTR, LPTSTR, LPTSTR, DWORD); // Initalzing

    ~DRIVER();

    DWORD UnloadSvc(); DWORD StopSvc(); DWORD StartSvc(); DWORD CreateSvc();
    DWORD InitSvc(LPTSTR DriverPath, LPTSTR ServiceName, LPTSTR DosServiceName, DWORD StartType);
public:
    void LoadDriver(LPTSTR DriverPath, LPTSTR ServiceName, LPTSTR DosServiceName, DWORD StartType);
    void UnloadDriver();
};

DRIVER::DRIVER() :
	Init(false), Loaded(false), Started(false), mDriverPath(NULL), mServiceName(NULL),
	mDosServiceName(NULL), mStartType(0), mhService(NULL)
{
}


DRIVER::DRIVER(LPTSTR filePath, LPTSTR serviceName, LPTSTR displayName, DWORD startType) :
	Init(true), Loaded(false), Started(false), mDriverPath(filePath), mServiceName(serviceName),
	mDosServiceName(displayName), mStartType(startType), mhService(NULL)
{
}

DRIVER::~DRIVER()
{
	UnloadSvc();
	mDriverPath = NULL; mServiceName = NULL; mDosServiceName = NULL; mStartType = 0; mhService = NULL;
	Init = false; Loaded = false; Started = false;
}

DWORD DRIVER::CreateSvc()
{
	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == NULL) { throw std::exception("OpenSCManager Failed with error code: " + GetLastError()); }

	mhService = CreateService(hSCManager, mServiceName, mDosServiceName, SC_MANAGER_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, mStartType, SERVICE_ERROR_NORMAL, mDriverPath, NULL, NULL, NULL, NULL, NULL);
	if (mhService == NULL) 
	{ 
		mhService = OpenService(hSCManager, mServiceName, SERVICE_ALL_ACCESS); 
		if (mhService == NULL) { CloseServiceHandle(hSCManager); throw std::exception("CreateService Failed with error code: " + GetLastError()); }
	}

	CloseServiceHandle(hSCManager); Loaded = true; return SVC_OK;
}

DWORD DRIVER::InitSvc(LPTSTR DriverPath, LPTSTR ServiceName, LPTSTR DosServiceName, DWORD StartType)
{
	if (IsInit()) { return SVC_OK; }

	mDriverPath = DriverPath; mServiceName = ServiceName; mDosServiceName = DosServiceName; mStartType = StartType; mhService = NULL;

	Init = true; Loaded = false; Started = false; return SVC_OK;
}

DWORD DRIVER::StartSvc()
{
	if (!IsLoaded()) { throw std::exception("Service is not loaded"); }

	if (IsStarted()) { return SVC_OK; }

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (hSCManager == NULL) { throw std::exception("OpenSCManager Failed with error code: " + GetLastError()); }

	mhService = OpenService(hSCManager, mServiceName, SERVICE_ALL_ACCESS);
	if (mhService == NULL) { CloseServiceHandle(hSCManager); throw std::exception("OpenService Failed with error code: " + GetLastError()); }

	if (StartService(mhService, 0, NULL) == NULL) 
	{ 
		CloseServiceHandle(hSCManager); CloseServiceHandle(mhService); throw std::exception("StartService Failed with error code: " + GetLastError());
	}

	CloseServiceHandle(hSCManager); Started = true; return SVC_OK;
}

DWORD DRIVER::StopSvc()
{
	SERVICE_STATUS ServiceStatus; if (!IsStarted()) { return SVC_OK; }

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == NULL) { throw std::exception("OpenSCManager Failed with error code: " + GetLastError()); }

	mhService = OpenService(hSCManager, mServiceName, SERVICE_ALL_ACCESS);
	if (mhService == NULL) { CloseServiceHandle(hSCManager); throw std::exception("OpenService Failed with error code: " + GetLastError()); }

	if (ControlService(mhService, SERVICE_CONTROL_STOP, &ServiceStatus) == NULL)
	{
		CloseServiceHandle(hSCManager); CloseServiceHandle(mhService); throw std::exception("ControlService Failed with error code: " + GetLastError());
	}
	
	CloseServiceHandle(hSCManager); CloseServiceHandle(mhService); Started = false;	return SVC_OK;
}

DWORD DRIVER::UnloadSvc()
{
	if (!IsLoaded()) { return SVC_OK; }

	if (IsStarted()) { if (StopSvc() != SVC_OK) { throw std::exception("Unloading driver Failed with error code: " + GetLastError()); } }

	SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (hSCManager == NULL) { throw std::exception("OpenSCManager Failed with error code: " + GetLastError()); }

	mhService = OpenService(hSCManager, mServiceName, SERVICE_ALL_ACCESS);
	if (mhService == NULL) { CloseServiceHandle(hSCManager); throw std::exception("OpenService Failed with error code: " + GetLastError()); }
	
	DeleteService(mhService); CloseServiceHandle(hSCManager); Loaded = false; return SVC_OK;
}

void DRIVER::LoadDriver(LPTSTR DriverPath, LPTSTR ServiceName, LPTSTR DosServiceName, DWORD StartType)
{
	InitSvc(DriverPath, ServiceName, DosServiceName, StartType); CreateSvc(); StartSvc();
}

void DRIVER::UnloadDriver() { UnloadSvc(); }
