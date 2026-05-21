#include "ServiceDefault.h"

ServiceDefault::ServiceDefault(void)
{
	m_bRunning = false;
}

ServiceDefault::~ServiceDefault(void)
{
}

ServiceDefault* ServiceDefault::getInstance()
{
	static ServiceDefault inst;

	return &inst;
}

DWORD ServiceDefault::Install(LPWSTR szServiceName, LPWSTR szServiceDisplayName, LPCWSTR szBinaryPath)
{
	SC_HANDLE schSCManager, schService;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (schSCManager == NULL) 
	{
		ErrorMessage("ServiceDefault::Install, OpenSCManager");
		return -1;
	}

	schService = CreateService(schSCManager, szServiceName, szServiceDisplayName,
		SERVICE_ALL_ACCESS,	SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
		szBinaryPath, NULL, NULL, NULL, NULL, NULL);

	if (schService == NULL)
	{
		ErrorMessage("ServiceDefault::Install, CreateService");
		return -1; 
	}
	
	CloseServiceHandle(schService);
	CloseServiceHandle(schSCManager);
	
	return 0;
}

DWORD ServiceDefault::Uninstall(LPWSTR szServiceName)
{
	SC_HANDLE schSCManager, hService;

	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (schSCManager == NULL)
	{
		ErrorMessage("ServiceDefault::UnInstall, OpenSCManager");
		return -1;
	}
	
	hService=OpenService(schSCManager, szServiceName, SERVICE_ALL_ACCESS);
	
	if (hService == NULL)
	{
		ErrorMessage("ServiceDefault::UnInstall, OpenService");
		return -1;
	}

	if(!DeleteService(hService))
	{
		ErrorMessage("ServiceDefault::UnInstall, DeleteService");
		return -1;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(schSCManager);

	return 0;
}

void ServiceDefault::Run(LPWSTR szServiceName)
{
	SERVICE_TABLE_ENTRY DispatchTable[2];
		
	wcscpy_s(m_szServiceName, SERVICE_MAX_NAME, szServiceName);

	DispatchTable[0].lpServiceName = m_szServiceName;
	DispatchTable[0].lpServiceProc = &ServiceDefault::ServiceMain;
	DispatchTable[1].lpServiceName = NULL;
	DispatchTable[1].lpServiceProc = NULL;

	StartServiceCtrlDispatcher(DispatchTable);
}

void WINAPI ServiceDefault::ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv)
{
	ServiceDefault* instance = ServiceDefault::getInstance();
	
	memset(&instance->m_ServiceStatus, 0, sizeof(SERVICE_STATUS));

	instance->m_ServiceStatus.dwServiceType = SERVICE_WIN32;
	instance->m_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	instance->m_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

	instance->m_ServiceStatusHandle = RegisterServiceCtrlHandler(instance->m_szServiceName, &ServiceDefault::ServiceCtrlHandler); 

	if (instance->m_ServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) {
		return;
	}

	/*
	if(!instance->OnStart())
		return;
	*/

	instance->m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	
	if (!SetServiceStatus (instance->m_ServiceStatusHandle, &instance->m_ServiceStatus)) {
		return;
	}

	instance->m_bRunning = true;
	while(instance->m_bRunning) {
		//instance->ServiceProc();
		Sleep(3000);
	}

	return;
}

void WINAPI ServiceDefault::ServiceCtrlHandler(DWORD fdwControl)
{
	ServiceDefault* instance = ServiceDefault::getInstance();

	switch(fdwControl)
	{
		case SERVICE_CONTROL_PAUSE: 
			instance->m_ServiceStatus.dwCurrentState = SERVICE_PAUSED;
		break;
		case SERVICE_CONTROL_CONTINUE:
			instance->m_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
		break;
		case SERVICE_CONTROL_STOP:
			instance->m_ServiceStatus.dwWin32ExitCode = 0;
			instance->m_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			instance->m_ServiceStatus.dwCheckPoint = 0;
			instance->m_ServiceStatus.dwWaitHint = 0;

			SetServiceStatus (instance->m_ServiceStatusHandle, &instance->m_ServiceStatus);
			instance->m_bRunning = false;
		break;
		case SERVICE_CONTROL_INTERROGATE:
		break; 
	}
}

BOOL ServiceDefault::OnStart() 
{
	return 0; 
}

BOOL ServiceDefault::ServiceProc() 
{
	return 0;
}

#define MAX_ERR_LEN		260

void ErrorMessage(const char *func)
{
	DWORD dwCode = GetLastError();
	char error_message[MAX_ERR_LEN];

	DWORD dwErr = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, 0, dwCode, 
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
		error_message, 0, 0);

	if(dwErr == 0)
	{
		std::cout << func << " error: " << error_message << ", code = " << dwCode << std::endl;
	}
	else
	{
		std::cout << func << " error: unknown error, code = " << dwCode << std::endl;
	}
}