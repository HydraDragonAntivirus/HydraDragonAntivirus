#pragma once
#include <iostream>
#include <Windows.h>

#define SERVICE_MAX_NAME 256

extern void ErrorMessage(const char *);

class ServiceDefault
{
private:
	volatile bool m_bRunning;
	WCHAR m_szServiceName[SERVICE_MAX_NAME];
	SERVICE_STATUS m_ServiceStatus;
	SERVICE_STATUS_HANDLE m_ServiceStatusHandle;

	ServiceDefault(void);

public:
	virtual ~ServiceDefault(void);

	static ServiceDefault* getInstance();

	DWORD Install(LPCWSTR szServiceName, LPCWSTR szServiceDisplayName, LPCWSTR szBinaryPath);
	DWORD Uninstall(LPCWSTR szServiceName);
	void Run(LPCWSTR szServiceName);

private:
	static void WINAPI ServiceMain(DWORD dwArgc, LPTSTR *lpszArgv);
	static void WINAPI ServiceCtrlHandler(DWORD Opcode);

protected:
	virtual BOOL OnStart();
	virtual BOOL ServiceProc();

};
