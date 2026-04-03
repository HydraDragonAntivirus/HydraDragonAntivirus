#include "DriverLoader/include/DriverLoader.hpp"
#include "Debugger/Application/Pe/PEReader.hpp"
#include "Debugger/Application/Pe/PEInformation.hpp"

#include <Windows.h>

#include <iostream>
#include <string>

#define IOCTL_REGISTER_EVENT \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK_SUCCESS \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BREAKPOINT_PASS \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_WRITE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_CLOSE_FILE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_PE_ANALYZE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS )

typedef enum { IRP_BASED, EVENT_BASED } NOTIFY_TYPE;

typedef struct _REGISTER_EVENT { NOTIFY_TYPE Type; HANDLE  hEvent; } REGISTER_EVENT, * PREGISTER_EVENT;

enum Restrictions {
	PacketChunkSize = 1000,
	UsermodeBufferSize = sizeof(UINT32) + PacketChunkSize + 1,
	SIZEOF_REGISTER_EVENT = sizeof(REGISTER_EVENT),
};

//////////////////////////////////////////////////
//				Operation Codes					//
//////////////////////////////////////////////////

// Message area >= 0x4
enum OperantionCodes {
	OPERATION_LOG_INFO_MESSAGE = 1,
	OPERATION_LOG_WARNING_MESSAGE,
	OPERATION_LOG_ERROR_MESSAGE,
	OPERATION_LOG_NON_IMMEDIATE_MESSAGE,
	OPERATION_LOG_TRACE_MESSAGE,
	OPERATION_LOG_BREAKPOINT_MESSAGE
};

BOOLEAN IsSvmOffProcessStart;

class BreakOnEntry {
public:
	unsigned char SetBreakPoint(PEInformation& PEInformation, uint64_t Addr, HANDLE Device, HANDLE hProcess)
	{
		unsigned char BPInt3 = 0xCC;
		unsigned char BPByte;

		if (!ReadProcessMemory(hProcess,
			(LPCVOID)Addr, (LPVOID)&BPByte, 1, NULL)) {
			printf("ReadProcessMemory failed\n"); return 0;
		}

		if (!WriteProcessMemory(hProcess,
			(LPVOID)Addr, (LPCVOID)&BPInt3, 1, NULL)) {
			printf("WriteProcessMemory failed\n"); return 0;
		}

		printf("BP bytes: %X\n", BPByte);

		return BPByte;
	}

	void RestoreData(PEInformation& PEInformation, uint64_t Addr, HANDLE Device, HANDLE hProcess, unsigned char BPByte, bool ThreadSuspend)
	{
		bool* OutputBufferBool = (bool*)malloc(sizeof(bool));
		ULONG ReturnedLength;

		if (ThreadSuspend) { ResumeThread(PEInformation.ProcessInfo.hThread); }

		while (TRUE)
		{
			NTSTATUS Status = DeviceIoControl(
				Device,							// Handle to device
				IOCTL_BREAKPOINT_PASS,			// IO Control code
				NULL,				// Input Buffer to driver.
				NULL,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
				OutputBufferBool,					// Output Buffer from driver.
				sizeof(bool),				// Length of output buffer in bytes.
				&ReturnedLength,				// Bytes placed in buffer.
				NULL							// synchronous call
			);

			if (*OutputBufferBool == true)
			{
				if (!WriteProcessMemory(hProcess,
					(LPVOID)Addr, (LPCVOID)&BPByte, 1, NULL)) {
					printf("WriteProcessMemory failed\n"); return;
				}
				break;
			}
			else { continue; }
		}
		return;
	}
};

DWORD WINAPI TraceWriter(HANDLE hDriver)
{
	NTSTATUS Status = DeviceIoControl(
		hDriver,
		IOCTL_WRITE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

	return 0;
}

DWORD WINAPI ReadIrpBasedBuffer(HANDLE hDriver)
{
	BOOL    Status;
	ULONG   ReturnedLength;
	REGISTER_EVENT RegisterEvent;
	UINT32 OperationCode;

	printf(" =============================== Kernel-Mode Logs (Driver) ===============================\n");
	RegisterEvent.hEvent = NULL;
	RegisterEvent.Type = IRP_BASED;
	// allocate buffer for transfering messages
	char* OutputBuffer = (char*)malloc(UsermodeBufferSize);
	bool* OutputBufferBool = (bool*)malloc(sizeof(bool));

	while (TRUE) {
		if (!IsSvmOffProcessStart)
		{
			ZeroMemory(OutputBuffer, UsermodeBufferSize);
			ReturnedLength = 0;

			Status = DeviceIoControl(
				hDriver,							// Handle to device
				IOCTL_BUFFER_CHECK,			// IO Control code
				NULL,				// Input Buffer to driver.
				NULL,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
				OutputBufferBool,					// Output Buffer from driver.
				sizeof(bool),				// Length of output buffer in bytes.
				&ReturnedLength,				// Bytes placed in buffer.
				NULL							// synchronous call
			);

			if (*OutputBufferBool == true)
			{
				Status = DeviceIoControl(
					hDriver,							// Handle to device
					IOCTL_REGISTER_EVENT,			// IO Control code
					&RegisterEvent,					// Input Buffer to driver.
					SIZEOF_REGISTER_EVENT * 2,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
					OutputBuffer,					// Output Buffer from driver.
					UsermodeBufferSize,				// Length of output buffer in bytes.
					&ReturnedLength,				// Bytes placed in buffer.
					NULL							// synchronous call
				);

				if (!Status) { printf("Ioctl failed with code %d\n", GetLastError()); break; }

				if (ReturnedLength > 1)
				{
					printf("\n========================= Kernel Mode (Buffer) =========================\n");

					OperationCode = 0;
					memcpy(&OperationCode, OutputBuffer, sizeof(UINT32));

					printf("Returned Length : 0x%x \n", ReturnedLength);
					printf("Operation Code : 0x%x \n", OperationCode);

					switch (OperationCode)
					{
					case OPERATION_LOG_NON_IMMEDIATE_MESSAGE:
						printf("A buffer of messages (OPERATION_LOG_NON_IMMEDIATE_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_INFO_MESSAGE:
						printf("Information log (OPERATION_LOG_INFO_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_ERROR_MESSAGE:
						printf("Error log (OPERATION_LOG_ERROR_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_WARNING_MESSAGE:
						printf("Warning log (OPERATION_LOG_WARNING_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_BREAKPOINT_MESSAGE:
						printf("Breakpoint occured on (OPERATION_LOG_BREAKPOINT_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					default:
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					}

					printf("\n========================================================================\n");

					Status = DeviceIoControl(
						hDriver,							// Handle to device
						IOCTL_BUFFER_CHECK_SUCCESS,			// IO Control code
						NULL,				// Input Buffer to driver.
						NULL,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
						NULL,					// Output Buffer from driver.
						NULL,				// Length of output buffer in bytes.
						NULL,				// Bytes placed in buffer.
						NULL							// synchronous call
					);
				}
				else { continue; }
			}
			else
			{
				continue;
			}
		}
		else
		{
			return 0;
		}
	}
	return 0;
}

void Attach(PEInformation& PEInformation, HANDLE hDriver)
{
	std::string Application;
	std::cout << "ATTACH TO APP: ";
	getline(std::cin, Application, '\n');
	const wchar_t szModuleName[] = L"JustCause4.exe";

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 entry;

	entry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (wcscmp((const wchar_t*)entry.szExeFile, (const wchar_t*)szModuleName) == 0)//wcscmp//_stricmp
			{
				HANDLE HANDLE_OF_CHILD_PROC = OpenProcess(PROCESS_ALL_ACCESS, TRUE, entry.th32ProcessID);

				BreakOnEntry objBreakOnEntry;
				objBreakOnEntry.RestoreData(PEInformation,
					0x15B28407C,//0x14398CA38,//0x14B1F7325,//0x15B28407C,
					hDriver,
					HANDLE_OF_CHILD_PROC,
					objBreakOnEntry.SetBreakPoint(PEInformation, 0x15B28407C, hDriver, HANDLE_OF_CHILD_PROC), false);
			}
		}
	}
}

int main()
{
	std::unique_ptr<DRIVER> Driver; Driver = std::make_unique<DRIVER>();
	std::string Wait;

	Driver->LoadDriver((LPTSTR)L"C:\\RedDbgDrv.sys", (LPTSTR)L"RedTracer", (LPTSTR)L"RedTracer", SERVICE_DEMAND_START);
	std::cout << "Driver Started!" << std::endl;

	HANDLE hDriver = CreateFileA("\\\\.\\MyHypervisorDevice",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ |
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL |
		FILE_FLAG_OVERLAPPED,
		NULL); 

	if (hDriver == INVALID_HANDLE_VALUE) { DWORD ErrorNum = GetLastError(); printf("[*] CreateFile failed : %d\n", ErrorNum); return false; }
	
	HANDLE hDriverInterfaceTracerThread = CreateThread(NULL, 0, TraceWriter, hDriver, 0, NULL);
	if (hDriverInterfaceTracerThread) { printf("[*] hTracerThread Created successfully !!!\n"); }

	HANDLE hDriverInterfaceLogThread = CreateThread(NULL, 0, ReadIrpBasedBuffer, hDriver, 0, NULL);
	if (hDriverInterfaceLogThread) { printf("[*] hLogThread Created successfully !!!\n"); }
	IsSvmOffProcessStart = false;
	
	PEInformation PEInformation;
	PeReader PeReader;
	PeReader.PathToCurrentDebugging = "E:\\JustCause4\\JustCause4.exe"; //"C:\\PseudoDetectTf.exe"; //"E:\\JustCause4\\JustCause4.exe";
	PeReader.Start = false;
	PEInformation = PeReader.Pe(PEInformation);
	
	NTSTATUS Status = DeviceIoControl(
		hDriver,
		IOCTL_PE_ANALYZE,
		&PEInformation.Funcs,
		DWORD(PEInformation.Funcs.size() * sizeof(std::pair<ULONG_PTR, const std::string>)),
		NULL,
		NULL,
		NULL,
		NULL
	);
	
	Attach(PEInformation, hDriver);

	/*
	BreakOnEntry objBreakOnEntry;
	objBreakOnEntry.RestoreData(PEInformation,
		PEInformation.pImageNTHeaderOfPe->OptionalHeader.AddressOfEntryPoint + PEInformation.pImageNTHeaderOfPe->OptionalHeader.ImageBase,
		hDriver, 
		PEInformation.ProcessInfo.hProcess, 
		objBreakOnEntry.SetBreakPoint(PEInformation, PEInformation.pImageNTHeaderOfPe->OptionalHeader.AddressOfEntryPoint + PEInformation.pImageNTHeaderOfPe->OptionalHeader.ImageBase,
		hDriver, PEInformation.ProcessInfo.hProcess), true);
	*/
	
	std::cout << "Press any key to unload driver...\n";
    getline(std::cin, Wait, '\n');

	IsSvmOffProcessStart = true;

	Status = DeviceIoControl(
		hDriver,
		IOCTL_CLOSE_FILE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	);

    Driver->UnloadDriver();
    std::cout << "Driver unloaded!" << std::endl;

	TerminateProcess(PEInformation.ProcessInfo.hProcess, NULL);
	
	return true;
}