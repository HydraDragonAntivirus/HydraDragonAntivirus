#include "HyperVisor/CommonApi/SystemMemory.hpp"

typedef NTSTATUS(*_ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength);

typedef NTSTATUS(*_ZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength);

//#define FIELD_OFFSET(t,f)       ((LONG)(LONG_PTR)&(((t*) 0)->f))

FORCEINLINE struct _TEB* NtCurrentTeb(VOID)
{
	return (struct _TEB*)__readgsqword(FIELD_OFFSET(NT_TIB, Self));
}

#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)

#define BASESRV_SERVERDLL_INDEX     1
#define BASESRV_FIRST_API_NUMBER    0

bool GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
{
	PBASE_STATIC_SERVER_DATA BaseStaticServerData;
	
	PPEB Peb = NtCurrentPeb();//https://www.unknowncheats.me/forum/general-programming-and-reversing/452636-peb.html

	ASSERT(Peb->ReadOnlyStaticServerData);
	BaseStaticServerData = (PBASE_STATIC_SERVER_DATA)Peb->ReadOnlyStaticServerData[BASESRV_SERVERDLL_INDEX];
	ASSERT(BaseStaticServerData);

	SYSTEM_PERFORMANCE_INFORMATION PerformanceInfo;
	VM_COUNTERS VmCounters;
	QUOTA_LIMITS QuotaLimits;
	ULONGLONG PageFile, PhysicalMemory;
	NTSTATUS Status;
	
	if (lpBuffer->dwLength != sizeof(*lpBuffer))
	{
		return FALSE;
	}

	UNICODE_STRING ZwQSI;
	RtlInitUnicodeString(&ZwQSI, L"ZwQuerySystemInformation");
	PVOID PZwQuerySystemInformation = MmGetSystemRoutineAddress(&ZwQSI);
	_ZwQuerySystemInformation ZwQuerySystemInformation = reinterpret_cast<_ZwQuerySystemInformation>(PZwQuerySystemInformation);

	// Query performance information
	Status = ZwQuerySystemInformation(SystemPerformanceInformation,
		&PerformanceInfo,
		sizeof(PerformanceInfo),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	// Calculate memory load
	lpBuffer->dwMemoryLoad = ((UINT32)(BaseStaticServerData->SysInfo.NumberOfPhysicalPages -
		PerformanceInfo.AvailablePages) * 100) /
		BaseStaticServerData->SysInfo.NumberOfPhysicalPages;

	// Save physical memory
	PhysicalMemory = BaseStaticServerData->SysInfo.NumberOfPhysicalPages *
		BaseStaticServerData->SysInfo.PageSize;
	lpBuffer->ullTotalPhys = PhysicalMemory;

	// Now save available physical memory
	PhysicalMemory = PerformanceInfo.AvailablePages *
		BaseStaticServerData->SysInfo.PageSize;
	lpBuffer->ullAvailPhys = PhysicalMemory;

	UNICODE_STRING ZwQIP;
	RtlInitUnicodeString(&ZwQIP, L"ZwQueryInformationProcess");
	PVOID PZwQueryInformationProcess = MmGetSystemRoutineAddress(&ZwQIP);
	_ZwQueryInformationProcess ZwQueryInformationProcess = reinterpret_cast<_ZwQueryInformationProcess>(PZwQueryInformationProcess);

	// Query VM and Quota Limits
	Status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessQuotaLimits,
		&QuotaLimits,
		sizeof(QUOTA_LIMITS),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	Status = ZwQueryInformationProcess(NtCurrentProcess(),
		ProcessVmCounters,
		&VmCounters,
		sizeof(VM_COUNTERS),
		NULL);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	// Save the commit limit
	lpBuffer->ullTotalPageFile = min(QuotaLimits.PagefileLimit,
		PerformanceInfo.CommitLimit);
	lpBuffer->ullTotalPageFile *= BaseStaticServerData->SysInfo.PageSize;

	// Calculate how many pages are left
	PageFile = PerformanceInfo.CommitLimit - PerformanceInfo.CommittedPages;

	// Save the total
	lpBuffer->ullAvailPageFile = min(PageFile,
		QuotaLimits.PagefileLimit -
		VmCounters.PagefileUsage);
	lpBuffer->ullAvailPageFile *= BaseStaticServerData->SysInfo.PageSize;

	// Now calculate the total virtual space
	lpBuffer->ullTotalVirtual = (BaseStaticServerData->SysInfo.MaximumUserModeAddress -
		BaseStaticServerData->SysInfo.MinimumUserModeAddress) + 1;

	// And finally the available virtual space
	lpBuffer->ullAvailVirtual = lpBuffer->ullTotalVirtual - VmCounters.VirtualSize;
	lpBuffer->ullAvailExtendedVirtual = 0;
	
	return TRUE;
}