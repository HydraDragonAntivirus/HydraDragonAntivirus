#include "ConnectionManager.h"

DWORD StartScan(LPWSTR szPath)
{
	return g_ConnectionManager.StartScan(szPath);
}

DWORD GetScanData(DWORD hScan, zRPCAnswer &answer)
{
	return g_ConnectionManager.GetScanData(hScan, answer);
}
