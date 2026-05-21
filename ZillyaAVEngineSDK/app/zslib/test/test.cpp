// test.cpp : Defines the entry point for the console application.
//

#include "zsdk_def.h"


int main(int argc, char* argv[])
{
	DWORD hScan = 0, res;
	zRPCAnswer answer;

	hScan = StartScan(L"c:\\WINDOWS\\notepad.exe");

	while(1)
	{
		res = GetScanData(hScan, answer);

		if(res != ZSDK_REQUEST_MORE_DATA)
			break;
	}

	return 0;
}

