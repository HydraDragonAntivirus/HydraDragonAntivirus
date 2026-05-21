#include "zsdk_def.h"
#include "stdio.h"

void wmain(int argc, wchar_t* argv[])
{
	DWORD hScan = 0;
	DWORD res;
	zRPCAnswer answer;
	wchar_t szFileName[MAX_PATH];

	if(argc < 2)
		return ;

	wcscpy_s(szFileName, MAX_PATH, argv[1]);

	hScan = StartScan(szFileName);

	while(1)
	{
		res = GetScanData(hScan, answer);
		
		printf("");

		if(res == ZSDK_REQUEST_OK){
			printf("All scanned");
			break;
		}
		else if(res == ZSDK_REQUEST_MORE_DATA){
			printf("More data");
		}
		else if(res == ZSDK_REQUEST_ERROR){
			printf("Error in scan");
			break;
		}
	}
	system("pause");
}