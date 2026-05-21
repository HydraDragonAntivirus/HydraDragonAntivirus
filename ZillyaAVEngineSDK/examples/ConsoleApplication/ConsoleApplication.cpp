//Tou can read more information in documentation!!!

#include "windows.h"
#include <conio.h>
#include <string>

//Some pathes
#define NAME_DLL			L"CoreMain.DLL"

#define WITH_OUT_PAUSE		2
#define WITH_PAUSE			3

//Arguments that can be transfer to argv[]
#define NAME_FILE_ARGUMENT	1
#define PAUSE_ARGUMENT		2

#define COMAND_VAR_SMALL	"/p"
#define COMAND_VAR_BIG		"/P"

//Header with described structures
#include "engine_def.h"

//For load CoreMain.DLL
HINSTANCE hinstLib; 

//Pointers to fuctions.
PCoreInit coreInit_;
PCoreFree coreFree_;
PCoreFScan coreFScan_;

//structures
//Passed as a parameter in function CoreInit.
TCoreInit_Interface initParams;

//Structure is filled by the kernel when the CoreInit function called.
TCoreData coreData;

//With what parameters scan.
TCoreFScan_Interface scanParams;

//This structures are parameters for TCoreFScan_Interface.
TCoreUnpackMode unpackMode;
TCoreResult scanResult;

DWORD coreHandle;
char vNameBuffer[64];

int result;

//Pause function
static void pause()
{
	printf("Press any key.\n");
	_getch();
}

//Frees the loaded dynamic-link library (DLL) module and, if necessary, decrements its reference count.
static void FreeDLL()
{
	FreeLibrary(hinstLib);
	printf("The core dll was free.\n");
}

//Frees the core
static void FreeCore()
{
	coreFree_(coreHandle); 
	printf("The core was free.\n");
}

int main(int argc, char* argv[])
{
	wchar_t wszContent[MAX_PATH];
	wchar_t *wpTemp;
	
	if(!GetModuleFileName(NULL, wszContent, ARRAYSIZE(wszContent))) 
	{
		printf("error getting current path");
		return 0;
	}

	if(wpTemp = wcsrchr(wszContent, '\\')) 
	{
		wcscpy(wpTemp, L"\\aveng");
	}

	//Changes the current directory for the current process.
	SetCurrentDirectory(wszContent);

	//If to program send in arguments: name  of file and /p(or /P).
	if(argc == WITH_PAUSE)
	{
		if(!strcmp(argv[PAUSE_ARGUMENT], COMAND_VAR_SMALL) || !strcmp(argv[PAUSE_ARGUMENT],COMAND_VAR_BIG) )
		{
			//Register pause function
			if(atexit(pause))
			{
				return 0;
			}
		}
		else
		{
			printf("Third argument not valid!\n");
			pause();
		}
	}
	//If to program send in arguments only name of file.
	else if (argc == WITH_OUT_PAUSE)
	{
		printf("No pause\n");
	}
	//If to program doesn't send arguments
	else
	{
		printf("You don't send arguments to program! \n");
		printf("First argument: full way to file\n");
		printf("Second argument: /p or /P (optional, write it if you want to pause console application in the end of work)\n");
		pause();
		return 0;
	}

	//Save the name of file that will be scan.
	std::string str_file = argv[NAME_FILE_ARGUMENT];
	std::wstring wstr_file(str_file.begin(), str_file.end());

	printf("The file the path:\n");
	printf("%s\n", argv[NAME_FILE_ARGUMENT]);
	printf("will check.\n");
	

	//Load CoreMain.DLL
	hinstLib = LoadLibrary(NAME_DLL);

	//Check that is load a dll.
	if( !hinstLib )
	{
		printf("The CoreMain.DLL didn't load!\n");
		return 0;
	}
	else
	{
		printf("The core dll was load.\n");
		//If dll is load, don't forgot to use  FreeLibrary();
		//This function call when program close.
		if(atexit(FreeDLL))
			return 0;
	}	


	//Get pointers on functions from dll.
	coreInit_ = (PCoreInit)GetProcAddress(hinstLib, "CoreInit");
	coreFree_ = (PCoreFree)GetProcAddress(hinstLib, "CoreFree");					
	coreFScan_ = (PCoreFScan)GetProcAddress(hinstLib, "CoreFScan");			


	//Check that is get all adress of function.
	if(!coreInit_ || !coreFree_ || !coreFScan_)
	{
		printf("The functions adress from dll wasn't get.\n");
		return 0;
	}
	else
	{
		printf("The functions adress from dll was get.\n");
	}

	//Clear memory
	memset(&initParams,0,sizeof(TCoreInit_Interface));
	memset(&coreData,0,sizeof(TCoreData));
	memset(&scanParams,0,sizeof(TCoreFScan_Interface));
	memset(&unpackMode,0,sizeof(TCoreUnpackMode));
	memset(&scanResult,0,sizeof(TCoreResult));

	//Fill the structure TCoreInit_Interface
	initParams.CoreData = &coreData;
	initParams.EPath = wszContent;
	initParams.VPath = wszContent;
	
	printf("The core is initialized. Please wait ...\n");

	//Initialization core
	coreHandle = coreInit_(&initParams);

	//This function call when program close.
	if(atexit(FreeCore))
		return 0;

	//If sucsessed, return handle of the core new copy.
	if(coreHandle < ZSDK_MIN_HANDLE || coreHandle > ZSDK_MAX_HANDLE)
	{
		printf("The core initialization didn't come sucsessed.\n");
		return 0;
	}
	else
	{
		printf("The core was initialized.\n");
	}

	//Fill the structure TCoreFScan_Interface.
	scanParams.FName = wstr_file.c_str();
	scanParams.VName = vNameBuffer;
	scanParams.BaseMode = 0xffffffff;
	scanParams.UnpackMode = &unpackMode;
	scanParams.CoreResult = &scanResult;

	//Scan the file.
	result = coreFScan_(coreHandle, &scanParams);

	//Look the result
	switch(result)
	{
		//The file is clear
		case 0:
			printf("The file is clear\n");
			break;

		//The file is suspicious
		case 1:
			printf("The file is suspicious\n");
			break;

		//The file is infected
		case 2:
			printf("The file is infected\n");
			break;

		default:
			printf("Error in scan. \n");
	}

	return 0;
}