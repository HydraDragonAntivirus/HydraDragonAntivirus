/*********************************************************************
 *	Zillya AVEngine SDK
 *	Copyright (C) 2012 ALLIT Service
 *	All rights reserved
 *
 *	This file is a part of the AVEngine SDK
 *	Contains code an information to communicate with AVEngine library
 *
 ********************************************************************/

#ifndef _ZSDK_ENG_DEF_H
#define _ZSDK_ENG_DEF_H

#include "engine_common.h"

/**
 *	Ñallback function that is called, when the scan engine finishes checking the next file in the archive
 *	@param CoreHandle Opened antivirus core handle
 *	@param FileName The full path and display name of the extracted file
 *	@param Status File check status
 *	@param VirusName The name of the virus found
 *	@return Status
 **/
typedef DWORD __stdcall TUnpackingInfoCallBack(DWORD CoreHandle,LPCWSTR FileName,CHAR Status,LPCSTR VirusName);
typedef TUnpackingInfoCallBack *PUnpackingInfoCallBack;

/**
 *	Ñallback function that is called, when the scan engine finishes checking the next file in the archive
 *	@param CoreHandle Opened antivirus core handle
 *	@param VirusName The name of the virus found
 *	@return Status
 **/
typedef DWORD __stdcall TRegInfoCallBack(DWORD CoreHandle,LPCSTR VirusName);
typedef TRegInfoCallBack *PRegInfoCallBack;

// Setting of the structure alignment of 1 byte
#pragma pack(1)

/**
 *	Sets the parameters of extracting containers
 **/
typedef struct TCoreUnpackMode
{
	DWORD MaxArchSize; 										// The maximum size of the container being unpacked
	DWORD MaxArchDept; 										// The maximum depth of container extraction
	UINT64 ArchMode; 										// Mode of unpacking archives
	UINT64 InstMode; 										// Mode of unpackers installers
	UINT64 ContMode; 										// Mode of use of different containers unpackers 
	UINT64 Reserved1;
	UINT64 Reserved2;
	UINT64 Reserved3;
	UINT64 Reserved4;
	UINT64 Flags;  											// Additional flags bitmask
} *PCoreUnpackMode;

/**
 *	Contains information about the loaded copy of the kernel
 **/
typedef struct TCoreData
{
	DWORD AVEVers;  										// Antivirus core version
	DWORD AVERecCount;  									// Antivirus bases records count
} *PCoreData;

/**
 *	Structure consiscts the result of the scaning
 **/
typedef struct TCoreResult
{
	DWORD FilesCount;  										// Number of objects scanned 
	DWORD VirCount;  										// The number of bodies discovered viruses
	DWORD InfectionType;  									// Supported infected files operations
	DWORD ActionRes;  										// Action performed on the file
	DWORD IsContainer;  									// Flag detection container
} *PCoreResult;

// Core initialize options
#define CORE_INIT_OPTION_BREAKARCHSCAN	0x00000001 			// Stop checking the archive, on detected threats 
#define CORE_INIT_OPTION_DEBUGMODE		0x00000002 			// Run core in debug mode
#define CORE_INIT_OPTION_LOADSIMPLE		0x00000004 			// Load reduced base

/**
 *	Structure contains information about the copy of the kernel is initialized
 **/
typedef struct TCoreInit_Interface
{
	LPCWSTR EPath; 											// The path to the folder that contains anti-virus engine
	LPCWSTR VPath; 											// The path to the folder containing the virus database
	DWORD Options; 											// The options of the core being loaded
	PUnpackingInfoCallBack UnpackingCallBack;				
	PRegInfoCallBack RegCallBack;							
	LPCWSTR LogFPath;										// Path to LOG-file with error messages
	PCoreData CoreData;										
} *PCoreInit_Interface;

/**
 *	Contains information about the file to be scanned. 
 **/
typedef struct TCoreFScan_Interface
{
	LPCWSTR FName;											// Name of file, that will scanned
	DWORD ToDo;												// File process mode
	DWORD BaseMode;											// Range of BaseMode anti-virus and heuristic algorithms
	PCoreUnpackMode UnpackMode;
	LPSTR VName;											// Pointer to the virus name buffer
	PCoreResult CoreResult;									// Results an object scanning
} *PCoreFScan_Interface;

/**
 *	Contains information about the additional core options
 **/
typedef struct TCoreOptions_Interface
{
	DWORD Options; 											// Additional options
	LPCSTR LogFPath; 										// Path to the log file
	DWORD R1, R2, R3, R4, R5; 								// Reserved
} *PCoreOptions_Interface;

/**
 *	Contains information about the memory block to be scanned
 **/
typedef struct TCoreMScan_interface
{
	LPCVOID MemPointer;										// A pointer to memory containing the object to be scanned
	DWORD MemSize;											// Block size
	DWORD BaseMode;											// Mode of virus bases usage
	PCoreUnpackMode UnpackMode;
	LPSTR VName;											// Pointer to the virus name buffer
	PCoreResult AVEResult;									// Results an object scanning
} *PCoreMScan_interface;

/**
 *Contains information about the registry key to be scanned
 **/
typedef struct TCoreRScan_interface
{
	LPCSTR RegKey;											// Key
} *PCoreRScan_interface;

// end of 1 bytes aligment
#pragma pack()

/**
 *	Initializes the loaded copy of the core
 *	@param params initialize params
 *	@return new core handle
 **/
typedef DWORD _stdcall TCoreInit(const PCoreInit_Interface params);
typedef TCoreInit *PCoreInit;

// The minimum correct value of handle, returned by CoreInit
#define ZSDK_MIN_HANDLE					1

// The maximum correct value of handle, returned by CoreInit
#define ZSDK_MAX_HANDLE					64		

// CoreInit result test macros
#define ZSDK_INIT_SUCCEEDED(x)	( x >= ZSDK_MIN_HANDLE && x <= ZSDK_MAX_HANDLE )

/**
 *	Merges the extending set of bases, with initial set
 *	@param params initialize params
 *	@return merge result
 **/
typedef DWORD _stdcall TCoreInitMerge(const PCoreInit_Interface params);
typedef TCoreInitMerge *PCoreInitMerge;

/**
 *	Scans the file for viruses
 *	@param CoreHandle opened handle of the scan thread
 *	@param params scan params
 *	@return scan status
 **/
typedef int _stdcall TCoreFScan(DWORD CoreHandle, const PCoreFScan_Interface params);
typedef TCoreFScan *PCoreFScan;

/**
 *	Sets the options of the antivirus engine
 *	@param CoreHandle opened handle of the scan thread
 *	@param OPTIONS additional options
 *	@return oprion set result
 **/
typedef DWORD _stdcall TCoreOptions(DWORD CoreHandle, const PCoreOptions_Interface OPTIONS);
typedef TCoreOptions *PCoreOptions;

/**
 *	Scans the memory block for viruses
 *	@param CoreHandle opened handle of the scan thread
 *	@param params scan params
 *	@return scan status
 **/
typedef int _stdcall TCoreMScan(DWORD CoreHandle, const PCoreMScan_interface params);
typedef TCoreMScan *PCoreMScan;

/**
 *	Scans the registry key for viruses
 *	@param CoreHandle opened handle of the scan thread
 *	@param params scan params
 *	@return scan status
 **/
typedef int _stdcall TCoreRScan(DWORD CoreHandle, const PCoreRScan_interface params);
typedef TCoreRScan *PCoreRScan;

/**
 *	Closes an open antivirus core handle
 *	@param CoreHandle opened handle of the scan thread
 *	@return operation result
 **/
typedef int _stdcall TCoreFree(DWORD CoreHandle);
typedef TCoreFree *PCoreFree;

/**
 *	Stops scanning the object to the specified stream
 *	@param CoreHandle opened handle of the scan thread
 *	@return operation result
 **/
typedef DWORD _stdcall TCoreStopScan(DWORD CoreHandle);
typedef TCoreStopScan *PCoreStopScan;

#endif //_ZSDK_ENG_DEF_H
