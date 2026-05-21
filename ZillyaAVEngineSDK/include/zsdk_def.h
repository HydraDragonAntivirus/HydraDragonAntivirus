/*********************************************************************
 *	Zillya AVEngine SDK
 *	Copyright (C) 2012 ALLIT Service
 *	All rights reserved
 *
 *	This file is a part of the AVEngine SDK
 *	Contains code an information to connect AVEngine Service
 *
 ********************************************************************/

#ifndef _ZSDK_DEF_H
#define _ZSDK_DEF_H

#include <windows.h>

#include "engine_common.h"

// if uses static lib, to connect with AVEngineService
#ifdef _ZSDK_INCLUDE_STATIC
#pragma comment(lib, "zslib.lib")
#endif

// The default virus name lenght
#define VIRNAME_LEN						64

//Request status result
#define ZSDK_REQUEST_OK					0
#define ZSDK_REQUEST_MORE_DATA			1
#define ZSDK_REQUEST_ERROR				-1

/**
 *	Provides information about scanning. Used to initiate a new scan
 **/
typedef struct zRPCRequest {
	wchar_t szScanPath[MAX_PATH];					// Scanning path
} *pZRPCRequest;

/**
 *	Contains the results of the scan.
 **/
typedef struct zRPCAnswer {
	wchar_t szFileName[MAX_PATH];					// File, than will be scanned
	wchar_t szVirName[VIRNAME_LEN];					// Virus name
	DWORD ScanStatus;								// Resut status
	DWORD FilesScanned;								// Files scannded (its >1 if have container)
	DWORD VirCount;									// Virus bodies found
	DWORD Action;									// Action taken
} *pzRPCAnswer;

/**
 *	Starts new scan thread
 *
 *	@param szPath path that will be scanned
 *	@return new scan thread handle
 **/
DWORD StartScan(LPWSTR szPath);

/**
 *	Get the next file scan result
 *	@param hScan scan thread handle
 *	@param answer scan result structure
 *	@return scan status
 **/ 
DWORD GetScanData(DWORD hScan, zRPCAnswer &answer);


#endif // _ZSDK_DEF_H