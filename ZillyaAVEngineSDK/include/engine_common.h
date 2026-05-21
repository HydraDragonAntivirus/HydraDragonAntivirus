/*********************************************************************
 *	Zillya AVEngine SDK
 *	Copyright (C) 2012 ALLIT Service
 *	All rights reserved
 *
 *	This file is a part of the AVEngine SDK
 *	Contains common constants.
 *
 ********************************************************************/

#ifndef _ZSDK_COMMON_H
#define _ZSDK_COMMON_H

// Defines constants for scaning result
#define ZSDK_SCAN_RES_OK				0 	/* File does not contain malicious code */
#define ZSDK_SCAN_RES_HEUR				1 	/* Detected suspicious code (heuristic analysis) */
#define ZSDK_SCAN_RES_MALICIOUS			2	/* Malicious code is detected (infected file) */
#define ZSDK_SCAN_RES_GENERALERR		-1 	/* General error of the scan engine */
#define ZSDK_SCAN_RES_WRONGHANDLE		-2 	/* Incorrect number of scanning thread (abnormal range) */
#define ZSDK_SCAN_RES_UNKNOWNHANDLE		-3	/* Scan the specified thread does not exist (not initialized) */
#define ZSDK_SCAN_RES_PATHTOOLONG		-4 	/* Set too long path for the file */
#define ZSDK_SCAN_RES_OPENERR			-5 	/* Error opening/reading the file */

#define ZSDK_SCAN_RES_CLEAN(x)			( x == 0 )
#define ZSDK_SCAN_RES_INFECTED(x)		( x == ZSDK_SCAN_RES_HEUR ) || ( x == ZSDK_SCAN_RES_MALICIOUS )
#define ZSDK_SCAN_RES_ERROR(x)			( x < 0 )

#endif // _ZSDK_COMMON_H