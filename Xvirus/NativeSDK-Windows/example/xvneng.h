#pragma once
#ifndef _XVNENG_H
#define _XVNENG_H

#define LoadFnKey "load"
#define UnloadFnKey "unload"
#define ScanFnKey "scan"
#define ScanAsStringFnKey "scanAsString"
#define ScanFolderFnKey "scanFolder"
#define ScanFolderAsStringFnKey "scanFolderAsString"
#define CheckUpdatesFnKey "checkUpdates"
#define GetSettingsFnKey "getSettings"
#define LoggingFnKey "logging"
#define BaseFolderFnKey "baseFolder"
#define VersionFnKey "version"

struct ActionResult
{
	bool sucess;
	wchar_t *result;
	wchar_t *error;
};

struct ScanResult
{
	bool sucess;
	wchar_t *error;
	bool isMalware;
	wchar_t *name;
	double malwareScore;
	wchar_t *path;
};

typedef ActionResult (*LoadFn)(bool force);
typedef ActionResult (*UnloadFn)();
typedef ScanResult (*ScanFn)(const wchar_t *filepath);
typedef ActionResult (*ScanAsStringFn)(const wchar_t *filepath);
typedef ScanResult *(*ScanFolderFn)(const wchar_t *folderPath);
typedef ActionResult (*ScanFolderAsStringFn)(const wchar_t *folderPath);
typedef ActionResult (*CheckUpdatesFn)(bool loadDBAfterUpdate);
typedef ActionResult (*GetSettingsFn)();
typedef bool (*LoggingFn)(bool enableLogging);
typedef wchar_t *(*BaseFolderFn)(const wchar_t *baseFolder);
typedef wchar_t *(*VersionFn)();

#endif // _XVNENG_H
