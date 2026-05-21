#ifndef COREDEFINITIONS_H
#define COREDEFINITIONS_H

#pragma once
#include <Windows.h>

namespace Zillya
{
	typedef DWORD __stdcall TUnpackingInfoCallBack(DWORD CoreHandle,LPCWSTR FileName,CHAR Status,LPCSTR VirusName);
	typedef TUnpackingInfoCallBack *PUnpackingInfoCallBack;

	typedef DWORD __stdcall TRegInfoCallBack(DWORD CoreHandle,LPCSTR VirusName);
	typedef TRegInfoCallBack *PRegInfoCallBack;

	#pragma pack(1) //Установка выравнивания структур в 1 байт

	typedef struct TCoreUnpackMode
	{
		DWORD MaxArchSize; //Максмимальный размер распаковываемого контейнера
		DWORD MaxArchDept; //Максимальная глубина распаковки контейнера
		UINT64 ArchMode; // Режим использования распаковщиков архивов
		UINT64 InstMode; // Режим использования распаковщиков инсталляторов
		UINT64 ContMode; // Режим использования распаковщиков контейнеров
		UINT64 Reserved1;
		UINT64 Reserved2;
		UINT64 Reserved3;
		UINT64 Reserved4;
		UINT64 Flags;  // дополнительные флаги 0x00000001 - отображать тип архива
	} *PCoreUnpackMode;

	typedef struct TCoreData
	{
		DWORD AVEVers;  //Версия антивирусного ядра
		DWORD AVERecCount;  //Количество антивирусных записей
	} *PCoreData;

	typedef struct TCoreResult
	{
		DWORD FilesCount;  //Количество проверенных объектов (в случае контейнера >1)
		DWORD VirCount;  //Количество обнаруженных тел вирусов
		DWORD InfectionType;  //Поддерживаемое действие над файлом: 1 - Лечение, 2 - Удаление
		DWORD ActionRes;  //Выполненное над файлом действие: 0 - Пропуск, 1 - Лечение, 2 - Удаление
		DWORD IsContainer;  //Флаг обнаружения контейнера: 0 - нет, 1 - да
	} *PCoreResult;

	#define CORE_INIT_OPTION_BREAKARCHSCAN	0x00000001 //прекратить проверку архива при обнаружении вируса
	#define CORE_INIT_OPTION_DEBUGMODE		0x00000002 //Debug режим (писать в логи максимум информации)
	#define CORE_INIT_OPTION_LOADSIMPLE		0x00000004 //Загружать сокращенную версию баз

	typedef struct TCoreInit_Interface
	{
		LPCWSTR EPath; //Путь к папке антивирусного ядра
		LPCWSTR VPath; //Путь к папке антивирусных баз
		DWORD Options; //Дополнительные параметры:
		//   0x00000001 - прекратить проверку архива при обнаружении вируса
		//   0x00000002 - Debug режим (писать в логи максимум информации)
		//	 0x00000004 - Загружать сокращенную версию баз
		PUnpackingInfoCallBack UnpackingCallBack;
		PRegInfoCallBack RegCallBack;
		LPCWSTR LogFPath; // Путь к файлу об ошибках
		PCoreData CoreData;
	} *PCoreInit_Interface;

	typedef struct TCoreFScan_Interface
	{
		LPCWSTR FName;  // имя файла для проверки
		DWORD ToDo;  // Режим обработки файла: 0 - только тест, 1 - лечение, 2 - удаление
		DWORD BaseMode;  // Режим использования вирусных баз
		PCoreUnpackMode UnpackMode;
		//Возвращаемые значения
		LPSTR VName;  // Буфер для имени вируса (до 64 символов)
		PCoreResult CoreResult; // Указатель на запись возвращаемых значений
	} *PCoreFScan_Interface;

	typedef struct TCoreOptions_Interface
	{
		DWORD Options; //Дополнительные параметры:
		LPCSTR LogFPath; // Путь к файлу об ошибках
		DWORD R1, R2, R3, R4, R5; // Зарезервировано
	} *PCoreOptions_Interface;

	typedef struct TCoreMScan_interface
	{
		LPCVOID MemPointer;// указатель на область памяти
		DWORD MemSize;  // размер области памяти
		DWORD BaseMode;  // Режим использования вирусных баз
		PCoreUnpackMode UnpackMode;
		//Возвращаемые значения
		LPSTR VName;  // Буфер для имени вируса (до 64 символов)
		PCoreResult AVEResult;      // Указатель на запись возвращаемых значений
	} *PCoreMScan_interface;

	typedef struct TCoreRScan_interface
	{
		LPCSTR RegKey;
	} *PCoreRScan_interface;

	#pragma pack()

	typedef DWORD _stdcall TCoreInit(const PCoreInit_Interface params);
	typedef TCoreInit *PCoreInit;

	typedef DWORD _stdcall TCoreInitMerge(const PCoreInit_Interface params);
	typedef TCoreInitMerge *PCoreInitMerge;

	typedef int _stdcall TCoreFScan(DWORD CoreHandle, const PCoreFScan_Interface params);
	typedef TCoreFScan *PCoreFScan;
	// 0 - чистый; 1 - подозрительный, 2 - инфицированный

	typedef DWORD _stdcall TCoreOptions(DWORD CoreHandle, const PCoreOptions_Interface OPTIONS);
	typedef TCoreOptions *PCoreOptions;

	typedef int _stdcall TCoreMScan(DWORD CoreHandle, const PCoreMScan_interface params);
	typedef TCoreMScan *PCoreMScan;
	// 0 - чистый; 1 - подозрительный, 2 - инфицированный

	typedef int _stdcall TCoreRScan(DWORD CoreHandle, const PCoreRScan_interface params);
	typedef TCoreRScan *PCoreRScan;
	// 0 - чистый; 1 - подозрительный, 2 - инфицированный

	typedef int _stdcall TCoreFree(DWORD CoreHandle);
	typedef TCoreFree *PCoreFree;

	typedef DWORD _stdcall TCoreStopScan(DWORD CoreHandle);
	typedef TCoreStopScan *PCoreStopScan;
}

#endif //COREDEFINITIONS_H