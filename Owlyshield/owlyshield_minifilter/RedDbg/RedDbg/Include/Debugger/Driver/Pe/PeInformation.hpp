#pragma once
#include "PeStruct.hpp"
#include <ntddk.h>

class PEInformation
{
private:
	class x64
	{
	public:
		PIMAGE_NT_HEADERS64 pImageNTHeader64;
		IMAGE_OPTIONAL_HEADER64 ImageOptionalHeader64;
		PIMAGE_THUNK_DATA64 pOriginalFirstThrunk;
	};

	class Dll
	{
	public:
		x64 x64;

		PIMAGE_DOS_HEADER pImageDOSHeaderOfPe;
		PIMAGE_NT_HEADERS pImageNTHeaderOfPe;

		PIMAGE_SECTION_HEADER pImageExportHeader;
		PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

		PIMAGE_SECTION_HEADER pImageImportHeader;
		PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;

		IMAGE_FILE_HEADER ImageFileHeader;
		PIMAGE_SECTION_HEADER pImageSectionHeader;
	};
public:
	x64 x64;
	Dll Dll;
public:
	PIMAGE_DOS_HEADER pImageDOSHeaderOfPe;
	PIMAGE_NT_HEADERS pImageNTHeaderOfPe;

	PIMAGE_SECTION_HEADER pImageExportHeader;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;

	PIMAGE_SECTION_HEADER pImageImportHeader;
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor;

	IMAGE_FILE_HEADER ImageFileHeader;
	PIMAGE_SECTION_HEADER pImageSectionHeader;
};