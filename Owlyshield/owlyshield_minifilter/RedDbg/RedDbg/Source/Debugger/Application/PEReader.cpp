#include "Debugger/Application/Pe/PEInformation.hpp"
#include "Debugger/Application/Pe/PEReader.hpp"

#include <Windows.h>
#include <filesystem>
#include <vector>
#include <iostream>

std::wstring StringToWideString(
	const std::string& str)
{
	// Create a std::string_view from the input string
	std::string_view strView(str);

	// Create a std::wstring from the std::string_view using the data() function
	std::wstring wideStr(strView.data(), strView.data() + strView.size());

	return wideStr;
}


PEInformation PeReader::SectionCopierOfDll64(
	PEInformation& PEInformation,
	std::vector<LPVOID>& BAs,
	std::vector<size_t>& BAsSize)
{
	for (unsigned char Section = 0; Section < PEInformation.Dll.ImageFileHeader.NumberOfSections; ++Section)
	{
		const PIMAGE_SECTION_HEADER pCurrentSectionHeader = 
			(PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.Dll.pImageSectionHeader + Section * sizeof(IMAGE_SECTION_HEADER));

		uint64_t sectionAddress =
			(PEInformation.Dll.x64.pImageNTHeader64->OptionalHeader.ImageBase + pCurrentSectionHeader->VirtualAddress);
	}

	return PEInformation;
}

PEInformation PeReader::GetSectionsOfDll64(
	PEInformation& PEInformation)
{
	for (unsigned char Section = 0; Section < PEInformation.Dll.ImageFileHeader.NumberOfSections; ++Section)
	{
		const PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.Dll.pImageSectionHeader + Section * sizeof(IMAGE_SECTION_HEADER));

		if (PEInformation.Dll.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress >= pCurrentSectionHeader->VirtualAddress &&
			PEInformation.Dll.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress <
			pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
			PEInformation.Dll.pImageImportHeader = pCurrentSectionHeader;
	}
	return PEInformation;
}

PEInformation PeReader::GetImportsOfDll64(
	PEInformation& PEInformation,
	uint64_t dRawOffset,
	const std::wstring& DllName)
{
	while (PEInformation.Dll.pImageImportDescriptor->Name != 0)
	{
		std::string DllName = (char*)(dRawOffset + (PEInformation.Dll.pImageImportDescriptor->Name - PEInformation.Dll.pImageImportHeader->VirtualAddress));
		std::wcout << L"\n\tDLL NAME: " << StringToWideString(DllName) << "\n";

		hFileContent = GetContentOfDll(StringToWideString(DllName), 2);

		if (PEInformation.Dll.pImageImportDescriptor->OriginalFirstThunk == 0) continue;

		PEInformation.Dll.x64.pOriginalFirstThrunk =
			(PIMAGE_THUNK_DATA64(dRawOffset + (PEInformation.Dll.pImageImportDescriptor->FirstThunk - PEInformation.Dll.pImageImportHeader->VirtualAddress)));

		while (PEInformation.Dll.x64.pOriginalFirstThrunk->u1.AddressOfData != 0)
		{
			if (PEInformation.Dll.x64.pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64) { ++PEInformation.Dll.x64.pOriginalFirstThrunk; continue; }

			const PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)PEInformation.Dll.x64.pOriginalFirstThrunk->u1.AddressOfData;
			if (pImageImportByName == nullptr) continue;

			if (IMAGE_SNAP_BY_ORDINAL(PEInformation.Dll.x64.pOriginalFirstThrunk->u1.Ordinal))
			{
				FARPROC pfnProc = GetProcAddress((HMODULE)hFileContent, (LPCSTR)PEInformation.Dll.x64.pOriginalFirstThrunk->u1.Ordinal);
				if (pfnProc == NULL) { puts("\t\tpfnProc is null\n"); return PEInformation; }
				PEInformation.Dll.x64.pOriginalFirstThrunk->u1.Function = (ULONGLONG)pfnProc;
			}
			else
			{
				const std::string FunctionName = dRawOffset + (pImageImportByName->Name - PEInformation.Dll.pImageImportHeader->VirtualAddress);
				FARPROC pfnProc = GetProcAddress((HMODULE)hFileContent, FunctionName.c_str());
				if (pfnProc == NULL) { puts("\t\tpfnProc is null\n"); return PEInformation; }
				PEInformation.Dll.x64.pOriginalFirstThrunk->u1.Function = (ULONG_PTR)pfnProc;
			}
			++PEInformation.Dll.x64.pOriginalFirstThrunk;
		}
		++PEInformation.Dll.pImageImportDescriptor;
	}
	return PEInformation;
}

HANDLE inline PeReader::GetContentOfDll(
	const std::wstring& DllName,
	uint8_t Method)
{
	if (Method == 1)
	{
		const HANDLE hFile = CreateFileW(DllName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			printf("[-] An error occured when trying to open the PE file !\n");
			CloseHandle(hFile);
			return nullptr;
		}

		const DWORD dFileSize = GetFileSize(hFile, nullptr);
		if (dFileSize == INVALID_FILE_SIZE)
		{
			printf("[-] An error occured when trying to get the PE file size !\n");
			CloseHandle(hFile);
			return nullptr;
		}

		const HANDLE hFileContent = VirtualAlloc(NULL, dFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (hFileContent == INVALID_HANDLE_VALUE)
		{
			printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
			CloseHandle(hFile);
			CloseHandle(hFileContent);
			return nullptr;
		}

		const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
		if (!bFileRead)
		{
			printf("[-] An error occured when trying to read the PE file content !\n");
			CloseHandle(hFile);
			if (hFileContent != nullptr) CloseHandle(hFileContent);

			return nullptr;
		}

		CloseHandle(hFile);
		return hFileContent;
	}
	else if (Method == 2)
	{
		HMODULE hFile = LoadLibraryW(DllName.c_str());
		if (hFile == 0)
		{
			//std::wstring DllPath = PathToCurrentDebugging.parent_path().wstring() + PathToCurrentDebugging.root_directory().wstring() + DllName;
			hFile = LoadLibraryW((PathToCurrentDebugging.parent_path().wstring() + PathToCurrentDebugging.root_directory().wstring() + DllName).c_str());
			if (hFile == 0)
			{
				puts("[-] An error occured when trying to open the PE file !");
				return nullptr;
			}
		}
		return hFile;
	}
}

PEInformation PeReader::ParseImageOfDll32(
	const std::wstring& DllName,
	PEInformation& PEInformation)
{
	PEInformation.Dll.x32.pImageNTHeader32 =
		(PIMAGE_NT_HEADERS32)((DWORD_PTR)PEInformation.Dll.pImageDOSHeaderOfPe + PEInformation.Dll.pImageDOSHeaderOfPe->e_lfanew);
	if (PEInformation.Dll.x64.pImageNTHeader64 == nullptr) { return PEInformation; }

	PEInformation.Dll.ImageFileHeader = PEInformation.Dll.x32.pImageNTHeader32->FileHeader;
	PEInformation.Dll.x32.ImageOptionalHeader32 = PEInformation.Dll.x32.pImageNTHeader32->OptionalHeader;

	PEInformation.Dll.pImageSectionHeader =
		(PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.Dll.x32.pImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + PEInformation.Dll.ImageFileHeader.SizeOfOptionalHeader);
	if (PEInformation.Dll.pImageSectionHeader == nullptr) { return PEInformation; }

	return PEInformation;
}

PEInformation PeReader::ParseImageOfDll64(
	const std::wstring& DllName,
	PEInformation& PEInformation)
{
	PEInformation.Dll.x64.pImageNTHeader64 =
		(PIMAGE_NT_HEADERS64)((DWORD_PTR)PEInformation.Dll.pImageDOSHeaderOfPe + PEInformation.Dll.pImageDOSHeaderOfPe->e_lfanew);
	if (PEInformation.Dll.x64.pImageNTHeader64 == nullptr) { return PEInformation; }

	PEInformation.Dll.ImageFileHeader = PEInformation.Dll.x64.pImageNTHeader64->FileHeader;
	PEInformation.Dll.x64.ImageOptionalHeader64 = PEInformation.Dll.x64.pImageNTHeader64->OptionalHeader;

	PEInformation.Dll.pImageSectionHeader = 
		(PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.Dll.x64.pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + PEInformation.Dll.ImageFileHeader.SizeOfOptionalHeader);
	if (PEInformation.Dll.pImageSectionHeader == nullptr) { return PEInformation; }

	PEInformation = GetSectionsOfDll64(PEInformation);

	if (PEInformation.Dll.pImageImportHeader == nullptr) { puts("\n[-] An error when trying to retrieve PE imports !\n"); return PEInformation; }

	uint64_t dRawOffset = (uint64_t)PEInformation.Dll.pImageDOSHeaderOfPe + PEInformation.Dll.pImageImportHeader->PointerToRawData;

	PEInformation.Dll.pImageImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR(
		(uint64_t(dRawOffset + (PEInformation.Dll.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) -
			PEInformation.Dll.pImageImportHeader->VirtualAddress)));

	PEInformation = GetImportsOfDll64(PEInformation, dRawOffset, DllName);

	std::wcout << std::endl << L"\tDLL NAME: " << DllName << std::endl;

	return PEInformation;
}

PEInformation PeReader::Dll(
	const std::wstring DllName,
	PEInformation& PEInformation)
{
	hFileContent = GetContentOfDll(DllName, 1);
	if (hFileContent == 0)
	{
		if (hFileContent != nullptr) { CloseHandle(hFileContent); } return PEInformation;
	}

	PEInformation.Dll.pImageDOSHeaderOfPe = (PIMAGE_DOS_HEADER)hFileContent;
	if (PEInformation.Dll.pImageDOSHeaderOfPe == nullptr)
	{
		if (hFileContent != nullptr) { FreeLibrary(HMODULE(hFileContent)); CloseHandle(hFileContent); } return PEInformation;
	}

	PEInformation.Dll.pImageNTHeaderOfPe = (PIMAGE_NT_HEADERS)((DWORD_PTR)hFileContent + PEInformation.Dll.pImageDOSHeaderOfPe->e_lfanew);
	if (PEInformation.Dll.pImageNTHeaderOfPe == nullptr)
	{
		if (hFileContent != nullptr) { FreeLibrary(HMODULE(hFileContent)); CloseHandle(hFileContent); } return PEInformation;
	}

	if (PEInformation.Dll.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		 PEInformation = ParseImageOfDll64(DllName, PEInformation);
	}
	else if (PEInformation.Dll.pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		 PEInformation = ParseImageOfDll32(DllName, PEInformation);
	}

	return PEInformation;
}



HANDLE inline PeReader::GetFileContent()
{
	const HANDLE hFile = CreateFileW(PathToCurrentDebugging.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to open the PE file !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const DWORD dFileSize = GetFileSize(hFile, nullptr);
	if (dFileSize == INVALID_FILE_SIZE)
	{
		printf("[-] An error occured when trying to get the PE file size !\n");
		CloseHandle(hFile);
		return nullptr;
	}

	const HANDLE hFileContent = VirtualAlloc(NULL, dFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (hFileContent == INVALID_HANDLE_VALUE)
	{
		printf("[-] An error occured when trying to allocate memory for the PE file content !\n");
		CloseHandle(hFile);
		CloseHandle(hFileContent);
		return nullptr;
	}

	const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);
	if (!bFileRead)
	{
		printf("[-] An error occured when trying to read the PE file content !\n");
		CloseHandle(hFile);
		if (hFileContent != nullptr) CloseHandle(hFileContent);

		return nullptr;
	}

	CloseHandle(hFile);
	return hFileContent;
}

PEInformation PeReader::GetSections64(
	PEInformation& PEInformation)
{
	for (unsigned char Section = 0; Section < PEInformation.ImageFileHeader.NumberOfSections; ++Section)
	{
		const PIMAGE_SECTION_HEADER pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.pImageSectionHeader + Section * sizeof(IMAGE_SECTION_HEADER));

		if (PEInformation.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress >= pCurrentSectionHeader->VirtualAddress &&
			PEInformation.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress <
			pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
			PEInformation.pImageImportHeader = pCurrentSectionHeader;
	}
	return PEInformation;
}

PEInformation PeReader::GetImports64(
	PEInformation& PEInformation,
	uint64_t dRawOffset)
{
	while (PEInformation.pImageImportDescriptor->Name != 0)
	{
		std::string DllName = (char*)(dRawOffset + (PEInformation.pImageImportDescriptor->Name - PEInformation.pImageImportHeader->VirtualAddress));
		std::wcout << L"\n\tDLL NAME: " << StringToWideString(DllName) << "\n";

		//PEInformation = Dll(StringToWideString(DllName), PathToCurrentDebugging, PEInformation);

		hFileContent = GetContentOfDll(StringToWideString(DllName), 2);

		//if (PEInformation.pImageImportDescriptor->OriginalFirstThunk == 0) continue;

		PEInformation.x64.pOriginalFirstThrunk = 
			(PIMAGE_THUNK_DATA64(dRawOffset + (PEInformation.pImageImportDescriptor->FirstThunk - PEInformation.pImageImportHeader->VirtualAddress)));

		while (PEInformation.x64.pOriginalFirstThrunk->u1.AddressOfData != 0)
		{
			if (PEInformation.x64.pOriginalFirstThrunk->u1.AddressOfData >= IMAGE_ORDINAL_FLAG64) { ++PEInformation.x64.pOriginalFirstThrunk; continue; }

			const PIMAGE_IMPORT_BY_NAME pImageImportByName = (PIMAGE_IMPORT_BY_NAME)PEInformation.x64.pOriginalFirstThrunk->u1.AddressOfData;
			if (pImageImportByName == nullptr) continue;

			if (IMAGE_SNAP_BY_ORDINAL(PEInformation.x64.pOriginalFirstThrunk->u1.Ordinal))
			{
				FARPROC pfnProc = GetProcAddress((HMODULE)hFileContent, (LPCSTR)PEInformation.x64.pOriginalFirstThrunk->u1.Ordinal);
				if (pfnProc == NULL) { puts("\t\tpfnProc is null\n"); return PEInformation; }
				PEInformation.x64.pOriginalFirstThrunk->u1.Function = (ULONGLONG)pfnProc;
				std::cout << "\t\t Address: " << std::hex << pfnProc << " Name(Ordinal) of funcion: " << PEInformation.x64.pOriginalFirstThrunk->u1.Ordinal << "\n";
			}
			else
			{
				const std::string FunctionName = dRawOffset + (pImageImportByName->Name - PEInformation.pImageImportHeader->VirtualAddress);
				FARPROC pfnProc = GetProcAddress((HMODULE)hFileContent, FunctionName.c_str());
				if (pfnProc == NULL) { puts("\t\tpfnProc is null\n"); return PEInformation; }
				PEInformation.x64.pOriginalFirstThrunk->u1.Function = (ULONG_PTR)pfnProc;
				std::cout << "\t\t Address: " << std::hex << pfnProc << " Name(Ordinal) of funcion: " << FunctionName << "\n";

				PEInformation.Funcs.push_back(std::make_pair((ULONG_PTR)pfnProc, FunctionName));
			}
			++PEInformation.x64.pOriginalFirstThrunk;
		}
		++PEInformation.pImageImportDescriptor;
	}

	for (const auto& pair : PEInformation.Funcs)
	{
		if (pair.second == "ExitProcess")
		{
			return PEInformation;
		}
	}

	hFileContent = GetContentOfDll(StringToWideString(Kernel32Dll), 2);
	FARPROC pfnProc = GetProcAddress((HMODULE)hFileContent, ExitProcess.c_str());
	PEInformation.Funcs.push_back(std::make_pair((ULONG_PTR)pfnProc, ExitProcess));

	return PEInformation;
}

PEInformation PeReader::GetExportSection64(
	PEInformation& PEInformation)
{
	for (unsigned char Section = 0; Section < PEInformation.ImageFileHeader.NumberOfSections; ++Section)
	{
		const PIMAGE_SECTION_HEADER pCurrentSectionHeader =
			(PIMAGE_SECTION_HEADER)((DWORD64)PEInformation.pImageSectionHeader + Section * sizeof(IMAGE_SECTION_HEADER));

		if (PEInformation.x64.ImageOptionalHeader64.DataDirectory[0].VirtualAddress >= pCurrentSectionHeader->VirtualAddress
			&& PEInformation.x64.ImageOptionalHeader64.DataDirectory[0].VirtualAddress < pCurrentSectionHeader->VirtualAddress + pCurrentSectionHeader->Misc.VirtualSize)
			PEInformation.pImageImportHeader = pCurrentSectionHeader;
	}
	return PEInformation;
}

PEInformation PeReader::ParseImage64(
	PEInformation& PEInformation)
{
	PEInformation.x64.pImageNTHeader64 = (PIMAGE_NT_HEADERS64)((DWORD_PTR)PEInformation.pImageDOSHeaderOfPe + PEInformation.pImageDOSHeaderOfPe->e_lfanew);
	if (PEInformation.x64.pImageNTHeader64 == nullptr) { return PEInformation; }

	PEInformation.ImageFileHeader = PEInformation.x64.pImageNTHeader64->FileHeader; PEInformation.x64.ImageOptionalHeader64 = PEInformation.x64.pImageNTHeader64->OptionalHeader;

	PEInformation.pImageSectionHeader = 
		(PIMAGE_SECTION_HEADER)((DWORD_PTR)PEInformation.x64.pImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + PEInformation.ImageFileHeader.SizeOfOptionalHeader);
	if (PEInformation.pImageSectionHeader == nullptr) { return PEInformation; }

	PEInformation.FirstSize = PEInformation.x64.pImageNTHeader64->OptionalHeader.ImageBase;

	PEInformation = GetSections64(PEInformation);

	if (PEInformation.pImageImportHeader == nullptr) { puts("\n[-] An error when trying to retrieve PE imports !\n"); return PEInformation; }

	uint64_t dRawOffset = (uint64_t)PEInformation.pImageDOSHeaderOfPe + PEInformation.pImageImportHeader->PointerToRawData;

	PEInformation.pImageImportDescriptor = PIMAGE_IMPORT_DESCRIPTOR(
		(uint64_t(dRawOffset + (PEInformation.x64.ImageOptionalHeader64.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) - 
			PEInformation.pImageImportHeader->VirtualAddress)));

	if (PEInformation.pImageImportDescriptor == NULL) { puts("\n[-] An error occurred when trying to retrieve PE imports descriptor!\n"); return PEInformation; }

	PEInformation = GetImports64(PEInformation, dRawOffset); PEInformation = GetExportSection64(PEInformation);
	//TO DO:
	// NEED TO FIX BUGS WITH PACKED SAMPLES IN GetImports64

	std::wcout << std::endl << L"\tEXE NAME: " << PathToCurrentDebugging.filename().wstring() << std::endl;

	if (Start)
	{
		//const std::wstring CommandArgs = 
		//	L" -AUTH_LOGIN=unused -AUTH_PASSWORD=06d37181dacc44729c6af28845bfd1d6 -AUTH_TYPE=exchangecode -epicapp=Kakopo -epicenv=Prod -epicovt=\"E:/JustCause4/.egstore/e86e262415f44532bc9e365648ce26ff/ba8062bdcc1342c0b78743e3c624257511fa5d6106524a3fa600b111ac243f58.ovt\" -EpicPortal  -epicusername=\"Nitruha-G\" -epicuserid=e86e262415f44532bc9e365648ce26ff -epiclocale=en -epicsandboxid=ba8062bdcc1342c0b78743e3c6242575";
			CreateProcessW(PathToCurrentDebugging.wstring().c_str(), 
			NULL, NULL, NULL, FALSE, CREATE_SUSPENDED,
			NULL, NULL, &PEInformation.StartupInfo, &PEInformation.ProcessInfo);
	}

	return PEInformation;
}

PEInformation PeReader::Pe(
	PEInformation& PEInformation)
{
	hPeFileContent = GetFileContent();
	if (hPeFileContent == INVALID_HANDLE_VALUE)
	{
		puts("[-] hPeFileContent contains INVALID_HANDLE_VALUE !\n");
		return PEInformation;
	}

	pImageDOSHeaderOfPe = (PIMAGE_DOS_HEADER)hPeFileContent;
	if (pImageDOSHeaderOfPe == nullptr)
	{
		puts("[-] pImageDOSHeaderOfPe contains nullptr !\n");
		VirtualFree(hPeFileContent, 0, MEM_RELEASE);
		CloseHandle(hPeFileContent);
		return PEInformation;
	}

	pImageNTHeaderOfPe = (PIMAGE_NT_HEADERS)((DWORD_PTR)hPeFileContent + pImageDOSHeaderOfPe->e_lfanew);
	if (pImageNTHeaderOfPe == nullptr)
	{
		puts("[-] pImageNTHeaderOfPe contains nullptr !\n");
		VirtualFree(hPeFileContent, 0, MEM_RELEASE);
		CloseHandle(hPeFileContent);
		return PEInformation;
	}

	if (pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PEInformation.pImageDOSHeaderOfPe = pImageDOSHeaderOfPe;
		PEInformation.pImageNTHeaderOfPe = pImageNTHeaderOfPe;
		PEInformation = ParseImage64(PEInformation);
	}
	else if (pImageNTHeaderOfPe->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{

	}

	return PEInformation;
}