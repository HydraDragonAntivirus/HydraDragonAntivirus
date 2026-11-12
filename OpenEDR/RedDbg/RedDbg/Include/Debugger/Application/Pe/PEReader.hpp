#include "PEInformation.hpp"

#include <vector>
#include <string>
#include <Windows.h>
#include <filesystem> 

class PeReader
{
private:
	const std::string ExitProcess = "ExitProcess";
	const std::string Kernel32Dll = "kernel32.dll";
private:
	HANDLE hFileContent;
	HANDLE hPeFileContent;
private:
	PIMAGE_DOS_HEADER pImageDOSHeaderOfPe;
	PIMAGE_NT_HEADERS pImageNTHeaderOfPe;
private:
	HANDLE inline GetFileContent();
	HANDLE inline GetContentOfDll(
		const std::wstring& DllName,
		uint8_t Method);
	PEInformation ParseImageOfDll64(
		const std::wstring& DllName,
		PEInformation& PEInformation);
	PEInformation SectionCopierOfDll64(
		PEInformation& PEInformation,
		std::vector<LPVOID>& BAs, 
		std::vector<size_t>& BAsSize);
	PEInformation ParseImage64(
		PEInformation& PEInformation);
	PEInformation ParseImageOfDll32(
		const std::wstring& DllName,
		PEInformation& PEInformation);
	PEInformation GetSectionsOfDll64(
		PEInformation& PEInformation);
	PEInformation GetSections64(
		PEInformation& PEInformation);
	PEInformation GetExportSection64(
		PEInformation& PEInformation);
	PEInformation GetImports64(
		PEInformation& PEInformation,
		uint64_t dRawOffset);
	PEInformation GetImportsOfDll64(
		PEInformation& PEInformation,
		uint64_t dRawOffset,
		const std::wstring& DllName);
public:
	PEInformation Dll(
		const std::wstring DllName,
		PEInformation& PEInformation);
	PEInformation Pe(
		PEInformation& PEInformation);
	std::filesystem::path PathToCurrentDebugging;
	bool Start;
};