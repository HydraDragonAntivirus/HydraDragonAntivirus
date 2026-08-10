//
// edrav2.edrdrv project
//
// Author: Denis Shavrovskiy (15.03.2021)
// Reviewer:
//
///
/// @addtogroup kernelinjectlib
/// @{

#include "common.h"
#include <ntimage.h>
#include "petools.hpp"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

namespace cmd {
namespace petools {

[[nodiscard]] inline bool isAddressInRange(const PVOID Address, const PVOID RangeStart, const ULONG RangeSize)
{
	return (Address >= RangeStart) && (Address < Add2Ptr(RangeStart, RangeSize));
}

[[nodiscard]] inline bool equalStrings(__in_ecount_z(MaxCount) const char* String1, __in_ecount_z(MaxCount) const char* String2, __in size_t MaxCount)
{
	return (0 == _strnicmp(String1, String2, MaxCount));
}

[[nodiscard]] PVOID getSystemModuleHandle(const ANSI_STRING& ModuleName)
{
	UNREFERENCED_PARAMETER(ModuleName);

	PAGED_CODE();

	if (nullptr == g_pCommonData->fnZwQuerySystemInformation)
	{
		LOGERROR(STATUS_PROCEDURE_NOT_FOUND, "ZwQuerySystemInformation not found\r\n");
		return nullptr;
	}

	ULONG bufferLength = 0;
	NTSTATUS status = g_pCommonData->fnZwQuerySystemInformation(SystemModuleInformation, &bufferLength, 0, &bufferLength);
	if ((STATUS_BUFFER_TOO_SMALL != status && STATUS_INFO_LENGTH_MISMATCH != status) || (0 == bufferLength))
	{
		LOGERROR(status, "ZwQuerySystemInformation failed\r\n");
		return nullptr;
	}

	cmd::Blob buffer;
	status = buffer.alloc(bufferLength);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to allocate user-memory\r\n");
		return nullptr;
	}

	PRTL_PROCESS_MODULES modules = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer.getData());
	status = g_pCommonData->fnZwQuerySystemInformation(SystemModuleInformation, modules, bufferLength, nullptr);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "ZwQuerySystemInformation failed\r\n");
		return nullptr;
	}

	PVOID imageBase = nullptr;
	PRTL_PROCESS_MODULE_INFORMATION moduleInfo = modules->Modules;
	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		PCCH dllName = (PCCH)Add2Ptr(moduleInfo[i].FullPathName, moduleInfo[i].OffsetToFileName);
		if (!equalStrings(dllName, ModuleName.Buffer, ModuleName.MaximumLength))
			continue;

		imageBase = moduleInfo[i].ImageBase;
		break;
	}

	return imageBase;
}

[[nodiscard]] PVOID getSystemModuleHandle(const UNICODE_STRING& ModuleName)
{
	ANSI_STRING ansiName = { 0 };
	SIZE_T size = RtlUnicodeStringToAnsiSize(&ModuleName);
	
	Blob buffer;
	NTSTATUS status = buffer.alloc(size + 1);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate memory for %wZ\r\n", ModuleName);
		return nullptr;
	}

	RtlInitEmptyAnsiString(&ansiName, reinterpret_cast<PCHAR>(buffer.getData()), static_cast<USHORT>(buffer.getSize()));
	status = RtlUnicodeStringToAnsiString(&ansiName, &ModuleName, FALSE);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to convert DLL name: %wZ\r\n", ModuleName);
		return nullptr;
	}

	return getSystemModuleHandle(ansiName);
}

extern "C" {
NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T NumberOfBytesCopied
);
}

static NTSTATUS SafeReadProcessMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetBuffer, SIZE_T Size)
{
	SIZE_T bytesCopied = 0;
	return MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(), TargetBuffer, Size, KernelMode, &bytesCopied);
}

[[nodiscard]] PVOID getProcAddressInternal(PEPROCESS Process, const PVOID ImageBase, const ANSI_STRING& ProcName)
{
	if (!ImageBase || !ProcName.Buffer || ProcName.Length == 0)
	{
		return nullptr;
	}

	// Parse DOS header
	IMAGE_DOS_HEADER dosHeader;
	NTSTATUS status = SafeReadProcessMemory(Process, ImageBase, &dosHeader, sizeof(IMAGE_DOS_HEADER));
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to read DOS header at %p\r\n", ImageBase);
		return nullptr;
	}

	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid DOS signature at %p (magic: 0x%X)\r\n", ImageBase, dosHeader.e_magic);
		return nullptr;
	}

	// Validate e_lfanew is reasonable
	if (dosHeader.e_lfanew == 0 || dosHeader.e_lfanew > 0x10000000)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid e_lfanew offset: 0x%X\r\n", dosHeader.e_lfanew);
		return nullptr;
	}

	// Read basic NT headers (Signature + FileHeader + Magic) to check 32-bit vs 64-bit
	struct {
		ULONG Signature;
		IMAGE_FILE_HEADER FileHeader;
		USHORT Magic;
	} ntHeaderBasic;

	status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, dosHeader.e_lfanew), &ntHeaderBasic, sizeof(ntHeaderBasic));
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to read basic NT headers\r\n");
		return nullptr;
	}

	if (ntHeaderBasic.Signature != IMAGE_NT_SIGNATURE)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid NT signature at %p (sig: 0x%X)\r\n", Add2Ptr(ImageBase, dosHeader.e_lfanew), ntHeaderBasic.Signature);
		return nullptr;
	}

	IMAGE_DATA_DIRECTORY exportDataDir;

	if (ntHeaderBasic.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		IMAGE_NT_HEADERS32 ntHeaders32;
		status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, dosHeader.e_lfanew), &ntHeaders32, sizeof(IMAGE_NT_HEADERS32));
		if (!NT_SUCCESS(status))
		{
			LOGERROR(status, "Failed to read NT headers 32\r\n");
			return nullptr;
		}
		exportDataDir = ntHeaders32.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (ntHeaderBasic.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		IMAGE_NT_HEADERS64 ntHeaders64;
		status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, dosHeader.e_lfanew), &ntHeaders64, sizeof(IMAGE_NT_HEADERS64));
		if (!NT_SUCCESS(status))
		{
			LOGERROR(status, "Failed to read NT headers 64\r\n");
			return nullptr;
		}
		exportDataDir = ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid NT headers magic: 0x%X\r\n", ntHeaderBasic.Magic);
		return nullptr;
	}

	// Validate and parse export directory
	if (exportDataDir.VirtualAddress == 0 || exportDataDir.Size == 0)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "No export directory for image %p\r\n", ImageBase);
		return nullptr;
	}

	if (exportDataDir.VirtualAddress > 0x10000000 || exportDataDir.Size > 0x1000000)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory RVA/Size out of bounds (RVA: 0x%X, Size: 0x%X)\r\n",
			exportDataDir.VirtualAddress, exportDataDir.Size);
		return nullptr;
	}

	IMAGE_EXPORT_DIRECTORY exportDirectory;
	status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, exportDataDir.VirtualAddress), &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY));
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to read export directory\r\n");
		return nullptr;
	}

	if (exportDirectory.AddressOfNames == 0 ||
		exportDirectory.AddressOfNameOrdinals == 0 ||
		exportDirectory.AddressOfFunctions == 0)
	{
		LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory has null RVAs\r\n");
		return nullptr;
	}

	ULONG nameCount = exportDirectory.NumberOfNames;
	if (nameCount == 0)
	{
		return nullptr;
	}

	if (nameCount > 65536)
	{
		nameCount = 65536;
	}

	ULONG* nameTable = static_cast<ULONG*>(ExAllocatePoolWithTag(PagedPool, nameCount * sizeof(ULONG), 'tpeP'));
	if (!nameTable)
	{
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate memory for name table\r\n");
		return nullptr;
	}

	status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, exportDirectory.AddressOfNames), nameTable, nameCount * sizeof(ULONG));
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(nameTable, 'tpeP');
		LOGERROR(status, "Failed to read name table\r\n");
		return nullptr;
	}

	USHORT* ordinalTable = static_cast<USHORT*>(ExAllocatePoolWithTag(PagedPool, nameCount * sizeof(USHORT), 'tpeP'));
	if (!ordinalTable)
	{
		ExFreePoolWithTag(nameTable, 'tpeP');
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate memory for ordinal table\r\n");
		return nullptr;
	}

	status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, exportDirectory.AddressOfNameOrdinals), ordinalTable, nameCount * sizeof(USHORT));
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(ordinalTable, 'tpeP');
		ExFreePoolWithTag(nameTable, 'tpeP');
		LOGERROR(status, "Failed to read ordinal table\r\n");
		return nullptr;
	}

	char* nameBuf = static_cast<char*>(ExAllocatePoolWithTag(PagedPool, ProcName.Length + 1, 'npeP'));
	if (!nameBuf)
	{
		LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "Failed to allocate memory for name buffer\r\n");
		ExFreePoolWithTag(ordinalTable, 'tpeP');
		ExFreePoolWithTag(nameTable, 'tpeP');
		return nullptr;
	}

	PVOID resultAddress = nullptr;

	for (ULONG hintIndex = 0; hintIndex < nameCount; hintIndex++)
	{
		RtlZeroMemory(nameBuf, ProcName.Length + 1);
		status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, nameTable[hintIndex]), nameBuf, ProcName.Length + 1);
		if (!NT_SUCCESS(status))
			continue;

		if (nameBuf[ProcName.Length] == '\0' && strlen(nameBuf) == ProcName.Length && equalStrings(nameBuf, ProcName.Buffer, ProcName.Length))
		{
			USHORT ordinal = ordinalTable[hintIndex];
			if (ordinal >= exportDirectory.NumberOfFunctions)
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Ordinal %u exceeds function count %lu\r\n", ordinal, exportDirectory.NumberOfFunctions);
				break;
			}

			ULONG functionRVA = 0;
			status = SafeReadProcessMemory(Process, Add2Ptr(ImageBase, exportDirectory.AddressOfFunctions + ordinal * sizeof(ULONG)), &functionRVA, sizeof(ULONG));
			if (!NT_SUCCESS(status))
			{
				LOGERROR(status, "Failed to read function RVA\r\n");
				break;
			}

			resultAddress = Add2Ptr(ImageBase, functionRVA);
			break;
		}
	}

	ExFreePoolWithTag(nameBuf, 'npeP');
	ExFreePoolWithTag(ordinalTable, 'tpeP');
	ExFreePoolWithTag(nameTable, 'tpeP');
	return resultAddress;
}

[[nodiscard]] PVOID getProcAddress(const PVOID ImageBase, const ANSI_STRING& ProcName)
{
	return getProcAddressInternal(PsGetCurrentProcess(), ImageBase, ProcName);
}

[[nodiscard]] PVOID getProcAddressForProcess(const ULONG ProcessId, const PVOID ImageBase, const ANSI_STRING& ProcName)
{
	NT_ASSERT(ARGUMENT_PRESENT(ImageBase) && ProcName.Buffer != nullptr && ProcName.Length != 0);

	PEPROCESS process = nullptr;
	NTSTATUS status = PsLookupProcessByProcessId(UlongToHandle(ProcessId), &process);
	if (!NT_SUCCESS(status))
	{
		LOGERROR(status, "Failed to lookup process %lu\r\n", ProcessId);
		return nullptr;
	}

	PVOID result = getProcAddressInternal(process, ImageBase, ProcName);

	ObDereferenceObject(process);
	return result;
}

} // namespace petools
} // namespace cmd

/// @}