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

[[nodiscard]] PVOID getProcAddress(const PVOID ImageBase, const ANSI_STRING& ProcName)
{
	NT_ASSERT(ARGUMENT_PRESENT(ImageBase) && ProcName.Buffer != nullptr && ProcName.Length != 0);

	__try
	{
		// Validate ImageBase is a valid PE image
		if (!MmIsAddressValid(ImageBase))
		{
			LOGERROR(STATUS_INVALID_PARAMETER, "Invalid ImageBase %p\r\n", ImageBase);
			return nullptr;
		}

		// Manually parse PE headers instead of using RtlImageDirectoryEntryToData for user-mode addresses
		PIMAGE_DOS_HEADER dosHeader = static_cast<PIMAGE_DOS_HEADER>(ImageBase);
		if (!MmIsAddressValid(dosHeader) || dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid DOS header at %p (magic: 0x%X)\r\n", ImageBase,
				MmIsAddressValid(dosHeader) ? dosHeader->e_magic : 0);
			return nullptr;
		}

		// Validate e_lfanew is reasonable (not too large, properly aligned)
		if (dosHeader->e_lfanew == 0 || dosHeader->e_lfanew > 0x10000000 || (dosHeader->e_lfanew & 3) != 0)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid e_lfanew offset: 0x%X\r\n", dosHeader->e_lfanew);
			return nullptr;
		}

		PIMAGE_NT_HEADERS ntHeaders = static_cast<PIMAGE_NT_HEADERS>(Add2Ptr(ImageBase, dosHeader->e_lfanew));
		if (!MmIsAddressValid(ntHeaders))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "NT headers at %p is not accessible\r\n", ntHeaders);
			return nullptr;
		}

		// Validate we can read the full NT headers structure
		if (!MmIsAddressValid(Add2Ptr(ntHeaders, sizeof(IMAGE_NT_HEADERS) - 1)))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "NT headers structure at %p is not fully accessible\r\n", ntHeaders);
			return nullptr;
		}

		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Invalid NT signature at %p (sig: 0x%X)\r\n", ntHeaders, ntHeaders->Signature);
			return nullptr;
		}

		// Get export directory from data directory
		PIMAGE_DATA_DIRECTORY exportDataDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!MmIsAddressValid(exportDataDir) || exportDataDir->VirtualAddress == 0 || exportDataDir->Size == 0)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "No export directory for image %p\r\n", ImageBase);
			return nullptr;
		}

		// Validate export directory RVA is within reasonable bounds (typical DLLs are < 100MB)
		if (exportDataDir->VirtualAddress > 0x10000000 || exportDataDir->Size > 0x1000000)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory RVA/Size out of bounds (RVA: 0x%X, Size: 0x%X)\r\n",
				exportDataDir->VirtualAddress, exportDataDir->Size);
			return nullptr;
		}

		ULONG exportSize = exportDataDir->Size;
		const PIMAGE_EXPORT_DIRECTORY exportDirectory = static_cast<PIMAGE_EXPORT_DIRECTORY>(
			Add2Ptr(ImageBase, exportDataDir->VirtualAddress));

		// Validate export directory is within image bounds
		if (!MmIsAddressValid(exportDirectory))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory at %p is not valid\r\n", exportDirectory);
			return nullptr;
		}

		// Additional validation: check if we can read the export directory structure
		if (!MmIsAddressValid(Add2Ptr(exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY) - 1)))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory structure at %p is not fully accessible\r\n", exportDirectory);
			return nullptr;
		}

		// Validate export table pointers before dereferencing
		if (exportDirectory->AddressOfNames == 0 ||
			exportDirectory->AddressOfNameOrdinals == 0 ||
			exportDirectory->AddressOfFunctions == 0)
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Export directory has null RVAs\r\n");
			return nullptr;
		}

		const PULONG nameTableBase = static_cast<PULONG>(Add2Ptr(ImageBase, exportDirectory->AddressOfNames));
		if (!MmIsAddressValid(nameTableBase))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Name table at %p is not valid\r\n", nameTableBase);
			return nullptr;
		}

		const PUSHORT ordinalsTableBase = static_cast<PUSHORT>(Add2Ptr(ImageBase, exportDirectory->AddressOfNameOrdinals));
		if (!MmIsAddressValid(ordinalsTableBase))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Ordinals table at %p is not valid\r\n", ordinalsTableBase);
			return nullptr;
		}

		const PULONG addressTableBase = static_cast<PULONG>(Add2Ptr(ImageBase, exportDirectory->AddressOfFunctions));
		if (!MmIsAddressValid(addressTableBase))
		{
			LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Address table at %p is not valid\r\n", addressTableBase);
			return nullptr;
		}

		for (ULONG hintIndex = 0; hintIndex < exportDirectory->NumberOfNames; hintIndex++)
		{
			// Validate array access
			if (!MmIsAddressValid(&nameTableBase[hintIndex]))
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Name table entry %lu is not valid\r\n", hintIndex);
				continue;
			}

			const PSTR currentName = static_cast<PSTR>(Add2Ptr(ImageBase, nameTableBase[hintIndex]));
			if (!MmIsAddressValid(currentName))
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Name string at %p is not valid\r\n", currentName);
				continue;
			}

			const ULONG maxLength = PtrOffset(currentName, Add2Ptr(exportDirectory, exportSize));
			if (!equalStrings(currentName, ProcName.Buffer, min(maxLength, ProcName.MaximumLength)))
				continue;

			// Validate ordinal access
			if (!MmIsAddressValid(&ordinalsTableBase[hintIndex]))
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Ordinal entry %lu is not valid\r\n", hintIndex);
				return nullptr;
			}

			const USHORT ordinal = ordinalsTableBase[hintIndex];
			
			// Validate ordinal is within bounds
			if (ordinal >= exportDirectory->NumberOfFunctions)
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Ordinal %u exceeds function count %lu\r\n", ordinal, exportDirectory->NumberOfFunctions);
				return nullptr;
			}

			// Validate function address access
			if (!MmIsAddressValid(&addressTableBase[ordinal]))
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Function address entry %u is not valid\r\n", ordinal);
				return nullptr;
			}

			PVOID functionAddress = Add2Ptr(ImageBase, addressTableBase[ordinal]);
			
			// Validate the resolved function address
			if (!MmIsAddressValid(functionAddress))
			{
				LOGERROR(STATUS_INVALID_IMAGE_FORMAT, "Function address %p is not valid\r\n", functionAddress);
				return nullptr;
			}

			return functionAddress;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LOGERROR(GetExceptionCode(), "getProcAddress exception at ImageBase=%p, ProcName=%Z\r\n", ImageBase, &ProcName);
		return nullptr;
	}
	return nullptr;
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

	PVOID result = nullptr;
	KAPC_STATE apcState;
	
	__try
	{
		// Attach to the target process context to access its memory
		KeStackAttachProcess(process, &apcState);

		__try
		{
			// Now we're in the target process context, memory should be accessible
			result = getProcAddress(ImageBase, ProcName);
		}
		__finally
		{
			// Always detach from the process
			KeUnstackDetachProcess(&apcState);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		LOGERROR(GetExceptionCode(), "Exception in getProcAddressForProcess for PID %lu, ImageBase=%p\r\n", ProcessId, ImageBase);
		result = nullptr;
	}

	ObDereferenceObject(process);
	return result;
}

} // namespace petools
} // namespace cmd

/// @}