//
// edrav2.edrdrv project
//
// Quarantine functionality for malicious files
// Ported from Owlyshield minifilter
//
/// @file Quarantine operations implementation
///
/// @addtogroup edrdrv
/// @{

#include "common.h"
#include "quarantine.h"

namespace cmd {
namespace quarantine {

//
// Global quarantine path storage
//
UNICODE_STRING g_quarantinePath = { 0 };
ERESOURCE g_quarantinePathLock;

///
/// @brief Initialize quarantine subsystem
///
NTSTATUS initialize()
{
	IFERR_RET(ExInitializeResourceLite(&g_quarantinePathLock));
	
	// Set default quarantine path: C:\Quarantine
	WCHAR defaultPath[] = L"\\??\\C:\\Quarantine";
	UNICODE_STRING defaultQuarantinePath;
	RtlInitUnicodeString(&defaultQuarantinePath, defaultPath);
	
	return setQuarantinePath(&defaultQuarantinePath);
}

///
/// @brief Cleanup quarantine subsystem
///
void finalize()
{
	ExEnterCriticalRegionAndAcquireResourceExclusive(&g_quarantinePathLock);
	
	if (g_quarantinePath.Buffer != NULL)
	{
		ExFreePoolWithTag(g_quarantinePath.Buffer, c_nQuarantinePathTag);
		g_quarantinePath.Buffer = NULL;
		g_quarantinePath.Length = 0;
		g_quarantinePath.MaximumLength = 0;
	}
	
	ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
	ExDeleteResourceLite(&g_quarantinePathLock);
}

///
/// @brief Set the quarantine directory path
///
NTSTATUS setQuarantinePath(_In_ PUNICODE_STRING path)
{
	if (path == NULL || path->Buffer == NULL || path->Length == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}
	
	// Allocate new buffer
	PWCHAR newBuffer = (PWCHAR)ExAllocatePoolWithTag(
		NonPagedPool,
		path->Length + sizeof(WCHAR), // +1 for null terminator
		c_nQuarantinePathTag);
	
	if (newBuffer == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	
	RtlCopyMemory(newBuffer, path->Buffer, path->Length);
	newBuffer[path->Length / sizeof(WCHAR)] = L'\0';
	
	ExEnterCriticalRegionAndAcquireResourceExclusive(&g_quarantinePathLock);
	
	// Free old buffer if exists
	if (g_quarantinePath.Buffer != NULL)
	{
		ExFreePoolWithTag(g_quarantinePath.Buffer, c_nQuarantinePathTag);
	}
	
	// Set new path
	g_quarantinePath.Buffer = newBuffer;
	g_quarantinePath.Length = path->Length;
	g_quarantinePath.MaximumLength = path->Length + sizeof(WCHAR);
	
	ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
	
	return STATUS_SUCCESS;
}

///
/// @brief Get the current quarantine directory path
///
NTSTATUS getQuarantinePath(_Out_ PUNICODE_STRING* path)
{
	if (path == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	
	ExEnterCriticalRegionAndAcquireResourceShared(&g_quarantinePathLock);
	*path = &g_quarantinePath;
	ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
	
	return STATUS_SUCCESS;
}

///
/// @brief Check if a path is within the quarantine directory
///
BOOLEAN isPathInQuarantineDir(_In_ PUNICODE_STRING path)
{
	if (path == NULL || path->Buffer == NULL || path->Length == 0)
	{
		return FALSE;
	}
	
	ExEnterCriticalRegionAndAcquireResourceShared(&g_quarantinePathLock);
	
	if (g_quarantinePath.Buffer == NULL || g_quarantinePath.Length == 0)
	{
		ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
		return FALSE;
	}
	
	// Check if path starts with quarantine directory
	BOOLEAN result = FALSE;
	if (path->Length >= g_quarantinePath.Length)
	{
		// Case-insensitive comparison
		result = (_wcsnicmp(path->Buffer, g_quarantinePath.Buffer, 
			g_quarantinePath.Length / sizeof(WCHAR)) == 0);
	}
	
	ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
	
	return result;
}

///
/// @brief Delete a file by path
///
NTSTATUS deleteFileByPath(_In_ PUNICODE_STRING filePath)
{
	if (filePath == NULL || filePath->Buffer == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}
	
	OBJECT_ATTRIBUTES objAttributes;
	InitializeObjectAttributes(&objAttributes, filePath, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	return ZwDeleteFile(&objAttributes);
}

///
/// @brief Quarantine a file by moving it to the quarantine directory
///
NTSTATUS quarantineFileByPath(_In_ PUNICODE_STRING filePath)
{
	if (filePath == NULL || filePath->Buffer == NULL || filePath->Length == 0)
	{
		return STATUS_INVALID_PARAMETER;
	}
	
	NTSTATUS status;
	HANDLE sourceHandle = NULL;
	HANDLE destHandle = NULL;
	PFILE_RENAME_INFORMATION renameInfo = NULL;
	ULONG renameInfoSize = 0;
	
	ExEnterCriticalRegionAndAcquireResourceShared(&g_quarantinePathLock);
	
	if (g_quarantinePath.Buffer == NULL || g_quarantinePath.Length == 0)
	{
		ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
		return STATUS_INVALID_PARAMETER;
	}
	
	// Create quarantine directory if it doesn't exist
	OBJECT_ATTRIBUTES objAttribs;
	IO_STATUS_BLOCK ioStatus;
	
	InitializeObjectAttributes(&objAttribs, &g_quarantinePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwCreateFile(&destHandle,
		GENERIC_WRITE | SYNCHRONIZE,
		&objAttribs,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);
	
	if (!NT_SUCCESS(status))
	{
		ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
		LOGINFO2("Failed to create quarantine directory: 0x%08X", status);
		return status;
	}
	
	// Open source file with DELETE access
	InitializeObjectAttributes(&objAttribs, filePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	status = ZwOpenFile(&sourceHandle,
		DELETE | SYNCHRONIZE,
		&objAttribs,
		&ioStatus,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT);
	
	if (!NT_SUCCESS(status))
	{
		ZwClose(destHandle);
		ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
		LOGINFO2("Failed to open source file for quarantine: 0x%08X", status);
		return status;
	}
	
	// Extract filename from full path
	UNICODE_STRING filename;
	filename.Buffer = NULL;
	filename.Length = 0;
	filename.MaximumLength = 0;
	
	// Find last backslash
	for (USHORT i = filePath->Length / sizeof(WCHAR); i > 0; i--)
	{
		if (filePath->Buffer[i - 1] == L'\\')
		{
			filename.Buffer = &filePath->Buffer[i];
			filename.Length = filePath->Length - (i * sizeof(WCHAR));
			filename.MaximumLength = filename.Length;
			break;
		}
	}
	
	if (filename.Buffer == NULL)
	{
		// No backslash found, use entire path as filename
		filename = *filePath;
	}
	
	// Allocate FILE_RENAME_INFORMATION structure
	renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + filename.Length;
	renameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePoolWithTag(
		NonPagedPool, renameInfoSize, c_nQuarantineFileTag);
	
	if (renameInfo == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	
	RtlZeroMemory(renameInfo, renameInfoSize);
	renameInfo->ReplaceIfExists = TRUE;
	renameInfo->RootDirectory = destHandle;
	renameInfo->FileNameLength = filename.Length;
	RtlCopyMemory(renameInfo->FileName, filename.Buffer, filename.Length);
	
	// Move file to quarantine directory
	status = ZwSetInformationFile(sourceHandle, &ioStatus, renameInfo,
		renameInfoSize, FileRenameInformation);
	
	if (!NT_SUCCESS(status))
	{
		LOGINFO2("Failed to move file to quarantine: 0x%08X", status);
		goto cleanup;
	}
	
	// Close and reopen the file in quarantine directory to rename it
	ZwClose(sourceHandle);
	sourceHandle = NULL;
	
	// Build new path in quarantine directory
	UNICODE_STRING quarantinedFilePath;
	USHORT newPathLength = g_quarantinePath.Length + sizeof(WCHAR) + filename.Length;
	PWCHAR newPathBuffer = (PWCHAR)ExAllocatePoolWithTag(
		NonPagedPool, newPathLength + sizeof(WCHAR), c_nQuarantineFileTag);
	
	if (newPathBuffer == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	
	RtlZeroMemory(newPathBuffer, newPathLength + sizeof(WCHAR));
	RtlCopyMemory(newPathBuffer, g_quarantinePath.Buffer, g_quarantinePath.Length);
	newPathBuffer[g_quarantinePath.Length / sizeof(WCHAR)] = L'\\';
	RtlCopyMemory(&newPathBuffer[(g_quarantinePath.Length / sizeof(WCHAR)) + 1],
		filename.Buffer, filename.Length);
	
	quarantinedFilePath.Buffer = newPathBuffer;
	quarantinedFilePath.Length = newPathLength;
	quarantinedFilePath.MaximumLength = newPathLength + sizeof(WCHAR);
	
	// Open the quarantined file
	InitializeObjectAttributes(&objAttribs, &quarantinedFilePath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	
	NTSTATUS openQuarantinedStatus = ZwOpenFile(&sourceHandle,
		DELETE | SYNCHRONIZE,
		&objAttribs,
		&ioStatus,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_SYNCHRONOUS_IO_NONALERT);
	
	if (!NT_SUCCESS(openQuarantinedStatus))
	{
		ExFreePoolWithTag(newPathBuffer, c_nQuarantineFileTag);
		status = openQuarantinedStatus;
		goto cleanup;
	}
	
	// Add .quarantined extension
	WCHAR quarantinedExt[] = L".quarantined";
	USHORT extLength = (USHORT)(wcslen(quarantinedExt) * sizeof(WCHAR));
	USHORT finalNameLength = filename.Length + extLength;
	
	// Reallocate rename info for extension
	ExFreePoolWithTag(renameInfo, c_nQuarantineFileTag);
	renameInfoSize = sizeof(FILE_RENAME_INFORMATION) + finalNameLength;
	renameInfo = (PFILE_RENAME_INFORMATION)ExAllocatePoolWithTag(
		NonPagedPool, renameInfoSize, c_nQuarantineFileTag);
	
	if (renameInfo == NULL)
	{
		ExFreePoolWithTag(newPathBuffer, c_nQuarantineFileTag);
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}
	
	RtlZeroMemory(renameInfo, renameInfoSize);
	renameInfo->ReplaceIfExists = TRUE;
	renameInfo->RootDirectory = destHandle;
	renameInfo->FileNameLength = finalNameLength;
	RtlCopyMemory(renameInfo->FileName, filename.Buffer, filename.Length);
	RtlCopyMemory((PUCHAR)renameInfo->FileName + filename.Length,
		quarantinedExt, extLength);
	
	// Rename to add .quarantined extension
	status = ZwSetInformationFile(sourceHandle, &ioStatus, renameInfo,
		renameInfoSize, FileRenameInformation);
	
	ExFreePoolWithTag(newPathBuffer, c_nQuarantineFileTag);
	
	if (!NT_SUCCESS(status))
	{
		LOGINFO2("Failed to add .quarantined extension: 0x%08X", status);
	}
	
cleanup:
	if (renameInfo != NULL)
	{
		ExFreePoolWithTag(renameInfo, c_nQuarantineFileTag);
	}
	
	if (sourceHandle != NULL)
	{
		ZwClose(sourceHandle);
	}
	
	if (destHandle != NULL)
	{
		ZwClose(destHandle);
	}
	
	ExReleaseResourceAndLeaveCriticalRegion(&g_quarantinePathLock);
	
	return status;
}

} // namespace quarantine
} // namespace cmd

/// @}
