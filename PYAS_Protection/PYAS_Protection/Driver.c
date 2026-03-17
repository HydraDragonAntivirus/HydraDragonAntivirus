#include "Driver.h"

#define SELF_DEFENSE_PIPE_NAME L"\\Device\\NamedPipe\\Global\\self_defense_alerts"

// Track if pipe is available (to avoid log spam)
static BOOLEAN g_PipeAvailable = FALSE;
static BOOLEAN g_PipeUnavailableLogged = FALSE;

// Shared pipe alert function with retry logic

// --- Helper: Validate Pipe Server Process ---
static BOOLEAN IsValidPipeServerProcess(HANDLE PipeHandle)
{
    NTSTATUS status;
    IO_STATUS_BLOCK ioStatus;
    FILE_PROCESS_IDS_USING_FILE_INFORMATION procIds = { 0 };
    BOOLEAN isValid = FALSE;
    HANDLE serverProcHandle = NULL;
    ULONG returnLength = 0;
    PUNICODE_STRING imagePath = NULL;
    
    // 1. Get process IDs using the pipe (should just be the server and us)
    status = ZwQueryInformationFile(
        PipeHandle,
        &ioStatus,
        &procIds,
        sizeof(procIds),
        FileProcessIdsUsingFileInformation
    );
    
    // Only proceed if exactly one other process (the server) has it open, or we can get list
    if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH) {
        return FALSE; // Can't verify, deny by default
    }
    
    // Allocate space for the process IDs list (it's dynamic)
    ULONG listSize = sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) + 
                     (sizeof(ULONG_PTR) * 16); // Up to 16 PIDs is plenty
    PFILE_PROCESS_IDS_USING_FILE_INFORMATION pProcIds = 
        (PFILE_PROCESS_IDS_USING_FILE_INFORMATION)ExAllocatePool2(POOL_FLAG_PAGED, listSize, 'pPiM');
        
    if (!pProcIds) return FALSE;
        
    status = ZwQueryInformationFile(PipeHandle, &ioStatus, pProcIds, listSize, FileProcessIdsUsingFileInformation);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(pProcIds, 'pPiM');
        return FALSE;
    }
    
    // Find a PID that is not our own (the system process)
    ULONG_PTR serverPid = 0;
    ULONG_PTR currentPid = (ULONG_PTR)PsGetCurrentProcessId();
    for (ULONG i = 0; i < pProcIds->NumberOfProcessIdsInList; i++) {
        if (pProcIds->ProcessIdList[i] != currentPid && pProcIds->ProcessIdList[i] != 0) {
            serverPid = pProcIds->ProcessIdList[i];
            break;
        }
    }
    
    ExFreePoolWithTag(pProcIds, 'pPiM');
    
    if (serverPid == 0) return FALSE; // Server not found
    
    // 2. Open the server process
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;
    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)serverPid;
    clientId.UniqueThread = NULL;
    
    status = ZwOpenProcess(&serverProcHandle, PROCESS_QUERY_INFORMATION, &objAttr, &clientId);
    if (!NT_SUCCESS(status)) return FALSE;
    
    // 3. Query the image path
    status = ZwQueryInformationProcess(serverProcHandle, ProcessImageFileName, NULL, 0, &returnLength);
    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLength == 0) {
        ZwClose(serverProcHandle);
        return FALSE;
    }
    
    imagePath = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_PAGED, returnLength, 'pPiM');
    if (!imagePath) {
        ZwClose(serverProcHandle);
        return FALSE;
    }
    
    status = ZwQueryInformationProcess(serverProcHandle, ProcessImageFileName, imagePath, returnLength, &returnLength);
    ZwClose(serverProcHandle);
    
    if (NT_SUCCESS(status) && imagePath->Buffer != NULL && imagePath->Length > 0) {
        // 4. Validate the path matches exactly C:\Program Files\HydraDragonAntivirus\owlyshield_ransom.exe
        UNICODE_STRING dosName;
        OBJECT_ATTRIBUTES linkObjAttr;
        HANDLE linkHandle;
        UNICODE_STRING driveCDeviceName = {0};

        RtlInitUnicodeString(&dosName, L"\\??\\C:");
        InitializeObjectAttributes(&linkObjAttr, &dosName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        if (NT_SUCCESS(ZwOpenSymbolicLinkObject(&linkHandle, SYMBOLIC_LINK_QUERY, &linkObjAttr)))
        {
            driveCDeviceName.MaximumLength = 256 * sizeof(WCHAR);
            driveCDeviceName.Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_PAGED, driveCDeviceName.MaximumLength, 'pPiM');
            
            if (driveCDeviceName.Buffer)
            {
                if (NT_SUCCESS(ZwQuerySymbolicLinkObject(linkHandle, &driveCDeviceName, NULL)))
                {
                    if (RtlPrefixUnicodeString(&driveCDeviceName, imagePath, TRUE))
                    {
                        UNICODE_STRING remainingPart;
                        remainingPart.Buffer = (PWCH)((PUCHAR)imagePath->Buffer + driveCDeviceName.Length);
                        remainingPart.Length = imagePath->Length - driveCDeviceName.Length;
                        remainingPart.MaximumLength = remainingPart.Length;
                        
                        // Normalize by trimming trailing spaces
                        while (remainingPart.Length >= sizeof(WCHAR) && 
                               remainingPart.Buffer[(remainingPart.Length / sizeof(WCHAR)) - 1] == L' ') {
                            remainingPart.Length -= sizeof(WCHAR);
                        }
                        
                        UNICODE_STRING expectedRemaining;
                        RtlInitUnicodeString(&expectedRemaining, L"\\Program Files\\HydraDragonAntivirus\\hydradragon\\Owlyshield\\Owlyshield Service\\owlyshield_ransom.exe");
                        
                        if (RtlCompareUnicodeString(&remainingPart, &expectedRemaining, TRUE) == 0)
                        {
                            isValid = TRUE;
                        }
                    }
                }
                ExFreePoolWithTag(driveCDeviceName.Buffer, 'pPiM');
            }
            ZwClose(linkHandle);
        }
    }
    
    ExFreePoolWithTag(imagePath, 'pPiM');
    return isValid;
}

NTSTATUS SendAlertToPipe(_In_ PCWSTR Message, _In_ SIZE_T MessageLength)
{
    HANDLE pipeHandle = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING pipeName;
    NTSTATUS status;
    LARGE_INTEGER delay;
    const ULONG MAX_RETRIES = 180;  // Retry for 3 minutes (180 seconds) for slow Python startup
    ULONG attempt;

    RtlInitUnicodeString(&pipeName, SELF_DEFENSE_PIPE_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &pipeName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Retry loop to handle startup race condition (kernel starts before Python)
    for (attempt = 0; attempt < MAX_RETRIES; attempt++)
    {
        status = ZwCreateFile(
            &pipeHandle,
            FILE_WRITE_DATA | SYNCHRONIZE,
            &objAttr,
            &ioStatusBlock,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL,
            0
        );

        if (NT_SUCCESS(status))
        {
            // Validate the pipe server process before writing
            if (!IsValidPipeServerProcess(pipeHandle)) {
                DbgPrint("[SendAlertToPipe] Pipe connected but server process validation failed! Alert dropped to prevent interception.\r\n");
                ZwClose(pipeHandle);
                return STATUS_ACCESS_DENIED; // Security failure: DO NOT send alert
            }

            // Log once when pipe becomes available
            if (!g_PipeAvailable)
            {
                DbgPrint("[SendAlertToPipe] Pipe connection established and verified to legitimate user-mode listener\r\n");
                g_PipeAvailable = TRUE;
                g_PipeUnavailableLogged = FALSE;
            }

            // Successfully opened pipe and validated server, now write the alert
            status = ZwWriteFile(
                pipeHandle,
                NULL,
                NULL,
                NULL,
                &ioStatusBlock,
                (PVOID)Message,
                (ULONG)MessageLength,
                NULL,
                NULL
            );

            ZwClose(pipeHandle);
            return status;
        }

        // If pipe doesn't exist or is unavailable, retry after a short delay
        if (status == STATUS_OBJECT_NAME_NOT_FOUND || status == STATUS_PIPE_NOT_AVAILABLE || status == STATUS_PENDING)
        {
            // Only retry if not the last attempt
            if (attempt < MAX_RETRIES - 1)
            {
                // Wait 1 second before retrying (negative = relative time, units of 100ns)
                // Python startup can be slow, so we give it plenty of time
                delay.QuadPart = -1000LL * 10000LL;  // 1000ms = 1 second
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
                continue;
            }
            else
            {
                // Last attempt failed, log once and silently drop further alerts
                // This is expected during system startup before Python initializes
                if (!g_PipeUnavailableLogged)
                {
                    DbgPrint("[SendAlertToPipe] Unable to connect to user-mode listener after %d retries - alerts will be dropped until pipe is available\r\n", MAX_RETRIES);
                    g_PipeUnavailableLogged = TRUE;
                    g_PipeAvailable = FALSE;
                }
                return STATUS_SUCCESS;
            }
        }
        else
        {
            // Some other error (not pipe-related), return immediately
            return status;
        }
    }

    // Should never reach here, but return success to avoid error spam
    return STATUS_SUCCESS;
}

// Bypass driver signature enforcement
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject)
{
#ifdef _WIN64
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG64 __Undefined1;
		ULONG64 __Undefined2;
		ULONG64 __Undefined3;
		ULONG64 NonPagedDebugInfo;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
		USHORT  LoadCount;
		USHORT  __Undefined5;
		ULONG64 __Undefined6;
		ULONG   CheckSum;
		ULONG   __padding1;
		ULONG   TimeDateStamp;
		ULONG   __padding2;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY listEntry;
		ULONG unknown1;
		ULONG unknown2;
		ULONG unknown3;
		ULONG unknown4;
		ULONG unknown5;
		ULONG unknown6;
		ULONG unknown7;
		UNICODE_STRING path;
		UNICODE_STRING name;
		ULONG   Flags;
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif

	PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	pLdrData->Flags |= 0x20;

	return TRUE;
}

// DriverEntry
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT pDriverObj,
	_In_ PUNICODE_STRING pRegistryString
)
{
	UNREFERENCED_PARAMETER(pRegistryString);

	BypassCheckSign(pDriverObj);
	//pDriverObj->DriverUnload = DriverUnload;

#if _WIN64
	PLDR_DATA_TABLE_ENTRY64 ldr = (PLDR_DATA_TABLE_ENTRY64)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
#else
	PLDR_DATA_TABLE_ENTRY32 ldr = (PLDR_DATA_TABLE_ENTRY32)pDriverObj->DriverSection;
	ldr->Flags |= 0x20;
#endif

	// Initialize core modules
	ProcessDriverEntry();
	FileDriverEntry();
	RegeditDriverEntry();

	return STATUS_SUCCESS;
}

// DriverUnload
//NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT pDriverObj)
//{
//	UNREFERENCED_PARAMETER(pDriverObj);
//
//	// Cleanup other modules
//  ProcessDriverUnload();
//	FileUnloadDriver();
//	RegeditUnloadDriver();
//
//	return STATUS_SUCCESS;
//}
