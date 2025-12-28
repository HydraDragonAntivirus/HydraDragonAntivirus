#include "Driver.h"

#define SELF_DEFENSE_PIPE_NAME L"\\Device\\NamedPipe\\Global\\self_defense_alerts"

// Track if pipe is available (to avoid log spam)
static BOOLEAN g_PipeAvailable = FALSE;
static BOOLEAN g_PipeUnavailableLogged = FALSE;

// Shared pipe alert function with retry logic
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
            // Log once when pipe becomes available
            if (!g_PipeAvailable)
            {
                DbgPrint("[SendAlertToPipe] Pipe connection established to user-mode listener\r\n");
                g_PipeAvailable = TRUE;
                g_PipeUnavailableLogged = FALSE;
            }

            // Successfully opened pipe, now write the alert
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
