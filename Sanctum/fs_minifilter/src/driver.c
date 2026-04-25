#include "flt.h"
#include "comms.h"
#include "globals.h"

#define FLT_TAG 'xulF'

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[i] Unloading Sanctum Minifilter...\n"));
    
    // Cleanup Comms
    UninitComms();
    
    // Unregister filter
    if (g_filter != NULL) {
        FltUnregisterFilter(g_filter);
        g_filter = NULL;
    }
}

NTSTATUS DriverEntry(
	PDRIVER_OBJECT driver_object, 
	PUNICODE_STRING registry_path
) {

	UNREFERENCED_PARAMETER(registry_path);

#if DBG
    driver_object->DriverUnload = DriverUnload;
#else
    driver_object->DriverUnload = NULL;
#endif

	//
	// Register the minifilter with the OS
	//
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[i] Starting file system minifilter..!\n"));
	NTSTATUS status = FltRegisterFilter(
		driver_object,
		&g_filter_registration,
		&g_filter
	);

	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-] Failed to register the minifilter. %#x!\n", status));
		return status;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Minifilter was registered!\n"));

	//
	// Start the minifilter
	//
	status = FltStartFiltering(g_filter);
	if (!NT_SUCCESS(status)) {
		KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[-] Failed to start filtering. %#x!\n", status));
		FltUnregisterFilter(g_filter);
		return status;
	}

	//
	// Initialise the device comms
	//
	status = InitComms(g_filter);

	return status;
}