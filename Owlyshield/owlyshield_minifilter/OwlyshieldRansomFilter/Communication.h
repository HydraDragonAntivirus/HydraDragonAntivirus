#pragma once

#include <fltKernel.h>
#include <stdio.h>

#ifdef __cplusplus
#include "../SharedDefs/SharedDefs.h"
#include "DriverData.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS InitCommData();

// close the comm handler, close both ports
void CommClose();

BOOLEAN IsCommClosed();

// AMFConnect: Handles user mode application which connects to the driver

NTSTATUS
RWFConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionCookie);

// AMFConnect: handle messages recieved from user mode

NTSTATUS RWFNewMessage(
    IN PVOID PortCookie,
    IN PVOID InputBuffer,
    IN ULONG InputBufferLength,
    OUT PVOID OutputBuffer,
    IN ULONG OutputBufferLength,
    OUT PULONG ReturnOutputBufferLength);

// AMFDissconnect: Handles user mode application which dissconnects from the driver

VOID RWFDissconnect(_In_opt_ PVOID ConnectionCookie);

// Independent hypervisor event queue for VMM bridge (C callable).
BOOLEAN QueueHypervisorEvent(_In_ ULONG RawEventType,
                             _In_opt_z_ PCWSTR EventName,
                             _In_ ULONG_PTR EventArg1,
                             _In_ ULONG_PTR EventArg2);

VOID DrainQueuedHypervisorEvents(_Inout_updates_bytes_(OutputBufferLength) PVOID OutputBuffer,
                                 _In_ ULONG OutputBufferLength,
                                 _Inout_ PULONG ReturnOutputBufferLength);

VOID ResetQueuedHypervisorEvents(VOID);

// ---------------------------------------------------------------------------
// Hook notification device  (\Device\OwlyshieldHook)
//
// InitHookNotifyDevice  — creates the device and installs dispatch wrappers.
//   Call AFTER FltStartFiltering so FltMgr's MajorFunction entries are
//   captured and forwarded correctly.
//
// CleanupHookNotifyDevice — removes the device before driver unload.
//   Call BEFORE FltUnregisterFilter so the saved dispatch pointers remain
//   valid during FltMgr's own cleanup IRPs.
// ---------------------------------------------------------------------------
NTSTATUS InitHookNotifyDevice(_In_ PDRIVER_OBJECT DriverObject);
VOID     CleanupHookNotifyDevice(VOID);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
struct CommHandler {
    //  Server-side communicate ports.
    PFLT_PORT ServerPort;

    //  port for a connection to user-mode
    PFLT_PORT ClientPort;

    //  The filter handle that results from a call to
    PFLT_FILTER Filter;

    //  A flag that indicating that the filter is connected
    BOOLEAN CommClosed;

    //  User process that connected to the port
    ULONG UserProcess;

    CommHandler(PFLT_FILTER Filter) :
        ServerPort(NULL),
        ClientPort(NULL),
        Filter(Filter),
        CommClosed(TRUE),
        UserProcess(0) {}
};

extern CommHandler* commHandle;
#endif
