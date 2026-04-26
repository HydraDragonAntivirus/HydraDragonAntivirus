
#ifndef CXX_FILEPROTECTX64_H
#define CXX_FILEPROTECTX64_H

#include <ntifs.h>
#include <ntddk.h>
#include <devioctl.h>
#include <ntstrsafe.h>
#include <wdm.h>

// File-object callbacks are registered only when supported by the OS.
// Do not patch OBJECT_TYPE internals to force SupportsObjectCallbacks.
OB_PREOP_CALLBACK_STATUS PreCallBack(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

NTSTATUS ProtectFileByObRegisterCallbacks();

#endif
