#pragma once

#include <fltKernel.h>

//
// ProtectBoot.h
//
// Include this header from the file that owns your FLT_OPERATION_REGISTRATION
// table.
//

#ifdef __cplusplus
extern "C" {
#endif

FLT_PREOP_CALLBACK_STATUS
ProtectBoot_PreDeviceControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    );

#ifdef __cplusplus
}
#endif
