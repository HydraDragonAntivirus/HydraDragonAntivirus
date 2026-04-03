#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOLEAN
OwlyAmdVmmShouldUseBackend(VOID);

NTSTATUS
OwlyAmdVmmInitialize(_Out_opt_ UINT32 *LastError);

VOID
OwlyAmdVmmUninitialize(VOID);

#ifdef __cplusplus
}
#endif
