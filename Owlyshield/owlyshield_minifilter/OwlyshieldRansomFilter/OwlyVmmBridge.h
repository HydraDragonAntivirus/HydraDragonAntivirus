#pragma once

#include <ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS
OwlyVmmInitialize(VOID);

VOID
OwlyVmmUninitialize(VOID);

#ifdef __cplusplus
}
#endif
