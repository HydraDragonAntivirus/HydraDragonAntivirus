#pragma once

#include <ntifs.h>

#include "pch.h"
#include "vmm/vmx/Hv.h"
#include "vmm/vmx/Vmx.h"

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
