#pragma once

#include <ntifs.h>

#if defined(_M_AMD64)
#include "../HyperDbg/hyperdbg/hyperhv/pch.h"
#include "../HyperDbg/hyperdbg/hyperhv/header/vmm/vmx/Hv.h"
#include "../HyperDbg/hyperdbg/hyperhv/header/vmm/vmx/Vmx.h"
#endif

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
