#pragma once

#include <ntifs.h>

#if defined(_M_AMD64)
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#define SCRIPT_ENGINE_KERNEL_MODE
#define HYPERDBG_KERNEL_MODE
#define HYPERDBG_VMM
#define HYPERDBG_HYPEREVADE
#include "SDK/HyperDbgSdk.h"
#include "SDK/modules/VMM.h"
#include "SDK/modules/HyperEvade.h"
#include "SDK/imports/kernel/HyperDbgVmmImports.h"
#include "SDK/imports/kernel/HyperDbgHyperEvade.h"
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
