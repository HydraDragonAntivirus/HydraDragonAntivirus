#pragma once

#include <fltKernel.h>
#include "SharedDefs.h"

#ifndef IOCTL_OWLY_COMPAT_MESSAGE
#define IOCTL_OWLY_COMPAT_MESSAGE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

namespace cmd {
namespace owly {

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS ProcessCompatMessage(
    _In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

} // namespace owly
} // namespace cmd
