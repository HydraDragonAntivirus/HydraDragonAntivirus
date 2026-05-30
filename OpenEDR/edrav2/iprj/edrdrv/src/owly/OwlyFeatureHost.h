#pragma once

#include <fltKernel.h>

namespace cmd {
namespace owly {

// Initializes Owlyshield feature modules inside edrdrv without registering a
// second minifilter and without creating the legacy \\RWFilter communication port.
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS InitializeFeatureHost(_In_ PDRIVER_OBJECT DriverObject);

_IRQL_requires_(PASSIVE_LEVEL)
VOID FinalizeFeatureHost();

} // namespace owly
} // namespace cmd
