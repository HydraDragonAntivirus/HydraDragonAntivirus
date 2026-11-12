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

// Late binding of the hypervisor bridge. edrdrv is in a load order group and
// starts before the standalone hypervisor drivers (hyperhv for Intel, RedDbg
// for AMD), so their device usually does not exist yet when the feature host
// is initialized. The bridge is tried again when the service connects to the
// filter port. Does nothing when the bridge is already bound, is compiled out
// or the feature host is not initialized.
_IRQL_requires_(PASSIVE_LEVEL)
VOID RetryHypervisorBridge();

} // namespace owly
} // namespace cmd
