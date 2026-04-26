//
// edrav2.edrdrv project
//
// Author: Yury Podpruzhnikov (29.01.2019)
// Reviewer: Denis Bogdanov (21.02.2019)
//
///
/// @file Driver IOCTL
///
/// @addtogroup edrdrv
/// @{
#pragma once

namespace cmd {
namespace drvioctl {

///
/// Initialization.
///
/// @return The function returns NTSTATUS of the operation.
///
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS initialize();

///
/// Finalization.
///
void finalize();

///
/// Returns TRUE only when the current caller is the Sanctum broker running as
/// Antimalware ProtectedLight. This is the mandatory gate for privileged
/// OpenEDR driver activation and configuration IOCTLs.
///
BOOLEAN isCurrentCallerSanctumController();

///
/// Returns STATUS_SUCCESS only for the Sanctum AntimalwareLight broker.
/// Use before every state-changing IOCTL handler, including START and STOP.
///
NTSTATUS requireSanctumController();

// Internal interface for device dispatcher
namespace detail {

//
// Callback for check device support
//
bool isSupportDevice(_DEVICE_OBJECT * pDeviceObject);

//
// Process IRP of own device 
//
NTSTATUS dispatchIrp(_DEVICE_OBJECT * pDeviceObject, _IRP * pIrp);

} // namespace detail

} // namespace drvioctl
} // namespace cmd
/// @}
