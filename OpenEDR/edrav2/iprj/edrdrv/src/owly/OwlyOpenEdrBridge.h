#pragma once

#include <fltKernel.h>

// Owlyshield shared telemetry model.
// In the integrated build this header should resolve to the uploaded SharedDefs.h.
#include "SharedDefs.h"

namespace cmd {
namespace owly {

// Mirrors an Owlyshield DRIVER_MESSAGE into the OpenEDR/edrdrv LBVS fltport stream.
// This is intentionally best-effort: it must never break the original producer path.
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS MirrorDriverMessageToOpenEdr(_In_ const DRIVER_MESSAGE* Message);

// Converts an Owlyshield IRP_MAJOR_OP / FILE_CHANGE_INFO pair to an OpenEDR SysmonEvent id.
// Exposed for unit tests and diagnostics.
USHORT MapOwlyMessageToOpenEdrEventId(_In_ UCHAR IrpOp, _In_ UCHAR FileChange);

} // namespace owly
} // namespace cmd
