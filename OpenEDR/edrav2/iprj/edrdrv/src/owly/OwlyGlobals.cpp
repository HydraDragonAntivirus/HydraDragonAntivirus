#include <fltKernel.h>

// Regedit.cpp imports this symbol. FSfilter.cpp used to define it, but
// FSfilter.cpp is intentionally removed from the integrated OpenEDR build.
PDEVICE_OBJECT g_DeviceObject = nullptr;
