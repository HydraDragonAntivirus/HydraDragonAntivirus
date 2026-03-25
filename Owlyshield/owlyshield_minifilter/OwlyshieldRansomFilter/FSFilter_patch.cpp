// =============================================================================
// FSFilter.cpp — PATCH: Call RootkitDetectorOnDriverEvent on every IRP event
//
// Add this include near the top of FSFilter.cpp:
//   #include "RootkitDetector.h"
//
// In DriverEntry, after RootkitDetectorInitialize(), add:
//   RootkitDetectorSetDeviceObject(g_WorkItemDeviceObject);
//
// Paste the helper function below near the top of the file (before DriverEntry).
// Then call  RkDispatchOnEvent(irpOp)  at the start of the IRP completion path,
// AddRemProcessRoutineCore, and ImageLoadCallback.
// =============================================================================

// ---------------------------------------------------------------------------
// Helper — maps an IRP_MAJOR_OP value to the appropriate RK_TRIGGER and
// fires RootkitDetectorOnDriverEvent.  Safe to call from any IRQL; the
// detector queues a passive-level work item internally.
// ---------------------------------------------------------------------------
static __forceinline VOID
RkDispatchOnEvent(_In_ ULONG IrpOp)
{
    RK_TRIGGER trigger;

    switch (IrpOp)
    {
    // New process created: run full scan — a rootkit may have hidden itself
    // or patched the SSDT between the last scan and this process creation.
    case IRP_PROCESS_CREATE:
        trigger = RK_TRIGGER_FULL;
        break;

    // Kernel-level injection/API events: something is manipulating memory or
    // threads at kernel level — full scan to catch SSDT hooks / hidden objects.
    case IRP_KERNEL_REMOTE_THREAD:   // 13
    case IRP_KERNEL_WRITE_MEMORY:    // 14
    case IRP_KERNEL_PROTECT_MEMORY:  // 15
    case IRP_KERNEL_CREATE_THREAD:   // 16
    case IRP_KERNEL_QUEUE_APC:       // 17
    case IRP_KERNEL_CREATE_SECTION:  // 18
    case IRP_KERNEL_MAP_SECTION:     // 19
    case IRP_USERMODE_HOOK_EVENT:    // 20
        trigger = RK_TRIGGER_FULL;
        break;

    // All other events: cheap SSDT + inline-hook check only.
    default:
        trigger = RK_TRIGGER_LIGHT;
        break;
    }

    RootkitDetectorOnDriverEvent(trigger, IrpOp);
}

// ---------------------------------------------------------------------------
// In ImageLoadCallback, add at the very beginning:
//
//   RootkitDetectorOnDriverEvent(RK_TRIGGER_DRIVER, 0);
//
// This fires a hidden-driver + hidden-process scan whenever a new image is
// loaded (covers cases where a rootkit maps itself and immediately unlinks
// from PsLoadedModuleList).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Integration checklist:
//
// 1. DriverEntry:
//      RootkitDetectorInitialize();                      // resolves imports
//      RootkitDetectorSetDeviceObject(g_WorkItemDeviceObject); // for work items
//
// 2. Main minifilter post-op completion (or wherever IRP events are forwarded
//    to driverData->AddIrpMessage):
//      RkDispatchOnEvent((ULONG)currentIrpOp);
//
// 3. AddRemProcessRoutineCore (process create branch):
//      RkDispatchOnEvent(IRP_PROCESS_CREATE);
//
// 4. ImageLoadCallback (top of function):
//      RootkitDetectorOnDriverEvent(RK_TRIGGER_DRIVER, 0);
//
// 5. FSFilter_HookDeviceControl_UNUSED / IOCTL dispatch for
//    MESSAGE_RUN_ROOTKIT_SCAN COM message type:
//      case MESSAGE_RUN_ROOTKIT_SCAN:
//          RootkitDetectorRunScan();
//          break;
//
// 6. DriverUnload path:
//      RootkitDetectorCleanup();
// ---------------------------------------------------------------------------
