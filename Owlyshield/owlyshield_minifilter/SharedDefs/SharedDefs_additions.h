// =============================================================================
// SharedDefs.h — ROOTKIT DETECTION ADDITIONS
// Add these definitions to the existing SharedDefs.h.
// =============================================================================

// ---------------------------------------------------------------------------
// New IRP_OP codes for rootkit detection findings.
// Place these alongside the existing IRP_MAJOR_OP enum entries.
// ---------------------------------------------------------------------------
//
// In the IRP_MAJOR_OP enum, after IRP_USERMODE_HOOK_EVENT = 20, add:
//
//   IRP_ROOTKIT_SSDT_HOOK      = 21,  // SSDT entry points outside ntoskrnl
//   IRP_ROOTKIT_HIDDEN_PROCESS = 22,  // Process in PspCidTable but not EPROCESS list
//   IRP_ROOTKIT_HIDDEN_DRIVER  = 23,  // Driver not in PsLoadedModuleList
//   IRP_ROOTKIT_KERNEL_HOOK    = 24,  // Inline hook on monitored ntoskrnl export
//
// As #defines (for use in RootkitDetector.cpp without enum cast):

#define IRP_ROOTKIT_SSDT_HOOK       21U
#define IRP_ROOTKIT_HIDDEN_PROCESS  22U
#define IRP_ROOTKIT_HIDDEN_DRIVER   23U
#define IRP_ROOTKIT_KERNEL_HOOK     24U

// ---------------------------------------------------------------------------
// New COM_MESSAGE_TYPE for on-demand scans from user mode.
// Add to the existing COM_MESSAGE_TYPE enum:
//
//   MESSAGE_RUN_ROOTKIT_SCAN,   // Trigger immediate RootkitDetectorRunScan()
//
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// KERNEL_EVENT_INFO fields used by rootkit events:
//
//   EventType       = IRP_ROOTKIT_* above
//   SourceProcessId = PID of hidden process (0 for driver/SSDT events)
//   MemoryAddress   = hooked/hidden address
//   MemorySize      = image size (for hidden driver events)
//   ObjectName      = human-readable description:
//                       SSDT:   L"SSDT[N]=0x<addr> outside ntoskrnl"
//                       Process: L"<ImageFileName>" or L"<hidden>"
//                       Driver:  L"\Driver\<name>"
//                       Hook:    L"<ExportName>"
//   RawArgument1    = for SSDT: index; for hidden process: PID;
//                     for kernel hook: target address (hook redirect)
//   RawArgument2    = for SSDT: raw encoded entry
// ---------------------------------------------------------------------------
