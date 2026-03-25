// =============================================================================
// SharedDefs.h — PATCH: Add rootkit detection opcodes
//
// 1. In the IRP_MAJOR_OP enum add these four entries after IRP_USERMODE_HOOK_EVENT:
//
//     IRP_ROOTKIT_SSDT_HOOK       = 21,
//     IRP_ROOTKIT_HIDDEN_PROCESS  = 22,
//     IRP_ROOTKIT_HIDDEN_DRIVER   = 23,
//     IRP_ROOTKIT_KERNEL_HOOK     = 24,
//
// 2. In the COM_MESSAGE_TYPE enum add after MESSAGE_ADD_BLOCK_PATH:
//
//     MESSAGE_RUN_ROOTKIT_SCAN,   // On-demand: trigger RootkitDetectorRunScan()
//
// 3. Add these #defines anywhere after the existing IRP_USERMODE_HOOK_EVENT define.
//    (RootkitDetector.cpp uses them as ULONG constants, not enum casts.)
// =============================================================================

#define IRP_ROOTKIT_SSDT_HOOK       21U
#define IRP_ROOTKIT_HIDDEN_PROCESS  22U
#define IRP_ROOTKIT_HIDDEN_DRIVER   23U
#define IRP_ROOTKIT_KERNEL_HOOK     24U

// =============================================================================
// KERNEL_EVENT_INFO fields used by rootkit findings:
//
//   EventType        = IRP_ROOTKIT_* above
//   SourceProcessId  = PID of the hidden process (0 for SSDT/driver/hook events)
//   MemoryAddress    = hooked/hidden VA
//   MemorySize       = image size (hidden-driver events only)
//   ObjectName       = human-readable:
//                        SSDT:    L"SSDT[N]=0x<addr> outside ntoskrnl"
//                        Process: L"<ImageFileName>" or L"<hidden>"
//                        Driver:  L"\Driver\<name>"
//                        Hook:    L"<ExportName>"
//   RawArgument1     = SSDT: table index; hidden process: PID;
//                      inline hook: redirect target address
//   RawArgument2     = SSDT: raw encoded entry; others: 0
// =============================================================================
