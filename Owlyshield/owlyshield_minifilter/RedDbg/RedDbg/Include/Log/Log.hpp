#pragma once
#include <ntddk.h>

#define IOCTL_REGISTER_EVENT \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_RETURN_IRP_PENDING_PACKETS_AND_DISALLOW_IOCTL \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK_SUCCESS \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_EP_BREAKPOINT \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BREAKPOINT_PASS \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_WRITE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_CLOSE_FILE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_SERIAL_CHECK \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_PE_ANALYZE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_PE_ANALYZE_FIRST_SIZE \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_PE_ANALYZE_SIZE_OF_ALL \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS )

typedef enum {
	IRP_BASED,
	EVENT_BASED
} NOTIFY_TYPE;

typedef struct _REGISTER_EVENT
{
	NOTIFY_TYPE Type;
	HANDLE  hEvent;

} REGISTER_EVENT, * PREGISTER_EVENT;

enum OperantionCodes {
	OPERATION_LOG_INFO_MESSAGE = 1,
	OPERATION_LOG_WARNING_MESSAGE,
	OPERATION_LOG_ERROR_MESSAGE,
	OPERATION_LOG_NON_IMMEDIATE_MESSAGE,
	OPERATION_LOG_TRACE_MESSAGE,
	OPERATION_LOG_BREAKPOINT_MESSAGE
};

typedef struct _NOTIFY_RECORD {
	NOTIFY_TYPE     Type;
	union {
		PKEVENT     Event;
		PIRP        PendingIrp;
	} Message;
	KDPC            Dpc;
	BOOLEAN			CheckSvmRootMessagePool; // Set so that notify callback can understand where to check (Vmx root or Vmx non-root)
} NOTIFY_RECORD, * PNOTIFY_RECORD;

// Message buffer structure
typedef struct _BUFFER_HEADER {
	UINT32 OpeationNumber;	// Operation ID to user-mode
	UINT32 BufferLength;	// The actual length
	BOOLEAN Valid;			// Determine whether the buffer was valid to send or not
} BUFFER_HEADER, * PBUFFER_HEADER;

// Core-specific buffers
typedef struct _LOG_BUFFER_INFORMATION {

	PVOID BufferStartAddress;						// Start address of the buffer
	PVOID BufferEndAddress;						// End address of the buffer

	PVOID BufferForMultipleNonImmediateMessage;	// Start address of the buffer for accumulating non-immadiate messages
	UINT32 CurrentLengthOfNonImmBuffer;				// the current size of the buffer for accumulating non-immadiate messages


	KSPIN_LOCK BufferLock;							// SpinLock to protect access to the queue
	KSPIN_LOCK BufferLockForNonImmMessage;			// SpinLock to protect access to the queue of non-imm messages

	UINT32 CurrentIndexToSend;						// Current buffer index to send to user-mode
	UINT32 CurrentIndexToWrite;						// Current buffer index to write new messages

} LOG_BUFFER_INFORMATION, * PLOG_BUFFER_INFORMATION;

enum Restrictions {
	MaximumPacketsCapacity = 1000,//1000
	PacketChunkSize = 1000,//1000
	UsermodeBufferSize = sizeof(UINT32) + PacketChunkSize + 1,
	LogBufferSize = MaximumPacketsCapacity * (PacketChunkSize + sizeof(_BUFFER_HEADER)),

	SIZEOF_REGISTER_EVENT = sizeof(REGISTER_EVENT),

	DbgPrintLimitation = 512
};