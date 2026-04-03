#pragma once
#include "Log/Log.hpp"
#include "HyperVisor/CommonApi/Spinlock.hpp"

#include <ntddk.h>

class Log {
private:
	Spinlock Spinlock;
private:
	const ULONG POOLTAG = 0x98969693;
private:
	volatile LONG SvmRootLoggingLock;
	volatile LONG SvmRootLoggingLockForNonImmBuffers;
private:
	PNOTIFY_RECORD GlobalNotifyRecord;
	PLOG_BUFFER_INFORMATION MessageBufferInformation;
public:
	bool BufferIsReady = FALSE;
public:
	BOOLEAN LogInitialize();
	BOOLEAN LogSendBuffer(UINT32 OperationCode, PVOID Buffer, UINT32 BufferLength);
	BOOLEAN LogReadBuffer(BOOLEAN IsSvmRoot, PVOID BufferToSaveMessage, UINT32* ReturnedLength);
	BOOLEAN LogCheckForNewMessage(BOOLEAN IsSvmRoot);
	BOOLEAN LogSendMessageToQueue(UINT32 OperationCode, BOOLEAN IsImmediateMessage, BOOLEAN ShowCurrentSystemTime, const char* Fmt, ...);

	VOID LogNotifyUsermodeCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);

	NTSTATUS LogRegisterIrpBasedNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp);
	NTSTATUS LogRegisterEventBasedNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp);
};
