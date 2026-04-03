#include "Log/Logger.hpp"

#include <ntddk.h>
#include <cstdarg>
#include <stdio.h>

#include "General.hpp"

namespace
{
	static PVOID
	LogAllocateNonPaged(_In_ SIZE_T size, _In_ ULONG tag)
	{
		return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag);
	}
}

BOOLEAN Log::LogInitialize()
{
	MessageBufferInformation = static_cast<struct _LOG_BUFFER_INFORMATION*>(
		LogAllocateNonPaged(sizeof(_LOG_BUFFER_INFORMATION) * 2, 'gLfR'));

	if (!MessageBufferInformation) { KdPrint(("Message %p", MessageBufferInformation)); return FALSE; }

	RtlZeroMemory(MessageBufferInformation, sizeof(_LOG_BUFFER_INFORMATION) * 2);
	GlobalNotifyRecord = NULL;
	SvmRootLoggingLock = 0;
	SvmRootLoggingLockForNonImmBuffers = 0;

	for (int i = 0; i < 2; i++)
	{
		KeInitializeSpinLock(&MessageBufferInformation[i].BufferLock);
		KeInitializeSpinLock(&MessageBufferInformation[i].BufferLockForNonImmMessage);

		MessageBufferInformation[i].BufferStartAddress =
			LogAllocateNonPaged(LogBufferSize, 'bLfR');
		MessageBufferInformation[i].BufferForMultipleNonImmediateMessage =
			LogAllocateNonPaged(PacketChunkSize, 'mLfR');

		if (!MessageBufferInformation[i].BufferStartAddress ||
			!MessageBufferInformation[i].BufferForMultipleNonImmediateMessage)
		{
			return FALSE;
		}
		RtlZeroMemory(MessageBufferInformation[i].BufferStartAddress, LogBufferSize);
		RtlZeroMemory(MessageBufferInformation[i].BufferForMultipleNonImmediateMessage, PacketChunkSize);

		MessageBufferInformation[i].BufferEndAddress = PVOID(UINT64(MessageBufferInformation[i].BufferStartAddress) + LogBufferSize);

	}
	return TRUE;
}

BOOLEAN Log::LogSendBuffer(UINT32 OperationCode, PVOID Buffer, UINT32 BufferLength)
{
	KIRQL OldIRQL = 0;
	UINT32 Index;
	BOOLEAN IsSvmRoot;

	if (BufferLength > PacketChunkSize - 1 || BufferLength == 0) { return FALSE; }

	// Check that if we're in vmx root-mode
	// IsSvmRoot = false;
	IsSvmRoot = true;

	if (IsSvmRoot) { Index = 1; Spinlock.SpinlockLock((LONG*)&SvmRootLoggingLock); }
	else { Index = 0; KeAcquireSpinLock(&MessageBufferInformation[Index].BufferLock, &OldIRQL); }

	if (MessageBufferInformation[Index].CurrentIndexToWrite > MaximumPacketsCapacity - 1) { MessageBufferInformation[Index].CurrentIndexToWrite = 0; }

	BUFFER_HEADER* Header = (BUFFER_HEADER*)((UINT64)MessageBufferInformation[Index].BufferStartAddress + (MessageBufferInformation[Index].CurrentIndexToWrite * (PacketChunkSize + sizeof(BUFFER_HEADER))));

	Header->OpeationNumber = OperationCode;
	Header->BufferLength = BufferLength;
	Header->Valid = TRUE;

	PVOID SavingBuffer = (PVOID)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
		(MessageBufferInformation[Index].CurrentIndexToWrite * (PacketChunkSize + sizeof(BUFFER_HEADER))) + sizeof(BUFFER_HEADER));

	RtlCopyBytes(SavingBuffer, Buffer, BufferLength);

	MessageBufferInformation[Index].CurrentIndexToWrite = MessageBufferInformation[Index].CurrentIndexToWrite + 1;

	if (GlobalNotifyRecord != NULL)
	{
		GlobalNotifyRecord->CheckSvmRootMessagePool = IsSvmRoot;

		KeInsertQueueDpc(&GlobalNotifyRecord->Dpc, GlobalNotifyRecord, NULL);

		GlobalNotifyRecord = NULL;
	}

	IsSvmRoot ? Spinlock.SpinlockUnlock((LONG*)&SvmRootLoggingLock) : KeReleaseSpinLock(&MessageBufferInformation[Index].BufferLock, OldIRQL);
	return TRUE;
}

BOOLEAN Log::LogReadBuffer(BOOLEAN IsSvmRoot, PVOID BufferToSaveMessage, UINT32 * ReturnedLength) 
{

	KIRQL OldIRQL = PASSIVE_LEVEL; UINT32 Index;

	if (IsSvmRoot) { Index = 1; Spinlock.SpinlockLock((LONG*)&SvmRootLoggingLock); }
	else { Index = 0; KeAcquireSpinLock(&MessageBufferInformation[Index].BufferLock, &OldIRQL); }

	BUFFER_HEADER* Header =
		(BUFFER_HEADER*)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
			(MessageBufferInformation[Index].CurrentIndexToSend * (PacketChunkSize + sizeof(BUFFER_HEADER))));

	if (!Header->Valid)
	{
		if (IsSvmRoot) { Spinlock.SpinlockUnlock((LONG*)&SvmRootLoggingLock); }
		else { KeReleaseSpinLock(&MessageBufferInformation[Index].BufferLock, OldIRQL); }
		return FALSE;
	}

	RtlCopyBytes(BufferToSaveMessage, &Header->OpeationNumber, sizeof(UINT32));

	PVOID SendingBuffer = (PVOID)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
		(MessageBufferInformation[Index].CurrentIndexToSend * (PacketChunkSize + sizeof(BUFFER_HEADER))) + sizeof(BUFFER_HEADER));
	PVOID SavingAddress = (PVOID)((UINT64)BufferToSaveMessage + sizeof(UINT32)); // Because we want to pass the header of usermode header
	RtlCopyBytes(SavingAddress, SendingBuffer, Header->BufferLength);

	Header->Valid = FALSE;
	*ReturnedLength = Header->BufferLength + sizeof(UINT32);
	RtlZeroMemory(SendingBuffer, Header->BufferLength);

	if (MessageBufferInformation[Index].CurrentIndexToSend > MaximumPacketsCapacity - 2) { MessageBufferInformation[Index].CurrentIndexToSend = 0; }
	else { MessageBufferInformation[Index].CurrentIndexToSend = MessageBufferInformation[Index].CurrentIndexToSend + 1; }

	if (IsSvmRoot) { Spinlock.SpinlockUnlock((LONG*)&SvmRootLoggingLock); }
	else { KeReleaseSpinLock(&MessageBufferInformation[Index].BufferLock, OldIRQL); }
	return TRUE;
}

BOOLEAN Log::LogCheckForNewMessage(BOOLEAN IsSvmRoot)
{
	UINT32 Index;

	IsSvmRoot ? Index = 1 : Index = 0;

	BUFFER_HEADER* Header = (BUFFER_HEADER*)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
		(MessageBufferInformation[Index].CurrentIndexToSend * (PacketChunkSize + sizeof(BUFFER_HEADER))));

	if (!Header->Valid) { return FALSE; }

	return TRUE;
}

BOOLEAN Log::LogSendMessageToQueue(UINT32 OperationCode, BOOLEAN IsImmediateMessage, BOOLEAN ShowCurrentSystemTime, const char* Fmt, ...)
{
	UNREFERENCED_PARAMETER(ShowCurrentSystemTime);
	UNREFERENCED_PARAMETER(IsImmediateMessage);

	if (Fmt == nullptr)
	{
		return FALSE;
	}

	char LogMessage[PacketChunkSize] = {};
	size_t messageLength = strnlen_s(Fmt, RTL_NUMBER_OF(LogMessage) - 1);

	if (messageLength == 0 || messageLength >= RTL_NUMBER_OF(LogMessage))
	{
		return FALSE;
	}

	RtlCopyMemory(LogMessage, Fmt, messageLength);
	LogMessage[messageLength] = '\0';

	BufferIsReady = TRUE;
	return LogSendBuffer(OperationCode, LogMessage, static_cast<UINT32>(messageLength));
}

VOID Log::LogNotifyUsermodeCallback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
{
	PNOTIFY_RECORD NotifyRecord; PIRP Irp; UINT32 Length;

	UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(SystemArgument1); UNREFERENCED_PARAMETER(SystemArgument2);

	NotifyRecord = (PNOTIFY_RECORD)DeferredContext;

	ASSERT(NotifyRecord != NULL); _Analysis_assume_(NotifyRecord != NULL);

	switch (NotifyRecord->Type)
	{
	case IRP_BASED:
		Irp = NotifyRecord->Message.PendingIrp;

		if (Irp != NULL) {

			PCHAR OutBuff; // pointer to output buffer
			ULONG InBuffLength; // Input buffer length
			ULONG OutBuffLength; // Output buffer length
			PIO_STACK_LOCATION IrpSp;

			if (!(Irp->CurrentLocation <= Irp->StackCount + 1)) { return; }

			IrpSp = IoGetCurrentIrpStackLocation(Irp);
			InBuffLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
			OutBuffLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

			if (!InBuffLength || !OutBuffLength)
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				break;
			}

			if (!Irp->AssociatedIrp.SystemBuffer) { return; }

			OutBuff = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
			Length = 0;

			if (!LogReadBuffer(NotifyRecord->CheckSvmRootMessagePool, OutBuff, &Length)) { return; }

			Irp->IoStatus.Information = Length;
			Irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
		}
		break;

	case EVENT_BASED:
		KeSetEvent(NotifyRecord->Message.Event, 0, FALSE);
		ObDereferenceObject(NotifyRecord->Message.Event);
		break;
	default:
		ASSERT(FALSE);
		break;
	}

	if (NotifyRecord != NULL) { ExFreePoolWithTag(NotifyRecord, POOLTAG); }
}

namespace Cwrapper 
{
	Log* GLogPtr = nullptr;
	static void Callback(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
	{
		if (GLogPtr) { return GLogPtr->LogNotifyUsermodeCallback(Dpc, DeferredContext, SystemArgument1, SystemArgument2); }
	}
}

NTSTATUS Log::LogRegisterIrpBasedNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PNOTIFY_RECORD NotifyRecord;

	if (GlobalNotifyRecord == NULL)
	{
		NotifyRecord = static_cast<PNOTIFY_RECORD>(
			ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NOTIFY_RECORD), POOLTAG));

		if (NULL == NotifyRecord) {
			return  STATUS_INSUFFICIENT_RESOURCES;
		}

		NotifyRecord->Type = IRP_BASED;
		NotifyRecord->Message.PendingIrp = Irp;

		Cwrapper::GLogPtr = this;
		KeInitializeDpc(&NotifyRecord->Dpc, // Dpc
			Cwrapper::Callback, // DeferredRoutine
			NotifyRecord // DeferredContext
		);

		IoMarkIrpPending(Irp);

		if (LogCheckForNewMessage(FALSE)) { NotifyRecord->CheckSvmRootMessagePool = FALSE; KeInsertQueueDpc(&NotifyRecord->Dpc, NotifyRecord, NULL); }
		else if (LogCheckForNewMessage(TRUE)) { NotifyRecord->CheckSvmRootMessagePool = TRUE; KeInsertQueueDpc(&NotifyRecord->Dpc, NotifyRecord, NULL); }
		else { GlobalNotifyRecord = NotifyRecord; }
		return STATUS_PENDING;
	}
	else
	{
		return STATUS_SUCCESS;
	}
}

NTSTATUS Log::LogRegisterEventBasedNotification(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PNOTIFY_RECORD NotifyRecord;
	NTSTATUS Status;
	PREGISTER_EVENT RegisterEvent;

	RegisterEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;

	// Allocate a record and save all the event context.
	NotifyRecord = static_cast<PNOTIFY_RECORD>(
		ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(NOTIFY_RECORD), POOLTAG));

	if (NULL == NotifyRecord) { return  STATUS_INSUFFICIENT_RESOURCES; }

	NotifyRecord->Type = EVENT_BASED;

	Cwrapper::GLogPtr = this;
	KeInitializeDpc(&NotifyRecord->Dpc, // Dpc
		Cwrapper::Callback, // DeferredRoutine
		NotifyRecord // DeferredContext
	);

	// Get the object pointer from the handle. Note we must be in the context of the process that created the handle.
	Status = ObReferenceObjectByHandle(RegisterEvent->hEvent,
		SYNCHRONIZE | EVENT_MODIFY_STATE,
		*ExEventObjectType,
		Irp->RequestorMode,
		(PVOID*)NotifyRecord->Message.Event,
		NULL
	);

	if (!NT_SUCCESS(Status)) 
	{ ExFreePoolWithTag(NotifyRecord, POOLTAG); return Status; }

	// Insert dpc to the queue
	KeInsertQueueDpc(&NotifyRecord->Dpc, NotifyRecord, NULL);

	return STATUS_SUCCESS;
}
