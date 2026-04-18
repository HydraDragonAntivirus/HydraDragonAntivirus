#include "Log/Logger.hpp"

#include <ntddk.h>
#include <cstdarg>
#include <stdio.h>

#include "General.hpp"

BOOLEAN Log::LogInitialize()
{
	MessageBufferInformation = (struct _LOG_BUFFER_INFORMATION*)ExAllocatePool(NonPagedPool, sizeof(_LOG_BUFFER_INFORMATION) * 2);

	if (!MessageBufferInformation) { KdPrint(("Message %p", MessageBufferInformation)); return FALSE; }

	RtlZeroMemory(MessageBufferInformation, sizeof(_LOG_BUFFER_INFORMATION) * 2);
	SvmRootLoggingLock = 0;

	for (int i = 0; i < 2; i++)
	{
		KeInitializeSpinLock(&MessageBufferInformation[i].BufferLock);
		KeInitializeSpinLock(&MessageBufferInformation[i].BufferLockForNonImmMessage);

		MessageBufferInformation[i].BufferStartAddress = ExAllocatePool(NonPagedPool, LogBufferSize);
		MessageBufferInformation[i].BufferForMultipleNonImmediateMessage = ExAllocatePool(NonPagedPool, PacketChunkSize);

		if (!MessageBufferInformation[i].BufferStartAddress)
		{
			return FALSE;
		}
		RtlZeroMemory(MessageBufferInformation[i].BufferStartAddress, LogBufferSize);

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
}

BOOLEAN Log::LogReadBuffer(BOOLEAN IsSvmRoot, PVOID BufferToSaveMessage, UINT32 * ReturnedLength) 
{

	KIRQL OldIRQL; UINT32 Index;

	if (IsSvmRoot) { Index = 1; Spinlock.SpinlockLock((LONG*)&SvmRootLoggingLock); }
	else { Index = 0; KeAcquireSpinLock(&MessageBufferInformation[Index].BufferLock, &OldIRQL); }

	BUFFER_HEADER* Header =
		(BUFFER_HEADER*)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
			(MessageBufferInformation[Index].CurrentIndexToSend * (PacketChunkSize + sizeof(BUFFER_HEADER))));

	if (!Header->Valid) { return FALSE; }

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
	KIRQL OldIRQL; UINT32 Index;

	IsSvmRoot ? Index = 1 : Index = 0;

	BUFFER_HEADER* Header = (BUFFER_HEADER*)((UINT64)MessageBufferInformation[Index].BufferStartAddress +
		(MessageBufferInformation[Index].CurrentIndexToSend * (PacketChunkSize + sizeof(BUFFER_HEADER))));

	if (!Header->Valid) { return FALSE; }

	return TRUE;
}

BOOLEAN Log::LogSendMessageToQueue(UINT32 OperationCode, BOOLEAN IsImmediateMessage, BOOLEAN ShowCurrentSystemTime, const char* Fmt, ...)
{
	BOOLEAN Result;
	va_list ArgList;
	size_t WrittenSize;
	UINT32 Index;
	KIRQL OldIRQL;
	BOOLEAN IsSvmRootMode;
	int SprintfResult = 0;
	char LogMessage[PacketChunkSize];
	char TempMessage[PacketChunkSize];
	char TimeBuffer[20] = { 0 };

	// Set Vmx State
	// IsSvmRootMode = false;//GuestState[KeGetCurrentProcessorNumber()].IsOnVmxRootMode;
	
	IsSvmRootMode = true;
	/*
	if (ShowCurrentSystemTime)
	{
		va_start(ArgList, Fmt);

		SprintfResult = vsprintf_s(LogMessage, PacketChunkSize - 1, Fmt, ArgList);
		va_end(ArgList);

		if (SprintfResult == -1) { return FALSE; }

		TIME_FIELDS TimeFields;
		LARGE_INTEGER SystemTime, LocalTime;
		KeQuerySystemTime(&SystemTime);
		ExSystemTimeToLocalTime(&SystemTime, &LocalTime);
		RtlTimeToTimeFields(&LocalTime, &TimeFields);

		sprintf_s(TimeBuffer, RTL_NUMBER_OF(TimeBuffer), "%02hd:%02hd:%02hd.%03hd", TimeFields.Hour,
			TimeFields.Minute, TimeFields.Second,
			TimeFields.Milliseconds);

		// Append time with previous message
		SprintfResult = sprintf_s(LogMessage, PacketChunkSize - 1, "(%s - core : %d - vmx-root? %s)\t %s",
			TimeBuffer, KeGetCurrentProcessorNumberEx(0), IsSvmRootMode ? "yes" : "no", TempMessage);

		if (SprintfResult == -1) { return FALSE; }
	}
	else
	{
		va_start(ArgList, Fmt);

		SprintfResult = vsprintf_s(LogMessage, PacketChunkSize - 1, Fmt, ArgList);
		va_end(ArgList);

		if (SprintfResult == -1) { return FALSE; }
	}

	WrittenSize = strnlen_s(LogMessage, PacketChunkSize - 1);

	if (LogMessage[0] == '\0') { return FALSE; }

	if (IsImmediateMessage) 
	{ 
		BufferIsReady = TRUE; 
		LogSendBuffer(OperationCode, LogMessage, WrittenSize);
		RtlZeroMemory(LogMessage, sizeof(LogMessage));
	}
	else
	{
		if (IsSvmRootMode) { Index = 1; Spinlock.SpinlockLock((LONG*)&SvmRootLoggingLockForNonImmBuffers); }
		else { Index = 0; KeAcquireSpinLock(&MessageBufferInformation[Index].BufferLockForNonImmMessage, &OldIRQL); }

		Result = TRUE;

		if ((MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer + WrittenSize) > PacketChunkSize - 1 &&
			MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer != 0)
		{
			BufferIsReady = TRUE;
			Result = LogSendBuffer(OPERATION_LOG_NON_IMMEDIATE_MESSAGE,
				MessageBufferInformation[Index].BufferForMultipleNonImmediateMessage,
				MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer);

			MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer = 0;
			RtlZeroMemory(MessageBufferInformation[Index].BufferForMultipleNonImmediateMessage, PacketChunkSize);
		}

		RtlCopyBytes(PVOID(UINT64(MessageBufferInformation[Index].BufferForMultipleNonImmediateMessage) +
			MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer), LogMessage, WrittenSize);

		MessageBufferInformation[Index].CurrentLengthOfNonImmBuffer += WrittenSize;

		if (IsSvmRootMode) { Spinlock.SpinlockUnlock((LONG*)&SvmRootLoggingLockForNonImmBuffers); }
		else { KeReleaseSpinLock(&MessageBufferInformation[Index].BufferLockForNonImmMessage, OldIRQL); }

		return Result;
	}
	*/
	return 1;
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
	PNOTIFY_RECORD NotifyRecord;
	PIO_STACK_LOCATION IrpStack;
	KIRQL OOldIrql;
	PREGISTER_EVENT RegisterEvent;

	if (GlobalNotifyRecord == NULL)
	{
		IrpStack = IoGetCurrentIrpStackLocation(Irp);
		RegisterEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;

		NotifyRecord = (PNOTIFY_RECORD)ExAllocatePoolWithQuotaTag(NonPagedPool, sizeof(NOTIFY_RECORD), POOLTAG);

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
	PNOTIFY_RECORD NotifyRecord;
	NTSTATUS Status;
	PIO_STACK_LOCATION IrpStack;
	PREGISTER_EVENT RegisterEvent;
	KIRQL OldIrql;

	IrpStack = IoGetCurrentIrpStackLocation(Irp);
	RegisterEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;

	// Allocate a record and save all the event context.
	NotifyRecord = (PNOTIFY_RECORD)ExAllocatePoolWithQuotaTag(NonPagedPool, sizeof(NOTIFY_RECORD), POOLTAG);

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