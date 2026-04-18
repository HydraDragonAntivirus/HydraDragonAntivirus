#include <ntddk.h>

#include "Debugger/Driver/GuestContext.hpp"
#include "Zydis/Zydis.h"
#include "HyperVisor/HyperVisor.hpp"
#include "Log/Logger.hpp"
#include "Log/File.hpp"
#include "Log/Trace.hpp"

#include <cstdarg>
#include <stdio.h>
#include <memory.h>
#include <stdio.h>
#include <vector>

HyperVisorSvm objHyperVisorSvm;
Log objLog;
File objFile;
Trace objTrace;
Transparent objTransparent;

bool TransparentMode = true;

uint64_t CounterOfInstrs = 0;
uint64_t FirstSize = 0;
uint64_t SizeOfAll = 0;
std::vector<ULONG_PTR> AddrsFuncs;
std::vector<std::pair<ULONG_PTR, const std::string>>* Funcs;
ULONG_PTR ExitProcesAddr; 
ULONGLONG freeMemory = 0;

#define LogInfo(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, false, false, "[+] Information (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__)

#define LogInfoImmediate(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, TRUE, false, "[+] Information (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__)

#define LogWarning(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_WARNING_MESSAGE, TRUE, false, "[-] Warning (%s:%d) | " format "\n",	\
		__func__, __LINE__, __VA_ARGS__)

#define LogError(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_ERROR_MESSAGE, TRUE, false, "[!] Error (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__);	\

#define LogBreakpointImmediate(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_BREAKPOINT_MESSAGE, TRUE, false, "[+] BreakPoint(%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__);	\

// Log without any prefix
#define Log(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, false, false, format "\n", __VA_ARGS__)

SVM::PRIVATE_VM_DATA* Interceptions(
	_Inout_ SVM::PRIVATE_VM_DATA* Private)
{
	Private->Guest.ControlArea.InterceptCpuid = TRUE;
	Private->Guest.ControlArea.InterceptVmrun = TRUE;
	//Private->Guest.ControlArea.InterceptRdtsc = TRUE;
	//Private->Guest.ControlArea.InterceptRdtscp = TRUE;

	Private->Guest.ControlArea.InterceptExceptions.Bitmap.InterceptionVectorDB = TRUE;
	Private->Guest.ControlArea.InterceptExceptions.Bitmap.InterceptionVectorBP = TRUE;
	Private->Guest.ControlArea.InterceptMsr = TRUE;
	Private->Guest.ControlArea.MsrpmBasePa = reinterpret_cast<UINT64>(PhysicalMemory::GetPhysicalAddress(&Private->Msrpm));

	return Private;
}

void InjectEvent(__out SVM::VMCB* Guest, unsigned char Vector, unsigned char Type, unsigned int Code)
{
	SVM::EVENTINJ Event = {};
	Event.Bitmap.Vector = Vector;
	Event.Bitmap.Type = Type;
	Event.Bitmap.ErrorCodeValid = TRUE;
	Event.Bitmap.Valid = TRUE;
	Event.Bitmap.ErrorCode = Code;
	Guest->ControlArea.EventInjection = Event.Value;
}

void VmFuncSetRflagTrapFlag(_In_ BOOLEAN Set, _In_ SVM::PRIVATE_VM_DATA* Private)
{
	Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.TF = Set;
}

bool BpPass = false;
ZydisDecoder* DecoderMinimal = nullptr;
ZydisDecodedInstruction* Instruction = nullptr;

typedef CPUID_REGS FEATURE_INFORMATION;

extern "C" uint64_t PushfqHandler(_In_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag);
extern "C" uint64_t PushfHandler(_In_ uint64_t Rsp, _In_ bool CSLongMode, _In_ uint64_t RflagsValue, _In_ uint32_t VmFlag, _In_ uint32_t RFlag);

bool TrapFlagHandler(_Inout_ SVM::PRIVATE_VM_DATA* Private, _Inout_ GuestContext* Context)
{
	auto VMROOTCR3 = __readcr3();
	__writecr3(((CR3)Private->Guest.StateSaveArea.Cr3).Value);
	__invlpg((void*)Private->Guest.StateSaveArea.Rip);
	__invlpg((void*)Private->Guest.StateSaveArea.Rsp);

	if (Private->Guest.StateSaveArea.Rip != ExitProcesAddr)
	{
		++CounterOfInstrs;
		VmFuncSetRflagTrapFlag(TRUE, Private);
		objTrace.TraceMnemonic(Private);
	}
	else
	{
		objTrace.TraceMnemonicFinalization();
		VmFuncSetRflagTrapFlag(FALSE, Private);

		KdPrint(("ExitProcessAddress reached!\n"));
		KdPrint(("Count of executed instructions: %p\n", CounterOfInstrs));
	}

	if (((const unsigned char*)Private->Guest.StateSaveArea.Rip) != nullptr &&
		((const unsigned char*)Private->Guest.StateSaveArea.Rip)[0] != 0 &&
		Private->Guest.StateSaveArea.Cpl == 3)
	{
		ZydisDecoderDecodeInstruction(
			DecoderMinimal,
			NULL,
			(const unsigned char*)Private->Guest.StateSaveArea.Rip,
			ZYDIS_MAX_INSTRUCTION_LENGTH,
			Instruction);

		if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHFQ)
		{
			Private->Guest.StateSaveArea.Rsp = PushfqHandler(
				Private->Guest.StateSaveArea.Rsp,
				Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
				Private->Guest.StateSaveArea.Rflags.Value,
				Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
				Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);

			if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
			else { Private->Guest.ControlArea.NextRip += Instruction->length; }
		}
		else if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHF)
		{
			Private->Guest.StateSaveArea.Rsp = PushfHandler(
				Private->Guest.StateSaveArea.Rsp,
				Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
				Private->Guest.StateSaveArea.Rflags.Value,
				Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
				Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);
			if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
			else { Private->Guest.ControlArea.NextRip += Instruction->length; }
		}
	}

	__writecr3(VMROOTCR3);
	if (!Private->Guest.ControlArea.NextRip)
	{
		Private->Guest.StateSaveArea.Rax = Context->Rax;
		return true;
	}
	else { return false; }
}

extern "C" SVM::VMM_STATUS SvmVmexitHandler(
	_In_ SVM::PRIVATE_VM_DATA* Private,
	_In_ GuestContext* Context)
{
	SIMDGuestContext objSIMDGuestContext;
	_fxsave64(&objSIMDGuestContext);

	// Load the host state:-
	__svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.HostVmcbPa));
	// Restore the guest's RAX that was overwritten by host's RAX on #VMEXIT:
	Context->Rax = Private->Guest.StateSaveArea.Rax;

	SVM::VMM_STATUS Status = SVM::VMM_STATUS::VMM_CONTINUE;	
	//RDTSC 110
	//RDTSCP 135
	switch (Private->Guest.ControlArea.ExitCode)
	{
	case SVM::SVM_EXIT_CODE::VMEXIT_EXCP_DB://65
	{
		auto VMROOTCR3 = __readcr3();
		__writecr3(((CR3)Private->Guest.StateSaveArea.Cr3).Value);
		__invlpg((void*)Private->Guest.StateSaveArea.Rip);
		__invlpg((void*)Private->Guest.StateSaveArea.Rsp);

		if (Private->Guest.StateSaveArea.Rip != ExitProcesAddr)
		{
			++CounterOfInstrs;
			VmFuncSetRflagTrapFlag(TRUE, Private);
			objTrace.TraceMnemonic(Private);
		}
		else
		{
			objTrace.TraceMnemonicFinalization();
			VmFuncSetRflagTrapFlag(FALSE, Private);

			KdPrint(("ExitProcessAddress reached!\n"));
			KdPrint(("Count of executed instructions: %p\n", CounterOfInstrs));
		}

		if (((const unsigned char*)Private->Guest.StateSaveArea.Rip) != nullptr &&
			((const unsigned char*)Private->Guest.StateSaveArea.Rip)[0] != 0 &&
			Private->Guest.StateSaveArea.Cpl == 3)
		{
			ZydisDecoderDecodeInstruction(
				DecoderMinimal,
				NULL,
				(const unsigned char*)Private->Guest.StateSaveArea.Rip,
				ZYDIS_MAX_INSTRUCTION_LENGTH,
				Instruction);

			if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHFQ)
			{
				Private->Guest.StateSaveArea.Rsp = PushfqHandler(
					Private->Guest.StateSaveArea.Rsp,
					Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
					Private->Guest.StateSaveArea.Rflags.Value,
					Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
					Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);

				if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
				else { Private->Guest.ControlArea.NextRip += Instruction->length; }
			}
			else if (Instruction->mnemonic == ZYDIS_MNEMONIC_PUSHF)
			{
				Private->Guest.StateSaveArea.Rsp = PushfHandler(
					Private->Guest.StateSaveArea.Rsp,
					Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode,
					Private->Guest.StateSaveArea.Rflags.Value,
					Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.VM,
					Private->Guest.StateSaveArea.Rflags.Bitmap.Eflags.Bitmap.RF);
				if (!Private->Guest.ControlArea.NextRip) { Private->Guest.StateSaveArea.Rip += Instruction->length; }
				else { Private->Guest.ControlArea.NextRip += Instruction->length; }
			}
		}

		_fxrstor64(&objSIMDGuestContext);

		__writecr3(VMROOTCR3);
		if (!Private->Guest.ControlArea.NextRip)
		{
			Private->Guest.StateSaveArea.Rax = Context->Rax;
			return Status;
		}
		else { break; }
		//DbgBreakPoint();
		//if (!TrapFlagHandler(Private, Context)) { return Status; }
		//break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_EXCP_BP://67
	{
		auto VMROOTCR3 = __readcr3();
		VmFuncSetRflagTrapFlag(TRUE, Private); BpPass = true;
		Private->Guest.StateSaveArea.Rax = Context->Rax;
		__writecr3(VMROOTCR3);
		return Status;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_RDTSC://110
	{
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_CPUID://114
	{
		CPUID_REGS Regs = {};
		int Function = static_cast<int>(Context->Rax);
		int SubLeaf = static_cast<int>(Context->Rcx);
		__cpuidex(Regs.Raw, Function, SubLeaf);

		if (Function == CPUID_VMM_SHUTDOWN) { Status = SVM::VMM_STATUS::VMM_SHUTDOWN; }
		else if (TransparentMode && Function == CPUID::Generic::CPUID_EXTENDED_FEATURE_INFORMATION) 
		{ 
			CPUID::FEATURE_INFORMATION RegsFeature = (CPUID::FEATURE_INFORMATION)Regs; 
			Context = objTransparent.InvisibleCpuid(RegsFeature, Context); 
		}
		else
		{
			Context->Rax = Regs.Regs.Eax;
			Context->Rbx = Regs.Regs.Ebx;
			Context->Rcx = Regs.Regs.Ecx;
			Context->Rdx = Regs.Regs.Edx;
		}
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_MSR://124
	{
		if ((Context->Rcx & MAXUINT32) == static_cast<unsigned int>(AMD::AMD_MSR::MSR_EFER) && Private->Guest.ControlArea.ExitInfo1)
		{
			AMD::EFER Efer = {};
			Efer.Value = ((Context->Rdx & MAXUINT32) << 32) | (Context->Rax & MAXUINT32);
			if (!Efer.Bitmap.SecureVirtualMachineEnable)
			{
				InjectEvent(&Private->Guest, INTERRUPT_VECTOR::GeneralProtection, EXCEPTION_VECTOR::FaultTrapException, 0); // #GP (Vector = 13, Type = Exception)
				break;
			}
			Private->Guest.StateSaveArea.Efer = Efer.Value;
		}
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_VMRUN://128
	{
		InjectEvent(&Private->Guest, INTERRUPT_VECTOR::GeneralProtection, EXCEPTION_VECTOR::FaultTrapException, 0); // #GP (Vector = 13, Type = Exception)
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_RDTSCP://135
	{
		break;
	}
	}
	
	if (Status == SVM::VMM_STATUS::VMM_SHUTDOWN)
	{
		// We should to devirtualize this processor:
		Context->Rax = reinterpret_cast<UINT64>(Private) & MAXUINT32; // Low part
		Context->Rbx = Private->Guest.ControlArea.NextRip;
		Context->Rcx = Private->Guest.StateSaveArea.Rsp;
		Context->Rdx = reinterpret_cast<UINT64>(Private) >> 32; // High part

		// Load the guest's state:
		__svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.GuestVmcbPa));

		// Store the GIF - Global Interrupt Flag:
		_disable();
		__svm_stgi();

		// Disable the SVM by resetting the EFER.SVME bit:
		AMD::EFER Efer = {};
		Efer.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER));
		Efer.Bitmap.SecureVirtualMachineEnable = FALSE;
		__writemsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER), Efer.Value);

		// Restoring the EFlags:
		__writeeflags(Private->Guest.StateSaveArea.Rflags.Value);
	}

	Private->Guest.StateSaveArea.Rax = Context->Rax;

	// Go to the next instruction:
	Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;
	return Status;
}

//Define in asm file(in my example)
extern "C" void SvmVmmRun(_In_ void* InitialVmmStackPointer);

void DrvUnload(_In_ PDRIVER_OBJECT DriverObj)
{
	UNREFERENCED_PARAMETER(DriverObj);
	KdPrint(("Sample driver Unload called\n"));
}

NTSTATUS DrvUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	objHyperVisorSvm.PInterceptions = &Interceptions;
	objHyperVisorSvm.PSvmVmmRun = &SvmVmmRun;

	if (objHyperVisorSvm.IsSvmSupported()) 
	{ 
		objFile.CreateFile(
			L"\\??\\E:\\Trace.out",
			FILE_GENERIC_WRITE,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
		objHyperVisorSvm.VirtualizeAllProcessors(); 
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvDispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack;
	PREGISTER_EVENT RegisterEvent;
	NTSTATUS Status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_REGISTER_EVENT:
	{
		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength < SIZEOF_REGISTER_EVENT || Irp->AssociatedIrp.SystemBuffer == NULL) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		RegisterEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;

		switch (RegisterEvent->Type)
		{
		case IRP_BASED:
			Status = objLog.LogRegisterIrpBasedNotification(DeviceObject, Irp);
			break;
		case EVENT_BASED:
			Status = objLog.LogRegisterEventBasedNotification(DeviceObject, Irp);
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		break;
	}
	case IOCTL_BUFFER_CHECK:
	{
		RtlCopyBytes(Irp->AssociatedIrp.SystemBuffer, &objLog.BufferIsReady, sizeof(bool));

		Irp->IoStatus.Information = sizeof(bool);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_WRITE:
	{
		//objTrace.AcceptRipMessage(objFile);
		//objTrace.AcceptMnemonicMessage(objFile);
		objTrace.AcceptGraphMessage(objFile);
		//objTrace.AcceptGraphCycleFoldingMessage(objFile);
		//while (TRUE)
		//{
		//	objTrace.AcceptCombineBufferRipMessage(objFile, objTrace.MainBuffer);
		//
		////	if(objTrace.Exit) { objTrace.AcceptCombineBufferRipMessage(objFile, objTrace.MainBuffer); }
		//}
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_CLOSE_FILE:
	{
		objFile.CloseFile();

		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_BREAKPOINT_PASS:
	{
		RtlCopyBytes(Irp->AssociatedIrp.SystemBuffer, &BpPass, sizeof(bool));
		Irp->IoStatus.Information = sizeof(bool);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_BUFFER_CHECK_SUCCESS:
	{
		objLog.BufferIsReady = FALSE;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_PE_ANALYZE:
	{
		Funcs = (std::vector<std::pair<ULONG_PTR, const std::string>>*)Irp->AssociatedIrp.SystemBuffer;
		if (Funcs && Funcs->size() > 0)
		{
			for (const auto& pair : *Funcs)
			{
				if (pair.second == "ExitProcess") { ExitProcesAddr = pair.first; }
				AddrsFuncs.push_back(pair.first);
			}
		}
		else { KdPrint(("Funcs is empty or nullptr\n")); }

		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	}
	return Status;
}

NTSTATUS DrvClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


bool SvmExitCodesAllocator()
{
	DecoderMinimal = (ZydisDecoder*)ExAllocatePool(NonPagedPoolNx, sizeof(ZydisDecoder));
	if (DecoderMinimal != nullptr)
	{
		RtlZeroMemory(DecoderMinimal, sizeof(ZydisDecoder));
		DecoderMinimal->decoder_mode = ZYDIS_DECODER_MODE_MINIMAL;
		DecoderMinimal->machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
		DecoderMinimal->stack_width = ZYDIS_STACK_WIDTH_64;

		Instruction = (ZydisDecodedInstruction*)ExAllocatePool(NonPagedPoolNx, sizeof(ZydisDecodedInstruction));
		if (Instruction != nullptr)
		{
			RtlZeroMemory(Instruction, sizeof(ZydisDecodedInstruction));
		}
		else { return false; }
	}
	else { return false; }

	return true;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath); NTSTATUS Ntstatus = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL; UNICODE_STRING DriverName, DosDeviceName;
	__crt_init();

	if (!objLog.LogInitialize()) { DbgPrint("[*] Log buffer is not initialized !\n"); DbgBreakPoint(); }
	if (!objTrace.TraceInitializeMnemonic()) { DbgPrint("[*] Trace buffer is not initialized !\n"); DbgBreakPoint(); }
	if (!SvmExitCodesAllocator()) { DbgPrint("[*] SvmExitCodesAllocator buffer is not initialized !\n"); DbgBreakPoint(); }

	RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisorDevice");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
	
	Ntstatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (Ntstatus == STATUS_SUCCESS)
	{
		for (UINT64 Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++) { DriverObject->MajorFunction[Index] = DrvUnsupported; }

		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchIoControl;
		DriverObject->DriverUnload = DrvUnload;
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return STATUS_SUCCESS;
}