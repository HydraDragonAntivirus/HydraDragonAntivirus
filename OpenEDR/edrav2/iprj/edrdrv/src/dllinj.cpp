//
//  edrav2.libdllinj
//  Driver library for DLL injection
//
///
/// @file libdllinj API
///
#pragma once

#include "common.h"
#include "kstack.h"
#include "osutils.h"
#include "fltport.h"
#include "dllinj.h"
#include "UserModeHookEngine.h"

namespace cmd {
namespace dllinj {

using kernelInjectLib::eInjectorType;
using kernelInjectLib::IInjector;

//
//
//
static PDEVICE_OBJECT g_pDeviceObjectForWorkItem = nullptr;

//
// Small lock-free-friendly gate to suppress only the first initial thread
// inserted by a parent process into its newly created child.
//
struct InitialThreadToken
{
	ULONG nTargetPid;
	ULONG nCreatorPid;
	ULONGLONG nExpireTick;
};

static KSPIN_LOCK g_mtxInitialThreadTokens = 0;
static BOOLEAN g_fInitialThreadTokensInit = FALSE;
static InitialThreadToken g_initialThreadTokens[64] = {};

static void recordInitialThreadToken(HANDLE TargetPid, HANDLE CreatorPid)
{
	if (!g_fInitialThreadTokensInit || TargetPid == 0 || CreatorPid == 0)
		return;
	const ULONG nTarget = (ULONG)(ULONG_PTR)TargetPid;
	const ULONG nCreator = (ULONG)(ULONG_PTR)CreatorPid;
	if (nTarget == nCreator)
		return;
	const ULONGLONG nNow = getTickCount64();
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_mtxInitialThreadTokens, &oldIrql);
	ULONG nReplace = 0;
	ULONGLONG nOldest = ~0ull;
	for (ULONG i = 0; i < ARRAYSIZE(g_initialThreadTokens); ++i)
	{
		if (g_initialThreadTokens[i].nTargetPid == 0 || g_initialThreadTokens[i].nExpireTick <= nNow)
		{
			nReplace = i;
			break;
		}
		if (g_initialThreadTokens[i].nExpireTick < nOldest)
		{
			nOldest = g_initialThreadTokens[i].nExpireTick;
			nReplace = i;
		}
	}
	g_initialThreadTokens[nReplace].nTargetPid = nTarget;
	g_initialThreadTokens[nReplace].nCreatorPid = nCreator;
	g_initialThreadTokens[nReplace].nExpireTick = nNow + 2000;
	KeReleaseSpinLock(&g_mtxInitialThreadTokens, oldIrql);
}

static bool consumeInitialThreadToken(HANDLE TargetPid, HANDLE CreatorPid)
{
	if (!g_fInitialThreadTokensInit || TargetPid == 0 || CreatorPid == 0)
		return false;
	const ULONG nTarget = (ULONG)(ULONG_PTR)TargetPid;
	const ULONG nCreator = (ULONG)(ULONG_PTR)CreatorPid;
	const ULONGLONG nNow = getTickCount64();
	bool fFound = false;
	KIRQL oldIrql;
	KeAcquireSpinLock(&g_mtxInitialThreadTokens, &oldIrql);
	for (ULONG i = 0; i < ARRAYSIZE(g_initialThreadTokens); ++i)
	{
		if (g_initialThreadTokens[i].nTargetPid == 0)
			continue;
		if (g_initialThreadTokens[i].nExpireTick <= nNow)
		{
			g_initialThreadTokens[i].nTargetPid = 0;
			continue;
		}
		if (g_initialThreadTokens[i].nTargetPid == nTarget &&
			g_initialThreadTokens[i].nCreatorPid == nCreator)
		{
			g_initialThreadTokens[i].nTargetPid = 0;
			fFound = true;
			break;
		}
	}
	KeReleaseSpinLock(&g_mtxInitialThreadTokens, oldIrql);
	return fFound;
}

static void sendImageOrDriverEvent(
	SysmonEvent eEvent,
	HANDLE ProcessId,
	PUNICODE_STRING FullImageName,
	PIMAGE_INFO ImageInfo)
{
	if (g_pCommonData == nullptr || !g_pCommonData->fEnableMonitoring || !g_pCommonData->fFltPortIsInitialized)
		return;
	if (KeGetCurrentIrql() > APC_LEVEL)
		return;
	if (!isEventEnabled(eEvent))
		return;
	if (FullImageName == nullptr || FullImageName->Buffer == nullptr || FullImageName->Length == 0)
		return;

	NonPagedLbvsSerializer<edrdrv::EventField> serializer;
	if (!serializer.write(EvFld::RawEventId, uint16_t(eEvent))) return;
	if (!serializer.write(EvFld::TickTime, getTickCount64())) return;
	if (!serializer.write(EvFld::ProcessPid, (uint32_t)(ULONG_PTR)ProcessId)) return;
	if (!write(serializer, EvFld::FilePath, FullImageName)) return;
	if (ImageInfo != nullptr)
	{
		if (!serializer.write(EvFld::OwlyHvMemoryAddress, (uint64_t)(ULONG_PTR)ImageInfo->ImageBase)) return;
		if (!serializer.write(EvFld::OwlyHvMemorySize, (uint64_t)ImageInfo->ImageSize)) return;
	}
	if (eEvent == SysmonEvent::DriverLoad)
	{
		if (!kstack::writeKernelStack(serializer))
			return;
	}

	IFERR_LOG(fltport::sendRawEvent(serializer),
		"Can't send image/driver load event %u pid: %Iu.\r\n", (ULONG)eEvent, (ULONG_PTR)ProcessId);
}

static void sendRemoteThreadEvent(HANDLE CreatorPid, HANDLE TargetPid, HANDLE ThreadId)
{
	if (g_pCommonData == nullptr || !g_pCommonData->fEnableMonitoring || !g_pCommonData->fFltPortIsInitialized)
		return;
	if (KeGetCurrentIrql() > APC_LEVEL)
		return;
	if (!isEventEnabled(SysmonEvent::RemoteThreadCreate))
		return;

	NonPagedLbvsSerializer<edrdrv::EventField> serializer;
	if (!serializer.write(EvFld::RawEventId, uint16_t(SysmonEvent::RemoteThreadCreate))) return;
	if (!serializer.write(EvFld::TickTime, getTickCount64())) return;
	if (!serializer.write(EvFld::ProcessPid, (uint32_t)(ULONG_PTR)CreatorPid)) return;
	if (!serializer.write(EvFld::TargetProcessPid, (uint32_t)(ULONG_PTR)TargetPid)) return;
	if (!serializer.write(EvFld::ThreadId, (uint32_t)(ULONG_PTR)ThreadId)) return;
	if (!kstack::writeKernelStack(serializer))
		return;

	IFERR_LOG(fltport::sendRawEvent(serializer),
		"Can't send remote thread event creator: %Iu target: %Iu.\r\n", (ULONG_PTR)CreatorPid, (ULONG_PTR)TargetPid);
}

//
// This callback is called whenever a new image is loaded
//
static VOID ImageCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (ImageInfo != NULL && (ProcessId == 0 || ImageInfo->SystemModeImage))
	{
		sendImageOrDriverEvent(SysmonEvent::DriverLoad, PsGetProcessId(PsInitialSystemProcess), FullImageName, ImageInfo);
		return;
	}

	if (ProcessId != 0 && ProcessId != PsGetProcessId(PsInitialSystemProcess))
	{
		g_pCommonData->injector->onImageLoad(g_pDeviceObjectForWorkItem, ProcessId, FullImageName, ImageInfo);
		sendImageOrDriverEvent(SysmonEvent::ImageLoad, ProcessId, FullImageName, ImageInfo);

		// When user-mode DLLs are mapped into target processes, apply/refresh hooks
		if (ImageInfo != NULL && !ImageInfo->SystemModeImage)
		{
			UserModeHookProcess((ULONG)(ULONG_PTR)ProcessId);
		}
	}
}

//
// This callback is called whenever a new thread is created
//
static VOID CreateThreadCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	if (0 == ProcessId || (PsGetProcessId(PsInitialSystemProcess) == ProcessId))
		return;

	g_pCommonData->injector->onCreateThread(ProcessId, ThreadId, Create);

	if (Create != FALSE)
	{
		HANDLE nCreatorPid = PsGetCurrentProcessId();
		if (nCreatorPid != 0 &&
			nCreatorPid != ProcessId &&
			nCreatorPid != PsGetProcessId(PsInitialSystemProcess) &&
			!consumeInitialThreadToken(ProcessId, nCreatorPid))
		{
			sendRemoteThreadEvent(nCreatorPid, ProcessId, ThreadId);
		}
	}
}

//////////////////////////////////////////////////////////////////////////
//
// External API
//

//
//
//
NTSTATUS setInjectedDllList(List<DynUnicodeString>& dllList)
{
	if (!g_pCommonData->fDllInjectorIsInitialized)
		return LOGERROR(STATUS_UNSUCCESSFUL, "DllInjector is not initialized\r\n");

	g_pCommonData->injector->cleanupDllList();

	for (const auto& dllName : dllList)
	{
		IFERR_RET(g_pCommonData->injector->addSystemDll(dllName), "Can't add DLL for injection. path: <%wZ>.\r\n", static_cast<PCUNICODE_STRING>(dllName));
	}

	return STATUS_SUCCESS;
}

//
//
//
void enableInjectedDllVerification(bool fEnable)
{
	if (fEnable)
	{
		g_pCommonData->injector->enableDllVerification(SE_SIGNING_LEVEL_AUTHENTICODE);
	}
}


//
//
//
NTSTATUS initialize()
{
	/// Init IInjector instance
	g_pCommonData->injector = IInjector::CreateInstance(eInjectorType::ApcInjector);
	if (!g_pCommonData->injector.get())
		return LOGERROR(STATUS_INSUFFICIENT_RESOURCES, "Not enough memory to initialize IInjector\r\n");

	if (!g_pCommonData->injector->initialize())
		return LOGERROR(STATUS_FLT_NOT_INITIALIZED, "Failed to initialize IInjector\r\n");

	/// Init notification about newly loaded images.
	g_pDeviceObjectForWorkItem = g_pCommonData->pIoctlDeviceObject;
	KeInitializeSpinLock(&g_mtxInitialThreadTokens);
	RtlZeroMemory(g_initialThreadTokens, sizeof(g_initialThreadTokens));
	g_fInitialThreadTokensInit = TRUE;
	
	IFERR_RET(PsSetLoadImageNotifyRoutine(ImageCallback), "Failed to set LoadImageNotifyRoutine\r\n");
	IFERR_RET(PsSetCreateThreadNotifyRoutine(CreateThreadCallback), "Failed to set CreateThreadNotifyRoutine\r\n");

	g_pCommonData->fDllInjectorIsInitialized = true;

	return STATUS_SUCCESS;
}

//
//
//
void finalize()
{
	if (!g_pCommonData->fDllInjectorIsInitialized)
		return;

	g_pCommonData->fDllInjectorIsInitialized = false;
	g_fInitialThreadTokensInit = FALSE;

	// unregister the notification about images
	PsRemoveCreateThreadNotifyRoutine(CreateThreadCallback);
	PsRemoveLoadImageNotifyRoutine(ImageCallback);
}


namespace detail {

//
//
//
void notifyOnProcessCreation(procmon::Context* pNewProcessCtx, procmon::Context* pParentProcessCtx)
{
	if (!g_pCommonData->fDllInjectorIsInitialized)
		return;

	if (pNewProcessCtx != nullptr && pParentProcessCtx != nullptr)
	{
		recordInitialThreadToken(pNewProcessCtx->processInfo.nPid, pParentProcessCtx->processInfo.nPid);
	}

	if (!g_pCommonData->fEnableDllInjection)
		return;

	// Injection filtration
	if (!pNewProcessCtx->fEnableInject)
	{
		LOGINFO3("Skip injection of DLL into process. pid: %Iu.\r\n", (ULONG_PTR)pNewProcessCtx->processInfo.nPid);
		return;
	}

	LOGINFO3("Try to inject DLL into process. pid: %Iu.\r\n", (ULONG_PTR)pNewProcessCtx->processInfo.nPid);

	g_pCommonData->injector->onProcessCreate(HandleToUlong(pNewProcessCtx->processInfo.nPid), HandleToUlong(pParentProcessCtx->processInfo.nPid));
}

//
//
//
void notifyOnProcessTermination(procmon::Context* pProcessCtx)
{
	if (!g_pCommonData->fDllInjectorIsInitialized)
		return;

	g_pCommonData->injector->onProcessTerminate(HandleToUlong(pProcessCtx->processInfo.nPid));
}

} // namespace detail

} // namespace dllinj
} // namespace cmd
