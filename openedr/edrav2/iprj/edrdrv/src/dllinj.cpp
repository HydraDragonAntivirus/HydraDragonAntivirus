//
//  edrav2.libdllinj
//  Driver library for DLL injection
//
///
/// @file libdllinj API
///
#pragma once

#include "common.h"
#include "dllinj.h"

namespace cmd {
namespace dllinj {

using kernelInjectLib::eInjectorType;
using kernelInjectLib::IInjector;

//
//
//
static PDEVICE_OBJECT g_pDeviceObjectForWorkItem = nullptr;

//
// This callback is called whenever a new image is loaded
//
static VOID ImageCallback(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	if (ProcessId != 0 && ProcessId != PsGetProcessId(PsInitialSystemProcess))
	{
		g_pCommonData->injector->onImageLoad(g_pDeviceObjectForWorkItem, ProcessId, FullImageName, ImageInfo);
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
