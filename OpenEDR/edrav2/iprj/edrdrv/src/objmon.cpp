//
// edrav2.edrdrv project
//
// Author: Yury Podpruzhnikov (31.01.2019)
// Reviewer: Denis Bogdanov (21.02.2019)
//
///
/// @file Processes access filter (self protection)
///
/// @addtogroup edrdrv
/// @{
#include "common.h"
#include "osutils.h"
#include "objmon.h"
#include "fltport.h"

namespace cmd {
namespace objmon {

//////////////////////////////////////////////////////////////////////////
//
// Sending events
//
//////////////////////////////////////////////////////////////////////////

namespace detail {

//
// Universal file event sending
//
template<typename Fn>
NTSTATUS sendObjectEvent(SysmonEvent eEvent, ULONG_PTR nProcessId, Fn fnWriteAdditionalData)
{
	NonPagedLbvsSerializer<edrdrv::EventField> serializer;

	// +FIXME : Why STATUS_NO_MEMORY?
	// Cause only no memory can lead to error.
	if (!serializer.write(EvFld::RawEventId, uint16_t(eEvent))) return STATUS_NO_MEMORY;
	//if (!serializer.write(EvFld::Time, getSystemTime())) return STATUS_NO_MEMORY;
	if (!serializer.write(EvFld::TickTime, getTickCount64())) return STATUS_NO_MEMORY;
	if (!serializer.write(EvFld::ProcessPid, (uint32_t)nProcessId)) return STATUS_NO_MEMORY;

	IFERR_RET(fnWriteAdditionalData(&serializer));

	return fltport::sendRawEvent(serializer);
}


} // namespace detail

//
// Universal file event sending
//
template<typename Fn>
void sendObjectEvent(SysmonEvent eEvent, Fn fnWriteAdditionalData)
{
	auto nProcessId = (ULONG_PTR)PsGetCurrentProcessId();

	IFERR_LOG(detail::sendObjectEvent(eEvent, nProcessId, fnWriteAdditionalData),
		"Can't send object event %u pid: %Iu.\r\n", (ULONG)eEvent, nProcessId);
}

//
//
//
GENERIC_MAPPING c_processGenericMapping =
{
	0x21410, // GenericRead
	0x20BEA, // GenericWrite
	0x121001, // GenericExecute
	PROCESS_ALL_ACCESS // GenericAll
};

//
// Expand Generic in desiredAccess for processes
//
ACCESS_MASK expandProcessDesiredAccess(ACCESS_MASK src)
{
	RtlMapGenericMask(&src, &c_processGenericMapping);
	return src;
}

//
// File (FILE_OBJECT) section-mapping access bits.
// A file handle is opened with SECTION_MAP_READ / SECTION_MAP_WRITE before
// NtCreateSection/NtMapViewOfSection maps it. IRP_MJ_READ/IRP_MJ_WRITE never
// fire for such mapped-section access, so the handle-open desired access is the
// only IRP-side signal that reveals the mapping intent. Mimic the generic
// mapping used by the I/O manager for file objects.
//
GENERIC_MAPPING c_fileGenericMapping =
{
	FILE_GENERIC_READ,    // GenericRead
	FILE_GENERIC_WRITE,   // GenericWrite
	FILE_GENERIC_EXECUTE, // GenericExecute
	FILE_ALL_ACCESS       // GenericAll
};

//
// Expand Generic in desiredAccess for file objects
//
ACCESS_MASK expandFileDesiredAccess(ACCESS_MASK src)
{
	RtlMapGenericMask(&src, &c_fileGenericMapping);
	return src;
}

#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

//
// THREAD_* access rights (same values as winnt.h)
//
#define THREAD_TERMINATE                   (0x0001)
#define THREAD_SUSPEND_RESUME              (0x0002)
#define THREAD_ALERT                       (0x0004)
#define THREAD_GET_CONTEXT                 (0x0008)
#define THREAD_SET_CONTEXT                 (0x0010)
#define THREAD_SET_INFORMATION             (0x0020)
#define THREAD_QUERY_INFORMATION           (0x0040)
#define THREAD_SET_THREAD_TOKEN            (0x0080)
#define THREAD_IMPERSONATE                 (0x0100)
#define THREAD_DIRECT_IMPERSONATION        (0x0200)
#define THREAD_SET_LIMITED_INFORMATION     (0x0400)
#define THREAD_QUERY_LIMITED_INFORMATION   (0x0800)
#define THREAD_RESUME                      (0x1000)
#define THREAD_READ_CONTROL                (0x00020000)
#define THREAD_WRITE_DAC                   (0x00040000)
#define THREAD_WRITE_OWNER                 (0x00080000)  


//
//
//
struct ProcessCallContext
{
	HANDLE nInitiatorPid = nullptr;
	HANDLE nTargetPid = nullptr;

	ProcessCallContext(HANDLE nPidInitiator_, HANDLE nTargetPid_) :
		nTargetPid(nTargetPid_), nInitiatorPid(nPidInitiator_)
	{
	}
};

//
// Process objects hook
//
OB_PREOP_CALLBACK_STATUS preProcessObjectAccess(PVOID /*RegistrationContext*/, 
	POB_PRE_OPERATION_INFORMATION preOpInfo)
{
	// We should collect data on preAction
	// because we don't have correct all information on postAction

	if (!g_pCommonData->fObjMonStarted)
		return OB_PREOP_SUCCESS;

	// Skip if access is from kernel
	if (preOpInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	// Check parameters
	if ((PEPROCESS)preOpInfo->Object == nullptr)
		return OB_PREOP_SUCCESS;

	// Extract operation information
	HANDLE nInitiatorPid = PsGetCurrentProcessId(); //< Accessor
	HANDLE nTargetPid = PsGetProcessId((PEPROCESS)preOpInfo->Object); //< target object
	HANDLE nDstPid = nullptr; //< Destination process (which will have new handle)
	ACCESS_MASK* pDesiredAccess = nullptr;
	if (preOpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
	{
		nDstPid = nInitiatorPid;
		pDesiredAccess = &preOpInfo->Parameters->CreateHandleInformation.DesiredAccess;
	}
	else if (preOpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
	{
		auto& pInfo = preOpInfo->Parameters->DuplicateHandleInformation;
		nDstPid = PsGetProcessId((PEPROCESS)pInfo.TargetProcess);
		// TODO: Skip event if SourceProcess == nInitiatorPid
		pDesiredAccess = &pInfo.DesiredAccess;
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	ACCESS_MASK eOrigDesiredAccess = *pDesiredAccess;
	ACCESS_MASK eExpandedDesiredAccess = expandProcessDesiredAccess(eOrigDesiredAccess);

	//LOGINFO4("preOpenProcess: act:%u ini: %Iu, trg: %Iu, dst: %Iu, da:0x%08X.\r\n", 
	//	(ULONG)preOpInfo->Operation, (ULONG_PTR)nInitiatorPid, (ULONG_PTR)nTargetPid, 
	//	(ULONG_PTR)nDstPid, (ULONG)eOrigDesiredAccess );

	// Skip access to self
	if (nInitiatorPid == nTargetPid)
		return OB_PREOP_SUCCESS;

	// Get contexts
	procmon::ContextPtr pTargetCtx;
	procmon::ContextPtr pInitiatorCtx;
	IFERR_LOG(procmon::fillContext(nTargetPid, nullptr, pTargetCtx));
	IFERR_LOG(procmon::fillContext(nInitiatorPid, nullptr, pInitiatorCtx));

	// Skip access from parent to child
	bool fHasParentChildRelation = false;
	if (pTargetCtx)
	{
		auto nTargetParent = pTargetCtx->processInfo.nParentPid;
		fHasParentChildRelation = (nTargetParent == nInitiatorPid) || (nTargetParent == nDstPid);
	}

	// Check selfdefense
	do 
	{
		static constexpr ACCESS_MASK c_nDeniedAccessMask = PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
			PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE |
			PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION |
			PROCESS_SUSPEND_RESUME | /*PROCESS_QUERY_LIMITED_INFORMATION |*/ PROCESS_SET_LIMITED_INFORMATION;

		// If has parent-child relations, allow all
		if(fHasParentChildRelation)
			break;
		// If Target is not protected, allow all
		if (!pTargetCtx || !pTargetCtx->fIsProtected)
			break;

		// If Initiator is trusted, allow all
		if(procmon::isProcessTrusted(pInitiatorCtx))
			break;

		// Skip access from csrss
		if(testFlag(pInitiatorCtx->processInfo.nFlags, (UINT32)ProcessInfoFlags::CsrssProcess))
			break;
		

		// If no denied access
		if((eExpandedDesiredAccess & c_nDeniedAccessMask) == 0)
			break;
		
		// partial restrict access
		*pDesiredAccess = eExpandedDesiredAccess & ~c_nDeniedAccessMask;

		if (*pDesiredAccess == 0)
			*pDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;

		LOGINFO1("Selfdefense: Partial restrict access: pid: %Iu, operation: %u, targetPid: %Iu, oldAccess: 0x%08X, newAccess: 0x%08X.\r\n", 
			(ULONG_PTR)nInitiatorPid, (ULONG)preOpInfo->Operation, 
			(ULONG_PTR)nTargetPid, (ULONG)eOrigDesiredAccess, (ULONG)*pDesiredAccess);
	} while (false);
	

	// Filtering events for sending
	bool fSendEvent = false;
	do 
	{
		if (!g_pCommonData->fEnableMonitoring)
			break;
		if (fHasParentChildRelation)
			break;
		// Skip white list processes
		if (procmon::isProcessInWhiteList(pInitiatorCtx))
			break;
		if (!isEventEnabled(SysmonEvent::ProcessOpen))
			break;

		// Skip terminated processes
		if (pTargetCtx && pTargetCtx->processInfo.fIsTerminated)
			break;

		fSendEvent = true;
	} while (false);


	// All check are completed - init postOperation call context
	if (fSendEvent)
		preOpInfo->CallContext = new (NonPagedPool) ProcessCallContext(nInitiatorPid, nTargetPid);

	return OB_PREOP_SUCCESS;
}

//
//
//
VOID postProcessObjectAccess(PVOID /*RegistrationContext*/, POB_POST_OPERATION_INFORMATION postOpInfo)
{
	// Skip action skipped by preAction
	if (postOpInfo->CallContext == nullptr)
		return;

	UniquePtr<ProcessCallContext> pCallContext((ProcessCallContext*)postOpInfo->CallContext);

	// Skip unsuccessful
	if (!NT_SUCCESS(postOpInfo->ReturnStatus))
		return;

	// Check GrantedAccess
	ACCESS_MASK eGrantedAccess = (postOpInfo->Operation == OB_OPERATION_HANDLE_CREATE) ?
		postOpInfo->Parameters->CreateHandleInformation.GrantedAccess :
		postOpInfo->Parameters->DuplicateHandleInformation.GrantedAccess;

	// All but querying information
	static constexpr ACCESS_MASK eDetectedAccessMask = PROCESS_TERMINATE | PROCESS_CREATE_THREAD |
		PROCESS_SET_SESSIONID | PROCESS_VM_OPERATION | /*PROCESS_VM_READ |*/ PROCESS_VM_WRITE | /*PROCESS_DUP_HANDLE |*/
		PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | /*PROCESS_QUERY_INFORMATION |*/
		PROCESS_SUSPEND_RESUME /*| PROCESS_QUERY_LIMITED_INFORMATION*/ /*| PROCESS_SET_LIMITED_INFORMATION*/;

	if (!FlagOn(eGrantedAccess, eDetectedAccessMask))
		return;

	// Filter repeated openProcess
	bool fSendEvent = true;
	do 
	{
		procmon::ContextPtr pInitiatorCtx;
		IFERR_LOG(procmon::fillContext(pCallContext->nInitiatorPid, nullptr, pInitiatorCtx));
		if (!pInitiatorCtx)
			break;

		uint64_t nCurTime = getTickCount64();

		{
			ScopedLock lock(g_pCommonData->mtxOpenProcessFilter);
			auto pFilter = pInitiatorCtx->pOpenProcessFilter;

			// Check event repeat
			procmon::Context::OpenProcessInfo* pOpenProcessInfo = nullptr;
			IFERR_LOG(pFilter->findOrInsert((uint32_t)(ULONG_PTR) pCallContext->nTargetPid, &pOpenProcessInfo));
			if (pOpenProcessInfo != nullptr)
			{
				if ((nCurTime - pOpenProcessInfo->m_LastOpenSend) < g_pCommonData->nOpenProcessRepeatTimeout)
					fSendEvent = false;
				else
					pOpenProcessInfo->m_LastOpenSend = nCurTime;
			}

			// Garbage collecting
			static constexpr uint64_t c_nGarbageCollectTimeout = 5 /*min*/ * 60 /*sec*/ * 1000 /*ms*/;
			if (fSendEvent && nCurTime - pInitiatorCtx->nLastGarbageCollectTime > c_nGarbageCollectTimeout)
			{
				auto endIter = pFilter->end();
				for (auto iter = pFilter->begin(); iter != endIter;)
				{
					if (nCurTime - iter->second.m_LastOpenSend < c_nGarbageCollectTimeout)
						++iter;
					else
						iter = pFilter->remove(iter);
				}
				pInitiatorCtx->nLastGarbageCollectTime = nCurTime;
			}
		}
	} while (false);

	if (!fSendEvent)
		return;

	LOGINFO2("sendEvent: %u (objectEvent), pid: %Iu, target: %Iu, access: 0x%08X, oper:%u, status: 0x%08X.\r\n", 
		(ULONG)SysmonEvent::ProcessOpen, (ULONG_PTR)pCallContext->nInitiatorPid, 
		(ULONG_PTR)pCallContext->nTargetPid, (ULONG)eGrantedAccess, (ULONG) postOpInfo->Operation, 
		(ULONG) postOpInfo->ReturnStatus);

	// Send event
	sendObjectEvent(SysmonEvent::ProcessOpen, 
		[eGrantedAccess, &pCallContext](auto pSerializer) {
			if (!pSerializer->write(EvFld::TargetProcessPid, (uint32_t) (ULONG_PTR)pCallContext->nTargetPid)) 
				return STATUS_NO_MEMORY;
			if (!pSerializer->write(EvFld::AccessMask, uint32_t(eGrantedAccess)))
				return STATUS_NO_MEMORY;
			return STATUS_SUCCESS;
		}
	);
}

//
//
//
struct FileCallContext
{
	HANDLE nInitiatorPid = nullptr;
	ACCESS_MASK eDesiredAccess = 0;
	PFILE_OBJECT pFileObject = nullptr;

	FileCallContext(HANDLE nPidInitiator_, ACCESS_MASK eDesiredAccess_, PFILE_OBJECT pFileObject_) :
		nInitiatorPid(nPidInitiator_), eDesiredAccess(eDesiredAccess_), pFileObject(pFileObject_)
	{
		if (pFileObject != nullptr)
			ObReferenceObject(pFileObject);
	}

	~FileCallContext()
	{
		if (pFileObject != nullptr)
			ObDereferenceObject(pFileObject);
	}
};

//
// File objects hook
//
OB_PREOP_CALLBACK_STATUS preFileObjectAccess(PVOID /*RegistrationContext*/, 
	POB_PRE_OPERATION_INFORMATION preOpInfo)
{
	if (!g_pCommonData->fObjMonStarted)
		return OB_PREOP_SUCCESS;

	// Skip if access is from kernel
	if (preOpInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	// Check parameters
	if ((PFILE_OBJECT)preOpInfo->Object == nullptr)
		return OB_PREOP_SUCCESS;

	// Extract desired access
	ACCESS_MASK eDesiredAccess = 0;
	if (preOpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		eDesiredAccess = preOpInfo->Parameters->CreateHandleInformation.DesiredAccess;
	else if (preOpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		eDesiredAccess = preOpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
	else
		return OB_PREOP_SUCCESS;

	// Expand generics (e.g. GENERIC_READ on a file means FILE_GENERIC_READ)
	ACCESS_MASK eExpandedAccess = expandFileDesiredAccess(eDesiredAccess);

	// Only mapping-capable opens are interesting. Readable/writable mapping is
	// the only way to access a file's content through a section without an
	// IRP_MJ_READ/IRP_MJ_WRITE, so a handle carrying SECTION_MAP_* access is
	// exactly the "united api+minifilter" kernel-side leg we want to observe.
	static constexpr ACCESS_MASK c_nMapAccessMask = SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_EXTEND_SIZE;
	if ((eExpandedAccess & c_nMapAccessMask) == 0)
		return OB_PREOP_SUCCESS;

	// Filtering for event sending
	bool fSendEvent = false;
	do
	{
		if (!g_pCommonData->fEnableMonitoring)
			break;

		auto nInitiatorPid = (ULONG_PTR)PsGetCurrentProcessId();

		procmon::ContextPtr pInitiatorCtx;
		IFERR_LOG(procmon::fillContext((HANDLE)nInitiatorPid, nullptr, pInitiatorCtx));
		if (!pInitiatorCtx)
			break;
		if (procmon::isProcessInWhiteList(pInitiatorCtx))
			break;

		fSendEvent = true;
	} while (false);

	// All checks are completed - init postOperation call context
	if (fSendEvent)
		preOpInfo->CallContext = new (NonPagedPool) FileCallContext(
			PsGetCurrentProcessId(), eExpandedAccess, (PFILE_OBJECT)preOpInfo->Object);

	return OB_PREOP_SUCCESS;
}

//
//
//
VOID postFileObjectAccess(PVOID /*RegistrationContext*/, POB_POST_OPERATION_INFORMATION postOpInfo)
{
	// Skip action skipped by preAction
	if (postOpInfo->CallContext == nullptr)
		return;

	UniquePtr<FileCallContext> pCallContext((FileCallContext*)postOpInfo->CallContext);

	// Skip unsuccessful
	if (!NT_SUCCESS(postOpInfo->ReturnStatus))
		return;

	// Resolve the file name from the FILE_OBJECT.
	// The FILE_OBJECT->FileName field only holds the base name; use the
	// object-manager name (full NT path) instead.
	DynUnicodeString usFileName;
	NTSTATUS ns = ObQueryNameString(pCallContext->pFileObject, usFileName);
	PCUNICODE_STRING pusFileName = (PCUNICODE_STRING)usFileName;
	if (!NT_SUCCESS(ns) || pusFileName->Length == 0)
		return;

///
/// Emit a dedicated ObRegisterCallbacks file-handle-open event so the engine
/// exposes it as a distinct SDK rule type ("handle_open"), separate from the
/// minifilter IRP-level read/write and section-map (mmap) events. The desired
/// access is carried in the AccessMask field for finer rule filtering.
///
	SysmonEvent eEvent = SysmonEvent::FileHandleOpen;

	LOGINFO2("sendEvent: %u (fileObjectEvent), pid: %Iu, access: 0x%08X, file:<%wZ>.\r\n",
		(ULONG)eEvent, (ULONG_PTR)pCallContext->nInitiatorPid,
		(ULONG)pCallContext->eDesiredAccess, pusFileName);

	// Use the stored initiator PID (pre-op time) so cross-process handle
	// duplication is attributed to the original opener.
	IFERR_LOG(detail::sendObjectEvent(eEvent, (ULONG_PTR)pCallContext->nInitiatorPid,
		[pusFileName, &pCallContext](auto pSerializer) {
			if (!write(*pSerializer, EvFld::FilePath, pusFileName))
				return STATUS_NO_MEMORY;
			if (!pSerializer->write(EvFld::AccessMask, uint32_t(pCallContext->eDesiredAccess)))
				return STATUS_NO_MEMORY;
			return STATUS_SUCCESS;
		}
	), "Can't send file object event %u pid: %Iu.\r\n",
		(ULONG)eEvent, (ULONG_PTR)pCallContext->nInitiatorPid);
}

//
//
//
struct ThreadCallContext
{
	HANDLE nInitiatorPid = nullptr;
	ACCESS_MASK eDesiredAccess = 0;
	PETHREAD pThreadObject = nullptr;

	ThreadCallContext(HANDLE nPidInitiator_, ACCESS_MASK eDesiredAccess_, PETHREAD pThreadObject_) :
		nInitiatorPid(nPidInitiator_), eDesiredAccess(eDesiredAccess_), pThreadObject(pThreadObject_)
	{
		if (pThreadObject != nullptr)
			ObReferenceObject(pThreadObject);
	}

	~ThreadCallContext()
	{
		if (pThreadObject != nullptr)
			ObDereferenceObject(pThreadObject);
	}
};

//
// Thread objects hook
//
OB_PREOP_CALLBACK_STATUS preThreadObjectAccess(PVOID /*RegistrationContext*/,
	POB_PRE_OPERATION_INFORMATION preOpInfo)
{
	if (!g_pCommonData->fObjMonStarted)
		return OB_PREOP_SUCCESS;

	// Skip if access is from kernel
	if (preOpInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	// Check parameters
	if ((PETHREAD)preOpInfo->Object == nullptr)
		return OB_PREOP_SUCCESS;

	// Extract desired access
	ACCESS_MASK eDesiredAccess = 0;
	if (preOpInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		eDesiredAccess = preOpInfo->Parameters->CreateHandleInformation.DesiredAccess;
	else if (preOpInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		eDesiredAccess = preOpInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
	else
		return OB_PREOP_SUCCESS;

	// Filtering for event sending
	bool fSendEvent = false;
	do
	{
		if (!g_pCommonData->fEnableMonitoring)
			break;

		auto nInitiatorPid = (ULONG_PTR)PsGetCurrentProcessId();

		procmon::ContextPtr pInitiatorCtx;
		IFERR_LOG(procmon::fillContext((HANDLE)nInitiatorPid, nullptr, pInitiatorCtx));
		if (!pInitiatorCtx)
			break;
		if (procmon::isProcessInWhiteList(pInitiatorCtx))
			break;

		fSendEvent = true;
	} while (false);

	// All checks are completed - init postOperation call context
	if (fSendEvent)
		preOpInfo->CallContext = new (NonPagedPool) ThreadCallContext(
			PsGetCurrentProcessId(), eDesiredAccess, (PETHREAD)preOpInfo->Object);

	return OB_PREOP_SUCCESS;
}

//
//
//
VOID postThreadObjectAccess(PVOID /*RegistrationContext*/, POB_POST_OPERATION_INFORMATION postOpInfo)
{
	// Skip action skipped by preAction
	if (postOpInfo->CallContext == nullptr)
		return;

	UniquePtr<ThreadCallContext> pCallContext((ThreadCallContext*)postOpInfo->CallContext);

	// Skip unsuccessful
	if (!NT_SUCCESS(postOpInfo->ReturnStatus))
		return;

	// Check GrantedAccess
	ACCESS_MASK eGrantedAccess = (postOpInfo->Operation == OB_OPERATION_HANDLE_CREATE) ?
		postOpInfo->Parameters->CreateHandleInformation.GrantedAccess :
		postOpInfo->Parameters->DuplicateHandleInformation.GrantedAccess;

	// All but querying information
	static constexpr ACCESS_MASK eDetectedAccessMask = THREAD_TERMINATE | THREAD_SUSPEND_RESUME |
		THREAD_SET_CONTEXT | THREAD_SET_THREAD_TOKEN | THREAD_IMPERSONATE | THREAD_DIRECT_IMPERSONATION |
		THREAD_SET_INFORMATION | THREAD_READ_CONTROL | THREAD_WRITE_DAC | THREAD_WRITE_OWNER;

	if (!FlagOn(eGrantedAccess, eDetectedAccessMask))
		return;

	SysmonEvent eEvent = SysmonEvent::ThreadOpen;

	LOGINFO2("sendEvent: %u (threadObjectEvent), pid: %Iu, targetTid: %Iu, access: 0x%08X, oper:%u, status: 0x%08X.\r\n",
		(ULONG)eEvent, (ULONG_PTR)pCallContext->nInitiatorPid,
		(ULONG_PTR)PsGetThreadId(pCallContext->pThreadObject), (ULONG)eGrantedAccess,
		(ULONG)postOpInfo->Operation, (ULONG)postOpInfo->ReturnStatus);

	IFERR_LOG(detail::sendObjectEvent(eEvent, (ULONG_PTR)pCallContext->nInitiatorPid,
		[&pCallContext](auto pSerializer) {
			if (!pSerializer->write(EvFld::ThreadId, (uint32_t)(ULONG_PTR)PsGetThreadId(pCallContext->pThreadObject)))
				return STATUS_NO_MEMORY;
			if (!pSerializer->write(EvFld::AccessMask, uint32_t(pCallContext->eDesiredAccess)))
				return STATUS_NO_MEMORY;
			return STATUS_SUCCESS;
		}
	), "Can't send thread object event %u pid: %Iu.\r\n",
		(ULONG)eEvent, (ULONG_PTR)pCallContext->nInitiatorPid);
}

//////////////////////////////////////////////////////////////////////////
//
// Create/Terminate process callback
//
namespace detail {

//
//
//
void notifyOnProcessCreation(procmon::Context* pNewProcessCtx, 
	procmon::Context* pParentProcessCtx)
{
	if (!g_pCommonData->fObjMonStarted)
		return;

	// Protection inheritance
	if (pParentProcessCtx->fIsProtected)
		pNewProcessCtx->fIsProtected;

	return;
}

//
//
//
void notifyOnProcessTermination(procmon::Context* /*pProcessCtx*/)
{
}

} // namespace detail

//
// Initialization
//
NTSTATUS initialize()
{
	if (g_pCommonData->fObjMonStarted)
		return STATUS_SUCCESS;

	g_pCommonData->hProcFltCallbackRegistration = nullptr;
	g_pCommonData->hFileFltCallbackRegistration = nullptr;
	g_pCommonData->hThreadFltCallbackRegistration = nullptr;

	// Set hooks
	{
		// Processes callbacks. ObRegisterCallbacks allows only one object type
		// per registration call, so process and file objects are registered
		// separately.
		OB_OPERATION_REGISTRATION stObOpReg[2] = {};
		OB_CALLBACK_REGISTRATION stObCbReg = {};

		stObOpReg[0].ObjectType = PsProcessType;
		stObOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		stObOpReg[0].PreOperation = preProcessObjectAccess;
		stObOpReg[0].PostOperation = postProcessObjectAccess;

		stObCbReg.Version = OB_FLT_REGISTRATION_VERSION;
		stObCbReg.OperationRegistrationCount = 1;
		stObCbReg.OperationRegistration = stObOpReg;
		RtlInitUnicodeString(&stObCbReg.Altitude, edrdrv::c_sAltitudeValue);

		IFERR_RET(ObRegisterCallbacks(&stObCbReg, &g_pCommonData->hProcFltCallbackRegistration));
	}

	// Set file object callbacks
	{
		OB_OPERATION_REGISTRATION stObOpReg[2] = {};
		OB_CALLBACK_REGISTRATION stObCbReg = {};

		stObOpReg[0].ObjectType = IoFileObjectType;
		stObOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		stObOpReg[0].PreOperation = preFileObjectAccess;
		stObOpReg[0].PostOperation = postFileObjectAccess;

		stObCbReg.Version = OB_FLT_REGISTRATION_VERSION;
		stObCbReg.OperationRegistrationCount = 1;
		stObCbReg.OperationRegistration = stObOpReg;
		RtlInitUnicodeString(&stObCbReg.Altitude, edrdrv::c_sAltitudeValue);

		IFERR_RET(ObRegisterCallbacks(&stObCbReg, &g_pCommonData->hFileFltCallbackRegistration));
	}

	// Set thread object callbacks
	{
		OB_OPERATION_REGISTRATION stObOpReg[2] = {};
		OB_CALLBACK_REGISTRATION stObCbReg = {};

		stObOpReg[0].ObjectType = PsThreadType;
		stObOpReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
		stObOpReg[0].PreOperation = preThreadObjectAccess;
		stObOpReg[0].PostOperation = postThreadObjectAccess;

		stObCbReg.Version = OB_FLT_REGISTRATION_VERSION;
		stObCbReg.OperationRegistrationCount = 1;
		stObCbReg.OperationRegistration = stObOpReg;
		RtlInitUnicodeString(&stObCbReg.Altitude, edrdrv::c_sAltitudeValue);

		IFERR_RET(ObRegisterCallbacks(&stObCbReg, &g_pCommonData->hThreadFltCallbackRegistration));
	}

	g_pCommonData->fObjMonStarted = TRUE;

	return STATUS_SUCCESS;
}

//
//
//
void finalize()
{
	if (!g_pCommonData->fObjMonStarted) return;

	// Reset hooks
	if (g_pCommonData->hProcFltCallbackRegistration != nullptr)
	{
		ObUnRegisterCallbacks(g_pCommonData->hProcFltCallbackRegistration);
		g_pCommonData->hProcFltCallbackRegistration = nullptr;
	}

	if (g_pCommonData->hFileFltCallbackRegistration != nullptr)
	{
		ObUnRegisterCallbacks(g_pCommonData->hFileFltCallbackRegistration);
		g_pCommonData->hFileFltCallbackRegistration = nullptr;
	}

	if (g_pCommonData->hThreadFltCallbackRegistration != nullptr)
	{
		ObUnRegisterCallbacks(g_pCommonData->hThreadFltCallbackRegistration);
		g_pCommonData->hThreadFltCallbackRegistration = nullptr;
	}

	g_pCommonData->fObjMonStarted = FALSE;
}

} // namespace objmon
} // namespace cmd
/// @}
