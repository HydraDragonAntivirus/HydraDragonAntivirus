//
// edrav2.edrdrv project
//
// Author: Yury Podpruzhnikov (31.01.2019)
// Reviewer: Denis Bogdanov (21.02.2019)
//
///
/// @file File filter
///
/// @addtogroup edrdrv
/// @{
#include <initguid.h>

#include "common.h"
#include "osutils.h"
#include "filemon.h"
#include "diskutils.h"
#include "ShanonEntropy.h"
#include "procmon.h"
#include "fltport.h"
#include "config.h"

#include <Ntddstor.h>
#include <ntstrsafe.h>

#ifndef IOCTL_DISK_BASE
#define IOCTL_DISK_BASE FILE_DEVICE_DISK
#endif

#ifndef IOCTL_SCSI_BASE
#define IOCTL_SCSI_BASE FILE_DEVICE_CONTROLLER
#endif

#ifndef IOCTL_DISK_FORMAT_TRACKS
#define IOCTL_DISK_FORMAT_TRACKS \
	CTL_CODE(IOCTL_DISK_BASE, 0x0006, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_DISK_FORMAT_TRACKS_EX
#define IOCTL_DISK_FORMAT_TRACKS_EX \
	CTL_CODE(IOCTL_DISK_BASE, 0x000B, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_DISK_SET_DRIVE_LAYOUT_EX
#define IOCTL_DISK_SET_DRIVE_LAYOUT_EX \
	CTL_CODE(IOCTL_DISK_BASE, 0x0015, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

#ifndef IOCTL_SCSI_PASS_THROUGH_DIRECT
#define IOCTL_SCSI_PASS_THROUGH_DIRECT \
	CTL_CODE(IOCTL_SCSI_BASE, 0x0405, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

namespace cmd {
namespace filemon {

static constexpr USHORT c_nMinSectorSize = 0x200;

// predefinition
bool isSelfProtected(PCUNICODE_STRING pusFileName, ACCESS_MASK desiredAccess);


//
//
//
enum class VolumeDriveType
{
	Fixed,
	Network,
	Removable
};

//
//
//
inline const char* convertToString(VolumeDriveType eType)
{
	switch (eType)
	{
	case cmd::filemon::VolumeDriveType::Fixed:
		return "FIXED";
	case cmd::filemon::VolumeDriveType::Network:
		return "NETWORK";
	case cmd::filemon::VolumeDriveType::Removable:
		return "REMOVABLE";
	default:
		return "";
	}
}

//
//
//
enum class CreationStatus
{
	None = 0, //< Not init
	Created, //< New file was created. Old file was not exist.
	Opened, //< Old file was opened
	Truncated, //< Old file was truncated
};


///
/// InstanceContext.
///
struct InstanceContext
{
	PFLT_INSTANCE pInstance; ///< Instance for this context.

	BOOLEAN fSetupIsFinished; ///< Context was succesfulle filled.

	BOOLEAN fIsNetworkFS; ///< is network FS (MUP, virtual machine shares)
	BOOLEAN fIsMup; ///< is standard windows network share access (network FS)

	BOOLEAN fIsUsb; ///< is USB device
	BOOLEAN fPidVidSnDetected; ///< USB pid vid is detected
	BOOLEAN fIsFixed; ///< fixed drive
	BOOLEAN fIsCdrom; ///< cdrom drive

	USHORT nSectorSize; ///< size of sector

	char sDeviceName[260]; ///< Device name for logging

	VolumeDriveType eDriveType; ///< Internal drive type for event

	UNICODE_STRING usDiskPdoName; ///< Disk PDO. if not filled, .length = 0
	PVOID pDiskPdoNameBuffer; ///< For internal usage. Disk PDO buffer. 

	UNICODE_STRING usDeviceName; ///< Volume device name. if not filled, .length = 0
	PVOID pDeviceNameBuffer; ///< For internal usage. Disk PDO buffer. 

	UNICODE_STRING usContainerId; ///< Disk ContainerId. if not filled, .length = 0
	PVOID pContainerIdBuffer; ///< For internal usage. Disk ContainerId buffer.

	UNICODE_STRING usVolumeGuid; ///< Volume GUID. if not filled, .length = 0
	WCHAR sVolumeGuidBuffer[100]; ///< For internal usage. usVolumeGuid buffer. 

	void init()
	{
		RtlZeroMemory(this, sizeof(*this));

		usVolumeGuid.Buffer = sVolumeGuidBuffer;
		usVolumeGuid.Length = 0;
		usVolumeGuid.MaximumLength = sizeof(sVolumeGuidBuffer);

		nSectorSize = c_nMinSectorSize;
	}
};

//////////////////////////////////////////////////////////////////////////
//
// StreamHandleContext
//

///
/// Special cases flags.
///
CMD_DEFINE_ENUM_FLAG(SpecialCase, uint64_t)
{
	PrefetchOpen = 1 << 0, ///< Windows prefetcher opens file
	MsSecurityFltOpen = 1 << 1, ///< Windows Defender opens file
	CsvDownLevelOpen = 1 << 2, ///< Low level csvfs
};

///
/// Info to detect sequence file reading/writing.
///
struct SequenceActionInfo
{
	AtomicBool fEnabled = FALSE; ///< Processing is enabled
	xxh::hash_state64_t hash;  ///< Processed data hash
	uint64_t nNextPos = 0;  ///< Expected offset of next action
	ULONGLONG nMaxEntropyQ24 = 0; ///< Maximum entropy detected during sequence

	// Allow processing sub-IRP requests 
	// sub-IRP can be sent if driver returns STATUS_FLT_DISALLOW_FAST_IO
	BOOLEAN fAllowNotTopLevelIrp = FALSE;

	//
	//
	//
	NTSTATUS updateHash(const void* pData, size_t nDataSize)
	{
		NTSTATUS eCalcStatus = STATUS_SUCCESS;
		__try
		{
			auto eErrorCode = hash.update(pData, nDataSize);
			if (eErrorCode == xxh::error_code::ok)
			{
				nNextPos += nDataSize;
				__leave;
			}

			eCalcStatus = STATUS_UNSUCCESSFUL;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			eCalcStatus = GetExceptionCode();
		}

		return eCalcStatus;
	}
};

static constexpr uint64_t c_nUnknownFileSize = (uint64_t)-1;

///
/// StreamHandleContext structure.
///
struct StreamHandleContext
{
private:
	// alloc it via create method.
	StreamHandleContext() = default;

	~StreamHandleContext()
	{
		if (pNameInfo != nullptr)
		{
			FltReleaseFileNameInformation(pNameInfo);
			pNameInfo = nullptr;
		}

		if (pInstanceContext != nullptr)
		{
			FltReleaseContext(pInstanceContext);
			pInstanceContext = nullptr;
		}

		RansomTeeClose(false);
	}


	// class placement new
	void* __cdecl operator new (size_t, void * p)
	{
		return p;
	}

	// class placement delete
	void __cdecl operator delete(void*)
	{
	}

public:

	PFLT_FILE_NAME_INFORMATION pNameInfo = nullptr; ///< File name information
	uint64_t nSizeAtCreation = c_nUnknownFileSize;  ///< size of file at handle creation

	ULONG_PTR nOpeningProcessId = 0; ///< process which opened file

	CreationStatus eCreationStatus = CreationStatus::None; ///< Creation information.
	BOOLEAN fIsDirectory = FALSE; ///< it is directory
	BOOLEAN fIsExecute = FALSE;  ///< File was opened for execution
	BOOLEAN fDeleteOnClose = FALSE;  ///< File will be deleted on close
	BOOLEAN fDispositionDelete = FALSE;  ///< SetFileInfo(FILE_DISPOSITION_DELETE) was called
	BOOLEAN fWasChanged = FALSE;  ///< There was a successful write operation.

	BOOLEAN fSkipItem = FALSE; ///< Don't send events for file

	SequenceActionInfo sequenceReadInfo;
	SequenceActionInfo sequenceWriteInfo;

	// RansomShield: set once the pre-overwrite content has been shadow-
	// copied to ProgramData for this handle (pre-image saved at most once).
	volatile LONG fPreImageSaved = 0;
	BOOLEAN fIsBackupFile = FALSE;

	// Read-time tee: while sequence-read hashing streams through the filter,
	// bytes are duplicated into this handle so the ORIGINAL content survives
	// any later overwrite/delete (exclusive-open ransomware included).
	HANDLE hRansomTee = nullptr;
	PFILE_OBJECT pRansomTeeObj = nullptr;
	LARGE_INTEGER nRansomOff = {};
	wchar_t szRansomDst[300] = L"";

	InstanceContext* pInstanceContext = nullptr; ///< VolumeInfo

	// RansomShield tee helpers (defined below, prototypes here)
	void RansomTeeOpenIfNeeded(PCFLT_RELATED_OBJECTS pFltObjects);
	void RansomTeeChunk(PCFLT_RELATED_OBJECTS pFltObjects, void* pDataBuffer, SIZE_T nLen);
	void RansomTeeClose(bool fFlush);

	static NTSTATUS create(StreamHandleContext** ppThis, PCFLT_RELATED_OBJECTS pFltObjects)
	{
		// alloc
		PFLT_CONTEXT pFltCtx = nullptr;
		NTSTATUS ns = FltAllocateContext(pFltObjects->Filter,
			FLT_STREAMHANDLE_CONTEXT, sizeof(StreamHandleContext),
			NonPagedPool, &pFltCtx);
		if (!NT_SUCCESS(ns))
		{
			IFERR_LOG(ns);
			if (pFltCtx != nullptr)
				FltReleaseContext(pFltCtx);
			return ns;
		}

		// add context
		ns = FltSetStreamHandleContext(pFltObjects->Instance,
			pFltObjects->FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
			pFltCtx, nullptr);
		if (!NT_SUCCESS(ns))
		{
			IFERR_LOG(ns);
			if (pFltCtx != nullptr)
				FltReleaseContext(pFltCtx);
			return ns;
		}

		// call constructor
		*ppThis = new(pFltCtx) StreamHandleContext;

		return STATUS_SUCCESS;
	}

	static void cleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE /*ContextType*/)
	{
		auto pCtx = (StreamHandleContext*)Context;
		delete pCtx; // class delete is called
		//pCtx->~StreamHandleContext();
	}
};

//
// Constants
//

// Constant for logging
PRESET_STATIC_UNICODE_STRING(c_usUnknown, L"UNKNOWN");

// ESP of Windows  defender
#ifndef GUID_ECP_MSSECFLT_OPEN_DEFINED
DEFINE_GUID(GUID_ECP_MSSECFLT_OPEN, 0xAB97C9D8, 0x9A82, 0x4E58, 0xA2, 0x09,
	0xCD, 0x56, 0xC5, 0x8A, 0xA5, 0xD4);
#endif // GUID_ECP_MSSECFLT_OPEN_DEFINED

// This GUID is used to identify ECP that is sent by CsvFs to the
// Metadata Node (MDS a.k.a. Coordinating Node), and contains information
// about the type of the create.
#if (NTDDI_VERSION < NTDDI_WIN8)
DEFINE_GUID(GUID_ECP_CSV_DOWN_LEVEL_OPEN,
	0x4248be44,
	0x647f,
	0x488f,
	0x8b, 0xe5, 0xa0, 0x8a, 0xaf, 0x70, 0xf0, 0x28);
#endif // NTDDI_VERSION < NTDDI_WIN8


CMD_DEFINE_ENUM_FLAG(PostOperationFlag, ULONG_PTR)
{
	None = 0,
	
	// Write at same position is detected.
	// Possible ned to skip update hash. See postWrite().
	WriteToSamePosition = 1 << 0,
};


//////////////////////////////////////////////////////////////////////////
//
// USB info API
//
//////////////////////////////////////////////////////////////////////////


///
/// Check Usb info and set InstanceContext flags.
///
/// @param pFltObjects - TBD.
/// @param pInCtx - TBD.
/// @returns The function returns NTSTATUS of the operation.
///
NTSTATUS collectUsbInfo(PCFLT_RELATED_OBJECTS pFltObjects, InstanceContext* pInCtx)
{
	//PrintVolumeInfo(pFltObjects);

	PDEVICE_OBJECT pDevObj = NULL;
	__try
	{
		// Get pDevObj
		IFERR_RET(FltGetDiskDeviceObject(pFltObjects->Volume, &pDevObj));
		if (pDevObj == NULL) return LOGERROR(STATUS_UNSUCCESSFUL);
		
		// Get pDevDesc
		CHAR sBuffer[512];
		auto pDevDesc = (PSTORAGE_DEVICE_DESCRIPTOR)&sBuffer[0];
		
		STORAGE_PROPERTY_QUERY propertyQuery;
		propertyQuery.PropertyId = StorageDeviceProperty;
		propertyQuery.QueryType = PropertyStandardQuery;
		NTSTATUS ns = callKernelDeviceIoControl(pDevObj, IOCTL_STORAGE_QUERY_PROPERTY, 
			&propertyQuery, sizeof(propertyQuery), pDevDesc, sizeof(sBuffer));
		if (NT_ERROR(ns))
		{
			LOGINFO2("Can't get DeviceDescriptor for volume.\r\n");
			return STATUS_SUCCESS;
		}
	
		// Is it USB?
		if (pDevDesc->BusType != BusTypeUsb)
			return STATUS_SUCCESS;
		
		pInCtx->fIsUsb = TRUE;

		// Get PDO
		IFERR_LOG(getDiskPdoName(pDevObj, &pInCtx->usDiskPdoName, 
			&pInCtx->pDiskPdoNameBuffer), "Can't get DiskPdoName\r\n");
		
		// Get ContainerId
		if (g_pCommonData->fIsWin8orHigher)
			IFERR_LOG(getContainerId(pDevObj, &pInCtx->usContainerId, 
				&pInCtx->pContainerIdBuffer), "Can't get ContainerId\r\n");
	}
	__finally
	{
		if (pDevObj != NULL)
			ObDereferenceObject(pDevObj);
	}

	return STATUS_SUCCESS;
}


//////////////////////////////////////////////////////////////////////////
//
// Instance process
//
//////////////////////////////////////////////////////////////////////////


// 
// FltMgr calls this routine immediately before it deletes the context.
// 
// Arguments:
//     pContext - Pointer to the minifilter driver's portion of the context.
//     contextType - Type of context. Must be FLT_INSTANCE_CONTEXT
// 
VOID cleanupInstanceContext(_In_ PFLT_CONTEXT pContext, _In_ FLT_CONTEXT_TYPE /*eContextType*/)
{
	// +FIXME: Can pContext be NULL?
	// No. This function is called for allocated context only.
	InstanceContext* pInstanceContext = (InstanceContext*)pContext;

	if (pInstanceContext->pDiskPdoNameBuffer != nullptr)
		ExFreePoolWithTag(pInstanceContext->pDiskPdoNameBuffer, c_nAllocTag);

	if (pInstanceContext->pDeviceNameBuffer != nullptr)
		ExFreePoolWithTag(pInstanceContext->pDeviceNameBuffer, c_nAllocTag);
	
	if (pInstanceContext->pContainerIdBuffer != nullptr)
		ExFreePoolWithTag(pInstanceContext->pContainerIdBuffer, c_nAllocTag);
}

// 
// This routine is called whenever a new instance is created on a volume. This
// gives us a chance to decide if we need to attach to this volume or not.
// 
// If this routine is not defined in the registration structure, automatic
// instances are alwasys created.
// 
//   eVolumeDeviceType = 
//       FILE_DEVICE_CD_ROM_FILE_SYSTEM, FILE_DEVICE_DISK_FILE_SYSTEM, FILE_DEVICE_FILE_SYSTEM, 
//       FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_DEVICE_TAPE_FILE_SYSTEM, FILE_DEVICE_DFS_FILE_SYSTEM
//
// Return Value:
// 
//     STATUS_SUCCESS - attach
//     STATUS_FLT_DO_NOT_ATTACH - do not attach
// 
NTSTATUS setupInstance(_In_ PCFLT_RELATED_OBJECTS pFltObjects, 
	_In_ FLT_INSTANCE_SETUP_FLAGS /*eFlags*/,
    _In_ DEVICE_TYPE eVolumeDeviceType, 
	_In_ FLT_FILESYSTEM_TYPE eVolumeFilesystemType)
{	
	InstanceContext* pInstCtx = NULL;
	PFLT_VOLUME_PROPERTIES pVolumeProperties = NULL;

	__try
	{
		//  Allocate and set the instance context.
		PFLT_CONTEXT pFltCtx = NULL;
		IFERR_RET(FltAllocateContext(pFltObjects->Filter, FLT_INSTANCE_CONTEXT,
				sizeof(InstanceContext), NonPagedPool, &pFltCtx));
		pInstCtx = (InstanceContext*)pFltCtx;
		pInstCtx->init();
		pInstCtx->pInstance = pFltObjects->Instance;
		IFERR_RET(FltSetInstanceContext(pFltObjects->Instance, 
			FLT_SET_CONTEXT_REPLACE_IF_EXISTS, pInstCtx, NULL));
	
		if (eVolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM || 
			eVolumeDeviceType == FILE_DEVICE_CD_ROM)
			pInstCtx->fIsCdrom = TRUE;

		// Get VolumeProperties (safe)
		do 
		{
			ULONG nBufferSize = 0;
			NTSTATUS ns = FltGetVolumeProperties(pFltObjects->Volume, NULL, 0, &nBufferSize);
			if (NT_ERROR(ns) && ns != STATUS_BUFFER_TOO_SMALL) { IFERR_LOG(ns); break; }

			pVolumeProperties = (PFLT_VOLUME_PROPERTIES)ExAllocatePoolWithTag(NonPagedPool, nBufferSize, c_nAllocTag);
			if (pVolumeProperties == NULL) { return LOGERROR(STATUS_NO_MEMORY); break; }

			ns = FltGetVolumeProperties(pFltObjects->Volume, pVolumeProperties, nBufferSize, &nBufferSize);
			if (NT_ERROR(ns)) 
			{
				IFERR_LOG(ns);
				ExFreePoolWithTag(pVolumeProperties, c_nAllocTag);
				pVolumeProperties = NULL;
				break; 
			}
		} while (false, false); // disable warning C4127

		// Get Device Name
		PUNICODE_STRING pusDevName = pVolumeProperties == nullptr ? &c_usUnknown : 
			&pVolumeProperties->RealDeviceName;

		ANSI_STRING asDevName;
		asDevName.Buffer = pInstCtx->sDeviceName;
		asDevName.Length = 0;
		asDevName.MaximumLength = sizeof(pInstCtx->sDeviceName) - 1;

		NTSTATUS ns = RtlUnicodeStringToAnsiString(&asDevName, pusDevName, FALSE);
		if (NT_ERROR(ns))
		{
			IFERR_LOG(ns);
			asDevName.Length = 0;
		}
		pInstCtx->sDeviceName[asDevName.Length] = 0;

		if (pVolumeProperties != nullptr)
		{
			IFERR_LOG(cloneUnicodeString(&pVolumeProperties->RealDeviceName, 
				&pInstCtx->usDeviceName, &pInstCtx->pDeviceNameBuffer));
		}

		// Get sector size
		if (pVolumeProperties != nullptr)
		{
			pInstCtx->nSectorSize = max(pVolumeProperties->SectorSize, c_nMinSectorSize);
		}

		// Check network FS info
		if (eVolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			pInstCtx->fIsNetworkFS = TRUE;

			PRESET_STATIC_UNICODE_STRING(c_usDeviceMup, L"\\device\\mup");
			if (pVolumeProperties != NULL && 
				RtlEqualUnicodeString(&pVolumeProperties->RealDeviceName, &c_usDeviceMup, TRUE))
					pInstCtx->fIsMup = TRUE;
		}

		// Collect Usb info
		if (eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM)
		{
			IFERR_LOG(collectUsbInfo(pFltObjects, pInstCtx));
		}

 		// Detect fixed
 		if (pVolumeProperties != nullptr)
 		{
 			pInstCtx->fIsFixed = BooleanFlagOn(pVolumeProperties->DeviceCharacteristics,
 				FILE_REMOVABLE_MEDIA | FILE_FLOPPY_DISKETTE | FILE_REMOTE_DEVICE | FILE_PORTABLE_DEVICE)
 				? FALSE : TRUE;
 		}
		else
		{
			pInstCtx->fIsFixed = (BOOLEAN)(eVolumeDeviceType == FILE_DEVICE_DISK_FILE_SYSTEM && !pInstCtx->fIsUsb);
		}

		// Get volume guid
		ULONG nBufferSizeNeeded = 0;
		if (!NT_SUCCESS(FltGetVolumeGuidName(pFltObjects->Volume, &pInstCtx->usVolumeGuid, &nBufferSizeNeeded)))
			LOGINFO2("[WARN] Can't FltGetVolumeGuidName for device: <%s>.\r\n", pInstCtx->sDeviceName);

		// Get DriveType
		if (pInstCtx->fIsNetworkFS)
		{
			pInstCtx->eDriveType = VolumeDriveType::Network;
		}
		else if (pVolumeProperties != nullptr)
		{
			if (FlagOn(pVolumeProperties->DeviceCharacteristics, FILE_REMOVABLE_MEDIA))
				pInstCtx->eDriveType = VolumeDriveType::Removable;
			else
				pInstCtx->eDriveType = VolumeDriveType::Fixed;
		}
		else
		{
			if (pInstCtx->fIsFixed)
				pInstCtx->eDriveType = VolumeDriveType::Fixed;
			else
				pInstCtx->eDriveType = VolumeDriveType::Removable;
		}

		ULONG nDeviceCharacteristics = pVolumeProperties != nullptr ? pVolumeProperties->DeviceCharacteristics : 0;

		LOGINFO2("Mount volume: type: %s, cdrom: %s, usb: %s, chr: 0x%08X, devType=%u, fsType=%u, deviceName: <%s>.\r\n", 
			convertToString(pInstCtx->eDriveType), pInstCtx->fIsCdrom ? "true" : "false", 
			pInstCtx->fIsUsb ? "true" : "false", nDeviceCharacteristics, 
			eVolumeDeviceType, eVolumeFilesystemType, pInstCtx->sDeviceName);

		pInstCtx->fSetupIsFinished = TRUE;
	}
	__finally
	{
		if (pInstCtx != nullptr) 
			FltReleaseContext(pInstCtx);
		if (pVolumeProperties != nullptr)
		 	ExFreePoolWithTag(pVolumeProperties, c_nAllocTag);
	}

	return STATUS_SUCCESS;

}

// 
//  This is called when an instance is being manually deleted by a
//  call to FltDetachVolume or FilterDetach thereby giving us a
//  chance to fail that detach request.
//
//  If this routine is not defined in the registration structure, explicit
//  detach requests via FltDetachVolume or FilterDetach will always be
//  failed.
// 
NTSTATUS queryInstanceTeardown(_In_ PCFLT_RELATED_OBJECTS /*pFltObjects*/,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS /*eFlags*/)
{
    return STATUS_SUCCESS;
}


// 
// This routine is called at the start of instance teardown.
// 
VOID startInstanceTeardown(_In_ PCFLT_RELATED_OBJECTS /*pFltObjects*/, 
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS /*eFlags*/)
{
}


// 
// This routine is called at the end of instance teardown.
// 
VOID completeInstanceTeardown(_In_ PCFLT_RELATED_OBJECTS pFltObjects, 
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS /*eFlags*/)
{
	InstanceContext* pInstanceContext = NULL;
	__try
	{
		FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pInstanceContext);
		LOGINFO2("Volume unmount from filter. device:\"%s\"\r\n", pInstanceContext==NULL? "UNKNOW" : pInstanceContext->sDeviceName);
	}
	__finally
	{
		if (pInstanceContext != NULL)
			FltReleaseContext(pInstanceContext);
	}
}

//
// applyForEachInstance
//
template <typename TFn>
NTSTATUS applyForEachInstance(TFn fn)
{
	ULONG nInstanceCount = 0;
	PFLT_INSTANCE* pInstances = nullptr;

	__try
	{
		// Get a count of how many instances there are
		ULONG nAllocCount = 0;
		NTSTATUS ns = FltEnumerateInstances(nullptr, g_pCommonData->pFilter, nullptr, 0, &nAllocCount);
		if (NT_ERROR(ns) && (ns != STATUS_BUFFER_TOO_SMALL)) IFERR_RET(ns);
		// add a some entries in case a filter loads while we are doing this
		// +FIXME : Why 5?
		// It is from MS sample. We can select another.
		nAllocCount += 5;
		
		// Alloc buffer
		pInstances = (PFLT_INSTANCE*)ExAllocatePoolWithTag(NonPagedPool, 
			nAllocCount * sizeof(PFLT_INSTANCE), c_nAllocTag);
		if (pInstances == nullptr) return LOGERROR(STATUS_NO_MEMORY);

		// Get instances
		IFERR_RET(FltEnumerateInstances(nullptr, g_pCommonData->pFilter, 
			pInstances, nAllocCount, &nInstanceCount));
		if (nInstanceCount > nAllocCount)
			return LOGERROR(STATUS_UNSUCCESSFUL);

		__analysis_assume(nInstanceCount <= nAllocCount);
		// Check InstanceContext
		for (ULONG i = 0; i < nInstanceCount; i++) 
		{
			InstanceContext* pInstanceContext = nullptr;
			#pragma warning(suppress : 6385)
			if (!NT_SUCCESS(FltGetInstanceContext(pInstances[i],
				(PFLT_CONTEXT*)&pInstanceContext))) continue;
			if (pInstanceContext == nullptr) continue;

			if (pInstanceContext->fSetupIsFinished)
				fn(pInstanceContext);
			
			FltReleaseContext(pInstanceContext);
		}
		
		return STATUS_SUCCESS;
	}
	__finally
	{
		// Free every Instance
		for (size_t i = 0; i < nInstanceCount; ++i) 
			if (pInstances[i] != nullptr)
				FltObjectDereference(pInstances[i]);

		// Free array
		if (pInstances != nullptr)
			ExFreePoolWithTag(pInstances, c_nAllocTag);

		// +FIXME: What is return result in this case
	}
}

//
//
//
NTSTATUS printInstances()
{
	LOGINFO2("printInstances:\r\n");
	return applyForEachInstance([](InstanceContext* pInstanceContext)
		{
			LOGINFO2("  - device: %s\r\n", pInstanceContext->sDeviceName);
		}
	);
}

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
NTSTATUS sendFileEvent(SysmonEvent eEvent, ULONG_PTR nProcessId, StreamHandleContext* pStreamHandleContext,
	Fn fnWriteAdditionalData)
{
	if (pStreamHandleContext == nullptr)
		return STATUS_INVALID_PARAMETER_1;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;

	NonPagedLbvsSerializer<edrdrv::EventField> serializer;

	// +FIXME : Why STATUS_NO_MEMORY?
	// Cause only no memory can lead to error.
	if (!serializer.write(EvFld::RawEventId, uint16_t(eEvent))) return STATUS_NO_MEMORY;
	//if (!serializer.write(EvFld::Time, getSystemTime())) return STATUS_NO_MEMORY;
	if (!serializer.write(EvFld::TickTime, getTickCount64())) return STATUS_NO_MEMORY;
	if (!serializer.write(EvFld::ProcessPid, (uint32_t)nProcessId)) return STATUS_NO_MEMORY;
	// +FIXME: Can we use one call format? 
	// serializer can know UNICODE_STRING or we can pass raw string and size
	//
	// I need additional function to write UNICODE_STRING or any my internal structures
	// We can use one call format if we define `write` not as method but as function
	if (pStreamHandleContext->pNameInfo != nullptr && pStreamHandleContext->pNameInfo->Name.Buffer != nullptr)
	{
		if (!write(serializer, EvFld::FilePath, &pStreamHandleContext->pNameInfo->Name))
			return STATUS_NO_MEMORY;
	}
	else
	{
		UNICODE_STRING usEmpty = RTL_CONSTANT_STRING(L"");
		if (!write(serializer, EvFld::FilePath, &usEmpty))
			return STATUS_NO_MEMORY;
	}

	auto pInstanceContext = pStreamHandleContext->pInstanceContext;
	if (pInstanceContext != nullptr)
	{
		if (pInstanceContext->usVolumeGuid.Buffer != nullptr && pInstanceContext->usVolumeGuid.Length > 0)
		{
			if (!write(serializer, EvFld::FileVolumeGuid, &pInstanceContext->usVolumeGuid))
				return STATUS_NO_MEMORY;
		}

		if (!serializer.write(EvFld::FileVolumeType, convertToString(pInstanceContext->eDriveType)))
			return STATUS_NO_MEMORY;

		if (pInstanceContext->usDeviceName.Buffer != nullptr && pInstanceContext->usDeviceName.Length != 0)
		{
			if (!write(serializer, EvFld::FileVolumeDevice, &pInstanceContext->usDeviceName))
				return STATUS_NO_MEMORY;
		}
	}

	#pragma warning(suppress : 4127)
	IFERR_RET(fnWriteAdditionalData(&serializer));

	return fltport::sendRawEvent(serializer);
}


} // namespace detail

//
// Universal file event sending
//
template<typename Fn>
void sendFileEvent(SysmonEvent eEvent, StreamHandleContext* pStreamHandleContext, Fn fnWriteAdditionalData)
{
	if (!isEventEnabled(eEvent))
		return;
	if (pStreamHandleContext == nullptr || pStreamHandleContext->fSkipItem)
		return;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return;

	auto nProcessId = (ULONG_PTR)pStreamHandleContext->nOpeningProcessId;
	if (procmon::isProcessInWhiteList(nProcessId))
		return;

	PCUNICODE_STRING pusName = (pStreamHandleContext->pNameInfo != nullptr && pStreamHandleContext->pNameInfo->Name.Buffer != nullptr) ?
		&pStreamHandleContext->pNameInfo->Name : nullptr;

	LOGINFO2("sendEvent: %u (fileEvent), pid: %Iu, file: <%wZ>\r\n",
		(ULONG)eEvent, nProcessId, pusName);

	IFERR_LOG(detail::sendFileEvent(eEvent, nProcessId, pStreamHandleContext, fnWriteAdditionalData),
		"Can't send file event %u pid: %Iu file: <%wZ>.\r\n",
		(ULONG)eEvent, nProcessId, pusName);
}

//
//
//
void sendFileEvent(SysmonEvent eEvent, StreamHandleContext* pStreamHandleContext)
{
	return sendFileEvent(eEvent, pStreamHandleContext, [](auto /*pSerializer*/) {return STATUS_SUCCESS; });
}

bool isDangerousDiskIoctl(ULONG nIoControlCode)
{
	switch (nIoControlCode)
	{
		case IOCTL_DISK_SET_DRIVE_LAYOUT_EX:
		case IOCTL_SCSI_PASS_THROUGH_DIRECT:
		case IOCTL_DISK_FORMAT_TRACKS:
		case IOCTL_DISK_FORMAT_TRACKS_EX:
			return true;
		default:
			return false;
	}
}

void sendPathEvent(SysmonEvent eEvent, PCUNICODE_STRING pusPath, ULONG_PTR nProcessId, ULONG nAccessOrIoctl)
{
	if (!g_pCommonData->fEnableMonitoring)
		return;
	if (!isEventEnabled(eEvent))
		return;

	NonPagedLbvsSerializer<edrdrv::EventField> serializer;
	if (!serializer.write(EvFld::RawEventId, uint16_t(eEvent))) return;
	if (!serializer.write(EvFld::TickTime, getTickCount64())) return;
	if (!serializer.write(EvFld::ProcessPid, (uint32_t)nProcessId)) return;
	if (pusPath != nullptr && pusPath->Buffer != nullptr && pusPath->Length != 0)
	{
		if (!write(serializer, EvFld::FilePath, pusPath)) return;
	}
	if (!serializer.write(EvFld::AccessMask, uint32_t(nAccessOrIoctl))) return;

	IFERR_LOG(fltport::sendRawEvent(serializer),
		"Can't send OpenEDR path event %u pid: %Iu.\r\n", (ULONG)eEvent, nProcessId);
}

//////////////////////////////////////////////////////////////////////////
//
// Hash calculator
//
//////////////////////////////////////////////////////////////////////////

//
//
//
enum class HashedAction
{
	Read,
	Write,
};

//
//
//
inline NTSTATUS _updateHashOnPostOp(StreamHandleContext* pStreamHandleContext, PFLT_CALLBACK_DATA pData, HashedAction eAction, PCFLT_RELATED_OBJECTS pFltObjects = nullptr)
{
	auto& readParams = pData->Iopb->Parameters.Read;
	auto& writeParams = pData->Iopb->Parameters.Write;

	SequenceActionInfo& actionInfo = (eAction == HashedAction::Read) ? pStreamHandleContext->sequenceReadInfo :
		pStreamHandleContext->sequenceWriteInfo;
	SIZE_T nDataSize = pData->IoStatus.Information;

	PMDL pHeadMdl = (eAction == HashedAction::Read) ? readParams.MdlAddress : writeParams.MdlAddress;
	//
	// Process MDL
	//
	if (pHeadMdl != nullptr) 
	{
		// Process a MDL chains
		size_t nRestDataSize = nDataSize;
		for (PMDL pCurMdl = pHeadMdl; pCurMdl != NULL && nRestDataSize != 0; pCurMdl = pCurMdl->Next)
		{
			void* pDataBuffer = MmGetSystemAddressForMdlSafe(pCurMdl, NormalPagePriority | MdlMappingNoExecute);
			if (pDataBuffer == nullptr)
				return STATUS_INVALID_PARAMETER_3;

			size_t nCurMdlDataSize = min(MmGetMdlByteCount(pCurMdl), nRestDataSize);
			if (eAction == HashedAction::Write) {
				ULONGLONG currentEntropy = shannonEntropyQ24((PUCHAR)pDataBuffer, nCurMdlDataSize);
				if (currentEntropy > actionInfo.nMaxEntropyQ24) {
					actionInfo.nMaxEntropyQ24 = currentEntropy;
				}
			}
			IFERR_RET_NOLOG(actionInfo.updateHash(pDataBuffer, nCurMdlDataSize));

			// RansomShield read-time tee
			if (eAction == HashedAction::Read && pFltObjects != nullptr)
				pStreamHandleContext->RansomTeeChunk(pFltObjects, pDataBuffer, nCurMdlDataSize);

			nRestDataSize -= nCurMdlDataSize;
		}

		// If All data was not read, return error
		if(nRestDataSize != 0)
			return STATUS_INVALID_PARAMETER_3;
		return STATUS_SUCCESS;
	}

	//
	// Process buffer
	//
	else 
	{
		// Test if buffer is not safe for dispatch
		if (KeGetCurrentIrql() > APC_LEVEL)
		{
			//
			//  If this is a system buffer, just use the given address because
			//      it is valid in all thread contexts.
			//  If this is a FASTIO operation, we can just use the
			//      buffer (inside a try/except) since we know we are in
			//      the correct thread context (you can't pend FASTIO's).
			//
			if (!(FlagOn(pData->Flags, FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) ||
				FlagOn(pData->Flags, FLTFL_CALLBACK_DATA_FAST_IO_OPERATION)))
				return STATUS_NOT_SUPPORTED;
		}

		void* pDataBuffer = (eAction == HashedAction::Read) ? readParams.ReadBuffer : writeParams.WriteBuffer;
		if (pDataBuffer == nullptr || nDataSize == 0)
			return STATUS_SUCCESS;

		__try {
			if (eAction == HashedAction::Write) {
				ULONGLONG currentEntropy = shannonEntropyQ24((PUCHAR)pDataBuffer, nDataSize);
				if (currentEntropy > actionInfo.nMaxEntropyQ24) {
					actionInfo.nMaxEntropyQ24 = currentEntropy;
				}
			}

			// RansomShield read-time tee
			if (eAction == HashedAction::Read && pFltObjects != nullptr)
				pStreamHandleContext->RansomTeeChunk(pFltObjects, pDataBuffer, nDataSize);

			return actionInfo.updateHash(pDataBuffer, nDataSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return GetExceptionCode();
		}
	}
}

//
// update hash on post operation
//
inline NTSTATUS updateHashOnPostOp(StreamHandleContext* pStreamHandleContext, PFLT_CALLBACK_DATA pData, HashedAction eAction, PCFLT_RELATED_OBJECTS pFltObjects = nullptr)
{
	FLT_ASSERT(pStreamHandleContext != nullptr);
	if (pStreamHandleContext == nullptr) return STATUS_INVALID_PARAMETER_1;
	FLT_ASSERT(pData != nullptr);
	if (pData == nullptr) return STATUS_INVALID_PARAMETER_2;

	SequenceActionInfo& actionInfo = (eAction == HashedAction::Read) ? pStreamHandleContext->sequenceReadInfo :
		pStreamHandleContext->sequenceWriteInfo;

	if (!actionInfo.fEnabled)
		return STATUS_SUCCESS;

	NTSTATUS ns = _updateHashOnPostOp(pStreamHandleContext, pData, eAction, pFltObjects);

	if (!NT_SUCCESS(ns))
		actionInfo.fEnabled = FALSE;

	return ns;
}

//////////////////////////////////////////////////////////////////////////
//
// ESP routines
//
//////////////////////////////////////////////////////////////////////////

bool checkEspListHasKernelGuid(PFLT_FILTER pFilter, PECP_LIST pEcpList, LPCGUID pGuid)
{
	PVOID pEcpContext = nullptr;
	if (!NT_SUCCESS(FltFindExtraCreateParameter(pFilter, pEcpList, pGuid, &pEcpContext, nullptr)))
		return false;
	if (FltIsEcpFromUserMode(pFilter, pEcpContext))
		return false;
	return true;
}



//////////////////////////////////////////////////////////////////////////
//
// MiniFilter callback routines
//
//////////////////////////////////////////////////////////////////////////


//
//
//
FLT_PREOP_CALLBACK_STATUS FLTAPI preCreate(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	// If preCreate returns FLT_PREOP_SUCCESS_NO_CALLBACK, pStreamHandleContext is not created (in postCreate).
	// So the same items is skipped at others callbacks

	//////////////////////////////////////////////////////////////////////////
	//
	// Skip not processed situations
	//

	if (KeGetCurrentIrql() > PASSIVE_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (IoGetTopLevelIrp()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (FLT_IS_FASTIO_OPERATION(pData)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (!FLT_IS_IRP_OPERATION(pData)) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE))
	{
		sendPathEvent(
			SysmonEvent::NamedPipeCreate,
			&pFltObjects->FileObject->FileName,
			(ULONG_PTR)FltGetRequestorProcessId(pData),
			pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Skip MAILSLOT VOLUME_OPEN
	if (FlagOn(pFltObjects->FileObject->Flags, FO_MAILSLOT | FO_VOLUME_OPEN))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip	PAGING_FILE
	if (FlagOn(pData->Iopb->OperationFlags, SL_OPEN_PAGING_FILE))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip	Special cases by ESP
	PECP_LIST ecpList = nullptr;
	if (NT_SUCCESS(FltGetEcpListFromCallbackData(g_pCommonData->pFilter, pData, &ecpList)) && ecpList != nullptr)
	{
		// Skip prefetcher
		if (checkEspListHasKernelGuid(g_pCommonData->pFilter, ecpList, &GUID_ECP_PREFETCH_OPEN))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		// Skip Windows defender csvfs calls
		if (checkEspListHasKernelGuid(g_pCommonData->pFilter, ecpList, &GUID_ECP_CSV_DOWN_LEVEL_OPEN))
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}


	// Process info

	HANDLE nProcessId = (HANDLE)(ULONG_PTR) FltGetRequestorProcessId(pData);
	procmon::ContextPtr pProcessCtx;
	IFERR_LOG(procmon::fillContext(nProcessId, nullptr, pProcessCtx));


	//////////////////////////////////////////////////////////////////////////
	//
	// Self defense
	//

	InstanceContext* pInstanceContext = nullptr;
	PFLT_FILE_NAME_INFORMATION pNameInfo = nullptr;
	bool fDenyAccess = false;
	__try
	{
		// allow all for trusted
		if (procmon::isProcessTrusted(pProcessCtx))
			__leave;

		// Self defense is no applied for NetworkFS
		if (!NT_SUCCESS(FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pInstanceContext)))
			__leave;
		if (pInstanceContext == nullptr || pInstanceContext->fIsNetworkFS)
			__leave;

		// Get Name Info
		// Disable logging this errors. Can't identify problem object. 
		(void)FltGetFileNameInformation(pData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT), &pNameInfo);
		if (pNameInfo == nullptr)
			__leave;

		// Check rules
		ACCESS_MASK desiredAccess = pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		if (!isSelfProtected(&pNameInfo->Name, desiredAccess))
			__leave;

		// deny access
		LOGINFO1("Selfdefense: Deny access: pid: %Iu, access: 0x%08X, file: <%wZ>.\r\n",
			(ULONG_PTR)nProcessId, (ULONG)desiredAccess, &pNameInfo->Name);

		fDenyAccess = true;
	}
	__finally
	{
		if (pInstanceContext != nullptr)
			FltReleaseContext(pInstanceContext);
		if (pNameInfo != nullptr)
			FltReleaseFileNameInformation(pNameInfo);
	}

	if (fDenyAccess)
	{
		pData->IoStatus.Status = STATUS_ACCESS_DENIED;
		return FLT_PREOP_COMPLETE;
	}
	

	//////////////////////////////////////////////////////////////////////////
	//
	// Skip situations when not need send events
	//

	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Skip	white list
	if (procmon::isProcessInWhiteList(pProcessCtx))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;


	// Skip if no file events
	constexpr SysmonEventMask nEventsMask =
		createEventMask(edrdrv::SysmonEvent::FileCreate) |
		createEventMask(edrdrv::SysmonEvent::FileDelete) |
		createEventMask(edrdrv::SysmonEvent::FileClose) |
		createEventMask(edrdrv::SysmonEvent::FileDataChange) |
		createEventMask(edrdrv::SysmonEvent::FileDataReadFull) |
		createEventMask(edrdrv::SysmonEvent::FileDataWriteFull);

	if(!isEventMaskEnabled(nEventsMask))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;


	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

//
//
//
FLT_POSTOP_CALLBACK_STATUS FLTAPI postCreate(
	__inout PFLT_CALLBACK_DATA pData,
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/, 
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_POSTOP_FINISHED_PROCESSING;

	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) 
		return FLT_POSTOP_FINISHED_PROCESSING;
	if (!NT_SUCCESS(pData->IoStatus.Status) || (pData->IoStatus.Status == STATUS_REPARSE)) 
		return FLT_POSTOP_FINISHED_PROCESSING;
	
	InstanceContext* pInstanceContext = nullptr;
	PFLT_FILE_NAME_INFORMATION pNameInfo = nullptr;
	StreamHandleContext* pStreamHandleContext = nullptr;
	__try
	{
		// Skip	PIPE MAILSLOT VOLUME_OPEN, which is set by FS driver
		if (FlagOn(pFltObjects->FileObject->Flags, FO_NAMED_PIPE | FO_MAILSLOT | FO_VOLUME_OPEN))
			return FLT_POSTOP_FINISHED_PROCESSING;

		ULONG_PTR nProcessId = (ULONG_PTR)FltGetRequestorProcessId(pData);

		// Get size and isDirectory
		BOOLEAN fIsDirectory = FALSE;
		uint64_t nSizeAtCreation = c_nUnknownFileSize;
		FILE_STANDARD_INFORMATION StdInfo = {};
		ULONG nRetLength = 0;
		NTSTATUS ns = FltQueryInformationFile(pFltObjects->Instance, 
			pFltObjects->FileObject, &StdInfo, sizeof(FILE_STANDARD_INFORMATION), 
			FileStandardInformation, &nRetLength);
		if (NT_SUCCESS(ns))
		{
			fIsDirectory = StdInfo.Directory;
			nSizeAtCreation = StdInfo.EndOfFile.QuadPart;
		}
		
		// Skip directories
		if (fIsDirectory)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Get instance context
		ns = FltGetInstanceContext(pFltObjects->Instance, (PFLT_CONTEXT*)&pInstanceContext);
		if (NT_ERROR(ns)) { LOGERROR(ns); return FLT_POSTOP_FINISHED_PROCESSING; }
		
		// Get Name Info
		// Disable logging this errors. Can't identify problem object. 
		(void)FltGetFileNameInformation(pData, (FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT), &pNameInfo);
		if (pNameInfo != nullptr)
			IFERR_LOG(FltParseFileNameInformation(pNameInfo));
		if (pNameInfo == nullptr)
			return FLT_POSTOP_FINISHED_PROCESSING;
	
		// Create StreamHandleContext to collect file actions
		ns = StreamHandleContext::create(&pStreamHandleContext, pFltObjects);

		// Disable monitoring if can't set context
		if (!NT_SUCCESS(ns))
		{
			LOGERROR(ns, "Can't set handle context for pid: %Iu file: <%wZ>.\r\n",
				(ULONG_PTR)nProcessId, &pNameInfo->Name);
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		//
		// Fill StreamHandleContext
		//

		pStreamHandleContext->nOpeningProcessId = nProcessId;

		FltReferenceFileNameInformation(pNameInfo);
		pStreamHandleContext->pNameInfo = pNameInfo;
		pStreamHandleContext->fIsDirectory = fIsDirectory;
		pStreamHandleContext->nSizeAtCreation = nSizeAtCreation;

		FltReferenceContext(pInstanceContext);
		pStreamHandleContext->pInstanceContext = pInstanceContext;

		// Create Parameters
		ACCESS_MASK desiredAccess = pData->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
		ULONG createOptions = pData->Iopb->Parameters.Create.Options & 0xFFFFFF;

		pStreamHandleContext->fDeleteOnClose = 
			BooleanFlagOn(createOptions, FILE_DELETE_ON_CLOSE);
		pStreamHandleContext->fIsExecute = 
			!FlagOn(createOptions, FILE_DIRECTORY_FILE) &&
			FlagOn(desiredAccess, FILE_EXECUTE) &&
			(!FlagOn(desiredAccess, FILE_WRITE_DATA)) &&
			(!FlagOn(desiredAccess, FILE_READ_EA));

		// Fill eCreationStatus
		switch (pData->IoStatus.Information)
		{
			case FILE_SUPERSEDED:
			case FILE_OVERWRITTEN:
				pStreamHandleContext->eCreationStatus = CreationStatus::Truncated;
				break;
			case FILE_OPENED:
				pStreamHandleContext->eCreationStatus = CreationStatus::Opened;
				break;
			case FILE_CREATED:
				pStreamHandleContext->eCreationStatus = CreationStatus::Created;
				break;
			default:
				pStreamHandleContext->eCreationStatus = CreationStatus::Opened;
		}

		// Detect skipped items
		if (pStreamHandleContext->pNameInfo != nullptr && pStreamHandleContext->pNameInfo->Name.Buffer != nullptr)
		{
			if (wcsstr(pStreamHandleContext->pNameInfo->Name.Buffer, L"HydraDragonBackups") != nullptr)
			{
				pStreamHandleContext->fSkipItem = TRUE;
				pStreamHandleContext->fIsBackupFile = TRUE;
			}
		}

		// Add test item only
		if (g_pCommonData->fUseFilemonMask)
		{
			ScopedLock lock(g_pCommonData->mtxFilemonMask);
			if (!isEndedWith(&pStreamHandleContext->pNameInfo->Name, g_pCommonData->usFilemonMask))
				pStreamHandleContext->fSkipItem = TRUE;
		}

		// Start detect sequence reading and writing
		if (!pStreamHandleContext->fSkipItem)
		{
			if (isEventEnabled(SysmonEvent::FileDataWriteFull) &&
				pStreamHandleContext->nSizeAtCreation == 0)
				pStreamHandleContext->sequenceWriteInfo.fEnabled = TRUE;

			if (isEventEnabled(SysmonEvent::FileDataReadFull) &&
				pStreamHandleContext->nSizeAtCreation >= g_pCommonData->nMinFullActFileSize &&
				pStreamHandleContext->nSizeAtCreation <= g_pCommonData->nMaxFullActFileSize)
				pStreamHandleContext->sequenceReadInfo.fEnabled = TRUE;

			sendFileEvent(SysmonEvent::FileCreate, pStreamHandleContext);

			LOGINFO4("filemon: postCreate: id: %05Iu:%p:%p, size: %I64u, fullR:0(%u), fullW:0(%u), name: <%wZ>.\r\n",
				(ULONG_PTR)nProcessId, pStreamHandleContext, pFltObjects->FileObject,
				pStreamHandleContext->nSizeAtCreation, 
				(ULONG)(bool)pStreamHandleContext->sequenceReadInfo.fEnabled,
				(ULONG)(bool)pStreamHandleContext->sequenceWriteInfo.fEnabled,
				&pStreamHandleContext->pNameInfo->Name);
		}
	}
	__finally
	{
		if (pInstanceContext != nullptr)
			FltReleaseContext(pInstanceContext);
		if (pStreamHandleContext != nullptr)
			FltReleaseContext(pStreamHandleContext);
		if (pNameInfo != nullptr)
			FltReleaseFileNameInformation(pNameInfo);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;

}

//
//
//
FLT_PREOP_CALLBACK_STATUS FLTAPI preCleanup(
	_Inout_ PFLT_CALLBACK_DATA /*pData*/,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	NTSTATUS ns = FltGetStreamHandleContext(pFltObjects->Instance, 
		pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext);
	if (!NT_SUCCESS(ns) || pStreamHandleContext == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	BOOLEAN fSkipItem = pStreamHandleContext->fSkipItem;
	FltReleaseContext(pStreamHandleContext);

	return fSkipItem ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_SYNCHRONIZE;
}

template<typename T>
inline NTSTATUS writeFileHash(T* pSerializer, SequenceActionInfo& info)
{
	uint64_t nHash = info.hash.digest();
	char sHash[sizeof(nHash) * 2 + 1];
	convertBinToHex(&nHash, sizeof(nHash), sHash, ARRAYSIZE(sHash));
	if (!pSerializer->write(EvFld::FileRawHash, sHash))
		return STATUS_NO_MEMORY;
	return STATUS_SUCCESS;
}

//
//
//
FLT_POSTOP_CALLBACK_STATUS FLTAPI postCleanup(
	__inout PFLT_CALLBACK_DATA pData, 
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/, 
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_pCommonData->fEnableMonitoring) return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
	if (!NT_SUCCESS(pData->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	__try
	{
		IFERR_LOG(FltGetStreamHandleContext(pFltObjects->Instance, 
			pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext));
		if (pStreamHandleContext == nullptr)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Check that file was deleted (marked as deleted)
		bool fFileWasDeleted = false;
		if (pStreamHandleContext->fDeleteOnClose || 
			pStreamHandleContext->fDispositionDelete)
		{
			fFileWasDeleted = true;

			//
			//  The check for deletion is done via a query to
			//  FileStandardInformation. If that returns STATUS_FILE_DELETED
			//  it means the stream was deleted.
			//
			// Note: This way does not work if:
			//   - another process have opened file
			//   - file is in shared folder

			//FILE_STANDARD_INFORMATION fileInfo = {};
			//NTSTATUS ns = FltQueryInformationFile(pData->Iopb->TargetInstance,
			//	pData->Iopb->TargetFileObject, &fileInfo,
			//	sizeof(fileInfo), FileStandardInformation, NULL);
			//
			//fFileWasDeleted = ns == STATUS_FILE_DELETED;
		}

		{
			auto& readInfo = pStreamHandleContext->sequenceReadInfo;
			auto& writeInfo = pStreamHandleContext->sequenceWriteInfo;

			LOGINFO4("filemon: postCleanup: id: %05Iu:%p:%p, fDel:%u, fChange:%u, nFullR:%I64u(%u), nFullW:%I64u(%u).\r\n",
				(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject,
				(ULONG)fFileWasDeleted, (ULONG)pStreamHandleContext->fWasChanged,
				readInfo.nNextPos, (ULONG)(bool)readInfo.fEnabled, 
				writeInfo.nNextPos, (ULONG)(bool)writeInfo.fEnabled);
		}

		// Send FileDataWriteFull
		if(pStreamHandleContext->sequenceWriteInfo.fEnabled) do 
		{
			auto& writeInfo = pStreamHandleContext->sequenceWriteInfo;
			// Check file was not deleted
			if (fFileWasDeleted)
				break;
			// Check limits
			if (writeInfo.nNextPos < g_pCommonData->nMinFullActFileSize ||
				writeInfo.nNextPos > g_pCommonData->nMaxFullActFileSize)
				break;

			sendFileEvent(SysmonEvent::FileDataWriteFull, pStreamHandleContext, 
				[&writeInfo](auto pSerializer) {
					// Write entropy as raw Q24 uint64; Rust side divides by (1<<24) to get float.
					pSerializer->write(EvFld::OwlyEntropy, (uint64_t)writeInfo.nMaxEntropyQ24);
					pSerializer->write(EvFld::OwlyIsEntropyCalc, (uint32_t)1);
					return writeFileHash(pSerializer, writeInfo);
				}
			);

			LOGINFO2("FullWrite: pid: %Iu, size:%I64u, hash:%016I64X file:<%wZ>.\r\n",
				(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, writeInfo.nNextPos, (uint64_t)writeInfo.hash.digest(),
				&pStreamHandleContext->pNameInfo->Name);
		} while (false);

		// Send FileDataReadFull
		if(pStreamHandleContext->sequenceReadInfo.fEnabled) do 
		{
			auto& readInfo = pStreamHandleContext->sequenceReadInfo;
			// Check that full file was read
			if (readInfo.nNextPos != pStreamHandleContext->nSizeAtCreation)
				break;
			// Check limits
			if (readInfo.nNextPos < g_pCommonData->nMinFullActFileSize ||
				readInfo.nNextPos > g_pCommonData->nMaxFullActFileSize)
				break;

			// RansomShield: finalize the read-time pre-image before the
			// event goes out so usermode can map victim -> backup.
			pStreamHandleContext->RansomTeeClose(true);

			sendFileEvent(SysmonEvent::FileDataReadFull, pStreamHandleContext,
				[&readInfo, pStreamHandleContext](auto pSerializer) {
					auto nsH = writeFileHash(pSerializer, readInfo);
					if (!NT_SUCCESS(nsH))
						return nsH;
					UNICODE_STRING usBk;
					RtlInitUnicodeString(&usBk,
						pStreamHandleContext->szRansomDst);
					(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
return STATUS_SUCCESS;
				}
			);

			LOGINFO2("FullRead: pid: %Iu, size:%I64u, hash:%016I64X, file:<%wZ>.\r\n",
				(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, readInfo.nNextPos, (uint64_t)readInfo.hash.digest(),
				&pStreamHandleContext->pNameInfo->Name);
		} while (false);

		// Send FileDataChange
		if (pStreamHandleContext->fWasChanged != FALSE && !fFileWasDeleted)
		{
			sendFileEvent(SysmonEvent::FileDataChange, pStreamHandleContext);
		}

		// Send FileDelete
		if (fFileWasDeleted && pStreamHandleContext->eCreationStatus != CreationStatus::Created)
		{
			sendFileEvent(SysmonEvent::FileDelete, pStreamHandleContext);
		}

		// Send FileClose
		sendFileEvent(SysmonEvent::FileClose, pStreamHandleContext);
	}
	__finally
	{
		if (pStreamHandleContext != nullptr)
			FltReleaseContext(pStreamHandleContext);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//
// Forward declaration (defined later in this file) so destructive rename/delete
// pre-image capture in preSetFileInfo can shadow-copy the original file content.
//
NTSTATUS BackupPreImage(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Inout_ StreamHandleContext* pCtx);

//
//
//
FLT_PREOP_CALLBACK_STATUS FLTAPI preSetFileInfo(_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Handle destructive rename and delete for the general RansomShield pre-image.
	auto eInfoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;
	const bool fDelete = (eInfoClass == FileDispositionInformation ||
		eInfoClass == FileDispositionInformationEx);
	const bool fRename = (eInfoClass == FileRenameInformation ||
		eInfoClass == FileRenameInformationEx);
	if (!fDelete && !fRename)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	NTSTATUS ns = FltGetStreamHandleContext(pFltObjects->Instance,
		pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext);
	if (!NT_SUCCESS(ns) || pStreamHandleContext == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if(!pStreamHandleContext->fSkipItem)
		LOGINFO4("filemon: preSetFileInfo: id: %05Iu:%p:%p, infoclass: %u.\r\n",
			(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject, (ULONG)eInfoClass);

	// RansomShield: shadow-copy the (original) file's current content BEFORE the
	// destructive rename/delete so it can be restored later. This is the GENERAL
	// guard against EVERY ransomware family, including those that write a new
	// encrypted file and then rename/delete the original (no in-place overwrite,
	// so the read-then-write heuristic in preWrite never fires). Pre-image is taken
	// for any file (not path-scoped) except explicitly skipped items, and at most
	// once per handle.
	if (!pStreamHandleContext->fSkipItem &&
		!pStreamHandleContext->fPreImageSaved &&
		pStreamHandleContext->pNameInfo != nullptr &&
		pStreamHandleContext->pNameInfo->Name.Buffer != nullptr)
	{
		BackupPreImage(pFltObjects, pStreamHandleContext);
	}

	BOOLEAN fSkipItem = pStreamHandleContext->fSkipItem;
	FltReleaseContext(pStreamHandleContext);
	if(fSkipItem)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	return FLT_PREOP_SYNCHRONIZE;
}

//
// FILE_RENAME_INFORMATION_EX is not defined in this WDK/SDK revision.
// The layout mirrors the documented structure: Flags, RootDirectory,
// FileNameLength, FileName. Only FileNameLength/FileName are used here.
//
typedef struct _OWLY_FILE_RENAME_INFORMATION_EX
{
	ULONG Flags;
	HANDLE RootDirectory;
	ULONG FileNameLength;
	WCHAR FileName[1];
} OWLY_FILE_RENAME_INFORMATION_EX, *POWLY_FILE_RENAME_INFORMATION_EX;

//
//
//
FLT_POSTOP_CALLBACK_STATUS FLTAPI postSetFileInfo(
	__inout PFLT_CALLBACK_DATA pData, 
	__in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/, 
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_pCommonData->fEnableMonitoring) return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
	if (!NT_SUCCESS(pData->IoStatus.Status)) return FLT_POSTOP_FINISHED_PROCESSING;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	__try
	{
		IFERR_LOG(FltGetStreamHandleContext(pFltObjects->Instance, 
			pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext));
		if (pStreamHandleContext == nullptr)
			return FLT_POSTOP_FINISHED_PROCESSING;

		// Skip if it is not delete
		auto eInfoClass = pData->Iopb->Parameters.SetFileInformation.FileInformationClass;
		if (eInfoClass == FileDispositionInformation)
		{
			BOOLEAN fDelete = ((PFILE_DISPOSITION_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer)->DeleteFile;
			pStreamHandleContext->fDispositionDelete = fDelete;
			// Emit the delete event immediately on a successful delete disposition.
			// The rule layer filters by path/extension; the driver must not drop
			// delete attempts silently (postCleanup only emits FileDelete for
			// delete-on-close, missing plain FileDispositionInformation deletes).
			if (fDelete)
				sendFileEvent(SysmonEvent::FileDelete, pStreamHandleContext,
					[pStreamHandleContext](auto pSerializer) {
						UNICODE_STRING usBk;
						RtlInitUnicodeString(&usBk,
							pStreamHandleContext->szRansomDst);
						(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
return STATUS_SUCCESS;
					});
		}
		else if (eInfoClass == FileDispositionInformationEx)
		{
			ULONG flags = ((PFILE_DISPOSITION_INFORMATION_EX)pData->Iopb->Parameters.SetFileInformation.InfoBuffer)->Flags;

			if (FlagOn(flags, FILE_DISPOSITION_ON_CLOSE))
				pStreamHandleContext->fDeleteOnClose = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
			else
			{
				BOOLEAN fDelete = BooleanFlagOn(flags, FILE_DISPOSITION_DELETE);
				pStreamHandleContext->fDispositionDelete = fDelete;
				if (fDelete)
					sendFileEvent(SysmonEvent::FileDelete, pStreamHandleContext,
						[pStreamHandleContext](auto pSerializer) {
							UNICODE_STRING usBk;
							RtlInitUnicodeString(&usBk,
								pStreamHandleContext->szRansomDst);
							(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
return STATUS_SUCCESS;
						});
			}
		}
		else if (eInfoClass == FileRenameInformation || eInfoClass == FileRenameInformationEx)
		{
			// Emit a rename event on a successful rename request. The target name
			// is carried in the FileName field (relative to RootDirectory, which is
			// typically NULL for same-directory renames). The rule layer compares
			// the previous extension (tracked per file id) against the new target
			// extension to detect extension changes.
			UNICODE_STRING usTarget;
			RtlInitEmptyUnicodeString(&usTarget, nullptr, 0);
			if (eInfoClass == FileRenameInformation)
			{
				auto pRename = (PFILE_RENAME_INFORMATION)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
				usTarget.Length = (USHORT)pRename->FileNameLength;
				usTarget.MaximumLength = usTarget.Length;
				usTarget.Buffer = pRename->FileName;
			}
			else
			{
				auto pRename = (POWLY_FILE_RENAME_INFORMATION_EX)pData->Iopb->Parameters.SetFileInformation.InfoBuffer;
				usTarget.Length = (USHORT)pRename->FileNameLength;
				usTarget.MaximumLength = usTarget.Length;
				usTarget.Buffer = pRename->FileName;
			}

			if (usTarget.Buffer != nullptr && usTarget.Length != 0)
			{
				detail::sendFileEvent(SysmonEvent::FileRename,
					(ULONG_PTR)pStreamHandleContext->nOpeningProcessId,
					pStreamHandleContext,
					[&usTarget, pStreamHandleContext](auto pSerializer) -> NTSTATUS {
						UNICODE_STRING usBk;
						RtlInitUnicodeString(&usBk,
							pStreamHandleContext->szRansomDst);
						(void)write(*(pSerializer),
							EvFld::FileBackupPath, &usBk);
						return write(*(pSerializer), EvFld::FileRenameTarget,
							&usTarget);
					});
			}
			else
			{
				sendFileEvent(SysmonEvent::FileRename, pStreamHandleContext,
					[pStreamHandleContext](auto pSerializer) {
						UNICODE_STRING usBk;
						RtlInitUnicodeString(&usBk,
							pStreamHandleContext->szRansomDst);
						(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
return STATUS_SUCCESS;
					});
			}
		}
	}
	__finally
	{
		if (pStreamHandleContext != nullptr)
			FltReleaseContext(pStreamHandleContext);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//
// Check skipped action for pre read/write.
// @return true if action is skipped.
//
bool isReadWriteSkipping(PFLT_CALLBACK_DATA pData, StreamHandleContext* pStreamHandleContext, HashedAction eAction)
{
	// Process all top level IRP
	if (IoGetTopLevelIrp() == nullptr)
		return false;
	

	SequenceActionInfo& actionInfo = (eAction == HashedAction::Read) ? pStreamHandleContext->sequenceReadInfo :
		pStreamHandleContext->sequenceWriteInfo;

	// Check not top level IRP
	if (actionInfo.fEnabled && actionInfo.fAllowNotTopLevelIrp)
	{
		// Allow all FASTIO
		//if (FLT_IS_FASTIO_OPERATION(pData))
		//	return false;

		// Allow IRP action with appropriate flags
		ULONG eOperationFlag = (eAction == HashedAction::Read) ? IRP_READ_OPERATION : IRP_WRITE_OPERATION;
		if (FLT_IS_IRP_OPERATION(pData) && FlagOn(pData->Iopb->IrpFlags, eOperationFlag))
			return false;
	}

	return true;
}

//
//
//
//
// RansomShield: shadow-copy the current (pre-overwrite) content of the file
// to \HydraDragonBackups\<pid>\ BEFORE the writer's IRP goes down.
// Runs synchronously in preWrite (<= APC_LEVEL), so the writing thread is held until
// the copy completes - zero data loss even for in-place encryption.
// The saved path is reported to usermode via OwlyPreImageSaved.
//

static NTSTATUS CreateDirZw(PCWSTR pszDir)
{
	UNICODE_STRING usDir;
	RtlInitUnicodeString(&usDir, pszDir);
	OBJECT_ATTRIBUTES oa = {};
	InitializeObjectAttributes(&oa, &usDir,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	IO_STATUS_BLOCK ios = {};
	HANDLE hDir = nullptr;

	NTSTATUS ns = ZwCreateFile(&hDir,
		SYNCHRONIZE | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
		&oa, &ios, nullptr,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN_IF,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr, 0);

	if (NT_SUCCESS(ns))
	{
		ZwClose(hDir);
	}
	return ns;
}

//
// RansomShield read-time tee ---------------------------------------------
//

// Opens (once) the pre-image stream under
// \HydraDragonBackups\<pid>\read_<tick>_<name> on the active volume.
void StreamHandleContext::RansomTeeOpenIfNeeded(PCFLT_RELATED_OBJECTS pFltObjects)
{
	if (hRansomTee != nullptr)
		return; // already open

	if (pFltObjects == nullptr || pFltObjects->Instance == nullptr)
		return;

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		hRansomTee = ((HANDLE)(LONG_PTR)-1); // sentinel: skip this handle
		return;
	}

	// Sentinel marks a previous failed open: stop retrying this handle.
	hRansomTee = ((HANDLE)(LONG_PTR)-1);

	const ULONG nPid = (ULONG)(ULONG_PTR)nOpeningProcessId;

	(void)CreateDirZw(L"\\??\\C:\\ProgramData\\HydraDragonBackups");

	wchar_t szPidDir[96] = L"";
	RtlStringCchPrintfW(szPidDir, RTL_NUMBER_OF(szPidDir),
		L"\\??\\C:\\ProgramData\\HydraDragonBackups\\%lu", nPid);
	(void)CreateDirZw(szPidDir);

	PCWSTR pszLast = L"unknown";
	if (pNameInfo != nullptr && pNameInfo->Name.Buffer != nullptr)
	{
		pszLast = pNameInfo->Name.Buffer;
		for (PCWSTR p = pszLast; *p != L'\0'; ++p)
			if (*p == L'\\' || *p == L'/')
				pszLast = p + 1;
	}

	wchar_t szName[192] = L"";
	RtlStringCchCopyW(szName, RTL_NUMBER_OF(szName), pszLast);
	for (PWSTR p = szName; *p != L'\0'; ++p)
		if (*p == L':' || *p == L'"' || *p == L'*' || *p == L'?' || *p == L'<' || *p == L'>' || *p == L'|')
			*p = L'_';

	LARGE_INTEGER nTick = {};
	KeQueryTickCount(&nTick);

	wchar_t szTick[24] = L"";
	RtlStringCchPrintfW(szTick, RTL_NUMBER_OF(szTick), L"read_%08x_", nTick.LowPart);

	RtlStringCchPrintfW(szRansomDst, RTL_NUMBER_OF(szRansomDst),
		L"%s\\%s%s", szPidDir, szTick, szName);

	UNICODE_STRING usDst;
	RtlInitUnicodeString(&usDst, szRansomDst);
	OBJECT_ATTRIBUTES oaDst = {};
	InitializeObjectAttributes(&oaDst, &usDst,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	IO_STATUS_BLOCK ios = {};
	NTSTATUS ns = ZwCreateFile(&hRansomTee, FILE_WRITE_DATA | SYNCHRONIZE, &oaDst, &ios, nullptr,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
		nullptr, 0);

	if (NT_SUCCESS(ns))
	{
		ObReferenceObjectByHandle(hRansomTee, FILE_WRITE_DATA, *IoFileObjectType, KernelMode, (PVOID*)&pRansomTeeObj, nullptr);
	}
	else
	{
		hRansomTee = ((HANDLE)(LONG_PTR)-1);
		pRansomTeeObj = nullptr;
		LOGINFO4("RansomShield tee open failed 0x%08X pid %lu\r\n", ns, nPid);
	}
}

// Duplicates one read chunk into the pre-image stream.
void StreamHandleContext::RansomTeeChunk(PCFLT_RELATED_OBJECTS pFltObjects, void* pDataBuffer, SIZE_T nLen)
{
	if (pDataBuffer == nullptr || nLen == 0)
		return;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return;

	RansomTeeOpenIfNeeded(pFltObjects);
	if (hRansomTee == nullptr || hRansomTee == ((HANDLE)(LONG_PTR)-1) || pRansomTeeObj == nullptr || pFltObjects == nullptr || pFltObjects->Instance == nullptr)
		return;

	// Copy pDataBuffer to a safe Kernel NonPagedPool/stack buffer so ZwWriteFile
	// never receives a user-mode Virtual Address (which causes INVALID_MDL_RANGE 0x12e in CLASSPNP/partmgr).
	UCHAR stackBuffer[1024];
	PVOID pKernelBuffer = nullptr;
	PVOID pAllocatedBuffer = nullptr;

	if (nLen <= sizeof(stackBuffer))
	{
		pKernelBuffer = stackBuffer;
	}
	else
	{
		pAllocatedBuffer = ExAllocatePoolWithTag(NonPagedPool, nLen, 'TnsR');
		if (pAllocatedBuffer == nullptr)
			return;
		pKernelBuffer = pAllocatedBuffer;
	}

	__try
	{
		RtlCopyMemory(pKernelBuffer, pDataBuffer, nLen);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (pAllocatedBuffer != nullptr)
			ExFreePoolWithTag(pAllocatedBuffer, 'TnsR');
		return;
	}

	LARGE_INTEGER off = nRansomOff;
	ULONG nWritten = 0;
	IO_STATUS_BLOCK iosWrite = {};
	NTSTATUS ns = ZwWriteFile(hRansomTee, nullptr, nullptr, nullptr, &iosWrite,
		pKernelBuffer, (ULONG)nLen, &off, nullptr);
	if (NT_SUCCESS(ns))
	{
		nWritten = (ULONG)iosWrite.Information;
		nRansomOff.QuadPart += nWritten;
	}

	if (pAllocatedBuffer != nullptr)
	{
		ExFreePoolWithTag(pAllocatedBuffer, 'TnsR');
	}
}

struct RansomTeeCloseCtx {
	WORK_QUEUE_ITEM WorkItem;
	HANDLE hRansomTee;
};

static void RansomTeeCloseWorker(PVOID Context)
{
	auto pCtx = (RansomTeeCloseCtx*)Context;
	ZwClose(pCtx->hRansomTee);
	ExFreePoolWithTag(pCtx, 'TnsR');
}

// Flushes and closes the tee stream.
void StreamHandleContext::RansomTeeClose(bool /*fFlush*/)
{
	if (pRansomTeeObj != nullptr)
	{
		ObDereferenceObject(pRansomTeeObj);
		pRansomTeeObj = nullptr;
	}
	if (hRansomTee != nullptr && hRansomTee != ((HANDLE)(LONG_PTR)-1))
	{
		if (KeGetCurrentIrql() > APC_LEVEL)
		{
			auto pCtx = (RansomTeeCloseCtx*)ExAllocatePoolWithTag(NonPagedPool, sizeof(RansomTeeCloseCtx), 'TnsR');
			if (pCtx)
			{
				pCtx->hRansomTee = hRansomTee;
				ExInitializeWorkItem(&pCtx->WorkItem, RansomTeeCloseWorker, pCtx);
				ExQueueWorkItem(&pCtx->WorkItem, DelayedWorkQueue);
			}
		}
		else
		{
			ZwClose(hRansomTee);
		}
	}
	hRansomTee = nullptr;
}

NTSTATUS BackupPreImage(_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Inout_ StreamHandleContext* pCtx)
{
	if (pFltObjects == nullptr || pFltObjects->Instance == nullptr || pFltObjects->FileObject == nullptr)
		return STATUS_INVALID_PARAMETER;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return STATUS_NOT_SUPPORTED;

	NTSTATUS ns = STATUS_SUCCESS;
	PVOID pBuffer = nullptr;
	HANDLE hDst = nullptr;
	PFILE_OBJECT pDstObj = nullptr;

	const ULONG nPid = (ULONG)(ULONG_PTR)pCtx->nOpeningProcessId;

	wchar_t szDst[512] = L"";
	wchar_t szName[192] = L"";

	__try
	{
		FILE_STANDARD_INFORMATION stdInfo = {};
		IO_STATUS_BLOCK iosQ = {};
		ns = FltQueryInformationFile(pFltObjects->Instance, pFltObjects->FileObject,
			&stdInfo, sizeof(stdInfo), FileStandardInformation, nullptr);
		if (!NT_SUCCESS(ns))
			__leave;

		uint64_t nSize = (uint64_t)stdInfo.EndOfFile.QuadPart;
		if (nSize == 0)
		{
			ns = STATUS_SUCCESS; // nothing to preserve
			InterlockedExchange(&pCtx->fPreImageSaved, 1);
			__leave;
		}
		if (nSize > g_pCommonData->nMaxFullActFileSize)
			nSize = g_pCommonData->nMaxFullActFileSize;

		(void)CreateDirZw(L"\\??\\C:\\ProgramData\\HydraDragonBackups");

		wchar_t szPidDir[96] = L"";
		RtlStringCchPrintfW(szPidDir, RTL_NUMBER_OF(szPidDir),
			L"\\??\\C:\\ProgramData\\HydraDragonBackups\\%lu", nPid);
		(void)CreateDirZw(szPidDir);

		PCWSTR pszFullPath = L"";
		if (pCtx->pNameInfo != nullptr && pCtx->pNameInfo->Name.Buffer != nullptr)
			pszFullPath = pCtx->pNameInfo->Name.Buffer;

		PCWSTR pszLast = L"unknown";
		for (PCWSTR p = pszFullPath; *p != L'\0'; ++p)
			if (*p == L'\\' || *p == L'/')
				pszLast = p + 1;

		RtlStringCchCopyW(szName, RTL_NUMBER_OF(szName), pszLast);
		for (PWSTR p = szName; *p != L'\0'; ++p)
			if (*p == L':' || *p == L'"' || *p == L'*' || *p == L'?' || *p == L'<' || *p == L'>' || *p == L'|')
				*p = L'_';

		LARGE_INTEGER nTick = {};
		KeQueryTickCount(&nTick);

		wchar_t szTick[24] = L"";
		RtlStringCchPrintfW(szTick, RTL_NUMBER_OF(szTick), L"%08x_",
			nTick.LowPart);

		RtlStringCchPrintfW(szDst, RTL_NUMBER_OF(szDst),
			L"%s\\%s%s", szPidDir, szTick, szName);

		UNICODE_STRING usDst;
		RtlInitUnicodeString(&usDst, szDst);
		OBJECT_ATTRIBUTES oaDst = {};
		InitializeObjectAttributes(&oaDst, &usDst,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);

		IO_STATUS_BLOCK iosDst = {};
		ns = ZwCreateFile(&hDst, FILE_WRITE_DATA | SYNCHRONIZE, &oaDst, &iosDst, nullptr,
			FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_NO_INTERMEDIATE_BUFFERING,
			nullptr, 0);

		if (!NT_SUCCESS(ns))
			__leave;

		ObReferenceObjectByHandle(hDst, FILE_WRITE_DATA, *IoFileObjectType, KernelMode, (PVOID*)&pDstObj, nullptr);

		constexpr ULONG c_nChunk = 256 * 1024;
		pBuffer = ExAllocatePoolWithTag(PagedPool, c_nChunk, 'rdSB');
		if (pBuffer == nullptr)
		{
			ns = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		LARGE_INTEGER nSrcOff = {};
		LARGE_INTEGER nDstOff = {};
		uint64_t nTotal = 0;

		while (nTotal < nSize)
		{
			ULONG nToRead = c_nChunk;
			if ((uint64_t)nToRead > nSize - nTotal)
				nToRead = (ULONG)(nSize - nTotal);

			ULONG nRead = 0;
			ns = FltReadFile(pFltObjects->Instance, pFltObjects->FileObject,
				&nSrcOff, nToRead, pBuffer,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				&nRead, nullptr, nullptr);
			if (!NT_SUCCESS(ns) || nRead == 0)
				break;

			ULONG nWritten = 0;
			IO_STATUS_BLOCK iosWrite = {};
			ns = ZwWriteFile(hDst, nullptr, nullptr, nullptr, &iosWrite,
				pBuffer, nRead, &nDstOff, nullptr);
			if (NT_SUCCESS(ns))
				nWritten = (ULONG)iosWrite.Information;
			if (!NT_SUCCESS(ns))
				break;

			nSrcOff.QuadPart += nRead;
			nDstOff.QuadPart += nRead;
			nTotal += nRead;
		}

		if (nTotal > 0)
		{
			InterlockedExchange(&pCtx->fPreImageSaved, 1);
			LOGINFO4("RansomShield pre-image saved: pid %lu bytes %I64u -> <%ws>\r\n",
				nPid, nTotal, szDst);

			UNICODE_STRING usBk;
			RtlInitUnicodeString(&usBk, szDst);
			sendFileEvent(SysmonEvent::OwlyPreImageSaved, pCtx,
				[&usBk](auto pSerializer)
				{
					(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
					return STATUS_SUCCESS;
				});
		}

		ns = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ns = GetExceptionCode();
	}

	if (pBuffer != nullptr)
		ExFreePoolWithTag(pBuffer, 'rdSB');
	if (pDstObj != nullptr)
		ObDereferenceObject(pDstObj);
	if (hDst != nullptr)
		ZwClose(hDst);

	return ns;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI preWrite(_Inout_ PFLT_CALLBACK_DATA pData, 
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	NTSTATUS ns = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext);
	if(!NT_SUCCESS(ns) || pStreamHandleContext == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (pStreamHandleContext->fIsBackupFile)
	{
		FltReleaseContext(pStreamHandleContext);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Check skipping flags
	if (isReadWriteSkipping(pData, pStreamHandleContext, HashedAction::Write)
		|| pStreamHandleContext->fSkipItem)
	{
		FltReleaseContext(pStreamHandleContext);
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	auto& writeParams = pData->Iopb->Parameters.Write;

	bool fSyncNeeded = false;

	// RansomShield pre-image & destructive op tracking:
	// If this handle read the file sequentially and is now performing a write,
	// capture pre-image before destructive overwrite and track op frequency per PID.
	do
	{
		auto& rInfo = pStreamHandleContext->sequenceReadInfo;
		if (!rInfo.fEnabled || rInfo.nNextPos == 0)
			break;

		if (writeParams.Length == 0)
			break;

		if (rInfo.nNextPos > g_pCommonData->nMaxFullActFileSize)
			break;

		fSyncNeeded = true; // writer waits on this thread until copy done

		if (!pStreamHandleContext->fPreImageSaved)
		{
			NTSTATUS nsBk = BackupPreImage(pFltObjects, pStreamHandleContext);
			if (NT_SUCCESS(nsBk))
				pStreamHandleContext->fPreImageSaved = 1;
		}
	} while (false);

	// process sequenced write
	do
	{
		auto& info = pStreamHandleContext->sequenceWriteInfo;

		// detection is disabled
		if (!info.fEnabled)
			break;

		// not interesting action
		if (writeParams.Length == 0)
			break;

		// getting writing pos from parameters or current file pos
		uint64_t nWritePos = 
			(writeParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION && writeParams.ByteOffset.HighPart == -1) ?
			pFltObjects->FileObject->CurrentByteOffset.QuadPart : 
			writeParams.ByteOffset.QuadPart;

		// check write position
		if (nWritePos != info.nNextPos)
		{
			info.fEnabled = false;
			break;
		}

		// check max limit
		if (nWritePos > g_pCommonData->nMaxFullActFileSize)
		{
			info.fEnabled = false;
			break;
		}

		fSyncNeeded = true;
	} while (false);

	LOGINFO4("filemon: preWrite: id: %05Iu:%p:%p, pos: %I64u, size: %u, post: %u.\r\n",
		(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject,
		pFltObjects->FileObject->CurrentByteOffset.QuadPart, (ULONG)writeParams.Length, 
		(ULONG)fSyncNeeded ? 1 : 0);

	FltReleaseContext(pStreamHandleContext);

	if (!fSyncNeeded)
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;

	return FLT_PREOP_SYNCHRONIZE;
}

//
//
//
FLT_POSTOP_CALLBACK_STATUS FLTAPI postWrite(__inout PFLT_CALLBACK_DATA pData, __in PCFLT_RELATED_OBJECTS pFltObjects,
	__in_opt PVOID /*pCompletionContext*/, __in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_pCommonData->fEnableMonitoring) return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	__try
	{
		IFERR_LOG(FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext));
		if (pStreamHandleContext == nullptr)
			return FLT_POSTOP_FINISHED_PROCESSING;

		LOGINFO4("filemon: postWrite: id: %05Iu:%p:%p, status: 0x%08X, info: %u.\r\n", 
			(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject,
			(ULONG)pData->IoStatus.Status, (ULONG)pData->IoStatus.Information);

		// if any bytes was written
		if (NT_SUCCESS(pData->IoStatus.Status))
		{
			pStreamHandleContext->fWasChanged = TRUE;
			// Disable detect sequence read
			pStreamHandleContext->sequenceReadInfo.fEnabled = FALSE;
			// First overwrite ends the read phase: flush + close the tee so
			// the captured pre-image is complete on disk.
			pStreamHandleContext->RansomTeeClose(true);
		}

		// Sequence action detection
		do
		{
			auto& info = pStreamHandleContext->sequenceWriteInfo;

			//
			// If not enabled 
			if (!info.fEnabled)
				break;

			// If operation is failed
			if (!NT_SUCCESS(pData->IoStatus.Status))
			{
				// Some devices (e.g, USB drives) can deny FAST_IO and returns STATUS_FLT_DISALLOW_FAST_IO.
				// And next action will be with the same buffers as IRP.
				if (pData->IoStatus.Status == STATUS_FLT_DISALLOW_FAST_IO)
					info.fAllowNotTopLevelIrp = TRUE;
				else
					info.fEnabled = FALSE;
				break;
			}

			IFERR_LOG(updateHashOnPostOp(pStreamHandleContext, pData, HashedAction::Write),
				"Can't calculate write hash. pid: %Iu, pos: 0x%016I64X, size: %Iu.\r\n",
				(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, info.nNextPos,
				pData->IoStatus.Information);
		} while (false);

		// Emit the write event for every successful write. The rule layer filters
		// by path/extension; the driver must not drop writes silently. The event is
		// sent after sequence hashing so hash-based rules (e.g. FILE_COPY detection)
		// can correlate read/write pairs via "file.rawHash". When sequence hashing
		// is not active the event carries no hash; the service-side hash key
		// calculation skips the missing field instead of failing.
		if (NT_SUCCESS(pData->IoStatus.Status) && pData->IoStatus.Information != 0)
		{
			auto& info = pStreamHandleContext->sequenceWriteInfo;
			sendFileEvent(SysmonEvent::FileDataWriteFull, pStreamHandleContext,
				[&info, pStreamHandleContext](auto pSerializer) {
					if (info.fEnabled)
					{
						NTSTATUS nsH = writeFileHash(pSerializer, info);
						if (!NT_SUCCESS(nsH))
							return nsH;
					}
					if (pStreamHandleContext != nullptr && pStreamHandleContext->szRansomDst[0] != L'\0')
					{
						UNICODE_STRING usBk;
						RtlInitUnicodeString(&usBk, pStreamHandleContext->szRansomDst);
						(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
					}
					return STATUS_SUCCESS;
				}
			);
		}
	}
	__finally
	{
		if (pStreamHandleContext != nullptr)
			FltReleaseContext(pStreamHandleContext);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//
//
//
FLT_PREOP_CALLBACK_STATUS FLTAPI preRead(_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring) return FLT_PREOP_SUCCESS_NO_CALLBACK;
	if (KeGetCurrentIrql() > APC_LEVEL) return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	NTSTATUS ns = FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext);
	if (!NT_SUCCESS(ns) || pStreamHandleContext == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Check skipping flags
	if (isReadWriteSkipping(pData, pStreamHandleContext, HashedAction::Read)
		|| pStreamHandleContext->fSkipItem)
	{
		FltReleaseContext(pStreamHandleContext);
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	auto& readParams = pData->Iopb->Parameters.Read;

	// postRead is necessary to check operation success and emit the read event.
	// Every read IRP must reach the engine unfiltered â€” the rule layer decides
	// whether the file extension/path is interesting. Random-access and partial
	// reads (ransomware scans) previously produced no event at all because the
	// old logic only enabled postRead for full sequential reads.
	// Sequence hashing requires a synchronous post-op (buffer stays valid);
	// plain event emission only needs a callback on completion.
	bool fSyncNeeded = false;

	// Processing sequence read (full-file sequential read tracking)
	do 
	{
		auto& info = pStreamHandleContext->sequenceReadInfo;

		if(!info.fEnabled)
			break;
		// not interesting action
		if (readParams.Length == 0)
			break;

		// getting reading pos from parameters or current file pos
		uint64_t nReadPos =
			(readParams.ByteOffset.LowPart == FILE_USE_FILE_POINTER_POSITION && readParams.ByteOffset.HighPart == -1) ?
			pFltObjects->FileObject->CurrentByteOffset.QuadPart :
			readParams.ByteOffset.QuadPart;


		// check write position
		if (nReadPos != info.nNextPos)
		{
			info.fEnabled = false;
			break;
		}

		fSyncNeeded = true;
	} while (false);

	LOGINFO4("filemon: preRead: id: %05Iu:%p:%p, pos: %I64u, size: %u, post: %u.\r\n",
		(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject,
		pFltObjects->FileObject->CurrentByteOffset.QuadPart, (ULONG)readParams.Length,
		(ULONG)fSyncNeeded ? 1 : 0);

	FltReleaseContext(pStreamHandleContext);
	return fSyncNeeded ? FLT_PREOP_SYNCHRONIZE : FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


//
//
//
FLT_POSTOP_CALLBACK_STATUS FLTAPI postRead(__inout PFLT_CALLBACK_DATA pData, 
	__in PCFLT_RELATED_OBJECTS pFltObjects,__in_opt PVOID /*pCompletionContext*/, 
	__in FLT_POST_OPERATION_FLAGS Flags)
{
	if (!g_pCommonData->fEnableMonitoring) return FLT_POSTOP_FINISHED_PROCESSING;
	if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;

	// if no context - skip post operation
	StreamHandleContext* pStreamHandleContext = nullptr;
	__try
	{
		IFERR_LOG(FltGetStreamHandleContext(pFltObjects->Instance, pFltObjects->FileObject, (PFLT_CONTEXT*)&pStreamHandleContext));
		if (pStreamHandleContext == nullptr)
			return FLT_POSTOP_FINISHED_PROCESSING;

		LOGINFO4("filemon: postRead: id: %05Iu:%p:%p, status: 0x%08X, info: %u.\r\n",
			(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext, pFltObjects->FileObject,
			(ULONG)pData->IoStatus.Status, (ULONG)pData->IoStatus.Information);

		// Sequence action detection
		do
		{
			auto& info = pStreamHandleContext->sequenceReadInfo;

			//
			// If not enabled 
			if (!info.fEnabled)
				break;

			// If operation is failed
			if (!NT_SUCCESS(pData->IoStatus.Status))
			{
				// Some devices (e.g, USB drives) can deny FAST_IO and returns STATUS_FLT_DISALLOW_FAST_IO.
				// And next action will be with the same buffers as IRP.
				if (pData->IoStatus.Status == STATUS_FLT_DISALLOW_FAST_IO)
					info.fAllowNotTopLevelIrp = TRUE;
				else
					info.fEnabled = FALSE;
				break;
			}
			
			IFERR_LOG(updateHashOnPostOp(pStreamHandleContext, pData, HashedAction::Read, pFltObjects),
				"Can't calculate read hash. pid: %Iu, pos: 0x%016I64X, size: %Iu.\r\n",
				(ULONG_PTR)pStreamHandleContext->nOpeningProcessId, pStreamHandleContext->sequenceReadInfo.nNextPos,
				pData->IoStatus.Information);
		} while (false);

		// Emit the read event for every successful read. The rule layer filters
		// by path/extension; the driver must not drop reads silently. The event is
		// sent after sequence hashing so hash-based rules (e.g. FILE_COPY detection)
		// can correlate read/write pairs via "file.rawHash". When sequence hashing
		// is not active the event carries no hash; the service-side hash key
		// calculation skips the missing field instead of failing.
		if (NT_SUCCESS(pData->IoStatus.Status) && pData->IoStatus.Information != 0)
		{
			auto& info = pStreamHandleContext->sequenceReadInfo;
			sendFileEvent(SysmonEvent::FileDataReadFull, pStreamHandleContext,
				[&info, pStreamHandleContext](auto pSerializer) {
					if (info.fEnabled)
					{
						NTSTATUS nsH = writeFileHash(pSerializer, info);
						if (!NT_SUCCESS(nsH))
							return nsH;
					}
					if (pStreamHandleContext != nullptr && pStreamHandleContext->szRansomDst[0] != L'\0')
					{
						UNICODE_STRING usBk;
						RtlInitUnicodeString(&usBk,
							pStreamHandleContext->szRansomDst);
						(void)write(*(pSerializer), EvFld::FileBackupPath, &usBk);
					}
					return STATUS_SUCCESS;
				}
			);
		}
	}
	__finally
	{
		if (pStreamHandleContext != nullptr)
			FltReleaseContext(pStreamHandleContext);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI preDeviceControl(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (pData == nullptr || pData->Iopb == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (pData->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	ULONG nIoControlCode = pData->Iopb->Parameters.DeviceIoControl.Common.IoControlCode;
	if (!isDangerousDiskIoctl(nIoControlCode))
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	UNICODE_STRING usFallback;
	RtlInitUnicodeString(&usFallback, L"BOOT_DISK_OR_DRIVE_LAYOUT");
	PCUNICODE_STRING pusTarget = &usFallback;
	if (pFltObjects != nullptr &&
		pFltObjects->FileObject != nullptr &&
		pFltObjects->FileObject->FileName.Buffer != nullptr &&
		pFltObjects->FileObject->FileName.Length != 0)
	{
		pusTarget = &pFltObjects->FileObject->FileName;
	}

	sendPathEvent(
		SysmonEvent::DeviceIoControl,
		pusTarget,
		(ULONG_PTR)FltGetRequestorProcessId(pData),
		nIoControlCode);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION (Windows 10 1809+)
//
// A file-backed section is created against a file (NtCreateSection +
// NtMapViewOfSection) WITHOUT issuing IRP_MJ_READ/IRP_MJ_WRITE. This is the
// only minifilter-visible IRP for mapped-section access. PageProtection reveals
// the mapping intent: PAGE_READONLY => read-only section (read intent),
// writable protections => writable section (write intent). Emit a path event so
// the engine can attribute the mapped access to the file.
//
FLT_PREOP_CALLBACK_STATUS FLTAPI preAcquireForSectionSync(
	_Inout_ PFLT_CALLBACK_DATA pData,
	_In_ PCFLT_RELATED_OBJECTS pFltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* /*pCompletionContext*/)
{
	if (!g_pCommonData->fEnableMonitoring)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (KeGetCurrentIrql() > APC_LEVEL)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (pData == nullptr || pData->Iopb == nullptr || pFltObjects == nullptr)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	if (pData->RequestorMode == KernelMode)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	auto& sectionParams = pData->Iopb->Parameters.AcquireForSectionSynchronization;

	// Only the initial section creation carries allocation attributes.
	if (sectionParams.SyncType != SyncTypeCreateSection)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	ULONG nPageProtection = sectionParams.PageProtection;

	// Skip executable image sections: those are the loader mapping code images,
	// not data-file reads/writes. SEC_IMAGE is set for image-backed sections.
	constexpr ULONG c_nSecImage = 0x01000000; // SEC_IMAGE
	if (sectionParams.AllocationAttributes & c_nSecImage)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	// Classify mapping intent from page protection.
	static constexpr ULONG c_nWritableProtections =
		PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
	bool fWriteIntent = (nPageProtection & c_nWritableProtections) != 0;

	// Only emit for section mappings with an actual page protection requested
	// and skip "other" sync operations (map/unmap of an already-created section).
	if (nPageProtection == 0)
		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	UNICODE_STRING usFallback;
	RtlInitUnicodeString(&usFallback, L"UNKNOWN");
	PCUNICODE_STRING pusTarget = &usFallback;
	if (pFltObjects->FileObject != nullptr &&
		pFltObjects->FileObject->FileName.Buffer != nullptr &&
		pFltObjects->FileObject->FileName.Length != 0)
	{
		pusTarget = &pFltObjects->FileObject->FileName;
	}

	// Reuse dedicated section-map (mmap) event ids so the engine classifies the
	// mapped access as a distinct mmap rule type ("mmap_read"/"mmap_write"),
	// separate from ordinary IRP-level read/write. The original FileDataReadFull
	// / FileDataWriteFull events remain the united (api + minifilter) rule type.
	sendPathEvent(
		fWriteIntent ? SysmonEvent::FileMapWrite : SysmonEvent::FileMapRead,
		pusTarget,
		(ULONG_PTR)FltGetRequestorProcessId(pData),
		nPageProtection);

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


//////////////////////////////////////////////////////////////////////////
//
// MiniFilter Descriptor
//
//////////////////////////////////////////////////////////////////////////

NTSTATUS unloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

//
// Operation callbacks
//
CONST FLT_OPERATION_REGISTRATION c_Callbacks[] = 
{
	{ IRP_MJ_CREATE, 0, preCreate, postCreate },
	{ IRP_MJ_CLEANUP, 0, preCleanup, postCleanup },
	{ IRP_MJ_SET_INFORMATION, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, preSetFileInfo, postSetFileInfo },
	{ IRP_MJ_WRITE, 0, preWrite, postWrite },
	{ IRP_MJ_READ, 0, preRead, postRead },
	{ IRP_MJ_DEVICE_CONTROL, 0, preDeviceControl, nullptr },
	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, preAcquireForSectionSync, nullptr },

	{ IRP_MJ_OPERATION_END }
};

//
// Filters context registration data structure
//
const FLT_CONTEXT_REGISTRATION c_ContextRegistration[] = {

	{ FLT_INSTANCE_CONTEXT, 0, cleanupInstanceContext,
	sizeof(InstanceContext), c_nAllocTag },

	{ FLT_STREAMHANDLE_CONTEXT, 0, StreamHandleContext::cleanup,
	sizeof(StreamHandleContext), c_nAllocTag },

	{ FLT_CONTEXT_END }
};


//
//  This defines what we want to filter with FltMgr
//
CONST FLT_REGISTRATION c_FilterRegistration = 
{
	sizeof(FLT_REGISTRATION),		  //  Size
	FLT_REGISTRATION_VERSION,         //  Version
	0,                                //  eFlags

	c_ContextRegistration,            //  Context
	c_Callbacks,                      //  Operation callbacks

	unloadFilter,                     //  MiniFilterUnload

	setupInstance,                    //  InstanceSetup
	queryInstanceTeardown,            //  InstanceQueryTeardown
	startInstanceTeardown,            //  InstanceTeardownStart
	completeInstanceTeardown,         //  InstanceTeardownComplete

	NULL,                             //  GenerateFileName
	NULL,                             //  GenerateDestinationFileName
	NULL                              //  NormalizeNameComponent
};

//////////////////////////////////////////////////////////////////////////
//
// File rules and self defense 
//
//////////////////////////////////////////////////////////////////////////

///
/// Access mask has write rights
///
inline bool hasFileWriteAccess(ACCESS_MASK access)
{
	static constexpr ACCESS_MASK c_nFileWriteAccessMask =
		/*FILE_READ_DATA |*/ FILE_WRITE_DATA | FILE_APPEND_DATA | /*FILE_READ_EA |*/
		FILE_WRITE_EA | /*FILE_EXECUTE |*/ FILE_DELETE_CHILD | /*FILE_READ_ATTRIBUTES |*/
		FILE_WRITE_ATTRIBUTES | DELETE | /*READ_CONTROL |*/ WRITE_DAC | WRITE_OWNER /*| SYNCHRONIZE*/;

	// expand file generic access
	RtlMapGenericMask(&access, IoGetFileObjectGenericMapping());
	return ((access & c_nFileWriteAccessMask) != 0);
}



//
// Check selfprotection for specified process and file.
// Returns true if need to restrict access.
//
bool isSelfProtected(PCUNICODE_STRING pusFileName, ACCESS_MASK desiredAccess)
{
	// apply rules
	SharedLock lock(g_pCommonData->mtxFileRules);
	for (auto& rule : g_pCommonData->fileRules)
	{

		PCUNICODE_STRING pusRulePath = rule.usNtPath;
		// Check prefix
		if (!isStartWith(pusFileName, pusRulePath))
			continue;

		// check protected dirs
		if (pusRulePath->Length != pusFileName->Length)
		{
			if (!rule.fIsDir)
				continue;

			// Check '\\' after prefix
			if ((pusFileName->Length - pusRulePath->Length) < sizeof(WCHAR))
				continue;
			auto pNextChar = (WCHAR*)&(((uint8_t*)pusFileName->Buffer)[pusRulePath->Length]);
			if (*pNextChar != L'\\')
				continue;

		}

		// apply rule
		switch (rule.eAccessType)
		{
			case edrdrv::AccessType::Full:
				return false;
			case edrdrv::AccessType::NoAccess:
				return true;
			case edrdrv::AccessType::ReadOnly:
				return hasFileWriteAccess(desiredAccess);
			default:
				// stop iteration because rule was applied
				return false;
		}
	}

	// rule was not found
	return false;
}

//
// Print rules
//
void printFileRuleList(const FileRuleList& rules)
{
	ULONG nIndex = 0;
	for (auto& rule : rules)
	{
		LOGINFO1("rule#%02u: path: <%wZ>, val: %u, dir: %u, tag: <%wZ>.\r\n",
			nIndex, (PCUNICODE_STRING)rule.usNtPath, (ULONG)rule.eAccessType, (ULONG)rule.fIsDir,
			(PCUNICODE_STRING)rule.usTag);
		++nIndex;
	}
}

//
//
//
NTSTATUS loadRulesFromConfig()
{
	Blob data;
	IFERR_RET(cfg::loadConfigBlob(cfg::ConfigId::ProtectedFiles, data));
	if (data.isEmpty())
		return STATUS_SUCCESS;

	IFERR_LOG(updateFileRules(data.getData(), data.getSize()));
	return STATUS_SUCCESS;
}

//
//
//
NTSTATUS saveRulesToConfig()
{
	// Serialization
	bool fRemoveConfig = false;
	NonPagedLbvsSerializer<UpdateRulesField> serializer;
	do
	{
		SharedLock rulesLock(g_pCommonData->mtxFileRules);

		// If list is empty - delete config
		if (g_pCommonData->fileRules.isEmpty())
		{
			fRemoveConfig = true;
			break;
		}

		if (!serializer.write(UpdateRulesField::Mode, (uint32_t)UpdateRulesMode::Replace)) return LOGERROR(STATUS_NO_MEMORY);

		for (auto& rule : g_pCommonData->fileRules)
		{
			if (!serializer.write(UpdateRulesField::Rule)) return LOGERROR(STATUS_NO_MEMORY);
			if (!serializer.write(UpdateRulesField::RuleValue, (uint32_t)rule.eAccessType)) return LOGERROR(STATUS_NO_MEMORY);
			if (!rule.usNtPath.isEmpty())
				if (!write(serializer, UpdateRulesField::RulePath, rule.usNtPath)) return LOGERROR(STATUS_NO_MEMORY);
			if (!rule.usTag.isEmpty())
				if (!write(serializer, UpdateRulesField::RuleTag, rule.usTag)) return LOGERROR(STATUS_NO_MEMORY);
			if (rule.fIsDir)
				if (!serializer.write(UpdateRulesField::RuleRecursive, true)) return LOGERROR(STATUS_NO_MEMORY);
		}
	} while (false);

	// Save
	if (fRemoveConfig)
	{
		IFERR_RET(cfg::removeConfigBlob(cfg::ConfigId::ProtectedFiles));
	}
	else
	{
		IFERR_RET(cfg::saveConfigBlob(cfg::ConfigId::ProtectedFiles, serializer));
	}
	return STATUS_SUCCESS;
}


//
//
//
NTSTATUS updateFileRules(const void* pData, size_t nDataSize)
{
	//////////////////////////////////////////////////////////////////////////
	//
	// Deserialize
	//

	variant::BasicLbvsDeserializer<UpdateRulesField> deserializer;
	if (!deserializer.reset(pData, nDataSize))
		return LOGERROR(STATUS_DATA_ERROR, "Invalid data format.\r\n");

	// Deserialize main data
	UpdateRulesMode updateMode = UpdateRulesMode::Invalid;
	DynUnicodeString usTagForDelete;
	for (auto& item : deserializer)
	{
		switch (item.id)
		{
		case UpdateRulesField::Mode:
		{
			IFERR_RET(getEnumValue(item, updateMode));
			continue; // goto next item
		}
		case UpdateRulesField::Tag:
		{
			IFERR_RET(getValue(item, usTagForDelete));
			continue; // goto next item
		}
		}
	}

	// Deserialize rules.
	// Should be after main fields, cause it uses this data, but order is not determined
	FileRuleList rules;
	for (auto& item : deserializer)
	{
		switch (item.id)
		{
			case UpdateRulesField::Rule:
			{
				IFERR_RET(rules.pushBack(FileRule()));
				// Set default tag
				if (!usTagForDelete.isEmpty())
					IFERR_RET(rules.getBack().usTag.assign(usTagForDelete), "Can't assign tag");
				continue; // goto next item
			}
			case UpdateRulesField::RulePath:
			case UpdateRulesField::RuleImagePath:
			{
				if (rules.isEmpty())
					return LOGERROR(STATUS_INVALID_PARAMETER, "Unexpected field: %u.\r\n", (ULONG)item.id);
				IFERR_RET(getValue(item, rules.getBack().usNtPath));
				continue; // goto next item
			}
			case UpdateRulesField::RuleTag:
			{
				if (rules.isEmpty())
					return LOGERROR(STATUS_INVALID_PARAMETER, "Unexpected field: %u.\r\n", (ULONG)item.id);
				IFERR_RET(getValue(item, rules.getBack().usTag));
				continue; // goto next item
			}
			case UpdateRulesField::RuleInherite:
			case UpdateRulesField::RuleRecursive:
			{
				if (rules.isEmpty())
					return LOGERROR(STATUS_INVALID_PARAMETER, "Unexpected field: %u.\r\n", (ULONG)item.id);
				IFERR_RET(getValue(item, rules.getBack().fIsDir));
				continue; // goto next item
			}
			case UpdateRulesField::RuleValue:
			{
				if (rules.isEmpty())
					return LOGERROR(STATUS_INVALID_PARAMETER, "Unexpected field: %u.\r\n", (ULONG)item.id);
				IFERR_RET(getEnumValue(item, rules.getBack().eAccessType));
				continue; // goto next item
			}
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//
	// Logging
	//

	if (g_pCommonData->nLogLevel >= 2)
	{
		LOGINFO2("updateFileRules. mode: %u, tag: <%wZ>, rulesCount: %u.\r\n",
			(ULONG)updateMode, (PCUNICODE_STRING)usTagForDelete, (ULONG)rules.getSize());
		printFileRuleList(rules);
	}

	//////////////////////////////////////////////////////////////////////////
	//
	// Verification
	//

	if (updateMode <= UpdateRulesMode::Invalid || updateMode >= UpdateRulesMode::_Max)
		return LOGERROR(STATUS_INVALID_PARAMETER, "The %u field is absent or invalid.\r\n", (ULONG)UpdateRulesField::Mode);

	if (updateMode == edrdrv::UpdateRulesMode::DeleteByTag)
	{
		if (usTagForDelete.isEmpty())
			return LOGERROR(STATUS_INVALID_PARAMETER, "The %u field is absent or invalid.\r\n", (ULONG)UpdateRulesField::Tag);
	}

	if (updateMode == edrdrv::UpdateRulesMode::DeleteByTag || updateMode == edrdrv::UpdateRulesMode::Clear)
	{
		if (!rules.isEmpty())
			// This error does not break the function, but should be logged
			LOGERROR(STATUS_INVALID_PARAMETER, "The 'rules' should not be set for mode: %u.\r\n", (ULONG)updateMode);
	}

	//////////////////////////////////////////////////////////////////////////
	//
	// Update rules
	//

	// Delete by tag
	bool fNeedSave = false;
	if (updateMode == edrdrv::UpdateRulesMode::DeleteByTag)
	{
		UniqueLock rulesLock(g_pCommonData->mtxFileRules);

		PCUNICODE_STRING usTag = usTagForDelete;
		auto nDeletedCount = g_pCommonData->fileRules.removeIf([usTag](const FileRule& rule) -> bool
		{
			return rule.usTag.isEqual(usTag, false);
		});
		fNeedSave = nDeletedCount != 0;
		LOGINFO2("updateFileRules. %u rules were deleted.\r\n", (ULONG)nDeletedCount);
	}
	// Update
	else
	{
		UniqueLock rulesLock(g_pCommonData->mtxFileRules);
		fNeedSave = true;
		updateList(updateMode, g_pCommonData->fileRules, rules);
	}

	//////////////////////////////////////////////////////////////////////////
	//
	// Logging new state
	//

	if (g_pCommonData->nLogLevel >= 2)
	{
		SharedLock rulesLock(g_pCommonData->mtxFileRules);
		LOGINFO1("File rules: count:%u.\r\n", (ULONG)g_pCommonData->fileRules.getSize());
		printFileRuleList(g_pCommonData->fileRules);
	}

	// Save into config
	if (fNeedSave)
	{
		IFERR_LOG(saveRulesToConfig());
	}

	return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
//
// Filter registration / deregistration
//
//////////////////////////////////////////////////////////////////////////

//
//
//
NTSTATUS initialize()
{
	LOGINFO2("Register FileFilter\r\n");

	bool fSuccessInit = false;

	IFERR_LOG(loadRulesFromConfig());

	__try
	{
		

		NTSTATUS ns = FltRegisterFilter(g_pCommonData->pDriverObject, &c_FilterRegistration, &g_pCommonData->pFilter);
		IFERR_RET(ns);
		LOGINFO2("FltRegisterFilter returns 0x%08X.\r\n", (ULONG)ns);

		IFERR_RET(fltport::initialize());

		ns = FltStartFiltering(g_pCommonData->pFilter);
		IFERR_RET(ns);
		LOGINFO2("FltStartFiltering returns 0x%08X.\r\n", (ULONG)ns);

		IFERR_RET(tools::getSystemRootDirectoryPath(g_pCommonData->systemRootDirectory));
		fSuccessInit = true;
	}
	__finally
	{
		if (!fSuccessInit)
			finalize();
	}

	return STATUS_SUCCESS;
}

//
//
//
void finalize()
{
	fltport::finalize();

	if (g_pCommonData->pFilter == NULL) return;
	FltUnregisterFilter(g_pCommonData->pFilter);
	g_pCommonData->pFilter = NULL;
}

//
// This is the unload routine for this miniFilter driver. This is called
// when the minifilter is about to be unloaded. We can fail this unload
// request if this is not a mandatory unloaded indicated by the eFlags
// parameter.
//
NTSTATUS unloadFilter(_In_ FLT_FILTER_UNLOAD_FLAGS /*Flags*/)
{
	LOGINFO2("%s: Entered\r\n", __FUNCTION__);

	finalize();
	return STATUS_SUCCESS;
}

namespace tools
{

__drv_maxIRQL(APC_LEVEL)
__checkReturn
NTSTATUS
getInstanceFromFileObject(
	__in PFILE_OBJECT FileObject,
	__deref_out PFLT_INSTANCE* Instance
	)
{
	if (nullptr == g_pCommonData->pFilter)
		return STATUS_FLT_NOT_INITIALIZED;

	FltVolumeDeref volume;
	IFERR_RET_NOLOG(FltGetVolumeFromFileObject(g_pCommonData->pFilter, FileObject, &volume));
	IFERR_RET_NOLOG(FltGetVolumeInstanceFromName(g_pCommonData->pFilter, volume, nullptr, Instance));
	return STATUS_SUCCESS;
}

__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
openFile(
	__in_opt PFLT_INSTANCE Instance,
	__in const UNICODE_STRING& FilePath,
	__out UniqueFltHandle& FileHandle,
	__out FileObjectPtr& FileObject,
	__in ACCESS_MASK DesiredAccess,
	__in ULONG ShareAccess
	)
{
	if (nullptr == g_pCommonData->pFilter)
		return STATUS_FLT_NOT_INITIALIZED;

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(
		&objectAttributes,
		const_cast<PUNICODE_STRING>(&FilePath),
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		nullptr);

	IO_STATUS_BLOCK ioStatus;
	IFERR_RET_NOLOG(FltCreateFileEx(
		g_pCommonData->pFilter,
		Instance,
		&FileHandle,
		&FileObject,
		DesiredAccess,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		ShareAccess,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK));

	return STATUS_SUCCESS;
}

//
//
//
__drv_maxIRQL(PASSIVE_LEVEL)
__checkReturn
NTSTATUS
getSystemRootDirectoryPath(
	__out DynUnicodeString& SystemRootPath
	)
{
	if (nullptr == cmd::g_pCommonData->pFilter)
		return STATUS_FLT_NOT_INITIALIZED;

	DECLARE_CONST_UNICODE_STRING(rootLink, L"\\SystemRoot");

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, const_cast<PUNICODE_STRING>(&rootLink), OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, nullptr, nullptr);
	IO_STATUS_BLOCK ioStatus = { 0 };

	FileObjectPtr fileObject;
	UniqueFltHandle fileHandle;

	IFERR_RET_NOLOG(FltCreateFileEx(cmd::g_pCommonData->pFilter,
		nullptr,
		&fileHandle,
		&fileObject,
		FILE_TRAVERSE | SYNCHRONIZE,
		&objectAttributes,
		&ioStatus,
		nullptr,
		FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_ALL,
		FILE_OPEN,
		FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
		nullptr,
		0,
		IO_IGNORE_SHARE_ACCESS_CHECK | IO_NO_PARAMETER_CHECKING));

	FltInstanceDeref instance;
	IFERR_RET_NOLOG(filemon::tools::getInstanceFromFileObject(fileObject, &instance));

	FltFileNameInfoDeref fileNameInfo;
	IFERR_RET_NOLOG(FltGetFileNameInformationUnsafe(fileObject, instance, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &fileNameInfo));
	IFERR_RET_NOLOG(SystemRootPath.assign(&fileNameInfo->Name));

	return STATUS_SUCCESS;
}

} // namespace tools
} // namespace filemon
} // namespace cmd
/// @}

