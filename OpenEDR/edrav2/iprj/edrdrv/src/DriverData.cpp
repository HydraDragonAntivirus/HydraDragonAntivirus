#include "DriverData.h"

// Sentinel stored in PidToGids when a terminate callback fires for a PID that
// RecordNewProcess has not yet inserted. If RecordNewProcess later runs for the
// same PID it will find this marker, skip insertion, and clean up the tombstone.
// Value chosen to be unreachable by the monotonically-increasing GidCounter.
#define TERMINATED_PID_SENTINEL ((ULONGLONG)0xFFFFFFFFFFFFFFFFULL)

// Bound the user-mode telemetry backlog. Each IRP_ENTRY is a nonpaged-pool
// allocation, so an unresponsive consumer must not be allowed to grow this list
// without limit.
#define MAX_PENDING_IRP_MESSAGES 8192UL

DriverData::DriverData(PDRIVER_OBJECT DriverObject) :
    FilterRun(FALSE),
    Filter(nullptr),
    DriverObject(DriverObject),
    pid(0),
    irpOpsSize(0),
    directoryRootsSize(0),
    GidToPids(),
    PidToGids() {
    systemRootPath[0] = L'\0';
    InitializeListHead(&irpOps);
    InitializeListHead(&rootDirectories);
    InitializeListHead(&blockedPaths);
    KeInitializeSpinLock(&irpOpsLock);  //init spin lock
    KeInitializeSpinLock(&directoriesSpinLock);  //init spin lock
    KeInitializeSpinLock(&blockedPathsLock);  //init spin lock

    GidCounter = 0;
    blockedPathsSize = 0;
    KeInitializeSpinLock(&GIDSystemLock);  //init spin lock
    gidsSize = 0;
    InitializeListHead(&GidsList);

    registryBackupsSize = 0;
    InitializeListHead(&registryBackups);
    KeInitializeSpinLock(&registryBackupsLock);

    RtlZeroMemory(lineageRing, sizeof(lineageRing));
    lineageNext = 0;
    KeInitializeSpinLock(&lineageLock);

    // Initialize volumeCacheLock
    KeInitializeSpinLock(&volumeCacheLock);

    // Initialize quarantinePath
    RtlInitUnicodeString(&quarantinePath, NULL);
}

DriverData::~DriverData() {
    Clear();
}

DriverData* driverData;

static VOID FreeOwnedProcessName(_In_opt_ PUNICODE_STRING ProcessName) {
    if (ProcessName != NULL) {
        ExFreePoolWithTag(ProcessName, OWLY_POOL_TAG_PROCESS_NAME);
    }
}

//#######################################################################################
//# Volume Cache handling
//#######################################################################################

VOID DriverData::FreeCachedUnicodeString(PVOID str) {
    PUNICODE_STRING pStr = (PUNICODE_STRING)str;
    if (pStr != NULL) {
        if (pStr->Buffer != NULL) {
            ExFreePoolWithTag(pStr->Buffer, OWLY_POOL_TAG_VOLUME_CACHE);
        }
        ExFreePoolWithTag(pStr, OWLY_POOL_TAG_VOLUME_CACHE);
    }
}

VOID DriverData::ClearVolumeCache() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&volumeCacheLock, &oldIrql);

    VolumeToDosName.clear(FreeCachedUnicodeString);

    KeReleaseSpinLock(&volumeCacheLock, oldIrql);
}

NTSTATUS DriverData::AddVolumeDosName(PFLT_VOLUME volume, PUNICODE_STRING dosName) {
    if (volume == NULL || dosName == NULL || dosName->Buffer == NULL || dosName->Length == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PUNICODE_STRING cachedName =
        (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), OWLY_POOL_TAG_VOLUME_CACHE);
    if (cachedName == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cachedName->MaximumLength = dosName->Length + sizeof(WCHAR);
    cachedName->Buffer =
        (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, cachedName->MaximumLength, OWLY_POOL_TAG_VOLUME_CACHE);
    if (cachedName->Buffer == NULL) {
        ExFreePoolWithTag(cachedName, OWLY_POOL_TAG_VOLUME_CACHE);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    cachedName->Length = dosName->Length;
    RtlCopyMemory(cachedName->Buffer, dosName->Buffer, dosName->Length);
    cachedName->Buffer[cachedName->Length / sizeof(WCHAR)] = L'\0';

    KIRQL oldIrql;
    KeAcquireSpinLock(&volumeCacheLock, &oldIrql);

    HANDLE previousValue = VolumeToDosName.insertNode((ULONGLONG)(ULONG_PTR)volume, cachedName);

    KeReleaseSpinLock(&volumeCacheLock, oldIrql);

    if (previousValue != NULL && previousValue != cachedName) {
        FreeCachedUnicodeString(previousValue);
    }

    return STATUS_SUCCESS;
}

NTSTATUS DriverData::GetVolumeDosName(PFLT_VOLUME volume, PUNICODE_STRING outDosName) {
    if (volume == NULL || outDosName == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(outDosName, sizeof(*outDosName));

    KIRQL oldIrql;
    KeAcquireSpinLock(&volumeCacheLock, &oldIrql);

    PUNICODE_STRING cachedName =
        (PUNICODE_STRING)VolumeToDosName.get((ULONGLONG)(ULONG_PTR)volume);

    if (cachedName == NULL || cachedName->Buffer == NULL || cachedName->Length == 0) {
        KeReleaseSpinLock(&volumeCacheLock, oldIrql);
        return STATUS_NOT_FOUND;
    }

    USHORT copyLength = cachedName->Length;
    KeReleaseSpinLock(&volumeCacheLock, oldIrql);

    outDosName->MaximumLength = copyLength + sizeof(WCHAR);
    outDosName->Buffer =
        (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, outDosName->MaximumLength, OWLY_POOL_TAG_VOLUME_CACHE);
    if (outDosName->Buffer == NULL) {
        outDosName->MaximumLength = 0;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeAcquireSpinLock(&volumeCacheLock, &oldIrql);

    cachedName = (PUNICODE_STRING)VolumeToDosName.get((ULONGLONG)(ULONG_PTR)volume);
    if (cachedName == NULL || cachedName->Buffer == NULL || cachedName->Length == 0 ||
        cachedName->Length > copyLength) {
        KeReleaseSpinLock(&volumeCacheLock, oldIrql);
        ExFreePoolWithTag(outDosName->Buffer, OWLY_POOL_TAG_VOLUME_CACHE);
        outDosName->Buffer = NULL;
        outDosName->MaximumLength = 0;
        return STATUS_NOT_FOUND;
    }

    outDosName->Length = cachedName->Length;
    RtlCopyMemory(outDosName->Buffer, cachedName->Buffer, cachedName->Length);
    KeReleaseSpinLock(&volumeCacheLock, oldIrql);

    outDosName->Buffer[outDosName->Length / sizeof(WCHAR)] = L'\0';
    return STATUS_SUCCESS;
}

//#######################################################################################
//# Quarantine Path Handling
//#######################################################################################

VOID DriverData::SetQuarantinePath(PUNICODE_STRING path) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql); // Using directoriesSpinLock for quarantinePath protection

    // Free existing buffer if any
    if (quarantinePath.Buffer != NULL) {
        ExFreePoolWithTag(quarantinePath.Buffer, OWLY_POOL_TAG_QUARANTINE_PATH);
        quarantinePath.Buffer = NULL;
        quarantinePath.Length = 0;
        quarantinePath.MaximumLength = 0;
    }

    if (path != NULL && path->Length > 0) {
        quarantinePath.MaximumLength = path->Length + sizeof(WCHAR); // + null terminator
        quarantinePath.Buffer =
            (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, quarantinePath.MaximumLength, OWLY_POOL_TAG_QUARANTINE_PATH);
        if (quarantinePath.Buffer != NULL) {
            RtlCopyUnicodeString(&quarantinePath, path);
            quarantinePath.Buffer[quarantinePath.Length / sizeof(WCHAR)] = L'\0'; // Null-terminate
            
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: Quarantine path set to: %wZ\n", &quarantinePath);
#endif

        } else {
            
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: Failed to allocate memory for quarantine path.\n");
#endif

            RtlInitUnicodeString(&quarantinePath, NULL); // Ensure it's null-initialized on failure
        }
    } else {
        RtlInitUnicodeString(&quarantinePath, NULL); // Clear path if input is null or empty
    }

    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
}

BOOLEAN DriverData::IsPathInQuarantineDir(CONST PUNICODE_STRING path) {
    if (path == NULL || path->Buffer == NULL || quarantinePath.Buffer == NULL || quarantinePath.Length == 0) {
        return FALSE;
    }

    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql); // Using directoriesSpinLock for quarantinePath protection

    // Check if the input path starts with the quarantine path
    if (path->Length >= quarantinePath.Length) {
        if (RtlCompareMemory(path->Buffer, quarantinePath.Buffer, quarantinePath.Length) == quarantinePath.Length) {
            // Ensure it's a directory match, not just a prefix of a filename
            // e.g., "C:\Quarantine" should match "C:\Quarantine\file.txt" but not "C:\Quarantine_Extra"
            if (path->Length == quarantinePath.Length || path->Buffer[quarantinePath.Length / sizeof(WCHAR)] == L'\\') {
                ret = TRUE;
            }
        }
    }

    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
    return ret;
}

//#######################################################################################
//# Gid system handling
//#######################################################################################

/****************** Private ******************/

// call assumes protected code high irql
BOOLEAN DriverData::RemoveProcessRecordAux(ULONG ProcessId, ULONGLONG gid) {
    BOOLEAN ret = FALSE;
    PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (gidRecord == nullptr) {  // shouldnt happen
        return FALSE;
    }
    PLIST_ENTRY header = &(gidRecord->HeadListPids);
    PLIST_ENTRY iterator = header->Flink;
    while (iterator != header) {
        PPID_ENTRY pStrct =
            (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
        if (pStrct->Pid == ProcessId) {
            RemoveEntryList(iterator);
            FreeOwnedProcessName(pStrct->Path);
            pStrct->Path = NULL;
            delete pStrct;
            gidRecord->pidsSize--;
            ret = TRUE;
            break;
        }
        iterator = iterator->Flink;
    }
    if (ret) {
        if (IsListEmpty(header)) {
            GidToPids.deleteNode(gid);  // remove the gidRecord from GidToPids
            RemoveEntryList(
                &(gidRecord->GidListEntry));  // unlink from list of gids
            gidsSize--;
            delete gidRecord;
        }
        PidToGids.deleteNode(ProcessId);
    }
    return ret;
}

// call assumes protected code high irql
BOOLEAN DriverData::RemoveGidRecordAux(PGID_ENTRY gidRecord) {
    BOOLEAN ret = FALSE;
    ASSERT(gidRecord != nullptr);
    PLIST_ENTRY headerPids = &(gidRecord->HeadListPids);
    PULONGLONG pidsSize = &(gidRecord->pidsSize);
    PLIST_ENTRY iterator = headerPids->Flink;
    while (iterator != headerPids) {  // clear list
        PPID_ENTRY pStrct =
            (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
        PLIST_ENTRY next = iterator->Flink;
        RemoveEntryList(iterator);
        PidToGids.deleteNode(pStrct->Pid);
        pidsSize--;
        FreeOwnedProcessName(pStrct->Path);  // release PUNICODE_STRING
        pStrct->Path = NULL;
        delete pStrct;  // release PID_ENTRY
        ret = TRUE;
        iterator = next;
    }
    ASSERT(IsListEmpty(headerPids));
    return ret;
}

/****************** Public ******************/

BOOLEAN DriverData::RemoveProcess(ULONG ProcessId) {
    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    ULONGLONG gid = (ULONGLONG)PidToGids.get(ProcessId);
    if (gid == TERMINATED_PID_SENTINEL) {
        // Double-terminate (extremely rare): just remove the existing tombstone.
        PidToGids.deleteNode(ProcessId);
    } else if (gid) {
        // Normal path: process was tracked, clean it up.
        ret = RemoveProcessRecordAux(ProcessId, gid);
    } else {
        // Terminate fired before RecordNewProcess — plant a tombstone so that
        // if RecordNewProcess runs late for this PID it will detect the race
        // and skip insertion instead of leaving a permanent ghost entry.
        PidToGids.insertNode(ProcessId, (HANDLE)TERMINATED_PID_SENTINEL);
    }
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return ret;
}

_Use_decl_annotations_
ULONGLONG DriverData::RecordNewProcess(
    PUNICODE_STRING ProcessName,
    ULONG ProcessId,
    ULONG ParentPid) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);

    // Check for tombstone planted by RemoveProcess when terminate fired first.
    ULONGLONG existingEntry = (ULONGLONG)PidToGids.get(ProcessId);
    if (existingEntry == TERMINATED_PID_SENTINEL) {
        // The process already terminated before we recorded it.
        // Remove tombstone and bail — do NOT insert a ghost entry.
        PidToGids.deleteNode(ProcessId);
        KeReleaseSpinLock(&GIDSystemLock, oldIrql);
        FreeOwnedProcessName(ProcessName);
        return 0ULL;
    }

    if (existingEntry != 0) {
        if (!RemoveProcessRecordAux(ProcessId, existingEntry)) {
            PidToGids.deleteNode(ProcessId);
        }
    }

    ULONGLONG gid = (ULONGLONG)PidToGids.get(ParentPid);
    if (gid == TERMINATED_PID_SENTINEL) {
        gid = 0;
    }

    PGID_ENTRY gidRecord = NULL;
    if (gid) {
        gidRecord = (PGID_ENTRY)GidToPids.get(gid);
        if (gidRecord == NULL) {
            gid = 0;
        }
    }

    PPID_ENTRY pStrct = new PID_ENTRY;
    if (pStrct == NULL) {
        KeReleaseSpinLock(&GIDSystemLock, oldIrql);
        FreeOwnedProcessName(ProcessName);
        return 0ULL;
    }

    pStrct->Pid = ProcessId;
    pStrct->Path = ProcessName;
    pStrct->IsAcgEnabled = FALSE;
    if (gid) {  // there is Gid — child inherits parent's GID
        PidToGids.insertNode(ProcessId, (HANDLE)gid);
        InsertHeadList(&(gidRecord->HeadListPids), &(pStrct->entry));
        gidRecord->pidsSize++;
    } else {
        // Parent not tracked — assign a fresh GID for this process
        gid = ++GidCounter;
        PGID_ENTRY newGidRecord = new GID_ENTRY(gid);
        if (newGidRecord == NULL) {
            KeReleaseSpinLock(&GIDSystemLock, oldIrql);
            pStrct->Path = NULL;
            delete pStrct;
            FreeOwnedProcessName(ProcessName);
            return 0ULL;
        }

        InsertHeadList(&(newGidRecord->HeadListPids), &(pStrct->entry));
        InsertTailList(&GidsList, &(newGidRecord->GidListEntry));
        GidToPids.insertNode(gid, newGidRecord);
        PidToGids.insertNode(ProcessId, (HANDLE)gid);
        newGidRecord->pidsSize++;
        gidsSize++;
    }
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return gid;  // return the assigned GID so callers can populate IRP_ENTRY.Gid
}

BOOLEAN DriverData::RemoveGid(ULONGLONG gid) {
    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (gidRecord) {  // there is Gid list
        RemoveGidRecordAux(gidRecord);  //clear process list
        GidToPids.deleteNode(gid);  // remove the gidRecord from GidToPids
        RemoveEntryList(
            &(gidRecord->GidListEntry));  // unlink from list of gids
        gidsSize--;
        delete gidRecord;
        ret = TRUE;
    }

    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return ret;
}

ULONGLONG DriverData::GetGidSize(ULONGLONG gid, PBOOLEAN found) {
    ASSERT(found != nullptr);
    *found = FALSE;
    ULONGLONG ret = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    PGID_ENTRY GidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (GidRecord != nullptr) {  // there is such Gid
        *found = TRUE;
        ret = GidRecord->pidsSize;
    }
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return ret;
}

BOOLEAN DriverData::GetGidPids(
    ULONGLONG gid,
    PULONG buffer,
    ULONGLONG bufferSize,
    PULONGLONG returnedLength) {
    ASSERT(buffer != nullptr);
    ASSERT(returnedLength != nullptr);
    *returnedLength = 0;
    if (bufferSize == 0)
        return FALSE;
    ULONGLONG pidsSize = 0;
    ULONGLONG pidsIter = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    PGID_ENTRY GidRecord = (PGID_ENTRY)GidToPids.get(gid);
    if (GidRecord != nullptr) {  // there is such Gid
        pidsSize = GidRecord->pidsSize;
        PLIST_ENTRY PidsListHeader = &(GidRecord->HeadListPids);
        PLIST_ENTRY iterator = PidsListHeader->Flink;
        while (iterator != PidsListHeader && pidsIter < bufferSize) {
            PPID_ENTRY pStrct =
                (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
            ASSERT(pStrct != nullptr);
            if (pStrct != nullptr) {
                buffer[pidsIter++] = pStrct->Pid;
                *returnedLength += 1;
            }
            iterator = iterator->Flink;
        }
    }
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    if (GidRecord == nullptr) {
        return FALSE;
    }
    if (pidsSize == pidsIter) {
        return TRUE;
    }
    return FALSE;
}

// if found return true on found else return false
ULONGLONG DriverData::GetProcessGid(ULONG ProcessId, PBOOLEAN found) {
    BOOLEAN localFound = FALSE;
    if (found == nullptr) {
        found = &localFound;
    }

    *found = FALSE;
    ULONGLONG ret = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    ret = (ULONGLONG)PidToGids.get(ProcessId);
    if (ret == TERMINATED_PID_SENTINEL) {
        ret = 0;
    } else if (ret) {
        *found = TRUE;
    }
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    //
#if IS_DEBUG_IRP
DbgPrint("Gid: %d %d\n", ret, *found);
#endif

    return ret;
}

BOOLEAN DriverData::CopyProcessPathByPid(
    _In_ ULONG ProcessId,
    _Out_writes_z_(OutCch) PWCHAR OutBuffer,
    _In_ SIZE_T OutCch)
{
    BOOLEAN found = FALSE;
    KIRQL oldIrql;

    if (OutBuffer == NULL || OutCch == 0)
    {
        return FALSE;
    }

    OutBuffer[0] = L'\0';

    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);

    ULONGLONG gid = (ULONGLONG)PidToGids.get(ProcessId);
    if (gid != 0 && gid != TERMINATED_PID_SENTINEL)
    {
        PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
        if (gidRecord != nullptr)
        {
            PLIST_ENTRY header = &(gidRecord->HeadListPids);
            PLIST_ENTRY iterator = header->Flink;
            while (iterator != header)
            {
                PPID_ENTRY pStrct =
                    (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
                if (pStrct != nullptr &&
                    pStrct->Pid == ProcessId &&
                    pStrct->Path != nullptr &&
                    pStrct->Path->Buffer != nullptr &&
                    pStrct->Path->Length > 0)
                {
                    SIZE_T charsToCopy = pStrct->Path->Length / sizeof(WCHAR);
                    if (charsToCopy >= OutCch)
                    {
                        charsToCopy = OutCch - 1;
                    }

                    if (charsToCopy > 0)
                    {
                        RtlCopyMemory(OutBuffer,
                                      pStrct->Path->Buffer,
                                      charsToCopy * sizeof(WCHAR));
                    }
                    OutBuffer[charsToCopy] = L'\0';
                    found = TRUE;
                    break;
                }

                iterator = iterator->Flink;
            }
        }
    }

    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return found;
}

VOID DriverData::SetProcessIsAcgEnabled(ULONG ProcessId, BOOLEAN IsAcgEnabled)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);

    ULONGLONG gid = (ULONGLONG)PidToGids.get(ProcessId);
    if (gid != 0 && gid != TERMINATED_PID_SENTINEL)
    {
        PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
        if (gidRecord != nullptr)
        {
            PLIST_ENTRY header = &(gidRecord->HeadListPids);
            PLIST_ENTRY iterator = header->Flink;
            while (iterator != header)
            {
                PPID_ENTRY pStrct =
                    (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
                if (pStrct->Pid == ProcessId)
                {
                    pStrct->IsAcgEnabled = IsAcgEnabled;
                    break;
                }
                iterator = iterator->Flink;
            }
        }
    }

    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
}

BOOLEAN DriverData::GetProcessIsAcgEnabled(ULONG ProcessId)
{
    BOOLEAN isAcgEnabled = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);

    ULONGLONG gid = (ULONGLONG)PidToGids.get(ProcessId);
    if (gid != 0 && gid != TERMINATED_PID_SENTINEL)
    {
        PGID_ENTRY gidRecord = (PGID_ENTRY)GidToPids.get(gid);
        if (gidRecord != nullptr)
        {
            PLIST_ENTRY header = &(gidRecord->HeadListPids);
            PLIST_ENTRY iterator = header->Flink;
            while (iterator != header)
            {
                PPID_ENTRY pStrct =
                    (PPID_ENTRY)CONTAINING_RECORD(iterator, PID_ENTRY, entry);
                if (pStrct->Pid == ProcessId)
                {
                    isAcgEnabled = pStrct->IsAcgEnabled;
                    break;
                }
                iterator = iterator->Flink;
            }
        }
    }

    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return isAcgEnabled;
}

//clear all data related to Gid system
VOID DriverData::ClearGidsPids() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    PLIST_ENTRY headGids = &GidsList;
    PLIST_ENTRY iterator = headGids->Flink;
    while (iterator != headGids) {  // clear list
        PGID_ENTRY pStrct =
            (PGID_ENTRY)CONTAINING_RECORD(iterator, GID_ENTRY, GidListEntry);
        PLIST_ENTRY next = iterator->Flink;
        RemoveGidRecordAux(
            pStrct);  // clear process list and processes from PidToGids
        GidToPids.deleteNode(pStrct->gid);  // remove gid from GidToPids
        gidsSize--;
        delete pStrct;  // release GID_ENTRY
        iterator = next;
    }
    //ASSERT(headGids->Flink == headGids);
    GidCounter = 0;
    PidToGids.clear(NULL);
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
}

ULONGLONG DriverData::GidsSize() {
    ULONGLONG ret = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&GIDSystemLock, &oldIrql);
    ret = gidsSize;
    KeReleaseSpinLock(&GIDSystemLock, oldIrql);
    return ret;
}

//#######################################################################################
//# Irp handling
//#######################################################################################

VOID DriverData::ClearIrps() {
    KIRQL oldIrql;
    LIST_ENTRY pendingIrps;
    InitializeListHead(&pendingIrps);

    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    while (!IsListEmpty(&irpOps)) {
        PLIST_ENTRY entry = RemoveHeadList(&irpOps);
        InsertTailList(&pendingIrps, entry);
    }
    irpOpsSize = 0;
    KeReleaseSpinLock(&irpOpsLock, oldIrql);

    while (!IsListEmpty(&pendingIrps)) {
        PLIST_ENTRY pEntryIrps = RemoveHeadList(&pendingIrps);
        PIRP_ENTRY pStrct =
            (PIRP_ENTRY)CONTAINING_RECORD(pEntryIrps, IRP_ENTRY, entry);
        delete pStrct;
    }
}

ULONG DriverData::IrpSize() {
    ULONG ret = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    ret = irpOpsSize;
    KeReleaseSpinLock(&irpOpsLock, oldIrql);
    return ret;
}

BOOLEAN DriverData::AddIrpMessage(PIRP_ENTRY newEntry) {
    KIRQL oldIrql;
    LIST_ENTRY droppedIrps;

    if (newEntry == nullptr) {
        return FALSE;
    }

    InitializeListHead(&droppedIrps);

    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    while (irpOpsSize >= MAX_PENDING_IRP_MESSAGES && !IsListEmpty(&irpOps)) {
        PLIST_ENTRY entry = RemoveHeadList(&irpOps);
        irpOpsSize--;
        InsertTailList(&droppedIrps, entry);
    }

    irpOpsSize++;
    InsertTailList(&irpOps, &newEntry->entry);
    KeReleaseSpinLock(&irpOpsLock, oldIrql);

    while (!IsListEmpty(&droppedIrps)) {
        PLIST_ENTRY entry = RemoveHeadList(&droppedIrps);
        PIRP_ENTRY dropped =
            (PIRP_ENTRY)CONTAINING_RECORD(entry, IRP_ENTRY, entry);
        delete dropped;
    }

    return TRUE;
}

BOOLEAN DriverData::RemIrpMessage(PIRP_ENTRY newEntry) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    RemoveEntryList(&newEntry->entry);
    irpOpsSize--;

    KeReleaseSpinLock(&irpOpsLock, oldIrql);
    return TRUE;
}

PIRP_ENTRY DriverData::GetFirstIrpMessage() {
    PLIST_ENTRY ret;
    KIRQL oldIrql;
    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    if (IsListEmpty(&irpOps)) {
        KeReleaseSpinLock(&irpOpsLock, oldIrql);
        return NULL;
    }

    ret = RemoveHeadList(&irpOps);
    irpOpsSize--;
    KeReleaseSpinLock(&irpOpsLock, oldIrql);
    return (PIRP_ENTRY)CONTAINING_RECORD(ret, IRP_ENTRY, entry);
}

VOID DriverData::DriverGetIrps(
    PVOID Buffer,
    ULONG BufferSize,
    PULONG ReturnOutputBufferLength) {
    PCHAR OutputBuffer = (PCHAR)Buffer;
    ASSERT(OutputBuffer != nullptr);
    ASSERT(ReturnOutputBufferLength != nullptr);

    ULONG initialOutputSize = sizeof(RWD_REPLY_IRPS);
    RWD_REPLY_IRPS outHeader;

    if (*ReturnOutputBufferLength >= sizeof(RWD_REPLY_IRPS) && *ReturnOutputBufferLength <= BufferSize)
    {
        initialOutputSize = *ReturnOutputBufferLength;
        RtlCopyMemory(&outHeader, OutputBuffer, sizeof(RWD_REPLY_IRPS));

        if (outHeader.dataSize < sizeof(RWD_REPLY_IRPS) || outHeader.dataSize > BufferSize)
        {
            outHeader = RWD_REPLY_IRPS();
            initialOutputSize = sizeof(RWD_REPLY_IRPS);
        }
    }
    else
    {
        *ReturnOutputBufferLength = sizeof(RWD_REPLY_IRPS);
    }

    LIST_ENTRY tempIrpList;
    InitializeListHead(&tempIrpList);

    KIRQL oldIrql;
    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    // Move all IRPs from irpOps to tempIrpList
    while (!IsListEmpty(&irpOps)) {
        PLIST_ENTRY entry = RemoveHeadList(&irpOps);
        InsertTailList(&tempIrpList, entry);
    }
    // Update irpOpsSize after moving
    irpOpsSize = 0;
    KeReleaseSpinLock(&irpOpsLock, oldIrql);

    *ReturnOutputBufferLength = initialOutputSize;
    PCHAR CurrentBuffer = OutputBuffer + initialOutputSize;
    ULONG BufferSizeRemain = (BufferSize > initialOutputSize) ? (BufferSize - initialOutputSize) : 0;

    // Process the temporary list without holding the spinlock
    while (!IsListEmpty(&tempIrpList)) {
        PLIST_ENTRY irpEntryList = RemoveHeadList(&tempIrpList);
        PIRP_ENTRY irp =
            (PIRP_ENTRY)CONTAINING_RECORD(irpEntryList, IRP_ENTRY, entry);
        
        PDRIVER_MESSAGE irpMsg = &(irp->data);
        USHORT nameBufferSize = irp->filePath.Length;
        if (nameBufferSize > MAX_FILE_NAME_SIZE) {
            nameBufferSize = MAX_FILE_NAME_SIZE;
        }

        USHORT alignedNameBufferSize = (nameBufferSize + 7) & ~7;
        ULONG requiredSize = sizeof(DRIVER_MESSAGE) + alignedNameBufferSize;

        if (requiredSize > BufferSize) {
#if IS_DEBUG_IRP
DbgPrint("!!! Driver: Dropping message larger than output buffer. Required: %lu, Buffer: %lu\n", requiredSize, BufferSize);
#endif

            delete irp;
            continue;
        }

        if (requiredSize > BufferSizeRemain) {
            
#if IS_DEBUG_IRP
DbgPrint("!!! Driver: Output buffer too small for message. Required: %lu, Remaining: %lu\n", requiredSize, BufferSizeRemain);
#endif

            // Not enough space, put it back to the temp list and break
            InsertHeadList(&tempIrpList, irpEntryList);
            break;
        }

        // Prepare the message for user-mode.
        // The file path will follow immediately after the DRIVER_MESSAGE structure.
        // We set the buffer pointer to null to avoid leaking a kernel address.
        // The user-mode application must know to look for the string data after the struct.
        PWCHAR originalPathBuffer = irp->filePath.Buffer;
        irpMsg->filePath.Buffer = nullptr;
        irpMsg->filePath.Length = nameBufferSize;
        irpMsg->filePath.MaximumLength = nameBufferSize;
        irpMsg->next = nullptr;

        // Copy the DRIVER_MESSAGE structure into the output buffer.
        RtlCopyMemory(CurrentBuffer, irpMsg, sizeof(DRIVER_MESSAGE));
        
        // Copy the actual file path string right after the structure.
        if (nameBufferSize > 0) {
            RtlCopyMemory(CurrentBuffer + sizeof(DRIVER_MESSAGE), originalPathBuffer, nameBufferSize);
        }
        
        CurrentBuffer += requiredSize;
        BufferSizeRemain -= requiredSize;

        outHeader.addSize(requiredSize);
        *ReturnOutputBufferLength += requiredSize;
        outHeader.addOp();
        
        delete irp;
    }

    // Put back any remaining IRPs in the temp list to the main list
    if (!IsListEmpty(&tempIrpList)) {
        LIST_ENTRY droppedIrps;
        InitializeListHead(&droppedIrps);

        KeAcquireSpinLock(&irpOpsLock, &oldIrql);
        while (!IsListEmpty(&tempIrpList)) {
            PLIST_ENTRY entry = RemoveHeadList(&tempIrpList);
            if (irpOpsSize < MAX_PENDING_IRP_MESSAGES) {
                InsertTailList(&irpOps, entry);
                irpOpsSize++;
            } else {
                InsertTailList(&droppedIrps, entry);
            }
        }
        KeReleaseSpinLock(&irpOpsLock, oldIrql);

        while (!IsListEmpty(&droppedIrps)) {
            PLIST_ENTRY entry = RemoveHeadList(&droppedIrps);
            PIRP_ENTRY dropped =
                (PIRP_ENTRY)CONTAINING_RECORD(entry, IRP_ENTRY, entry);
            delete dropped;
        }
    }

    if (outHeader.numOps()) {
        outHeader.data = (PDRIVER_MESSAGE)(OutputBuffer + sizeof(RWD_REPLY_IRPS));
    }

    RtlCopyMemory(OutputBuffer, &outHeader, sizeof(RWD_REPLY_IRPS));
}

LIST_ENTRY DriverData::GetAllEntries() {
    LIST_ENTRY newList;
    KIRQL oldIrql;
    KeAcquireSpinLock(&irpOpsLock, &oldIrql);
    irpOpsSize = 0;
    newList = irpOps;
    InitializeListHead(&irpOps);

    KeReleaseSpinLock(&irpOpsLock, oldIrql);
    return newList;
}

//#######################################################################################
//# Directory handling
//#######################################################################################

BOOLEAN DriverData::AddDirectoryEntry(PDIRECTORY_ENTRY newEntry) {
    BOOLEAN ret = FALSE;
    BOOLEAN foundMatch = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql);

    PLIST_ENTRY pEntry = rootDirectories.Flink;
    while (pEntry != &rootDirectories) {
        PDIRECTORY_ENTRY pStrct;
        //
        // Do some processing.
        //
        pStrct =
            (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);

        if (!wcsncmp(
                newEntry->path,
                pStrct->path,
                wcsnlen_s(newEntry->path, MAX_FILE_NAME_LENGTH))) {
            foundMatch = TRUE;
            break;
        }
        //
        //Move to next Entry in list.
        //
        pEntry = pEntry->Flink;
    }
    if (foundMatch == FALSE) {
        InsertHeadList(&rootDirectories, &newEntry->entry);
        directoryRootsSize++;
        ret = TRUE;
    }
    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
    return ret;
}

PDIRECTORY_ENTRY DriverData::RemDirectoryEntry(LPCWSTR directory) {
    PDIRECTORY_ENTRY ret = NULL;
    KIRQL oldIrql;
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql);

    PLIST_ENTRY pEntry = rootDirectories.Flink;

    while (pEntry != &rootDirectories) {
        PDIRECTORY_ENTRY pStrct;
        //
        // Do some processing.
        //
        pStrct =
            (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);

        if (!wcsncmp(
                directory,
                pStrct->path,
                wcsnlen_s(directory, MAX_FILE_NAME_LENGTH))) {
            if (RemoveEntryList(pEntry)) {
                ret = pStrct;
                directoryRootsSize--;
                break;
            }
        }
        //
        //Move to next Entry in list.
        //
        pEntry = pEntry->Flink;
    }
    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
    return ret;
}

/**
	IsContainingDirectory returns true if one of the directory entries in our LIST_ENTRY of PDIRECTORY_ENTRY is in the path passed as param
*/
BOOLEAN DriverData::IsContainingDirectory(CONST PUNICODE_STRING path) {
    if (path == NULL || path->Buffer == NULL)
        return FALSE;
    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql);
    if (directoryRootsSize != 0) {
        PLIST_ENTRY pEntry = rootDirectories.Flink;
        while (pEntry != &rootDirectories) {
            PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)
                CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);
            
            // Fix: path->Length is in bytes, we need character count
            ULONG pathChars = path->Length / sizeof(WCHAR);
            BOOLEAN match = TRUE;

            for (ULONG i = 0; i < MAX_FILE_NAME_LENGTH; i++) {
                // If we reached the end of the protected root path, it's a match
                if (pStrct->path[i] == L'\0') {
                    ret = TRUE;
                    break;
                }

                // If we reached the end of the input path but not the root, no match
                if (i >= pathChars) {
                    match = FALSE;
                    break;
                }

                // Case-insensitive comparison (recommended for Windows paths)
                if (RtlUpcaseUnicodeChar(pStrct->path[i]) != RtlUpcaseUnicodeChar(path->Buffer[i])) {
                    match = FALSE;
                    break;
                }
            }

            if (ret || match) {
                // Double check if it was a true prefix match or just a partial name match
                // e.g., C:\Temp matching C:\Temp\file.txt is good, but C:\Temp matching C:\Template is bad
                if (ret) {
                    // It matched the whole pStrct->path. 
                    // Now check if the next char in 'path' is a backslash or if 'path' ended.
                    ULONG pStrctLen = (ULONG)wcsnlen(pStrct->path, MAX_FILE_NAME_LENGTH);
                    if (pathChars > pStrctLen && path->Buffer[pStrctLen] != L'\\') {
                        ret = FALSE; // false positive (e.g. C:\Temp vs C:\Template)
                    }
                }
            }

            if (ret)
                break;
            
            pEntry = pEntry->Flink;
        }
    }
    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
    return ret;
}

VOID DriverData::ClearDirectories() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&directoriesSpinLock, &oldIrql);
    PLIST_ENTRY pEntryDirs = rootDirectories.Flink;
    while (pEntryDirs != &rootDirectories) {
        LIST_ENTRY temp = *pEntryDirs;
        PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)
            CONTAINING_RECORD(pEntryDirs, DIRECTORY_ENTRY, entry);
        delete pStrct;
        //next
        pEntryDirs = temp.Flink;
    }
    directoryRootsSize = 0;
    InitializeListHead(&rootDirectories);
    KeReleaseSpinLock(&directoriesSpinLock, oldIrql);
}

//#######################################################################################
//# Blocked Path handling
//#######################################################################################

BOOLEAN DriverData::AddBlockedPath(PDIRECTORY_ENTRY newEntry) {
    BOOLEAN ret = FALSE;
    BOOLEAN foundMatch = FALSE;
    KIRQL oldIrql;

    // Canonicalize to root-relative form ("\foo\bar") so DOS ("C:\...")
    // and NT ("\Device\HarddiskVolumeN\...") spellings match at check time.
    {
        WCHAR szNorm[MAX_FILE_NAME_LENGTH] = { 0 };
        UNICODE_STRING usNorm;
        UNICODE_STRING usSrc;
        RtlInitUnicodeString(&usSrc, newEntry->path);
        if (OwlyNormalizePathForMatch(&usSrc, szNorm, &usNorm))
        {
            RtlCopyMemory(newEntry->path, szNorm, sizeof(szNorm));
        }
    }

    KeAcquireSpinLock(&blockedPathsLock, &oldIrql);

    PLIST_ENTRY pEntry = blockedPaths.Flink;
    while (pEntry != &blockedPaths) {
        PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);

        if (!wcsncmp(newEntry->path, pStrct->path, MAX_FILE_NAME_LENGTH)) {
            foundMatch = TRUE;
            break;
        }
        pEntry = pEntry->Flink;
    }
    if (foundMatch == FALSE) {
        InsertHeadList(&blockedPaths, &newEntry->entry);
        blockedPathsSize++;
        ret = TRUE;
        
#if IS_DEBUG_IRP
DbgPrint("!!! FSfilter: Path added to KERNEL BLOCK LIST: %ws\n", newEntry->path);
#endif

    }
    KeReleaseSpinLock(&blockedPathsLock, oldIrql);
    return ret;
}

BOOLEAN DriverData::IsPathBlocked(CONST PUNICODE_STRING path) {
    if (path == NULL || path->Buffer == NULL)
        return FALSE;
    BOOLEAN ret = FALSE;
    KIRQL oldIrql;
    
    KeAcquireSpinLock(&blockedPathsLock, &oldIrql);
    if (blockedPathsSize != 0) {
        PLIST_ENTRY pEntry = blockedPaths.Flink;
        while (pEntry != &blockedPaths) {
            PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)CONTAINING_RECORD(pEntry, DIRECTORY_ENTRY, entry);
            
            ULONG pathChars = path->Length / sizeof(WCHAR);
            BOOLEAN match = TRUE;

            for (ULONG i = 0; i < MAX_FILE_NAME_LENGTH; i++) {
                if (pStrct->path[i] == L'\0') {
                    ret = TRUE;
                    break;
                }
                if (i >= pathChars) {
                    match = FALSE;
                    break;
                }
                if (RtlUpcaseUnicodeChar(pStrct->path[i]) != RtlUpcaseUnicodeChar(path->Buffer[i])) {
                    match = FALSE;
                    break;
                }
            }

            if (ret || match) {
                ULONG pStrctLen = (ULONG)wcsnlen(pStrct->path, MAX_FILE_NAME_LENGTH);
                if (pathChars > pStrctLen && path->Buffer[pStrctLen] != L'\\') {
                    ret = FALSE; 
                }
            }

            if (ret) break;
            pEntry = pEntry->Flink;
        }
    }
    KeReleaseSpinLock(&blockedPathsLock, oldIrql);
    return ret;
}

VOID DriverData::ClearBlockedPaths() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&blockedPathsLock, &oldIrql);
    PLIST_ENTRY pEntryPaths = blockedPaths.Flink;
    while (pEntryPaths != &blockedPaths) {
        LIST_ENTRY temp = *pEntryPaths;
        PDIRECTORY_ENTRY pStrct = (PDIRECTORY_ENTRY)
            CONTAINING_RECORD(pEntryPaths, DIRECTORY_ENTRY, entry);
        delete pStrct;
        pEntryPaths = temp.Flink;
    }
    blockedPathsSize = 0;
    InitializeListHead(&blockedPaths);
    KeReleaseSpinLock(&blockedPathsLock, oldIrql);
}

//#######################################################################################
//# Registry handling
//#######################################################################################

ULONGLONG DriverData::RegistryNameHash(PCUNICODE_STRING keyPath, PCUNICODE_STRING valueName) {
    // FNV-1a over the upper-cased characters; 0xFFFF (not a name character)
    // separates the key from the value name.
    ULONGLONG h = 14695981039346656037ULL;
    auto mix = [&h](PCUNICODE_STRING s) {
        if (s == nullptr || s->Buffer == nullptr)
            return;
        for (USHORT i = 0; i < s->Length / sizeof(WCHAR); ++i) {
            h ^= (ULONGLONG)RtlUpcaseUnicodeChar(s->Buffer[i]);
            h *= 1099511628211ULL;
        }
    };
    mix(keyPath);
    h ^= 0xFFFFULL;
    h *= 1099511628211ULL;
    mix(valueName);
    return h;
}

PREGISTRY_BACKUP_ENTRY DriverData::AllocRegistryBackup(
    PCUNICODE_STRING keyPath, PCUNICODE_STRING valueName, ULONG dataSize) {
    if (keyPath == nullptr || keyPath->Buffer == nullptr || keyPath->Length == 0)
        return nullptr;
    const SIZE_T keyBytes = keyPath->Length;
    const SIZE_T valueBytes = (valueName != nullptr && valueName->Buffer != nullptr) ? valueName->Length : 0;
    // MaximumLength (USHORT) holds the length plus the NUL.
    if (keyBytes > MAXUSHORT - sizeof(WCHAR) || valueBytes > MAXUSHORT - sizeof(WCHAR))
        return nullptr;
    const SIZE_T total = sizeof(REGISTRY_BACKUP_ENTRY) + keyBytes + sizeof(WCHAR) + valueBytes + sizeof(WCHAR) + dataSize;

    auto entry = (PREGISTRY_BACKUP_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, OWLY_POOL_TAG_REGISTRY_BACKUP);
    if (entry == nullptr)
        return nullptr;

    PUCHAR p = (PUCHAR)(entry + 1);
    entry->KeyPath.Buffer = (PWCH)p;
    entry->KeyPath.Length = (USHORT)keyBytes;
    entry->KeyPath.MaximumLength = (USHORT)(keyBytes + sizeof(WCHAR));
    RtlCopyMemory(p, keyPath->Buffer, keyBytes);
    p += keyBytes + sizeof(WCHAR);  // zeroed by ExAllocatePool2: NUL-terminated

    entry->ValueName.Buffer = (PWCH)p;
    entry->ValueName.Length = (USHORT)valueBytes;
    entry->ValueName.MaximumLength = (USHORT)(valueBytes + sizeof(WCHAR));
    if (valueBytes)
        RtlCopyMemory(p, valueName->Buffer, valueBytes);
    p += valueBytes + sizeof(WCHAR);

    entry->Data = p;
    entry->DataSize = dataSize;
    entry->NameHash = RegistryNameHash(keyPath, valueName);
    return entry;
}

VOID DriverData::FreeRegistryBackup(PREGISTRY_BACKUP_ENTRY entry) {
    if (entry != nullptr)
        ExFreePoolWithTag(entry, OWLY_POOL_TAG_REGISTRY_BACKUP);
}

BOOLEAN DriverData::HasRegistryBackup(ULONG processId, ULONGLONG nameHash) {
    BOOLEAN found = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&registryBackupsLock, &oldIrql);
    for (PLIST_ENTRY e = registryBackups.Flink; e != &registryBackups; e = e->Flink) {
        auto b = CONTAINING_RECORD(e, REGISTRY_BACKUP_ENTRY, list);
        if (b->Pid == processId && b->NameHash == nameHash) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&registryBackupsLock, oldIrql);
    return found;
}

VOID DriverData::AddRegistryBackup(PREGISTRY_BACKUP_ENTRY newEntry) {
    if (newEntry == nullptr)
        return;
    PREGISTRY_BACKUP_ENTRY dropped = nullptr;
    KIRQL oldIrql;
    KeAcquireSpinLock(&registryBackupsLock, &oldIrql);
    // Only the value as it was before the process first touched it matters:
    // a later change by the same process is not a new original.
    for (PLIST_ENTRY e = registryBackups.Flink; e != &registryBackups; e = e->Flink) {
        auto b = CONTAINING_RECORD(e, REGISTRY_BACKUP_ENTRY, list);
        if (b->Pid == newEntry->Pid && b->NameHash == newEntry->NameHash) {
            dropped = newEntry;
            newEntry = nullptr;
            break;
        }
    }
    if (newEntry != nullptr) {
        // Full: drop the oldest. (Dropping the new one stopped every later backup.)
        if (registryBackupsSize >= MAX_REGISTRY_BACKUPS && !IsListEmpty(&registryBackups)) {
            dropped = CONTAINING_RECORD(RemoveHeadList(&registryBackups), REGISTRY_BACKUP_ENTRY, list);
            registryBackupsSize--;
        }
        InsertTailList(&registryBackups, &newEntry->list);
        registryBackupsSize++;
    }
    KeReleaseSpinLock(&registryBackupsLock, oldIrql);
    FreeRegistryBackup(dropped);
}

VOID DriverData::ClearRegistryBackups() {
    LIST_ENTRY toFree;
    InitializeListHead(&toFree);
    KIRQL oldIrql;
    KeAcquireSpinLock(&registryBackupsLock, &oldIrql);
    while (!IsListEmpty(&registryBackups))
        InsertTailList(&toFree, RemoveHeadList(&registryBackups));
    registryBackupsSize = 0;
    KeReleaseSpinLock(&registryBackupsLock, oldIrql);
    while (!IsListEmpty(&toFree))
        FreeRegistryBackup(CONTAINING_RECORD(RemoveHeadList(&toFree), REGISTRY_BACKUP_ENTRY, list));
}

VOID DriverData::RecordProcessCreator(ULONG processId, ULONG creatorPid) {
    if (processId == 0)
        return;
    KIRQL oldIrql;
    KeAcquireSpinLock(&lineageLock, &oldIrql);
    const ULONG slot = lineageNext;
    lineageNext = (lineageNext + 1) % LINEAGE_CAPACITY;
    // Evict the PID recorded in this slot, unless it was recorded again since
    // (then its value names a newer slot).
    const ULONG evicted = lineageRing[slot];
    if (evicted != 0) {
        const ULONGLONG v = (ULONGLONG)PidToCreator.get(evicted);
        if ((ULONG)(v >> 32) == slot + 1)
            PidToCreator.deleteNode(evicted);
    }
    lineageRing[slot] = processId;
    PidToCreator.insertNode(processId, (HANDLE)(((ULONGLONG)(slot + 1) << 32) | creatorPid));
    KeReleaseSpinLock(&lineageLock, oldIrql);
}

ULONG DriverData::GetProcessAncestors(ULONG processId, PULONG ancestors, ULONG maxCount) {
    ULONG n = 0;
    KIRQL oldIrql;
    KeAcquireSpinLock(&lineageLock, &oldIrql);
    ULONG cur = processId;
    while (n < maxCount) {
        const ULONGLONG v = (ULONGLONG)PidToCreator.get(cur);
        if (v == 0)
            break;
        const ULONG creator = (ULONG)(v & 0xFFFFFFFFULL);
        if (creator == 0 || creator == 4 || creator == cur)
            break;
        // A loop (PID reuse) ends the chain.
        BOOLEAN seen = (creator == processId);
        for (ULONG i = 0; i < n && !seen; ++i)
            seen = (ancestors[i] == creator);
        if (seen)
            break;
        ancestors[n++] = creator;
        cur = creator;
    }
    KeReleaseSpinLock(&lineageLock, oldIrql);
    return n;
}

VOID DriverData::ClearProcessLineage() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&lineageLock, &oldIrql);
    PidToCreator.clear(NULL);
    RtlZeroMemory(lineageRing, sizeof(lineageRing));
    lineageNext = 0;
    KeReleaseSpinLock(&lineageLock, oldIrql);
}

// Writes back one deleted key: creates it again and sets the values it had
// (REGISTRY_BACKUP_ENTRY::IsKeyDelete, records written by regmon.cpp).
static NTSTATUS RestoreDeletedKey(PREGISTRY_BACKUP_ENTRY backup) {
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &backup->KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    HANDLE hKey = NULL;
    ULONG disposition = 0;
    NTSTATUS status = ZwCreateKey(&hKey, KEY_SET_VALUE, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, &disposition);
    if (!NT_SUCCESS(status))
        return status;

    PUCHAR p = backup->Data;
    PUCHAR end = backup->Data + backup->DataSize;
    while ((SIZE_T)(end - p) >= sizeof(REGISTRY_KEY_VALUE_RECORD)) {
        REGISTRY_KEY_VALUE_RECORD rec;
        RtlCopyMemory(&rec, p, sizeof(rec));
        p += sizeof(rec);
        if ((SIZE_T)(end - p) < (SIZE_T)rec.NameBytes + rec.DataSize)
            break;
        UNICODE_STRING name;
        name.Buffer = (PWCH)p;
        name.Length = rec.NameBytes;
        name.MaximumLength = rec.NameBytes;
        ZwSetValueKey(hKey, &name, 0, rec.Type, p + rec.NameBytes, rec.DataSize);
        p += (SIZE_T)rec.NameBytes + rec.DataSize;
    }
    ZwClose(hKey);
    return status;
}

VOID DriverData::RevertRegistryChangesForGid(ULONGLONG gid) {
    // The processes of the gid: a PID-flagged gid is one process, else the GID table.
    ULONG pids[64];
    ULONGLONG pidCount = 0;
    ULONG single = 0;
    if (PidFromGid(gid, &single)) {
        pids[0] = single;
        pidCount = 1;
    } else {
        GetGidPids(gid, pids, RTL_NUMBER_OF(pids), &pidCount);
    }
    if (pidCount == 0)
        return;

    auto inGroup = [&](ULONG pid) -> BOOLEAN {
        for (ULONGLONG i = 0; i < pidCount; ++i)
            if (pids[i] == pid)
                return TRUE;
        return FALSE;
    };

    LIST_ENTRY toRevert;
    InitializeListHead(&toRevert);

    // A change belongs to the group when the process that made it, or any process
    // in its creator chain at that time, is in the group: the children (any depth)
    // of a killed ransomware process are reverted with it.
    KIRQL oldIrql;
    KeAcquireSpinLock(&registryBackupsLock, &oldIrql);
    PLIST_ENTRY current = registryBackups.Flink;
    while (current != &registryBackups) {
        PLIST_ENTRY next = current->Flink;
        auto backup = CONTAINING_RECORD(current, REGISTRY_BACKUP_ENTRY, list);
        BOOLEAN match = inGroup(backup->Pid);
        for (ULONG i = 0; i < backup->AncestorCount && !match; ++i)
            match = inGroup(backup->Ancestors[i]);
        if (match) {
            RemoveEntryList(current);
            registryBackupsSize--;
            InsertTailList(&toRevert, current);
        }
        current = next;
    }
    KeReleaseSpinLock(&registryBackupsLock, oldIrql);

    // Newest first: when the same value was changed twice, the oldest original is
    // written last and stays; a deleted key is created again before the keys under
    // it (RegDeleteTree deletes the children first, so they are older).
    while (!IsListEmpty(&toRevert)) {
        auto backup = CONTAINING_RECORD(RemoveTailList(&toRevert), REGISTRY_BACKUP_ENTRY, list);

        NTSTATUS status;
        if (backup->IsKeyDelete) {
            status = RestoreDeletedKey(backup);
        } else {
            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &backup->KeyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE hKey = NULL;
            status = ZwOpenKey(&hKey, KEY_SET_VALUE, &objAttr);
            if (NT_SUCCESS(status)) {
                if (backup->ValueExisted)
                    status = ZwSetValueKey(hKey, &backup->ValueName, 0, backup->Type, backup->Data, backup->DataSize);
                else
                    status = ZwDeleteValueKey(hKey, &backup->ValueName);  // created by the process
                ZwClose(hKey);
            }
        }
#if IS_DEBUG_IRP
        DbgPrint("!!! Registry revert pid %lu %wZ\\%wZ (%s): 0x%X\n", backup->Pid, &backup->KeyPath,
                 &backup->ValueName,
                 backup->IsKeyDelete ? "key" : (backup->ValueExisted ? "restore" : "delete"), status);
#endif
        UNREFERENCED_PARAMETER(status);
        FreeRegistryBackup(backup);
    }
}
