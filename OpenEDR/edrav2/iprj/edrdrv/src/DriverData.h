#pragma once

#include <fltKernel.h>

#include "HashTable.h"
#include "KernelCommon.h"
#include "log.h"
#include "KernelString.h"

/* DriverData: shared class across driver, hold driver D.S. */
class DriverData {
    BOOLEAN FilterRun;  // true if filter currently runs
    PFLT_FILTER Filter;
    PDRIVER_OBJECT DriverObject;  // internal
    WCHAR systemRootPath
        [MAX_FILE_NAME_LENGTH];  // system root path, help analyze image files loaded
    ULONG
        pid;  // pid of the current connected user mode application, set by communication
    UNICODE_STRING quarantinePath; // Path to the quarantine directory

    ULONG irpOpsSize;  // number of irp ops waiting in entry_list
    LIST_ENTRY irpOps;  // list entry bdirectional list of irp ops
    KSPIN_LOCK irpOpsLock;  // lock for irp list ops

    ULONG directoryRootsSize;  // number of protected dirs in list
    LIST_ENTRY rootDirectories;  // list entry bdirectional of protected dirs
    KSPIN_LOCK directoriesSpinLock;  // lock for directory list

    ULONG blockedPathsSize;    // number of blocked paths
    LIST_ENTRY blockedPaths;   // list of blocked paths
    KSPIN_LOCK blockedPathsLock; // lock for blocked paths

    /* GID system data members */
    ULONGLONG
        GidCounter;  // interal counter for gid, every new application recieves a new gid
    HashMap GidToPids;  // mapping from gid to pids
    HashMap PidToGids;  // mapping from pid to gid
    ULONGLONG gidsSize;  // number of gids currently active
    LIST_ENTRY GidsList;  // list entry of gids, used to clear memory
    KSPIN_LOCK GIDSystemLock;

    /* Volume cache data members */
    HashMap VolumeToDosName;
    KSPIN_LOCK volumeCacheLock;

    /* Registry backup data members */
    ULONG registryBackupsSize;
    LIST_ENTRY registryBackups;
    KSPIN_LOCK registryBackupsLock;

    /* Process lineage: the creator of each recent process, kept after the
       process exits (the ransomware parent often exits before it is killed).
       PidToCreator value: creator PID | (ring slot + 1) << 32; the ring evicts
       the oldest PID once LINEAGE_CAPACITY processes were recorded. */
  public:
    static constexpr ULONG LINEAGE_CAPACITY = 8192;
  private:
    HashMap PidToCreator;
    ULONG lineageRing[LINEAGE_CAPACITY];
    ULONG lineageNext;
    KSPIN_LOCK lineageLock;

  private:
    // Helper to free a UNICODE_STRING and its buffer
    static VOID FreeCachedUnicodeString(PVOID str);
    // call assumes protected code - high IRQL
    BOOLEAN RemoveProcessRecordAux(ULONG ProcessId, ULONGLONG gid);

    // call assumes protected code - high IRQL
    BOOLEAN RemoveGidRecordAux(PGID_ENTRY gidRecord);

  public:
    // c'tor init D.S.
    explicit DriverData(PDRIVER_OBJECT DriverObject);

    ~DriverData();

    PWCHAR GetSystemRootPath() {
        return systemRootPath;
    }

    // sets the system root path, received from user mode application, we copy the systemRootPath sent on the message
    VOID setSystemRootPath(PWCHAR setsystemRootPath) {
        RtlZeroBytes(systemRootPath, MAX_FILE_NAME_SIZE);
        RtlCopyBytes(systemRootPath, setsystemRootPath, MAX_FILE_NAME_LENGTH);
        RtlCopyBytes(
            systemRootPath + wcsnlen(systemRootPath, MAX_FILE_NAME_LENGTH / 2),
            L"\\Windows",
            wcsnlen(L"\\Windows", MAX_FILE_NAME_LENGTH / 2));
        DbgPrint("Set system root path %ls\n", systemRootPath);
    }

    // Sets the path to the quarantine directory
    VOID SetQuarantinePath(PUNICODE_STRING path);

    // Checks if the given path is within the quarantine directory
    BOOLEAN IsPathInQuarantineDir(CONST PUNICODE_STRING path);

    // remove a process which ended from the GID system, function raise IRQL
    BOOLEAN RemoveProcess(ULONG ProcessId);

    // record a process which was created to the GID system, function raise IRQL
    // Returns the assigned GID on success, 0 on failure (e.g. process already terminated).
    _IRQL_raises_(DISPATCH_LEVEL) ULONGLONG RecordNewProcess(
        PUNICODE_STRING ProcessName,
        ULONG ProcessId,
        ULONG ParentPid);

    // removed a gid from the system, function raise IRQL
    BOOLEAN RemoveGid(ULONGLONG gid);

    // gets the number of processes in a gid, function raise IRQL
    ULONGLONG GetGidSize(ULONGLONG gid, PBOOLEAN found);

    // help function, recieves a buffer and returns an array of pids, returns true only if all pids are restored
    BOOLEAN GetGidPids(
        ULONGLONG gid,
        PULONG buffer,
        ULONGLONG bufferSize,
        PULONGLONG returnedLength);

    // if found return true on found else return false
    ULONGLONG GetProcessGid(ULONG ProcessId, PBOOLEAN found);

    // Copy the tracked process image path for a PID into a caller buffer.
    // Safe for ProcessProtection callbacks because it only reads DriverData state.
    BOOLEAN CopyProcessPathByPid(
        _In_ ULONG ProcessId,
        _Out_writes_z_(OutCch) PWCHAR OutBuffer,
        _In_ SIZE_T OutCch);

    // Sets the IsAcgEnabled flag for a tracked process
    VOID SetProcessIsAcgEnabled(ULONG ProcessId, BOOLEAN IsAcgEnabled);

    // Retrieves the IsAcgEnabled flag for a tracked process
    BOOLEAN GetProcessIsAcgEnabled(ULONG ProcessId);

    //clear all data related to Gid system
    VOID ClearGidsPids();

    ULONGLONG GidsSize();

    // The callers of the kill / revert messages (owlyshield_predict, HIPS in
    // libsysmon, the firewall) send `PID | 0x8000000000000000` as the gid: the
    // GID table is not filled for them. Returns the PID of such a gid.
    static BOOLEAN PidFromGid(ULONGLONG gid, PULONG processId) {
        if ((gid & GID_PID_FLAG) == 0)
            return FALSE;
        *processId = (ULONG)(gid & 0xFFFFFFFFULL);
        return *processId != 0;
    }
    static constexpr ULONGLONG GID_PID_FLAG = 0x8000000000000000ULL;

    /* Registry backups (regmon.cpp takes them, MESSAGE_REVERT_REGISTRY_CHANGES
       restores them). At most MAX_REGISTRY_BACKUPS, the oldest dropped first. */
    static constexpr ULONG MAX_REGISTRY_BACKUPS = 4096;
    // Case-insensitive hash of key path + value name (backup identity per PID).
    static ULONGLONG RegistryNameHash(PCUNICODE_STRING keyPath, PCUNICODE_STRING valueName);
    // One allocation for the entry and copies of the strings / data; nullptr on failure.
    static PREGISTRY_BACKUP_ENTRY AllocRegistryBackup(
        PCUNICODE_STRING keyPath, PCUNICODE_STRING valueName, ULONG dataSize);
    static VOID FreeRegistryBackup(PREGISTRY_BACKUP_ENTRY entry);
    // Whether this process's original value of this name is already kept.
    BOOLEAN HasRegistryBackup(ULONG processId, ULONGLONG nameHash);
    // Takes ownership of the entry (freed when it is a duplicate).
    VOID AddRegistryBackup(PREGISTRY_BACKUP_ENTRY newEntry);
    // Writes back the values and keys that the processes of this gid and every
    // process they started (any depth) changed, newest first.
    VOID RevertRegistryChangesForGid(ULONGLONG gid);
    VOID ClearRegistryBackups();

    // Process lineage (procmon create notify). The creator is the process that
    // really created it (CreatingThreadId), not the reported parent, which a
    // caller can spoof.
    VOID RecordProcessCreator(ULONG processId, ULONG creatorPid);
    // Creator chain of a process, nearest first; returns how many were written.
    ULONG GetProcessAncestors(ULONG processId, PULONG ancestors, ULONG maxCount);
    VOID ClearProcessLineage();

    BOOLEAN setFilterStart() {
        return (FilterRun = TRUE);
    }

    BOOLEAN setFilterStop() {
        return (FilterRun = FALSE);
    }

    BOOLEAN isFilterClosed() {
        return (FilterRun == FALSE);
    }

    PFLT_FILTER* getFilterAdd() {
        return &Filter;
    }
    PFLT_FILTER getFilter() {
        return Filter;
    }
    ULONG getPID() {
        return pid;
    }
    ULONG setPID(ULONG Pid) {
        pid = Pid;
        return Pid;
    }

    // clears all irps waiting to report, function raise IRQL
    VOID ClearIrps();

    ULONG IrpSize();

    BOOLEAN AddIrpMessage(PIRP_ENTRY newEntry);

    BOOLEAN RemIrpMessage(PIRP_ENTRY newEntry);

    PIRP_ENTRY GetFirstIrpMessage();

    // Takes Irps from the driverData and copy them to a buffer, also copies the file names on which the irp occured, function raise IRQL
    VOID DriverGetIrps(
        PVOID Buffer,
        ULONG BufferSize,
        PULONG ReturnOutputBufferLength);

    LIST_ENTRY GetAllEntries();

    BOOLEAN AddDirectoryEntry(PDIRECTORY_ENTRY newEntry);

    PDIRECTORY_ENTRY RemDirectoryEntry(LPCWSTR directory);

    /**
		IsContainingDirectory returns true if one of the directory entries in our LIST_ENTRY of PDIRECTORY_ENTRY is in the path passed as param
	*/
    BOOLEAN IsContainingDirectory(CONST PUNICODE_STRING path);

    VOID ClearDirectories();

    BOOLEAN AddBlockedPath(PDIRECTORY_ENTRY newEntry);

    BOOLEAN IsPathBlocked(CONST PUNICODE_STRING path);

    VOID ClearBlockedPaths();

    /* Volume Cache functions */
    VOID ClearVolumeCache();
    // Returns a POINTER TO A COPY of the DOS name. Caller is responsible for freeing it.
    NTSTATUS GetVolumeDosName(PFLT_VOLUME volume, PUNICODE_STRING outDosName);
    // Stores a copy of the DOS name for the given volume.
    NTSTATUS AddVolumeDosName(PFLT_VOLUME volume, PUNICODE_STRING dosName);

    VOID Clear() {
        // clear directories
        ClearDirectories();

        // clear blocked paths
        ClearBlockedPaths();

        // clear irps
        ClearIrps();

        // clear gid system
        ClearGidsPids();

        // clear registry backups
        ClearRegistryBackups();
        ClearProcessLineage();

        // Free quarantine path buffer if allocated
        if (quarantinePath.Buffer != NULL) {
            ExFreePoolWithTag(quarantinePath.Buffer, OWLY_POOL_TAG_QUARANTINE_PATH);
            quarantinePath.Buffer = NULL;
            quarantinePath.Length = 0;
            quarantinePath.MaximumLength = 0;
        }
    }
};

extern DriverData* driverData;

