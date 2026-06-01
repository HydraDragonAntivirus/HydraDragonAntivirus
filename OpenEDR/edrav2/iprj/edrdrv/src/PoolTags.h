#pragma once

#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64 // Non paged pool NX
#endif

#ifndef POOL_FLAG_PAGED
#define POOL_FLAG_PAGED 0x0000000000000001UI64
#endif

#if !defined(NTDDI_WIN10_VB) || (NTDDI_VERSION < NTDDI_WIN10_VB)
static __forceinline PVOID OwlyAllocatePool2Compat(ULONGLONG Flags, SIZE_T NumberOfBytes, ULONG Tag)
{
    POOL_TYPE poolType = ((Flags & POOL_FLAG_PAGED) != 0) ? PagedPool : NonPagedPool;
    return ExAllocatePoolWithTag(poolType, NumberOfBytes, Tag);
}

#define ExAllocatePool2(Flags, NumberOfBytes, Tag) OwlyAllocatePool2Compat((Flags), (NumberOfBytes), (Tag))
#endif

// Pool tags are written in reverse order so WinDbg shows the readable name.
#define OWLY_POOL_TAG_IRP_ENTRY 'rIwO'        // OwIr
#define OWLY_POOL_TAG_PID_ENTRY 'iPwO'        // OwPi
#define OWLY_POOL_TAG_GID_ENTRY 'dGwO'        // OwGd
#define OWLY_POOL_TAG_DIRECTORY_ENTRY 'rDwO'  // OwDr
#define OWLY_POOL_TAG_REGISTRY_BACKUP 'bRwO'  // OwRb
#define OWLY_POOL_TAG_HASH_NODE 'tHwO'        // OwHt
#define OWLY_POOL_TAG_PROCESS_NAME 'nPwO'     // OwPn
#define OWLY_POOL_TAG_UNICODE_STRING 'sUwO'   // OwUs
#define OWLY_POOL_TAG_VOLUME_CACHE 'cVwO'     // OwVc
#define OWLY_POOL_TAG_QUARANTINE_PATH 'pQwO'  // OwQp
#define OWLY_POOL_TAG_GID_BUFFER 'bGwO'       // OwGb
#define OWLY_POOL_TAG_FILE_TEMP 'tFwO'        // OwFt
