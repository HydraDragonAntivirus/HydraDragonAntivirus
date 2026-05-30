#include <ntifs.h>

// CRT initialization/deinitialization prototypes
extern "C" int __crt_init();
extern "C" void __crt_deinit();

// Pool tag for Owlyshield allocations
constexpr unsigned long OwlyPoolTag = 'ylwO'; // 'Owly'

//
// Kernel-mode C++ new/delete operators
//

void *__cdecl operator new(size_t Size)
{
    void *Pointer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, OwlyPoolTag);
    if (Pointer)
        RtlZeroMemory(Pointer, Size);
    return Pointer;
}

void *__cdecl operator new(size_t Size, POOL_TYPE PoolType)
{
    ULONG_PTR Flags = (PoolType & PagedPool) ? POOL_FLAG_PAGED : POOL_FLAG_NON_PAGED;
    void *Pointer = ExAllocatePool2(Flags, Size, OwlyPoolTag);
    if (Pointer)
        RtlZeroMemory(Pointer, Size);
    return Pointer;
}

void *__cdecl operator new[](size_t Size)
{
    void *Pointer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, OwlyPoolTag);
    if (Pointer)
        RtlZeroMemory(Pointer, Size);
    return Pointer;
}

void __cdecl operator delete(void *Pointer)
{
    if (!Pointer)
        return;
    ExFreePoolWithTag(Pointer, OwlyPoolTag);
}

void __cdecl operator delete(void *Pointer, size_t Size)
{
    UNREFERENCED_PARAMETER(Size);
    if (!Pointer)
        return;
    ExFreePoolWithTag(Pointer, OwlyPoolTag);
}

void __cdecl operator delete[](void *Pointer)
{
    if (!Pointer)
        return;
    ExFreePoolWithTag(Pointer, OwlyPoolTag);
}

void __cdecl operator delete[](void *Pointer, size_t Size)
{
    UNREFERENCED_PARAMETER(Size);
    if (!Pointer)
        return;
    ExFreePoolWithTag(Pointer, OwlyPoolTag);
}

//
// Basic CRT support for global objects (if needed)
//

using _PVFV = void(__cdecl *)(void);
using _PIFV = int(__cdecl *)(void);

#pragma section(".CRT$XCA", long, read)
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = {0};
#pragma section(".CRT$XCZ", long, read)
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = {0};

#pragma section(".CRT$XPA", long, read)
__declspec(allocate(".CRT$XPA")) _PVFV __xp_a[] = {0};
#pragma section(".CRT$XPZ", long, read)
__declspec(allocate(".CRT$XPZ")) _PVFV __xp_z[] = {0};

static void execute_pvfv_array(_PVFV *begin, _PVFV *end)
{
    _PVFV *fn = begin;
    while (fn != end)
    {
        if (*fn)
            (**fn)();
        ++fn;
    }
}

extern "C" int __crt_init()
{
    execute_pvfv_array(__xc_a, __xc_z);
    return 0;
}

extern "C" void __crt_deinit()
{
    execute_pvfv_array(__xp_a, __xp_z);
}

extern "C" int _fltused = 0;

int __cdecl _purecall()
{
    __debugbreak();
    return 0;
}
