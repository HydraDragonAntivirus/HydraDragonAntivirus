//! Internal allocator to allow wdk-mutex to use the allocator as required.

use core::{alloc::GlobalAlloc, ptr::null_mut};

use wdk_sys::{
    ntddk::{ExAllocatePool2, ExFreePool},
    POOL_FLAG_NON_PAGED,
};

/// Memory allocator used by the crate.
///
/// SAFETY: This is safe IRQL <= DISPATCH_LEVEL
pub struct KMAlloc;

// The value memory tags are stored as.
const MEM_TAG_WDK_MUTEX: u32 = u32::from_le_bytes(*b"kmtx");

unsafe impl GlobalAlloc for KMAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let ptr = unsafe {
            ExAllocatePool2(POOL_FLAG_NON_PAGED, layout.size() as u64, MEM_TAG_WDK_MUTEX)
        };
        if ptr.is_null() {
            return null_mut();
        }

        ptr.cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        unsafe {
            ExFreePool(ptr.cast());
        }
    }
}
