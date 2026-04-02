use windows::{
    core::*,
    Win32::System::LibraryLoader::*,
};

/// Get the syscall number for a given NT function by reading it from ntdll
pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    unsafe {
        let ntdll_handle = GetModuleHandleA(s!("ntdll.dll")).ok()?;
        if ntdll_handle.is_invalid() {
            return None;
        }

        let c_func_name = std::ffi::CString::new(func_name).ok()?;
        let func_addr = GetProcAddress(ntdll_handle, PCSTR(c_func_name.as_ptr() as *const u8));
        if func_addr.is_none() {
            return None;
        }

        let func_addr = func_addr.unwrap();
        // Read 8 bytes from the function address
        let func_bytes = std::slice::from_raw_parts(func_addr as *const u8, 8);

        // Check for the standard syscall stub pattern:
        // mov r10, rcx
        // mov eax, <syscall_number>
        if func_bytes[0] == 0x4c
            && func_bytes[1] == 0x8b
            && func_bytes[2] == 0xd1
            && func_bytes[3] == 0xb8
            && func_bytes[6] == 0x00
            && func_bytes[7] == 0x00
        {
            let high = u32::from(func_bytes[5]);
            let low = u32::from(func_bytes[4]);
            let syscall_number = (high << 8) | low;
            return Some(syscall_number);
        }

        None
    }
}
