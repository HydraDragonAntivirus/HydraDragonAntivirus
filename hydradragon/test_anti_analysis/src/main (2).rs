use std::fs;
use std::mem;
use std::ptr;
use std::ffi::CString;
use std::env;

#[cfg(windows)]
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect, VirtualFree};
#[cfg(windows)]
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, MEM_RELEASE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_READONLY, IMAGE_BASE_RELOCATION};
#[cfg(windows)]
use winapi::um::libloaderapi::{LoadLibraryA, GetProcAddress};
#[cfg(windows)]
use winapi::shared::minwindef::{HMODULE, LPVOID, DWORD};
#[cfg(windows)]
use winapi::um::processthreadsapi::FlushInstructionCache;
#[cfg(windows)]
use winapi::um::errhandlingapi::GetLastError;

// PE Header structures
#[repr(C)]
struct ImageDosHeader { e_magic: u16, e_cblp: u16, e_cp: u16, e_crlc: u16, e_cparhdr: u16, e_minalloc: u16, e_maxalloc: u16, e_ss: u16, e_sp: u16, e_csum: u16, e_ip: u16, e_cs: u16, e_lfarlc: u16, e_ovno: u16, e_res: [u16; 4], e_oemid: u16, e_oeminfo: u16, e_res2: [u16; 10], e_lfanew: i32, }
#[repr(C)]
struct ImageFileHeader { machine: u16, number_of_sections: u16, time_date_stamp: u32, pointer_to_symbol_table: u32, number_of_symbols: u32, size_of_optional_header: u16, characteristics: u16, }

// --- MODIFIED: Renamed to ImageOptionalHeader64 and removed `base_of_data` ---
#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    // BaseOfData field is removed for PE32+ (x64)
    image_base: usize,
    section_alignment: u32,
    file_alignment: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    check_sum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: usize,
    size_of_stack_commit: usize,
    size_of_heap_reserve: usize,
    size_of_heap_commit: usize,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
}

// --- MODIFIED: Renamed to ImageNtHeaders64 to use the correct optional header ---
#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header: ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageSectionHeader { name: [u8; 8], virtual_size: u32, virtual_address: u32, size_of_raw_data: u32, pointer_to_raw_data: u32, pointer_to_relocations: u32, pointer_to_linenumbers: u32, number_of_relocations: u16, number_of_linenumbers: u16, characteristics: u32, }
#[repr(C)]
struct ImageDataDirectory { virtual_address: u32, size: u32, }
#[repr(C)]
struct ImageImportDescriptor { original_first_thunk: u32, time_date_stamp: u32, forwarder_chain: u32, name: u32, first_thunk: u32, }
#[repr(C)]
struct ImageImportByName { hint: u16, name: [u8; 1], }
#[repr(C)]
struct ImageBaseRelocation { virtual_address: u32, size_of_block: u32, }
#[repr(C)]
struct ImageExportDirectory { characteristics: u32, time_date_stamp: u32, major_version: u16, minor_version: u16, name: u32, base: u32, number_of_functions: u32, number_of_names: u32, address_of_functions: u32, address_of_names: u32, address_of_name_ordinals: u32, }
#[repr(C)]
struct ImageTlsDirectory64 { start_address_of_raw_data: u64, end_address_of_raw_data: u64, address_of_index: u64, address_of_callbacks: u64, size_of_zero_fill: u32, characteristics: u32, }

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000; const IMAGE_SCN_MEM_READ: u32 = 0x40000000; const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000; const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0; const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1; const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5; const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9; const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10; const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

// --- MODIFIED: Helper functions now use the new `64` suffixed structs ---
#[cfg(windows)]
unsafe fn get_data_directory(nt_headers: *const ImageNtHeaders64, index: usize) -> *const ImageDataDirectory {
    let optional_header_ptr = &(*nt_headers).optional_header as *const ImageOptionalHeader64;
    let data_dir_ptr = (optional_header_ptr as usize + mem::offset_of!(ImageOptionalHeader64, number_of_rva_and_sizes) + mem::size_of::<u32>()) as *const ImageDataDirectory;
    data_dir_ptr.add(index)
}
#[cfg(windows)]
unsafe fn set_section_permissions(image_base: *mut u8, section: &ImageSectionHeader) -> Result<(), String> { let characteristics = section.characteristics; let mut protect = PAGE_READONLY; if (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 { if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 { protect = PAGE_EXECUTE_READWRITE; } else if (characteristics & IMAGE_SCN_MEM_READ) != 0 { protect = PAGE_EXECUTE_READ; } } else if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 { protect = PAGE_READWRITE; } else if (characteristics & IMAGE_SCN_MEM_READ) != 0 { protect = PAGE_READONLY; } let section_start = image_base.add(section.virtual_address as usize); let mut old_protect = 0; let result = VirtualProtect(section_start as LPVOID, section.virtual_size as usize, protect, &mut old_protect,); if result == 0 { return Err(format!("Failed to set section protection (error: {})", GetLastError())); } Ok(()) }
#[cfg(windows)]
unsafe fn process_relocations(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> { let reloc_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_BASERELOC); if (*reloc_dir).virtual_address == 0 { println!("[!] No relocations found"); return Ok(()); } let preferred_base = (*nt_headers).optional_header.image_base; let delta = image_base as isize - preferred_base as isize; if delta == 0 { println!("[+] No relocation needed (loaded at preferred base)"); return Ok(()); } let mut reloc_ptr = image_base.add((*reloc_dir).virtual_address as usize) as *const ImageBaseRelocation; let reloc_end = (reloc_ptr as usize + (*reloc_dir).size as usize) as *const ImageBaseRelocation; let mut reloc_count = 0; while (reloc_ptr as usize) < (reloc_end as usize) && (*reloc_ptr).size_of_block > 0 { let count = ((*reloc_ptr).size_of_block as usize - mem::size_of::<ImageBaseRelocation>()) / 2; let entries = (reloc_ptr as usize + mem::size_of::<ImageBaseRelocation>()) as *const u16; for i in 0..count { let entry = *entries.add(i); let reloc_type = entry >> 12; let offset = entry & 0xFFF; if reloc_type == 3 { let patch_addr = image_base.add((*reloc_ptr).virtual_address as usize + offset as usize) as *mut u32; *patch_addr = ((*patch_addr as isize) + delta) as u32; reloc_count += 1; } else if reloc_type == 10 { let patch_addr = image_base.add((*reloc_ptr).virtual_address as usize + offset as usize) as *mut u64; *patch_addr = ((*patch_addr as isize) + delta) as u64; reloc_count += 1; } } reloc_ptr = (reloc_ptr as usize + (*reloc_ptr).size_of_block as usize) as *const ImageBaseRelocation; } println!("[+] Processed {} relocations (delta: 0x{:x})", reloc_count, delta); Ok(()) }
#[cfg(windows)]
unsafe fn resolve_imports(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> { let import_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_IMPORT); if (*import_dir).virtual_address == 0 { println!("[!] No import table found"); return Ok(()); } let mut import_desc = image_base.add((*import_dir).virtual_address as usize) as *const ImageImportDescriptor; let mut dll_count = 0; while (*import_desc).name != 0 { let dll_name_ptr = image_base.add((*import_desc).name as usize); let dll_name = std::ffi::CStr::from_ptr(dll_name_ptr as *const i8); println!("[+] Loading: {:?}", dll_name); let module = LoadLibraryA(dll_name_ptr as *const i8); if module.is_null() { return Err(format!("Failed to load DLL: {:?} (error: {})", dll_name, GetLastError())); } let mut thunk_ref = if (*import_desc).original_first_thunk != 0 { image_base.add((*import_desc).original_first_thunk as usize) as *const usize } else { image_base.add((*import_desc).first_thunk as usize) as *const usize }; let mut func_ref = image_base.add((*import_desc).first_thunk as usize) as *mut usize; let mut func_count = 0; while *thunk_ref != 0 { let func_addr = if (*thunk_ref & (1 << 63)) != 0 { let ordinal = (*thunk_ref & 0xFFFF) as u16; GetProcAddress(module, ordinal as usize as *const i8) } else { let import_by_name = image_base.add(*thunk_ref as usize) as *const ImageImportByName; let func_name_ptr = &(*import_by_name).name as *const u8 as *const i8; GetProcAddress(module, func_name_ptr) }; if func_addr.is_null() { return Err(format!("Failed to import function (error: {})", GetLastError())); } *func_ref = func_addr as usize; func_count += 1; thunk_ref = thunk_ref.add(1); func_ref = func_ref.add(1); } println!("  → Resolved {} functions", func_count); dll_count += 1; import_desc = import_desc.add(1); } println!("[+] Imported {} DLLs", dll_count); Ok(()) }
#[cfg(windows)]
unsafe fn process_tls_callbacks(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> { let tls_dir = get_data_directory(nt_headers, IMAGE_DIRECTORY_ENTRY_TLS); if (*tls_dir).virtual_address == 0 { return Ok(()); } println!("[*] Processing TLS callbacks..."); let tls = image_base.add((*tls_dir).virtual_address as usize) as *const ImageTlsDirectory64; let callbacks_addr = (*tls).address_of_callbacks as usize; if callbacks_addr == 0 { return Ok(()); } let mut callback_ptr = callbacks_addr as *const usize; let mut callback_count = 0; while *callback_ptr != 0 { let callback: extern "system" fn(LPVOID, DWORD, LPVOID) = mem::transmute(*callback_ptr); callback(image_base as LPVOID, 1, ptr::null_mut()); callback_count += 1; callback_ptr = callback_ptr.add(1); } println!("[+] Executed {} TLS callbacks", callback_count); Ok(()) }
#[cfg(windows)]
unsafe fn finalize_sections(image_base: *mut u8, nt_headers: *const ImageNtHeaders64) -> Result<(), String> { println!("[*] Finalizing section permissions..."); let section_header_ptr = (nt_headers as *const ImageNtHeaders64 as usize + mem::size_of::<u32>() + mem::size_of::<ImageFileHeader>() + (*nt_headers).file_header.size_of_optional_header as usize) as *const ImageSectionHeader; for i in 0..(*nt_headers).file_header.number_of_sections { let section = &*section_header_ptr.offset(i as isize); let section_name = std::str::from_utf8(&section.name).unwrap_or("???").trim_end_matches('\0'); set_section_permissions(image_base, section)?; let perms = if (section.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 { "X" } else { "-" }.to_string() + if (section.characteristics & IMAGE_SCN_MEM_READ) != 0 { "R" } else { "-" } + if (section.characteristics & IMAGE_SCN_MEM_WRITE) != 0 { "W" } else { "-" }; println!("  → {} [{}]", section_name, perms); } use winapi::um::processthreadsapi::GetCurrentProcess; FlushInstructionCache(GetCurrentProcess(), image_base as LPVOID, (*nt_headers).optional_header.size_of_image as usize); Ok(()) }

#[cfg(windows)]
unsafe fn load_pe_from_memory(pe_data: &[u8]) -> Result<(), String> {
    println!("=== Advanced PE Memory Loader (x64 Only) ===\n");

    // Check headers and bounds
    if pe_data.len() < mem::size_of::<ImageDosHeader>() {
        return Err("PE data is too small for DOS header".to_string());
    }
    
    let dos_header = &*(pe_data.as_ptr() as *const ImageDosHeader);
    if dos_header.e_magic != 0x5A4D { // "MZ"
        return Err("Invalid PE file (MZ signature missing)".to_string());
    }

    let nt_headers_offset = dos_header.e_lfanew as usize;
    if nt_headers_offset == 0 || (nt_headers_offset + mem::size_of::<ImageNtHeaders64>()) > pe_data.len() {
        return Err(format!(
            "Invalid NT header offset (e_lfanew = 0x{:x}) or file is too small.",
            dos_header.e_lfanew
        ));
    }

    // --- MODIFIED: Cast to the 64-bit specific header struct ---
    let nt_headers = &*(pe_data.as_ptr().add(nt_headers_offset) as *const ImageNtHeaders64);
    if nt_headers.signature != 0x4550 { // "PE\0\0"
        return Err("Invalid PE signature".to_string());
    }
    
    // --- FIX: Enforce 64-bit architecture ---
    if nt_headers.optional_header.magic != 0x20b { // 0x20b == PE32+
        return Err("Loader only supports 64-bit (x64) PE files.".to_string());
    }

    println!("[+] PE Header validated");
    println!("[+] Architecture: x64"); // We've already confirmed this
    println!("[+] Entry Point: 0x{:x}", nt_headers.optional_header.address_of_entry_point);
    println!("[+] Image Base: 0x{:x}", nt_headers.optional_header.image_base);
    println!("[+] Image Size: 0x{:x} ({} KB)", 
        nt_headers.optional_header.size_of_image,
        nt_headers.optional_header.size_of_image / 1024);
    println!("[+] Subsystem: {}", match nt_headers.optional_header.subsystem {
        2 => "GUI",
        3 => "Console",
        _ => "Other",
    });

    let image_size = nt_headers.optional_header.size_of_image as usize;
    if image_size == 0 {
        return Err("Invalid PE file (SizeOfImage is zero)".to_string());
    }

    // Allocate memory
    let image_base = VirtualAlloc(
        ptr::null_mut(),
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );

    if image_base.is_null() {
        return Err(format!("Memory allocation failed (error: {})", GetLastError()));
    }

    println!("[+] Memory allocated at: {:p}\n", image_base);

    // Copy headers
    let headers_size = nt_headers.optional_header.size_of_headers as usize;
    ptr::copy_nonoverlapping(pe_data.as_ptr(), image_base as *mut u8, headers_size);
    println!("[+] Headers copied ({} bytes)", headers_size);

    // Copy sections
    let section_header_ptr = (nt_headers as *const _ as usize
        + mem::size_of::<u32>() // Signature
        + mem::size_of::<ImageFileHeader>()
        + nt_headers.file_header.size_of_optional_header as usize) as *const ImageSectionHeader;

    println!("[*] Mapping sections:");
    for i in 0..nt_headers.file_header.number_of_sections {
        let section = &*section_header_ptr.offset(i as isize);
        let section_name = std::str::from_utf8(&section.name).unwrap_or("???").trim_end_matches('\0');
        println!("  → {} (VA: 0x{:08x}, Raw: 0x{:08x})", section_name, section.virtual_address, section.size_of_raw_data);
        if section.size_of_raw_data > 0 {
            let dest = (image_base as usize + section.virtual_address as usize) as *mut u8;
            let src = pe_data.as_ptr().offset(section.pointer_to_raw_data as isize);
            ptr::copy_nonoverlapping(src, dest, section.size_of_raw_data as usize);
        }
    }
    println!();

    // Process relocations
    println!("[*] Processing relocations...");
    process_relocations(image_base as *mut u8, nt_headers)?;
    println!();

    // Resolve imports
    println!("[*] Resolving imports...");
    resolve_imports(image_base as *mut u8, nt_headers)?;
    println!();

    // --- FIX: Set section permissions BEFORE running any code ---
    // Finalize section permissions
    finalize_sections(image_base as *mut u8, nt_headers)?;
    println!();
    
    // Process TLS callbacks (now that the code is executable)
    process_tls_callbacks(image_base as *mut u8, nt_headers)?;

    // Execute entry point
    let entry_point = (image_base as usize + nt_headers.optional_header.address_of_entry_point as usize) as *const ();
    println!("[*] Calling entry point at: {:p}", entry_point);
    println!("[*] Executing program...\n");
    println!("========================================");
    
    if nt_headers.optional_header.subsystem == 2 || nt_headers.optional_header.subsystem == 3 {
        let entry_fn: extern "system" fn() -> i32 = mem::transmute(entry_point);
        let exit_code = entry_fn();
        println!("\n========================================");
        println!("[+] Program terminated (Exit code: {})", exit_code);
    } else {
        let dll_main: extern "system" fn(HMODULE, u32, *mut u8) -> i32 = mem::transmute(entry_point);
        let result = dll_main(image_base as HMODULE, 1, ptr::null_mut()); // DLL_PROCESS_ATTACH
        println!("\n========================================");
        println!("[+] DLL loaded (DllMain returned: {})", result);
    }

    Ok(())
}

// ------------------------------------
// Custom XOR Obfuscation (Unchanged)
// ------------------------------------
const SECRET_KEY: &[u8] = b"change-this-secret-key-to-something-unique";

fn transform_data(data: &[u8]) -> Vec<u8> {
    if SECRET_KEY.is_empty() { return data.to_vec(); }
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ SECRET_KEY[i % SECRET_KEY.len()])
        .collect()
}

// ------------------------------------
// Main Function (Unchanged)
// ------------------------------------
fn print_usage(program: &str) { println!("Usage:\n  {} [--encode|-e] <input-file>   # Obfuscates binary -> <input-file>.obin\n  {} [--decode|-d] <input-file>   # De-obfuscates and runs .obin file in memory (Windows only)\n  {} <input-file>                 # Default: Read raw binary and try to load it (Windows only)", program, program, program); }

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { print_usage(&args.get(0).cloned().unwrap_or_else(|| "program".into())); return; }
    let (mode, path) = if args.len() == 2 { ("load", args[1].as_str()) } else { match args[1].as_str() { "--encode" | "-e" => ("encode", args[2].as_str()), "--decode" | "-d" => ("decode", args[2].as_str()), other => { eprintln!("Unknown flag: {}", other); print_usage(&args[0]); return; } } };
    #[cfg(windows)] { match mode { "encode" => { println!("[*] Reading file: {}", path); match fs::read(path) { Ok(data) => { println!("[+] File size: {} bytes", data.len()); let obfuscated_data = transform_data(&data); let out_path = format!("{}.obin", path); match fs::write(&out_path, &obfuscated_data) { Ok(_) => println!("[+] Wrote obfuscated binary to: {}", out_path), Err(e) => eprintln!("[✗] Failed to write {}: {}", out_path, e), } } Err(e) => eprintln!("[✗] Failed to read file: {}", e), } } "decode" => { println!("[*] Reading obfuscated binary file: {}", path); match fs::read(path) { Ok(obfuscated_data) => { let bytes = transform_data(&obfuscated_data); println!("[+] De-obfuscated size: {} bytes -- passing to loader\n", bytes.len()); unsafe { match load_pe_from_memory(&bytes) { Ok(_) => println!("\n[✓] Operation completed successfully!"), Err(e) => eprintln!("\n[✗] Error: {}", e), } } } Err(e) => eprintln!("[✗] Failed to read {}: {}", path, e), } } "load" => { println!("[*] Reading raw binary file: {}", path); match fs::read(path) { Ok(exe_data) => { println!("[+] File size: {} bytes", exe_data.len()); unsafe { match load_pe_from_memory(&exe_data) { Ok(_) => println!("\n[✓] Operation completed successfully!"), Err(e) => eprintln!("\n[✗] Error: {}", e), } } } Err(e) => eprintln!("[✗] Failed to read file: {}", e), } } _ => { print_usage(&args[0]); } } }
    #[cfg(not(windows))] { if mode == "encode" { println!("[*] Reading file: {}", path); match fs::read(path) { Ok(data) => { println!("[+] File size: {} bytes", data.len()); let obfuscated_data = transform_data(&data); let out_path = format!("{}.obin", path); match fs::write(&out_path, &obfuscated_data) { Ok(_) => println!("[+] Wrote obfuscated binary to: {}", out_path), Err(e) => eprintln!("[✗] Failed to write {}: {}", out_path, e), } } Err(e) => eprintln!("[✗] Failed to read file: {}", e), } } else { eprintln!("[✗] Loading/Decoding is only supported on Windows."); print_usage(&args[0]); } }
}
