//! This module deals with integrity checking of the internal process that the Sanctum DLL is injected into.

use std::{
    ffi::{CStr, c_void},
    thread::sleep,
    time::Duration,
};

use md5::{Digest, Md5};
use shared_no_std::ghost_hunting::DLLMessage;
use windows::{
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER},
            LibraryLoader::GetModuleHandleA,
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE},
            Threading::{CreateThread, THREAD_CREATION_FLAGS},
        },
    },
    core::s,
};

use crate::{ipc::send_ipc_to_engine, threads::suspend_all_threads};

/// The entrypoint to starting the NTDLL integrity checker. This will spawn a new OS thread which will occasionally monitor the
/// integrity of NTDLL to check for changes to the .text segment of NTDLL in memory. Once we have hooked the DLL there should be no
/// reason for this to be further modified.
///
/// This function **must** be called after the EDR DLL has hooked API's and before all threads are resumed.
pub fn start_ntdll_integrity_monitor() {
    // todo if the driver injects our DLL before early-bird techniques, can we prevent remapping before the hash takes place?

    let mut ntdll_info = NtdllIntegrity::new();

    let hash = hash_ntdll_text_segment(&ntdll_info);
    ntdll_info.hash = hash;

    let p_ntdll_info = Box::into_raw(Box::new(ntdll_info));
    unsafe {
        CreateThread(
            None,
            0,
            Some(native_wrapper_worker_thread),
            Some(p_ntdll_info as _),
            THREAD_CREATION_FLAGS(0),
            None,
        )
    }
    .expect("unable to create native thread for ntdll monitoring");
}

unsafe extern "system" fn native_wrapper_worker_thread(param: *mut c_void) -> u32 {
    if param.is_null() {
        panic!("[-] Param for native_wrapper_worker_thread was null.");
    }

    let ntdll_info = *unsafe { Box::from_raw(param as *mut NtdllIntegrity) };
    periodically_check_ntdll_hash(ntdll_info);
}

/// The core mappings of NTDLL so that it can be monitored for changes via a hash value
struct NtdllIntegrity {
    /// The base address (VA) of the .text segment
    text_base: usize,
    /// The size in memory of the .text segment
    size: usize,
    hash: String,
}

impl NtdllIntegrity {
    fn new() -> Self {
        let (base_of_code, size_of_text_sec) = get_base_and_sz_ntdll();

        assert_ne!(size_of_text_sec, 0);

        Self {
            text_base: base_of_code as usize,
            size: size_of_text_sec as _,
            hash: String::new(),
        }
    }
}

pub fn get_base_and_sz_ntdll() -> (usize, usize) {
    // `module` will contain the base address of the DLL
    let module =
        unsafe { GetModuleHandleA(s!("ntdll.dll")) }.expect("[-] Could not get a handle to NTDLL");

    //
    // Resolve the Virtual Address address & size of the .text section
    //
    let dos_header = unsafe { std::ptr::read(module.0 as *const IMAGE_DOS_HEADER) };
    if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
        panic!("[-] Bytes of NTDLL did not match DOS signature.");
    }

    let mut size_of_text_sec: u32 = 0;
    let headers = unsafe {
        std::ptr::read(module.0.add(dos_header.e_lfanew as _) as *const IMAGE_NT_HEADERS64)
    };

    // Get the virtual address of the .text segment
    let base_of_code_offset = headers.OptionalHeader.BaseOfCode as usize;
    let base_of_code = (module.0 as usize + base_of_code_offset) as *const c_void;

    // Look for the .text section to get the size of the section in bytes
    for i in 0..headers.FileHeader.NumberOfSections {
        let section_header = unsafe {
            std::ptr::read(
                module
                    .0
                    .add(dos_header.e_lfanew as _)
                    .add(size_of_val(&headers))
                    .add(i as usize * size_of::<IMAGE_SECTION_HEADER>())
                    as *const IMAGE_SECTION_HEADER,
            )
        };

        let name = unsafe { CStr::from_ptr(section_header.Name.as_ptr() as *const _) }
            .to_str()
            .expect("[-] Could not parse name to str");
        if name == ".text" {
            // SAFETY: Reading union field on documented & MSFT provided field as part of PE structure, should be fine
            size_of_text_sec = unsafe { section_header.Misc.VirtualSize };
            break;
        }
    }

    (base_of_code as usize, size_of_text_sec as usize)
}

/// Get a hash of NTDLL in its entirety, and save the state of this for future lookups.
fn read_ntdll_bytes(ntdll_info: &NtdllIntegrity) -> Vec<u8> {
    // todo would it be more efficient to just hash functions of interest? (is efficiency that important if we are not
    // blocking the applications main thread / other threads?)

    // The position we are indexing into, using the size of the image as a ceiling
    let mut pos = 0;
    // Buffer to store the bytes for hashing
    // todo may want to read into a stack / small heap buffer to preserve system resources if all processes do this
    let mut buf: Vec<u8> = Vec::with_capacity(ntdll_info.size);
    while pos < ntdll_info.size {
        // SAFETY: This read should be safe so long as NTDLL remains mapped in memory. Should NTDLL be remapped or removed
        // then this will lead to UB.
        buf.push(unsafe {
            std::ptr::read((ntdll_info.text_base as *const c_void).add(pos as _) as *const _)
        });
        pos += 1;
    }

    assert_eq!(buf.len(), ntdll_info.size as usize);

    buf
}

fn hash_ntdll_text_segment(ntdll_info: &NtdllIntegrity) -> String {
    // Read the bytes
    let buf = read_ntdll_bytes(&ntdll_info);

    // Calculate the hash
    let mut hasher = Md5::new();
    hasher.update(buf);
    let hash = hasher.finalize();
    let hash: String = hash.iter().map(|byte| format!("{:02X}", byte)).collect();
    hash
}

/// The worker routine in a thread which checks for NTDLL hash changes, this will detect:
///
/// 1 - Remapping NTDLL such that an unhooked version is copied into memory; and
/// 2 - Patching instructions in NTDLL, such as ETW / AMSI bypass techniques.
///
/// The function runs a main 'event loop' which monitors the integrity of NTDLL in memory
/// for changes based on a hash generated. If a change is detected, the EDR will suspend all process threads
/// to limit the impact of the attack, and wait on an instruction from the central EDR engine.
///
/// **Note**: the response to this by the EDR is not yet implemented, so the process will just hang until
/// terminated.
///
/// # Considerations
///
/// This monitoring is **expensive** as it runs in a tight loop; further experimentation is needed
/// to tune this, or find methods that maximise coverage without overly degrading system performance.
/// The challenge is presented mostly through malware which would temporarily patch NTDLL, and revert
/// the segment after the malicious operations are complete. Otherwise, we could also check the
/// integrity on program exit; but if it was modified before that point back to the hooked version,
/// our integrity checker would be non-the-wiser.
///
/// Alternatively, we could use ETW: Threat Intelligence to monitor memory writes to the NTDLL Virtual
/// Address region. Whilst we couldn't block it via ETW monitoring, we can still detect it happening in
/// 'near' real time. Given messing with ETW:TI requires **significant** effort by the adversary, most
/// of which we can now block / detect, this significantly raises the bar for the  adversary able to
/// breach the EDR defences to this technique, which may be **good enough** to filter out 99% of threats.
fn periodically_check_ntdll_hash(ntdll: NtdllIntegrity) -> ! {
    loop {
        let hash = hash_ntdll_text_segment(&ntdll);

        // Check for tampering with NTDLL.
        // If tampering is detected, suspend all threads except our EDR thread, and notify the
        // engine of the event.
        if hash != ntdll.hash {
            let threads: Vec<HANDLE> = suspend_all_threads();

            println!(
                "Hash change detected, sending info to engine. Old: {}, New: {}",
                ntdll.hash, hash
            );
            send_ipc_to_engine(DLLMessage::NtdllOverwrite);
            hash_ntdll_text_segment(&ntdll);

            // todo wait for response from EDR as to whether to allow the change, or
            // if the process needs memory dumping & terminating for an analyst to pick up
            loop {
                // loop waiting for instruction
                sleep(Duration::from_secs(3));
            }
        }

        sleep(Duration::from_millis(50));
    }
}
