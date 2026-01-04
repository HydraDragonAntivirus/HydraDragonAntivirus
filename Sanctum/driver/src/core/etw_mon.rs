//! Monitoring of the Events Tracing for Windows kernel structures for tampering by
//! rootkits or kernel mode exploitation.

use core::{ffi::c_void, ptr::null_mut, time::Duration};

use alloc::{collections::btree_map::BTreeMap, format, string::String, vec::Vec};
use wdk::println;
use wdk_mutex::{
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _MODE::KernelMode,
    FALSE, HANDLE, LARGE_INTEGER, STATUS_SUCCESS, THREAD_ALL_ACCESS, UNICODE_STRING,
    ntddk::{
        KeBugCheckEx, KeDelayExecutionThread, MmGetSystemRoutineAddress, ObReferenceObjectByHandle,
        PsCreateSystemThread, PsTerminateSystemThread, RtlInitUnicodeString,
    },
};

use crate::utils::duration_to_large_int;

/// Entrypoint for monitoring kernel ETW structures to detect rootkits or other ETW manipulation
pub fn monitor_kernel_etw() {
    // Call the functions
    let guid_map = match traverse_guid_tables_for_etw_monitoring_data() {
        Ok(g) => g,
        Err(_) => {
            println!(
                "[sanctum] [-] Failed to start the monitoring of guid enabled mask, kernel ETW is not being monitored."
            );
            return;
        }
    };

    if monitor_etw_dispatch_table().is_err() {
        println!(
            "[sanctum] [-] Failed to start the monitoring of ETW Table, kernel ETW is not being monitored."
        );
        return;
    }

    if monitor_system_logger_bitmask().is_err() {
        println!(
            "[sanctum] [-] Failed to start the monitoring of system logging ETW bitmask, kernel ETW is not being monitored."
        );
        return;
    }

    // Add any returned maps to the Grt for mutex use - it's possible some functions don't expose their maps
    // and implement them internally, that is fine.
    if Grt::register_fast_mutex("etw_guid_table", guid_map.0).is_err() {
        println!(
            "[sanctum] [-] Could not register wdk-mutex for etw_guid_table, kernel ETW is not being monitored."
        );
        return;
    }

    if Grt::register_fast_mutex("etw_guid_reg_entry_mask", guid_map.1).is_err() {
        println!(
            "[sanctum] [-] Could not register wdk-mutex for etw_guid_reg_entry_mask, kernel ETW is not being monitored."
        );
        return;
    }

    // Start the thread that will monitor for changes
    let mut thread_handle: HANDLE = null_mut();

    let thread_status = unsafe {
        PsCreateSystemThread(
            &mut thread_handle,
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            Some(thread_run_monitor_etw),
            null_mut(),
        )
    };

    if thread_status != STATUS_SUCCESS {
        println!(
            "[sanctum] [-] Could not create new thread for monitoring ETW patching, kernel ETW is not being monitored."
        );
        return;
    }

    // To prevent a BSOD when exiting the thread on driver unload, we need to reference count the handle
    // so that it isn't deallocated whilst waiting on the thread to exit.
    let mut object: *mut c_void = null_mut();
    if unsafe {
        ObReferenceObjectByHandle(
            thread_handle,
            THREAD_ALL_ACCESS,
            null_mut(),
            KernelMode as _,
            &mut object,
            null_mut(),
        )
    } != STATUS_SUCCESS
    {
        println!(
            "[sanctum] [-] Could not get thread handle by ObRef.. kernel ETW is not being monitored."
        );
        return;
    }

    if Grt::register_fast_mutex("TERMINATION_FLAG_ETW_MONITOR", false).is_err() {
        println!(
            "[sanctum] [-] Could not register TERMINATION_FLAG_ETW_MONITOR as a FAST_MUTEX, PANICKING."
        );
        panic!(
            "[sanctum] [-] Could not register TERMINATION_FLAG_ETW_MONITOR as a FAST_MUTEX, PANICKING."
        );
    }
    if Grt::register_fast_mutex("ETW_THREAD_HANDLE", object).is_err() {
        println!("[sanctum] [-] Could not register ETW_THREAD_HANDLE as a FAST_MUTEX, PANICKING");
        panic!("[sanctum] [-] Could not register ETW_THREAD_HANDLE as a FAST_MUTEX, PANICKING")
    }
}

fn monitor_etw_dispatch_table() -> Result<(), ()> {
    let table = match get_etw_dispatch_table() {
        Ok(t) => t,
        Err(_) => {
            println!("[sanctum] [-] Could not get the ETW Kernel table");
            return Err(());
        }
    };

    // use my `wdk-mutex` crate to wrap the ETW table in a mutex and have it globally accessible
    // https://github.com/0xflux/wdk-mutex
    if let Err(e) = Grt::register_fast_mutex_checked("etw_table", table) {
        println!("[sanctum] [-] wdk-mutex could not register new fast mutex for etw_table");
        panic!("[sanctum] [-] wdk-mutex could not register new fast mutex for etw_table");
    }

    Ok(())
}

/// Resolves the relative offset to a symbol being searched for by directly reading kernel memory.
///
/// # Args
///
/// - `function_name`: The name of the function contained in ntoskrnl you wish to search for the symbol
/// - `offset`: The pre-calculated offset to the symbol from manual disassembly. The offset should be the instruction address
///   which IMMEDIATELY follows the 4 byte offset to the struct. See the note for a better explanation.
///
/// # Note
///
/// To accurately select the offset location of the search, you **must** choose the address immediately following the
/// 4 byte (DWORD) offset to  the symbol. For example with this disassembly:
///
///     nt!KeInsertQueueApc:
///     fffff802`7f280380 4c89442418         mov     qword ptr [rsp+18h], r8
///     fffff802`7f280385 4889542410         mov     qword ptr [rsp+10h], rdx
///     fffff802`7f28038a 489c               pushfq  
///     fffff802`7f28038c 53                 push    rbx
///     fffff802`7f28038d 55                 push    rbp
///     fffff802`7f28038e 56                 push    rsi
///     fffff802`7f28038f 57                 push    rdi
///     fffff802`7f280390 4154               push    r12
///     fffff802`7f280392 4155               push    r13
///     fffff802`7f280394 4156               push    r14
///     fffff802`7f280396 4157               push    r15
///     fffff802`7f280398 4883ec70           sub     rsp, 70h
///     fffff802`7f280399 83ec70             sub     esp, 70h
///     fffff802`7f28039a ec                 in      al, dx
///     fffff802`7f28039b 704c               jo      ntkrnlmp!KeInsertQueueApc+0x69 (fffff8027f2803e9)
///     fffff802`7f28039d 8b15b5dfc700       mov     edx, dword ptr [ntkrnlmp!EtwThreatIntProvRegHandle (fffff8027fefe358)]
///     fffff802`7f2803a3 458be9             mov     r13d, r9d
///     ^ YOU WANT THE OFFSET IN BYTES TO THIS ADDRESS
///     fffff802`7f2803a6 488be9             mov     rbp, rcx
///
/// The function will then step back 4 bytes, as they are encoded in LE, to calculate the offset to the actual virtual address of the symbol .
pub fn resolve_relative_symbol_offset(
    function_name: &str,
    offset: usize,
) -> Result<*const c_void, EtwMonitorError> {
    let mut function_name_unicode = UNICODE_STRING::default();
    let string_wide: Vec<u16> = function_name.encode_utf16().collect();
    unsafe {
        RtlInitUnicodeString(&mut function_name_unicode, string_wide.as_ptr());
    }

    let function_address =
        unsafe { MmGetSystemRoutineAddress(&mut function_name_unicode) } as usize;
    if function_address == 0 {
        println!(
            "[sanctum] [-] Address of {function_name} was null whilst searching for the function address."
        );
        return Err(EtwMonitorError::SymbolNotFound);
    }

    let offset_to_next_instruction = function_address + offset;
    let mut distance_to_symbol: i32 = 0;

    for i in 0..4 {
        // The starting point has us displaced immediately after the 4 byte offset; so we want to start with the
        // first byte and we then process each byte in the DWORD.
        // We calculate a pointer to the byte we want to read as a u32 (so it can be shifted into a u32). Then
        // shift it left by (i * 8) bits, and then OR them in place by setting the relevant bits.
        let ptr = unsafe { (offset_to_next_instruction as *const u8).sub(4 - i) };
        let byte = unsafe { core::ptr::read(ptr) } as i32;
        distance_to_symbol |= byte << (i * 8);
    }

    // Calculate the actual virtual address of the symbol we are hunting..
    let symbol = offset_to_next_instruction as isize + distance_to_symbol as isize;

    Ok(symbol as *const c_void)
}

pub fn get_etw_dispatch_table<'a>() -> Result<BTreeMap<&'a str, *const c_void>, EtwMonitorError> {
    // Construct the table of pointers to the kernel ETW dispatch objects. This will be stored in
    // a BTreeMap with the key of the dispatch symbol name, and a value of the pointer to the symbol.
    let mut dispatch_table: BTreeMap<&str, *const c_void> = BTreeMap::new();

    let etw_threat_int_prov_reg_handle = resolve_relative_symbol_offset("KeInsertQueueApc", 35)?;
    dispatch_table.insert("EtwThreatIntProvRegHandle", etw_threat_int_prov_reg_handle);

    // EtwKernelProvRegHandle contiguously follows EtwThreatIntProvRegHandle
    dispatch_table.insert("EtwKernelProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8)
    });

    // EtwApiCallsProvRegHandle contiguously follows EtwKernelProvRegHandle
    dispatch_table.insert("EtwApiCallsProvRegHandle", unsafe {
        etw_threat_int_prov_reg_handle.add(8 * 2)
    });

    // Now we are out of contiguous addressing, so we need to search for the symbol
    let etwp_event_tracing_prov_reg_handle = resolve_relative_symbol_offset("EtwUnregister", 452)?;
    dispatch_table.insert(
        "EtwpEventTracingProvRegHandle",
        etwp_event_tracing_prov_reg_handle,
    );

    // EtwpPsProvRegHandle acts as a memory anchor to find the remainder of the table
    dispatch_table.insert("EtwpPsProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x20)
    });

    // The remainder can be calculated based off of pre-determined in memory offsets from EtwpPsProvRegHandle

    dispatch_table.insert("EtwpFileProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8)
    });
    dispatch_table.insert("EtwpDiskProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x30)
    });
    dispatch_table.insert("EtwpNetProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x28)
    });
    dispatch_table.insert("EtwLpacProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 4)
    });
    dispatch_table.insert("EtwCVEAuditProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(8 * 5)
    });
    dispatch_table.insert("EtwAppCompatProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x10)
    });
    dispatch_table.insert("EtwpMemoryProvRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.sub(0x8)
    });
    // dispatch_table.insert("EtwCpuPartitionProvRegHandle", unsafe {
    //     etwp_event_tracing_prov_reg_handle.add(0x30)
    // });
    // dispatch_table.insert("EtwCpuStarvationProvRegHandle", unsafe {
    //     etwp_event_tracing_prov_reg_handle.add(0x10)
    // });
    dispatch_table.insert("EtwSecurityMitigationsRegHandle", unsafe {
        etwp_event_tracing_prov_reg_handle.add(0x18)
    });

    for item in &dispatch_table {
        if !(*item.1).is_null() {
            // SAFETY: Null pointer of the inner pointer is checked above; we can guarantee at this point that the original pointer
            // in item.1 is valid, thus the question only remains of the inner pointer.
            let inner_ptr: *const EtwRegEntry = unsafe { *(*item.1 as *const *const EtwRegEntry) };

            if inner_ptr.is_null() {
                println!(
                    "[sanctum] [!] Symbol {}: inner pointer is null, raw value found: {:?}. This is indicative of tampering.",
                    item.0, inner_ptr
                );
                return Err(EtwMonitorError::NullPtr);
            }

            // SAFETY: Pointer dereference checked above
            let etw_reg_entry: &EtwRegEntry = unsafe { &*inner_ptr };
            let actual_guid_entry: *const GuidEntry = etw_reg_entry.p_guid_entry;
            if actual_guid_entry.is_null() {
                println!(
                    "[sanctum] [!] Symbol {}: p_guid_entry is null, this is indicative of tampering.",
                    item.0
                );
                return Err(EtwMonitorError::NullPtr);
            }
        }
    }

    Ok(dispatch_table)
}

/// This routine is to be spawned in a thread that monitors rootkit behaviour in the kernel where it tries to blind the
/// EDR via ETW manipulation.
///
/// It monitors for manipulation of:
///
/// - ETW Kernel Dispatch Table
/// - Disabling global active system loggers
unsafe extern "C" fn thread_run_monitor_etw(_: *mut c_void) {
    let mut thread_sleep_time = duration_to_large_int(Duration::from_millis(150));

    loop {
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut thread_sleep_time) };

        // Check if we have received the cancellation flag, without this check we will get a BSOD. This flag will be
        // set to true on DriverExit.
        let terminate_flag_lock: &FastMutex<bool> = match Grt::get_fast_mutex(
            "TERMINATION_FLAG_ETW_MONITOR",
        ) {
            Ok(lock) => lock,
            Err(e) => {
                // Maybe this should terminate the thread instead? This would be a bad error to have as it means we cannot.
                // instruct the thread to terminate cleanly on driver exit. Or maybe do a count with max tries? We shall see.
                println!(
                    "[sanctum] [-] Error getting fast mutex for TERMINATION_FLAG_ETW_MONITOR. {:?}",
                    e
                );
                continue;
            }
        };
        let lock = match terminate_flag_lock.lock() {
            Ok(lock) => lock,
            Err(e) => {
                println!("[sanctum] [-] Failed to lock mutex for terminate_flag_lock");
                continue;
            }
        };
        if *lock {
            break;
        }

        // Perform all check routines for ETW tampering
        check_etw_table_for_modification();
        check_etw_system_logger_modification();
        check_etw_guids_for_tampering_is_enabled_field();
    }

    let _ = unsafe { PsTerminateSystemThread(STATUS_SUCCESS) };
}

/// This function performs two separate checks, due to the lookup mechanism, it's more performant to check the results both in
/// the same function here.
///
/// This function will check 2 things:
///
/// 1) Check `_ETW_GUID_ENTRY` entries in the silo for tampering with alterations to the `IsEnabled` field. This was employed by
///   the Lazarus rootkit, FudModule.
///
/// 2) Check the `_ETW_REG_ENTRY` of the `_ETW_GUID_ENTRY` for modification to the masks.
fn check_etw_guids_for_tampering_is_enabled_field() {
    // First check integrity of the GUID table IsEnabled
    let guid_table: &FastMutex<BTreeMap<String, u32>> = match Grt::get_fast_mutex("etw_guid_table")
    {
        Ok(table) => table,
        Err(e) => {
            println!("[sanctum] [-] Could not get etw_guid_table. {:?}", e);
            return;
        }
    };

    let snapshot_etw_monitoring_data = match traverse_guid_tables_for_etw_monitoring_data() {
        Ok(c) => c,
        Err(_) => {
            println!("[sanctum] [-] Call to monitor_all_guids_for_is_enabled_flag failed.");
            return;
        }
    };

    let snapshot_guid_table = snapshot_etw_monitoring_data.0;

    let mut lock = match guid_table.lock() {
        Ok(lock) => lock,
        Err(e) => {
            println!("[sanctum] [-] Could not lock etw_guid_table. {:?}", e);
            return;
        }
    };

    // check the integrity of the two tables against each other
    for item in lock.iter() {
        let cache_item = match snapshot_guid_table.get(item.0) {
            Some(c) => c,
            None => continue,
        };

        if item.1 != cache_item {
            println!(
                "[sanctum] [TAMPERING] Tampering detected on the GUID table. Mismatch on: {}, OG: {}, Local: {}",
                item.0, item.1, cache_item,
            );
            // As per my blog post - dont bug check this one as there are **some** instances of the IsEnabled field changing organically
            // (albeit seldom). Instead you should report this event for an analyst to review / threat hunt.
            // For the POC we will just log a message to the debugger.
        }
    }
    // There was some discrepancy between the tables, whether an item missing, added, or value had changed - therefore we want
    // to update the master table inside the mutex so it reflects the current state - otherwise we will just keep reporting
    // the same change over and over.
    *lock = snapshot_guid_table;

    drop(lock);

    // Now check for modification to the masks at `_ETW_REG_ENTRY`
    let baseline_reg_masks: &FastMutex<RegEntryEtwMaskBTreeMap> =
        match Grt::get_fast_mutex("etw_guid_reg_entry_mask") {
            Ok(fm) => fm,
            Err(e) => {
                println!(
                    "[sanctum] [-] Could not get wdk-mutex for etw_guid_reg_entry_mask. {:?}",
                    e
                );
                return;
            }
        };

    let snapshot_reg_masks = snapshot_etw_monitoring_data.1;
    let mut lock = match baseline_reg_masks.lock() {
        Ok(lock) => lock,
        Err(e) => {
            println!(
                "[sanctum] [-] Could not lock etw_guid_reg_entry_mask. {:?}.",
                e
            );
            return;
        }
    };

    // We have a BTreeMap in a BTreeMap containing the _ETW_REG_ENTRY data that we are monitoring for changes.
    // I've tried to make this intentionally more efficient than comparing the maps and then iterating if there was a difference
    // owing to the comparison being the same cost as the iteration that would have been done if they were different.
    // Loop through the snapshot
    let mut snapshot_differs = false;
    for (guid, snapshot_inner) in &snapshot_reg_masks {
        match lock.get(guid) {
            Some(baseline_inner) => {
                // Compare the inner maps for each key (memory address of the _ETW_REG_ENTRY)
                for (address, snapshot_mask) in snapshot_inner {
                    // We only care if the new mask is 0, i.e. its been unset
                    // The disas shows the kernel will still match on any value other than 0 (bool check)
                    if *snapshot_mask > 1 {
                        continue;
                    }

                    // Look for the address of the _ETW_REG_ENTRY itself so we can access the mask
                    match baseline_inner.get(address) {
                        Some(baseline_mask) => {
                            if baseline_mask != snapshot_mask {
                                println!(
                                    "[sanctum] [TAMPERING] Tampering detected on the group enable mask ETW kernel structure. GUID: {}, Original mask: {}, new mask: {}",
                                    guid, baseline_mask, snapshot_mask,
                                );
                            }
                        }
                        None => snapshot_differs = true,
                    }
                }
            }

            // There's no evidence of tampering at this point, and is to be expected
            None => snapshot_differs = true,
        }
    }

    if snapshot_differs {
        // Seeing as the maps are different, save the cached copy as the new authoritative version
        *lock = snapshot_reg_masks;
    }
}

fn check_etw_system_logger_modification() {
    let bitmask_address: &FastMutex<(*const u32, u32)> =
        match Grt::get_fast_mutex("system_logger_bitmask_addr") {
            Ok(fm) => fm,
            Err(e) => {
                println!(
                    "[sanctum] [-] Could not get system_logger_bitmask_addr from Grt. {:?}",
                    e
                );
                return;
            }
        };

    let mut lock = match bitmask_address.lock() {
        Ok(lock) => lock,
        Err(e) => {
            println!(
                "[sanctum] [-] Could not lock system_logger_bitmask_addr. {:?}",
                e
            );
            return;
        }
    };

    if lock.0.is_null() {
        println!("[sanctum] [-] system_logger_bitmask_addr bitmask was null, this is unexpected.");
        return;
    }

    // Dereference the first item in the tuple (the address of the DWORD bitmask), and compare it with the item at the second tuple entry
    // which is the original value we read when we initialised the driver.
    if unsafe { *(*lock).0 } != (*lock).1 {
        println!(
            "[sanctum] [TAMPERING] Modification detected, system logger bitmask has been modified. New value: {}, old value: {}. Address {:p}",
            unsafe { *(*lock).0 },
            (*lock).1,
            (*lock).0,
        );

        // Only bug check in the event it was set to a mask of 0 - there are legitimate instances it seems of the kernel changing the bit
        // flags in the struct, so we don't want to bug check on that - but as per the blog on Lazarus (and likely effect of other threat
        // actors wanting to zero this out) - bug check on a 0 mask.
        if unsafe { *(*lock).0 } == 0 {
            unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
        }

        // Update the value to the new value to monitor future changes
        lock.1 = unsafe { *(*lock).0 };
    }
}

fn check_etw_table_for_modification() {
    let table_live_read = match get_etw_dispatch_table() {
        Ok(t) => t,
        Err(e) => match e {
            EtwMonitorError::NullPtr => {
                // This case will tell us tampering has taken place and as such, we need to handle it - we will do this by
                // doing what Patch Guard will do, bringing about a kernel panic with the stop code CRITICAL_STRUCTURE_CORRUPTION.
                // This is acceptable as an EDR. Before panicking however, it would be good to send telemetry to a telemetry collection
                // service, for example if this was an actual networked EDR in an enterprise environment, we would want to send that
                // signal before we execute the bug check. Seeing as this is only building a POC, I am happy just to BSOD :)
                // println!("[sanctum] [TAMPERING] Tampering detected with the ETW Kernel Table.");
                return;
                unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
            }
            EtwMonitorError::SymbolNotFound => {
                println!(
                    "[sanctum] [-] Etw function failed with SymbolNotFound when trying to read kernel symbols."
                );
                return;
            }
        },
    };

    let table: &FastMutex<BTreeMap<&str, *const c_void>> = match Grt::get_fast_mutex("etw_table") {
        Ok(table) => table,
        Err(e) => {
            println!(
                "[sanctum] [-] Could not get fast mutex for etw_table. {:?}",
                e
            );
            return;
        }
    };
    let table_lock: FastMutexGuard<'_, BTreeMap<&str, *const c_void>> = match table.lock() {
        Ok(l) => l,
        Err(e) => {
            println!(
                "[sanctum] [-] Could not get Mutex Guard for etw_table. {:?}",
                e
            );
            return;
        }
    };

    if table_live_read != *table_lock {
        // As above - this should shoot some telemetry off in a real world EDR
        println!(
            "[sanctum] [TAMPERING] ETW Tampering detected, the ETW table does not match the current ETW table."
        );
        unsafe { KeBugCheckEx(0x00000109, 0, 0, 0, 0) };
    }
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_REG_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EtwRegEntry {
    reg_list: ListEntry,
    unused_1: ListEntry,
    pub p_guid_entry: *const GuidEntry,
    unused: [u8; 0x3C],
    mask_enable: u8,
    mask_group_enable: u8,
    mask_host_enable: u8,
    mask_host_group_enable: u8,
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_GUID_ENTRY
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GuidEntry {
    pub guid_list: ListEntry,
    unused_1: ListEntry,
    pub ref_count: i64,
    pub guid: GUID,
    pub reg_list_head: ListEntry,
    pub unused_3: [u8; 0x18],
    pub provider_enable_info: TraceEnableInfo,
    pub unused_4: [u8; 0x120],
    pub silo_state: *const c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TraceEnableInfo {
    pub is_enabled: u32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct GUID {
    data_1: u32,
    data_2: u16,
    data_3: u16,
    data_4: [u8; 8],
}

impl GUID {
    /// Converts GUID bytes to a prettified hex encoded string in GUID format
    pub fn to_string(&self) -> String {
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data_1,
            self.data_2,
            self.data_3,
            self.data_4[0],
            self.data_4[1],
            self.data_4[2],
            self.data_4[3],
            self.data_4[4],
            self.data_4[5],
            self.data_4[6],
            self.data_4[7]
        )
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ListEntry {
    pub flink: *const c_void,
    pub blink: *const c_void,
}

#[derive(Debug)]
pub enum EtwMonitorError {
    NullPtr,
    SymbolNotFound,
}

/// Monitor the system logger bitmask as observed to be exploited by Lazarus in their FudModule rootkit.
///
/// This function monitors abuse of teh _ETW_SILODRIVERSTATE.SystemLoggerSettings.EtwpActiveSystemLoggers bitmask.
fn monitor_system_logger_bitmask() -> Result<(), ()> {
    let address: *const *const EtwSiloDriverState =
        match resolve_relative_symbol_offset("EtwSendTraceBuffer", 78) {
            Ok(a) => a as *const *const EtwSiloDriverState,
            Err(e) => {
                println!(
                    "[sanctum] [-] Unable to resolve function EtwSendTraceBuffer. {:?}",
                    e
                );
                return Err(());
            }
        };

    if address.is_null() {
        println!("[sanctum] [-] Pointer to EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    if unsafe { *address }.is_null() {
        println!("[sanctum] [-] Address for EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    let active_system_loggers = unsafe { &**address }.settings.active_system_loggers;

    let address_of_silo_driver_state_struct = unsafe { *address } as usize;
    let logger_addr = address_of_silo_driver_state_struct + 0x1098;
    let addr = logger_addr as *const u32;

    // Add to the GRT so that we can access it in the monitoring thread
    Grt::register_fast_mutex("system_logger_bitmask_addr", (addr, active_system_loggers))
        .expect("[sanctum] [-] Could not register fast mutex system_logger_bitmask_addr");

    Ok(())
}

/// Gets the address of the current Silo _ETW_SILODRIVERSTATE structure.
///
/// # Returns
///
/// - Ok: Will return a pointer to the _ETW_SILODRIVERSTATE structure. This function guarantees dereferencing the pointer to _ETW_SILODRIVERSTATE
///   will be safe.
/// - Err: Unit type - check the debug logs for more info
pub fn get_silo_etw_struct_address() -> Result<*const EtwSiloDriverState, ()> {
    let address: *const *const EtwSiloDriverState =
        match resolve_relative_symbol_offset("EtwSendTraceBuffer", 78) {
            Ok(a) => a as *const *const EtwSiloDriverState,
            Err(e) => {
                println!(
                    "[sanctum] [-] Unable to resolve function EtwSendTraceBuffer. {:?}",
                    e
                );
                return Err(());
            }
        };

    if address.is_null() {
        println!("[sanctum] [-] Pointer to EtwSiloDriverState is null");
        return Err(());
    }

    // SAFETY: Null pointer checked above
    if unsafe { *address }.is_null() {
        println!("[sanctum] [-] Address for EtwSiloDriverState is null");
        return Err(());
    }

    Ok(unsafe { *address })
}

pub fn traverse_guid_tables_for_etw_monitoring_data()
-> Result<(BTreeMap<String, u32>, RegEntryEtwMaskBTreeMap), ()> {
    let silo_driver_state_raw_ptr = get_silo_etw_struct_address()?;
    // SAFETY: Null pointer is checked inside of get_silo_etw_struct_address
    let first_hash_address = &(unsafe { &*silo_driver_state_raw_ptr }.guid_hash_table);
    let mut bucket_guid_entries: BTreeMap<String, u32> = BTreeMap::new();
    let mut bucket_guid_reg_masks: RegEntryEtwMaskBTreeMap = BTreeMap::new();

    for i in 0..64 {
        let hash_bucket_entry =
            unsafe { first_hash_address.as_ptr().offset(i) } as *const *mut GuidEntry;
        if hash_bucket_entry.is_null() {
            println!("[sanctum] [i] Found null pointer whilst traversing list at index: {i}");
            continue;
        }

        if unsafe { *hash_bucket_entry }.is_null() {
            println!("[sanctum] [i] Found null INNER pointer whilst traversing list at index: {i}");
            continue;
        }

        // Add the current outer entry to the map
        let guid_entry = unsafe { &mut **hash_bucket_entry };
        bucket_guid_entries.insert(
            guid_entry.guid.to_string(),
            guid_entry.provider_enable_info.is_enabled,
        );

        // Look for other GUID entries under this bucket by traversing the linked list until we get back to
        // the beginning
        let first_guid_entry = guid_entry.guid_list.flink as *mut GuidEntry;
        let mut current_guid_entry: *mut GuidEntry = null_mut();

        // Add safety for the list becoming broken
        const MAX_LINKED_LIST_TRIES: usize = 1000;
        let mut i: usize = 0;

        while first_guid_entry != current_guid_entry {
            // Assign the first guid to the current in the event its the first iteration, aka the current is
            // null from the above initialisation.
            if current_guid_entry.is_null() {
                current_guid_entry = first_guid_entry;
            }

            if current_guid_entry.is_null() {
                println!("[sanctum] [-] Current GUID entry is null, which is unexpected.");
                break;
            }

            // Occasionally the GUID entry is invalid - leading to what appears to be a malformed GUID (with no references on Google)
            // and a wildly negative Reference Count, which obviously defeats the purpose of reference counting.
            // We can identify these from entries which have a null silo state pointer; it is unclear **why** these malformed entries
            // exist; but given no pointer to the silo state, we can assume this is a purposeful action by the kernel.
            unsafe {
                if (*(current_guid_entry)).silo_state.is_null() {
                    current_guid_entry = (*current_guid_entry).guid_list.flink as *mut GuidEntry;
                    continue;
                }
            }

            let guid_string = unsafe { (*current_guid_entry).guid.to_string() };
            if let Ok(result) =
                unsafe { populate_all_etw_reg_entry_masks(current_guid_entry, guid_string) }
            {
                for item in result {
                    if let Err(mut entry) = bucket_guid_reg_masks.try_insert(item.0, item.1.clone())
                    {
                        let mut_entry = entry.entry.get_mut();
                        for row in item.1 {
                            mut_entry.insert(row.0, row.1);
                        }
                    }
                }
            }

            let _ = unsafe {
                bucket_guid_entries.insert(
                    (*current_guid_entry).guid.to_string().to_ascii_uppercase(),
                    (*current_guid_entry).provider_enable_info.is_enabled,
                )
            };

            // Walk to the next GUID item
            // SAFETY: Null pointer dereference checked at the top of while loop
            current_guid_entry = unsafe { (*current_guid_entry).guid_list.flink as *mut GuidEntry };

            i += 1;

            if i >= MAX_LINKED_LIST_TRIES {
                println!("[sanctum] [i] Max tries reached enumerating GUID entries.");
                break;
            }
        }
    }

    Ok((bucket_guid_entries, bucket_guid_reg_masks))
}

type RegEntryEtwMaskBTreeMap = BTreeMap<String, BTreeMap<usize, u8>>;

unsafe fn populate_all_etw_reg_entry_masks(
    guid_entry: *const GuidEntry,
    guid_name: String,
) -> Result<RegEntryEtwMaskBTreeMap, ()> {
    let mut etw_reg_entry_dword_masks: RegEntryEtwMaskBTreeMap = BTreeMap::new();

    // We now need to traverse the _ETW_REG_ENTRY linked list for the relevant DWORD field to monitor for tampering
    let first_reg_entry = (*(guid_entry)).reg_list_head.flink as *const EtwRegEntry;

    let mut current_reg_entry: *const EtwRegEntry = null_mut();
    while first_reg_entry != current_reg_entry {
        // Assign the first _ETW_REG_ENTRY to the current in the event its the first iteration, aka the current is
        // null from the above initialisation.
        if current_reg_entry.is_null() {
            current_reg_entry = first_reg_entry;
        }

        if current_reg_entry.is_null() {
            println!("[sanctum] [-] Current _ETW_REG_ENTRY entry is null, which is unexpected.");
            break;
        }

        if (*(current_reg_entry)).reg_list.flink.is_null()
            || (*(current_reg_entry)).reg_list.blink.is_null()
        {
            println!(
                "[sanctum] [i] Flink for next reg list item is null in _ETW_REG_ENTRY: {:p}",
                current_reg_entry
            );
            break;
        }

        // SAFETY: Null pointer checked above
        // Insert the data data into the results> Essentially, what is going on here is we want to index the BTreeMap by the GUID string.
        // However, if we keep inserting by GUID we will just overwrite the map, which we dont want to do. Instead, we want to insert a new
        // BTreeMap if the GUID is present, where the inner BTreeMap contains the address of the reg entry, and the flag value.
        let mut tmp: BTreeMap<usize, u8> = BTreeMap::new();
        tmp.insert(
            current_reg_entry as usize,
            (*current_reg_entry).mask_group_enable,
        );

        if let Err(mut e) =
            etw_reg_entry_dword_masks.try_insert(guid_name.to_ascii_uppercase().clone(), tmp)
        {
            let entry = e.entry.get_mut();
            entry.insert(
                current_reg_entry as usize,
                (*current_reg_entry).mask_group_enable,
            );
        }

        // Walk to the next _ETW_REG_ENTRY item
        // SAFETY: Null pointer dereference checked at the top of while loop
        current_reg_entry = (*current_reg_entry).reg_list.flink as *const _;
    }

    Ok(etw_reg_entry_dword_masks)
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SILODRIVERSTATE
#[repr(C)]
pub struct EtwSiloDriverState {
    pub unused_1: [u8; 0x1d0],
    pub guid_hash_table: [EtwHashBucket; 64],
    pub unused_2: [u8; 0xB8],
    pub settings: EtwSystemLoggerSettings,
    pub unused_3: [u8; 0x38],
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_HASH_BUCKET
#[repr(C)]
#[derive(Debug)]
pub struct EtwHashBucket {
    pub list_head: ListEntry,
    unused: [u8; 0x28], // remaining space we dont need, but we do need them filling out
}

/// https://www.vergiliusproject.com/kernels/x64/windows-11/24h2/_ETW_SYSTEM_LOGGER_SETTINGS
#[repr(C)]
#[derive(Debug)]
struct EtwSystemLoggerSettings {
    unused: [u8; 0xf],
    active_system_loggers: u32,
    unused_2: [u8; 0x160],
}
