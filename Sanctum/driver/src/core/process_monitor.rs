//! # Sanctum Process Monitor
//!
//! The `process_monitor` module implements a Windows-kernel driver component
//! that tracks process lifecycles and applies “ghost-hunting” heuristics to detect
//! syscall-hooking evasion.  
//!
//! For more info on GhostHunting, see my blog post:
//! https://fluxsec.red/edr-syscall-hooking
//!
//! Key features:
//! - Maintains a global map of `Process` metadata  
//! - Spawns a monitoring thread to time syscall events  
//! - Exposes APIs to register new processes, remove exited ones, and feed
//!   Ghost Hunting telemetry

use core::{
    ffi::c_void,
    iter::once,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
    time::Duration,
};

use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use shared_no_std::{
    driver_ipc::ProcessStarted,
    ghost_hunting::{NtFunction, Syscall, SyscallEventSource},
    ioctl::BaseAddressesOfMonitoredDlls,
};
use wdk::{nt_success, println};
use wdk_mutex::{
    errors::GrtError,
    fast_mutex::{FastMutex, FastMutexGuard},
    grt::Grt,
};
use wdk_sys::{
    _EPROCESS, _IO_STACK_LOCATION, _LARGE_INTEGER,
    _MODE::KernelMode,
    HANDLE, LARGE_INTEGER, LIST_ENTRY, OBJ_CASE_INSENSITIVE, OBJ_KERNEL_HANDLE, OBJECT_ATTRIBUTES,
    PIRP, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION, PsProcessType, SECTION_MAP_READ,
    SECTION_QUERY, STATUS_SUCCESS, THREAD_ALL_ACCESS, TRUE, UNICODE_STRING,
    ntddk::{
        IoGetCurrentProcess, KeDelayExecutionThread, KeQuerySystemTimePrecise,
        MmMapViewInSystemSpace, MmUnmapViewInSystemSpace, ObOpenObjectByPointer,
        ObReferenceObjectByHandle, ObfDereferenceObject, PsCreateSystemThread, PsGetProcessId,
        RtlInitUnicodeString, ZwClose, ZwOpenSection,
    },
};

pub use crate::core::process_monitor::process::Process;

use crate::{
    device_comms::IoctlBuffer,
    ffi::{InitializeObjectAttributes, NtQueryInformationProcess},
    response::{ReportEventType, ReportInfo, contain_and_report},
    utils::{
        DriverError, eprocess_to_process_name, get_process_name,
        scan_usermode_module_for_function_address,
    },
};

pub static MONITORED_FN_PTRS: AtomicPtr<MonitoredApis> = AtomicPtr::new(null_mut());

#[derive(Debug)]
pub struct MonitoredApis {
    /// A BTreeMap containing the function's virtual address as a usize,
    /// and a tuple of (dll name, and the API as a [`SensitiveAPI`])
    pub inner: BTreeMap<usize, (String, SensitiveAPI)>,
}

mod process {
    use core::sync::atomic::AtomicBool;

    use alloc::{string::String, vec::Vec};

    use crate::{
        core::process_monitor::{GhostHuntingTimer, LoadedModules, ProcessTargetedApis},
        response::{self, DRIVER_MODE},
    };

    /// A `Process` is a Sanctum driver representation of a Windows process so that actions it preforms, and is performed
    /// onto it, can be tracked and monitored.
    #[derive(Debug, Default)]
    pub struct Process {
        pub pid: u32,
        /// Parent pid
        pub ppid: u32,
        pub process_image: String,
        pub commandline_args: String,
        pub risk_score: u16,
        pub allow_listed: bool, // whether the application is allowed to exist without monitoring
        /// Creates a time window in which a process handle must match from a hooked syscall with
        /// the kernel receiving the notification. Failure to match this may be an indicator of hooked syscall evasion.
        pub ghost_hunting_timers: Vec<GhostHuntingTimer>,
        targeted_by_apis: Vec<ProcessTargetedApis>,
        /// Has the process been marked for termination (not by us, but through naturally terminating)
        pub marked_for_deletion: bool,
        /// Setting this to `true` will allow blocked syscalls to 'complete' but without actually dispatching the syscall.
        /// This marker should not be added when the EDR is in report only mode.
        monitored_syscalls_disallowed: bool,
        // Note: It is possible atm for any processes started before the EDR was switched on that
        // we don't readily have this data. If the driver is loaded as ELAM then this wouldn't be such
        // a problem.
        pub loaded_modules: Option<LoadedModules>,
        pub process_ready_for_ghost_hunting: AtomicBool,
    }

    impl Process {
        pub fn new(pid: u32, ppid: u32, process_image: String, commandline_args: String) -> Self {
            Self {
                pid,
                ppid,
                process_image,
                commandline_args,
                ..Default::default()
            }
        }
        /// Adds a ghost hunt timer specifically to a process.
        ///
        /// This function will internally deal with cases where a timer for the same API already exists. If the timer already exists, it will
        /// use bit flags to
        pub fn add_ghost_hunt_timer(&mut self, new_timer: GhostHuntingTimer) {
            // If the timers are empty; then its the first in so we can add it to the list straight up.
            if self.ghost_hunting_timers.is_empty() {
                self.ghost_hunting_timers.push(new_timer);
                return;
            }

            // Otherwise, there is data in the ghost hunting timers ...
            for (index, timer_iter) in self.ghost_hunting_timers.iter_mut().enumerate() {
                // If the API Origin that this fn relates to is found in the list of cancellable APIs then cancel them out.
                // Part of the core Ghost Hunting logic. First though we need to check that the event type that can cancel it out
                // is present in the active flags (bugs were happening where other events of the same type were being XOR'ed, so if they
                // were previously unset, the flag  was being reset and the process was therefore failing).
                // To get around this we do a bitwise& check before running the XOR in unset_event_flag_in_timer.
                if core::mem::discriminant(&timer_iter.event_type)
                    == core::mem::discriminant(&new_timer.event_type)
                {
                    if timer_iter.origin != new_timer.origin {
                        self.ghost_hunting_timers.remove(index);
                        return;
                    }
                }
            }

            self.ghost_hunting_timers.push(new_timer);
        }

        /// Determines whether the process has outstanding ghost hunting transactions, applied with either a bitflag or not.
        /// For no flags, `None` should be given, which indicates that the caller only wants to know "are there any outstanding
        /// Ghost Hunting timers whatsoever?".
        ///
        /// Should this value be set to `Some`, it should consist of an ORed bitflag indicating which syscalls the caller cares
        /// about checking outstanding Ghost Hunt timers for.
        pub fn has_outstanding_gh_transactions(&self, flags: Option<u64>) -> bool {
            if let Some(flags) = flags {
                let mut active = 0;
                for t in &self.ghost_hunting_timers {
                    active |= t.event_type.as_mask();
                }

                return (active & flags) != 0;
            } else {
                !self.ghost_hunting_timers.is_empty()
            }
        }

        /// Returns whether the process is allowed to proceed with syscalls which are monitored. If badness is detected, before a
        /// process is terminated it is possible for the offending process to make a syscall which leads to something bad happening,
        /// that under [`DriverMode::Blocking`] we can prevent.
        ///
        /// If the EDR is in [`DriverMode::ReportOnly`] mode, this function will always return `false`.
        ///
        /// Otherwise, the function will determine if the halt flag is raised which will block any monitored choke point syscalls.
        pub fn are_syscalls_blocked(&self) -> bool {
            if DRIVER_MODE == response::DriverMode::ReportOnly {
                return true;
            }

            self.monitored_syscalls_disallowed
        }

        /// Raises the flag to prevent dangerous syscalls from completing, usually this should only be used at the point where
        /// we could be in a / near a syscall, but we want to terminate the process. An example of this is where direct/indirect syscalls
        /// are detected; but this could be during the dispatch of sensitive SSN's which are pending.
        ///
        /// If the EDR is set in [`DriverMode::ReportOnly`], this function wll do nothing.
        ///
        /// # Args
        /// The function accepts a `flag` which can be `true` or `false`, as to whether the EDR should block those syscalls. Realistically,
        /// this function will likely only be used with this set to `true`, you should consider the effects of setting this, then unsetting this.
        ///
        /// # Safety
        /// This function is marked as unsafe as it can have profound effects on the system if set to `true` incorrectly. Carefully consider
        /// the effects of blocking system calls if this does not directly lead to process containment.
        pub unsafe fn set_syscall_blocking(&mut self, flag: bool) {
            if DRIVER_MODE == response::DriverMode::Blocking {
                self.monitored_syscalls_disallowed = flag;
            }
        }
    }
}

/// A BTreeMap of loaded modules in the process, with:
///
/// - `key`: Module name
/// `value`: [`LoadedModule`]
#[derive(Debug, Clone)]
pub struct LoadedModules {
    inner: BTreeMap<String, LoadedModule>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum SensitiveAPI {
    LdrLoadDll,
    LoadLibraryA,
    LoadLibraryW,
}

/// A representation of a module loaded into a process.
#[derive(Debug, Clone, Copy)]
pub struct LoadedModule {
    image_base: *const c_void,
    image_sz: usize,
}

impl LoadedModule {
    pub fn new(image_base: *const c_void, image_sz: usize) -> Self {
        Self {
            image_base,
            image_sz,
        }
    }
}

/// Addresses within NTDLL that we care about detecting access to.
#[derive(Debug)]
pub struct NtdllAddresses {
    pub LdrLoadDll: *const c_void,
}

/// Addresses within NTDLL that we care about detecting access to.
#[derive(Debug)]
pub struct Kernel32Addresses {
    pub LoadLibraryW: *const c_void,
    pub LoadLibraryA: *const c_void,
}

// todo needs implementing
#[derive(Debug, Default, Clone)]
pub struct ProcessTargetedApis;

/// A `GhostHuntingTimer` is the timer metadata associated with the Ghost Hunting technique on my blog:
/// https://fluxsec.red/edr-syscall-hooking
///
/// The data contained in this struct allows timers to be polled and detects abuse of direct syscalls / hells gate.
#[derive(Clone)]
pub struct GhostHuntingTimer {
    // Query the time via `KeQuerySystemTime`
    pub timer_start: LARGE_INTEGER,
    pub event_type: NtFunction,
    /// todo update docs
    pub origin: SyscallEventSource,
}

impl ReportInfo for GhostHuntingTimer {
    fn explain(&self) -> String {
        format!(
            "The Ghost Hunting system detected abuse within a process strongly indicating that direct / indirect syscalls \
            are being used. This technique is common for malware which is trying to evade EDR by bypassing mechanisms that the \
            EDR can provide in its DLL. The process should be analysed for indications of malware. The system call and its \
            respective data responsible for this event is: {:?}.",
            self.event_type,
        )
    }

    fn event_type() -> ReportEventType {
        ReportEventType::GhostHunt
    }
}

impl core::fmt::Debug for GhostHuntingTimer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "GhostHuntingTimer: \
            timer_start: {}, \
            event_type: {:?}, \
            origin: {:?}",
            unsafe { self.timer_start.QuadPart },
            self.event_type,
            self.origin,
        )
    }
}

/// The ProcessMonitor is responsible for monitoring all processes running; this
/// structure holds a hashmap of all processes by the pid as an integer, and
/// the data within is a MonitoredProcess containing the details
///
/// The key of processes hashmap is the pid, which is duplicated inside the Process
/// struct.
pub struct ProcessMonitor;

#[derive(Debug)]
pub enum ProcessErrors {
    PidNotFound,
    DuplicatePid,
    BadHandle,
    BadFnAddress,
    BaseAddressNull,
    FailedToWriteMemory,
    FailedToCreateRemoteThread,
    FailedToOpenProcess,
}

impl ProcessMonitor {
    /// Instantiates a new `ProcessMonitor`; which is just an interface for access to the underlying
    /// globally managed mutex via `Grt` (my `wdk-mutex` crate).
    ///
    /// This function should only be called once on driver initialisation.
    ///
    /// The `ProcessMonitor` is required for use in driver callback routines, therefore we can either track via a single
    /// static; or use the `Grt` design pattern (favoured in this case).
    pub fn new() -> Result<(), GrtError> {
        // Walk all processes and add to the proc mon.
        let mut processes = BTreeMap::<u32, Process>::new();
        walk_processes_get_details(&mut processes);

        println!(
            "[sanctum] [i] Process monitor discovered {} processes on start.",
            processes.len()
        );

        Grt::register_fast_mutex("ProcessMonitor", processes)
    }

    pub fn block_syscalls_for_proc(pid: u32) -> bool {
        let process_list = Self::get_mtx_inner();
        if let Some(process) = process_list.get(&pid) {
            return process.are_syscalls_blocked();
        }

        // todo handle the error case where we didn't get a valid mapped process, maybe evidence of
        // rootkit unhooking processes?
        false
    }

    pub fn onboard_new_process(process: &ProcessStarted) -> Result<(), ProcessErrors> {
        let mut process_monitor_lock = ProcessMonitor::get_mtx_inner();

        if process_monitor_lock.get(&process.pid).is_some() {
            return Err(ProcessErrors::DuplicatePid);
        }

        process_monitor_lock.insert(
            process.pid,
            Process::new(
                process.pid,
                process.parent_pid,
                process.image_name.clone(),
                process.command_line.clone(),
            ),
        );

        Ok(())
    }

    pub fn add_loaded_module(lm: LoadedModule, image_name: &String, pid: u32) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        let process = match process_lock.get_mut(&pid) {
            Some(process) => process,
            None => {
                println!(
                    "[sanctum] [-] PID {pid} not found in active processes when trying to add image load info."
                );
                return;
            }
        };

        if let Some(process_loaded_mods) = process.loaded_modules.as_mut() {
            let _ = process_loaded_mods.inner.insert(image_name.clone(), lm);
        } else {
            let mut b = BTreeMap::new();
            b.insert(image_name.clone(), lm);
            process.loaded_modules = Some(LoadedModules { inner: b });
        }
    }

    pub fn fn_pointer_to_sensitive_address(requested_addr: *const c_void) -> Option<SensitiveAPI> {
        let monitored_fn_ptrs = MONITORED_FN_PTRS.load(Ordering::SeqCst);
        if monitored_fn_ptrs.is_null() {
            println!("[sanctum] [-] Monitored fn ptrs was null, this should be reported.");
            // todo send telemetry
            return None;
        }

        if let Some((_, api)) = unsafe { &*monitored_fn_ptrs }
            .inner
            .get(&(requested_addr as usize))
        {
            return Some(*api);
        }

        None
    }

    // todo need to remove processes from the monitor once they are terminated
    pub fn remove_process(pid: u32) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        //
        // We want to remove a process from the monitor only once any pending transactions have been completed.
        // This will ensure that if malware does something bad, which we are waiting on other telemetry for, and the
        // process terminates before we have chance to receive that telemetry, that the incident does not get lost.
        // In the case there are outstanding transactions, we will mark the process for termination; only once all transactions
        // are closed.
        //
        // The logic for monitoring those transactions will be held elsewhere (in the main worker thread for Process Monitoring)
        //

        let process = match process_lock.get_mut(&pid) {
            Some(process) => process,
            None => {
                println!(
                    "[sanctum] [-] PID {pid} not found in active processes when trying to remove process."
                );
                return;
            }
        };

        // If it has outstanding, mark for deletion until those are completed
        if process.has_outstanding_gh_transactions(None) {
            process.marked_for_deletion = true;
            return;
        }

        let _ = process_lock.remove(&pid);
    }

    /// Marks a process as being ready for ghost hunting once everything has been loaded and switched on.
    ///
    /// This function should be called after the Sanctum DLL is loaded into the process, and alt syscalls are turned on
    /// on the image load notification.
    pub fn mark_process_ready_for_ghost_hunting(pid: u32) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            process
                .process_ready_for_ghost_hunting
                .store(true, Ordering::SeqCst);
        }
    }

    pub fn is_sanc_dll_initialised(pid: u32) -> bool {
        let process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get(&pid) {
            return process
                .process_ready_for_ghost_hunting
                .load(Ordering::SeqCst);
        }

        // todo this is an error..
        false
    }

    /// Notifies the Ghost Hunting management that a new huntable event has occurred.
    pub fn ghost_hunt_add_event(signal: Syscall) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&signal.pid) {
            // If the process is not yet ready for ghost hunting (aka the Sanc DLL isn't fully
            // loaded yet)
            if !process
                .process_ready_for_ghost_hunting
                .load(Ordering::SeqCst)
            {
                return;
            }

            // Process is ready for GH, so add..
            println!("[sanctum] [*******] Adding event.. {signal:?}");

            let mut current_time = LARGE_INTEGER::default();
            unsafe { KeQuerySystemTimePrecise(&mut current_time) };

            process.add_ghost_hunt_timer(GhostHuntingTimer {
                timer_start: current_time,
                event_type: signal.data,
                origin: signal.source,
            });
        }
    }

    /// Iterates through the [`ProcessMonitor`] to search for a [`Process`] which is marked for deletion
    /// with no outstanding transactions.
    fn remove_stale_processes() {
        let mut process_lock = ProcessMonitor::get_mtx_inner();
        let mut pids_to_remove: Vec<u32> = Vec::new();

        for (_, process) in process_lock.iter_mut() {
            if process.marked_for_deletion && !process.has_outstanding_gh_transactions(None) {
                pids_to_remove.push(process.pid);
            }
        }

        for pid in pids_to_remove {
            let _ = process_lock.remove(&pid);
        }
    }

    /// This function is responsible for polling all Ghost Hunting timers to try match up hooked syscall API calls
    /// with kernel events sent from our driver.
    ///
    /// This is part of my Ghost Hunting technique https://fluxsec.red/edr-syscall-hooking
    pub fn poll_ghost_timers(max_time_allowed: _LARGE_INTEGER) {
        let mut process_lock = ProcessMonitor::get_mtx_inner();
        let mut processes_to_terminate = Vec::new();

        for (_, process) in process_lock.iter_mut() {
            if process.ghost_hunting_timers.is_empty() {
                continue;
            }

            //
            // Iterate over each Ghost Hunting timer that is active on the process. If the timer exceeds the permitted
            // wait time, aka it appears as though Hells Gate etc is being used, then.. todo.
            //
            // We can use the `extract_if` unstable API for `Vec`
            //

            println!("Number of timers: {}", process.ghost_hunting_timers.len());

            for timer in process.ghost_hunting_timers.extract_if(.., |t| {
                let mut current_time = LARGE_INTEGER::default();
                unsafe { KeQuerySystemTimePrecise(&mut current_time) };

                let time_delta = unsafe { current_time.QuadPart - t.timer_start.QuadPart };
                time_delta > unsafe { max_time_allowed.QuadPart }
            }) {
                println!(
                    "GH timer expired. [{} {}], {timer:?}",
                    process.pid, process.process_image
                );
                processes_to_terminate.push((process.pid, timer.clone()));
            }
        }

        drop(process_lock);

        if !processes_to_terminate.is_empty() {
            for p in processes_to_terminate {
                // respond_to_gh_timer_expiry(p.0, &p.1);
            }
        }
    }

    fn get_mtx_inner<'a>() -> FastMutexGuard<'a, BTreeMap<u32, Process>> {
        // todo rather than panic, ? error
        let process_lock: FastMutexGuard<BTreeMap<u32, Process>> =
            match Grt::get_fast_mutex("ProcessMonitor") {
                Ok(mtx) => match mtx.lock() {
                    Ok(l) => l,
                    Err(e) => {
                        println!(
                            "[-] Error locking KMutex for new process. Panicking. {:?}",
                            e
                        );
                        panic!()
                    }
                },
                Err(e) => {
                    println!("[sanctum] [-] Could not lock fast mutex. {:?}", e);
                    panic!()
                }
            };

        process_lock
    }

    pub fn disallow_syscalls(pid: u32) {
        let mut ps = Self::get_mtx_inner();
        if let Some(p) = ps.get_mut(&pid) {
            unsafe { p.set_syscall_blocking(true) };
        }
    }

    /// Spawns a system thread to poll Ghost Hunting timers and do other work on behalf of the [`ProcessMonitor`].
    ///
    /// # Panics
    /// Panics if thread creation or handle reference fails.
    pub fn start_process_monitor_worker() {
        // Start the thread that will monitor for changes
        let mut thread_handle: HANDLE = null_mut();

        let thread_status = unsafe {
            PsCreateSystemThread(
                &mut thread_handle,
                0,
                null_mut(),
                null_mut(),
                null_mut(),
                Some(process_monitor_worker_thread),
                null_mut(),
            )
        };

        if thread_status != STATUS_SUCCESS {
            println!("[sanctum] [-] Could not create new thread for the process monitor.");
            panic!();
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
                "[sanctum] [-] Could not get thread handle by ObRef.. process monitor not running."
            );
            panic!()
        }

        if Grt::register_fast_mutex("TERMINATION_FLAG_GH_MONITOR", false).is_err() {
            println!(
                "[sanctum] [-] Could not register TERMINATION_FLAG_GH_MONITOR as a FAST_MUTEX, PANICKING."
            );
            panic!()
        }
        if Grt::register_fast_mutex("GH_THREAD_HANDLE", object).is_err() {
            println!(
                "[sanctum] [-] Could not register GH_THREAD_HANDLE as a FAST_MUTEX, PANICKING"
            );
            panic!()
        }
    }

    /// Determines whether the process has outstanding ghost hunting transactions, applied with either a bitflag or not.
    /// For no mask, `None` should be given, which indicates that the caller only wants to know "are there any outstanding
    /// Ghost Hunting timers whatsoever?".
    ///
    /// Should this value be set to `Some`, it should consist of an ORed bitflag indicating which syscalls the caller cares
    /// about checking outstanding Ghost Hunt timers for.
    pub fn process_has_pending_gh_transactions(
        pid: u32,
        mask: Option<u64>,
    ) -> Result<bool, DriverError> {
        let mut process_lock = ProcessMonitor::get_mtx_inner();

        if let Some(process) = process_lock.get_mut(&pid) {
            return Ok(process.has_outstanding_gh_transactions(mask));
        }

        return Err(DriverError::ProcessNotFound);
    }
}

/// Worker thread entry point. Sleeps once per second, polls all `ghost_hunting_timers`, and exits when the driver is unloaded.
unsafe extern "C" fn process_monitor_worker_thread(_: *mut c_void) {
    let delay_as_duration = Duration::from_millis(200);
    let mut thread_sleep_time = LARGE_INTEGER {
        QuadPart: -((delay_as_duration.as_nanos() / 100) as i64),
    };

    let max_time_allowed_for_ghost_hunting_delta = Duration::from_secs(2);
    let max_time_allowed_for_ghost_hunting_delta = LARGE_INTEGER {
        QuadPart: ((max_time_allowed_for_ghost_hunting_delta.as_nanos() / 100) as i64),
    };

    loop {
        let _ =
            unsafe { KeDelayExecutionThread(KernelMode as _, TRUE as _, &mut thread_sleep_time) };

        ProcessMonitor::poll_ghost_timers(max_time_allowed_for_ghost_hunting_delta);
        ProcessMonitor::remove_stale_processes();

        // Check if we have received the cancellation flag, without this check we will get a BSOD. This flag will be
        // set to true on DriverExit.
        if process_monitor_thread_termination_flag_raised() {
            break;
        }
    }
}

fn process_monitor_thread_termination_flag_raised() -> bool {
    let terminate_flag_lock: &FastMutex<bool> =
        match Grt::get_fast_mutex("TERMINATION_FLAG_GH_MONITOR") {
            Ok(lock) => lock,
            Err(e) => {
                // Maybe this should terminate the thread instead? This would be a bad error to have as it means we cannot.
                // instruct the thread to terminate cleanly on driver exit. Or maybe do a count with max tries? We shall see.
                println!(
                    "[sanctum] [-] Error getting fast mutex for TERMINATION_FLAG_GH_MONITOR. {:?}",
                    e
                );
                return false;
            }
        };
    let lock = match terminate_flag_lock.lock() {
        Ok(lock) => lock,
        Err(e) => {
            println!(
                "[sanctum] [-] Failed to lock mutex for terminate_flag_lock/ {:?}",
                e
            );
            return false;
        }
    };

    *lock
}

/// Walk all processes and get [`Process`] details for each process running on the system.
///
/// This function is designed to be run on driver initialisation / setup to record what processes are running at the starting point.
/// It may be possible, during the snapshot, a new process is started and is missed.
fn walk_processes_get_details(processes: &mut BTreeMap<u32, Process>) {
    // Offsets in bytes for Win11 24H2
    const ACTIVE_PROCESS_LINKS_OFFSET: usize = 0x1d8;

    let current_process = unsafe { IoGetCurrentProcess() };
    if current_process.is_null() {
        println!("[sanctum] [-] current_process was NULL");
        return;
    }

    // Get the starting head for the list
    let head =
        unsafe { (current_process as *mut u8).add(ACTIVE_PROCESS_LINKS_OFFSET) } as *mut LIST_ENTRY;
    let mut entry = unsafe { (*head).Flink };

    while entry != head {
        // Get the record for the _EPROCESS
        let p_e_process =
            unsafe { (entry as *mut u8).sub(ACTIVE_PROCESS_LINKS_OFFSET) } as *mut _EPROCESS;

        let pid = unsafe { PsGetProcessId(p_e_process as *mut _) } as usize;

        // We can't get a handle / process details for the System Idle Process
        if pid == 0 {
            entry = unsafe { (*entry).Flink };
            continue;
        }

        // Pull out the process details we need to add to our process list
        let process_details = match extract_process_details(p_e_process, pid) {
            Ok(p) => p,
            Err(e) => {
                println!(
                    "[sanctum] [-] Failed to get process data during process walk. {:?}",
                    e
                );
                entry = unsafe { (*entry).Flink };
                continue;
            }
        };

        let pid = process_details.pid;
        let img = process_details.process_image.clone();
        if processes
            .insert(process_details.pid, process_details)
            .is_some()
        {
            println!(
                "[sanctum] [-] Duplicate pid found whilst walking processes? pid: {}, image: {}",
                pid, img
            );
        }

        entry = unsafe { (*entry).Flink };
    }
}

/// Extracts process details from a given `_EPROCESS`. It collates:
///
/// - pid
/// - parent pid
/// - image name (not full path)
fn extract_process_details<'a>(
    process: *mut _EPROCESS,
    pid: usize,
) -> Result<Process, DriverError> {
    let process_name = eprocess_to_process_name(process as *mut _)?;
    let mut out_sz = 0;

    let mut process_information = PROCESS_BASIC_INFORMATION::default();
    let mut process_handle: HANDLE = null_mut();

    let result = unsafe {
        ObOpenObjectByPointer(
            process as *mut _,
            0,
            null_mut(),
            PROCESS_ALL_ACCESS,
            *PsProcessType,
            KernelMode as _,
            &mut process_handle,
        )
    };

    if !nt_success(result) {
        println!(
            "[sanctum] [-] ObOpenObjectByPointer failed during process walk for pid: {pid}. Error: {:#x}",
            result
        );
        return Err(DriverError::Unknown(
            "Could not open process handle".to_string(),
        ));
    }

    let result = unsafe {
        NtQueryInformationProcess(
            process_handle,
            0,
            &mut process_information as *mut _ as *mut _,
            size_of_val(&process_information) as _,
            &mut out_sz,
        )
    };

    if !nt_success(result) {
        println!(
            "[sanctum] [-] Result of NtQueryInformationProcess was bad. Code: {:#x}. Out sz: {}",
            result, out_sz
        );
        return Err(DriverError::Unknown(
            "Could not query process information".to_string(),
        ));
    }

    let ppid = process_information.InheritedFromUniqueProcessId as u32;

    Ok(Process::new(
        pid as _,
        ppid,
        process_name.to_string(),
        String::new(),
    ))
}

pub fn set_monitored_dll_fn_ptrs(p_stack_location: *mut _IO_STACK_LOCATION, pirp: PIRP) {
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    match ioctl_buffer.receive() {
        Ok(i) => i,
        Err(_) => return,
    };

    let input_data = ioctl_buffer.buf as *const _ as *const BaseAddressesOfMonitoredDlls;
    if input_data.is_null() {
        println!("[sanctum] [-] Error receiving input data for setting monitored DLL addresses.");
        return;
    }

    let input_data: &BaseAddressesOfMonitoredDlls = unsafe { &*input_data };

    let ldr_load_dll_rva =
        extract_monitored_user_fn_ptrs_as_rva(r"\KnownDlls\ntdll.dll", "LdrLoadDll");
    let lla = extract_monitored_user_fn_ptrs_as_rva(r"\KnownDlls\kernel32.dll", "LoadLibraryA");
    let llw = extract_monitored_user_fn_ptrs_as_rva(r"\KnownDlls\kernel32.dll", "LoadLibraryW");

    if ldr_load_dll_rva.is_none() || lla.is_none() || llw.is_none() {
        println!(
            "[sanctum] [!!] FATAL: An expected DLL offset was None. Cannot continue. \
        {ldr_load_dll_rva:?}, {lla:?}, {llw:?}\
        "
        );
        panic!()
    }

    let ldr_load_dll = ldr_load_dll_rva.unwrap() + input_data.ntdll;
    let lla = lla.unwrap() + input_data.kernel32;
    let llw = llw.unwrap() + input_data.kernel32;

    let mut btm = BTreeMap::new();
    btm.insert(
        ldr_load_dll,
        ("ntdll.dll".to_string(), SensitiveAPI::LdrLoadDll),
    );
    btm.insert(
        lla,
        ("kernel32.dll".to_string(), SensitiveAPI::LoadLibraryA),
    );
    btm.insert(
        llw,
        ("kernel32.dll".to_string(), SensitiveAPI::LoadLibraryW),
    );

    let apis = Box::new(MonitoredApis { inner: btm });

    let apis = Box::into_raw(apis);

    MONITORED_FN_PTRS.store(apis, Ordering::SeqCst);
}

fn extract_monitored_user_fn_ptrs_as_rva(path: &str, name: &str) -> Option<usize> {
    let mut handle: *mut c_void = null_mut();
    let u16buf: alloc::vec::Vec<u16> = path.encode_utf16().chain(once(0)).collect();
    let mut us_path = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut us_path, u16buf.as_ptr()) };

    let mut oa: OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES::default();
    if let Err(_) = unsafe {
        InitializeObjectAttributes(
            &mut oa,
            &mut us_path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            null_mut(),
            null_mut(),
        )
    } {
        println!("[sanctum] [-] Error with object attributes.");
        return None;
    }

    let result = unsafe { ZwOpenSection(&mut handle, SECTION_QUERY | SECTION_MAP_READ, &mut oa) };
    if !nt_success(result) {
        println!("[sanctum] [-] Failed to call ZwOpenSection. E: {result:#?}");
        let _ = unsafe { ZwClose(handle) };
        return None;
    }

    let mut section_obj: *mut c_void = null_mut();
    let status = unsafe {
        ObReferenceObjectByHandle(
            handle,
            SECTION_MAP_READ,
            null_mut(),
            KernelMode as _,
            &mut section_obj,
            null_mut(),
        )
    };
    if !nt_success(status) {
        let _ = unsafe { ZwClose(handle) };
        println!("[sanctum] [-] ObReferenceObjectByHandle bad call.");
        return None;
    }

    let mut base: *mut c_void = null_mut();
    let mut view_size: u64 = 0;

    let result = unsafe { MmMapViewInSystemSpace(section_obj, &mut base, &mut view_size) };
    if !nt_success(result) || base.is_null() {
        println!("[sanctum] [-] Failed to call MmMapViewInSystemSpace. E: {result:#?}");
        let _ = unsafe { ObfDereferenceObject(section_obj) };
        let _ = unsafe { ZwClose(handle) };
        return None;
    }

    let result_absolute = unsafe { scan_usermode_module_for_function_address(base, name) };

    let _ = unsafe { MmUnmapViewInSystemSpace(base) };
    let _ = unsafe { ObfDereferenceObject(section_obj) };
    let _ = unsafe { ZwClose(handle) };

    let kernel_absolute = match result_absolute {
        Ok(abs) => abs,
        Err(_) => return None,
    };

    let relative: usize = kernel_absolute as usize - base as usize;

    Some(relative)
}

/// Determines what to do in the case of detecting an expired [`GhostHuntingTimer`], as not all timers are created equal.
/// There are edge cases around certain timers going off which may not inherently be bad behaviour (depending on edge cases
/// as they crop up).
fn respond_to_gh_timer_expiry(pid: u32, timer: &GhostHuntingTimer) {
    match &timer.event_type {
        NtFunction::None => (),
        NtFunction::NtOpenProcess(_)
        | NtFunction::NtWriteVirtualMemory(_)
        | NtFunction::NtAllocateVirtualMemory(_)
        | NtFunction::NtCreateThreadEx(_) => contain_and_report(pid, timer),
    }
}
