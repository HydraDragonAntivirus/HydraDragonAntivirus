//! Where the activities of processes are recorded and calculations of features are done, to feed
//! the input tensors used in the [`crate::predictions`] module.
//!
//! ## A GID is a family of processes
//! Each windows process has a unique parent. However, there are notable differences with Linux:
//! * Process creation is achieved by calling *`CreateProcess`*, which differs from *fork*,
//! * A process can erase its genealogy, and event change its parent!
//! Process Creations are monitored by the minifilter. As all processes are children of *Windows System*,
//! identified by pid == 4, the minifilter defines subfamilies identified by a unique group id
//! (referred to *gid* in the code).
//!
//! ## How is a GID state maintained over time?
//! A [`ProcessRecord`] instance is associated to each *GID* identified by the driver.
//! [`IOMessage`] fetched from the minifilter contains data that
//! are aggregated in real time and used for predictions by the RNN.
//!
//! ## Time is not a good metric
//! Let's consider two scenarios about the performances of the client hardware hosting *Owlyshield*:
//! * It is very fast: we would observe a very quick increase in activity over time, resulting in
//! false-positive
//! * It is very slow: the model would have a bad recall for malwares, as they would have a very slow
//! activity
//!
//! That's why *Owlyshield* uses time-independant metric which is the number of driver messages received
//! from a driver.

use slc_paths::clustering::{Clusters, clustering};
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::ops::Mul;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, SystemTime};
use std::{fmt, thread};

use crate::shared_def::effective_hypervisor_irp_byte;
use crate::shared_def::{
    DriveType,
    DriveType::{CDRom, Remote, Removable},
    FileChangeInfo, FileId, IOMessage, IrpMajorOp,
};

use crate::extensions::ExtensionsCount;
fn normalize_extension_token(extension: &str) -> String {
    extension
        .trim()
        .trim_matches('"')
        .trim_matches(char::from(0))
        .trim_start_matches('.')
        .to_lowercase()
}

fn normalize_path_for_extension_tracking(filepath: &str) -> String {
    filepath.to_lowercase().replace("\\", "/")
}

fn get_parent_path(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let normalized = path.replace("\\", "/");
    let p = Path::new(&normalized);
    if let Some(parent) = p.parent() {
        let ps = parent.to_string_lossy().to_string();
        if ps == "." || ps.is_empty() {
            return None;
        }
        // If the original path had backslashes, return with backslashes to match expectations
        if path.contains('\\') {
            return Some(ps.replace("/", "\\"));
        }
        return Some(ps);
    }
    None
}

fn extract_extension_from_path(filepath: &str) -> String {
    let leaf = filepath.rsplit('/').next().unwrap_or(filepath);
    if let Some((_, tail)) = leaf.rsplit_once('.') {
        return normalize_extension_token(tail);
    }
    String::new()
}

fn extract_effective_extension(msg_extension: &str, filepath: &str) -> String {
    let ext = normalize_extension_token(msg_extension);
    if !ext.is_empty() {
        return ext;
    }
    let normalized_path = normalize_path_for_extension_tracking(filepath);
    extract_extension_from_path(&normalized_path)
}

fn filepath_stem_key(filepath: &str) -> Option<String> {
    let leaf = filepath.rsplit('/').next().unwrap_or(filepath);
    let (stem, _) = leaf.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }

    if let Some((parent, _)) = filepath.rsplit_once('/') {
        if parent.is_empty() {
            Some(stem.to_string())
        } else {
            Some(format!("{}/{}", parent, stem))
        }
    } else {
        Some(stem.to_string())
    }
}

/// GID state in real-time. This is a central structure.
///
/// This struct has several functions:
/// - Store the activity of a gid by aggregating the data received from the driver in real-time
/// - Calculate multiple metrics that will feed the prediction
#[derive(Debug)]
pub struct ProcessRecord {
    /// Main process name.
    pub appname: String,
    /// Group Identifier: a unique number (maintained by the minifilter) identifying this family of precesses.
    pub gid: u64,
    /// Set of pids in this family of processes.
    pub pids: HashSet<u32>,
    /// Count of Read operations [IrpMajorOp::IrpRead]
    pub ops_read: u64,
    /// Count of SetInfo operations [IrpMajorOp::IrpSetInfo]
    pub ops_setinfo: u64,
    /// Count of Write operations [IrpMajorOp::IrpWrite]
    pub ops_written: u64,
    /// Count of Handle Creation operations [IrpMajorOp::IrpCreate]
    pub ops_open: u64,
    /// Total of bytes read
    pub bytes_read: u64,
    /// Total bytes written
    pub bytes_written: u64,
    /// Total entropy read
    pub entropy_read: f64,
    /// Total entropy write
    pub entropy_written: f64,
    /// File descriptors read
    pub files_read: HashSet<FileId>,
    /// File descriptors renamed
    pub files_renamed: HashSet<FileId>,
    /// Last known extension by file id (without leading dot)
    extension_by_file_id: HashMap<FileId, String>,
    /// Last known extension by normalized full path (without leading dot)
    extension_by_path: HashMap<String, String>,
    /// Last known extension by normalized stem path (without leading dot)
    extension_by_stem_path: HashMap<String, String>,
    /// Previous known extension by file id (without leading dot)
    previous_extension_by_file_id: HashMap<FileId, String>,
    /// Previous known extension by normalized full path (without leading dot)
    previous_extension_by_path: HashMap<String, String>,
    /// Previous known extension by normalized stem path (without leading dot)
    previous_extension_by_stem_path: HashMap<String, String>,
    /// File descriptors created
    pub files_opened: HashSet<FileId>,
    /// File descriptors written
    pub files_written: HashSet<FileId>,
    /// File descriptors deleted
    pub files_deleted: HashSet<FileId>,
    /// File paths created
    pub fpaths_created: HashSet<String>,
    /// File paths updated (by a *setinfo* operation)
    pub fpaths_updated: HashSet<String>,
    /// Directories having files created
    pub dirs_with_files_created: HashSet<String>,
    /// Directories having files updated
    pub dirs_with_files_updated: HashSet<String>,
    /// Directories having files opened (a file handle has been created)
    pub dirs_with_files_opened: HashSet<String>,
    /// Unique extensions read count
    pub extensions_read: ExtensionsCount,
    /// Unique extensions written count
    pub extensions_written: ExtensionsCount,
    /// Path to the exe of the main process (the root)
    pub exepath: PathBuf,
    /// Process command line (captured from kernel process-create notification when available)
    pub command_line: String,
    /// Process exe file still exists (father)?
    pub exe_exists: bool,
    /// Process execution state (Running, Suspended, Killed...)
    pub process_state: ProcessState,
    /// Has the process been classified as *malicious*?
    pub is_malicious: bool,
    /// Quarantine requested by behavior engine
    pub quarantine_requested: bool,
    /// Termination requested by behavior engine
    pub termination_requested: bool,
    /// Kernel path deny requested by behavior engine
    pub deny_access_requested: bool,
    /// Suspension requested by behavior engine
    pub suspend_requested: bool,
    /// Remove-on-kill requested by behavior engine
    pub kill_and_remove_requested: bool,
    /// User notification requested by behavior engine
    pub notify_user_requested: bool,
    /// Registry revert requested by behavior engine
    pub revert_requested: bool,
    /// Removal has been queued for the next restart instead of live cleanup.
    pub restart_cleanup_requested: bool,
    /// Name of the rule that was triggered
    pub triggered_rule_name: Option<String>,
    /// Rich detail string describing why the rule matched.
    pub triggered_rule_details: Option<String>,
    /// ML feature vector (feature name -> value) from the fast static ML engine
    /// (fast_detect_file), e.g. is_obfuscated, entropy, suspicious_score. Set
    /// when an ML detection fires so the behavior engine can record and expose
    /// the actual ML features, not just a fabricated detection label.
    pub fast_detection_features: Option<HashMap<String, f32>>,
    /// File artifact selected for direct remediation when it differs from the process image.
    pub remediation_target_path: Option<PathBuf>,
    /// Time of the main process start
    pub time_started: SystemTime,
    /// Time of the main process kill (if malicious)
    pub time_killed: Option<SystemTime>,
    /// Time of process suspended
    pub time_suspended: Option<SystemTime>,
    /// Clusters
    pub clusters: Clusters,
    /// Number of driver messages received for this Gid
    pub driver_msg_count: usize,

    /// Used by [Self::launch_thread_clustering] to communicate with a thread in charge of the heavy computations (clustering).
    tx: Sender<Clusters>,
    /// Used by [Self::launch_thread_clustering
    /// ] to communicate with a thread in charge of the heavy computations (clustering).
    rx: Receiver<Clusters>,
    /// Used by [Self::launch_thread_clustering] to communicate with a thread in charge of the heavy computations (clustering).
    is_thread_clustering_running: bool,
    last_thread_clustering_time: SystemTime,
    last_thread_clustering_duration: Duration,

    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_empty: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_tiny: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_small: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_medium: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_large: HashSet<String>,
    /// Files sorted by size according to steps, with the [sort_file_size](Self::sort_file_size) function.
    pub file_size_huge: HashSet<String>,

    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_empty: Vec<u64>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_tiny: Vec<u64>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_small: Vec<u64>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_medium: Vec<u64>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_large: Vec<u64>,
    /// Number of bytes transferred sorted according to steps, with the [sort_bytes](Self::sort_bytes) function.
    pub bytes_size_huge: Vec<u64>,
    /// Count of Read operations [IrpMajorOp::IrpRead] on a shared (remote) drive
    pub on_shared_drive_read_count: u32,
    /// Count of Write operations [IrpMajorOp::IrpWrite] on a shared (remote) drive
    pub on_shared_drive_write_count: u32,
    /// Count of Read operations [IrpMajorOp::IrpRead] on a removable drive
    pub on_removable_drive_read_count: u32,
    /// Count of Write operations [IrpMajorOp::IrpWrite] on a removable drive
    pub on_removable_drive_write_count: u32,

    // NEW: Kernel-level API hooking event tracking
    /// Count of NtWriteVirtualMemory events
    pub kernel_write_memory_count: u32,
    /// Count of NtAllocateVirtualMemory events
    pub kernel_allocate_memory_count: u32,
    /// Count of NtProtectVirtualMemory events
    pub kernel_protect_memory_count: u32,
    /// Count of NtCreateThreadEx events
    pub kernel_create_thread_count: u32,
    /// Count of NtQueueApcThread events
    pub kernel_queue_apc_count: u32,
    /// Count of NtSetContextThread events
    pub kernel_set_context_count: u32,
    /// Count of ZwCreateSection events
    pub kernel_create_section_count: u32,
    /// Count of ZwMapViewOfSection events
    pub kernel_map_section_count: u32,
    /// Count of NtDeleteFile events
    pub kernel_delete_file_count: u32,
    /// Count of NtLoadDriver events
    pub kernel_load_driver_count: u32,
    /// Count of NtOpenProcess events
    pub kernel_open_process_count: u32,
    /// Total kernel events
    pub kernel_events_total: u32,
    /// Max individual kernel event count
    pub kernel_events_max_individual: u32,

    // NEW: Signature tracking
    /// Is process signed
    pub is_signed: bool,
    /// Has valid signature
    pub has_valid_signature: bool,

    /// Time of execution of the I/O operation
    pub time: SystemTime,
}

impl ProcessRecord {
    /// Create a new ProcessRecord with minimal initialization
    pub fn new(gid: u64, appname: String, exepath: PathBuf) -> ProcessRecord {
        let (tx, rx) = mpsc::channel::<Clusters>();

        ProcessRecord {
            appname,
            gid,
            pids: HashSet::new(),
            ops_read: 0,
            ops_setinfo: 0,
            ops_written: 0,
            ops_open: 0,
            bytes_read: 0,
            bytes_written: 0,
            entropy_read: 0.0,
            entropy_written: 0.0,
            files_read: HashSet::new(),
            files_renamed: HashSet::new(),
            extension_by_file_id: HashMap::new(),
            extension_by_path: HashMap::new(),
            extension_by_stem_path: HashMap::new(),
            previous_extension_by_file_id: HashMap::new(),
            previous_extension_by_path: HashMap::new(),
            previous_extension_by_stem_path: HashMap::new(),
            files_opened: HashSet::new(),
            files_written: HashSet::new(),
            files_deleted: HashSet::new(),
            fpaths_created: HashSet::new(),
            fpaths_updated: HashSet::new(),
            dirs_with_files_created: HashSet::new(),
            dirs_with_files_updated: HashSet::new(),
            dirs_with_files_opened: HashSet::new(),
            extensions_read: ExtensionsCount::new(),
            extensions_written: ExtensionsCount::new(),
            exepath,
            command_line: String::new(),
            exe_exists: true,
            process_state: ProcessState::Running,
            is_malicious: false,
            termination_requested: false,
            quarantine_requested: false,
            deny_access_requested: false,
            suspend_requested: false,
            kill_and_remove_requested: false,
            notify_user_requested: false,
            revert_requested: false,
            restart_cleanup_requested: false,
            triggered_rule_name: None,
            triggered_rule_details: None,
            fast_detection_features: None,
            remediation_target_path: None,
            time_started: SystemTime::now(),
            time_killed: None,
            driver_msg_count: 0,
            clusters: Vec::new(),
            tx,
            rx,
            is_thread_clustering_running: false,
            last_thread_clustering_time: SystemTime::now(),
            last_thread_clustering_duration: Duration::ZERO,
            file_size_empty: HashSet::new(),
            file_size_tiny: HashSet::new(),
            file_size_small: HashSet::new(),
            file_size_medium: HashSet::new(),
            file_size_large: HashSet::new(),
            file_size_huge: HashSet::new(),
            bytes_size_empty: Vec::new(),
            bytes_size_tiny: Vec::new(),
            bytes_size_small: Vec::new(),
            bytes_size_medium: Vec::new(),
            bytes_size_large: Vec::new(),
            bytes_size_huge: Vec::new(),
            time_suspended: None,
            on_shared_drive_read_count: 0,
            on_shared_drive_write_count: 0,
            on_removable_drive_read_count: 0,
            on_removable_drive_write_count: 0,

            // NEW: Initialize kernel event counters
            kernel_write_memory_count: 0,
            kernel_allocate_memory_count: 0,
            kernel_protect_memory_count: 0,
            kernel_create_thread_count: 0,
            kernel_queue_apc_count: 0,
            kernel_set_context_count: 0,
            kernel_create_section_count: 0,
            kernel_map_section_count: 0,
            kernel_delete_file_count: 0,
            kernel_load_driver_count: 0,
            kernel_open_process_count: 0,
            kernel_events_total: 0,
            kernel_events_max_individual: 0,

            // NEW: Initialize signature fields
            is_signed: false,
            has_valid_signature: false,

            time: SystemTime::now(),
        }
    }

    pub fn from(iomsg: &IOMessage, appname: String, exepath: PathBuf) -> ProcessRecord {
        let (tx, rx) = mpsc::channel::<Clusters>();

        ProcessRecord {
            appname,
            gid: iomsg.gid,
            pids: HashSet::new(),
            ops_read: 0,
            ops_setinfo: 0,
            ops_written: 0,
            ops_open: 0,
            bytes_read: 0,
            bytes_written: 0,
            entropy_read: 0.0,
            entropy_written: 0.0,
            files_read: HashSet::new(),
            files_renamed: HashSet::new(),
            extension_by_file_id: HashMap::new(),
            extension_by_path: HashMap::new(),
            extension_by_stem_path: HashMap::new(),
            previous_extension_by_file_id: HashMap::new(),
            previous_extension_by_path: HashMap::new(),
            previous_extension_by_stem_path: HashMap::new(),
            files_opened: HashSet::new(),
            files_written: HashSet::new(),
            files_deleted: HashSet::new(),
            fpaths_created: HashSet::new(),
            fpaths_updated: HashSet::new(),
            dirs_with_files_created: HashSet::new(),
            dirs_with_files_updated: HashSet::new(),
            dirs_with_files_opened: HashSet::new(),
            extensions_read: ExtensionsCount::new(),
            extensions_written: ExtensionsCount::new(),
            exepath,
            command_line: iomsg.runtime_features.command_line.clone(),
            exe_exists: true,
            process_state: ProcessState::Running,
            is_malicious: false,
            termination_requested: false,
            quarantine_requested: false,
            deny_access_requested: false,
            suspend_requested: false,
            kill_and_remove_requested: false,
            notify_user_requested: false,
            revert_requested: false,
            restart_cleanup_requested: false,
            triggered_rule_name: None,
            triggered_rule_details: None,
            fast_detection_features: None,
            remediation_target_path: None,
            time_started: SystemTime::now(),
            time_killed: None,
            driver_msg_count: 0,
            clusters: Vec::new(),
            tx,
            rx,
            is_thread_clustering_running: false,
            last_thread_clustering_time: SystemTime::now(),
            last_thread_clustering_duration: Duration::ZERO,
            file_size_empty: HashSet::new(),
            file_size_tiny: HashSet::new(),
            file_size_small: HashSet::new(),
            file_size_medium: HashSet::new(),
            file_size_large: HashSet::new(),
            file_size_huge: HashSet::new(),
            bytes_size_empty: Vec::new(),
            bytes_size_tiny: Vec::new(),
            bytes_size_small: Vec::new(),
            bytes_size_medium: Vec::new(),
            bytes_size_large: Vec::new(),
            bytes_size_huge: Vec::new(),
            time_suspended: None,
            on_shared_drive_read_count: 0,
            on_shared_drive_write_count: 0,
            on_removable_drive_read_count: 0,
            on_removable_drive_write_count: 0,

            // NEW: Initialize kernel event counters
            kernel_write_memory_count: 0,
            kernel_allocate_memory_count: 0,
            kernel_protect_memory_count: 0,
            kernel_create_thread_count: 0,
            kernel_queue_apc_count: 0,
            kernel_set_context_count: 0,
            kernel_create_section_count: 0,
            kernel_map_section_count: 0,
            kernel_delete_file_count: 0,
            kernel_load_driver_count: 0,
            kernel_open_process_count: 0,
            kernel_events_total: 0,
            kernel_events_max_individual: 0,

            // NEW: Initialize signature fields
            is_signed: false,
            has_valid_signature: false,

            time: iomsg.time,
        }
    }

    pub fn primary_remediation_path(&self) -> &Path {
        self.remediation_target_path
            .as_deref()
            .unwrap_or(self.exepath.as_path())
    }

    pub fn effective_extension_for_event(iomsg: &IOMessage) -> String {
        extract_effective_extension(&iomsg.extension, &iomsg.filepathstr)
    }

    pub fn previous_extension_for_event(&self, iomsg: &IOMessage) -> Option<String> {
        let current_ext = Self::effective_extension_for_event(iomsg);

        if iomsg.file_id_id.0 != 0 {
            if let Some(ext) = self.extension_by_file_id.get(&iomsg.file_id_id) {
                if !ext.is_empty() && ext != &current_ext {
                    return Some(ext.clone());
                }
            }
            if let Some(ext) = self.previous_extension_by_file_id.get(&iomsg.file_id_id) {
                if !ext.is_empty() && ext != &current_ext {
                    return Some(ext.clone());
                }
            }
        }

        let normalized_path = normalize_path_for_extension_tracking(&iomsg.filepathstr);
        if let Some(ext) = self.extension_by_path.get(&normalized_path) {
            if !ext.is_empty() && ext != &current_ext {
                return Some(ext.clone());
            }
        }
        if let Some(ext) = self.previous_extension_by_path.get(&normalized_path) {
            if !ext.is_empty() && ext != &current_ext {
                return Some(ext.clone());
            }
        }

        if let Some(stem_key) = filepath_stem_key(&normalized_path) {
            if let Some(ext) = self.extension_by_stem_path.get(&stem_key) {
                if !ext.is_empty() && ext != &current_ext {
                    return Some(ext.clone());
                }
            }
            if let Some(ext) = self.previous_extension_by_stem_path.get(&stem_key) {
                if !ext.is_empty() && ext != &current_ext {
                    return Some(ext.clone());
                }
            }
        }

        None
    }

    pub fn remember_extension_observation(&mut self, iomsg: &IOMessage, ext_without_dot: &str) {
        if ext_without_dot.is_empty() {
            return;
        }

        const MAX_TRACKED_EXTENSIONS: usize = 16384;
        if iomsg.file_id_id.0 != 0 {
            let old = self
                .extension_by_file_id
                .insert(iomsg.file_id_id, ext_without_dot.to_string());
            if let Some(prev) = old {
                if prev != ext_without_dot {
                    self.previous_extension_by_file_id
                        .insert(iomsg.file_id_id, prev);
                }
            }
            if self.extension_by_file_id.len() > MAX_TRACKED_EXTENSIONS {
                self.extension_by_file_id.clear();
                self.previous_extension_by_file_id.clear();
            }
        }

        let normalized_path = normalize_path_for_extension_tracking(&iomsg.filepathstr);
        let old_path = self
            .extension_by_path
            .insert(normalized_path.clone(), ext_without_dot.to_string());
        if let Some(prev) = old_path {
            if prev != ext_without_dot {
                self.previous_extension_by_path
                    .insert(normalized_path.clone(), prev);
            }
        }
        if self.extension_by_path.len() > MAX_TRACKED_EXTENSIONS {
            self.extension_by_path.clear();
            self.previous_extension_by_path.clear();
        }

        if let Some(stem_key) = filepath_stem_key(&normalized_path) {
            let old_stem = self
                .extension_by_stem_path
                .insert(stem_key.clone(), ext_without_dot.to_string());
            if let Some(prev) = old_stem {
                if prev != ext_without_dot {
                    self.previous_extension_by_stem_path.insert(stem_key, prev);
                }
            }
            if self.extension_by_stem_path.len() > MAX_TRACKED_EXTENSIONS {
                self.extension_by_stem_path.clear();
                self.previous_extension_by_stem_path.clear();
            }
        }
    }

    pub fn has_renamed_file_id(&self, file_id: &FileId) -> bool {
        self.files_renamed.contains(file_id)
    }

    pub fn has_read_file_id(&self, file_id: &FileId) -> bool {
        self.files_read.contains(file_id)
    }

    pub fn has_written_file_id(&self, file_id: &FileId) -> bool {
        self.files_written.contains(file_id)
    }

    fn launch_thread_clustering(&self) {
        let tx = self.tx.to_owned();
        let dir_with_files_u = self.dirs_with_files_updated.clone();
        thread::spawn(move || {
            let cs = clustering(&dir_with_files_u);
            tx.send(cs).unwrap();
        });
    }

    fn update_clusters(&mut self) {
        if self.driver_msg_count.is_multiple_of(100) {
            if self.is_to_cluster() {
                self.launch_thread_clustering();
                self.is_thread_clustering_running = true;
                self.last_thread_clustering_time = SystemTime::now();
            } else {
                let received = self.rx.try_recv();
                if let Ok(clusters) = received {
                    self.last_thread_clustering_duration = self
                        .last_thread_clustering_time
                        .elapsed()
                        .unwrap_or(Duration::ZERO);
                    self.clusters = clusters;
                    self.is_thread_clustering_running = false;
                } else {
                    // println!("Waiting for thread");
                }
            }
        }
    }

    /// Public function to add an IRP record.
    pub fn add_irp_record(&mut self, iomsg: &IOMessage, _av_integration: Option<&mut ()>) {
        self.add_irp_record_common(iomsg);
    }

    /// Private function containing the common logic for processing an IRP record.
    fn add_irp_record_common(&mut self, iomsg: &IOMessage) {
        self.driver_msg_count += 1;
        self.pids.insert(iomsg.pid);
        self.exe_exists = iomsg.runtime_features.exe_still_exists;
        if !iomsg.runtime_features.command_line.trim().is_empty() {
            self.command_line = iomsg.runtime_features.command_line.clone();
        }
        let irp_op = IrpMajorOp::from_sysmonevent(iomsg.irp_op);
        self.update_kernel_event_features(iomsg, &irp_op);
        match irp_op {
            IrpMajorOp::IrpNone => {}
            IrpMajorOp::IrpRead => self.update_read(iomsg),
            IrpMajorOp::IrpWrite => self.update_write(iomsg),
            IrpMajorOp::IrpSetInfo => self.update_set(iomsg),
            IrpMajorOp::IrpCreate => self.update_create(iomsg),
            _ => {}
        }
        let ext = Self::effective_extension_for_event(iomsg);
        self.remember_extension_observation(iomsg, &ext);

        self.update_clusters();
        self.time = iomsg.time;
    }

    fn update_kernel_event_features(&mut self, iomsg: &IOMessage, _raw_irp: &IrpMajorOp) {
        let effective_irp = IrpMajorOp::from_sysmonevent(effective_hypervisor_irp_byte(iomsg));
        // Verbose observability: with VERBOSE_LOGGING=1 each user-mode API hook
        // event is written to owlyshield.jsonl so the actual API calls (and the
        // process that issued them) are visible — otherwise only the hook
        // registration count ("how many apis monitored") is observable.
        if effective_irp == IrpMajorOp::IrpUserModeHookEvent
            && crate::logging::is_verbose_logging_enabled()
        {
            crate::logging::Logging::debug(&format!(
                "[API HOOK] function={} src_pid={} tgt_pid={}",
                iomsg.kernel_event_info.object_name,
                iomsg.kernel_event_info.source_process_id,
                iomsg.kernel_event_info.target_process_id,
            ));
        }
        // The kernel driver delivers API-hook telemetry only to the Owlyshield
        // engine (it is the single usermode fltport/IOCTL client), so edrsvc's
        // OpenEDR pipeline never sees these events. Re-inject each hook event as
        // a JSON LLE_DEVICE_IOCTL event into OpenEDR so PTM rules such as
        // CRYPTO_API_MASS (which key on @event.owlyHook.functionName) can fire.
        if effective_irp == IrpMajorOp::IrpUserModeHookEvent {
            let function = iomsg.kernel_event_info.object_name.replace('\\', "\\\\").replace('"', "\\\"");
            let src = iomsg.kernel_event_info.source_process_id;
            let tgt = iomsg.kernel_event_info.target_process_id;
            let payload = format!(
                "{{\"rawEventId\":12,\"process\":{{\"pid\":{src}}},\"owlyHook\":{{\"eventType\":16,\"functionName\":\"{function}\",\"sourcePid\":{src},\"targetPid\":{tgt},\"arg1\":0,\"arg2\":0,\"arg3\":0,\"arg4\":0}}}}"
            );
            crate::ffi::publish_openedr_event(payload.as_bytes());
        }
        self.record_kernel_event_feature(effective_irp, &iomsg.kernel_event_info.object_name);
    }

    fn record_kernel_event_feature(&mut self, irp_op: IrpMajorOp, event_name: &str) {
        let is_kernel_event = matches!(
            irp_op,
            IrpMajorOp::IrpUserModeHookEvent
                | IrpMajorOp::IrpKernelRemoteThread
                | IrpMajorOp::IrpKernelWriteMemory
                | IrpMajorOp::IrpKernelProtectMemory
                | IrpMajorOp::IrpKernelCreateThread
                | IrpMajorOp::IrpKernelQueueApc
                | IrpMajorOp::IrpKernelCreateSection
                | IrpMajorOp::IrpKernelMapSection
                | IrpMajorOp::IrpRootkitSsdtHook
                | IrpMajorOp::IrpRootkitHiddenProcess
                | IrpMajorOp::IrpRootkitHiddenDriver
                | IrpMajorOp::IrpRootkitKernelHook
                | IrpMajorOp::IrpRootkitTerminateProcess
                | IrpMajorOp::IrpRootkitFileMove
                | IrpMajorOp::IrpRootkitGeneric
                | IrpMajorOp::IrpNamedPipeCreate
                | IrpMajorOp::IrpNamedPipeWrite
        );

        if !is_kernel_event {
            return;
        }

        Self::increment_u32(&mut self.kernel_events_total);

        match irp_op {
            IrpMajorOp::IrpKernelRemoteThread | IrpMajorOp::IrpKernelCreateThread => {
                Self::increment_u32(&mut self.kernel_create_thread_count);
            }
            IrpMajorOp::IrpKernelWriteMemory => {
                Self::increment_u32(&mut self.kernel_write_memory_count);
            }
            IrpMajorOp::IrpKernelProtectMemory => {
                Self::increment_u32(&mut self.kernel_protect_memory_count);
            }
            IrpMajorOp::IrpKernelQueueApc => {
                Self::increment_u32(&mut self.kernel_queue_apc_count);
            }
            IrpMajorOp::IrpKernelCreateSection => {
                Self::increment_u32(&mut self.kernel_create_section_count);
            }
            IrpMajorOp::IrpKernelMapSection => {
                Self::increment_u32(&mut self.kernel_map_section_count);
            }
            IrpMajorOp::IrpUserModeHookEvent => {
                self.increment_kernel_counter_from_event_name(event_name);
            }
            _ => {}
        }

        self.refresh_kernel_events_max_individual();
    }

    fn increment_kernel_counter_from_event_name(&mut self, event_name: &str) {
        let name = event_name.trim().to_ascii_lowercase();
        if name.is_empty() {
            return;
        }

        if name.contains("writevirtualmemory") || name.contains("writeprocessmemory") {
            Self::increment_u32(&mut self.kernel_write_memory_count);
        } else if name.contains("allocatevirtualmemory")
            || name.contains("virtualallocex")
            || name.contains("virtualalloc")
        {
            Self::increment_u32(&mut self.kernel_allocate_memory_count);
        } else if name.contains("protectvirtualmemory")
            || name.contains("virtualprotectex")
            || name.contains("virtualprotect")
        {
            Self::increment_u32(&mut self.kernel_protect_memory_count);
        } else if name.contains("createremotethread")
            || name.contains("createthreadex")
            || name.contains("createthread")
        {
            Self::increment_u32(&mut self.kernel_create_thread_count);
        } else if name.contains("queueapcthread") || name.contains("queueuserapc") {
            Self::increment_u32(&mut self.kernel_queue_apc_count);
        } else if name.contains("setcontextthread") {
            Self::increment_u32(&mut self.kernel_set_context_count);
        } else if name.contains("createsection") {
            Self::increment_u32(&mut self.kernel_create_section_count);
        } else if name.contains("mapviewofsection") || name.contains("mapviewoffile") {
            Self::increment_u32(&mut self.kernel_map_section_count);
        } else if name.contains("deletefile") {
            Self::increment_u32(&mut self.kernel_delete_file_count);
        } else if name.contains("loaddriver") {
            Self::increment_u32(&mut self.kernel_load_driver_count);
        } else if name.contains("openprocess") && !name.contains("token") {
            Self::increment_u32(&mut self.kernel_open_process_count);
        }
    }

    fn increment_u32(value: &mut u32) {
        *value = value.saturating_add(1);
    }

    fn refresh_kernel_events_max_individual(&mut self) {
        let max_counter = [
            self.kernel_write_memory_count,
            self.kernel_allocate_memory_count,
            self.kernel_protect_memory_count,
            self.kernel_create_thread_count,
            self.kernel_queue_apc_count,
            self.kernel_set_context_count,
            self.kernel_create_section_count,
            self.kernel_map_section_count,
            self.kernel_delete_file_count,
            self.kernel_load_driver_count,
            self.kernel_open_process_count,
        ]
        .into_iter()
        .max()
        .unwrap_or(0);

        self.kernel_events_max_individual = self.kernel_events_max_individual.max(max_counter);
        if self.kernel_events_total > 0 && self.kernel_events_max_individual == 0 {
            self.kernel_events_max_individual = 1;
        }
    }

    fn update_read(&mut self, iomsg: &IOMessage) {
        self.ops_read += 1;
        self.bytes_read += iomsg.mem_sized_used;
        self.files_read.insert(iomsg.file_id_id);
        self.extensions_read.add_cat_extension(&iomsg.extension);
        self.entropy_read += iomsg.entropy * (iomsg.mem_sized_used as f64);
        match DriveType::from_filepath(&iomsg.filepathstr) {
            Removable => self.on_removable_drive_read_count += 1,
            Remote => self.on_shared_drive_read_count += 1,
            CDRom => self.on_removable_drive_read_count += 1,
            _ => {}
        }
    }

    fn update_write(&mut self, iomsg: &IOMessage) {
        self.ops_written += 1;
        self.bytes_written += iomsg.mem_sized_used;
        let fpath = iomsg.filepathstr.clone();
        self.fpaths_updated.insert(fpath);
        self.files_written.insert(iomsg.file_id_id);
        if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
            self.dirs_with_files_updated.insert(dir);
        }
        self.extensions_written.add_cat_extension(&iomsg.extension);
        self.entropy_written += iomsg.entropy * (iomsg.mem_sized_used as f64);
        self.sort_bytes(iomsg.mem_sized_used);
        self.sort_file_size(iomsg.file_size, &iomsg.filepathstr);
        match DriveType::from_filepath(&iomsg.filepathstr) {
            Removable => self.on_removable_drive_write_count += 1,
            Remote => self.on_shared_drive_write_count += 1,
            CDRom => self.on_removable_drive_write_count += 1,
            _ => {}
        }
    }

    fn update_set(&mut self, iomsg: &IOMessage) {
        self.ops_setinfo += 1;
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone();
        match file_change_enum {
            Some(FileChangeInfo::ChangeDeleteFile) => {
                self.files_deleted.insert(iomsg.file_id_id);
                self.fpaths_updated.insert(fpath);
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_updated.insert(dir);
                }
            }
            Some(FileChangeInfo::ChangeExtensionChanged) => {
                self.extensions_written.add_cat_extension(&iomsg.extension);

                self.fpaths_updated.insert(fpath);
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_updated.insert(dir);
                }
                self.files_renamed.insert(iomsg.file_id_id);
            }
            Some(FileChangeInfo::ChangeRenameFile) => {
                self.fpaths_updated.insert(fpath);
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_updated.insert(dir);
                }
                self.files_renamed.insert(iomsg.file_id_id);
            }
            _ => {}
        }
    }

    fn update_create(&mut self, iomsg: &IOMessage) {
        self.ops_open += 1;
        self.extensions_written.add_cat_extension(&iomsg.extension);
        let file_change_enum = num::FromPrimitive::from_u8(iomsg.file_change);
        let fpath = iomsg.filepathstr.clone();
        match file_change_enum {
            Some(FileChangeInfo::ChangeNewFile) => {
                self.files_opened.insert(iomsg.file_id_id);
                self.fpaths_created.insert(fpath);
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_created.insert(dir);
                }
            }
            Some(FileChangeInfo::ChangeOverwriteFile) => {
                // File is overwritten
                self.files_opened.insert(iomsg.file_id_id);
            }
            Some(FileChangeInfo::ChangeDeleteFile) => {
                // Opened and deleted on close
                self.files_deleted.insert(iomsg.file_id_id);
                self.fpaths_updated.insert(fpath);
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_updated.insert(dir);
                }
            }
            Some(FileChangeInfo::OpenDirectory) => {
                if let Some(dir) = get_parent_path(&iomsg.filepathstr) {
                    self.dirs_with_files_opened.insert(dir);
                }
            }
            _ => {}
        }
    }

    /// Sorts the number of bytes transferred according to the defined levels:
    /// * Empty    (0 KB)
    /// * Tiny    (0 – 16 KB)
    /// * Small    (16 KB – 1 MB)
    /// * Medium    (1 – 128 MB)
    /// * Large    (128 MB – 1 GB)
    /// * Huge    (> 1 GB)
    fn sort_bytes(&mut self, bytes: u64) {
        if bytes == 0 {
            self.bytes_size_empty.push(0);
        } else if bytes > 0 && bytes <= 16_000 {
            self.bytes_size_tiny.push(bytes);
        } else if bytes > 16_000 && bytes <= 1_000_000 {
            self.bytes_size_small.push(bytes);
        } else if bytes > 1_000_000 && bytes <= 128_000_000 {
            self.bytes_size_medium.push(bytes);
        } else if bytes > 128_000_000 && bytes <= 1_000_000_000 {
            self.bytes_size_large.push(bytes);
        } else if bytes > 1_000_000_000 {
            self.bytes_size_huge.push(bytes);
        }
    }

    /// Sorts the files by size according to the defined levels:
    /// * Empty    (0 KB)
    /// * Tiny    (0 – 16 KB)
    /// * Small    (16 KB – 1 MB)
    /// * Medium    (1 – 128 MB)
    /// * Large    (128 MB – 1 GB)
    /// * Huge    (> 1 GB)
    fn sort_file_size(&mut self, fsize: i64, fpath: &str) {
        if fsize == 0 {
            self.file_size_empty.insert(fpath.to_string());
        } else if fsize > 0 && fsize <= 16_000 {
            self.file_size_tiny.insert(fpath.to_string());
        } else if fsize > 16_000 && fsize <= 1_000_000 {
            self.file_size_small.insert(fpath.to_string());
        } else if fsize > 1_000_000 && fsize <= 128_000_000 {
            self.file_size_medium.insert(fpath.to_string());
        } else if fsize > 128_000_000 && fsize <= 1_000_000_000 {
            self.file_size_large.insert(fpath.to_string());
        } else if fsize > 1_000_000_000 {
            self.file_size_huge.insert(fpath.to_string());
        }
    }

    pub fn is_any_pid_alive(&self) -> bool {
        for p in &self.pids {
            if crate::utils::is_process_alive(*p) {
                return true;
            }
        }
        false
    }

    /// Decides if a new clustering is required. Three parameters are considered:
    /// 1. Is the clustering thread running?
    /// 2. The last clustering time.
    /// 3. The last clustering duration.
    ///
    /// This function is to reduce the frequency of clustering on some applications whose clustering requires a lot of CPU.
    fn is_to_cluster(&self) -> bool {
        if !self.is_thread_clustering_running {
            let multiplicator = 100;
            self.last_thread_clustering_time
                + self.last_thread_clustering_duration.mul(multiplicator)
                <= SystemTime::now()
        } else {
            false
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum ProcessState {
    Running,
    Suspended,
    Terminated,
    RestartCleanupPending,
}

impl fmt::Display for ProcessState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self {
            ProcessState::Running => write!(f, "RUNNING"),
            ProcessState::Suspended => write!(f, "SUSPENDED"),
            ProcessState::Terminated => write!(f, "TERMINATED"),
            ProcessState::RestartCleanupPending => write!(f, "RESTART_CLEANUP_PENDING"),
        }
    }
}

#[cfg(test)]
#[doc(hidden)]
mod tests {
    use crate::extensions::ExtensionCategory::{DocsMedia, Exe};
    use crate::process::{FileId, ProcessRecord};

    use crate::shared_def::KernelEventInfo;
    use crate::shared_def::{FileChangeInfo, IOMessage, IrpMajorOp, RuntimeFeatures};
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::time::SystemTime;

    fn fid(bytes: [u8; 16]) -> FileId {
        let mut full = [0u8; crate::shared_def::FILE_ID_LEN];
        let len = std::cmp::min(16, crate::shared_def::FILE_ID_LEN);
        full[..len].copy_from_slice(&bytes[..len]);
        FileId::from(full)
    }

    fn get_iomsgs() -> Vec<IOMessage> {
        let time = SystemTime::now();
        Vec::from([
            IOMessage {
                extension : String::new(),
                file_id_id : fid([231, 14, 3, 0, 0, 0, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : IrpMajorOp::_IrpCleanUp.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\173C426CDA68AF66D616B5C27D808FD8C6EB89AA".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 10899,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : String::new(),
                file_id_id : fid([184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30108,
                irp_op : IrpMajorOp::_IrpCleanUp.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.icos\DeliveryOptimization\Cache".parse().unwrap(),
                gid : 2008,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([116, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([140, 20, 1, 0, 0, 0, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 94,
                entropy : 5.132623395052655,
                pid : 13192,
                irp_op : IrpMajorOp::IrpWrite.to_sysmonevent_u32(),
                is_entropy_calc : 1,
                file_change : 2,
                file_location_info : 0,
                filepathstr : r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".parse().unwrap(),
                gid : 27,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 61086,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : String::new(),
                file_id_id : fid([241, 14, 3, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 16116,
                entropy : 5.966784127057974,
                pid : 30848,
                irp_op : IrpMajorOp::IrpWrite.to_sysmonevent_u32(),
                is_entropy_calc : 1,
                file_change : 2,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 16184,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([105, 99, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 218070,
                entropy : 2.948640431362244,
                pid : 30108,
                irp_op : IrpMajorOp::IrpRead.to_sysmonevent_u32(),
                is_entropy_calc : 1,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.ico".parse().unwrap(),
                gid : 2008,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 218070,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([101, 120, 101, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([4, 31, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 90112,
                entropy : 5.858913026451287,
                pid : 23812,
                irp_op : IrpMajorOp::IrpRead.to_sysmonevent_u32(),
                is_entropy_calc : 1,
                file_change : 0,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\JetBrains\IntelliJIdea2022.1\tmp\sendctrlc.x64.B37C5E935F3DA60B2940592241F826DA.exe".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 90112,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([99, 88, 14, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : IrpMajorOp::IrpSetInfo.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 6,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\B5C78DC28F7E98EF882C0BA6DC0CCB4FEFF5D25B".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([103, 88, 14, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : IrpMajorOp::IrpSetInfo.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 6,
                file_location_info : 0,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\95858FA1CCC13FA3E7E6D35C7FE6A8CF014CD91F".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : -1,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([17, 69, 8, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30848,
                irp_op : IrpMajorOp::IrpCreate.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 1,
                file_location_info : 1,
                filepathstr : r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2".parse().unwrap(),
                gid : 1883,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 4096,
                time,
                ..IOMessage::default()
            },

            IOMessage {
                extension : unsafe { String::from_utf8_unchecked([105, 99, 111, 0, 0, 0, 0, 0, 0, 0, 0, 0].to_vec()) },
                file_id_id : fid([184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                mem_sized_used : 0,
                entropy : 0.0,
                pid : 30108,
                irp_op : IrpMajorOp::IrpCreate.to_sysmonevent_u32(),
                is_entropy_calc : 0,
                file_change : 0,
                file_location_info : 1,
                filepathstr : r"C:\Program Files\MyProgram\Images\logo-red.ico".parse().unwrap(),
                gid : 2008,
                
                attacker_pid: 0,
                
                attacker_gid: 0,
                runtime_features: RuntimeFeatures::new(),
                file_size : 218070,
                time,
                ..IOMessage::default()
            }
        ])
    }

    fn add_record(pr: &mut ProcessRecord, iomsg: &IOMessage) {
        pr.add_irp_record(iomsg, None::<&mut ()>);
    }

    fn make_file_event(
        irp_op: IrpMajorOp,
        file_change: FileChangeInfo,
        file_id: FileId,
        path: &str,
        extension: &str,
        gid: u64,
        time: SystemTime,
    ) -> IOMessage {
        IOMessage {
            extension: extension.to_string(),
            file_id_id: file_id,
            pid: 4242,
            irp_op: irp_op.to_sysmonevent_u32(),
            file_change: file_change as u8,
            filepathstr: path.to_string(),
            gid,
            runtime_features: RuntimeFeatures::new(),
            file_size: 128,
            time,
            ..IOMessage::default()
        }
    }

    #[test]
    fn test_add_irp_record() {
        let iomsgs = get_iomsgs();
        let mut pr = ProcessRecord::from(&iomsgs[0], "".to_string(), "".parse().unwrap());

        for iomsg in iomsgs {
            pr.add_irp_record(&iomsg, None::<&mut ()>);
        }

        assert_eq!(pr.ops_read, 2);
        assert_eq!(pr.ops_setinfo, 2);
        assert_eq!(pr.ops_written, 2);
        assert_eq!(pr.ops_open, 2);
        assert_eq!(pr.bytes_read, 308182);
        assert_eq!(pr.bytes_written, 16210);
        assert_eq!(pr.entropy_read, 1170968.3895067428);
        assert_eq!(pr.entropy_written, 96643.15959080125);
        assert_eq!(
            pr.files_read,
            HashSet::from([
                fid([184, 45, 0, 0, 0, 0, 114, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                fid([4, 31, 7, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ])
        );
        assert_eq!(pr.files_renamed, HashSet::new());
        assert_eq!(pr.files_opened, HashSet::new());
        assert_eq!(
            pr.files_written,
            HashSet::from([
                fid([241, 14, 3, 0, 0, 0, 28, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                fid([140, 20, 1, 0, 0, 0, 107, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ])
        );
        assert_eq!(
            pr.files_deleted,
            HashSet::from([
                fid([99, 88, 14, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                fid([103, 88, 14, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            ])
        );
        assert_eq!(pr.fpaths_created, HashSet::new());
        assert_eq!(pr.fpaths_updated, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\95858FA1CCC13FA3E7E6D35C7FE6A8CF014CD91F".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\B5C78DC28F7E98EF882C0BA6DC0CCB4FEFF5D25B".to_string() ]));
        assert_eq!(pr.dirs_with_files_created, HashSet::new());
        assert_eq!(pr.dirs_with_files_updated, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries".to_string() ]));
        assert_eq!(
            pr.dirs_with_files_opened,
            HashSet::from([
                r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default"
                    .to_string()
            ])
        );

        assert_eq!(
            pr.extensions_read.categories_set.get(&Exe).unwrap(),
            &HashSet::from(["exe".to_string()])
        );
        assert_eq!(
            pr.extensions_read.categories_set.get(&DocsMedia).unwrap(),
            &HashSet::from(["ico".to_string()])
        );
        assert_eq!(
            pr.extensions_written
                .categories_set
                .get(&DocsMedia)
                .unwrap(),
            &HashSet::from(["txt".to_string(), "ico".to_string()])
        );
        assert_eq!(pr.file_size_empty, HashSet::new());
        assert_eq!(pr.file_size_tiny, HashSet::new());
        assert_eq!(pr.file_size_small, HashSet::from([ r"C:\ProgramData\McAfee\WebAdvisor\WATaskManager.dll\log_0020005F003E001500060033005D.txt".to_string(), r"C:\Users\Dev\AppData\Local\Mozilla\Firefox\Profiles\71ovz528.dev-edition-default\cache2\entries\1291463B146203711386759F4387CBD020F9C25F".to_string() ]));
        assert_eq!(pr.file_size_medium, HashSet::new());
        assert_eq!(pr.file_size_large, HashSet::new());
        assert_eq!(pr.file_size_huge, HashSet::new());
        assert_eq!(pr.bytes_size_empty, Vec::<u64>::new());
        assert_eq!(pr.bytes_size_tiny, [94].to_vec());
        assert_eq!(pr.bytes_size_small, [16116].to_vec());
        assert_eq!(pr.bytes_size_medium, Vec::<u64>::new());
        assert_eq!(pr.bytes_size_large, Vec::<u64>::new());
        assert_eq!(pr.bytes_size_huge, Vec::<u64>::new());
        assert_eq!(pr.on_shared_drive_read_count, 0);
        assert_eq!(pr.on_shared_drive_write_count, 0);
        assert_eq!(pr.on_removable_drive_read_count, 0);
        assert_eq!(pr.on_removable_drive_write_count, 0);
    }

    #[test]
    fn test_create_delete_extension_change_detected_delete_then_create() {
        let gid = 501;
        let time = SystemTime::now();
        let mut pr = ProcessRecord::new(gid, "test.exe".to_string(), PathBuf::new());
        let deleted_msg = make_file_event(
            IrpMajorOp::IrpSetInfo,
            FileChangeInfo::ChangeDeleteFile,
            fid([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\budget.docx",
            "docx",
            gid,
            time,
        );
        let created_msg = make_file_event(
            IrpMajorOp::IrpCreate,
            FileChangeInfo::ChangeNewFile,
            fid([2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\budget.locked",
            "locked",
            gid,
            time,
        );

        add_record(&mut pr, &deleted_msg);
        add_record(&mut pr, &created_msg);

        assert!(pr.previous_extension_for_event(&created_msg).is_some());
    }

    #[test]
    fn test_create_delete_extension_change_detected_create_then_delete() {
        let gid = 502;
        let time = SystemTime::now();
        let mut pr = ProcessRecord::new(gid, "test.exe".to_string(), PathBuf::new());
        let created_msg = make_file_event(
            IrpMajorOp::IrpCreate,
            FileChangeInfo::ChangeNewFile,
            fid([3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\notes.locked",
            "locked",
            gid,
            time,
        );
        let deleted_msg = make_file_event(
            IrpMajorOp::IrpSetInfo,
            FileChangeInfo::ChangeDeleteFile,
            fid([4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\notes.txt",
            "txt",
            gid,
            time,
        );

        add_record(&mut pr, &created_msg);
        add_record(&mut pr, &deleted_msg);

        assert!(pr.previous_extension_for_event(&deleted_msg).is_some());
    }

    #[test]
    fn test_create_delete_extension_change_ignores_same_extension() {
        let gid = 503;
        let time = SystemTime::now();
        let mut pr = ProcessRecord::new(gid, "test.exe".to_string(), PathBuf::new());
        let created_msg = make_file_event(
            IrpMajorOp::IrpCreate,
            FileChangeInfo::ChangeNewFile,
            fid([5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\report.docx",
            "docx",
            gid,
            time,
        );
        let deleted_msg = make_file_event(
            IrpMajorOp::IrpSetInfo,
            FileChangeInfo::ChangeDeleteFile,
            fid([6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            r"C:\Users\Dev\Documents\report.docx",
            "docx",
            gid,
            time,
        );

        add_record(&mut pr, &created_msg);
        add_record(&mut pr, &deleted_msg);

        assert!(pr.previous_extension_for_event(&deleted_msg).is_none());
    }

    #[test]
    fn test_direct_kernel_opcodes_update_prediction_features() {
        let gid = 601;
        let mut pr = ProcessRecord::new(gid, "injector.exe".to_string(), PathBuf::new());
        let write_msg = IOMessage {
            pid: 4242,
            irp_op: IrpMajorOp::IrpKernelWriteMemory.to_sysmonevent_u32(),
            gid,
            runtime_features: RuntimeFeatures::new(),
            ..IOMessage::default()
        };
        let protect_msg = IOMessage {
            pid: 4242,
            irp_op: IrpMajorOp::IrpKernelProtectMemory.to_sysmonevent_u32(),
            gid,
            runtime_features: RuntimeFeatures::new(),
            ..IOMessage::default()
        };

        add_record(&mut pr, &write_msg);
        add_record(&mut pr, &protect_msg);

        assert_eq!(pr.kernel_events_total, 2);
        assert_eq!(pr.kernel_write_memory_count, 1);
        assert_eq!(pr.kernel_protect_memory_count, 1);
        assert_eq!(pr.kernel_events_max_individual, 1);
    }

    #[test]
    fn test_effective_kernel_opcodes_update_prediction_features() {
        let gid = 602;
        let mut pr = ProcessRecord::new(gid, "hooked.exe".to_string(), PathBuf::new());
        let normalized_legacy_msg = IOMessage {
            pid: 4242,
            irp_op: IrpMajorOp::IrpKernelWriteMemory.to_sysmonevent_u32(),
            gid,
            kernel_event_info: KernelEventInfo {
                event_type: IrpMajorOp::IrpKernelWriteMemory.to_sysmonevent_u32(),
                object_name: "IRP_KERNEL_WRITE_MEMORY".to_string(),
                ..KernelEventInfo::default()
            },
            runtime_features: RuntimeFeatures::new(),
            ..IOMessage::default()
        };
        let dynamic_hook_msg = IOMessage {
            pid: 4242,
            irp_op: IrpMajorOp::IrpUserModeHookEvent.to_sysmonevent_u32(),
            gid,
            kernel_event_info: KernelEventInfo {
                event_type: 0x6000,
                object_name: "ntdll.dll!NtProtectVirtualMemory".to_string(),
                ..KernelEventInfo::default()
            },
            runtime_features: RuntimeFeatures::new(),
            ..IOMessage::default()
        };

        add_record(&mut pr, &normalized_legacy_msg);
        add_record(&mut pr, &dynamic_hook_msg);

        assert_eq!(pr.kernel_events_total, 2);
        assert_eq!(pr.kernel_write_memory_count, 1);
        assert_eq!(pr.kernel_protect_memory_count, 1);
        assert_eq!(pr.kernel_events_max_individual, 1);
    }
}
