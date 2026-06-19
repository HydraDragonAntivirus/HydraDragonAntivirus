// fs/mod.rs — Virtual File System traits and flag types.
//
// Ports TinyAntivirus's IVirtualFs, IMemoryFs, IFsAttribute, IFsStream, IFsEnum,
// IFsEnumContext, and IFsEnumObserver interfaces to idiomatic Rust.
//
// Key design differences from the C++ original:
//   - CRefCount / IUnknown → Arc<dyn Trait>
//   - HRESULT               → Result<T, AvError>
//   - BSTR / LPCWSTR        → String / &str / PathBuf
//   - IFsStream             → std::io::{Read, Write, Seek} + FsStream supertrait

pub mod enum_fs;
pub mod file_fs;
pub mod memory_fs;

use crate::error::AvResult;
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Access / creation flags for VFS objects (mirrors IVirtualFs::IFsObjectFlags).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FsFlags: u32 {
        const READ              = 1 << 0;
        const WRITE             = 1 << 1;
        const SHARED_READ       = 1 << 2;
        const SHARED_WRITE      = 1 << 3;
        const SHARED_DELETE     = 1 << 4;
        const CREATE_NEW        = 1 << 5;
        const CREATE_ALWAYS     = 1 << 6;
        const OPEN_ALWAYS       = 1 << 7;
        const OPEN_EXISTING     = 1 << 8;
        const ATTR_NORMAL       = 1 << 9;
        const ATTR_READONLY     = 1 << 10;
        const ATTR_SYSTEM       = 1 << 11;
        const ATTR_HIDDEN       = 1 << 12;
        const ATTR_TEMPORARY    = 1 << 13;
        const ATTR_DELETE_ON_CLOSE = 1 << 14;
        const DEFERRED_CREATION = 1 << 15;
        const DEFERRED_DELETION = 1 << 16;
    }
}

/// VFS object type (mirrors IVirtualFs::IFsType).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsType {
    Unknown,
    Basic,
    Archive,
    Memory,
}

/// Enumeration context flags (mirrors IFsEnumContext::EnumContextFlags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnumContextFlags {
    DetectOnly,
    Disinfect,
}

// ---------------------------------------------------------------------------
// File attributes
// ---------------------------------------------------------------------------

/// Portable file metadata (replaces FILETIME / GetFileAttributes machinery).
#[derive(Debug, Clone)]
pub struct FileAttributes {
    pub size: u64,
    pub is_readonly: bool,
    pub is_hidden: bool,
    pub is_system: bool,
    pub created: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub modified: Option<SystemTime>,
}

// ---------------------------------------------------------------------------
// FsStream supertrait
// ---------------------------------------------------------------------------

/// Combined stream trait: every VFS object that supports streaming must implement
/// this alongside Read + Write + Seek from std::io.
///
/// Ports IFsStream::Shrink (truncate to current position).
pub trait FsStream: Read + Write + Seek + Send + Sync {
    /// Truncate the stream to the current seek position.
    /// Ports IFsStream::Shrink().
    fn shrink(&mut self) -> AvResult<()>;
}

// ---------------------------------------------------------------------------
// VirtualFs trait
// ---------------------------------------------------------------------------

/// Core virtual file-system object trait.
/// Ports IVirtualFs. Arc<dyn VirtualFs> replaces IVirtualFs*/CRefCount.
pub trait VirtualFs: Send + Sync {
    /// Create or open the backing object with the given flags.
    fn create(&mut self, path: &Path, flags: FsFlags) -> AvResult<()>;

    /// Close the backing object.
    fn close(&mut self) -> AvResult<()>;

    /// Re-open / re-attach.
    fn recreate(&mut self, flags: FsFlags) -> AvResult<()>;

    /// Whether the object is currently open.
    fn is_opened(&self) -> bool;

    /// Fully-qualified path of the object.
    fn full_path(&self) -> AvResult<PathBuf>;

    /// File name portion only.
    fn file_name(&self) -> AvResult<String>;

    /// Extension portion only.
    fn file_ext(&self) -> AvResult<String>;

    /// Object kind.
    fn fs_type(&self) -> FsType;

    /// Access flags the object was opened with.
    fn flags(&self) -> FsFlags;

    /// Container (parent archive / directory) if any.
    fn container(&self) -> Option<Arc<dyn VirtualFs>>;

    /// Set the container.
    fn set_container(&mut self, container: Arc<dyn VirtualFs>);

    /// Mark for deferred deletion (delete when closed).
    fn deferred_delete(&mut self) -> AvResult<()>;

    /// Last error code (maps to GetError / SetError).
    fn last_error(&self) -> u32;

    /// Retrieve file attributes.
    fn attributes(&self) -> AvResult<FileAttributes>;

    /// Open a streaming view of this object's bytes.
    /// Returns a boxed FsStream that borrows from the underlying file/buffer.
    fn open_stream(&self) -> AvResult<Box<dyn FsStream>>;
}

// ---------------------------------------------------------------------------
// MemoryVirtualFs trait
// ---------------------------------------------------------------------------

/// Extension for in-memory VFS objects (ports IMemoryFs).
pub trait MemoryVirtualFs: VirtualFs {
    /// Set the backing buffer.
    fn set_buffer(&mut self, data: &[u8]) -> AvResult<()>;

    /// Get the current contents.
    fn get_buffer(&self) -> AvResult<Vec<u8>>;

    /// Size of the backing buffer.
    fn buffer_size(&self) -> AvResult<u64>;
}

// ---------------------------------------------------------------------------
// Enumeration types
// ---------------------------------------------------------------------------

/// Called for each file found during enumeration.
/// Ports IFsEnumObserver.
pub trait FsEnumObserver: Send + Sync {
    /// Called for each file hit. Return `Err(AvError::ScanAborted)` to stop.
    fn on_file_found(
        &self,
        file: Arc<dyn VirtualFs>,
        context: &EnumContext,
        depth: i32,
    ) -> AvResult<()>;

    /// Called when an enumeration error occurs.
    fn on_error(&self, code: u32, message: Option<&str>);
}

/// Enumeration configuration (ports IFsEnumContext).
#[derive(Debug, Clone)]
pub struct EnumContext {
    pub search_root: Option<PathBuf>,
    pub search_pattern: Option<String>,
    pub max_depth: i32,
    pub max_depth_in_archive: i32,
    pub max_file_size: u64,
    pub flags: u32, // EnumContextFlags bitmask
    pub ignore_list: Vec<PathBuf>,
}

impl Default for EnumContext {
    fn default() -> Self {
        Self {
            search_root: None,
            search_pattern: Some("*".into()),
            max_depth: 32,
            max_depth_in_archive: 4,
            max_file_size: u64::MAX,
            flags: 0,
            ignore_list: Vec::new(),
        }
    }
}

impl EnumContext {
    pub fn detect_only() -> Self {
        Self {
            flags: 1, // EnumContextFlags::DetectOnly
            ..Default::default()
        }
    }

    pub fn disinfect() -> Self {
        Self {
            flags: 2, // EnumContextFlags::Disinfect
            ..Default::default()
        }
    }

    pub fn should_disinfect(&self) -> bool {
        self.flags & 2 != 0
    }
}

/// Filesystem enumerator (ports IFsEnum).
pub trait FsEnumerator: Send + Sync {
    fn add_observer(&mut self, observer: Arc<dyn FsEnumObserver>) -> AvResult<()>;
    fn remove_observer(&mut self, observer: &Arc<dyn FsEnumObserver>) -> AvResult<()>;
    fn enumerate(&self, context: &EnumContext) -> AvResult<()>;
    fn stop(&self);
}
