// lib.rs — HydraDragon Heuristic Engine
//
// A full Rust port of TinyAntivirus's engine (TinyAvCore), including:
//   - Virtual File System (VFS) traits and implementations
//   - PE file parser (32-bit + 64-bit)
//   - Module / plugin registry
//   - Scanner service with observer pattern
//   - Unicorn-based x86-32 CPU emulator
//   - W32.Sality.PE scan module (SalityKiller port)
//
// Nothing in this crate touches the existing hydradragonav scanner.

pub mod emulator;
pub mod error;
pub mod extract;
pub mod filetype;
pub mod fs;
pub mod module;
pub mod sality;
pub mod scanner;
pub mod unpacker;

// Re-export the most commonly needed types at crate root
pub use emulator::{EmulObserver, EmulateOrigin, Emulator, HookHandle, HookType, UnicornEmulator};
pub use error::{AvError, AvResult};
pub use filetype::{Pe32File, Pe64File, PeFile};
pub use fs::enum_fs::FileFsEnumerator;
pub use fs::file_fs::FileFs;
pub use fs::memory_fs::MemoryFs;
pub use fs::{
    EnumContext, FileAttributes, FsEnumObserver, FsEnumerator, FsFlags, FsStream, FsType,
    MemoryVirtualFs, VirtualFs,
};
pub use module::{Module, ModuleInfo, ModuleRegistry, ModuleType};
pub use sality::SalityModule;
pub use scanner::{
    CleanVerdict, LogScanObserver, NullScanObserver, ScanModule, ScanObserver, ScanResult,
    ScanService, ScanVerdict,
};
