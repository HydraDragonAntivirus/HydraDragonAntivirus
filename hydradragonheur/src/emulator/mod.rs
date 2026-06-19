// emulator/mod.rs — CPU emulator traits.
//
// Ports TinyAntivirus's IEmulator and IEmulObserver interfaces.
// The Unicorn-engine backend is in unicorn_backend.rs.

pub mod unicorn_backend;
pub use unicorn_backend::UnicornEmulator;

use crate::error::AvResult;
use crate::filetype::Pe32File;

// ---------------------------------------------------------------------------
// EmulateOrigin — where to start emulation relative to (ports IEmulator::EmulateOrigin)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulateOrigin {
    /// Start from ImageBase + rvaToStart.
    FromImageBase,
    /// Start from EntryPoint + rvaToStart.
    FromEntryPoint,
}

// ---------------------------------------------------------------------------
// EmulObserver trait (ports IEmulObserver)
// ---------------------------------------------------------------------------

/// Receives emulator lifecycle callbacks.
pub trait EmulObserver: Send + Sync {
    /// Called immediately before emulation begins.
    fn on_emulator_starting(&mut self) -> AvResult<()>;
    /// Called after emulation ends (normally or via StopEmulator).
    fn on_emulator_stopped(&mut self) -> AvResult<()>;
    /// Called when a non-fatal emulator error occurs.
    fn on_error(&mut self, code: u32);
}

// ---------------------------------------------------------------------------
// HookType — mirrors Unicorn's uc_hook_type constants used by TinyAntivirus
// ---------------------------------------------------------------------------

/// Hook types supported by the engine (subset of Unicorn's uc_hook_type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    /// Per-instruction hook (UC_HOOK_CODE).
    Code,
    /// Invalid memory read (UC_HOOK_MEM_READ_UNMAPPED).
    MemReadInvalid,
    /// Invalid memory write (UC_HOOK_MEM_WRITE_UNMAPPED).
    MemWriteInvalid,
    /// Both invalid read and write.
    MemInvalid,
}

// ---------------------------------------------------------------------------
// CodeHook / MemHook callbacks
// ---------------------------------------------------------------------------

/// Called on every instruction that matches a CODE hook.
pub type CodeHookFn = Box<dyn FnMut(u64, u32) + Send + Sync>;

/// Called on invalid memory accesses.
/// Returns true to handle the fault (map memory), false to stop emulation.
pub type MemHookFn = Box<dyn FnMut(u64, usize, i64) -> bool + Send + Sync>;

// ---------------------------------------------------------------------------
// HookHandle — opaque identifier for a registered hook
// ---------------------------------------------------------------------------
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HookHandle(pub u64);

// ---------------------------------------------------------------------------
// Emulator trait (ports IEmulator)
// ---------------------------------------------------------------------------

/// CPU emulator interface (ports IEmulator).
///
/// Implementors: `UnicornEmulator` (unicorn_backend.rs).
/// Note: NOT Send or Sync — Unicorn uses Rc internally. Create per scan call.
pub trait Emulator {
    // ---- Register access ----

    /// Read a CPU register. Register IDs are Unicorn x86 register constants.
    fn read_register(&self, reg: u32) -> AvResult<u64>;

    /// Write a CPU register.
    fn write_register(&mut self, reg: u32, value: u64) -> AvResult<()>;

    // ---- Memory access ----

    /// Read bytes from emulated memory.
    fn read_memory(&self, addr: u64, size: usize) -> AvResult<Vec<u8>>;

    /// Write bytes to emulated memory.
    fn write_memory(&mut self, addr: u64, data: &[u8]) -> AvResult<()>;

    // ---- Emulation control ----

    /// Stop emulation (can be called from inside a hook).
    fn stop(&mut self) -> AvResult<()>;

    /// Emulate a raw code buffer (ports IEmulator::EmulateCode).
    ///
    /// * `code`            — the machine code bytes to emulate
    /// * `mapped_addr`     — the virtual address where code is mapped
    /// * `stack_size`      — stack size in bytes (committed)
    /// * `stack_reserve`   — total stack reservation (mapped region)
    /// * `start_addr`      — address where emulation starts
    /// * `max_instructions`— 0 = run until code finishes
    fn emulate_code(
        &mut self,
        code: &[u8],
        mapped_addr: u64,
        stack_size: u32,
        stack_reserve: u32,
        start_addr: u64,
        max_instructions: u64,
    ) -> AvResult<()>;

    /// Emulate a PE32 file (ports IEmulator::EmulatePeFile).
    ///
    /// Maps the PE image at its preferred load address, sets up a stack,
    /// and begins emulation at `origin + rva_offset`.
    fn emulate_pe32(
        &mut self,
        pe: &Pe32File,
        rva_offset: u32,
        origin: EmulateOrigin,
        max_instructions: u64,
    ) -> AvResult<()>;

    // ---- Observer management ----

    /// Register an emulator observer.
    fn add_observer(&mut self, observer: Box<dyn EmulObserver>) -> AvResult<HookHandle>;

    /// Remove an emulator observer by handle.
    fn remove_observer(&mut self, handle: HookHandle) -> AvResult<()>;

    // ---- Hook management ----

    /// Register a per-instruction code hook. Returns an opaque handle.
    fn add_code_hook(&mut self, hook: CodeHookFn) -> AvResult<HookHandle>;

    /// Register an invalid-memory hook. Returns an opaque handle.
    fn add_mem_hook(&mut self, hook_type: HookType, hook: MemHookFn) -> AvResult<HookHandle>;

    /// Remove a hook (code or mem) by handle.
    fn remove_hook(&mut self, handle: HookHandle) -> AvResult<()>;
}
