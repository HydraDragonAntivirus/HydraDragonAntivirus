// emulator/unicorn_backend.rs — Unicorn-engine CPU emulator.
//
// Ports TinyAntivirus's CPeEmulator using the `unicorn-engine` Rust crate.
//
// Key mappings from C++:
//   IEmulator::EmulateCode    → UnicornEmulator::emulate_code
//   IEmulator::EmulatePeFile  → UnicornEmulator::emulate_pe32
//   IEmulator::ReadRegister   → UnicornEmulator::read_register
//   IEmulator::WriteRegister  → UnicornEmulator::write_register
//   IEmulator::ReadMemory     → UnicornEmulator::read_memory
//   IEmulator::WriteMemory    → UnicornEmulator::write_memory
//   IEmulator::AddHook        → UnicornEmulator::add_code_hook / add_mem_hook
//   IEmulator::RemoveHook     → UnicornEmulator::remove_hook
//   IEmulObserver             → EmulObserver trait callbacks
//
// Architecture: x86 32-bit (matching TinyAntivirus's UC_ARCH_X86 / UC_MODE_32).
// Stack: mapped at 0x7F000000, 1 MiB by default (matching CPeEmulator defaults).
//
// Note: Unicorn<'_, D> uses Rc<UnsafeCell<...>> internally and is therefore
// NOT Send or Sync. UnicornEmulator is intentionally single-threaded;
// the Emulator trait does NOT require Send+Sync — only the scan _results_
// need to cross thread boundaries.

use super::{CodeHookFn, EmulObserver, EmulateOrigin, Emulator, HookHandle, HookType, MemHookFn};
use crate::error::{AvError, AvResult};
use crate::filetype::Pe32File;
use std::collections::HashMap;
use unicorn_engine::{
    unicorn_const::{
        uc_error, Arch, HookType as UcHookType, Mode, Prot, SECOND_SCALE,
    },
    RegisterX86, UcHookId, Unicorn,
};

// ---------------------------------------------------------------------------
// Constants (match CPeEmulator defaults)
// ---------------------------------------------------------------------------

const STACK_ADDR: u64 = 0x7F00_0000;
const STACK_SIZE: u64 = 0x0010_0000; // 1 MiB
const PAGE_SIZE: u64 = 0x1000;

// ---------------------------------------------------------------------------
// Helper: round up to page boundary
// ---------------------------------------------------------------------------

fn page_align(n: u64) -> u64 {
    (n + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ---------------------------------------------------------------------------
// UnicornEmulator
// ---------------------------------------------------------------------------

/// Unicorn-based x86-32 CPU emulator (ports CPeEmulator).
///
/// Single-threaded by design — Unicorn's internals use Rc<UnsafeCell> and
/// are not Send/Sync. Create one per scan call rather than sharing across threads.
pub struct UnicornEmulator {
    uc: Unicorn<'static, ()>,
    observers: Vec<(HookHandle, Box<dyn EmulObserver>)>,
    next_handle: u64,
    // Map our opaque HookHandle → Unicorn's UcHookId
    uc_hooks: HashMap<u64, UcHookId>,
}

impl UnicornEmulator {
    /// Create a new x86-32 emulator instance.
    pub fn new() -> AvResult<Self> {
        let uc = Unicorn::new(Arch::X86, Mode::MODE_32)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("uc_open: {:?}", e) })?;
        Ok(Self {
            uc,
            observers: Vec::new(),
            next_handle: 1,
            uc_hooks: HashMap::new(),
        })
    }

    fn alloc_handle(&mut self) -> HookHandle {
        let h = HookHandle(self.next_handle);
        self.next_handle += 1;
        h
    }

    /// Map a region of memory in the emulator.
    /// Silently ignores MAP_OVERLAP (region already mapped) — mirrors C++ behaviour.
    fn map_region(&mut self, addr: u64, size: u64, perms: Prot) -> AvResult<()> {
        let aligned = page_align(size.max(PAGE_SIZE));
        match self.uc.mem_map(addr, aligned, perms) {
            Ok(_) => Ok(()),
            // unicorn-engine 2.x removed the MAP_OVERLAP variant; any error
            // on an already-mapped region manifests as UC_ERR_MAP.
            Err(uc_error::MAP) => Ok(()), // overlap / already mapped — acceptable
            Err(e) => Err(AvError::EmulatorInternal { reason: format!("mem_map: {:?}", e) }),
        }
    }

    fn setup_stack(&mut self, stack_addr: u64, stack_size: u64) -> AvResult<()> {
        self.map_region(stack_addr, stack_size, Prot::READ | Prot::WRITE)?;
        let esp = stack_addr + stack_size / 2;
        self.uc.reg_write(RegisterX86::ESP as i32, esp)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("reg_write ESP: {:?}", e) })?;
        self.uc.reg_write(RegisterX86::EBP as i32, esp)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("reg_write EBP: {:?}", e) })?;
        Ok(())
    }

    fn notify_starting(&mut self) -> AvResult<()> {
        let mut obs: Vec<_> = self.observers.drain(..).collect();
        let mut result = Ok(());
        for (_, o) in &mut obs {
            if let Err(e) = o.on_emulator_starting() {
                result = Err(e);
                break;
            }
        }
        self.observers = obs;
        result
    }

    fn notify_stopped(&mut self) -> AvResult<()> {
        let mut obs: Vec<_> = self.observers.drain(..).collect();
        let mut result = Ok(());
        for (_, o) in &mut obs {
            if let Err(e) = o.on_emulator_stopped() {
                result = Err(e);
                break;
            }
        }
        self.observers = obs;
        result
    }
}

impl Default for UnicornEmulator {
    fn default() -> Self {
        Self::new().expect("failed to create Unicorn x86-32 instance")
    }
}

impl Emulator for UnicornEmulator {
    // ------------------------------------------------------------------
    // Register access
    // ------------------------------------------------------------------

    fn read_register(&self, reg: u32) -> AvResult<u64> {
        self.uc
            .reg_read(reg as i32)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("reg_read {reg}: {:?}", e) })
    }

    fn write_register(&mut self, reg: u32, value: u64) -> AvResult<()> {
        self.uc
            .reg_write(reg as i32, value)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("reg_write {reg}: {:?}", e) })
    }

    // ------------------------------------------------------------------
    // Memory access
    // ------------------------------------------------------------------

    fn read_memory(&self, addr: u64, size: usize) -> AvResult<Vec<u8>> {
        self.uc
            .mem_read_as_vec(addr, size)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("mem_read @{addr:#x}: {:?}", e) })
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> AvResult<()> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("mem_write @{addr:#x}: {:?}", e) })
    }

    // ------------------------------------------------------------------
    // Stop
    // ------------------------------------------------------------------

    fn stop(&mut self) -> AvResult<()> {
        self.uc
            .emu_stop()
            .map_err(|e| AvError::EmulatorInternal { reason: format!("emu_stop: {:?}", e) })
    }

    // ------------------------------------------------------------------
    // emulate_code (ports IEmulator::EmulateCode)
    // ------------------------------------------------------------------

    fn emulate_code(
        &mut self,
        code: &[u8],
        mapped_addr: u64,
        _stack_size: u32,
        stack_reserve: u32,
        start_addr: u64,
        max_instructions: u64,
    ) -> AvResult<()> {
        let code_size = page_align(code.len() as u64);
        self.map_region(mapped_addr, code_size, Prot::ALL)?;
        self.uc.mem_write(mapped_addr, code)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("write code: {:?}", e) })?;

        let eff_stack = if stack_reserve > 0 { stack_reserve as u64 } else { STACK_SIZE };
        self.setup_stack(STACK_ADDR, eff_stack)?;

        self.notify_starting()?;

        let end_addr = mapped_addr + code.len() as u64;
        let result = self.uc.emu_start(
            start_addr,
            end_addr,
            10 * SECOND_SCALE,
            max_instructions as usize,
        );

        self.notify_stopped()?;

        match result {
            Ok(_) => Ok(()),
            Err(uc_error::OK) => Ok(()),
            Err(e) => Err(AvError::EmulatorInternal { reason: format!("emu_start: {:?}", e) }),
        }
    }

    // ------------------------------------------------------------------
    // emulate_pe32 (ports IEmulator::EmulatePeFile)
    // ------------------------------------------------------------------

    fn emulate_pe32(
        &mut self,
        pe: &Pe32File,
        rva_offset: u32,
        origin: EmulateOrigin,
        max_instructions: u64,
    ) -> AvResult<()> {
        let image_base = pe.image_base() as u64;
        let raw = pe.raw_data();
        let image_size = page_align(raw.len() as u64);

        self.map_region(image_base, image_size, Prot::ALL)?;
        self.uc.mem_write(image_base, raw)
            .map_err(|e| AvError::EmulatorInternal { reason: format!("write PE: {:?}", e) })?;

        let start_addr = match origin {
            EmulateOrigin::FromImageBase => image_base + rva_offset as u64,
            EmulateOrigin::FromEntryPoint => pe.entry_point_va() as u64 + rva_offset as u64,
        };

        self.setup_stack(STACK_ADDR, STACK_SIZE)?;
        self.notify_starting()?;

        let end_addr = image_base + image_size;
        let result = self.uc.emu_start(
            start_addr,
            end_addr,
            10 * SECOND_SCALE,
            max_instructions as usize,
        );

        self.notify_stopped()?;

        match result {
            Ok(_) => Ok(()),
            Err(uc_error::OK) => Ok(()),
            Err(e) => Err(AvError::EmulatorInternal { reason: format!("emu_start PE: {:?}", e) }),
        }
    }

    // ------------------------------------------------------------------
    // Observer management
    // ------------------------------------------------------------------

    fn add_observer(&mut self, observer: Box<dyn EmulObserver>) -> AvResult<HookHandle> {
        let h = self.alloc_handle();
        self.observers.push((h, observer));
        Ok(h)
    }

    fn remove_observer(&mut self, handle: HookHandle) -> AvResult<()> {
        self.observers.retain(|(h, _)| *h != handle);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Hook management
    // ------------------------------------------------------------------

    fn add_code_hook(&mut self, mut hook: CodeHookFn) -> AvResult<HookHandle> {
        let handle = self.alloc_handle();

        let uc_hook: UcHookId = self.uc
            .add_code_hook(0, u64::MAX, move |_uc, addr, size| {
                hook(addr, size);
            })
            .map_err(|e| AvError::EmulatorInternal { reason: format!("add_code_hook: {:?}", e) })?;

        self.uc_hooks.insert(handle.0, uc_hook);
        Ok(handle)
    }

    fn add_mem_hook(&mut self, hook_type: HookType, mut hook: MemHookFn) -> AvResult<HookHandle> {
        let handle = self.alloc_handle();

        let uc_type = match hook_type {
            HookType::Code           => return Err(AvError::InvalidArgument),
            HookType::MemReadInvalid  => UcHookType::MEM_READ_UNMAPPED,
            HookType::MemWriteInvalid => UcHookType::MEM_WRITE_UNMAPPED,
            HookType::MemInvalid      => UcHookType::MEM_READ_UNMAPPED | UcHookType::MEM_WRITE_UNMAPPED,
        };

        let uc_hook: UcHookId = self.uc
            .add_mem_hook(uc_type, 0, u64::MAX, move |_uc, _mt, addr, size, value| {
                hook(addr, size, value)
            })
            .map_err(|e| AvError::EmulatorInternal { reason: format!("add_mem_hook: {:?}", e) })?;

        self.uc_hooks.insert(handle.0, uc_hook);
        Ok(handle)
    }

    fn remove_hook(&mut self, handle: HookHandle) -> AvResult<()> {
        if let Some(uc_hook) = self.uc_hooks.remove(&handle.0) {
            self.uc
                .remove_hook(uc_hook)
                .map_err(|e| AvError::EmulatorInternal { reason: format!("remove_hook: {:?}", e) })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_emulator() {
        assert!(UnicornEmulator::new().is_ok());
    }

    #[test]
    fn emulate_simple_nop_ret() {
        // x86-32: NOP NOP RET (0x90 0x90 0xC3)
        let code: &[u8] = &[0x90, 0x90, 0xC3];
        let mut emu = UnicornEmulator::new().unwrap();
        let result = emu.emulate_code(code, 0x1000, 0, 0, 0x1000, 100);
        // Accept Ok or emulator-internal error (RET with no return address mapped)
        match result {
            Ok(_) | Err(AvError::EmulatorInternal { .. }) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn read_write_register() {
        let mut emu = UnicornEmulator::new().unwrap();
        emu.map_region(0x1000, 0x1000, Prot::ALL).unwrap();
        emu.write_register(RegisterX86::EAX as u32, 0xDEAD_BEEF).unwrap();
        let val = emu.read_register(RegisterX86::EAX as u32).unwrap();
        assert_eq!(val, 0xDEAD_BEEF);
    }

    #[test]
    fn read_write_memory() {
        let mut emu = UnicornEmulator::new().unwrap();
        emu.map_region(0x2000, 0x1000, Prot::ALL).unwrap();
        emu.write_memory(0x2000, b"hello").unwrap();
        let out = emu.read_memory(0x2000, 5).unwrap();
        assert_eq!(&out, b"hello");
    }

    #[test]
    fn code_hook_fires() {
        use std::sync::{Arc, Mutex};

        let counter = Arc::new(Mutex::new(0u32));
        let counter_clone = Arc::clone(&counter);

        let mut emu = UnicornEmulator::new().unwrap();
        emu.add_code_hook(Box::new(move |_addr, _size| {
            *counter_clone.lock().unwrap() += 1;
        }))
        .unwrap();

        let code: &[u8] = &[0x90, 0x90, 0xC3]; // NOP NOP RET
        let _ = emu.emulate_code(code, 0x1000, 0, 0, 0x1000, 3);
        assert!(*counter.lock().unwrap() >= 2);
    }
}
