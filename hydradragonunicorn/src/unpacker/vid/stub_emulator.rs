use std::{cell::RefCell, collections::HashSet, error::Error, fmt, num::NonZeroUsize};

use unicorn_engine::{
    MemType, RegisterX86, Unicorn,
    unicorn_const::{Arch, HookType, Mode, Prot, uc_error},
};

use super::emulator_source::Architecture;

const PAGE_SIZE: u64 = 0x1000;
const STACK_SIZE: u64 = 0x10_0000;
const X86_STACK_CANDIDATES: &[u64] = &[0x7000_0000, 0x0010_0000, 0x6000_0000, 0x7E00_0000];
const X64_STACK_CANDIDATES: &[u64] = &[
    0x0000_7fff_0000_0000,
    0x0000_7ff0_0000_0000,
    0x0000_0000_1000_0000,
];
const INITIAL_FLAGS: u64 = 0x202;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAccess {
    Read,
    Write,
    InstructionFetch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneralRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
    Esi,
    Edi,
    Ebp,
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl fmt::Display for GeneralRegister {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Eax => "eax",
            Self::Ebx => "ebx",
            Self::Ecx => "ecx",
            Self::Edx => "edx",
            Self::Esi => "esi",
            Self::Edi => "edi",
            Self::Ebp => "ebp",
            Self::Rax => "rax",
            Self::Rbx => "rbx",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::Rbp => "rbp",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::R10 => "r10",
            Self::R11 => "r11",
            Self::R12 => "r12",
            Self::R13 => "r13",
            Self::R14 => "r14",
            Self::R15 => "r15",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegisterReading {
    pub register: GeneralRegister,
    pub bits: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EmulationStop {
    ExternalTransfer {
        destination_address: u64,
        stack_pointer_delta: i64,
        external_return_address: u64,
    },
    UnmappedMemory {
        access: MemoryAccess,
        address: u64,
        byte_count: usize,
    },
    ReturnedToCaller {
        return_address: u64,
        register_readings: Vec<RegisterReading>,
    },
    InstructionLimit {
        instruction_address: u64,
    },
}

#[derive(Debug)]
pub enum EmulationError {
    EmptyModuleSnapshot,
    UnalignedModuleBase(u64),
    AddressOverflow,
    AddressOutsideModule {
        address_name: &'static str,
        address: u64,
    },
    X86AddressOutsideRange(u64),
    StackOverlapsModule,
    Unicorn {
        operation: &'static str,
        source: uc_error,
    },
}

impl EmulationError {
    fn unicorn(operation: &'static str, source: uc_error) -> Self {
        Self::Unicorn { operation, source }
    }
}

impl fmt::Display for EmulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyModuleSnapshot => formatter.write_str("the module snapshot is empty"),
            Self::UnalignedModuleBase(address) => write!(
                formatter,
                "module base 0x{address:x} is not aligned to a Unicorn page"
            ),
            Self::AddressOverflow => formatter.write_str("emulator address arithmetic overflowed"),
            Self::AddressOutsideModule {
                address_name,
                address,
            } => write!(
                formatter,
                "{address_name} 0x{address:x} is outside the module snapshot"
            ),
            Self::X86AddressOutsideRange(address) => {
                write!(
                    formatter,
                    "address 0x{address:x} is outside the x86 address space"
                )
            }
            Self::StackOverlapsModule => {
                formatter.write_str("the synthetic stack overlaps the module snapshot")
            }
            Self::Unicorn { operation, source } => {
                write!(formatter, "{operation}: Unicorn error {source:?}")
            }
        }
    }
}

impl Error for EmulationError {}

pub struct StubEmulator {
    architecture: Architecture,
    module_base: u64,
    module_end: u64,
    mapped_image_size: u64,
    stack_base: u64,
    module_snapshot: Vec<u8>,
    extra_data_regions: Vec<(u64, Vec<u8>)>,
    cached_unicorn: RefCell<Option<Unicorn<'static, ExecutionMonitor>>>,
    mapped_extra_regions: RefCell<Vec<(u64, u64, usize)>>,
}

impl StubEmulator {
    pub fn new(
        architecture: Architecture,
        module_base: u64,
        module_snapshot: Vec<u8>,
    ) -> Result<Self, EmulationError> {
        if module_snapshot.is_empty() {
            return Err(EmulationError::EmptyModuleSnapshot);
        }
        if !module_base.is_multiple_of(PAGE_SIZE) {
            return Err(EmulationError::UnalignedModuleBase(module_base));
        }

        let module_size = module_snapshot.len() as u64;
        let module_end = module_base
            .checked_add(module_size)
            .ok_or(EmulationError::AddressOverflow)?;
        let mapped_image_size = align_up(module_size, PAGE_SIZE)?;
        let mapped_image_end = module_base
            .checked_add(mapped_image_size)
            .ok_or(EmulationError::AddressOverflow)?;

        if architecture == Architecture::X86 && mapped_image_end > u64::from(u32::MAX) + 1 {
            return Err(EmulationError::X86AddressOutsideRange(mapped_image_end - 1));
        }

        let stack_base = select_stack_base(architecture, module_base, mapped_image_end)
            .ok_or(EmulationError::StackOverlapsModule)?;

        Ok(Self {
            architecture,
            module_base,
            module_end,
            mapped_image_size,
            stack_base,
            module_snapshot,
            extra_data_regions: Vec::new(),
            cached_unicorn: RefCell::new(None),
            mapped_extra_regions: RefCell::new(Vec::new()),
        })
    }

    /// Attach non-executable auxiliary data regions (e.g. emulator-allocated heap
    /// buffers populated during unpacking) to be mapped read-write during stub checks.
    pub fn with_extra_data_regions(mut self, regions: Vec<(u64, Vec<u8>)>) -> Self {
        self.extra_data_regions = regions;
        self.cached_unicorn = RefCell::new(None);
        self.mapped_extra_regions = RefCell::new(Vec::new());
        self
    }

    pub fn emulate_stub(
        &self,
        stub_entry_address: u64,
        return_address: Option<u64>,
        instruction_limit: NonZeroUsize,
    ) -> Result<EmulationStop, EmulationError> {
        self.validate_module_address("stub entry address", stub_entry_address)?;
        if let Some(return_address) = return_address {
            self.validate_module_address("return address", return_address)?;
        }

        if self.cached_unicorn.borrow().is_none() {
            let mode = match self.architecture {
                Architecture::X86 => Mode::MODE_32,
                Architecture::X64 => Mode::MODE_64,
            };
            let execution_monitor = ExecutionMonitor {
                module_begin: self.module_base,
                module_end: self.module_end,
                return_address: None,
                stop_reason: None,
                dirty_pages: Vec::new(),
                dirty_page_set: HashSet::new(),
            };
            let mut unicorn = Unicorn::new_with_data(Arch::X86, mode, execution_monitor)
                .map_err(|source| EmulationError::unicorn("cannot create the emulator", source))?;

            unicorn
                .mem_map(self.module_base, self.mapped_image_size, Prot::ALL)
                .map_err(|source| EmulationError::unicorn("cannot map the module snapshot", source))?;
            unicorn
                .mem_write(self.module_base, &self.module_snapshot)
                .map_err(|source| {
                    EmulationError::unicorn("cannot write the module snapshot", source)
                })?;

            unicorn
                .mem_map(self.stack_base, STACK_SIZE, Prot::ALL)
                .map_err(|source| EmulationError::unicorn("cannot map the synthetic stack", source))?;

            let mapped_extra = self.map_extra_data_regions(&mut unicorn);
            *self.mapped_extra_regions.borrow_mut() = mapped_extra;
            install_stop_hooks(&mut unicorn)?;
            install_dirty_write_hook(&mut unicorn)?;
            *self.cached_unicorn.borrow_mut() = Some(unicorn);
        }

        let mut unicorn_ref = self.cached_unicorn.borrow_mut();
        let unicorn = unicorn_ref
            .as_mut()
            .expect("cached Unicorn instance must be initialized");

        let stack_pointer = synthetic_stack_pointer(self.stack_base);
        let run_result = self.run_stub_once(
            unicorn,
            stub_entry_address,
            stack_pointer,
            return_address,
            instruction_limit,
        );
        let restore_result = self.restore_dirty_pages(unicorn);
        match (run_result, restore_result) {
            (Ok(stop), Ok(())) => Ok(stop),
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
        }
    }

    fn run_stub_once(
        &self,
        unicorn: &mut Unicorn<'static, ExecutionMonitor>,
        stub_entry_address: u64,
        stack_pointer: u64,
        return_address: Option<u64>,
        instruction_limit: NonZeroUsize,
    ) -> Result<EmulationStop, EmulationError> {
        {
            let monitor = unicorn.get_data_mut();
            monitor.return_address = return_address;
            monitor.stop_reason = None;
        }

        initialize_registers(unicorn, self.architecture, stack_pointer, return_address)?;
        if return_address.is_some() {
            record_dirty_range(
                unicorn.get_data_mut(),
                stack_pointer,
                self.architecture.pointer_size(),
            );
        }

        let execution = unicorn.emu_start(stub_entry_address, 0, 0, instruction_limit.get());
        if let Some(mut stop_reason) = unicorn.get_data_mut().stop_reason.take() {
            // @note: a protected stub can replace `mov reg, [IAT]` and return the imported
            // address instead of transferring control to it, so capture GPRs at this boundary.
            match &mut stop_reason {
                EmulationStop::ExternalTransfer {
                    stack_pointer_delta,
                    external_return_address,
                    ..
                } => {
                    let final_stack_pointer = read_stack_pointer(unicorn, self.architecture)?;
                    *stack_pointer_delta = i64::try_from(final_stack_pointer)
                        .ok()
                        .and_then(|final_stack_pointer| {
                            i64::try_from(stack_pointer).ok().and_then(|stack_pointer| {
                                final_stack_pointer.checked_sub(stack_pointer)
                            })
                        })
                        .ok_or(EmulationError::AddressOverflow)?;
                    *external_return_address =
                        read_stack_address(unicorn, self.architecture, final_stack_pointer)?;
                }
                EmulationStop::ReturnedToCaller {
                    register_readings, ..
                } => {
                    *register_readings = read_general_registers(unicorn, self.architecture)?;
                }
                EmulationStop::UnmappedMemory { .. } | EmulationStop::InstructionLimit { .. } => {}
            }
            return Ok(stop_reason);
        }
        execution.map_err(|source| {
            EmulationError::unicorn("cannot emulate the protected import stub", source)
        })?;

        let instruction_pointer = instruction_pointer(self.architecture);
        let instruction_address = unicorn.reg_read(instruction_pointer).map_err(|source| {
            EmulationError::unicorn("cannot read the instruction pointer", source)
        })?;
        Ok(EmulationStop::InstructionLimit {
            instruction_address,
        })
    }

    fn restore_dirty_pages(
        &self,
        unicorn: &mut Unicorn<'static, ExecutionMonitor>,
    ) -> Result<(), EmulationError> {
        const ZERO_PAGE: [u8; PAGE_SIZE as usize] = [0u8; PAGE_SIZE as usize];
        let dirty_pages = {
            let monitor = unicorn.get_data_mut();
            monitor.dirty_page_set.clear();
            std::mem::take(&mut monitor.dirty_pages)
        };
        if dirty_pages.is_empty() {
            return Ok(());
        }

        let module_end_mapped = self.module_base + self.mapped_image_size;
        let stack_end = self.stack_base + STACK_SIZE;
        let mapped_extra = self.mapped_extra_regions.borrow();

        for page_addr in dirty_pages {
            if page_addr >= self.module_base && page_addr < module_end_mapped {
                let offset = (page_addr - self.module_base) as usize;
                restore_snapshot_page(unicorn, page_addr, &self.module_snapshot, offset)?;
            } else if page_addr >= self.stack_base && page_addr < stack_end {
                unicorn.mem_write(page_addr, &ZERO_PAGE).map_err(|source| {
                    EmulationError::unicorn("cannot restore dirty synthetic stack page", source)
                })?;
            } else if let Some(&(_base, _end, idx)) = mapped_extra
                .iter()
                .find(|&&(base, end, _)| page_addr >= base && page_addr < end)
            {
                let (base, ref bytes) = self.extra_data_regions[idx];
                let offset = (page_addr - base) as usize;
                restore_snapshot_page(unicorn, page_addr, bytes, offset)?;
            }
        }
        Ok(())
    }

    fn map_extra_data_regions(
        &self,
        unicorn: &mut Unicorn<'_, ExecutionMonitor>,
    ) -> Vec<(u64, u64, usize)> {
        let mut mapped_extra = Vec::new();
        if self.extra_data_regions.is_empty() {
            return mapped_extra;
        }
        let module_end = self.module_base + self.mapped_image_size;
        let stack_end = self.stack_base + STACK_SIZE;
        let mut mapped_ranges: Vec<(u64, u64)> = vec![
            (self.module_base, module_end),
            (self.stack_base, stack_end),
        ];

        for (idx, (base, bytes)) in self.extra_data_regions.iter().enumerate() {
            if bytes.is_empty() || !base.is_multiple_of(PAGE_SIZE) {
                continue;
            }
            let Ok(aligned_len) = align_up(bytes.len() as u64, PAGE_SIZE) else {
                continue;
            };
            let Some(end) = base.checked_add(aligned_len) else {
                continue;
            };
            if self.architecture == Architecture::X86 && end > u64::from(u32::MAX) + 1 {
                continue;
            }
            if mapped_ranges
                .iter()
                .any(|&(r_begin, r_end)| ranges_overlap(*base, end, r_begin, r_end))
            {
                continue;
            }
            if unicorn
                .mem_map(*base, aligned_len, Prot::READ | Prot::WRITE)
                .is_ok()
            {
                let _ = unicorn.mem_write(*base, bytes);
                mapped_ranges.push((*base, end));
                mapped_extra.push((*base, end, idx));
            }
        }
        mapped_extra
    }

    fn validate_module_address(
        &self,
        address_name: &'static str,
        address: u64,
    ) -> Result<(), EmulationError> {
        if (self.module_base..self.module_end).contains(&address) {
            Ok(())
        } else {
            Err(EmulationError::AddressOutsideModule {
                address_name,
                address,
            })
        }
    }
}

struct ExecutionMonitor {
    module_begin: u64,
    module_end: u64,
    return_address: Option<u64>,
    stop_reason: Option<EmulationStop>,
    dirty_pages: Vec<u64>,
    dirty_page_set: HashSet<u64>,
}

fn record_dirty_range(monitor: &mut ExecutionMonitor, address: u64, size: usize) {
    let span = size.max(1) as u64;
    let first_page = address & !(PAGE_SIZE - 1);
    let last_page = address.saturating_add(span - 1) & !(PAGE_SIZE - 1);
    let mut page = first_page;
    loop {
        if monitor.dirty_page_set.insert(page) {
            monitor.dirty_pages.push(page);
        }
        if page >= last_page {
            break;
        }
        page = page.saturating_add(PAGE_SIZE);
    }
}

fn restore_snapshot_page(
    unicorn: &mut Unicorn<'static, ExecutionMonitor>,
    page_addr: u64,
    snapshot: &[u8],
    offset: usize,
) -> Result<(), EmulationError> {
    let page_len = PAGE_SIZE as usize;
    if let Some(full) = snapshot.get(offset..offset + page_len) {
        return unicorn.mem_write(page_addr, full).map_err(|source| {
            EmulationError::unicorn("cannot restore dirty snapshot page", source)
        });
    }
    let mut buf = [0u8; PAGE_SIZE as usize];
    if offset < snapshot.len() {
        let avail = snapshot.len() - offset;
        buf[..avail].copy_from_slice(&snapshot[offset..]);
    }
    unicorn
        .mem_write(page_addr, &buf)
        .map_err(|source| EmulationError::unicorn("cannot restore dirty snapshot page", source))
}

fn initialize_registers(
    unicorn: &mut Unicorn<'_, ExecutionMonitor>,
    architecture: Architecture,
    stack_pointer: u64,
    return_address: Option<u64>,
) -> Result<(), EmulationError> {
    let zero_regs: &[RegisterX86] = match architecture {
        Architecture::X86 => &[
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
            RegisterX86::ESI,
            RegisterX86::EDI,
            RegisterX86::EBP,
        ],
        Architecture::X64 => &[
            RegisterX86::RAX,
            RegisterX86::RBX,
            RegisterX86::RCX,
            RegisterX86::RDX,
            RegisterX86::RSI,
            RegisterX86::RDI,
            RegisterX86::RBP,
            RegisterX86::R8,
            RegisterX86::R9,
            RegisterX86::R10,
            RegisterX86::R11,
            RegisterX86::R12,
            RegisterX86::R13,
            RegisterX86::R14,
            RegisterX86::R15,
        ],
    };
    for &reg in zero_regs {
        unicorn.reg_write(reg, 0).map_err(|source| {
            EmulationError::unicorn("cannot reset general-purpose register", source)
        })?;
    }

    if let Some(return_address) = return_address {
        let return_bytes = match architecture {
            Architecture::X86 => (return_address as u32).to_le_bytes().to_vec(),
            Architecture::X64 => return_address.to_le_bytes().to_vec(),
        };
        unicorn
            .mem_write(stack_pointer, &return_bytes)
            .map_err(|source| {
                EmulationError::unicorn("cannot write the synthetic return address", source)
            })?;
    }

    let stack_pointer_register = match architecture {
        Architecture::X86 => RegisterX86::ESP,
        Architecture::X64 => RegisterX86::RSP,
    };
    unicorn
        .reg_write(stack_pointer_register, stack_pointer)
        .map_err(|source| EmulationError::unicorn("cannot initialize the stack pointer", source))?;
    unicorn
        .reg_write(RegisterX86::EFLAGS, INITIAL_FLAGS)
        .map_err(|source| {
            EmulationError::unicorn("cannot initialize the flags register", source)
        })?;
    Ok(())
}

fn install_dirty_write_hook(
    unicorn: &mut Unicorn<'_, ExecutionMonitor>,
) -> Result<(), EmulationError> {
    unicorn
        .add_mem_hook(
            HookType::MEM_WRITE,
            1,
            0,
            |unicorn, _memory_type, address, size, _write_value| {
                record_dirty_range(unicorn.get_data_mut(), address, size);
                true
            },
        )
        .map(|_| ())
        .map_err(|source| {
            EmulationError::unicorn("cannot install the dirty write hook", source)
        })
}

fn install_stop_hooks(unicorn: &mut Unicorn<'_, ExecutionMonitor>) -> Result<(), EmulationError> {
    unicorn
        .add_code_hook(1, 0, |unicorn, address, _instruction_size| {
            let stop_reason = {
                let execution_monitor = unicorn.get_data();
                if execution_monitor.return_address == Some(address) {
                    Some(EmulationStop::ReturnedToCaller {
                        return_address: address,
                        register_readings: Vec::new(),
                    })
                } else if !address_inside_module(execution_monitor, address) {
                    Some(EmulationStop::ExternalTransfer {
                        destination_address: address,
                        stack_pointer_delta: 0,
                        external_return_address: 0,
                    })
                } else {
                    None
                }
            };

            if let Some(stop_reason) = stop_reason {
                unicorn.get_data_mut().stop_reason = Some(stop_reason);
                let _ = unicorn.emu_stop();
            }
        })
        .map_err(|source| EmulationError::unicorn("cannot install the instruction hook", source))?;

    unicorn
        .add_mem_hook(
            HookType::MEM_INVALID,
            1,
            0,
            |unicorn, memory_type, address, byte_count, _write_value| {
                let stop_reason = if matches!(
                    memory_type,
                    MemType::FETCH_UNMAPPED | MemType::FETCH_PROT
                ) && !address_inside_module(unicorn.get_data(), address)
                {
                    EmulationStop::ExternalTransfer {
                        destination_address: address,
                        stack_pointer_delta: 0,
                        external_return_address: 0,
                    }
                } else {
                    EmulationStop::UnmappedMemory {
                        access: memory_access(memory_type),
                        address,
                        byte_count,
                    }
                };
                unicorn.get_data_mut().stop_reason = Some(stop_reason);
                let _ = unicorn.emu_stop();
                false
            },
        )
        .map_err(|source| EmulationError::unicorn("cannot install the memory hook", source))?;
    Ok(())
}

fn read_general_registers(
    unicorn: &Unicorn<'_, ExecutionMonitor>,
    architecture: Architecture,
) -> Result<Vec<RegisterReading>, EmulationError> {
    let registers: &[(GeneralRegister, RegisterX86)] = match architecture {
        Architecture::X86 => &[
            (GeneralRegister::Eax, RegisterX86::EAX),
            (GeneralRegister::Ebx, RegisterX86::EBX),
            (GeneralRegister::Ecx, RegisterX86::ECX),
            (GeneralRegister::Edx, RegisterX86::EDX),
            (GeneralRegister::Esi, RegisterX86::ESI),
            (GeneralRegister::Edi, RegisterX86::EDI),
            (GeneralRegister::Ebp, RegisterX86::EBP),
        ],
        Architecture::X64 => &[
            (GeneralRegister::Rax, RegisterX86::RAX),
            (GeneralRegister::Rbx, RegisterX86::RBX),
            (GeneralRegister::Rcx, RegisterX86::RCX),
            (GeneralRegister::Rdx, RegisterX86::RDX),
            (GeneralRegister::Rsi, RegisterX86::RSI),
            (GeneralRegister::Rdi, RegisterX86::RDI),
            (GeneralRegister::Rbp, RegisterX86::RBP),
            (GeneralRegister::R8, RegisterX86::R8),
            (GeneralRegister::R9, RegisterX86::R9),
            (GeneralRegister::R10, RegisterX86::R10),
            (GeneralRegister::R11, RegisterX86::R11),
            (GeneralRegister::R12, RegisterX86::R12),
            (GeneralRegister::R13, RegisterX86::R13),
            (GeneralRegister::R14, RegisterX86::R14),
            (GeneralRegister::R15, RegisterX86::R15),
        ],
    };

    registers
        .iter()
        .map(|(register, unicorn_register)| {
            unicorn
                .reg_read(*unicorn_register)
                .map(|bits| RegisterReading {
                    register: *register,
                    bits,
                })
                .map_err(|source| {
                    EmulationError::unicorn("cannot read a general-purpose register", source)
                })
        })
        .collect()
}

fn read_stack_pointer(
    unicorn: &Unicorn<'_, ExecutionMonitor>,
    architecture: Architecture,
) -> Result<u64, EmulationError> {
    let stack_pointer_register = match architecture {
        Architecture::X86 => RegisterX86::ESP,
        Architecture::X64 => RegisterX86::RSP,
    };
    unicorn.reg_read(stack_pointer_register).map_err(|source| {
        EmulationError::unicorn("cannot read the synthetic stack pointer", source)
    })
}

fn read_stack_address(
    unicorn: &Unicorn<'_, ExecutionMonitor>,
    architecture: Architecture,
    stack_pointer: u64,
) -> Result<u64, EmulationError> {
    match architecture {
        Architecture::X86 => {
            let mut bytes = [0_u8; 4];
            unicorn
                .mem_read(stack_pointer, &mut bytes)
                .map_err(|source| {
                    EmulationError::unicorn("cannot read the synthetic stack", source)
                })?;
            Ok(u64::from(u32::from_le_bytes(bytes)))
        }
        Architecture::X64 => {
            let mut bytes = [0_u8; 8];
            unicorn
                .mem_read(stack_pointer, &mut bytes)
                .map_err(|source| {
                    EmulationError::unicorn("cannot read the synthetic stack", source)
                })?;
            Ok(u64::from_le_bytes(bytes))
        }
    }
}

fn memory_access(memory_type: MemType) -> MemoryAccess {
    match memory_type {
        MemType::READ_UNMAPPED | MemType::READ_PROT | MemType::READ | MemType::READ_AFTER => {
            MemoryAccess::Read
        }
        MemType::WRITE_UNMAPPED | MemType::WRITE_PROT | MemType::WRITE => MemoryAccess::Write,
        MemType::FETCH_UNMAPPED | MemType::FETCH_PROT | MemType::FETCH => {
            MemoryAccess::InstructionFetch
        }
    }
}

fn address_inside_module(execution_monitor: &ExecutionMonitor, address: u64) -> bool {
    (execution_monitor.module_begin..execution_monitor.module_end).contains(&address)
}

fn select_stack_base(
    architecture: Architecture,
    module_base: u64,
    mapped_image_end: u64,
) -> Option<u64> {
    let candidates = match architecture {
        Architecture::X86 => X86_STACK_CANDIDATES,
        Architecture::X64 => X64_STACK_CANDIDATES,
    };
    candidates.iter().copied().find(|&candidate| {
        let Some(stack_end) = candidate.checked_add(STACK_SIZE) else {
            return false;
        };
        !ranges_overlap(module_base, mapped_image_end, candidate, stack_end)
    })
}

const fn synthetic_stack_pointer(stack_base: u64) -> u64 {
    stack_base + STACK_SIZE - PAGE_SIZE
}

const fn instruction_pointer(architecture: Architecture) -> RegisterX86 {
    match architecture {
        Architecture::X86 => RegisterX86::EIP,
        Architecture::X64 => RegisterX86::RIP,
    }
}

fn align_up(address: u64, alignment: u64) -> Result<u64, EmulationError> {
    address
        .checked_add(alignment - 1)
        .map(|address| address & !(alignment - 1))
        .ok_or(EmulationError::AddressOverflow)
}

fn ranges_overlap(first_begin: u64, first_end: u64, second_begin: u64, second_end: u64) -> bool {
    first_begin < second_end && second_begin < first_end
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE_BASE: u64 = 0x10_0000;
    const RESUME_ADDRESS: u64 = MODULE_BASE + 0x800;

    #[test]
    fn x86_external_jump_reports_destination() {
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[..7].copy_from_slice(&[0xb8, 0x00, 0x00, 0x00, 0x30, 0xff, 0xe0]);
        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful x86 emulation");

        assert_eq!(
            stop_reason,
            EmulationStop::ExternalTransfer {
                destination_address: 0x3000_0000,
                stack_pointer_delta: 0,
                external_return_address: RESUME_ADDRESS,
            }
        );
    }

    #[test]
    fn external_jump_without_caller_reports_zero_stack_top() {
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[..7].copy_from_slice(&[0xb8, 0x00, 0x00, 0x00, 0x30, 0xff, 0xe0]);
        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                None,
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful x86 emulation");

        assert_eq!(
            stop_reason,
            EmulationStop::ExternalTransfer {
                destination_address: 0x3000_0000,
                stack_pointer_delta: 0,
                external_return_address: 0,
            }
        );
    }

    #[test]
    fn x64_external_jump_reports_destination() {
        const DESTINATION_ADDRESS: u64 = 0x0000_7ffa_1234_5000;
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[..2].copy_from_slice(&[0x48, 0xb8]);
        module_snapshot[2..10].copy_from_slice(&DESTINATION_ADDRESS.to_le_bytes());
        module_snapshot[10..12].copy_from_slice(&[0xff, 0xe0]);
        let emulator = StubEmulator::new(Architecture::X64, MODULE_BASE, module_snapshot)
            .expect("valid x64 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful x64 emulation");

        assert_eq!(
            stop_reason,
            EmulationStop::ExternalTransfer {
                destination_address: DESTINATION_ADDRESS,
                stack_pointer_delta: 0,
                external_return_address: RESUME_ADDRESS,
            }
        );
    }

    #[test]
    fn ret_reports_resume_address() {
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[0] = 0xc3;
        let emulator = StubEmulator::new(Architecture::X64, MODULE_BASE, module_snapshot)
            .expect("valid x64 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful return emulation");

        let EmulationStop::ReturnedToCaller {
            return_address,
            register_readings,
        } = stop_reason
        else {
            panic!("the stub must return to its caller");
        };
        assert_eq!(return_address, RESUME_ADDRESS);
        assert!(
            register_readings
                .iter()
                .all(|register_reading| register_reading.bits == 0)
        );
    }

    #[test]
    fn x86_return_reports_import_address_in_eax() {
        const IMPORT_ADDRESS: u32 = 0x7654_3210;
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[0] = 0xb8;
        module_snapshot[1..5].copy_from_slice(&IMPORT_ADDRESS.to_le_bytes());
        module_snapshot[5] = 0xc3;
        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful x86 emulation");

        let EmulationStop::ReturnedToCaller {
            register_readings, ..
        } = stop_reason
        else {
            panic!("the stub must return to its caller");
        };
        assert!(register_readings.contains(&RegisterReading {
            register: GeneralRegister::Eax,
            bits: u64::from(IMPORT_ADDRESS),
        }));
    }

    #[test]
    fn unmapped_read_reports_address_and_width() {
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[..5].copy_from_slice(&[0xa1, 0x00, 0x00, 0x00, 0x30]);
        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(32).expect("non-zero limit"),
            )
            .expect("successful bounded emulation");

        assert_eq!(
            stop_reason,
            EmulationStop::UnmappedMemory {
                access: MemoryAccess::Read,
                address: 0x3000_0000,
                byte_count: 4,
            }
        );
    }

    #[test]
    fn loop_stops_at_instruction_limit() {
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        module_snapshot[..2].copy_from_slice(&[0xeb, 0xfe]);
        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let stop_reason = emulator
            .emulate_stub(
                MODULE_BASE,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(16).expect("non-zero limit"),
            )
            .expect("successful bounded emulation");

        assert_eq!(
            stop_reason,
            EmulationStop::InstructionLimit {
                instruction_address: MODULE_BASE,
            }
        );
    }

    #[test]
    fn reused_emulator_resets_gprs_and_dirty_module_pages() {
        let mut module_snapshot = vec![0_u8; (PAGE_SIZE as usize) * 2];
        let data_va = (MODULE_BASE + PAGE_SIZE + 0x10) as u32;
        // Orig data dword = 0x1122_3344
        module_snapshot[(PAGE_SIZE as usize) + 0x10..(PAGE_SIZE as usize) + 0x14]
            .copy_from_slice(&0x1122_3344_u32.to_le_bytes());

        // Stub 1 @ MODULE_BASE:
        //   mov dword ptr [data_va], 0xDEAD_BEEF ; c7 05 / modrm mod=00 rm=101 (disp32 in x86)
        //   mov eax, 0x12345678
        //   mov ebx, 0x22222222
        //   push 0x33333333
        //   add esp, 4
        //   ret
        let mut stub1 = Vec::new();
        stub1.extend_from_slice(&[0xC7, 0x05]);
        stub1.extend_from_slice(&data_va.to_le_bytes());
        stub1.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        stub1.push(0xB8);
        stub1.extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        stub1.push(0xBB);
        stub1.extend_from_slice(&0x2222_2222_u32.to_le_bytes());
        stub1.push(0x68);
        stub1.extend_from_slice(&0x3333_3333_u32.to_le_bytes());
        stub1.extend_from_slice(&[0x83, 0xC4, 0x04, 0xC3]);
        module_snapshot[..stub1.len()].copy_from_slice(&stub1);

        // Stub 2 @ MODULE_BASE + 0x100:
        //   mov eax, dword ptr [data_va] ; a1 <disp32>
        //   add eax, ebx                 ; 01 d8 (ebx must have been reset to 0)
        //   ret                          ; c3
        let stub2 = [
            0xA1,
            data_va as u8,
            (data_va >> 8) as u8,
            (data_va >> 16) as u8,
            (data_va >> 24) as u8,
            0x01,
            0xD8,
            0xC3,
        ];
        module_snapshot[0x100..0x100 + stub2.len()].copy_from_slice(&stub2);

        let emulator = StubEmulator::new(Architecture::X86, MODULE_BASE, module_snapshot)
            .expect("valid x86 emulator");

        let s1 = emulator
            .emulate_stub(MODULE_BASE, Some(RESUME_ADDRESS), NonZeroUsize::new(64).unwrap())
            .expect("stub 1 ok");
        assert!(matches!(s1, EmulationStop::ReturnedToCaller { .. }));

        let s2 = emulator
            .emulate_stub(
                MODULE_BASE + 0x100,
                Some(RESUME_ADDRESS + 4),
                NonZeroUsize::new(64).unwrap(),
            )
            .expect("stub 2 ok");
        let EmulationStop::ReturnedToCaller {
            return_address,
            register_readings,
        } = s2
        else {
            panic!("stub 2 must return to caller: {s2:?}");
        };
        assert_eq!(return_address, RESUME_ADDRESS + 4);
        assert!(register_readings.contains(&RegisterReading {
            register: GeneralRegister::Eax,
            bits: 0x1122_3344,
        }));
        assert!(register_readings.contains(&RegisterReading {
            register: GeneralRegister::Ebx,
            bits: 0,
        }));
    }

    #[test]
    fn reused_emulator_restores_dirty_extra_region_pages() {
        const EXTRA_BASE: u64 = 0x2000_0000;
        let mut module_snapshot = vec![0_u8; PAGE_SIZE as usize];
        // Stub 1 @ MODULE_BASE: write 0xCAFEBABE to [EXTRA_BASE+8], set rbx=0x99, ret
        let mut stub1 = Vec::new();
        stub1.extend_from_slice(&[0x48, 0xB8]); // mov rax, EXTRA_BASE+8
        stub1.extend_from_slice(&(EXTRA_BASE + 8).to_le_bytes());
        stub1.extend_from_slice(&[0xC7, 0x00]); // mov dword ptr [rax], 0xCAFEBABE
        stub1.extend_from_slice(&0xCAFE_BABE_u32.to_le_bytes());
        stub1.extend_from_slice(&[0x48, 0xC7, 0xC3, 0x99, 0x00, 0x00, 0x00]); // mov rbx, 0x99
        stub1.push(0xC3); // ret
        module_snapshot[..stub1.len()].copy_from_slice(&stub1);

        // Stub 2 @ MODULE_BASE + 0x100: read [EXTRA_BASE+8] into eax, add eax, ebx, ret
        let mut stub2 = Vec::new();
        stub2.extend_from_slice(&[0x48, 0xB8]);
        stub2.extend_from_slice(&(EXTRA_BASE + 8).to_le_bytes());
        stub2.extend_from_slice(&[0x8B, 0x00]); // mov eax, [rax]
        stub2.extend_from_slice(&[0x01, 0xD8, 0xC3]); // add eax, ebx; ret
        module_snapshot[0x100..0x100 + stub2.len()].copy_from_slice(&stub2);

        let mut extra_page = vec![0_u8; PAGE_SIZE as usize];
        extra_page[8..12].copy_from_slice(&0x5566_7788_u32.to_le_bytes());

        let emulator = StubEmulator::new(Architecture::X64, MODULE_BASE, module_snapshot)
            .expect("valid x64 emulator")
            .with_extra_data_regions(vec![(EXTRA_BASE, extra_page)]);

        let _ = emulator
            .emulate_stub(MODULE_BASE, Some(RESUME_ADDRESS), NonZeroUsize::new(64).unwrap())
            .expect("stub 1 ok");
        let s2 = emulator
            .emulate_stub(
                MODULE_BASE + 0x100,
                Some(RESUME_ADDRESS),
                NonZeroUsize::new(64).unwrap(),
            )
            .expect("stub 2 ok");
        let EmulationStop::ReturnedToCaller {
            register_readings, ..
        } = s2
        else {
            panic!("stub 2 must return to caller: {s2:?}");
        };
        assert!(register_readings.contains(&RegisterReading {
            register: GeneralRegister::Rax,
            bits: 0x5566_7788,
        }));
        assert!(register_readings.contains(&RegisterReading {
            register: GeneralRegister::Rbx,
            bits: 0,
        }));
    }
}
