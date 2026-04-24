// src-tauri/src/disasm.rs
// Capstone-powered multi-arch disassembler.

use capstone::prelude::*;
use crate::state::DisasmRow;

/// Supported architectures exposed to the frontend.
pub enum Arch {
    X86_32,
    X86_64,
    Arm,
    Arm64,
}

impl Arch {
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "x86_32" => Ok(Arch::X86_32),
            "x86_64" => Ok(Arch::X86_64),
            "arm"    => Ok(Arch::Arm),
            "arm64"  => Ok(Arch::Arm64),
            other    => Err(format!("Unknown arch: '{other}'")),
        }
    }

    fn build_capstone(&self) -> Result<Capstone, capstone::Error> {
        match self {
            Arch::X86_32 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode32)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
            Arch::X86_64 => Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build(),
            Arch::Arm => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .detail(true)
                .build(),
            Arch::Arm64 => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .detail(true)
                .build(),
        }
    }
}

/// Disassemble up to `max_insns` instructions from `data` starting at
/// file offset `offset`. `base_addr` is used as the virtual address base.
pub fn disassemble(
    data: &[u8],
    offset: usize,
    arch: Arch,
    base_addr: u64,
    max_insns: usize,
) -> Result<Vec<DisasmRow>, String> {
    if offset >= data.len() {
        return Err(format!(
            "Offset 0x{offset:X} is beyond end of file (0x{:X})",
            data.len()
        ));
    }

    let cs = arch.build_capstone().map_err(|e| e.to_string())?;

    let slice = &data[offset..];
    let virt_base = base_addr + offset as u64;

    let insns = cs
        .disasm_count(slice, virt_base, max_insns)
        .map_err(|e| e.to_string())?;

    let rows = insns
        .iter()
        .map(|insn| {
            let bytes_hex = insn
                .bytes()
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");

            DisasmRow {
                address:  insn.address(),
                bytes_hex,
                mnemonic: insn.mnemonic().unwrap_or("??").to_string(),
                operands: insn.op_str().unwrap_or("").to_string(),
            }
        })
        .collect();

    Ok(rows)
}
