// disinfect/engine.rs — Emulation side of the generic disinfector.
//
// The file runs in the unpacker's Windows environment (UnpackerEngine: sections
// mapped at their RVAs, TEB/PEB/LDR, IAT hooks). A basic-block hook checks every
// definition's signature at each block start, so the virus is matched in memory
// after any decryptor ran. Once matched, the definition says how to recover:
//   * stored:           read the original entry point / stolen bytes from the body
//   * emulate_to_host:  keep running until the virus jumps back into the host;
//                       that address is the original entry point and what it
//                       wrote into the host's executable sections is the code it
//                       restored (diffed against the image as loaded).
// The cleanup addresses are evaluated here too, while the emulated memory exists.

use super::pe_edit::{self as pe, Sec};
use super::rules::{AddrExpr, AddrMode, ArchFilter, Cleanup, CompiledRule, Locate, Recover, ValueExpr};
use crate::unpacker::engine::{Sample, UnpackerEngine};
use std::cell::RefCell;
use std::rc::Rc;
use unicorn_engine::Unicorn;

const DEFAULT_MAX_BLOCKS: u64 = 5_000_000;
/// Unchanged bytes allowed inside one restored run (keeps runs few and short).
const DIFF_MERGE_GAP: usize = 8;

/// A cleanup with its addresses resolved.
#[derive(Debug, Clone)]
pub(crate) enum PlannedCleanup {
    TruncateVa(u64),
    RemoveSectionOf(u64),
    ZeroRange(u64, u64),
}

/// What the repair has to do, all addresses are VAs.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub image_base: u64,
    pub oep: u64,
    pub restores: Vec<(u64, Vec<u8>)>,
    pub cleanup: Vec<PlannedCleanup>,
}

/// A definition recognised the file.
#[derive(Debug)]
pub(crate) struct Detected {
    pub rule: usize,
    pub virus_start: u64,
    /// Err = recognised but not repairable (patient zero, detection-only, ...).
    pub plan: Result<Plan, String>,
}

struct Hit {
    rule: usize,
    start: u64,
    region: (u64, u64),
    oep: Option<u64>,
    restores: Vec<(u64, Vec<u8>)>,
    fail: Option<String>,
}

struct State {
    rules: Vec<CompiledRule>,
    candidates: Vec<usize>,
    ep: u64,
    base: u64,
    image_end: u64,
    secs: Vec<Sec>,
    mask: u64,
    blocks: u64,
    max_blocks: u64,
    hit: Option<Hit>,
    /// Following the virus back to the host.
    seeking: bool,
}

fn read_le(uc: &Unicorn<'_, ()>, addr: u64, size: u8) -> Option<u64> {
    let b = uc.mem_read_as_vec(addr, size as usize).ok()?;
    let mut v = [0u8; 8];
    v[..b.len()].copy_from_slice(&b);
    Some(u64::from_le_bytes(v))
}

fn sign_extend(v: u64, size: u8) -> i64 {
    let bits = size as u32 * 8;
    if bits >= 64 { v as i64 } else { ((v << (64 - bits)) as i64) >> (64 - bits) }
}

fn eval_value(uc: &Unicorn<'_, ()>, start: u64, v: &ValueExpr) -> Option<u64> {
    match (v.value, v.offset) {
        (Some(c), _) => Some(c),
        (None, Some(o)) => Some(read_le(uc, start.wrapping_add(o), v.size)? ^ v.xor),
        _ => None,
    }
}

fn eval_addr(uc: &Unicorn<'_, ()>, start: u64, base: u64, mask: u64, a: &AddrExpr) -> Option<u64> {
    let add = a.add as u64;
    let r = if a.mode == AddrMode::VirusOffset {
        start.wrapping_add(add)
    } else {
        let v = read_le(uc, start.wrapping_add(a.offset), a.size)? ^ a.xor;
        match a.mode {
            AddrMode::Absolute => v.wrapping_add(add),
            AddrMode::Rva => base.wrapping_add(v).wrapping_add(add),
            AddrMode::Relative => start.wrapping_add(add).wrapping_add(sign_extend(v, a.size) as u64),
            AddrMode::RelativeBack => start.wrapping_add(add).wrapping_sub(v),
            AddrMode::VirusOffset => unreachable!(),
        }
    };
    Some(r & mask)
}

/// Original entry point and stored bytes of a `stored` definition.
fn read_stored(uc: &Unicorn<'_, ()>, st: &State, ci: usize, start: u64) -> Result<(u64, Vec<(u64, Vec<u8>)>), String> {
    let rule = &st.rules[ci];
    let Recover::Stored { oep, restore } = &rule.rule.recover else { unreachable!() };
    let oep = eval_addr(uc, start, st.base, st.mask, oep).ok_or("original entry point is not readable")?;
    let mut out = Vec::new();
    for (i, r) in restore.iter().enumerate() {
        if let Some(flag) = &r.present_flag {
            if eval_value(uc, start, flag).ok_or("restore flag is not readable")? == 0 {
                return Err("patient zero: the virus body stores no original code".into());
            }
        }
        let size = eval_value(uc, start, &r.size).ok_or("stored code size is not readable")?;
        if size < r.min_size {
            return Err("patient zero: the virus body stores no original code".into());
        }
        if size > r.max_size {
            return Err(format!("stored code size {size} is over the definition's limit {}", r.max_size));
        }
        let mut data = uc
            .mem_read_as_vec(start.wrapping_add(r.data_offset), size as usize)
            .map_err(|_| "stored original code is not readable".to_string())?;
        if let Some(key) = &rule.xor_keys[i] {
            data.iter_mut().zip(key.iter().cycle()).for_each(|(b, k)| *b ^= k);
        }
        let to = match &r.to {
            Some(t) => eval_addr(uc, start, st.base, st.mask, t).ok_or("restore target is not readable")?,
            None => oep,
        };
        out.push((to, data));
    }
    Ok((oep, out))
}

fn virus_region(st: &State, ci: usize, start: u64) -> (u64, u64) {
    if let Some(n) = st.rules[ci].rule.body_size {
        return (start, start.saturating_add(n));
    }
    match start.checked_sub(st.base).and_then(|r| pe::section_of_rva(&st.secs, r as u32)) {
        Some(s) => (start, st.base + s.span_end() as u64),
        None => (start, st.image_end.max(start + 1)),
    }
}

fn on_block(uc: &mut Unicorn<'_, ()>, st: &mut State, addr: u64) {
    st.blocks += 1;
    if st.blocks > st.max_blocks {
        let _ = uc.emu_stop();
        return;
    }
    if st.seeking {
        let hit = st.hit.as_mut().expect("seeking without a hit");
        let in_host = addr >= st.base
            && addr < st.image_end
            && !(addr >= hit.region.0 && addr < hit.region.1)
            && pe::section_of_rva(&st.secs, (addr - st.base) as u32).is_some();
        if in_host {
            hit.oep = Some(addr);
            st.seeking = false;
            let _ = uc.emu_stop();
        }
        return;
    }
    for k in 0..st.candidates.len() {
        let ci = st.candidates[k];
        let rule = &st.rules[ci];
        if rule.rule.locate == Locate::EntryPoint && addr != st.ep {
            continue;
        }
        let Ok(buf) = uc.mem_read_as_vec(addr, rule.sig_span) else { continue };
        if !rule.matches(&buf) {
            continue;
        }
        let region = virus_region(st, ci, addr);
        let mut hit = Hit { rule: ci, start: addr, region, oep: None, restores: Vec::new(), fail: None };
        match &rule.rule.recover {
            Recover::None => {
                hit.fail = Some("the definition recognises this virus but has no repair routine".into());
                let _ = uc.emu_stop();
            }
            Recover::Stored { .. } => {
                match read_stored(uc, st, ci, addr) {
                    Ok((oep, restores)) => {
                        hit.oep = Some(oep);
                        hit.restores = restores;
                    }
                    Err(e) => hit.fail = Some(e),
                }
                let _ = uc.emu_stop();
            }
            Recover::EmulateToHost { .. } => st.seeking = true,
        }
        st.hit = Some(hit);
        return;
    }
}

/// Bytes the virus wrote into the host's executable sections (outside its own body).
fn restored_by_virus(
    uc: &Unicorn<'_, ()>,
    st: &State,
    baseline: &[u8],
    region: (u64, u64),
    limit: u64,
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut total = 0u64;
    for s in st.secs.iter().filter(|s| s.executable()) {
        let lo = s.va as usize;
        let hi = (s.span_end() as usize).min(baseline.len());
        if lo >= hi {
            continue;
        }
        let now = uc
            .mem_read_as_vec(st.base + lo as u64, hi - lo)
            .map_err(|_| "host section is not readable after emulation".to_string())?;
        let mut i = 0;
        while i < now.len() {
            if now[i] == baseline[lo + i] || (st.base + (lo + i) as u64 >= region.0 && st.base + ((lo + i) as u64) < region.1) {
                i += 1;
                continue;
            }
            let start = i;
            let mut end = i + 1;
            let mut j = end;
            while j < now.len() && j - end <= DIFF_MERGE_GAP {
                let va = st.base + (lo + j) as u64;
                if va >= region.0 && va < region.1 {
                    break;
                }
                if now[j] != baseline[lo + j] {
                    end = j + 1;
                }
                j += 1;
            }
            total += (end - start) as u64;
            if total > limit {
                return Err(format!("the virus changed more than {limit} bytes of host code"));
            }
            out.push((st.base + (lo + start) as u64, now[start..end].to_vec()));
            i = end;
        }
    }
    Ok(out)
}

fn arch_ok(f: ArchFilter, machine: u16) -> bool {
    match f {
        ArchFilter::Any => true,
        ArchFilter::X86 => machine == 0x14c,
        ArchFilter::X64 => machine == 0x8664,
    }
}

/// Emulate `raw` and check the definitions. `None` = no definition recognised it.
pub(crate) fn emulate(raw: &[u8], rules: &[CompiledRule]) -> Option<Detected> {
    let mut sample = Sample::from_bytes(raw).ok()?;
    let machine = sample.pe_header.machine;
    let candidates: Vec<usize> = (0..rules.len()).filter(|&i| arch_ok(rules[i].rule.arch, machine)).collect();
    if candidates.is_empty() || !matches!(machine, 0x14c | 0x8664) {
        return None;
    }
    // The disinfector follows the virus wherever it goes: no unpacker stop rules.
    sample.unpacker.section_hopping_control = false;
    sample.unpacker.write_execute_control = false;
    sample.unpacker.endaddr = u64::MAX;

    let base = sample.base_addr;
    let vms = crate::unpacker::engine::page_align(sample.virtualmemorysize);
    let ep = base + sample.opt_header.address_of_entry_point as u64;
    let headers = (sample.opt_header.size_of_headers as usize).min(raw.len()).min(vms as usize);
    let l = pe::layout(raw).ok()?;
    let secs = pe::sections(raw, &l);
    let max_blocks = candidates
        .iter()
        .map(|&i| rules[i].rule.max_blocks)
        .max()
        .filter(|&m| m > 0)
        .unwrap_or(DEFAULT_MAX_BLOCKS);

    let mut engine = UnpackerEngine::new(sample, "memory");
    engine.init_uc().ok()?;
    let state = Rc::new(RefCell::new(State {
        rules: rules.to_vec(),
        candidates,
        ep,
        base,
        image_end: base + vms,
        secs,
        mask: if machine == 0x14c { 0xFFFF_FFFF } else { u64::MAX },
        blocks: 0,
        max_blocks,
        hit: None,
        seeking: false,
    }));
    let baseline = {
        let uc = engine.unicorn_mut()?;
        // The loader maps the headers too; a virus may read them (MZ / PE walk).
        let _ = uc.mem_write(base, &raw[..headers]);
        let st = Rc::clone(&state);
        uc.add_block_hook(1, 0, move |uc, addr, _size| on_block(uc, &mut st.borrow_mut(), addr)).ok()?;
        uc.mem_read_as_vec(base, vms as usize).ok()?
    };
    let _ = engine.emu();

    let uc = engine.unicorn_mut()?;
    let st = state.borrow();
    let hit = st.hit.as_ref()?;
    let rule = &st.rules[hit.rule];
    let plan = (|| -> Result<Plan, String> {
        if let Some(f) = &hit.fail {
            return Err(f.clone());
        }
        let oep = hit.oep.ok_or("the virus did not return to the host within the emulation limit")?;
        let restores = match &rule.rule.recover {
            Recover::EmulateToHost { max_restore_bytes } => {
                restored_by_virus(uc, &st, &baseline, hit.region, *max_restore_bytes)?
            }
            _ => hit.restores.clone(),
        };
        let mut cleanup = Vec::new();
        for c in &rule.rule.cleanup {
            cleanup.push(match c {
                Cleanup::TruncateAt { at } => PlannedCleanup::TruncateVa(
                    eval_addr(uc, hit.start, base, st.mask, at).ok_or("cut address is not readable")?,
                ),
                Cleanup::RemoveVirusSection => PlannedCleanup::RemoveSectionOf(hit.start),
                Cleanup::ZeroBody => PlannedCleanup::ZeroRange(hit.region.0, hit.region.1),
            });
        }
        Ok(Plan { image_base: base, oep, restores, cleanup })
    })();
    Some(Detected { rule: hit.rule, virus_start: hit.start, plan })
}
