// disinfect/engine.rs — Emulation side of the generic disinfector.
//
// The file runs in the unpacker's Windows environment (UnpackerEngine: sections
// mapped at their RVAs, TEB/PEB/LDR, IAT hooks). Definitions can match either on
// mapped sections before entry-point execution (`section_scan` / `last_section`,
// for EPO and API-blocked infectors) or on emulated basic blocks (`emulate` /
// `entry_point`, after any decryptor ran). Once matched, the definition recovers
// the host via:
//   * stored:           read the original entry point / stolen bytes from the body
//   * emulate_to_host:  keep running until the virus jumps back into the host;
//                       that address is the original entry point and what it
//                       wrote into the host's executable sections is the code it
//                       restored (diffed against the image as loaded)
//   * call_function:    call a specific decryptor / restore routine inside the
//                       virus (`UnpackerEngine::call_function`) with bounded
//                       instructions and timeout, then read decrypted bytes / OEP
//                       or diff restored host code.
// The cleanup addresses are evaluated here too, while the emulated memory exists.

use super::pe_edit::{self as pe, Sec};
use super::rules::{AddrExpr, AddrMode, ArchFilter, Cleanup, CompiledRule, Locate, Recover, RestoreBlock, ValueExpr};
use crate::unpacker::engine::{Sample, UnpackerEngine};
use std::cell::RefCell;
use std::rc::Rc;
use unicorn_engine::{Prot, Unicorn};

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
    call_ret: Option<u64>,
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
    /// Set once block-hook matching / seeking is complete so post-match `call_function` runs unimpeded.
    done: bool,
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

fn eval_addr(
    uc: &Unicorn<'_, ()>,
    start: u64,
    base: u64,
    mask: u64,
    a: &AddrExpr,
    call_ret: Option<u64>,
) -> Option<u64> {
    let add = a.add as u64;
    let r = match a.mode {
        AddrMode::VirusOffset => start.wrapping_add(add),
        AddrMode::ReturnVa => call_ret?.wrapping_add(add),
        AddrMode::ReturnRva => base.wrapping_add(call_ret?).wrapping_add(add),
        AddrMode::Absolute | AddrMode::Rva | AddrMode::Relative | AddrMode::RelativeBack => {
            let v = read_le(uc, start.wrapping_add(a.offset), a.size)? ^ a.xor;
            match a.mode {
                AddrMode::Absolute => v.wrapping_add(add),
                AddrMode::Rva => base.wrapping_add(v).wrapping_add(add),
                AddrMode::Relative => start.wrapping_add(add).wrapping_add(sign_extend(v, a.size) as u64),
                AddrMode::RelativeBack => start.wrapping_add(add).wrapping_sub(v),
                _ => unreachable!(),
            }
        }
    };
    Some(r & mask)
}

fn read_restore_blocks(
    uc: &Unicorn<'_, ()>,
    st: &State,
    ci: usize,
    start: u64,
    oep: u64,
    restore: &[RestoreBlock],
    call_ret: Option<u64>,
    scratches: &[Option<(u64, u64)>],
) -> Result<Vec<(u64, Vec<u8>)>, String> {
    let rule = &st.rules[ci];
    let mut out = Vec::with_capacity(restore.len());
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
        let src_va = match r.scratch_index {
            Some(idx) => {
                let (base_va, cap) = scratches
                    .get(idx)
                    .and_then(|s| *s)
                    .ok_or("restore scratch buffer is not mapped")?;
                if r.data_offset.saturating_add(size) > cap {
                    return Err(format!("stored code size {size} overflows scratch[{idx}] ({cap} bytes)"));
                }
                base_va.wrapping_add(r.data_offset)
            }
            None => start.wrapping_add(r.data_offset),
        };
        let mut data = uc
            .mem_read_as_vec(src_va, size as usize)
            .map_err(|_| "stored original code is not readable".to_string())?;
        if let Some(key) = &rule.xor_keys[i] {
            data.iter_mut().zip(key.iter().cycle()).for_each(|(b, k)| *b ^= k);
        }
        let to = match &r.to {
            Some(t) => eval_addr(uc, start, st.base, st.mask, t, call_ret).ok_or("restore target is not readable")?,
            None => oep,
        };
        out.push((to, data));
    }
    Ok(out)
}

/// Original entry point and stored bytes of a `stored` definition.
fn read_stored(uc: &Unicorn<'_, ()>, st: &State, ci: usize, start: u64) -> Result<(u64, Vec<(u64, Vec<u8>)>), String> {
    let rule = &st.rules[ci];
    let Recover::Stored { oep, restore } = &rule.rule.recover else { unreachable!() };
    let oep = match oep {
        Some(expr) => eval_addr(uc, start, st.base, st.mask, expr, None).ok_or("original entry point is not readable")?,
        None => st.ep,
    };
    let out = read_restore_blocks(uc, st, ci, start, oep, restore, None, &[])?;
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
    if st.done {
        return;
    }
    st.blocks += 1;
    if st.blocks > st.max_blocks {
        st.done = true;
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
            st.done = true;
            let _ = uc.emu_stop();
        }
        return;
    }
    for k in 0..st.candidates.len() {
        let ci = st.candidates[k];
        let rule = &st.rules[ci];
        match rule.rule.locate {
            Locate::SectionScan | Locate::LastSection => continue,
            Locate::EntryPoint if addr != st.ep => continue,
            Locate::Emulate | Locate::EntryPoint => {}
        }
        let Ok(buf) = uc.mem_read_as_vec(addr, rule.sig_span) else { continue };
        if !rule.matches(&buf) {
            continue;
        }
        let region = virus_region(st, ci, addr);
        let mut hit = Hit {
            rule: ci,
            start: addr,
            region,
            oep: None,
            restores: Vec::new(),
            call_ret: None,
            fail: None,
        };
        match &rule.rule.recover {
            Recover::None => {
                hit.fail = Some("the definition recognises this virus but has no repair routine".into());
                st.done = true;
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
                st.done = true;
                let _ = uc.emu_stop();
            }
            Recover::CallFunction { .. } => {
                st.done = true;
                let _ = uc.emu_stop();
            }
            Recover::EmulateToHost { .. } => st.seeking = true,
        }
        st.hit = Some(hit);
        return;
    }
}

/// Scan mapped image bytes for `section_scan` / `last_section` definitions before running entry-point code.
fn locate_in_mapped(baseline: &[u8], st: &State) -> Option<(usize, u64)> {
    for &ci in &st.candidates {
        let rule = &st.rules[ci];
        match rule.rule.locate {
            Locate::SectionScan => {
                for s in st.secs.iter().filter(|s| s.executable()) {
                    let lo = s.va as usize;
                    let hi = (s.span_end() as usize).min(baseline.len());
                    if lo < hi {
                        if let Some(rel) = rule.scan_slice(&baseline[lo..hi]) {
                            return Some((ci, st.base + (lo + rel) as u64));
                        }
                    }
                }
            }
            Locate::LastSection => {
                if let Some(s) = st.secs.last() {
                    let lo = s.va as usize;
                    let hi = (s.span_end() as usize).min(baseline.len());
                    if lo < hi {
                        if let Some(rel) = rule.scan_slice(&baseline[lo..hi]) {
                            return Some((ci, st.base + (lo + rel) as u64));
                        }
                    }
                }
            }
            Locate::Emulate | Locate::EntryPoint => {}
        }
    }
    None
}

fn alloc_scratch(uc: &mut Unicorn<'_, ()>, size: u64) -> Result<u64, String> {
    let aligned = crate::unpacker::engine::page_align(size.max(0x1000));
    for cand in (0x2000_0000u64..0x6800_0000).step_by(0x10_0000) {
        if uc.mem_map(cand, aligned, Prot::READ | Prot::WRITE).is_ok() {
            return Ok(cand);
        }
    }
    Err("no free virtual address space for call_function scratch buffer".into())
}

fn run_call_function(engine: &mut UnpackerEngine, state: &Rc<RefCell<State>>, baseline: &[u8]) {
    let (ci, start, region, base, image_end, ep, mask, compiled) = {
        let st = state.borrow();
        let Some(hit) = st.hit.as_ref() else { return };
        if hit.fail.is_some() || !matches!(st.rules[hit.rule].rule.recover, Recover::CallFunction { .. }) {
            return;
        }
        (
            hit.rule,
            hit.start,
            hit.region,
            st.base,
            st.image_end,
            st.ep,
            st.mask,
            st.rules[hit.rule].clone(),
        )
    };
    let Recover::CallFunction {
        func,
        args,
        max_instructions,
        timeout_ms,
        oep,
        restore,
        diff_host,
        max_restore_bytes,
    } = &compiled.rule.recover
    else {
        unreachable!()
    };

    let outcome: Result<(u64, Vec<(u64, Vec<u8>)>, u64), String> = (|| {
        let (func_va, call_args, scratches) = {
            let uc = engine.unicorn_mut().ok_or("emulator not initialized")?;
            let fva = eval_addr(uc, start, base, mask, func, None).ok_or("decryptor function address is not readable")?;
            if fva < base || fva >= image_end {
                return Err(format!("decryptor function 0x{fva:x} is outside the image"));
            }
            let mut cargs = Vec::with_capacity(args.len());
            let mut scratches = Vec::with_capacity(args.len());
            for a in args {
                if let Some(ad) = &a.addr {
                    let v = eval_addr(uc, start, base, mask, ad, None).ok_or("call_function argument address is not readable")?;
                    cargs.push(v);
                    scratches.push(None);
                } else if let Some(val) = &a.value {
                    let v = eval_value(uc, start, val).ok_or("call_function argument value is not readable")?;
                    cargs.push(v);
                    scratches.push(None);
                } else if let Some(sz) = a.scratch {
                    let va = alloc_scratch(uc, sz)?;
                    cargs.push(va);
                    scratches.push(Some((va, sz)));
                }
            }
            (fva, cargs, scratches)
        };

        let ret = engine
            .call_function(func_va, &call_args, timeout_ms.saturating_mul(1000), *max_instructions as usize)
            .map_err(|e| format!("call_function failed: {e}"))?;

        let uc = engine.unicorn_mut().ok_or("emulator not initialized")?;
        let st = state.borrow();
        let resolved_oep = match oep {
            Some(expr) => eval_addr(uc, start, base, mask, expr, Some(ret)).ok_or("original entry point is not readable")?,
            None => ep,
        };
        let mut restores = read_restore_blocks(uc, &st, ci, start, resolved_oep, restore, Some(ret), &scratches)?;
        if *diff_host {
            let diffs = restored_by_virus(uc, &st, baseline, region, *max_restore_bytes)?;
            restores.extend(diffs);
        }
        if oep.is_none() && restore.is_empty() && *diff_host && restores.is_empty() {
            return Err("patient zero: call_function restored no host code".into());
        }
        Ok((resolved_oep, restores, ret))
    })();

    let mut st = state.borrow_mut();
    if let Some(hit) = st.hit.as_mut() {
        match outcome {
            Ok((resolved_oep, restores, ret)) => {
                hit.oep = Some(resolved_oep);
                hit.restores = restores;
                hit.call_ret = Some(ret);
            }
            Err(e) => hit.fail = Some(e),
        }
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
    let has_emulate_rules = candidates
        .iter()
        .any(|&i| matches!(rules[i].rule.locate, Locate::Emulate | Locate::EntryPoint));
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
        done: false,
    }));
    let baseline = {
        let uc = engine.unicorn_mut()?;
        // The loader maps the headers too; a virus may read them (MZ / PE walk).
        let _ = uc.mem_write(base, &raw[..headers]);
        let st = Rc::clone(&state);
        uc.add_block_hook(1, 0, move |uc, addr, _size| on_block(uc, &mut st.borrow_mut(), addr)).ok()?;
        uc.mem_read_as_vec(base, vms as usize).ok()?
    };

    let mapped_match = locate_in_mapped(&baseline, &state.borrow());
    if let Some((ci, addr)) = mapped_match {
        let seek_from = {
            let uc = engine.unicorn_mut()?;
            let mut st = state.borrow_mut();
            let region = virus_region(&st, ci, addr);
            let mut hit = Hit {
                rule: ci,
                start: addr,
                region,
                oep: None,
                restores: Vec::new(),
                call_ret: None,
                fail: None,
            };
            let mut seek = false;
            match &st.rules[ci].rule.recover {
                Recover::None => {
                    hit.fail = Some("the definition recognises this virus but has no repair routine".into());
                    st.done = true;
                }
                Recover::Stored { .. } => {
                    match read_stored(uc, &st, ci, addr) {
                        Ok((oep, restores)) => {
                            hit.oep = Some(oep);
                            hit.restores = restores;
                        }
                        Err(e) => hit.fail = Some(e),
                    }
                    st.done = true;
                }
                Recover::CallFunction { .. } => {
                    st.done = true;
                }
                Recover::EmulateToHost { .. } => {
                    st.seeking = true;
                    seek = true;
                }
            }
            st.hit = Some(hit);
            seek.then_some(addr)
        };
        if let Some(start_va) = seek_from {
            let _ = engine.emu_from(start_va, 30_000_000, 0);
        }
    } else if has_emulate_rules {
        let _ = engine.emu();
    } else {
        return None;
    }

    run_call_function(&mut engine, &state, &baseline);

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
                    eval_addr(uc, hit.start, base, st.mask, at, hit.call_ret).ok_or("cut address is not readable")?,
                ),
                Cleanup::RemoveVirusSection => PlannedCleanup::RemoveSectionOf(hit.start),
                Cleanup::ZeroBody => PlannedCleanup::ZeroRange(hit.region.0, hit.region.1),
            });
        }
        Ok(Plan { image_base: base, oep, restores, cleanup })
    })();
    Some(Detected { rule: hit.rule, virus_start: hit.start, plan })
}
