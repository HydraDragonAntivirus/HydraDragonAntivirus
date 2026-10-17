// disinfect/pe_edit.rs — In-memory PE32 / PE32+ header edits used by the repair:
// entry point, cutting the file (section headers kept consistent), removing the
// last section, SizeOfImage. The checksum is unpacker::imagedump::fix_checksum.

pub(crate) struct Layout {
    pub opt_off: usize,
    pub sec_off: usize,
    pub nsec: usize,
    pub file_align: u32,
    pub sect_align: u32,
    pub is64: bool,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Sec {
    pub index: usize,
    pub va: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub chars: u32,
}

impl Sec {
    /// End RVA as the loader maps it.
    pub fn mem_end(&self) -> u32 {
        self.va.saturating_add(if self.vsize != 0 { self.vsize } else { self.raw_size })
    }
    /// End RVA as hooks and VA lookups see it (larger of the two sizes).
    pub fn span_end(&self) -> u32 {
        self.va.saturating_add(self.vsize.max(self.raw_size))
    }
    pub fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.va && rva < self.span_end()
    }
    pub fn executable(&self) -> bool {
        self.chars & (0x2000_0000 | 0x0000_0020) != 0
    }
}

fn rd16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn rd32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
pub(crate) fn wr32(d: &mut [u8], o: usize, v: u32) -> Result<(), String> {
    d.get_mut(o..o + 4)
        .ok_or_else(|| format!("header write at 0x{o:x} outside the file"))?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn align_up(v: u32, a: u32) -> u32 {
    if a <= 1 { v } else { v.div_ceil(a).saturating_mul(a) }
}

pub(crate) fn layout(d: &[u8]) -> Result<Layout, String> {
    let bad = |m: &str| format!("malformed PE: {m}");
    if rd16(d, 0) != Some(0x5A4D) {
        return Err(bad("no MZ"));
    }
    let pe = rd32(d, 0x3C).ok_or_else(|| bad("no e_lfanew"))? as usize;
    if rd32(d, pe) != Some(0x0000_4550) {
        return Err(bad("no PE signature"));
    }
    let coff = pe + 4;
    let nsec = rd16(d, coff + 2).ok_or_else(|| bad("COFF header"))? as usize;
    let opt_size = rd16(d, coff + 16).ok_or_else(|| bad("COFF header"))? as usize;
    let opt_off = coff + 20;
    let magic = rd16(d, opt_off).ok_or_else(|| bad("optional header"))?;
    let is64 = match magic {
        0x10b => false,
        0x20b => true,
        _ => return Err(bad("unknown optional header magic")),
    };
    let sect_align = rd32(d, opt_off + 32).ok_or_else(|| bad("optional header"))?;
    let file_align = rd32(d, opt_off + 36).ok_or_else(|| bad("optional header"))?;
    let sec_off = opt_off + opt_size;
    if sec_off + nsec * 40 > d.len() {
        return Err(bad("section table outside the file"));
    }
    Ok(Layout { opt_off, sec_off, nsec, file_align, sect_align, is64 })
}

pub(crate) fn sections(d: &[u8], l: &Layout) -> Vec<Sec> {
    (0..l.nsec)
        .map(|i| {
            let o = l.sec_off + i * 40;
            Sec {
                index: i,
                vsize: rd32(d, o + 8).unwrap_or(0),
                va: rd32(d, o + 12).unwrap_or(0),
                raw_size: rd32(d, o + 16).unwrap_or(0),
                raw_ptr: rd32(d, o + 20).unwrap_or(0),
                chars: rd32(d, o + 36).unwrap_or(0),
            }
        })
        .collect()
}

pub(crate) fn section_of_rva(secs: &[Sec], rva: u32) -> Option<Sec> {
    secs.iter().copied().find(|s| s.contains_rva(rva))
}

/// File offset of `len` bytes at `rva`, all inside one section's raw data.
pub(crate) fn rva_to_offset(secs: &[Sec], rva: u32, len: usize) -> Option<usize> {
    let s = secs.iter().find(|s| rva >= s.va && rva < s.va.saturating_add(s.raw_size))?;
    let rel = (rva - s.va) as usize;
    (rel + len <= s.raw_size as usize).then_some(s.raw_ptr as usize + rel)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn entry_point(d: &[u8], l: &Layout) -> u32 {
    rd32(d, l.opt_off + 16).unwrap_or(0)
}
pub(crate) fn set_entry_point(d: &mut [u8], l: &Layout, rva: u32) -> Result<(), String> {
    wr32(d, l.opt_off + 16, rva)
}
pub(crate) fn checksum(d: &[u8], l: &Layout) -> u32 {
    rd32(d, l.opt_off + 64).unwrap_or(0)
}

/// SizeOfImage from the section table (after sections were changed or removed).
pub(crate) fn update_size_of_image(d: &mut [u8], l: &Layout) -> Result<(), String> {
    let end = sections(d, l).iter().map(Sec::mem_end).max().unwrap_or(0);
    let headers = rd32(d, l.opt_off + 60).unwrap_or(0);
    wr32(d, l.opt_off + 56, align_up(end.max(headers), l.sect_align))
}

/// The Authenticode blob is addressed by FILE offset; drop the entry when the cut
/// removed it (it was invalid anyway: the file was modified by the virus).
fn clear_dangling_security_dir(d: &mut [u8], l: &Layout) -> Result<(), String> {
    let dd = l.opt_off + if l.is64 { 112 } else { 96 };
    let count = rd32(d, dd - 4).unwrap_or(0);
    if count <= 4 {
        return Ok(());
    }
    let e = dd + 4 * 8;
    let (off, size) = (rd32(d, e).unwrap_or(0) as usize, rd32(d, e + 4).unwrap_or(0) as usize);
    if off != 0 && off.saturating_add(size) > d.len() {
        wr32(d, e, 0)?;
        wr32(d, e + 4, 0)?;
    }
    Ok(())
}

/// Drop the section headers `from..nsec` (they must be the last ones).
fn drop_tail_sections(d: &mut Vec<u8>, l: &mut Layout, from: usize) -> Result<(), String> {
    for i in from..l.nsec {
        let o = l.sec_off + i * 40;
        d[o..o + 40].fill(0);
    }
    l.nsec = from;
    let coff = l.opt_off - 20;
    d[coff + 2..coff + 4].copy_from_slice(&(from as u16).to_le_bytes());
    Ok(())
}

/// Cut the file at `off`. The section containing the cut keeps its data up to it
/// (raw size re-aligned, virtual size never grown); sections that start at or
/// after the cut are removed, which is allowed only for the trailing sections.
pub(crate) fn truncate_at(d: &mut Vec<u8>, off: usize) -> Result<(), String> {
    let mut l = layout(d)?;
    let secs = sections(d, &l);
    let size_of_headers = rd32(d, l.opt_off + 60).unwrap_or(0) as usize;
    if off < size_of_headers.max(l.sec_off + l.nsec * 40) {
        return Err(format!("cut at 0x{off:x} would remove the PE headers"));
    }
    if off >= d.len() {
        return Ok(());
    }
    // Sections whose data starts at or after the cut disappear.
    let gone: Vec<usize> = secs
        .iter()
        .filter(|s| s.raw_size > 0 && s.raw_ptr as usize >= off)
        .map(|s| s.index)
        .collect();
    if let Some(&first) = gone.iter().min() {
        if gone.len() != l.nsec - first {
            return Err("cut would remove a section that is not at the end of the file".into());
        }
        let kept_end = secs[..first].iter().map(Sec::span_end).max().unwrap_or(0);
        if secs[first..].iter().any(|s| s.va < kept_end) {
            return Err("sections after the cut are not the last ones in memory".into());
        }
    }
    let cut_sec = secs.iter().find(|s| {
        s.raw_size > 0 && (s.raw_ptr as usize) < off && off < s.raw_ptr as usize + s.raw_size as usize
    });
    match cut_sec {
        Some(s) => {
            if gone.iter().any(|&g| g < s.index) {
                return Err("cut section is followed in the table by removed sections".into());
            }
            let new_len = (off - s.raw_ptr as usize) as u32;
            let raw = align_up(new_len, l.file_align);
            let o = l.sec_off + s.index * 40;
            if s.vsize != 0 {
                wr32(d, o + 8, s.vsize.min(new_len))?;
            }
            wr32(d, o + 16, raw)?;
            d.truncate(off);
            d.resize(s.raw_ptr as usize + raw as usize, 0);
        }
        None => d.truncate(off),
    }
    if let Some(&first) = gone.iter().min() {
        drop_tail_sections(d, &mut l, first)?;
    }
    update_size_of_image(d, &l)?;
    clear_dangling_security_dir(d, &l)
}

/// Remove section `index` (it must be the last one) and its data.
pub(crate) fn remove_section(d: &mut Vec<u8>, index: usize) -> Result<(), String> {
    let l = layout(d)?;
    let secs = sections(d, &l);
    let s = *secs.get(index).ok_or("no such section")?;
    if index + 1 != l.nsec {
        return Err(format!("section {index} is not the last section"));
    }
    if s.raw_size == 0 || secs.iter().any(|o| o.index != index && o.raw_ptr > s.raw_ptr) {
        // No data of its own, or data not at the end: drop only the header.
        let mut l = l;
        drop_tail_sections(d, &mut l, index)?;
        update_size_of_image(d, &l)?;
        return Ok(());
    }
    truncate_at(d, s.raw_ptr as usize)
}
