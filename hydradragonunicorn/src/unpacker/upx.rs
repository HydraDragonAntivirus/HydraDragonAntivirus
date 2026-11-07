// unpacker/upx.rs — static UPX unpacking of Windows PE files (win32/pe, win64/pe).
//
// The UPX stub decompresses the program into its first section, undoes the
// call-trick filter and loads the imports. Emulating it costs seconds on a big
// file (LZMA over tens of MB, often more than the emulation budget); this does
// the same steps directly, in milliseconds:
//   1. the pack header (`UPX!`, in the PE headers) gives the method, the sizes,
//      the Adler-32 of the compressed and of the unpacked data, filter and cto;
//   2. the compressed block is found in the entry point's section by its Adler-32;
//   3. NRV2B / NRV2D / NRV2E (le32) or LZMA, checked against the unpacked Adler-32;
//   4. the filter's call count and the import table are read from the stub's own
//      code (the immediates of its loops), and used the way the stub uses them.
// Anything it does not recognise is an error: the caller emulates as before.

use std::collections::HashMap;

use super::codecs::{self, Codec};

/// The most an unpacked image may take.
pub const MAX_UNPACKED: usize = 256 << 20;
const MAX_DLLS: usize = 4096;
const MAX_IMPORTS: usize = 1 << 16;
/// UPX_F_WIN32_PE / UPX_F_W64PE_AMD64.
const FMT_WIN32_PE: u8 = 9;
const FMT_WIN64_PE: u8 = 36;
/// How far into the entry point's section the compressed block may start.
const MAX_BLOCK_SKEW: usize = 0x1000;

/// The UPX pack header (version 10+, 32 bytes from `UPX!`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub format: u8,
    pub method: u8,
    pub level: u8,
    pub u_adler: u32,
    pub c_adler: u32,
    pub u_len: u32,
    pub c_len: u32,
    pub u_file_size: u32,
    pub filter: u8,
    pub filter_cto: u8,
}

/// The unpacked program: its memory image (offset = RVA), entry point and imports.
#[derive(Debug, Clone)]
pub struct Unpacked {
    pub header: Header,
    pub image: Vec<u8>,
    pub oep_rva: u32,
    /// DLL name and its imports, in the stub's order (`ord_N` for an ordinal).
    pub imports: Vec<(String, Vec<String>)>,
}

fn le16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn le32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The pack header of a UPX'd PE: the first `UPX!` in the headers with a known format.
pub fn header(data: &[u8]) -> Option<Header> {
    let area = &data[..data.len().min(0x1000)];
    let mut from = 0;
    while let Some(rel) = area.get(from..)?.windows(4).position(|w| w == b"UPX!") {
        let at = from + rel;
        from = at + 1;
        let h = data.get(at + 4..at + 32)?;
        let header = Header {
            version: h[0],
            format: h[1],
            method: h[2],
            level: h[3],
            u_adler: le32(h, 4)?,
            c_adler: le32(h, 8)?,
            u_len: le32(h, 12)?,
            c_len: le32(h, 16)?,
            u_file_size: le32(h, 20)?,
            filter: h[24],
            filter_cto: h[25],
        };
        if header.version >= 10
            && matches!(header.format, FMT_WIN32_PE | FMT_WIN64_PE)
            && header.c_len > 0
            && (header.u_len as usize) <= MAX_UNPACKED
            && header.c_len < header.u_len
        {
            return Some(header);
        }
    }
    None
}

pub fn adler32(data: &[u8]) -> u32 {
    const M: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= M;
        b %= M;
    }
    (b << 16) | a
}

/// First offset in `[0, max_skew]` where the `len` bytes of `data` have Adler-32
/// `want` (rolling, so the search costs one pass).
fn find_by_adler(data: &[u8], len: usize, want: u32, max_skew: usize) -> Option<usize> {
    const M: u64 = 65521;
    if len == 0 || data.len() < len {
        return None;
    }
    let first = adler32(&data[..len]);
    let (mut a, mut b) = ((first & 0xffff) as u64, (first >> 16) as u64);
    let n = len as u64 % M;
    for k in 0..=max_skew.min(data.len() - len) {
        if ((b << 16) | a) as u32 == want {
            return Some(k);
        }
        if k + len >= data.len() {
            break;
        }
        let (x, y) = (data[k] as u64, data[k + len] as u64);
        a = (a + M - x + y) % M;
        b = (b + M * M - (n * x) % M + a + M - 1) % M;
    }
    None
}

/// Bit reader of the UCL `le32` decompressors (32 bits at a time, MSB first).
struct Bits<'a> {
    src: &'a [u8],
    pos: usize,
    bb: u32,
    bc: u32,
}

impl Bits<'_> {
    fn bit(&mut self) -> Result<u32, String> {
        if self.bc == 0 {
            self.bb = le32(self.src, self.pos).ok_or("nrv: input ends")?;
            self.pos += 4;
            self.bc = 32;
        }
        self.bc -= 1;
        Ok((self.bb >> self.bc) & 1)
    }

    fn byte(&mut self) -> Result<u32, String> {
        let b = *self.src.get(self.pos).ok_or("nrv: input ends")?;
        self.pos += 1;
        Ok(b as u32)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nrv {
    B,
    D,
    E,
}

/// UCL NRV2B / NRV2D / NRV2E (`le32` bit buffer), as `ucl_nrv2?_decompress_le32`.
fn nrv(kind: Nrv, src: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    let mut s = Bits { src, pos: 0, bb: 0, bc: 0 };
    let mut out: Vec<u8> = Vec::with_capacity(out_len);
    let mut last_m_off: u32 = 1;
    // A gamma code longer than this is not a valid stream (offsets are < 2^24).
    let gamma_ok = |v: u32| if v > 0x0200_0000 { Err("nrv: bad code".to_string()) } else { Ok(()) };
    loop {
        while s.bit()? == 1 {
            if out.len() >= out_len {
                return Err("nrv: output overrun".into());
            }
            out.push(s.byte()? as u8);
        }
        let mut m_off: u32 = 1;
        let mut m_len: u32;
        match kind {
            Nrv::B => {
                loop {
                    m_off = m_off * 2 + s.bit()?;
                    gamma_ok(m_off)?;
                    if s.bit()? == 1 {
                        break;
                    }
                }
                if m_off == 2 {
                    m_off = last_m_off;
                } else {
                    m_off = (m_off - 3).wrapping_mul(256).wrapping_add(s.byte()?);
                    if m_off == u32::MAX {
                        break;
                    }
                    m_off += 1;
                    last_m_off = m_off;
                }
                m_len = s.bit()?;
                m_len = m_len * 2 + s.bit()?;
                if m_len == 0 {
                    m_len = 1;
                    loop {
                        m_len = m_len * 2 + s.bit()?;
                        gamma_ok(m_len)?;
                        if s.bit()? == 1 {
                            break;
                        }
                    }
                    m_len += 2;
                }
                m_len += (m_off > 0xd00) as u32;
            }
            Nrv::D | Nrv::E => {
                loop {
                    m_off = m_off * 2 + s.bit()?;
                    gamma_ok(m_off)?;
                    if s.bit()? == 1 {
                        break;
                    }
                    m_off = (m_off - 1) * 2 + s.bit()?;
                }
                if m_off == 2 {
                    m_off = last_m_off;
                    m_len = s.bit()?;
                } else {
                    m_off = (m_off - 3).wrapping_mul(256).wrapping_add(s.byte()?);
                    if m_off == u32::MAX {
                        break;
                    }
                    m_len = (m_off ^ u32::MAX) & 1;
                    m_off >>= 1;
                    m_off += 1;
                    last_m_off = m_off;
                }
                if kind == Nrv::D {
                    m_len = m_len * 2 + s.bit()?;
                    if m_len == 0 {
                        m_len = 1;
                        loop {
                            m_len = m_len * 2 + s.bit()?;
                            gamma_ok(m_len)?;
                            if s.bit()? == 1 {
                                break;
                            }
                        }
                        m_len += 2;
                    }
                } else if m_len != 0 {
                    m_len = 1 + s.bit()?;
                } else if s.bit()? == 1 {
                    m_len = 3 + s.bit()?;
                } else {
                    m_len = 1;
                    loop {
                        m_len = m_len * 2 + s.bit()?;
                        gamma_ok(m_len)?;
                        if s.bit()? == 1 {
                            break;
                        }
                    }
                    m_len += 3;
                }
                m_len += (m_off > 0x500) as u32;
            }
        }
        let (off, len) = (m_off as usize, m_len as usize + 1);
        if off == 0 || off > out.len() {
            return Err("nrv: match before the start".into());
        }
        if out.len() + len > out_len {
            return Err("nrv: output overrun".into());
        }
        let start = out.len() - off;
        for i in 0..len {
            let b = out[start + i];
            out.push(b);
        }
    }
    if out.len() != out_len {
        return Err(format!("nrv: {} bytes, header says {out_len}", out.len()));
    }
    Ok(out)
}

/// UPX's LZMA: a 2-byte header (`(lc+lp)<<3 | pb`, `lp<<4 | lc`), then the raw stream.
fn lzma(src: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    let (b0, b1) = (*src.first().ok_or("lzma: empty")?, *src.get(1).ok_or("lzma: empty")?);
    let (pb, lc, lp) = (b0 & 7, b1 & 15, b1 >> 4);
    if pb > 4 || lc > 8 || lp > 4 || (b0 >> 3) != lc + lp {
        return Err("lzma: bad UPX header".into());
    }
    let dict = (out_len as u32).max(1 << 16).checked_next_power_of_two().unwrap_or(1 << 30).min(1 << 30);
    let mut raw = Vec::with_capacity(src.len() + 3);
    raw.push((pb * 5 + lp) * 9 + lc);
    raw.extend_from_slice(&dict.to_le_bytes());
    raw.extend_from_slice(&src[2..]);
    let out = codecs::decompress(Codec::Lzma, &raw, Some(out_len), MAX_UNPACKED)?;
    if out.len() != out_len {
        return Err(format!("lzma: {} bytes, header says {out_len}", out.len()));
    }
    Ok(out)
}

/// Decompresses `c_len` bytes for `method` (UPX M_NRV2B_LE32 = 2, M_NRV2D_LE32 = 5,
/// M_NRV2E_LE32 = 8, M_LZMA = 14).
pub fn decompress(method: u8, src: &[u8], out_len: usize) -> Result<Vec<u8>, String> {
    match method {
        2 => nrv(Nrv::B, src, out_len),
        5 => nrv(Nrv::D, src, out_len),
        8 => nrv(Nrv::E, src, out_len),
        14 => lzma(src, out_len),
        m => Err(format!("method {m} not supported")),
    }
}

/// `needle` in `hay`, `None` matching any byte.
fn find_pattern(hay: &[u8], needle: &[Option<u8>]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    (0..=hay.len() - needle.len()).find(|&i| needle.iter().enumerate().all(|(j, b)| b.is_none_or(|b| hay[i + j] == b)))
}

fn pat(s: &str) -> Vec<Option<u8>> {
    s.split_whitespace().map(|t| if t == "??" { None } else { u8::from_str_radix(t, 16).ok() }).collect()
}

/// The i386 stub's call-trick loop: `mov ecx, N; (mov al,[edi]; inc edi; sub al,0E8h;
/// cmp al,1; ja ..; cmp byte [edi], cto; jnz ..)`: N, the number of calls to restore.
fn calltrick_count(stub: &[u8], cto: u8) -> Option<u32> {
    let p = pat(&format!("B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 ?? 80 3F {cto:02X} 75"));
    let at = find_pattern(stub, &p)?;
    le32(stub, at + 1)
}

/// Undoes the E8/E9 call-trick filter with a cto byte the way the stub does: the
/// first `count` calls whose next byte is `cto` get back `rel32 = BE24 - (pos + 1)`.
pub fn unfilter_calltrick(buf: &mut [u8], cto: u8, mut count: u32) {
    let mut i = 0usize;
    while count > 0 && i + 5 <= buf.len() {
        if matches!(buf[i], 0xE8 | 0xE9) && buf[i + 1] == cto {
            let v = (buf[i + 2] as u32) << 16 | (buf[i + 3] as u32) << 8 | buf[i + 4] as u32;
            let rel = v.wrapping_sub((i + 1) as u32);
            buf[i + 1..i + 5].copy_from_slice(&rel.to_le_bytes());
            count -= 1;
            i += 5;
        } else {
            i += 1;
        }
    }
}

/// The stub's import loop: `lea edi/rdi, [esi+IMPORTS]; ...; lea eax/rcx, [eax+esi+NAMES]`.
/// Both are offsets from the unpack base (the first section).
fn import_table_offsets(stub: &[u8], is_64: bool) -> Option<(u32, u32)> {
    let (p, imp_at, names_at) = if is_64 {
        (pat("48 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 48 8D 8C 30 ?? ?? ?? ?? 48 01 F3 48 83 C7 08"), 3, 20)
    } else {
        (pat("8D BE ?? ?? ?? ?? 8B 07 09 C0 74 ?? 8B 5F 04 8D 84 30 ?? ?? ?? ?? 01 F3 50 83 C7 08"), 2, 18)
    };
    let at = find_pattern(stub, &p)?;
    Some((le32(stub, at + imp_at)?, le32(stub, at + names_at)?))
}

fn cstr(d: &[u8], o: usize) -> Option<String> {
    let s = d.get(o..)?;
    let end = s.iter().take(512).position(|&b| b == 0)?;
    let s = &s[..end];
    (!s.is_empty() && s.iter().all(|b| b.is_ascii_graphic() || *b == b' ')).then(|| String::from_utf8_lossy(s).into_owned())
}

/// Reads the stub's import list from the image: entries `[u32 name, u32 iat]` (0 ends),
/// each followed by its imports: a flag byte (0 ends the DLL; high bit set = ordinal,
/// u16 follows; else a NUL-terminated name).
fn read_imports(image: &[u8], at: usize, names_base: usize) -> Option<(Vec<(String, Vec<String>)>, usize)> {
    let mut out = Vec::new();
    let mut p = at;
    let mut total = 0usize;
    loop {
        let name_off = le32(image, p)?;
        if name_off == 0 {
            p += 4;
            break;
        }
        let dll = cstr(image, names_base.checked_add(name_off as usize)?)?;
        p += 8;
        let mut funcs = Vec::new();
        loop {
            let flag = *image.get(p)?;
            p += 1;
            if flag == 0 {
                break;
            }
            if flag & 0x80 != 0 {
                funcs.push(format!("ord_{}", le16(image, p)?));
                p += 2;
            } else {
                let name = cstr(image, p)?;
                p += name.len() + 1;
                funcs.push(name);
            }
            total += 1;
            if total > MAX_IMPORTS {
                return None;
            }
        }
        out.push((dll, funcs));
        if out.len() > MAX_DLLS {
            return None;
        }
    }
    Some((out, p))
}

/// The stub's relocation loop, right after the import loop: `add edi,4; lea
/// ebx,[esi-4]; (xor eax,eax; mov al,[edi]; inc edi; or eax,eax; jz done; cmp al,0EFh;
/// ja ..; add ebx,eax; mov eax,[ebx]; bswap; add eax,esi; mov [ebx],eax)`; the x64 stub
/// does the same on qwords (`mov rax,[rbx]; bswap rax; add rax,rsi`).
fn has_reloc_loop(stub: &[u8], is_64: bool) -> bool {
    let p = if is_64 {
        pat("48 83 C7 04 48 8D 5E FC 31 C0 8A 07 48 FF C7 09 C0 74 ?? 3C EF 77 ?? 48 01 C3 48 8B 03 48 0F C8 48 01 F0 48 89 03")
    } else {
        pat("83 C7 04 8D 5E FC 31 C0 8A 07 47 09 C0 74 ?? 3C EF 77 ?? 01 C3 8B 03 86 C4 C1 C0 10 86 C4 01 F0 89 03")
    };
    find_pattern(stub, &p).is_some()
}

/// Applies UPX's relocation list at `at` (right after the import table) to the image
/// the way the stub does: a delta per address (1..0xEF; 0xF0+ = 20-bit delta
/// `(b & 0xF) << 16 | u16`, or a u32 when that is 0; 0 ends), starting 4 bytes before
/// the unpack base; each dword (qword for x64) is stored byte-swapped and without the
/// base: `bswap(v) + base_va`.
fn apply_relocs(image: &mut [u8], at: usize, dest: usize, base_va: u64, is_64: bool) -> Option<usize> {
    let mut p = at;
    let mut addr = dest.checked_sub(4)?;
    let mut n = 0usize;
    loop {
        let b = *image.get(p)? as usize;
        p += 1;
        if b == 0 {
            break;
        }
        let delta = if b <= 0xEF {
            b
        } else {
            let d = ((b & 0x0F) << 16) | le16(image, p)? as usize;
            p += 2;
            if d != 0 {
                d
            } else {
                let d = le32(image, p)? as usize;
                p += 4;
                d
            }
        };
        addr = addr.checked_add(delta)?;
        if is_64 {
            let v = u64::from_le_bytes(image.get(addr..addr + 8)?.try_into().ok()?);
            image[addr..addr + 8].copy_from_slice(&v.swap_bytes().wrapping_add(base_va).to_le_bytes());
        } else {
            let v = le32(image, addr)?;
            image[addr..addr + 4].copy_from_slice(&v.swap_bytes().wrapping_add(base_va as u32).to_le_bytes());
        }
        n += 1;
        if n > 1 << 24 {
            return None;
        }
    }
    Some(n)
}

/// Size of the base relocation directory in the original PE header at `oh`.
fn original_reloc_size(buf: &[u8], oh: usize) -> Option<u32> {
    let opt = oh + 24;
    let dirs = match le16(buf, opt)? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    le32(buf, dirs + 5 * 8 + 4)
}

/// Unpacks a UPX'd PE into its memory image (the packed headers and sections, the
/// first section onward overwritten with the unpacked data, the way the stub leaves it).
pub fn unpack(data: &[u8]) -> Result<Unpacked, String> {
    let h = header(data).ok_or("no UPX header")?;
    let pe = le32(data, 0x3c).ok_or("not a PE")? as usize;
    if data.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("not a PE".into());
    }
    let nsec = le16(data, pe + 6).ok_or("bad PE")? as usize;
    let opt = pe + 24;
    let is_64 = match le16(data, opt).ok_or("bad PE")? {
        0x10b => false,
        0x20b => true,
        _ => return Err("bad optional header".into()),
    };
    if is_64 != (h.format == FMT_WIN64_PE) {
        return Err("format and PE bitness differ".into());
    }
    let ep = le32(data, opt + 16).ok_or("bad PE")? as usize;
    let size_of_image = le32(data, opt + 56).ok_or("bad PE")? as usize;
    let size_of_headers = le32(data, opt + 60).ok_or("bad PE")? as usize;
    if size_of_image == 0 || size_of_image > MAX_UNPACKED {
        return Err("image too big".into());
    }
    let sh = opt + le16(data, pe + 20).ok_or("bad PE")? as usize;
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec.min(96) {
        let o = sh + 40 * i;
        let (vs, va, rs, ro) = (le32(data, o + 8), le32(data, o + 12), le32(data, o + 16), le32(data, o + 20));
        sections.push((vs.ok_or("bad sections")? as usize, va.ok_or("bad sections")? as usize, rs.ok_or("bad sections")? as usize, ro.ok_or("bad sections")? as usize));
    }
    // The stub and the compressed block are in the entry point's section; the
    // program is unpacked to the first section.
    let &(_, ep_va, ep_rs, ep_ro) = sections
        .iter()
        .find(|&&(vs, va, rs, _)| ep >= va && ep < va + vs.max(rs))
        .ok_or("entry point outside the sections")?;
    let dest = sections.iter().map(|s| s.1).min().ok_or("no sections")?;
    let sec_raw = data.get(ep_ro..(ep_ro + ep_rs).min(data.len())).ok_or("bad entry section")?;
    let (c_len, u_len) = (h.c_len as usize, h.u_len as usize);
    let skew = find_by_adler(sec_raw, c_len, h.c_adler, MAX_BLOCK_SKEW).ok_or("compressed block not found")?;
    let mut buf = decompress(h.method, &sec_raw[skew..skew + c_len], u_len)?;
    if adler32(&buf) != h.u_adler {
        return Err("unpacked data does not match the header checksum".into());
    }
    let stub = sec_raw.get(ep - ep_va..).unwrap_or(&[]);
    let stub = &stub[..stub.len().min(0x4000)];
    match h.filter {
        0 => {}
        0x26 if !is_64 => {
            let n = calltrick_count(stub, h.filter_cto).ok_or("filter loop not found")?;
            unfilter_calltrick(&mut buf, h.filter_cto, n);
        }
        f => return Err(format!("filter {f:#x} not supported")),
    }
    // The original entry point: the unpacked data ends with the original PE header.
    let tail = buf.len().saturating_sub(0x4000);
    let oh = buf[tail..].windows(4).rposition(|w| w == b"PE\0\0").map(|p| p + tail).ok_or("original header not found")?;
    let oep_rva = le32(&buf, oh + 24 + 16).ok_or("original header cut")?;
    if oep_rva as usize >= size_of_image {
        return Err("original entry point outside the image".into());
    }
    // The memory image the stub leaves.
    if dest + u_len > size_of_image {
        return Err("unpacked data does not fit the image".into());
    }
    let mut image = vec![0u8; size_of_image];
    let hdr = size_of_headers.min(data.len()).min(size_of_image);
    image[..hdr].copy_from_slice(&data[..hdr]);
    for &(vs, va, rs, ro) in &sections {
        let n = rs.min(vs.max(rs)).min(data.len().saturating_sub(ro)).min(size_of_image.saturating_sub(va));
        if n > 0 && ro < data.len() {
            image[va..va + n].copy_from_slice(&data[ro..ro + n]);
        }
    }
    image[dest..dest + u_len].copy_from_slice(&buf);
    let (imp, names) = import_table_offsets(stub, is_64).ok_or("import loop not found")?;
    let (imports, after_imports) =
        read_imports(&image, dest.wrapping_add(imp as usize), dest.wrapping_add(names as usize)).ok_or("import table unreadable")?;
    // Relocations: the stub applies its own list (right after the imports) when the
    // program has any. A stub whose loop is not this one is left to the emulator.
    let reloc_loop = has_reloc_loop(stub, is_64);
    if original_reloc_size(&buf, oh).unwrap_or(0) != 0 || reloc_loop {
        if !reloc_loop {
            return Err("relocation loop not found".into());
        }
        let image_base = if is_64 {
            u64::from_le_bytes(data.get(opt + 24..opt + 32).ok_or("bad PE")?.try_into().map_err(|_| "bad PE")?)
        } else {
            le32(data, opt + 28).ok_or("bad PE")? as u64
        };
        let base_va = image_base.wrapping_add(dest as u64);
        apply_relocs(&mut image, after_imports, dest, base_va, is_64).ok_or("relocation list unreadable")?;
    }
    Ok(Unpacked { header: h, image, oep_rva, imports })
}

/// [`unpack`] as a PE file (file offset = RVA, imports rebuilt by name), like the
/// emulator's dump of an unpacked image.
pub fn unpack_pe(data: &[u8]) -> Result<Vec<u8>, String> {
    let u = unpack(data)?;
    let mut imports: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for (dll, funcs) in u.imports {
        imports.entry(dll).or_default().extend(funcs.into_iter().map(|f| (f, 0)));
    }
    super::imagedump::image_to_pe(u.image, u.oep_rva, imports).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler_rolls_like_the_direct_sum() {
        // Pseudo-random (an LCG), so no window repeats.
        let mut x = 12345u32;
        let data: Vec<u8> = (0..5000)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
                (x >> 16) as u8
            })
            .collect();
        let want = adler32(&data[1234..1234 + 2000]);
        assert_eq!(find_by_adler(&data, 2000, want, 3000), Some(1234));
        assert_eq!(find_by_adler(&data, 2000, want ^ 1, 3000), None);
    }

    #[test]
    fn calltrick_unfilter_restores_relative_calls() {
        // E8 at 3 stored as `E8 cto 00 01 04`: the stub gives back
        // rel = BE24 - (pos + 1) = 0x104 - 4.
        let mut b = vec![0x90, 0x90, 0x90, 0xE8, 0x63, 0x00, 0x01, 0x04, 0xE8, 0x11, 0x22, 0x33, 0x44];
        unfilter_calltrick(&mut b, 0x63, 1);
        assert_eq!(&b[4..8], &0x100u32.to_le_bytes());
        // Not a filtered call (next byte is not cto): left alone; the count is spent.
        assert_eq!(&b[8..13], &[0xE8, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn stub_loops_are_read() {
        let stub = [0x5E, 0x89, 0xF7, 0xB9, 0xDD, 0x08, 0x00, 0x00, 0x8A, 0x07, 0x47, 0x2C, 0xE8, 0x3C, 0x01, 0x77, 0xF7, 0x80, 0x3F, 0x09, 0x75, 0xF2];
        assert_eq!(calltrick_count(&stub, 0x09), Some(0x8dd));
        assert_eq!(calltrick_count(&stub, 0x63), None);
        let imp = [0x8D, 0xBE, 0x00, 0x30, 0x0E, 0x00, 0x8B, 0x07, 0x09, 0xC0, 0x74, 0x3C, 0x8B, 0x5F, 0x04, 0x8D, 0x84, 0x30, 0x6C, 0x82, 0x0E, 0x00, 0x01, 0xF3, 0x50, 0x83, 0xC7, 0x08];
        assert_eq!(import_table_offsets(&imp, false), Some((0xE3000, 0xE826C)));
    }

    #[test]
    fn import_list_is_parsed() {
        let mut img = vec![0u8; 0x200];
        img[0x100..0x10D].copy_from_slice(b"KERNEL32.DLL\0");
        // [name 0x100 - base 0][iat] then 1 "Sleep", 0xFF ordinal 7, 0; then end.
        let mut t = Vec::new();
        t.extend_from_slice(&0x100u32.to_le_bytes());
        t.extend_from_slice(&0x40u32.to_le_bytes());
        t.extend_from_slice(b"\x01Sleep\0\xFF\x07\x00\x00");
        t.extend_from_slice(&0u32.to_le_bytes());
        img[0x20..0x20 + t.len()].copy_from_slice(&t);
        let (got, end) = read_imports(&img, 0x20, 0).unwrap();
        assert_eq!(end, 0x20 + t.len());
        assert_eq!(got, vec![("KERNEL32.DLL".to_string(), vec!["Sleep".to_string(), "ord_7".to_string()])]);
    }

    #[test]
    fn relocations_are_applied_like_the_stub() {
        // Base 0x1000: the first address is base-4+8 = 0x1004, the next +0x100 (a
        // 20-bit form: F0 then u16 0x0100), then the end.
        let mut img = vec![0u8; 0x2000];
        img[0x1004..0x1008].copy_from_slice(&0x0000_2000u32.swap_bytes().to_le_bytes());
        img[0x1104..0x1108].copy_from_slice(&0x0000_0010u32.swap_bytes().to_le_bytes());
        img[0x10..0x15].copy_from_slice(&[0x08, 0xF0, 0x00, 0x01, 0x00]);
        assert_eq!(apply_relocs(&mut img, 0x10, 0x1000, 0x40_1000, false), Some(2));
        assert_eq!(le32(&img, 0x1004), Some(0x40_3000));
        assert_eq!(le32(&img, 0x1104), Some(0x40_1010));
    }

    #[test]
    fn nrv2b_literals_and_end_marker() {
        // Bits (MSB first in each le32 word): 1 (literal 'A'), 1 (literal 'B'), 0 (no
        // literal), then the end marker: an offset gamma of 0x1000002, which with the
        // byte 0xFF gives 0xFFFFFFFF.
        let mut stream: Vec<u8> = Vec::new();
        let mut bits: Vec<u32> = vec![1, 1, 0];
        // m_off gamma for 0x1000002: m_off starts at 1; each step m_off = m_off*2 + bit,
        // then a stop bit (1 = stop). 0x1000002 = binary 1 0000 0000 0000 0000 0000 0010.
        let target: u32 = 0x1000002;
        let nbits = 32 - target.leading_zeros();
        for i in (0..nbits - 1).rev() {
            bits.push((target >> i) & 1);
            bits.push(if i == 0 { 1 } else { 0 });
        }
        // Words of 32 bits; literal bytes follow the word that announced them, the
        // offset byte follows the word holding the last gamma bit.
        let mut word = 0u32;
        let mut k = 0;
        let mut out_words = Vec::new();
        for b in &bits {
            word |= b << (31 - k);
            k += 1;
            if k == 32 {
                out_words.push(word);
                word = 0;
                k = 0;
            }
        }
        out_words.push(word);
        assert_eq!(out_words.len(), 2, "test layout: two words");
        // word0 bits: lit, lit, gamma...; bytes 'A','B' are read right after word0.
        stream.extend_from_slice(&out_words[0].to_le_bytes());
        stream.extend_from_slice(b"AB");
        stream.extend_from_slice(&out_words[1].to_le_bytes());
        stream.push(0xFF);
        assert_eq!(nrv(Nrv::B, &stream, 2).unwrap(), b"AB");
    }

    /// Real samples (when present): every one unpacks, matches the header's checksum
    /// and has imports.
    #[test]
    fn real_samples_unpack() {
        let Ok(dir) = std::env::var("UPX_SAMPLES") else { return };
        let mut n = 0;
        for e in std::fs::read_dir(dir).unwrap().flatten() {
            let d = std::fs::read(e.path()).unwrap();
            if header(&d).is_none() {
                continue;
            }
            let u = unpack(&d).unwrap_or_else(|err| panic!("{}: {err}", e.path().display()));
            assert!(!u.imports.is_empty());
            n += 1;
        }
        assert!(n > 0);
    }
}
