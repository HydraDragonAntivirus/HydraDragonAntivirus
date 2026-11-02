//! Compound File Binary (CFB / OLE2) reader: lists the streams of a structured
//! storage file (legacy Office documents, MSI, `.msg`, embedded OLE objects) so
//! the scanner can treat each stream as an archive member, and unwraps
//! `\x01Ole10Native` packager streams to the file they embed.
//!
//! Format: [MS-CFB]. Sector chains are walked with loop and length guards,
//! the directory tree with a depth limit and a visited set; every read is
//! bounds-checked, so a hostile file yields fewer streams, never a panic.

const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const HEADER_LEN: usize = 512;
const HEADER_DIFAT_ENTRIES: usize = 109;
const DIR_ENTRY_LEN: usize = 128;

const FREESECT: u32 = 0xFFFF_FFFF;
const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
const NOSTREAM: u32 = 0xFFFF_FFFF;

const TYPE_STORAGE: u8 = 1;
const TYPE_STREAM: u8 = 2;
const TYPE_ROOT: u8 = 5;

const MAX_DIR_ENTRIES: usize = 65_536;
const MAX_STREAMS: usize = 4096;
const MAX_TREE_DEPTH: usize = 32;

/// One stream: `/`-joined storage path and its bytes (possibly truncated to the cap).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfbStream {
    pub path: String,
    pub size: u64,
    pub data: Vec<u8>,
}

pub fn is_cfb(data: &[u8]) -> bool {
    data.len() >= HEADER_LEN && data.starts_with(&SIGNATURE)
}

fn u16_at(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(off..off.checked_add(2)?)?.try_into().ok()?))
}

fn u32_at(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off.checked_add(8)?)?.try_into().ok()?))
}

struct Cfb<'a> {
    data: &'a [u8],
    sector_size: usize,
    mini_sector_size: usize,
    mini_cutoff: u64,
    fat: Vec<u32>,
    minifat: Vec<u32>,
    mini_stream: Vec<u8>,
    major_version: u16,
}

impl<'a> Cfb<'a> {
    fn sector(&self, id: u32) -> Option<&'a [u8]> {
        let start = (id as usize).checked_add(1)?.checked_mul(self.sector_size)?;
        self.data.get(start..start.checked_add(self.sector_size)?)
    }

    fn max_sectors(&self) -> usize {
        self.data.len() / self.sector_size + 1
    }

    /// Follow a FAT chain from `start`, copying at most `limit` bytes.
    fn read_chain(&self, start: u32, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut id = start;
        let mut steps = 0usize;
        while id != ENDOFCHAIN && id != FREESECT && out.len() < limit && steps < self.max_sectors() {
            let Some(sector) = self.sector(id) else { break };
            out.extend_from_slice(&sector[..sector.len().min(limit - out.len())]);
            id = match self.fat.get(id as usize) {
                Some(&next) => next,
                None => break,
            };
            steps += 1;
        }
        out
    }

    fn read_mini_chain(&self, start: u32, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut id = start;
        let mut steps = 0usize;
        let max_steps = self.mini_stream.len() / self.mini_sector_size + 1;
        while id != ENDOFCHAIN && id != FREESECT && out.len() < limit && steps < max_steps {
            let Some(begin) = (id as usize).checked_mul(self.mini_sector_size) else { break };
            let Some(chunk) = self.mini_stream.get(begin..begin + self.mini_sector_size) else { break };
            out.extend_from_slice(&chunk[..chunk.len().min(limit - out.len())]);
            id = match self.minifat.get(id as usize) {
                Some(&next) => next,
                None => break,
            };
            steps += 1;
        }
        out
    }

    fn stream_bytes(&self, start: u32, size: u64, cap: usize) -> Vec<u8> {
        let want = (size.min(cap as u64)) as usize;
        let mut data = if size < self.mini_cutoff {
            self.read_mini_chain(start, want)
        } else {
            self.read_chain(start, want)
        };
        data.truncate(want);
        data
    }
}

fn parse_header(data: &[u8]) -> Option<Cfb<'_>> {
    if !is_cfb(data) || u16_at(data, 0x1c)? != 0xfffe {
        return None;
    }
    let major_version = u16_at(data, 0x1a)?;
    let sector_shift = u16_at(data, 0x1e)?;
    let mini_shift = u16_at(data, 0x20)?;
    if !matches!(sector_shift, 9 | 12) || mini_shift != 6 {
        return None;
    }
    let mut cfb = Cfb {
        data,
        sector_size: 1usize << sector_shift,
        mini_sector_size: 1usize << mini_shift,
        mini_cutoff: u32_at(data, 0x38)? as u64,
        fat: Vec::new(),
        minifat: Vec::new(),
        mini_stream: Vec::new(),
        major_version,
    };

    // FAT sector ids: 109 in the header, the rest in the DIFAT chain.
    let fat_sectors = u32_at(data, 0x2c)? as usize;
    let max_sectors = cfb.max_sectors();
    if fat_sectors > max_sectors {
        return None;
    }
    let mut fat_ids: Vec<u32> = (0..HEADER_DIFAT_ENTRIES)
        .filter_map(|i| u32_at(data, 0x4c + i * 4))
        .filter(|&id| id != FREESECT)
        .collect();
    let mut difat = u32_at(data, 0x44)?;
    let mut difat_steps = 0usize;
    let per_sector = cfb.sector_size / 4;
    while difat != ENDOFCHAIN && difat != FREESECT && fat_ids.len() < fat_sectors && difat_steps < max_sectors {
        let Some(sector) = cfb.sector(difat) else { break };
        for i in 0..per_sector - 1 {
            let id = u32_at(sector, i * 4)?;
            if id != FREESECT {
                fat_ids.push(id);
            }
        }
        difat = u32_at(sector, (per_sector - 1) * 4)?;
        difat_steps += 1;
    }
    fat_ids.truncate(fat_sectors);
    for id in fat_ids {
        let Some(sector) = cfb.sector(id) else { continue };
        cfb.fat.extend((0..per_sector).filter_map(|i| u32_at(sector, i * 4)));
    }

    let minifat_start = u32_at(data, 0x3c)?;
    let minifat_bytes = cfb.read_chain(minifat_start, data.len());
    cfb.minifat = (0..minifat_bytes.len() / 4).filter_map(|i| u32_at(&minifat_bytes, i * 4)).collect();
    Some(cfb)
}

#[derive(Debug, Clone)]
struct DirEntry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

fn parse_dir_entry(raw: &[u8], major_version: u16) -> Option<DirEntry> {
    let name_len = (u16_at(raw, 0x40)? as usize).min(64);
    let units: Vec<u16> = (0..name_len / 2).filter_map(|i| u16_at(raw, i * 2)).take_while(|&u| u != 0).collect();
    let size = u64_at(raw, 0x78)?;
    Some(DirEntry {
        name: String::from_utf16_lossy(&units),
        kind: raw[0x42],
        left: u32_at(raw, 0x44)?,
        right: u32_at(raw, 0x48)?,
        child: u32_at(raw, 0x4c)?,
        start: u32_at(raw, 0x74)?,
        // Version 3 files may leave garbage in the high half.
        size: if major_version == 3 { size & 0xFFFF_FFFF } else { size },
    })
}

/// Control characters in stream names (`\x01Ole10Native`, `\x05SummaryInformation`)
/// written as `\xNN` so member paths stay printable.
fn printable_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if (c as u32) < 0x20 {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else if c == '/' {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    out
}

/// Every stream of the file with its storage path. Each stream is read up to
/// `max_stream` bytes and at most `max_total` bytes are read overall.
/// `None` when `data` is not a readable compound file.
pub fn read_streams(data: &[u8], max_stream: usize, max_total: usize) -> Option<Vec<CfbStream>> {
    let mut cfb = parse_header(data)?;
    let dir_start = u32_at(data, 0x30)?;
    let dir_bytes = cfb.read_chain(dir_start, MAX_DIR_ENTRIES * DIR_ENTRY_LEN);
    let entries: Vec<Option<DirEntry>> = dir_bytes
        .chunks_exact(DIR_ENTRY_LEN)
        .map(|raw| parse_dir_entry(raw, cfb.major_version))
        .collect();
    let root = entries.first()?.as_ref().filter(|e| e.kind == TYPE_ROOT)?.clone();
    cfb.mini_stream = cfb.read_chain(root.start, root.size.min(data.len() as u64) as usize);

    let mut out = Vec::new();
    let mut total = 0usize;
    let mut visited = vec![false; entries.len()];
    // (entry id, parent path, depth); siblings share the parent's depth.
    let mut stack: Vec<(u32, String, usize)> = vec![(root.child, String::new(), 0)];
    while let Some((id, parent, depth)) = stack.pop() {
        if id == NOSTREAM || depth > MAX_TREE_DEPTH || out.len() >= MAX_STREAMS {
            continue;
        }
        let idx = id as usize;
        if idx >= entries.len() || std::mem::replace(&mut visited[idx], true) {
            continue;
        }
        let Some(entry) = entries[idx].as_ref() else { continue };
        stack.push((entry.left, parent.clone(), depth));
        stack.push((entry.right, parent.clone(), depth));
        let path = if parent.is_empty() {
            printable_name(&entry.name)
        } else {
            format!("{parent}/{}", printable_name(&entry.name))
        };
        match entry.kind {
            TYPE_STORAGE => stack.push((entry.child, path, depth + 1)),
            TYPE_STREAM => {
                let budget = max_stream.min(max_total.saturating_sub(total));
                let bytes = cfb.stream_bytes(entry.start, entry.size, budget);
                total += bytes.len();
                out.push(CfbStream { path, size: entry.size, data: bytes });
            }
            _ => {}
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Some(out)
}

/// `\x01Ole10Native` packager stream -> (embedded file name, embedded bytes).
/// Layout: total size u32, u16, label\0, source path\0, u32, u32, temp path\0,
/// data size u32, data.
pub fn ole10native_payload(stream: &[u8]) -> Option<(String, Vec<u8>)> {
    fn cstr(b: &[u8], off: usize) -> Option<(String, usize)> {
        let rest = b.get(off..)?;
        let end = rest.iter().take(4096).position(|&c| c == 0)?;
        Some((String::from_utf8_lossy(&rest[..end]).into_owned(), off + end + 1))
    }
    let mut off = 4 + 2;
    let (label, next) = cstr(stream, off)?;
    off = next;
    let (source, next) = cstr(stream, off)?;
    off = next + 8;
    let (_temp, next) = cstr(stream, off)?;
    off = next;
    let size = u32_at(stream, off)? as usize;
    let payload = stream.get(off + 4..(off + 4).checked_add(size)?)?;
    let name = [label.as_str(), source.rsplit(['\\', '/']).next().unwrap_or("")]
        .into_iter()
        .find(|n| !n.trim().is_empty())
        .unwrap_or("native_data")
        .replace(['/', '\\'], "_");
    Some((name, payload.to_vec()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn dir_entry(name: &str, kind: u8, left: u32, right: u32, child: u32, start: u32, size: u64) -> Vec<u8> {
        let mut e = vec![0u8; DIR_ENTRY_LEN];
        let units: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        for (i, u) in units.iter().enumerate() {
            e[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        e[0x40..0x42].copy_from_slice(&((units.len() * 2) as u16).to_le_bytes());
        e[0x42] = kind;
        e[0x44..0x48].copy_from_slice(&left.to_le_bytes());
        e[0x48..0x4c].copy_from_slice(&right.to_le_bytes());
        e[0x4c..0x50].copy_from_slice(&child.to_le_bytes());
        e[0x74..0x78].copy_from_slice(&start.to_le_bytes());
        e[0x78..0x80].copy_from_slice(&size.to_le_bytes());
        e
    }

    /// Version-3 compound file (512-byte sectors). Layout:
    /// sector 0 FAT, 1 directory, 2 mini FAT, 3 mini stream, 4.. big stream.
    /// Streams: `Small` (mini stream), `Big` (5000 bytes, regular sectors),
    /// `Store/\x01Ole10Native` (mini stream).
    pub(crate) fn build_cfb(small: &[u8], big: &[u8], native: &[u8]) -> Vec<u8> {
        assert!(small.len() <= 128 && native.len() <= 256 && big.len() >= 4096);
        let ss = 512usize;
        let big_sectors = big.len().div_ceil(ss);
        let mut file = vec![0u8; ss * (1 + 4 + big_sectors)];
        let h = &mut file[..HEADER_LEN];
        h[..8].copy_from_slice(&SIGNATURE);
        h[0x18..0x1a].copy_from_slice(&0x3eu16.to_le_bytes());
        h[0x1a..0x1c].copy_from_slice(&3u16.to_le_bytes());
        h[0x1c..0x1e].copy_from_slice(&0xfffeu16.to_le_bytes());
        h[0x1e..0x20].copy_from_slice(&9u16.to_le_bytes());
        h[0x20..0x22].copy_from_slice(&6u16.to_le_bytes());
        h[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
        h[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        h[0x38..0x3c].copy_from_slice(&4096u32.to_le_bytes());
        h[0x3c..0x40].copy_from_slice(&2u32.to_le_bytes());
        h[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        h[0x44..0x48].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        for i in 0..HEADER_DIFAT_ENTRIES {
            let v = if i == 0 { 0 } else { FREESECT };
            h[0x4c + i * 4..0x50 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        let sec = |id: usize| (id + 1) * ss;

        // FAT
        let mut fat = vec![FREESECT; ss / 4];
        fat[0] = 0xFFFF_FFFD;
        fat[1] = ENDOFCHAIN;
        fat[2] = ENDOFCHAIN;
        fat[3] = ENDOFCHAIN;
        for i in 0..big_sectors {
            fat[4 + i] = if i + 1 == big_sectors { ENDOFCHAIN } else { (5 + i) as u32 };
        }
        for (i, v) in fat.iter().enumerate() {
            file[sec(0) + i * 4..sec(0) + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }

        // Mini stream: Small at mini sectors 0..2, native at 2..6.
        let mut minifat = vec![FREESECT; ss / 4];
        let small_ms = small.len().div_ceil(64).max(1);
        let native_ms = native.len().div_ceil(64).max(1);
        for i in 0..small_ms {
            minifat[i] = if i + 1 == small_ms { ENDOFCHAIN } else { (i + 1) as u32 };
        }
        for i in 0..native_ms {
            let id = small_ms + i;
            minifat[id] = if i + 1 == native_ms { ENDOFCHAIN } else { (id + 1) as u32 };
        }
        for (i, v) in minifat.iter().enumerate() {
            file[sec(2) + i * 4..sec(2) + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        file[sec(3)..sec(3) + small.len()].copy_from_slice(small);
        file[sec(3) + small_ms * 64..sec(3) + small_ms * 64 + native.len()].copy_from_slice(native);
        file[sec(4)..sec(4) + big.len()].copy_from_slice(big);

        // Directory: 0 root, 1 Small, 2 Big, 3 Store, (sector 1 holds 4 entries).
        let entries = [
            dir_entry("Root Entry", TYPE_ROOT, NOSTREAM, NOSTREAM, 2, 3, 512),
            dir_entry("Small", TYPE_STREAM, NOSTREAM, NOSTREAM, NOSTREAM, 0, small.len() as u64),
            dir_entry("Big", TYPE_STREAM, 1, 3, NOSTREAM, 4, big.len() as u64),
            dir_entry("Store", TYPE_STORAGE, NOSTREAM, NOSTREAM, 4, 0, 0),
        ];
        for (i, e) in entries.iter().enumerate() {
            file[sec(1) + i * DIR_ENTRY_LEN..sec(1) + (i + 1) * DIR_ENTRY_LEN].copy_from_slice(e);
        }
        // Entry 4 lives in sector 1 too only if there is room: 512 / 128 = 4,
        // so chain the directory into a second sector appended at the end.
        let dir2 = file.len() / ss - 1;
        file.resize(file.len() + ss, 0);
        let fat_off = sec(0) + 4;
        file[fat_off..fat_off + 4].copy_from_slice(&(dir2 as u32).to_le_bytes());
        file[sec(0) + dir2 * 4..sec(0) + dir2 * 4 + 4].copy_from_slice(&ENDOFCHAIN.to_le_bytes());
        let e4 = dir_entry("\u{1}Ole10Native", TYPE_STREAM, NOSTREAM, NOSTREAM, NOSTREAM, small_ms as u32, native.len() as u64);
        file[sec(dir2)..sec(dir2) + DIR_ENTRY_LEN].copy_from_slice(&e4);
        file
    }

    pub(crate) fn ole10native(label: &str, payload: &[u8]) -> Vec<u8> {
        let mut s = vec![0u8; 4];
        s.extend_from_slice(&2u16.to_le_bytes());
        s.extend_from_slice(label.as_bytes());
        s.push(0);
        s.extend_from_slice(format!("C:\\tmp\\{label}").as_bytes());
        s.push(0);
        s.extend_from_slice(&0x0003_0000u32.to_le_bytes());
        s.extend_from_slice(&10u32.to_le_bytes());
        s.extend_from_slice(b"C:\\t\\x.js\0");
        s.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        s.extend_from_slice(payload);
        let total = (s.len() - 4) as u32;
        s[..4].copy_from_slice(&total.to_le_bytes());
        s
    }

    #[test]
    fn reads_mini_regular_and_nested_streams() {
        let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let native = ole10native("dropper.js", b"WScript.Shell");
        let file = build_cfb(b"hello small stream", &big, &native);
        let streams = read_streams(&file, usize::MAX, usize::MAX).unwrap();
        let paths: Vec<&str> = streams.iter().map(|s| s.path.as_str()).collect();
        assert_eq!(paths, vec!["Big", "Small", "Store/\\x01Ole10Native"]);
        assert_eq!(streams[0].data, big);
        assert_eq!(streams[1].data, b"hello small stream");
        assert_eq!(ole10native_payload(&streams[2].data), Some(("dropper.js".to_string(), b"WScript.Shell".to_vec())));
    }

    #[test]
    fn caps_and_garbage() {
        let big = vec![0x41u8; 4096];
        let file = build_cfb(b"x", &big, &ole10native("a", b"b"));
        let streams = read_streams(&file, 100, 150).unwrap();
        assert!(streams.iter().all(|s| s.data.len() <= 100));
        assert!(streams.iter().map(|s| s.data.len()).sum::<usize>() <= 150);
        assert!(read_streams(b"not ole", 1, 1).is_none());
        for cut in [0, 8, 511, 512, 1024, 2000, file.len() - 1] {
            let _ = read_streams(&file[..cut], usize::MAX, usize::MAX);
        }
        // Self-referencing FAT chain must terminate.
        let mut looped = file.clone();
        looped[512 + 4 * 4..512 + 4 * 4 + 4].copy_from_slice(&4u32.to_le_bytes());
        let _ = read_streams(&looped, usize::MAX, usize::MAX);
        assert!(ole10native_payload(b"\x00\x00").is_none());
    }
}
