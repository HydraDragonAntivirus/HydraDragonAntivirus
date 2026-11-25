//! Pure-Rust RFC 1321 MD5, SHA-1, SHA-256, and Mandiant-compatible PE IMPHASH computation.
//!
//! Uses only crates already present in Cargo.lock (`sha1`, `sha2`, `hex`, `moka`).

use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, UNIX_EPOCH};

const MAX_HASHABLE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_IMPHASH_PE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileHashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    pub size: u64,
}

// ============================================================================
// Pure-Rust RFC 1321 MD5
// ============================================================================

const MD5_SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

pub struct Md5Hasher {
    state: [u32; 4],
    total_len: u64,
    buffer: [u8; 64],
    buf_len: usize,
}

impl Md5Hasher {
    pub fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            total_len: 0,
            buffer: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut idx = 0usize;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buffer[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buffer[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buffer;
            self.compress(&block);
            self.buf_len = 0;
            idx = need;
        }

        while idx + 64 <= data.len() {
            let block: &[u8; 64] = data[idx..idx + 64].try_into().unwrap();
            self.compress(block);
            idx += 64;
        }

        if idx < data.len() {
            let rem = data.len() - idx;
            self.buffer[..rem].copy_from_slice(&data[idx..]);
            self.buf_len = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        let zero_pad = if self.buf_len <= 56 {
            56 - self.buf_len
        } else {
            64 - self.buf_len + 56
        };
        if zero_pad > 0 {
            let zeros = [0u8; 64];
            let mut rem = zero_pad;
            while rem > 0 {
                let n = rem.min(64);
                self.update(&zeros[..n]);
                rem -= n;
            }
        }
        self.update(&bit_len.to_le_bytes());

        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        hex::encode(self.finalize())
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            m[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        let [mut a, mut b, mut c, mut d] = self.state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            let sum = a
                .wrapping_add(f)
                .wrapping_add(MD5_K[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(MD5_SHIFTS[i]));
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

impl Default for Md5Hasher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn md5_hex(data: &[u8]) -> String {
    let mut h = Md5Hasher::new();
    h.update(data);
    h.finalize_hex()
}

// ============================================================================
// Pure-Rust Mandiant-Spec PE IMPHASH
// ============================================================================

#[inline]
fn read_u16_le(bytes: &[u8], off: usize) -> Option<u16> {
    let slice = bytes.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

#[inline]
fn read_u32_le(bytes: &[u8], off: usize) -> Option<u32> {
    let slice = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u64_le(bytes: &[u8], off: usize) -> Option<u64> {
    let slice = bytes.get(off..off + 8)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

#[derive(Clone, Copy)]
struct PeSection {
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
}

fn rva_to_offset(rva: u32, sections: &[PeSection], size_of_headers: u32) -> Option<usize> {
    if rva == 0 {
        return None;
    }
    for sec in sections {
        let span = sec.virtual_size.max(sec.raw_size);
        if span == 0 {
            continue;
        }
        if rva >= sec.virtual_address && rva < sec.virtual_address.saturating_add(span) {
            let delta = rva - sec.virtual_address;
            if delta < sec.raw_size {
                return sec.raw_ptr.checked_add(delta).map(|v| v as usize);
            }
            return None;
        }
    }
    if rva < size_of_headers {
        return Some(rva as usize);
    }
    None
}

fn read_cstr_ascii(bytes: &[u8], off: usize, max_len: usize) -> Option<String> {
    if off >= bytes.len() {
        return None;
    }
    let end = (off + max_len).min(bytes.len());
    let slice = &bytes[off..end];
    let nul_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    if nul_pos == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&slice[..nul_pos]).into_owned())
}

fn normalize_imphash_dll(dll: &str) -> String {
    let lower = dll.trim().to_ascii_lowercase();
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    lower
}

fn resolve_known_ordinal(dll_stem: &str, ord: u16) -> Option<&'static str> {
    match dll_stem {
        "ws2_32" | "wsock32" => match ord {
            1 => Some("accept"),
            2 => Some("bind"),
            3 => Some("closesocket"),
            4 => Some("connect"),
            5 => Some("getpeername"),
            6 => Some("getsockname"),
            7 => Some("getsockopt"),
            8 => Some("htonl"),
            9 => Some("htons"),
            10 => Some("ioctlsocket"),
            11 => Some("inet_addr"),
            12 => Some("inet_ntoa"),
            13 => Some("listen"),
            14 => Some("ntohl"),
            15 => Some("ntohs"),
            16 => Some("recv"),
            17 => Some("recvfrom"),
            18 => Some("select"),
            19 => Some("send"),
            20 => Some("sendto"),
            21 => Some("setsockopt"),
            22 => Some("shutdown"),
            23 => Some("socket"),
            51 => Some("gethostbyaddr"),
            52 => Some("gethostbyname"),
            57 => Some("gethostname"),
            111 => Some("wsagetlasterror"),
            112 => Some("wsasetlasterror"),
            115 => Some("wsastartup"),
            116 => Some("wsacleanup"),
            151 => Some("__wsafdisset"),
            _ => None,
        },
        "oleaut32" => match ord {
            2 => Some("sysallocstring"),
            4 => Some("sysallocstringlen"),
            6 => Some("sysfreestring"),
            7 => Some("sysstringlen"),
            8 => Some("variantinit"),
            9 => Some("variantclear"),
            10 => Some("variantcopy"),
            12 => Some("variantchangetype"),
            _ => None,
        },
        _ => None,
    }
}

/// Computes Mandiant-compatible PE IMPHASH (MD5 of normalized `dll.func,...`).
pub fn compute_imphash_from_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 64 || read_u16_le(bytes, 0)? != 0x5a4d {
        return None;
    }
    let e_lfanew = read_u32_le(bytes, 0x3c)? as usize;
    if e_lfanew.checked_add(24)? > bytes.len() {
        return None;
    }
    if read_u32_le(bytes, e_lfanew)? != 0x0000_4550 {
        return None;
    }

    let file_hdr_off = e_lfanew + 4;
    let num_sections = read_u16_le(bytes, file_hdr_off + 2)? as usize;
    let size_of_opt = read_u16_le(bytes, file_hdr_off + 16)? as usize;
    let opt_off = file_hdr_off + 20;
    if size_of_opt < 96 || opt_off.checked_add(size_of_opt)? > bytes.len() {
        return None;
    }

    let magic = read_u16_le(bytes, opt_off)?;
    let (is_pe32_plus, num_rva_off, data_dir_off) = match magic {
        0x010b => (false, opt_off + 92, opt_off + 96),
        0x020b => {
            if size_of_opt < 112 {
                return None;
            }
            (true, opt_off + 108, opt_off + 112)
        }
        _ => return None,
    };

    let size_of_headers = read_u32_le(bytes, opt_off + 60).unwrap_or(0);
    let num_rvas = read_u32_le(bytes, num_rva_off)?;
    if num_rvas < 2 || data_dir_off.checked_add(16)? > bytes.len() {
        return None;
    }

    let import_rva = read_u32_le(bytes, data_dir_off + 8)?;
    let import_size = read_u32_le(bytes, data_dir_off + 12)?;
    if import_rva == 0 || import_size == 0 {
        return None;
    }

    let sec_table_off = opt_off + size_of_opt;
    let max_sections = num_sections.min(256);
    let mut sections = Vec::with_capacity(max_sections);
    for i in 0..max_sections {
        let s_off = sec_table_off + i * 40;
        if s_off + 40 > bytes.len() {
            break;
        }
        sections.push(PeSection {
            virtual_size: read_u32_le(bytes, s_off + 8).unwrap_or(0),
            virtual_address: read_u32_le(bytes, s_off + 12).unwrap_or(0),
            raw_size: read_u32_le(bytes, s_off + 16).unwrap_or(0),
            raw_ptr: read_u32_le(bytes, s_off + 20).unwrap_or(0),
        });
    }

    let mut desc_off = rva_to_offset(import_rva, &sections, size_of_headers)?;
    let mut imports: Vec<String> = Vec::new();

    for _ in 0..4096 {
        if desc_off + 20 > bytes.len() {
            break;
        }
        let oft = read_u32_le(bytes, desc_off)?;
        let name_rva = read_u32_le(bytes, desc_off + 12)?;
        let ft = read_u32_le(bytes, desc_off + 16)?;
        desc_off += 20;

        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let Some(name_off) = rva_to_offset(name_rva, &sections, size_of_headers) else {
            continue;
        };
        let Some(dll_name) = read_cstr_ascii(bytes, name_off, 256) else {
            continue;
        };
        let dll_stem = normalize_imphash_dll(&dll_name);
        if dll_stem.is_empty() {
            continue;
        }

        let thunk_table_rva = if oft != 0 { oft } else { ft };
        let Some(mut thunk_off) = rva_to_offset(thunk_table_rva, &sections, size_of_headers) else {
            continue;
        };

        for _ in 0..65536 {
            if is_pe32_plus {
                let Some(val) = read_u64_le(bytes, thunk_off) else {
                    break;
                };
                if val == 0 {
                    break;
                }
                thunk_off += 8;
                if (val & 0x8000_0000_0000_0000) != 0 {
                    let ord = (val & 0xffff) as u16;
                    let fn_name = resolve_known_ordinal(&dll_stem, ord)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ord{ord}"));
                    imports.push(format!("{dll_stem}.{fn_name}"));
                } else if let Some(hint_off) =
                    rva_to_offset((val & 0x7fff_ffff) as u32, &sections, size_of_headers)
                {
                    if let Some(fn_name) = read_cstr_ascii(bytes, hint_off + 2, 512) {
                        imports.push(format!("{dll_stem}.{}", fn_name.to_ascii_lowercase()));
                    }
                }
            } else {
                let Some(val) = read_u32_le(bytes, thunk_off) else {
                    break;
                };
                if val == 0 {
                    break;
                }
                thunk_off += 4;
                if (val & 0x8000_0000) != 0 {
                    let ord = (val & 0xffff) as u16;
                    let fn_name = resolve_known_ordinal(&dll_stem, ord)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("ord{ord}"));
                    imports.push(format!("{dll_stem}.{fn_name}"));
                } else if let Some(hint_off) =
                    rva_to_offset(val & 0x7fff_ffff, &sections, size_of_headers)
                {
                    if let Some(fn_name) = read_cstr_ascii(bytes, hint_off + 2, 512) {
                        imports.push(format!("{dll_stem}.{}", fn_name.to_ascii_lowercase()));
                    }
                }
            }
        }
    }

    if imports.is_empty() {
        return None;
    }
    Some(md5_hex(imports.join(",").as_bytes()))
}

// ============================================================================
// Device Path Normalization + Cached File Hash Computation
// ============================================================================

#[cfg(target_os = "windows")]
fn build_dos_device_map() -> HashMap<String, String> {
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows::core::PCWSTR;

    let mut map = HashMap::new();
    let mut target_buf = vec![0u16; 512];
    for letter in b'A'..=b'Z' {
        let drive_utf16: [u16; 3] = [letter as u16, b':' as u16, 0];
        let copied = unsafe { QueryDosDeviceW(PCWSTR(drive_utf16.as_ptr()), Some(&mut target_buf)) };
        if copied > 0 {
            let end = target_buf
                .iter()
                .take(copied as usize)
                .position(|&c| c == 0)
                .unwrap_or(copied as usize);
            let nt_prefix = String::from_utf16_lossy(&target_buf[..end]).to_ascii_lowercase();
            if !nt_prefix.is_empty() {
                map.insert(nt_prefix, format!("{}:", letter as char));
            }
        }
    }
    map
}

#[cfg(not(target_os = "windows"))]
fn build_dos_device_map() -> HashMap<String, String> {
    HashMap::new()
}

fn dos_device_map() -> &'static RwLock<HashMap<String, String>> {
    static MAP: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();
    MAP.get_or_init(|| RwLock::new(build_dos_device_map()))
}

pub fn normalize_windows_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let norm = trimmed.replace('/', "\\");
    let lower = norm.to_ascii_lowercase();

    if lower.starts_with("\\device\\namedpipe\\")
        || lower.starts_with("\\device\\mailslot\\")
        || lower.starts_with("\\\\.\\pipe\\")
    {
        return None;
    }
    if let Some(rest) = norm.strip_prefix("\\??\\") {
        if rest.to_ascii_lowercase().starts_with("unc\\") {
            return Some(format!("\\\\{}", &rest[4..]));
        }
        return Some(rest.to_string());
    }
    if let Some(rest) = norm.strip_prefix("\\\\?\\") {
        return Some(rest.to_string());
    }
    if lower.starts_with("\\systemroot\\") {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        return Some(format!("{}{}", windir.trim_end_matches('\\'), &norm["\\SystemRoot".len()..]));
    }
    if lower.starts_with("system32\\") {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        return Some(format!("{}\\{}", windir.trim_end_matches('\\'), norm));
    }
    if lower.starts_with("\\device\\") {
        let lookup = |map: &HashMap<String, String>| -> Option<String> {
            for (nt_prefix, drive) in map {
                if lower.starts_with(nt_prefix)
                    && (norm.len() == nt_prefix.len()
                        || norm.as_bytes().get(nt_prefix.len()) == Some(&b'\\'))
                {
                    return Some(format!("{}{}", drive, &norm[nt_prefix.len()..]));
                }
            }
            None
        };
        if let Ok(guard) = dos_device_map().read() {
            if let Some(found) = lookup(&guard) {
                return Some(found);
            }
        }
        let refreshed = build_dos_device_map();
        let found = lookup(&refreshed);
        if let Ok(mut guard) = dos_device_map().write() {
            *guard = refreshed;
        }
        return found;
    }

    Some(norm)
}

fn hash_cache() -> &'static Cache<(String, u64, u64), FileHashes> {
    static CACHE: OnceLock<Cache<(String, u64, u64), FileHashes>> = OnceLock::new();
    CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(16_384)
            .time_to_live(Duration::from_secs(600))
            .build()
    })
}

pub fn compute_file_hashes_cached(raw_path: &str) -> Option<FileHashes> {
    let path = normalize_windows_path(raw_path)?;
    let meta = std::fs::metadata(&path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let size = meta.len();
    if size == 0 || size > MAX_HASHABLE_FILE_BYTES {
        return None;
    }
    let mtime_secs = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let cache_key = (path.to_ascii_lowercase(), size, mtime_secs);
    if let Some(cached) = hash_cache().get(&cache_key) {
        return Some(cached);
    }

    let mut file = File::open(&path).ok()?;
    let mut md5 = Md5Hasher::new();
    let mut sha1 = <Sha1 as Sha1Digest>::new();
    let mut sha256 = <Sha256 as Sha2Digest>::new();
    let mut buf = [0u8; 64 * 1024];
    let mut pe_bytes: Option<Vec<u8>> = None;
    let mut first_chunk = true;

    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        let chunk = &buf[..n];
        md5.update(chunk);
        Sha1Digest::update(&mut sha1, chunk);
        Sha2Digest::update(&mut sha256, chunk);

        if first_chunk {
            first_chunk = false;
            if n >= 2 && chunk[0] == b'M' && chunk[1] == b'Z' && (size as usize) <= MAX_IMPHASH_PE_BYTES {
                let mut v = Vec::with_capacity(size as usize);
                v.extend_from_slice(chunk);
                pe_bytes = Some(v);
            }
        } else if let Some(ref mut v) = pe_bytes {
            if v.len() + n <= MAX_IMPHASH_PE_BYTES {
                v.extend_from_slice(chunk);
            } else {
                pe_bytes = None;
            }
        }
    }

    let imphash = pe_bytes
        .as_deref()
        .and_then(compute_imphash_from_bytes);

    let result = FileHashes {
        md5: md5.finalize_hex(),
        sha1: hex::encode(Sha1Digest::finalize(sha1)),
        sha256: hex::encode(Sha2Digest::finalize(sha256)),
        imphash,
        size,
    };
    hash_cache().insert(cache_key, result.clone());
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"a"), "0cc175b9c0f1b6a831c399e269772661");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    #[test]
    fn imphash_matches_mandiant_spec_on_synthetic_pe32() {
        // Build a minimal 1024-byte PE32 image whose single .rdata section (RVA 0x1000, file 0x200)
        // contains one IMAGE_IMPORT_DESCRIPTOR for KERNEL32.dll -> CreateFileA, WriteFile.
        let mut pe = vec![0u8; 1024];
        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());

        // PE signature + COFF header at 0x80
        let pe_off = 0x80usize;
        pe[pe_off..pe_off + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes());
        pe[pe_off + 4 + 2..pe_off + 4 + 4].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections = 1
        let opt_size: u16 = 224;
        pe[pe_off + 4 + 16..pe_off + 4 + 18].copy_from_slice(&opt_size.to_le_bytes());

        // Optional header (PE32) at 0x98
        let opt_off = pe_off + 24;
        pe[opt_off..opt_off + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic
        pe[opt_off + 60..opt_off + 64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        pe[opt_off + 92..opt_off + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // DataDirectory[1] (Import) -> RVA 0x1000, Size 40
        pe[opt_off + 96 + 8..opt_off + 96 + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[opt_off + 96 + 12..opt_off + 96 + 16].copy_from_slice(&40u32.to_le_bytes());

        // Section 0 (.rdata) right after Optional Header
        let sec_off = opt_off + opt_size as usize;
        pe[sec_off..sec_off + 6].copy_from_slice(b".rdata");
        pe[sec_off + 8..sec_off + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        pe[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // Import table inside file offset 0x200 (RVA 0x1000):
        // Descriptor 0 at 0x200 (20B), null Descriptor 1 at 0x214 (20B)
        // OFT at 0x240 (RVA 0x1040): [RVA 0x1060, RVA 0x1080, 0]
        // DLL name at 0x250 (RVA 0x1050): "KERNEL32.dll\0"
        // Hint/Name 0 at 0x260 (RVA 0x1060): 2B hint + "CreateFileA\0"
        // Hint/Name 1 at 0x280 (RVA 0x1080): 2B hint + "WriteFile\0"
        pe[0x200..0x204].copy_from_slice(&0x1040u32.to_le_bytes()); // OriginalFirstThunk
        pe[0x20c..0x210].copy_from_slice(&0x1050u32.to_le_bytes()); // Name RVA
        pe[0x210..0x214].copy_from_slice(&0x1040u32.to_le_bytes()); // FirstThunk
        pe[0x240..0x244].copy_from_slice(&0x1060u32.to_le_bytes());
        pe[0x244..0x248].copy_from_slice(&0x1080u32.to_le_bytes());
        pe[0x250..0x25d].copy_from_slice(b"KERNEL32.dll\0");
        pe[0x262..0x26e].copy_from_slice(b"CreateFileA\0");
        pe[0x282..0x28c].copy_from_slice(b"WriteFile\0");

        let expected = md5_hex(b"kernel32.createfilea,kernel32.writefile");
        assert_eq!(compute_imphash_from_bytes(&pe).as_deref(), Some(expected.as_str()));
    }
}
