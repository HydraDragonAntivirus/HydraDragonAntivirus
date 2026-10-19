use std::collections::HashMap;
use unicorn_engine::{Prot, Unicorn};

/// String argument encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringType {
    Ansi,
    Wide,
}

/// Metadata specification for a hooked Windows API.
#[derive(Debug, Clone, Copy)]
pub struct ApiStubSpec {
    pub name: &'static str,
    pub arg_count: usize,
    pub default_ret: u64,
    pub string_args: &'static [(usize, StringType)],
}

macro_rules! api_specs {
    ($( $name:literal ( $argc:literal $(, [ $( ( $s_idx:literal , $s_type:ident ) ),* $(,)? ] )? ) -> $ret:expr );* $(;)?) => {
        pub static API_STUB_TABLE: &[ApiStubSpec] = &[
            $(
                ApiStubSpec {
                    name: $name,
                    arg_count: $argc,
                    default_ret: $ret,
                    string_args: &[ $( $( ($s_idx, StringType::$s_type) ),* )? ],
                },
            )*
        ];
    };
}

// Table of common Windows API stubs defined concisely via declarative DSL
api_specs! {
    // --- File APIs ---
    "createfilea"(7, [ (0, Ansi) ]) -> 0x1000;
    "createfilew"(7, [ (0, Wide) ]) -> 0x1000;
    "readfile"(5) -> 1;
    "writefile"(5) -> 1;
    "findfirstfilew"(2, [ (0, Wide) ]) -> 0x2000;
    "findfirstfilea"(2, [ (0, Ansi) ]) -> 0x2000;
    "findnextfilew"(2) -> 1;
    "findnextfilea"(2) -> 1;
    "findclose"(1) -> 1;
    "movefileexw"(3, [ (0, Wide), (1, Wide) ]) -> 1;
    "movefileexa"(3, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "movefilew"(2, [ (0, Wide), (1, Wide) ]) -> 1;
    "movefilea"(2, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "deletefilew"(1, [ (0, Wide) ]) -> 1;
    "deletefilea"(1, [ (0, Ansi) ]) -> 1;
    "getfileattributesw"(1, [ (0, Wide) ]) -> 0x80;
    "getfileattributesa"(1, [ (0, Ansi) ]) -> 0x80;
    "copyfilew"(3, [ (0, Wide), (1, Wide) ]) -> 1;
    "copyfilea"(3, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "copyfileexw"(6, [ (0, Wide), (1, Wide) ]) -> 1;
    "copyfileexa"(6, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "closehandle"(1) -> 1;
    "getfilesize"(2) -> 1024;
    "setfilepointer"(4) -> 0;
    "gettemppatha"(2) -> 14;
    "gettemppathw"(2) -> 14;
    "gettempfilenamea"(4, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "gettempfilenamew"(4, [ (0, Wide), (1, Wide) ]) -> 1;

    // --- Registry APIs ---
    "regopenkeya"(3, [ (1, Ansi) ]) -> 0;
    "regopenkeyw"(3, [ (1, Wide) ]) -> 0;
    "regopenkeyexa"(5, [ (1, Ansi) ]) -> 0;
    "regopenkeyexw"(5, [ (1, Wide) ]) -> 0;
    "regcreatekeya"(3, [ (1, Ansi) ]) -> 0;
    "regcreatekeyw"(3, [ (1, Wide) ]) -> 0;
    "regcreatekeyexa"(9, [ (1, Ansi) ]) -> 0;
    "regcreatekeyexw"(9, [ (1, Wide) ]) -> 0;
    "regqueryvaluea"(4, [ (1, Ansi) ]) -> 0;
    "regqueryvaluew"(4, [ (1, Wide) ]) -> 0;
    "regqueryvalueexa"(6, [ (1, Ansi) ]) -> 0;
    "regqueryvalueexw"(6, [ (1, Wide) ]) -> 0;
    "regsetvaluea"(5, [ (1, Ansi), (3, Ansi) ]) -> 0;
    "regsetvaluew"(5, [ (1, Wide), (3, Wide) ]) -> 0;
    "regsetvalueexa"(6, [ (1, Ansi) ]) -> 0;
    "regsetvalueexw"(6, [ (1, Wide) ]) -> 0;
    "regdeletekeya"(2, [ (1, Ansi) ]) -> 0;
    "regdeletekeyw"(2, [ (1, Wide) ]) -> 0;
    "regdeletekeyexa"(4, [ (1, Ansi) ]) -> 0;
    "regdeletekeyexw"(4, [ (1, Wide) ]) -> 0;
    "regdeletevaluea"(2, [ (1, Ansi) ]) -> 0;
    "regdeletevaluew"(2, [ (1, Wide) ]) -> 0;
    "regclosekey"(1) -> 0;

    // --- Process & Command Execution APIs ---
    "createprocessa"(10, [ (0, Ansi), (1, Ansi) ]) -> 1;
    "createprocessw"(10, [ (0, Wide), (1, Wide) ]) -> 1;
    "shellexecutea"(6, [ (1, Ansi), (2, Ansi), (3, Ansi), (4, Ansi) ]) -> 42;
    "shellexecutew"(6, [ (1, Wide), (2, Wide), (3, Wide), (4, Wide) ]) -> 42;
    "shellexecuteexa"(1) -> 1;
    "shellexecuteexw"(1) -> 1;
    "winexec"(2, [ (0, Ansi) ]) -> 32;
    "openprocess"(3) -> 0x1020;
    "terminateprocess"(2) -> 1;
    "exitprocess"(1) -> 0;
    "getcurrentprocess"(0) -> 0xFFFFFFFFFFFFFFFFu64;
    "getcurrentprocessid"(0) -> 1234;

    // --- Network APIs ---
    "winhttpopen"(5, [ (0, Wide) ]) -> 0x3000;
    "winhttpconnect"(4, [ (1, Wide) ]) -> 0x3004;
    "winhttpopenrequest"(7, [ (1, Wide), (2, Wide) ]) -> 0x3008;
    "winhttpsendrequest"(7) -> 1;
    "winhttpreceiveresponse"(2) -> 1;
    "winhttpreaddata"(4) -> 1;
    "winhttpclosehandle"(1) -> 1;
    "internetopena"(5, [ (0, Ansi) ]) -> 0x3000;
    "internetopenw"(5, [ (0, Wide) ]) -> 0x3000;
    "internetconnecta"(8, [ (1, Ansi) ]) -> 0x3004;
    "internetconnectw"(8, [ (1, Wide) ]) -> 0x3004;
    "httpopenrequesta"(8, [ (1, Ansi), (2, Ansi) ]) -> 0x3008;
    "httpopenrequestw"(8, [ (1, Wide), (2, Wide) ]) -> 0x3008;
    "httpsendrequesta"(5) -> 1;
    "httpsendrequestw"(5) -> 1;
    "internetclosehandle"(1) -> 1;
    "urldownloadtofilea"(5, [ (1, Ansi), (2, Ansi) ]) -> 0;
    "urldownloadtofilew"(5, [ (1, Wide), (2, Wide) ]) -> 0;
    "wsastartup"(2) -> 0;
    "wsacleanup"(0) -> 0;
    "socket"(3) -> 0x5000;
    "connect"(3) -> 0;
    "wsaconnect"(7) -> 0;
    "send"(4) -> 1;
    "recv"(4) -> 0;
    "closesocket"(1) -> 0;
    "getaddrinfo"(4, [ (0, Ansi) ]) -> 0;
    "getaddrinfow"(4, [ (0, Wide) ]) -> 0;
    "freeaddrinfo"(1) -> 0;
    "gethostbyname"(1, [ (0, Ansi) ]) -> 0;

    // --- Crypto APIs ---
    "cryptacquirecontexta"(5, [ (1, Ansi), (2, Ansi) ]) -> 1;
    "cryptacquirecontextw"(5, [ (1, Wide), (2, Wide) ]) -> 1;
    "cryptreleasecontext"(2) -> 1;
    "cryptgenrandom"(3) -> 1;
    "cryptcreatehash"(5) -> 1;
    "crypthashdata"(4) -> 1;
    "cryptderivekey"(5) -> 1;
    "cryptdestroyhash"(1) -> 1;
    "cryptdestroykey"(1) -> 1;
    "cryptencrypt"(7) -> 1;
    "cryptdecrypt"(7) -> 1;
    "bcryptopenalgorithmprovider"(4, [ (1, Wide) ]) -> 0;
    "bcryptclosealgorithmprovider"(2) -> 0;
    "bcryptgenrandom"(4) -> 0;
    "bcryptencrypt"(10) -> 0;
    "bcryptdecrypt"(10) -> 0;

    // --- Time & Anti-Evasion APIs ---
    "gettickcount"(0) -> 100_000;
    "gettickcount64"(0) -> 100_000;
    "timegettime"(0) -> 100_000;
    "queryperformancecounter"(1) -> 1;
    "queryperformancefrequency"(1) -> 1;
    "sleep"(1) -> 0;
    "sleepex"(2) -> 0;
    "isdebuggerpresent"(0) -> 0;
    "checkremotedebuggerpresent"(2) -> 1;

    // --- Module & Memory APIs ---
    "loadlibrarya"(1, [ (0, Ansi) ]) -> 0x50000000;
    "loadlibraryw"(1, [ (0, Wide) ]) -> 0x50000000;
    "loadlibraryexa"(3, [ (0, Ansi) ]) -> 0x50000000;
    "loadlibraryexw"(3, [ (0, Wide) ]) -> 0x50000000;
    "freelibrary"(1) -> 1;
    "getprocaddress"(2, [ (1, Ansi) ]) -> 0x7F080000;
    "getmodulehandlea"(1, [ (0, Ansi) ]) -> 0x400000;
    "getmodulehandlew"(1, [ (0, Wide) ]) -> 0x400000;
    "getmodulehandleexa"(3, [ (1, Ansi) ]) -> 1;
    "getmodulehandleexw"(3, [ (1, Wide) ]) -> 1;
    "getmodulefilenamea"(3) -> 12;
    "getmodulefilenamew"(3) -> 12;
    "virtualalloc"(4) -> 0x20000000;
    "virtualallocex"(5) -> 0x20000000;
    "virtualfree"(3) -> 1;
    "virtualprotect"(4) -> 1;
    "getlasterror"(0) -> 0;
    "setlasterror"(1) -> 0;
}

/// Normalizes an API name for lookup (removes prefixes, dll names, ordinal or stdcall decoration).
pub fn normalize_api_name(raw: &str) -> String {
    let mut s = raw;
    if let Some(pos) = s.rfind('!') {
        s = &s[pos + 1..];
    } else if let Some(pos) = s.rfind('.') {
        s = &s[pos + 1..];
    }
    let s = s.trim_start_matches("__imp_").trim_start_matches('_');
    let s = if let Some(at) = s.find('@') {
        &s[..at]
    } else {
        s
    };
    s.to_ascii_lowercase()
}

/// Look up API stub metadata by function name.
pub fn get_api_spec(api_name: &str) -> Option<&'static ApiStubSpec> {
    let normalized = normalize_api_name(api_name);
    API_STUB_TABLE.iter().find(|spec| spec.name == normalized)
}

/// State kept across emulated API calls (handle generation, search iterations, simulated ticks, dynamic hooks, mapped buffers).
#[derive(Debug, Clone)]
pub struct ApiState {
    pub next_file_handle: u64,
    pub next_hook_addr: u64,
    pub next_alloc_addr: u64,
    pub image_base: u64,
    pub dll_bases: HashMap<String, u64>,
    pub find_handles: HashMap<u64, u32>,
    pub file_handles: HashMap<u64, (String, bool)>,
    pub simulated_tick_count: u64,
    pub is_64: bool,
    pub dns_cache: HashMap<String, [u8; 4]>,
    pub ip_to_host: HashMap<[u8; 4], String>,
    pub next_fake_ip_index: usize,
    pub net_stub_base: u64,
    pub net_stub_offset: u64,
    pub net_stub_mapped: u64,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            next_file_handle: 0x1000,
            next_hook_addr: 0x7F080000,
            next_alloc_addr: 0x20000000,
            image_base: 0x400000,
            dll_bases: HashMap::new(),
            find_handles: HashMap::new(),
            file_handles: HashMap::new(),
            simulated_tick_count: 100_000,
            is_64: false,
            dns_cache: HashMap::new(),
            ip_to_host: HashMap::new(),
            next_fake_ip_index: 0,
            net_stub_base: 0x78000000,
            net_stub_offset: 0,
            net_stub_mapped: 0,
        }
    }
}

impl ApiState {
    /// Resolves a hostname to a unique RFC 5737 TEST-NET address (TEST-NET-1, TEST-NET-2, TEST-NET-3)
    /// or extended private range (10.200.x.y) without rollover or overwriting previous host mappings,
    /// recording both hostname -> IP and IP -> hostname so `connect()` calls can map
    /// the socket address back to the original domain name.
    pub fn resolve_or_assign_fake_ip(&mut self, host: &str) -> [u8; 4] {
        let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(&ip) = self.dns_cache.get(&clean) {
            return ip;
        }
        let idx = self.next_fake_ip_index;
        self.next_fake_ip_index += 1;

        let fake_ip = if idx < 254 {
            // RFC 5737 TEST-NET-1: 192.0.2.1 .. 192.0.2.254
            [192, 0, 2, (idx + 1) as u8]
        } else if idx < 508 {
            // RFC 5737 TEST-NET-2: 198.51.100.1 .. 198.51.100.254
            [198, 51, 100, (idx - 254 + 1) as u8]
        } else if idx < 762 {
            // RFC 5737 TEST-NET-3: 203.0.113.1 .. 203.0.113.254
            [203, 0, 113, (idx - 508 + 1) as u8]
        } else {
            // Extended private range (10.200.x.y) to prevent collision or rollover
            let ext_idx = idx - 762;
            let subnet = ((ext_idx / 254) % 250) as u8;
            let host_num = ((ext_idx % 254) + 1) as u8;
            [10, 200, subnet, host_num]
        };

        self.dns_cache.insert(clean.clone(), fake_ip);
        self.ip_to_host.insert(fake_ip, clean);
        fake_ip
    }
}

/// Allocates memory from the dedicated network stub region (0x78000000..0x7F000000), avoiding 64KB padding per call.
/// Maps 64KB pages on demand and never wraps around or overwrites previous structures.
/// Returns 0 on allocation or mapping failure.
pub fn alloc_net_stub(uc: &mut Unicorn<'_, ()>, api_state: &mut ApiState, size: usize) -> u64 {
    let aligned = (size + 15) & !15;
    let needed_end = api_state.net_stub_offset + (aligned as u64);

    // Map additional 64KB pages on demand if needed
    while needed_end > api_state.net_stub_mapped {
        let map_addr = api_state.net_stub_base + api_state.net_stub_mapped;
        // Safety bound: do not collide with HOOK_ADDR at 0x7F000000
        if map_addr >= 0x7F000000 {
            log::warn!("Network stub pool exhausted (reached HOOK_ADDR limit)");
            return 0;
        }
        if uc.mem_map(map_addr, 0x10000, Prot::ALL).is_err() {
            log::warn!("Failed to mem_map network stub page at {:#x}", map_addr);
            return 0;
        }
        api_state.net_stub_mapped += 0x10000;
    }

    let addr = api_state.net_stub_base + api_state.net_stub_offset;
    api_state.net_stub_offset += aligned as u64;
    addr
}

/// Parses a sockaddr_in structure at `addr`, returning (IPv4 bytes, port) if family == AF_INET (2).
pub fn parse_sockaddr(uc: &Unicorn<'_, ()>, addr: u64, len: usize) -> Option<([u8; 4], u16)> {
    if addr < 0x10000 || len < 8 {
        return None;
    }
    let mut buf = [0u8; 8];
    if uc.mem_read(addr, &mut buf).is_err() {
        return None;
    }
    let family = u16::from_le_bytes([buf[0], buf[1]]);
    if family == 2 {
        // AF_INET: family (2 bytes), port (2 bytes BE), IPv4 (4 bytes)
        let port = u16::from_be_bytes([buf[2], buf[3]]);
        let ip = [buf[4], buf[5], buf[6], buf[7]];
        Some((ip, port))
    } else {
        None
    }
}

/// Formats an IP:port endpoint, translating known synthetic IPs back to their original hostnames.
pub fn format_endpoint(api_state: &ApiState, ip: [u8; 4], port: u16) -> String {
    if let Some(host) = api_state.ip_to_host.get(&ip) {
        format!("{}:{}", host, port)
    } else {
        format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port)
    }
}

/// Matches a requested DLL name against loaded DLL bases (case-insensitive, optional .dll extension, path stripped).
pub fn find_dll_base(dll_bases: &HashMap<String, u64>, name: &str) -> Option<u64> {
    let mut clean = name.trim().to_ascii_lowercase();
    if let Some(pos) = clean.rfind('\\') {
        clean = clean[pos + 1..].to_string();
    }
    if let Some(pos) = clean.rfind('/') {
        clean = clean[pos + 1..].to_string();
    }
    for (k, &base) in dll_bases {
        let k_lower = k.to_ascii_lowercase();
        if k_lower == clean || k_lower.trim_end_matches(".dll") == clean.trim_end_matches(".dll") {
            return Some(base);
        }
    }
    None
}

/// Maps hooked API addresses to resolved function names and their enclosing DLL.
pub fn resolve_api_and_dll(
    addr: u64,
    dllname_to_functionlist: &HashMap<String, Vec<(String, u64)>>,
) -> (Option<String>, Option<String>) {
    for (dll, functions) in dllname_to_functionlist {
        for (name, hook_addr) in functions {
            if *hook_addr == addr {
                return (Some(name.clone()), Some(dll.clone()));
            }
        }
    }
    (None, None)
}

/// Maps hooked API addresses to resolved function names.
pub fn resolve_api_name(
    _apicall_counter: &HashMap<String, u64>,
    addr: u64,
    dllname_to_functionlist: &HashMap<String, Vec<(String, u64)>>,
) -> Option<String> {
    resolve_api_and_dll(addr, dllname_to_functionlist).0
}

/// Determines if an API uses the __cdecl calling convention (where caller cleans stack on x86)
/// rather than __stdcall (where callee cleans stack).
pub fn is_cdecl_api(api_name: &str, dll_name: Option<&str>) -> bool {
    let norm = normalize_api_name(api_name);
    if norm == "wsprintfa"
        || norm == "wsprintfw"
        || norm == "sprintf"
        || norm == "snprintf"
        || norm == "sscanf"
        || norm == "printf"
        || norm == "snwprintf"
        || norm == "swprintf"
        || norm == "scanf"
    {
        return true;
    }
    if let Some(dll) = dll_name {
        let d = dll.to_ascii_lowercase();
        if d.starts_with("msvcrt")
            || d.starts_with("ucrtbase")
            || d.starts_with("api-ms-win-crt-")
            || d.starts_with("vcruntime")
            || d.starts_with("crtdll")
        {
            return true;
        }
    }
    false
}

/// Reads a null-terminated ANSI C-string from Unicorn memory (up to 512 bytes).
pub fn read_ansi_string(uc: &Unicorn<'_, ()>, addr: u64, max_len: usize) -> Option<String> {
    if addr < 0x10000 || addr > 0x7FFFFFFF_FFFF {
        return None;
    }
    let limit = max_len.min(512);
    let mut buf = vec![0u8; limit];
    if uc.mem_read(addr, &mut buf).is_err() {
        return None;
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    if len == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..len]).to_string())
}

/// Reads a null-terminated UTF-16LE wide string from Unicorn memory (up to 512 characters).
pub fn read_wide_string(uc: &Unicorn<'_, ()>, addr: u64, max_len: usize) -> Option<String> {
    if addr < 0x10000 || addr > 0x7FFFFFFF_FFFF {
        return None;
    }
    let limit = max_len.min(512);
    let mut buf = vec![0u8; limit * 2];
    if uc.mem_read(addr, &mut buf).is_err() {
        return None;
    }
    let mut u16_chars = Vec::with_capacity(limit);
    for chunk in buf.chunks_exact(2) {
        let code = u16::from_le_bytes([chunk[0], chunk[1]]);
        if code == 0 {
            break;
        }
        u16_chars.push(code);
    }
    if u16_chars.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&u16_chars))
}

/// Heuristically probes whether an argument value points to a readable, valid null-terminated string.
/// In accordance with safe probing: validates memory range (PE image/heap/stack, excludes null/low/kernel addresses),
/// requires minimum 3 characters, valid printable content, and null termination.
pub fn probe_string_arg(uc: &Unicorn<'_, ()>, val: u64, is_wide_hint: bool) -> Option<String> {
    if val < 0x10000 || val > 0x7FFFFFFF_FFFF {
        return None;
    }

    if is_wide_hint {
        if let Some(s) = read_wide_string(uc, val, 512) {
            if s.len() >= 3 && s.chars().all(|c| !c.is_control() || c == '\r' || c == '\n' || c == '\t') {
                return Some(s);
            }
        }
    }

    if let Some(s) = read_ansi_string(uc, val, 512) {
        if s.len() >= 3 && s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            return Some(s);
        }
    }

    if !is_wide_hint {
        if let Some(s) = read_wide_string(uc, val, 512) {
            if s.len() >= 3 && s.chars().all(|c| !c.is_control() || c == '\r' || c == '\n' || c == '\t') {
                return Some(s);
            }
        }
    }

    None
}

/// Analyzes the call site immediately preceding `ret_addr` to estimate how many arguments were pushed
/// on the stack for a 32-bit x86 stdcall invocation.
/// Inspects backward up to 32 bytes to find the call instruction (indirect, direct, or register)
/// and counts the preceding `push` opcodes.
pub fn estimate_x86_stdcall_arg_count(uc: &Unicorn<'_, ()>, ret_addr: u64) -> Option<usize> {
    if ret_addr < 2 {
        return None;
    }
    // Try reading up to 32 bytes before ret_addr. If reading 32 bytes fails (e.g. crosses page boundary),
    // try smaller windows (24, 16, 10, 8, 6).
    let mut read_bytes = None;
    for &try_size in &[32u64, 24, 16, 10, 8, 6] {
        if ret_addr >= try_size {
            let start = ret_addr - try_size;
            let mut buf = vec![0u8; try_size as usize];
            if uc.mem_read(start, &mut buf).is_ok() {
                read_bytes = Some(buf);
                break;
            }
        }
    }
    let buf = read_bytes?;
    let len = buf.len();
    if len < 2 {
        return None;
    }

    // Call instruction ends at index `len`:
    // 1. call dword ptr [mem32] -> FF 15 xx xx xx xx (6 bytes)
    // 2. call reg -> FF D0-D7 (2 bytes)
    // 3. call rel32 -> E8 xx xx xx xx (5 bytes)
    // 4. call dword ptr [reg+off8] -> FF 50..57 xx (3 bytes)
    let call_start_idx = if len >= 6 && buf[len - 6] == 0xFF && buf[len - 5] == 0x15 {
        len - 6
    } else if len >= 2 && buf[len - 2] == 0xFF && (0xD0..=0xD7).contains(&buf[len - 1]) {
        len - 2
    } else if len >= 5 && buf[len - 5] == 0xE8 {
        len - 5
    } else if len >= 3 && buf[len - 3] == 0xFF && (0x50..=0x57).contains(&buf[len - 2]) {
        len - 3
    } else {
        return None;
    };

    let mut curr = call_start_idx;
    let mut push_count = 0;
    while curr > 0 && push_count < 16 {
        // 1-byte push: push reg (0x50 ..= 0x57)
        if (0x50..=0x57).contains(&buf[curr - 1]) {
            push_count += 1;
            curr -= 1;
            continue;
        }
        // 2-byte push: push imm8 (0x6A imm8)
        if curr >= 2 && buf[curr - 2] == 0x6A {
            push_count += 1;
            curr -= 2;
            continue;
        }
        // 5-byte push: push imm32 (0x68 imm32)
        if curr >= 5 && buf[curr - 5] == 0x68 {
            push_count += 1;
            curr -= 5;
            continue;
        }
        // 3-byte push: push [ebp - off8] or [ebp + off8] (0xFF 0x75/0x74 off8)
        if curr >= 3 && buf[curr - 3] == 0xFF && (buf[curr - 2] == 0x75 || buf[curr - 2] == 0x74) {
            push_count += 1;
            curr -= 3;
            continue;
        }
        // 6-byte push: push dword ptr [mem32] (0xFF 0x35 xx xx xx xx)
        if curr >= 6 && buf[curr - 6] == 0xFF && buf[curr - 5] == 0x35 {
            push_count += 1;
            curr -= 6;
            continue;
        }
        break;
    }

    if push_count > 0 {
        Some(push_count)
    } else {
        None
    }
}

/// Heuristically guess a sensible default return value for unknown APIs based on naming conventions.
pub fn guess_default_return(api_name: &str) -> u64 {
    let norm = normalize_api_name(api_name);
    if norm.starts_with("reg") {
        0 // ERROR_SUCCESS
    } else if norm.starts_with("is")
        || norm.starts_with("delete")
        || norm.starts_with("move")
        || norm.starts_with("copy")
        || norm.contains("close")
    {
        1 // TRUE / Success
    } else if norm.starts_with("create") || norm.starts_with("open") {
        0x1000 // Fake HANDLE
    } else if norm.starts_with("gettickcount") || norm.contains("time") {
        100_000
    } else if norm.starts_with("virtualalloc") {
        0x20000000
    } else {
        0
    }
}

/// Writes a simulated WIN32_FIND_DATAA structure to the specified memory buffer (320 bytes).
pub fn write_fake_find_data_a(uc: &mut Unicorn<'_, ()>, addr: u64, filename: &str) -> bool {
    if addr < 0x10000 {
        return false;
    }
    // WIN32_FIND_DATAA: 320 bytes
    // dwFileAttributes: DWORD (offset 0) -> 0x80 (FILE_ATTRIBUTE_NORMAL)
    // ftCreationTime: FILETIME (offset 4)
    // ftLastAccessTime: FILETIME (offset 12)
    // ftLastWriteTime: FILETIME (offset 20)
    // nFileSizeHigh: DWORD (offset 28)
    // nFileSizeLow: DWORD (offset 32) -> 1024
    // dwReserved0: DWORD (offset 36)
    // dwReserved1: DWORD (offset 40)
    // cFileName: CHAR[260] (offset 44)
    let mut data = vec![0u8; 320];
    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[32..36].copy_from_slice(&1024u32.to_le_bytes());

    let bytes = filename.as_bytes();
    let copy_len = bytes.len().min(259);
    data[44..44 + copy_len].copy_from_slice(&bytes[..copy_len]);

    uc.mem_write(addr, &data).is_ok()
}

/// Writes a simulated WIN32_FIND_DATAW structure to the specified memory buffer (592 bytes).
pub fn write_fake_find_data_w(uc: &mut Unicorn<'_, ()>, addr: u64, filename: &str) -> bool {
    if addr < 0x10000 {
        return false;
    }
    // WIN32_FIND_DATAW: 592 bytes
    let mut data = vec![0u8; 592];
    data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
    data[32..36].copy_from_slice(&1024u32.to_le_bytes());

    let utf16: Vec<u8> = filename
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let copy_len = utf16.len().min(518);
    data[44..44 + copy_len].copy_from_slice(&utf16[..copy_len]);

    uc.mem_write(addr, &data).is_ok()
}

/// Executes stub emulation logic for a resolved Windows API.
pub fn handle_api_call(
    uc: &mut Unicorn<'_, ()>,
    api_name: &str,
    args: &[u64],
    api_state: &mut ApiState,
    dllname_to_functionlist: &mut HashMap<String, Vec<(String, u64)>>,
) -> u64 {
    let norm = normalize_api_name(api_name);

    match norm.as_str() {
        // --- File APIs ---
        "createfilea" | "createfilew" => {
            let handle = api_state.next_file_handle;
            api_state.next_file_handle = api_state.next_file_handle.wrapping_add(4);

            let path_arg = args.get(0).copied().unwrap_or(0);
            let path = if norm.ends_with('w') {
                read_wide_string(uc, path_arg, 512)
            } else {
                read_ansi_string(uc, path_arg, 512)
            };

            let desired_access = args.get(1).copied().unwrap_or(0);
            let creation_disposition = args.get(4).copied().unwrap_or(0);
            // GENERIC_WRITE = 0x40000000, FILE_WRITE_DATA = 0x2, CREATE_NEW = 1, CREATE_ALWAYS = 2, TRUNCATE_EXISTING = 5
            let is_write = (desired_access & 0x40000002 != 0)
                || (creation_disposition == 1 || creation_disposition == 2 || creation_disposition == 5);

            if let Some(p) = path {
                api_state.file_handles.insert(handle, (p, is_write));
            }

            handle
        }
        "readfile" => {
            let buf_addr = args.get(1).copied().unwrap_or(0);
            let to_read = args.get(2).copied().unwrap_or(0) as u32;
            let read_ptr = args.get(3).copied().unwrap_or(0);

            if buf_addr != 0 && to_read > 0 {
                let zero_len = (to_read as usize).min(65536);
                let zeros = vec![0u8; zero_len];
                let _ = uc.mem_write(buf_addr, &zeros);
            }
            if read_ptr >= 0x10000 {
                let _ = uc.mem_write(read_ptr, &to_read.to_le_bytes());
            }
            1 // TRUE
        }
        "writefile" => {
            let to_write = args.get(2).copied().unwrap_or(0) as u32;
            let written_ptr = args.get(3).copied().unwrap_or(0);

            if written_ptr >= 0x10000 {
                let _ = uc.mem_write(written_ptr, &to_write.to_le_bytes());
            }
            1 // TRUE
        }
        "findfirstfilea" => {
            let find_handle = api_state.next_file_handle;
            api_state.next_file_handle = api_state.next_file_handle.wrapping_add(4);
            api_state.find_handles.insert(find_handle, 0);

            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            if find_data_ptr >= 0x10000 {
                let _ = write_fake_find_data_a(uc, find_data_ptr, "sample_1.dll");
            }
            find_handle
        }
        "findfirstfilew" => {
            let find_handle = api_state.next_file_handle;
            api_state.next_file_handle = api_state.next_file_handle.wrapping_add(4);
            api_state.find_handles.insert(find_handle, 0);

            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            if find_data_ptr >= 0x10000 {
                let _ = write_fake_find_data_w(uc, find_data_ptr, "sample_1.dll");
            }
            find_handle
        }
        "findnextfilea" => {
            let find_handle = args.get(0).copied().unwrap_or(0);
            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            let count = api_state.find_handles.entry(find_handle).or_insert(0);
            *count += 1;

            if *count == 1 {
                if find_data_ptr >= 0x10000 {
                    let _ = write_fake_find_data_a(uc, find_data_ptr, "sample_2.dat");
                }
                1 // TRUE: second file found
            } else {
                0 // FALSE: ERROR_NO_MORE_FILES (cleanly terminates search loop)
            }
        }
        "findnextfilew" => {
            let find_handle = args.get(0).copied().unwrap_or(0);
            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            let count = api_state.find_handles.entry(find_handle).or_insert(0);
            *count += 1;

            if *count == 1 {
                if find_data_ptr >= 0x10000 {
                    let _ = write_fake_find_data_w(uc, find_data_ptr, "sample_2.dat");
                }
                1 // TRUE: second file found
            } else {
                0 // FALSE: ERROR_NO_MORE_FILES (cleanly terminates search loop)
            }
        }
        "findclose" => {
            let find_handle = args.get(0).copied().unwrap_or(0);
            api_state.find_handles.remove(&find_handle);
            1
        }
        "movefileexw" | "movefileexa" | "movefilew" | "movefilea" | "deletefilew" | "deletefilea"
        | "copyfilew" | "copyfilea" | "copyfileexw" | "copyfileexa" | "closehandle" => 1,
        "getfileattributesw" | "getfileattributesa" => 0x80, // FILE_ATTRIBUTE_NORMAL
        "getfilesize" => 1024,
        "setfilepointer" => 0,

        // --- Time & Anti-Evasion ---
        "gettickcount" | "timegettime" => {
            api_state.simulated_tick_count = api_state.simulated_tick_count.wrapping_add(1000);
            api_state.simulated_tick_count & 0xFFFFFFFF
        }
        "gettickcount64" => {
            api_state.simulated_tick_count = api_state.simulated_tick_count.wrapping_add(1000);
            api_state.simulated_tick_count
        }
        "sleep" | "sleepex" => {
            let ms = args.get(0).copied().unwrap_or(1000).max(1000);
            api_state.simulated_tick_count = api_state.simulated_tick_count.wrapping_add(ms);
            0
        }
        "queryperformancecounter" | "queryperformancefrequency" => 1,

        // --- Dynamic API Resolution ---
        "getprocaddress" => {
            let proc_arg = args.get(1).copied().unwrap_or(0);
            let func_name = if proc_arg <= 0xFFFF {
                format!("ordinal_{}", proc_arg)
            } else {
                read_ansi_string(uc, proc_arg, 128)
                    .unwrap_or_else(|| format!("unknown_proc_{:#x}", proc_arg))
                    .to_ascii_lowercase()
            };

            let allocated_hook = api_state.next_hook_addr;
            api_state.next_hook_addr = api_state.next_hook_addr.wrapping_add(8);

            dllname_to_functionlist
                .entry("dynamic".to_string())
                .or_default()
                .push((func_name, allocated_hook));

            allocated_hook
        }

        // --- Registry ---
        "regopenkeya" | "regopenkeyw" | "regopenkeyexa" | "regopenkeyexw"
        | "regcreatekeya" | "regcreatekeyw" | "regcreatekeyexa" | "regcreatekeyexw"
        | "regqueryvaluea" | "regqueryvaluew" | "regqueryvalueexa" | "regqueryvalueexw"
        | "regsetvaluea" | "regsetvaluew" | "regsetvalueexa" | "regsetvalueexw"
        | "regdeletekeya" | "regdeletekeyw" | "regdeletevaluea" | "regdeletevaluew"
        | "regclosekey" => 0, // ERROR_SUCCESS

        // --- Process & Command Execution ---
        "createprocessa" | "createprocessw" => 1,
        "shellexecutea" | "shellexecutew" => 42, // > 32 indicates success
        "shellexecuteexa" | "shellexecuteexw" => 1,
        "winexec" => 32,
        "openprocess" => 0x1020,
        "terminateprocess" => if args.first().copied().unwrap_or(0) == 0 { 0 } else { 1 },
        "exitprocess" => 0,
        "getcurrentprocess" => 0xFFFFFFFFFFFFFFFFu64,

        // --- Network ---
        "winhttpopen" => 0x3000,
        "winhttpconnect" => 0x3004,
        "winhttpopenrequest" => 0x3008,
        "winhttpsendrequest" | "winhttpreceiveresponse" | "winhttpreaddata" | "winhttpclosehandle" => 1,
        "internetopena" | "internetopenw" => 0x3000,
        "internetconnecta" | "internetconnectw" => 0x3004,
        "httpopenrequesta" | "httpopenrequestw" => 0x3008,
        "httpsendrequesta" | "httpsendrequestw" | "internetclosehandle" => 1,
        "urldownloadtofilea" | "urldownloadtofilew" => 0,
        "wsastartup" => 0,
        "socket" => 0x5000,
        "connect" | "wsaconnect" | "closesocket" => 0,
        "send" => 1,
        "recv" => 0,
        "freeaddrinfo" => 0,
        "getaddrinfo" | "getaddrinfow" => {
            let node_ptr = args.get(0).copied().unwrap_or(0);
            let service_ptr = args.get(1).copied().unwrap_or(0);
            let pp_result = args.get(3).copied().unwrap_or(0);

            let node_name = if norm.ends_with('w') {
                read_wide_string(uc, node_ptr, 512)
            } else {
                read_ansi_string(uc, node_ptr, 512)
            };

            let port = if service_ptr >= 0x10000 {
                let serv_str = if norm.ends_with('w') {
                    read_wide_string(uc, service_ptr, 32)
                } else {
                    read_ansi_string(uc, service_ptr, 32)
                };
                match serv_str.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
                    Some(ref s) if s == "https" => 443,
                    Some(ref s) if s == "http" => 80,
                    Some(ref s) if s == "ftp" => 21,
                    Some(ref s) if s == "ssh" => 22,
                    Some(ref s) if s == "dns" || s == "domain" => 53,
                    Some(ref s) => s.parse::<u16>().unwrap_or(80),
                    None => 80,
                }
            } else {
                80
            };

            let fake_ip = if let Some(ref name) = node_name {
                api_state.resolve_or_assign_fake_ip(name)
            } else {
                [192, 0, 2, 1]
            };

            if pp_result >= 0x10000 {
                let is_64 = api_state.is_64;
                // Allocate sockaddr_in (16 bytes)
                let sockaddr_addr = alloc_net_stub(uc, api_state, 16);
                let ai_size = if is_64 { 48 } else { 32 };
                let ai_addr = alloc_net_stub(uc, api_state, ai_size);
                if sockaddr_addr >= 0x10000 && ai_addr >= 0x10000 {
                    let mut sa_buf = [0u8; 16];
                    sa_buf[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
                    sa_buf[2..4].copy_from_slice(&port.to_be_bytes()); // sin_port (big-endian)
                    sa_buf[4..8].copy_from_slice(&fake_ip);            // sin_addr
                    let _ = uc.mem_write(sockaddr_addr, &sa_buf);

                    let mut ai_buf = vec![0u8; ai_size];
                    ai_buf[4..8].copy_from_slice(&2u32.to_le_bytes()); // ai_family = AF_INET (2)
                    ai_buf[8..12].copy_from_slice(&1u32.to_le_bytes()); // ai_socktype = SOCK_STREAM (1)
                    ai_buf[12..16].copy_from_slice(&6u32.to_le_bytes()); // ai_protocol = IPPROTO_TCP (6)
                    if is_64 {
                        ai_buf[0x10..0x18].copy_from_slice(&16u64.to_le_bytes()); // ai_addrlen = 16
                        ai_buf[0x20..0x28].copy_from_slice(&sockaddr_addr.to_le_bytes()); // ai_addr
                        let _ = uc.mem_write(ai_addr, &ai_buf);
                        let _ = uc.mem_write(pp_result, &ai_addr.to_le_bytes());
                    } else {
                        ai_buf[0x10..0x14].copy_from_slice(&16u32.to_le_bytes()); // ai_addrlen = 16
                        ai_buf[0x18..0x1C].copy_from_slice(&(sockaddr_addr as u32).to_le_bytes()); // ai_addr
                        let _ = uc.mem_write(ai_addr, &ai_buf);
                        let _ = uc.mem_write(pp_result, &(ai_addr as u32).to_le_bytes());
                    }
                }
            }
            0 // STATUS_SUCCESS
        }
        "gethostbyname" => {
            let name_ptr = args.get(0).copied().unwrap_or(0);
            let name = read_ansi_string(uc, name_ptr, 512);
            let fake_ip = if let Some(ref n) = name {
                api_state.resolve_or_assign_fake_ip(n)
            } else {
                [192, 0, 2, 1]
            };

            let is_64 = api_state.is_64;
            // 1. IP buffer (4 bytes)
            let ip_addr = alloc_net_stub(uc, api_state, 16);
            let ptr_size = if is_64 { 8 } else { 4 };
            let addr_list_addr = alloc_net_stub(uc, api_state, ptr_size * 2);
            let host_str_addr = alloc_net_stub(uc, api_state, 16);
            let hostent_size = if is_64 { 32 } else { 16 };
            let hostent_addr = alloc_net_stub(uc, api_state, hostent_size);

            if ip_addr < 0x10000 || addr_list_addr < 0x10000 || host_str_addr < 0x10000 || hostent_addr < 0x10000 {
                return 0;
            }

            let _ = uc.mem_write(ip_addr, &fake_ip);
            if is_64 {
                let mut list_buf = [0u8; 16];
                list_buf[0..8].copy_from_slice(&ip_addr.to_le_bytes());
                let _ = uc.mem_write(addr_list_addr, &list_buf);
            } else {
                let mut list_buf = [0u8; 8];
                list_buf[0..4].copy_from_slice(&(ip_addr as u32).to_le_bytes());
                let _ = uc.mem_write(addr_list_addr, &list_buf);
            }

            let _ = uc.mem_write(host_str_addr, b"fakehost\0");

            let mut he_buf = vec![0u8; hostent_size];
            if is_64 {
                he_buf[0..8].copy_from_slice(&host_str_addr.to_le_bytes());
                he_buf[0x10..0x12].copy_from_slice(&2u16.to_le_bytes());
                he_buf[0x12..0x14].copy_from_slice(&4u16.to_le_bytes());
                he_buf[0x18..0x20].copy_from_slice(&addr_list_addr.to_le_bytes());
            } else {
                he_buf[0..4].copy_from_slice(&(host_str_addr as u32).to_le_bytes());
                he_buf[0x08..0x0A].copy_from_slice(&2u16.to_le_bytes());
                he_buf[0x0A..0x0C].copy_from_slice(&4u16.to_le_bytes());
                he_buf[0x0C..0x10].copy_from_slice(&(addr_list_addr as u32).to_le_bytes());
            }
            let _ = uc.mem_write(hostent_addr, &he_buf);
            hostent_addr
        }

        // --- Crypto ---
        "cryptacquirecontexta" | "cryptacquirecontextw" => 1,
        "cryptgenrandom" | "cryptcreatehash" | "crypthashdata" | "cryptderivekey" => 1,
        "cryptencrypt" | "cryptdecrypt" | "cryptdestroyhash" | "cryptdestroykey" | "cryptreleasecontext" => 1,
        "bcryptopenalgorithmprovider" | "bcryptclosealgorithmprovider"
        | "bcryptgenrandom" | "bcryptencrypt" | "bcryptdecrypt" => 0, // STATUS_SUCCESS

        // --- Module & Memory ---
        "loadlibrarya" | "loadlibraryw" | "loadlibraryexa" | "loadlibraryexw" => {
            let lib_name_arg = args.get(0).copied().unwrap_or(0);
            let name = if norm.ends_with('w') {
                read_wide_string(uc, lib_name_arg, 512)
            } else {
                read_ansi_string(uc, lib_name_arg, 512)
            };
            if let Some(ref n) = name {
                if let Some(base) = find_dll_base(&api_state.dll_bases, n) {
                    return base;
                }
            }
            // If the DLL is not preloaded in dll_bases, map a valid dummy PE header at 0x50000000
            // so that manual PE header checks (e.g. `cmp word ptr [eax], 'MZ'`) succeed without faults.
            let fallback_base = 0x50000000u64;
            let mut test_byte = [0u8; 1];
            if uc.mem_read(fallback_base, &mut test_byte).is_err() {
                if uc.mem_map(fallback_base, 0x1000, Prot::ALL).is_ok() {
                    let mut pe_hdr = vec![0u8; 0x1000];
                    pe_hdr[0..2].copy_from_slice(b"MZ");
                    pe_hdr[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
                    pe_hdr[0x80..0x84].copy_from_slice(b"PE\0\0"); // PE signature
                    let _ = uc.mem_write(fallback_base, &pe_hdr);
                }
            }
            fallback_base
        }
        "freelibrary" => 1,
        "getmodulehandlea" | "getmodulehandlew" => {
            let mod_name_arg = args.get(0).copied().unwrap_or(0);
            if mod_name_arg == 0 {
                api_state.image_base
            } else {
                let name = if norm.ends_with('w') {
                    read_wide_string(uc, mod_name_arg, 512)
                } else {
                    read_ansi_string(uc, mod_name_arg, 512)
                };
                if let Some(ref n) = name {
                    if let Some(base) = find_dll_base(&api_state.dll_bases, n) {
                        base
                    } else {
                        // In Win32, GetModuleHandle returns NULL (0) if the module is not found
                        0
                    }
                } else {
                    api_state.image_base
                }
            }
        }
        "getmodulehandleexa" | "getmodulehandleexw" => 1,
        "getmodulefilenamea" | "getmodulefilenamew" => 12,
        "virtualalloc" => {
            let req_addr = args.get(0).copied().unwrap_or(0);
            let raw_size = args.get(1).copied().unwrap_or(0x1000);
            // Cap allocation size to 64MB and avoid overflow across FFI boundary
            let size = raw_size.min(64 * 1024 * 1024).max(0x1000);
            let page_aligned = size.saturating_add(0xFFF) & !0xFFF;

            if req_addr >= 0x10000 {
                let target = req_addr & !0xFFF;
                for offset in (0..page_aligned).step_by(0x1000) {
                    let page_addr = target.saturating_add(offset);
                    let mut test = [0u8; 1];
                    if uc.mem_read(page_addr, &mut test).is_err() {
                        if uc.mem_map(page_addr, 0x1000, Prot::ALL).is_err() {
                            return 0;
                        }
                    } else {
                        let _ = uc.mem_protect(page_addr, 0x1000, Prot::ALL);
                    }
                }
                target
            } else {
                let addr = api_state.next_alloc_addr;
                // Guard against upper bound collision with HOOK_ADDR (0x7F000000) or DLL regions
                if addr.saturating_add(page_aligned) >= 0x70000000 {
                    return 0; // Out of memory
                }
                if uc.mem_map(addr, page_aligned, Prot::ALL).is_err() {
                    return 0;
                }
                api_state.next_alloc_addr = addr.saturating_add(page_aligned).saturating_add(0x10000);
                addr
            }
        }
        "virtualallocex" => {
            let req_addr = args.get(1).copied().unwrap_or(0);
            let raw_size = args.get(2).copied().unwrap_or(0x1000);
            let size = raw_size.min(64 * 1024 * 1024).max(0x1000);
            let page_aligned = size.saturating_add(0xFFF) & !0xFFF;

            if req_addr >= 0x10000 {
                let target = req_addr & !0xFFF;
                for offset in (0..page_aligned).step_by(0x1000) {
                    let page_addr = target.saturating_add(offset);
                    let mut test = [0u8; 1];
                    if uc.mem_read(page_addr, &mut test).is_err() {
                        if uc.mem_map(page_addr, 0x1000, Prot::ALL).is_err() {
                            return 0;
                        }
                    } else {
                        let _ = uc.mem_protect(page_addr, 0x1000, Prot::ALL);
                    }
                }
                target
            } else {
                let addr = api_state.next_alloc_addr;
                if addr.saturating_add(page_aligned) >= 0x70000000 {
                    return 0;
                }
                if uc.mem_map(addr, page_aligned, Prot::ALL).is_err() {
                    return 0;
                }
                api_state.next_alloc_addr = addr.saturating_add(page_aligned).saturating_add(0x10000);
                addr
            }
        }
        "virtualfree" => 1,
        "virtualprotect" => {
            let old_protect_ptr = args.get(3).copied().unwrap_or(0);
            if old_protect_ptr >= 0x10000 {
                let _ = uc.mem_write(old_protect_ptr, &0x40u32.to_le_bytes()); // PAGE_EXECUTE_READWRITE
            }
            1
        }
        "isdebuggerpresent" => 0,
        "checkremotedebuggerpresent" => {
            let pb_debugger_present = args.get(1).copied().unwrap_or(0);
            if pb_debugger_present >= 0x10000 {
                let _ = uc.mem_write(pb_debugger_present, &0u32.to_le_bytes()); // FALSE
            }
            1
        }
        "getlasterror" | "setlasterror" => 0,

        // --- Fallback ---
        _ => {
            if let Some(spec) = get_api_spec(api_name) {
                spec.default_ret
            } else {
                guess_default_return(api_name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicorn_engine::{Arch, Mode, Prot, Unicorn};

    #[test]
    fn test_normalize_api_name() {
        assert_eq!(normalize_api_name("KERNEL32.DLL!CreateFileW"), "createfilew");
        assert_eq!(normalize_api_name("kernel32.createfilea"), "createfilea");
        assert_eq!(normalize_api_name("__imp_Sleep@4"), "sleep");
        assert_eq!(normalize_api_name("_exit"), "exit");
    }

    #[test]
    fn test_api_stub_table_lookup() {
        let spec_cfw = get_api_spec("CreateFileW").expect("CreateFileW in table");
        assert_eq!(spec_cfw.arg_count, 7);
        assert_eq!(spec_cfw.default_ret, 0x1000);
        assert_eq!(spec_cfw.string_args, &[(0, StringType::Wide)]);

        let spec_rf = get_api_spec("ReadFile").expect("ReadFile in table");
        assert_eq!(spec_rf.arg_count, 5);
        assert_eq!(spec_rf.default_ret, 1);
        assert!(spec_rf.string_args.is_empty());

        // Process
        assert_eq!(get_api_spec("CreateProcessW").unwrap().arg_count, 10);
        assert_eq!(get_api_spec("WinExec").unwrap().arg_count, 2);

        // Crypto
        assert_eq!(get_api_spec("CryptEncrypt").unwrap().arg_count, 7);
        assert_eq!(get_api_spec("BCryptEncrypt").unwrap().arg_count, 10);
    }

    #[test]
    fn test_handle_api_call_state_and_dynamic_resolution() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mem_addr = 0x10000u64;
        uc.mem_map(mem_addr, 0x2000, Prot::ALL).expect("mem_map");

        let mut state = ApiState::default();
        let mut dll_map = HashMap::new();

        // 1. CreateFileW
        let h1 = handle_api_call(&mut uc, "CreateFileW", &[0, 0, 0, 0, 0, 0, 0], &mut state, &mut dll_map);
        assert_eq!(h1, 0x1000);

        // 2. ReadFile
        let buf_addr = mem_addr;
        let bytes_read_ptr = mem_addr + 0x100;
        let to_read = 64u64;
        let ret_rf = handle_api_call(
            &mut uc,
            "ReadFile",
            &[h1, buf_addr, to_read, bytes_read_ptr, 0],
            &mut state,
            &mut dll_map,
        );
        assert_eq!(ret_rf, 1);
        let mut read_bytes_out = [0u8; 4];
        uc.mem_read(bytes_read_ptr, &mut read_bytes_out).expect("mem_read");
        assert_eq!(u32::from_le_bytes(read_bytes_out), 64);

        // 3. FindFirstFileW / FindNextFileW
        let find_data_ptr = mem_addr + 0x200;
        let find_h = handle_api_call(&mut uc, "FindFirstFileW", &[0, find_data_ptr], &mut state, &mut dll_map);
        assert_eq!(find_h, 0x1004);

        let next1 = handle_api_call(&mut uc, "FindNextFileW", &[find_h, find_data_ptr], &mut state, &mut dll_map);
        assert_eq!(next1, 1);
        let next2 = handle_api_call(&mut uc, "FindNextFileW", &[find_h, find_data_ptr], &mut state, &mut dll_map);
        assert_eq!(next2, 0);

        // 4. Dynamic GetProcAddress
        let proc_name_addr = mem_addr + 0x300;
        uc.mem_write(proc_name_addr, b"VirtualProtect\0").expect("mem_write proc name");
        let dyn_hook = handle_api_call(&mut uc, "GetProcAddress", &[0x400000, proc_name_addr], &mut state, &mut dll_map);
        assert_eq!(dyn_hook, 0x7F080000);

        // Verify registered in dll_map
        let resolved = resolve_api_name(&HashMap::new(), dyn_hook, &dll_map);
        assert_eq!(resolved.as_deref(), Some("virtualprotect"));

        // 5. Time progression
        let t1 = handle_api_call(&mut uc, "GetTickCount", &[], &mut state, &mut dll_map);
        let t2 = handle_api_call(&mut uc, "GetTickCount", &[], &mut state, &mut dll_map);
        assert_eq!(t2, t1 + 1000);

        // 6. Unknown API defaults to guess_default_return
        assert_eq!(handle_api_call(&mut uc, "NonExistentApi123", &[], &mut state, &mut dll_map), 0);
        assert_eq!(handle_api_call(&mut uc, "RegCustomSecretKey", &[], &mut state, &mut dll_map), 0);
    }

    #[test]
    fn test_string_reading_and_probing() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mem_addr = 0x20000u64;
        uc.mem_map(mem_addr, 0x1000, Prot::ALL).expect("mem_map");

        // ANSI string
        let ansi_str = b"C:\\test\\sample.exe\0";
        uc.mem_write(mem_addr, ansi_str).expect("mem_write ansi");
        let read_ansi = read_ansi_string(&uc, mem_addr, 512);
        assert_eq!(read_ansi.as_deref(), Some("C:\\test\\sample.exe"));

        // Wide string
        let wide_str: Vec<u8> = "C:\\test\\file.txt\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        uc.mem_write(mem_addr + 0x100, &wide_str).expect("mem_write wide");
        let read_wide = read_wide_string(&uc, mem_addr + 0x100, 512);
        assert_eq!(read_wide.as_deref(), Some("C:\\test\\file.txt"));

        // Probe string
        let probed_ansi = probe_string_arg(&uc, mem_addr, false);
        assert_eq!(probed_ansi.as_deref(), Some("C:\\test\\sample.exe"));

        let probed_wide = probe_string_arg(&uc, mem_addr + 0x100, true);
        assert_eq!(probed_wide.as_deref(), Some("C:\\test\\file.txt"));

        // Invalid / non-string probe
        assert!(probe_string_arg(&uc, 0, false).is_none());
        assert!(probe_string_arg(&uc, 0x50, false).is_none());
    }

    #[test]
    fn test_estimate_x86_stdcall_arg_count() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let code_addr = 0x30000u64;
        uc.mem_map(code_addr, 0x1000, Prot::ALL).expect("mem_map");

        // Simulate x86 code:
        // push ebx (1 byte, 0x53)
        // push 0 (2 bytes, 0x6A 0x00)
        // push eax (1 byte, 0x50)
        // call dword ptr [0x401000] (6 bytes, 0xFF 0x15 0x00 0x10 0x40 0x00)
        // ret_addr here: code_addr + offset + code.len()
        let code = [
            0x53,
            0x6A, 0x00,
            0x50,
            0xFF, 0x15, 0x00, 0x10, 0x40, 0x00,
        ];
        let offset = 0x100u64;
        uc.mem_write(code_addr + offset, &code).expect("mem_write code");
        let ret_addr = code_addr + offset + code.len() as u64;

        let estimated = estimate_x86_stdcall_arg_count(&uc, ret_addr);
        assert_eq!(estimated, Some(3));
    }

    #[test]
    fn test_virtualalloc_mapping_and_out_pointers() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mut state = ApiState::default();
        let mut dll_map = HashMap::new();

        // VirtualAlloc with NULL req_addr
        let alloc_addr = handle_api_call(&mut uc, "VirtualAlloc", &[0, 0x1000, 0x1000, 0x40], &mut state, &mut dll_map);
        assert!(alloc_addr >= 0x10000);
        // Verify mapped by writing and reading
        let test_payload = b"MZ\x90\x00PACKED_SHELLCODE";
        assert!(uc.mem_write(alloc_addr, test_payload).is_ok());
        let mut read_back = vec![0u8; test_payload.len()];
        assert!(uc.mem_read(alloc_addr, &mut read_back).is_ok());
        assert_eq!(read_back, test_payload);

        // VirtualProtect old_protect out pointer
        let old_protect_ptr = alloc_addr + 0x100;
        let ret_vp = handle_api_call(&mut uc, "VirtualProtect", &[alloc_addr, 0x1000, 0x20, old_protect_ptr], &mut state, &mut dll_map);
        assert_eq!(ret_vp, 1);
        let mut old_prot_buf = [0u8; 4];
        assert!(uc.mem_read(old_protect_ptr, &mut old_prot_buf).is_ok());
        assert_eq!(u32::from_le_bytes(old_prot_buf), 0x40);

        // CheckRemoteDebuggerPresent out pointer
        let dbg_ptr = alloc_addr + 0x200;
        // Pre-fill with 1 (TRUE) to ensure it gets cleared to 0 (FALSE)
        uc.mem_write(dbg_ptr, &1u32.to_le_bytes()).unwrap();
        let ret_dbg = handle_api_call(&mut uc, "CheckRemoteDebuggerPresent", &[0xFFFFFFFF, dbg_ptr], &mut state, &mut dll_map);
        assert_eq!(ret_dbg, 1);
        let mut dbg_buf = [0u8; 4];
        assert!(uc.mem_read(dbg_ptr, &mut dbg_buf).is_ok());
        assert_eq!(u32::from_le_bytes(dbg_buf), 0);
    }

    #[test]
    fn test_cdecl_detection_and_find_data_structures() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mem = 0x40000u64;
        uc.mem_map(mem, 0x1000, Prot::ALL).expect("mem_map");

        // Cdecl check
        assert!(is_cdecl_api("wsprintfA", None));
        assert!(is_cdecl_api("wsprintfW", None));
        assert!(is_cdecl_api("sprintf", None));
        assert!(is_cdecl_api("_snprintf", None));
        assert!(is_cdecl_api("strlen", Some("msvcrt.dll")));
        assert!(is_cdecl_api("malloc", Some("ucrtbase.dll")));
        assert!(is_cdecl_api("memcpy", Some("api-ms-win-crt-string-l1-1-0.dll")));
        assert!(!is_cdecl_api("CreateFileW", Some("kernel32.dll")));
        assert!(!is_cdecl_api("VirtualAlloc", Some("kernel32.dll")));

        // FindDataA (320 bytes)
        assert!(write_fake_find_data_a(&mut uc, mem, "payload.exe"));
        let mut buf_a = [0u8; 320];
        assert!(uc.mem_read(mem, &mut buf_a).is_ok());
        assert_eq!(u32::from_le_bytes([buf_a[0], buf_a[1], buf_a[2], buf_a[3]]), 0x80);
        let filename_a = String::from_utf8_lossy(&buf_a[44..44 + 11]);
        assert_eq!(filename_a, "payload.exe");

        // FindDataW (592 bytes)
        let mem_w = mem + 0x400;
        assert!(write_fake_find_data_w(&mut uc, mem_w, "payload.exe"));
        let mut buf_w = [0u8; 592];
        assert!(uc.mem_read(mem_w, &mut buf_w).is_ok());
        assert_eq!(u32::from_le_bytes([buf_w[0], buf_w[1], buf_w[2], buf_w[3]]), 0x80);
    }

    #[test]
    fn test_module_handles_and_alloc_safety() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mut state = ApiState::default();
        let mut dll_map = HashMap::new();
        state.dll_bases.insert("kernel32.dll".to_string(), 0x7B000000);
        state.dll_bases.insert("ntdll.dll".to_string(), 0x7C000000);

        // find_dll_base matching
        assert_eq!(find_dll_base(&state.dll_bases, "kernel32.dll"), Some(0x7B000000));
        assert_eq!(find_dll_base(&state.dll_bases, "KERNEL32"), Some(0x7B000000));
        assert_eq!(find_dll_base(&state.dll_bases, "C:\\Windows\\System32\\ntdll.dll"), Some(0x7C000000));
        assert_eq!(find_dll_base(&state.dll_bases, "unknown.dll"), None);

        // GetModuleHandle(NULL) returns image_base
        let h_null = handle_api_call(&mut uc, "GetModuleHandleA", &[0], &mut state, &mut dll_map);
        assert_eq!(h_null, state.image_base);

        // VirtualAlloc with huge/overflowing size is capped and doesn't panic
        let huge_alloc = handle_api_call(&mut uc, "VirtualAlloc", &[0, u64::MAX, 0x1000, 0x40], &mut state, &mut dll_map);
        assert!(huge_alloc >= 0x10000);

        // LoadLibrary for unknown DLL maps dummy PE header with MZ signature at 0x50000000
        let h_dyn = handle_api_call(&mut uc, "LoadLibraryA", &[0], &mut state, &mut dll_map);
        assert_eq!(h_dyn, 0x50000000);
        let mut mz_buf = [0u8; 2];
        assert!(uc.mem_read(0x50000000, &mut mz_buf).is_ok());
        assert_eq!(&mz_buf, b"MZ");
    }

    #[test]
    fn test_network_stubs_dns_and_sockaddr() {
        let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Unicorn new");
        let mut state = ApiState::default();
        let mut dll_map = HashMap::new();

        // 1. DNS Cache and RFC 5737 TEST-NET assignment
        let ip1 = state.resolve_or_assign_fake_ip("c2.evil.com");
        assert_eq!(ip1, [192, 0, 2, 1]);
        let ip2 = state.resolve_or_assign_fake_ip("download.evil.com");
        assert_eq!(ip2, [192, 0, 2, 2]);
        // Same domain returns same IP
        assert_eq!(state.resolve_or_assign_fake_ip("C2.EVIL.COM"), [192, 0, 2, 1]);

        // Multi-subnet rollover resistance across TEST-NET blocks:
        // Advance to TEST-NET-2 (index 254)
        state.next_fake_ip_index = 254;
        let ip_net2 = state.resolve_or_assign_fake_ip("net2.evil.com");
        assert_eq!(ip_net2, [198, 51, 100, 1]);
        // Advance to TEST-NET-3 (index 508)
        state.next_fake_ip_index = 508;
        let ip_net3 = state.resolve_or_assign_fake_ip("net3.evil.com");
        assert_eq!(ip_net3, [203, 0, 113, 1]);
        // Advance to extended private range (index 762)
        state.next_fake_ip_index = 762;
        let ip_priv = state.resolve_or_assign_fake_ip("priv.evil.com");
        assert_eq!(ip_priv, [10, 200, 0, 1]);
        // Verify original ip1 mapping was NOT overwritten
        assert_eq!(state.ip_to_host.get(&ip1).map(|s| s.as_str()), Some("c2.evil.com"));

        // 2. sockaddr_in parsing and endpoint formatting
        let sa_addr = 0x35000u64;
        uc.mem_map(sa_addr, 0x1000, Prot::ALL).expect("mem_map");
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&2u16.to_le_bytes()); // AF_INET
        sa[2..4].copy_from_slice(&443u16.to_be_bytes()); // port 443
        sa[4..8].copy_from_slice(&ip1); // 192.0.2.1
        uc.mem_write(sa_addr, &sa).expect("mem_write");

        let parsed = parse_sockaddr(&uc, sa_addr, 16);
        assert_eq!(parsed, Some(([192, 0, 2, 1], 443)));
        let ep = format_endpoint(&state, [192, 0, 2, 1], 443);
        assert_eq!(ep, "c2.evil.com:443");

        // Unknown IP formats numerically
        let ep_raw = format_endpoint(&state, [10, 0, 0, 1], 80);
        assert_eq!(ep_raw, "10.0.0.1:80");

        // 3. getaddrinfo with "https" service string resolves to port 443
        let pp_result = 0x36000u64;
        uc.mem_map(pp_result, 0x1000, Prot::ALL).expect("mem_map");
        let node_name_addr = 0x37000u64;
        uc.mem_map(node_name_addr, 0x1000, Prot::ALL).expect("mem_map");
        uc.mem_write(node_name_addr, b"api.victim.com\0").expect("mem_write");
        let svc_name_addr = 0x38000u64;
        uc.mem_map(svc_name_addr, 0x1000, Prot::ALL).expect("mem_map");
        uc.mem_write(svc_name_addr, b"https\0").expect("mem_write");

        let res_ai = handle_api_call(
            &mut uc,
            "getaddrinfo",
            &[node_name_addr, svc_name_addr, 0, pp_result],
            &mut state,
            &mut dll_map,
        );
        assert_eq!(res_ai, 0); // STATUS_SUCCESS

        let mut res_ai_ptr_buf = [0u8; 4];
        assert!(uc.mem_read(pp_result, &mut res_ai_ptr_buf).is_ok());
        let ai_addr = u32::from_le_bytes(res_ai_ptr_buf) as u64;
        // Verify allocated in 0x78000000 region
        assert!(ai_addr >= 0x78000000 && ai_addr < 0x7F000000);

        // Read ai_addr field inside addrinfo (offset 0x18 in 32-bit)
        let mut sa_ptr_buf = [0u8; 4];
        assert!(uc.mem_read(ai_addr + 0x18, &mut sa_ptr_buf).is_ok());
        let sa_ptr = u32::from_le_bytes(sa_ptr_buf) as u64;
        assert!(sa_ptr >= 0x78000000 && sa_ptr < 0x7F000000);

        // Verify sockaddr_in family = 2 and port is 443 (big-endian)
        let mut resolved_sa = [0u8; 8];
        assert!(uc.mem_read(sa_ptr, &mut resolved_sa).is_ok());
        assert_eq!(u16::from_le_bytes([resolved_sa[0], resolved_sa[1]]), 2);
        assert_eq!(u16::from_be_bytes([resolved_sa[2], resolved_sa[3]]), 443);

        // 4. gethostbyname returns non-null hostent pointer in 0x78000000 region
        let he_addr = handle_api_call(
            &mut uc,
            "gethostbyname",
            &[node_name_addr],
            &mut state,
            &mut dll_map,
        );
        assert!(he_addr >= 0x78000000 && he_addr < 0x7F000000);
        // Read h_addr_list pointer at offset 0x0C in 32-bit
        let mut addr_list_ptr_buf = [0u8; 4];
        assert!(uc.mem_read(he_addr + 0x0C, &mut addr_list_ptr_buf).is_ok());
        let addr_list_ptr = u32::from_le_bytes(addr_list_ptr_buf) as u64;
        // Read in_addr pointer at addr_list[0]
        let mut in_addr_ptr_buf = [0u8; 4];
        assert!(uc.mem_read(addr_list_ptr, &mut in_addr_ptr_buf).is_ok());
        let in_addr_ptr = u32::from_le_bytes(in_addr_ptr_buf) as u64;
        let mut ip_bytes = [0u8; 4];
        assert!(uc.mem_read(in_addr_ptr, &mut ip_bytes).is_ok());
        assert_eq!(ip_bytes, state.resolve_or_assign_fake_ip("api.victim.com"));

        // 5. TerminateProcess(0) returns 0 (failure)
        let term_res = handle_api_call(
            &mut uc,
            "TerminateProcess",
            &[0, 1],
            &mut state,
            &mut dll_map,
        );
        assert_eq!(term_res, 0);
    }
}

