use std::collections::HashMap;
use unicorn_engine::Unicorn;

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
    "regsetvaluea"(5, [ (1, Ansi), (4, Ansi) ]) -> 0;
    "regsetvaluew"(5, [ (1, Wide), (4, Wide) ]) -> 0;
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
    "getcurrentprocess"(0) -> 0xFFFFFFFF;
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
    "send"(4) -> 1;
    "recv"(4) -> 0;
    "closesocket"(1) -> 0;
    "getaddrinfo"(4, [ (0, Ansi) ]) -> 0;
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
    "loadlibrarya"(1, [ (0, Ansi) ]) -> 0x7F000000;
    "loadlibraryw"(1, [ (0, Wide) ]) -> 0x7F000000;
    "loadlibraryexa"(3, [ (0, Ansi) ]) -> 0x7F000000;
    "loadlibraryexw"(3, [ (0, Wide) ]) -> 0x7F000000;
    "freelibrary"(1) -> 1;
    "getprocaddress"(2, [ (1, Ansi) ]) -> 0x7F080000;
    "getmodulehandlea"(1, [ (0, Ansi) ]) -> 0x400000;
    "getmodulehandlew"(1, [ (0, Wide) ]) -> 0x400000;
    "getmodulehandleexa"(3, [ (1, Ansi) ]) -> 1;
    "getmodulehandleexw"(3, [ (1, Wide) ]) -> 1;
    "getmodulefilenamea"(3) -> 12;
    "getmodulefilenamew"(3) -> 12;
    "virtualalloc"(4) -> 0x300000;
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

/// State kept across emulated API calls (handle generation, search iterations, simulated ticks, dynamic hooks).
#[derive(Debug, Clone)]
pub struct ApiState {
    pub next_file_handle: u64,
    pub next_hook_addr: u64,
    pub find_handles: HashMap<u64, u32>,
    pub simulated_tick_count: u64,
}

impl Default for ApiState {
    fn default() -> Self {
        Self {
            next_file_handle: 0x1000,
            next_hook_addr: 0x7F080000,
            find_handles: HashMap::new(),
            simulated_tick_count: 100_000,
        }
    }
}

/// Maps hooked API addresses to resolved function names.
pub fn resolve_api_name(
    _apicall_counter: &HashMap<String, u64>,
    addr: u64,
    dllname_to_functionlist: &HashMap<String, Vec<(String, u64)>>,
) -> Option<String> {
    for (_dll, functions) in dllname_to_functionlist {
        for (name, hook_addr) in functions {
            if *hook_addr == addr {
                return Some(name.clone());
            }
        }
    }
    None
}

/// Reads a null-terminated ANSI C-string from Unicorn memory (up to 512 bytes).
pub fn read_ansi_string(uc: &Unicorn<'_, ()>, addr: u64, max_len: usize) -> Option<String> {
    if addr == 0 {
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
    if addr == 0 {
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
    } else {
        0
    }
}

/// Writes a simulated WIN32_FIND_DATAW structure to the specified memory buffer.
fn write_fake_find_data_w(uc: &mut Unicorn<'_, ()>, addr: u64, filename: &str) -> bool {
    if addr == 0 {
        return false;
    }
    // WIN32_FIND_DATAW:
    // dwFileAttributes: DWORD (offset 0) -> 0x80 (FILE_ATTRIBUTE_NORMAL)
    // ftCreationTime: FILETIME (offset 4)
    // ftLastAccessTime: FILETIME (offset 12)
    // ftLastWriteTime: FILETIME (offset 20)
    // nFileSizeHigh: DWORD (offset 28)
    // nFileSizeLow: DWORD (offset 32) -> 1024
    // dwReserved0: DWORD (offset 36)
    // dwReserved1: DWORD (offset 40)
    // cFileName: WCHAR[260] (offset 44)
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
            if read_ptr != 0 {
                let _ = uc.mem_write(read_ptr, &to_read.to_le_bytes());
            }
            1 // TRUE
        }
        "writefile" => {
            let to_write = args.get(2).copied().unwrap_or(0) as u32;
            let written_ptr = args.get(3).copied().unwrap_or(0);

            if written_ptr != 0 {
                let _ = uc.mem_write(written_ptr, &to_write.to_le_bytes());
            }
            1 // TRUE
        }
        "findfirstfilew" | "findfirstfilea" => {
            let find_handle = api_state.next_file_handle;
            api_state.next_file_handle = api_state.next_file_handle.wrapping_add(4);
            api_state.find_handles.insert(find_handle, 0);

            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            if find_data_ptr != 0 {
                let _ = write_fake_find_data_w(uc, find_data_ptr, "sample_1.dll");
            }
            find_handle
        }
        "findnextfilew" | "findnextfilea" => {
            let find_handle = args.get(0).copied().unwrap_or(0);
            let find_data_ptr = args.get(1).copied().unwrap_or(0);
            let count = api_state.find_handles.entry(find_handle).or_insert(0);
            *count += 1;

            if *count == 1 {
                if find_data_ptr != 0 {
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
        "terminateprocess" => 1,

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
        "connect" | "closesocket" => 0,
        "send" => 1,
        "recv" => 0,

        // --- Crypto ---
        "cryptacquirecontexta" | "cryptacquirecontextw" => 1,
        "cryptgenrandom" | "cryptcreatehash" | "crypthashdata" | "cryptderivekey" => 1,
        "cryptencrypt" | "cryptdecrypt" | "cryptdestroyhash" | "cryptdestroykey" | "cryptreleasecontext" => 1,
        "bcryptopenalgorithmprovider" | "bcryptclosealgorithmprovider"
        | "bcryptgenrandom" | "bcryptencrypt" | "bcryptdecrypt" => 0, // STATUS_SUCCESS

        // --- Module & Memory ---
        "loadlibrarya" | "loadlibraryw" | "loadlibraryexa" | "loadlibraryexw" => 0x7F000000,
        "freelibrary" => 1,
        "getmodulehandlea" | "getmodulehandlew" => 0x400000,
        "getmodulehandleexa" | "getmodulehandleexw" => 1,
        "getmodulefilenamea" | "getmodulefilenamew" => 12,
        "virtualalloc" => 0x300000,
        "virtualfree" | "virtualprotect" => 1,
        "isdebuggerpresent" => 0,
        "checkremotedebuggerpresent" => 1,
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
}
