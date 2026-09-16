use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;

#[link(name = "openedr_static")]
extern "C" {
    fn openedr_static_init(base_rules_dir: *const c_char) -> i32;
    fn openedr_static_scan_file(file_path: *const c_char) -> *mut c_char;
    fn openedr_static_scan_bytes(data: *const u8, len: usize, file_name: *const c_char) -> *mut c_char;
    fn openedr_static_scan_url(url: *const c_char) -> *mut c_char;
    fn openedr_static_check_registry(reg_path: *const c_char) -> *mut c_char;
    fn openedr_static_free_string(s: *mut c_char);
}

pub struct OpenEdrScanner;

impl OpenEdrScanner {
    pub fn init(rules_dir: Option<&Path>) -> Result<Self, String> {
        let res = match rules_dir {
            Some(p) => {
                let s = p.to_str().ok_or("Invalid path string")?;
                let c_str = CString::new(s).map_err(|e| e.to_string())?;
                unsafe { openedr_static_init(c_str.as_ptr()) }
            }
            None => unsafe { openedr_static_init(std::ptr::null()) },
        };

        if res == 0 {
            Ok(Self)
        } else {
            Err(format!("Init failed with code: {}", res))
        }
    }

    fn c_str_to_string_and_free(ptr: *mut c_char) -> String {
        if ptr.is_null() {
            return String::new();
        }
        unsafe {
            let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
            openedr_static_free_string(ptr);
            s
        }
    }

    pub fn scan_file(&self, path: &Path) -> Result<String, String> {
        let s = path.to_str().ok_or("Invalid file path")?;
        let c_str = CString::new(s).map_err(|e| e.to_string())?;
        let ptr = unsafe { openedr_static_scan_file(c_str.as_ptr()) };
        Ok(Self::c_str_to_string_and_free(ptr))
    }

    pub fn scan_bytes(&self, data: &[u8], virtual_name: Option<&str>) -> String {
        let c_name = virtual_name.and_then(|n| CString::new(n).ok());
        let name_ptr = c_name.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        let ptr = unsafe { openedr_static_scan_bytes(data.as_ptr(), data.len(), name_ptr) };
        Self::c_str_to_string_and_free(ptr)
    }

    pub fn scan_url(&self, url: &str) -> Result<String, String> {
        let c_str = CString::new(url).map_err(|e| e.to_string())?;
        let ptr = unsafe { openedr_static_scan_url(c_str.as_ptr()) };
        Ok(Self::c_str_to_string_and_free(ptr))
    }

    pub fn check_registry(&self, reg_path: &str) -> Result<String, String> {
        let c_str = CString::new(reg_path).map_err(|e| e.to_string())?;
        let ptr = unsafe { openedr_static_check_registry(c_str.as_ptr()) };
        Ok(Self::c_str_to_string_and_free(ptr))
    }
}

fn main() {
    println!("[*] Initializing OpenEDR Scanner in Rust...");
    let scanner = match OpenEdrScanner::init(Some(Path::new("OpenMalwareScannerPortable"))) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[-] Error: {}", e);
            return;
        }
    };
    println!("[+] Initialized successfully!\n");

    // File scan
    let target = Path::new("OpenMalwareScannerPortable/openedr_static.dll");
    println!("--- 1. File Scan: {:?} ---", target);
    if let Ok(report) = scanner.scan_file(target) {
        println!("{}", report);
    }

    // URL scan
    let url = "https://phishing-domain.example.com";
    println!("\n--- 2. URL Scan: {} ---", url);
    if let Ok(url_report) = scanner.scan_url(url) {
        println!("{}", url_report);
    }

    // Registry check
    let reg = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SuspiciousApp";
    println!("\n--- 3. Registry Check: {} ---", reg);
    if let Ok(reg_report) = scanner.check_registry(reg) {
        println!("{}", reg_report);
    }
}
