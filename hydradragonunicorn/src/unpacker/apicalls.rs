use std::collections::HashMap;
use unicorn_engine::Unicorn;

use crate::unpacker::error::UnpackerResult;

/// Maps hooked API addresses to resolved function names.
pub fn resolve_api_name(
    apicall_counter: &HashMap<String, u64>,
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
    let _ = apicall_counter;
    None
}

/// Placeholder: will be extended with actual Windows API call handlers
/// that drive the emulation forward (e.g., LdrLoadDll, GetProcAddress, etc.).
pub fn handle_api_call(
    _uc: &mut Unicorn<'static, ()>,
    _api_name: &str,
) -> UnpackerResult<()> {
    Ok(())
}
