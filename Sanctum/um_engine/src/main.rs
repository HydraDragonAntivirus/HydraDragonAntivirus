//! The main entrypoint for the usermode engine for the Sanctum EDR. This will run as a service
//! on the host machine and is responsible for all EDR related activity in usermode, including
//! communicating with the driver, GUI, DLL's; performing scanning; and decision making.

#![feature(io_error_uncategorized)]

use engine::Engine;
use utils::log::Log;
use windows::Win32::{
    Foundation::LUID,
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

mod core;
mod driver_manager;
mod engine;
mod filescanner;
mod gui_communication;
mod settings;
mod strings;
mod utils;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    elevate("SeDebugPrivilege");
    elevate("SeImpersonatePrivilege");

    //
    // Start the engine, this will kick off and run the application; note this should never return,
    // unless an error occurred.
    //
    let error = Engine::start().await;

    let logger = Log::new();
    logger.panic(&format!(
        "A fatal error occurred in Engine::start() causing the application to crash. {:?}",
        error
    ));
}

fn elevate(name: &str) {
    println!("Elevating..");
    unsafe {
        let mut tok = Default::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut tok,
        )
        .ok()
        .unwrap();
        let mut luid = LUID::default();
        LookupPrivilegeValueW(None, &windows::core::HSTRING::from(name), &mut luid)
            .ok()
            .unwrap();
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let res = AdjustTokenPrivileges(tok, false, Some(&tp), 0, None, None);
        println!("Result of altering token: {res:?}");
    }
}
