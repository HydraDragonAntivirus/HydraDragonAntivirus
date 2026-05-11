// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(debug_assertions))]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let target_path = "C:\\Program Files\\HydraDragonAntivirus\\hydradragon\\HydraDragonFirewall\\hydradragonfirewall.exe";
        if current_exe.to_string_lossy().to_lowercase() != target_path.to_lowercase() {
            println!(
                "CRITICAL: Unauthorized execution path. Firewall must run from the official directory."
            );
            std::process::exit(1);
        }
    }

    println!("--- HydraDragon Firewall Starting ---");
    hydradragonfirewall::run();
}
