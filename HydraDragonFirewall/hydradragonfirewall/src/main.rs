// #![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(debug_assertions))]
    {
        let current_exe = std::env::current_exe().unwrap_or_default();
        let exe_str = current_exe.to_string_lossy().to_lowercase();
        if exe_str.ends_with("owlyshield_ransom.exe")
            || !(exe_str.contains("hydradragonantivirus") || exe_str.contains("appdata"))
        {
            println!(
                "CRITICAL: Unauthorized execution path. Firewall must run from the official directory."
            );
            std::process::exit(1);
        }
    }

    println!("--- HydraDragon Firewall Starting ---");
    hydradragonfirewall::run();
}
