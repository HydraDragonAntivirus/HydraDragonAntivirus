use std::process::Command;

const CRITICAL_DRIVERS: &[&str] = &[
    "sanctum",
    "MBRFilter",
    "hyperhv",
    "SimplePYASProtection",
    "RedDbg",
    "OwlyshieldRansomFilter",
    "edrdrv",
];

pub fn start_security_drivers() {
    for driver in CRITICAL_DRIVERS {
        println!("Attempting to start critical driver/service: {}", driver);
        let output = Command::new("sc")
            .arg("start")
            .arg(driver)
            .output();

        match output {
            Ok(out) => {
                let status = String::from_utf8_lossy(&out.stdout);
                let err = String::from_utf8_lossy(&out.stderr);
                if out.status.success() {
                    println!("Successfully started {}:\n{}", driver, status.trim());
                } else {
                    println!("sc start returned error for {}:\n{}\n{}", driver, status.trim(), err.trim());
                }
            }
            Err(e) => {
                println!("Failed to execute sc start for {}: {}", driver, e);
            }
        }
    }
}
