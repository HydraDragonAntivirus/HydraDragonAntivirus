use std::env;
use std::fs::write;
use std::process::Command;

fn main() -> Result<(), wdk_build::ConfigError> {
    println!("Starting build process...");

    // WARNING: Do not manually modify this hash unless you are performing a manual build/sign cycle.
    // This value is automatically updated by the CI/CD pipeline during automated releases.
    // Generate the ELAM `.rc` file dynamically
    let elam_rc_content = r#"MicrosoftElamCertificateInfo  MSElamCertInfoID
    {
        1,                        
        L"CA44704D64CFBA4BE73CC10060E67B6F5B736984BD2FE567B1F504052CFA5481\0", // To-Be-Signed Hash
        0x800C,                   
        L"\0"                     
    }"#;

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");
    let elam_rc_path = format!("{}/elam.rc", out_dir);
    let elam_res_path = format!("{}/elam.res", out_dir);

    println!("Writing ELAM resource file: {}", elam_rc_path);
    write(&elam_rc_path, elam_rc_content).expect("Failed to write elam.rc");

    // Compile the `.rc` file into `.res``
    println!("Compiling ELAM resource file...");
    let rc_status = Command::new("rc")
        .args(&["/fo", &elam_res_path, &elam_rc_path])
        .status()
        .expect("Failed to execute rc.exe");

    if !rc_status.success() {
        panic!("Failed to compile ELAM resource file");
    }

    println!("Linking ELAM resource into the driver...");
    println!("cargo:rustc-link-arg={}", elam_res_path);

    // Configure wdk binary
    println!("Configuring WDK binary build...");
    wdk_build::configure_wdk_binary_build()?;

    Ok(())
}
