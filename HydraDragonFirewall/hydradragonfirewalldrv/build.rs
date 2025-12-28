use wdk_build;

fn main() -> Result<(), wdk_build::ConfigError> {
    // Wrap unsafe code in an unsafe block
    unsafe {
        std::env::set_var("CARGO_CFG_TARGET_FEATURE", "crt-static");
    }

    // Call the `wdk_build` configuration function
    wdk_build::configure_wdk_binary_build()?;

    Ok(())
}
