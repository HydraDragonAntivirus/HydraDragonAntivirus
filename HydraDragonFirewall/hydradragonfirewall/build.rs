fn main() {
    let mut windows = tauri_build::WindowsAttributes::new();
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let manifest = include_str!("app.manifest");
        windows = windows.app_manifest(manifest);
    }
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows))
        .expect("failed to run build script");
}
