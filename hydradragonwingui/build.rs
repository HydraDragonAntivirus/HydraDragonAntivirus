//! Embeds the HydraDragon application icon (shared with hydradragonav) into the
//! executable so Explorer / taskbar / Alt-Tab show it. The same resource id (1)
//! is loaded at runtime for the window class icon.

fn main() {
    #[cfg(windows)]
    {
        let icon = "../hydradragon/assets/HydraDragonAV.ico";
        if std::path::Path::new(icon).exists() {
            let mut res = winres::WindowsResource::new();
            res.set_icon_with_id(icon, "1");
            if let Err(e) = res.compile() {
                println!("cargo:warning=icon embed failed: {e}");
            }
        } else {
            println!("cargo:warning=icon not found at {icon}");
        }
        println!("cargo:rerun-if-changed={icon}");
    }
}
