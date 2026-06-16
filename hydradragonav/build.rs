fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../hydradragon/assets/HydraDragonAV.ico");
        if let Err(e) = res.compile() {
            eprintln!("winres warning: {e}");
        }
    }
}