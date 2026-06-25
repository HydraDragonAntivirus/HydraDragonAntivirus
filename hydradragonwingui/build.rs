//! Embeds the HydraDragon application icon (shared with hydradragonav) into the
//! executable so Explorer / taskbar / Alt-Tab show it. The same resource id (1)
//! is loaded at runtime for the window class icon.
//!
//! Also embeds an application manifest that:
//!   * requires UAC elevation (`requireAdministrator`) — the GUI cleans/quarantines
//!     malware, scans process memory, the registry, boot sectors and installs the
//!     Explorer context menu, all of which need admin rights;
//!   * pulls in Common Controls v6 so the ListView/buttons get modern visual styles.

const MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0" processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df" language="*" />
    </dependentAssembly>
  </dependency>
</assembly>
"#;

fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_manifest(MANIFEST);

        let icon = "../hydradragon/assets/HydraDragonAV.ico";
        if std::path::Path::new(icon).exists() {
            res.set_icon_with_id(icon, "1");
        } else {
            println!("cargo:warning=icon not found at {icon}");
        }
        if let Err(e) = res.compile() {
            println!("cargo:warning=resource embed failed: {e}");
        }
        println!("cargo:rerun-if-changed={icon}");
    }
}
