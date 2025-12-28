mod compile;

use std::{env, fs};

pub const LIB_PATH_ARG: &str = "WINDIVERT_PATH";
pub const DLL_OUTPUT_PATH_ARG: &str = "WINDIVERT_DLL_OUTPUT";
pub const STATIC_BUILD_ARG: &str = "WINDIVERT_STATIC";

fn main() {
    // Avoid build in docs.rs
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    let out_dir = env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-env-changed={LIB_PATH_ARG}");
    println!("cargo:rerun-if-env-changed={DLL_OUTPUT_PATH_ARG}");
    println!("cargo:rerun-if-env-changed={STATIC_BUILD_ARG}");

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_ref() {
        "x86" => "32",
        "x86_64" => "64",
        "aarch64" => "64",
        "arm" => "64",
        _ => panic!("Unsupported target architecture!"),
    };

    // Prioritize environment variables over feature flags
    if env::var(STATIC_BUILD_ARG).is_ok() || cfg!(feature = "static") {
        println!("cargo:rerun-if-changed=wrapper.h");
        compile::lib();

        println!(
            "cargo:warning=WinDivert{arch}.sys must be located in the same path as the executable."
        )
    } else if let Ok(lib_path) = env::var(LIB_PATH_ARG) {
        println!("cargo:rustc-link-search=native={lib_path}");
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=dylib=WinDivert");
        handle_provided_dll(arch, &out_dir, &lib_path);
    } else if cfg!(feature = "vendored") {
        println!("cargo:rerun-if-changed=wrapper.h");
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=dylib=WinDivert");
        compile::dll();
    } else {
        panic!("Environment variable {LIB_PATH_ARG} not found and feature vendored not enabled, please provide the path to the WinDivert library files or enable the vendored feature to compile from source.");
    }
}

fn handle_provided_dll(arch: &str, out_dir: &str, lib_path: &str) {
    println!(
        "cargo:warning=Copying windivert dll, lib & sys files from the path provided if present."
    );
    for f in fs::read_dir(lib_path).unwrap() {
        let file = f.unwrap();
        if let Some(name) = file.file_name().to_str() {
            match name {
                "WinDivert.dll" | "WinDivert.lib" | "WinDivert32.sys" | "WinDivert64.sys" => {
                    let _ = fs::copy(file.path(), format!("{out_dir}/{name}"));
                }
                _ => {}
            }
        }
    }

    if fs::metadata(format!("{lib_path}\\WinDivert{arch}.sys")).is_err() {
        println!("cargo:warning=WinDivert{arch}.sys not found on the same directory as the dll.")
    }
}
