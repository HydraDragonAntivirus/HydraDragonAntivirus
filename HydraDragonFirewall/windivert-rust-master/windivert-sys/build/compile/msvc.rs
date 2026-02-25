use cc::Build;
use std::{env, fs};

use crate::DLL_OUTPUT_PATH_ARG;

pub fn lib() {
    let mut build = Build::new();
    let out_dir = env::var("OUT_DIR").unwrap();

    build
        .out_dir(&out_dir)
        .include(r#"vendor\include"#)
        .file(r#"vendor\dll\windivert.c"#);

    for &flag in STATIC_CL_ARGS {
        build.flag(flag);
    }
    build.compile("WinDivert");
}

pub fn dll() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut compiler = Build::new().get_compiler().to_command();

    let arch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_ref() {
        "x86" => "x86",
        "x86_64" => "x64",
        _ => panic!("Unsupported target architecture!"),
    };

    for &flag in DYNAMIC_CL_ARGS {
        compiler.arg(flag);
    }

    compiler.arg(&format!("/MACHINE:{arch}"));

    compiler.arg(&format!(r#"/PDB:{out_dir}\WinDivertDll.pdb"#));
    compiler.arg(&format!(r#"/OUT:{out_dir}\WinDivert.dll"#));
    compiler.arg(&format!(r#"/IMPLIB:{out_dir}\WinDivert.lib"#));

    if let Ok(out) = compiler.output() {
        if !out.status.success() {
            panic!(
                "\nERROR: {:?}\n{}\n",
                &out.status,
                String::from_utf8_lossy(&out.stdout),
            )
        }
    } else {
        panic!("Error compiling windivert dll.");
    }

    if let Ok(dylib_save_dir) = env::var(DLL_OUTPUT_PATH_ARG) {
        let _ = fs::copy(
            format!(r#"{out_dir}\WinDivert.dll"#),
            format!(r#"{dylib_save_dir}\WinDivert.dll"#),
        );
        let _ = fs::copy(
            format!(r#"{out_dir}\WinDivert.lib"#),
            format!(r#"{dylib_save_dir}\WinDivert.lib"#),
        );
    } else {
        println!("cargo:warning=Environment variable {DLL_OUTPUT_PATH_ARG} not found, compiled dll & lib files will be stored on {out_dir}");
    };
}

const DYNAMIC_CL_ARGS: &[&str] = &[
    r#"/Ivendor\include"#,
    r#"/ZI"#,
    r#"/JMC"#,
    r#"/nologo"#,
    r#"/W1"#,
    r#"/WX-"#,
    r#"/diagnostics:column"#,
    r#"/O1"#,
    r#"/Oi"#,
    r#"/Gm-"#,
    r#"/EHsc"#,
    r#"/MDd"#,
    r#"/GS-"#,
    r#"/fp:precise"#,
    r#"/Zc:wchar_t"#,
    r#"/Zc:forScope"#,
    r#"/Zc:inline"#,
    r#"/Gd"#,
    r#"/TC"#,
    r#"/FC"#,
    r#"/errorReport:queue"#,
    r#"vendor\dll\windivert.c"#,
    r#"/link"#,
    r#"/ERRORREPORT:QUEUE"#,
    r#"/INCREMENTAL"#,
    r#"/NOLOGO"#,
    r#"kernel32.lib"#,
    r#"advapi32.lib"#,
    r#"/NODEFAULTLIB"#,
    r#"/DEF:vendor/dll/windivert.def"#,
    r#"/MANIFEST"#,
    r#"/manifest:embed"#,
    r#"/DEBUG:FASTLINK"#,
    r#"/TLDLIB:1"#,
    r#"/ENTRY:"WinDivertDllEntry""#,
    r#"/DYNAMICBASE"#,
    r#"/NXCOMPAT"#,
    r#"/DLL"#,
];

const STATIC_CL_ARGS: &[&str] = &[
    r#"/nologo"#,
    r#"/WX-"#,
    r#"/diagnostics:column"#,
    r#"/O1"#,
    r#"/Oi"#,
    r#"/EHsc"#,
    r#"/GS-"#,
    r#"/fp:precise"#,
    r#"/Zc:wchar_t"#,
    r#"/Zc:forScope"#,
    r#"/Zc:inline"#,
    r#"/Gd"#,
    r#"/TC"#,
    r#"/FC"#,
    r#"/errorReport:queue"#,
];
