use cc::Build;
use std::process::{Command, Stdio};
use std::{env, fs};

pub fn lib() {
    let mut build = Build::new();
    let out_dir = env::var("OUT_DIR").unwrap();

    build
        .out_dir(&out_dir)
        .include(r#"vendor/include"#)
        .file(r#"vendor/dll/windivert.c"#);

    build.compile("WinDivert");
}

pub fn dll() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let compiler = Build::new().get_compiler();

    let mut cmd = compiler.to_command();
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    let mangle = if env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86" {
        "_"
    } else {
        ""
    };
    cmd.args(DYNAMIC_C_OPTIONS);
    cmd.arg(format!("-Wl,--entry=${mangle}WinDivertDllEntry"));
    cmd.args(["-c", "vendor/dll/windivert.c"]);
    cmd.args(["-o", &format!("{out_dir}/WinDivert.o")]);
    cmd.output().expect("Error compiling windivert c library");

    let mut cmd = Build::new().get_compiler().to_command();
    cmd.args(DYNAMIC_C_OPTIONS);
    cmd.args(["-o", &format!("{out_dir}/WinDivert.dll")]);
    cmd.args([
        &format!("{out_dir}/WinDivert.o"),
        "vendor/dll/windivert.def",
        "-nostdlib",
    ]);
    cmd.args(DYNAMIC_C_INCLUDES);
    cmd.output().expect("Error building windivert dll");

    let strip = Build::new()
        .get_compiler()
        .path()
        .to_string_lossy()
        .replace("gcc", "strip");

    let mut strip = Command::new(strip);
    strip.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    strip.arg(&format!("{out_dir}/WinDivert.dll"));
    let _ = strip.output().expect("Error striping windivert dll");

    let dlltool = Build::new()
        .get_compiler()
        .path()
        .to_string_lossy()
        .replace("gcc", "dlltool");
    let mut dlltool = Command::new(dlltool);
    dlltool.stdout(Stdio::inherit()).stderr(Stdio::inherit());

    dlltool.args(["--dllname", &format!("{out_dir}/WinDivert.dll")]);
    dlltool.args(["--def", "vendor/dll/windivert.def"]);
    dlltool.args(["--output-lib", &format!("{out_dir}/WinDivert.lib")]);
    let _ = dlltool.output().expect("Error building windivert lib");

    let _ = fs::remove_file(format!("{out_dir}/WinDivert.o"));
}

const DYNAMIC_C_OPTIONS: &[&str] = &[
    r#"-fno-ident"#,
    r#"-shared"#,
    r#"-Wall"#,
    r#"-Wno-pointer-to-int-cast"#,
    r#"-Os"#,
    r#"-Ivendor/include/"#,
    r#"-Wl,--enable-stdcall-fixup"#,
];

const DYNAMIC_C_INCLUDES: &[&str] = &[r#"-lkernel32"#, r#"-ladvapi32"#];
