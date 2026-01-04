fn main() {
    // Disable conflicting CRT libraries to prevent dynamic linking.
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:libvcruntimed.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:vcruntime.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:vcruntimed.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:libcmtd.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:msvcrt.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:msvcrtd.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:libucrt.lib");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB:libucrtd.lib");

    // Explicitly add static runtime libraries.
    println!("cargo:rustc-link-arg=/DEFAULTLIB:libcmt.lib");
    println!("cargo:rustc-link-arg=/DEFAULTLIB:libvcruntime.lib");
    println!("cargo:rustc-link-arg=/DEFAULTLIB:ucrt.lib");
}