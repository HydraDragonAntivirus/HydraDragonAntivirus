# WinDivert 2 Rust Wrapper

[![GitHub](https://img.shields.io/github/license/Rubensei/windivert-rust?color=blue)](https://raw.githubusercontent.com/Rubensei/windivert-rust/master/LICENSE)

**Note**: This is a work in process, so the crates won't follow semantic
versioning until 1.0.0 release, so any version change below 1.0.0 might
introduce breaking changes in the API or the crate usage in general.

This projects allows you to use
[WinDivert](https://www.reqrypt.org/windivert.html) from rust. It consists of
two crates:

- `windivert-sys`
  [![crates.io](https://img.shields.io/crates/v/windivert-sys)](https://crates.io/crates/windivert-sys)
  [![docs](https://docs.rs/windivert-sys/badge.svg)](https://docs.rs/windivert-sys/)
  [![dependency status](https://deps.rs/repo/github/Rubensei/windivert-rust/status.svg?path=windivert-sys)](https://deps.rs/repo/github/Rubensei/windivert-rust?path=windivert-sys):
  Crate providing raw bindings to the WinDivert user mode library.
- `windivert`
  [![crates.io](https://img.shields.io/crates/v/windivert)](https://crates.io/crates/windivert)
  [![docs](https://docs.rs/windivert/badge.svg)](https://docs.rs/windivert/)
  [![dependency status](https://deps.rs/repo/github/Rubensei/windivert-rust/status.svg?path=windivert)](https://deps.rs/repo/github/Rubensei/windivert-rust?path=windivert):
  (WIP) Built on top of `windivert-sys` and providing a friendlier Rust API and
  some abstractions.

# Build

To be able to build `windivert-sys` you require WinDivert library files:

- It's recommended to specify the path of the folder containing downloaded dll,
  lib & sys files using the `WINDIVERT_PATH` environment variable.
- As a fallback windivert dll & lib files can be compiled from source if the
  **vendored** feature is enabled. To avoid multiple compilations set
  `WINDIVERT_DLL_OUTPUT` environment variable to save the generated build.
- It's possible to compile for statically linking to the windivert library by
  enabling the **static** feature. Static linking can also be enabled if the
  `WINDIVERT_STATIC` is set and it takes priority over the crate features.
- **Any vendoring method will only compile the library. Sys files must always be
  provided.**

# Usage

- `windivert-sys` shares the same API the native library uses. Read
  [official documentation](https://www.reqrypt.org/windivert-doc.html) for more
  details.
- `windivert` WIP

**Note:** WinDivert dll expects the corresponding driver sys file to be located
on the same folder. Since the dll lib & sys files come in the same folder when
downloading from [official web](https://www.reqrypt.org/windivert.html)
`windivert-sys` will search for it on the path provided with `WINDIVERT_PATH`.
