//! An idiomatic Rust mutex type for Windows kernel driver development, supporting both `wdm` and `kmdf` drivers.
//!
//! ### Installation
//!
//! To use this crate, simply:
//!
//! ```shell
//! cargo add wdk-mutex
//! ```
//!
//! In addition to defining either `WDM` or `KMDF` in your `Cargo.toml` as per the instructions given at [windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs/),
//! you **must** add the following to your `.cargo/config.toml`:
//!
//! ```toml
//! [build]
//! rustflags = [
//!   "-C", "target-feature=+crt-static",
//!   "--cfg", 'driver_model__driver_type="WDM"' # This line, make sure driver type matches your config, either WDM or KMDF
//! ]
//! ```
//!
//! As per the above comment, ensure either `driver_model__driver_type="WDM"` for WDM, or `driver_model__driver_type="KMDF"`.
//!
//! ### Crate Info
//!
//! The crate will safely check IRQL before doing operations which would cause a STOP CODE of
//! IRQL NOT LESS OR EQUAL (**except for RAII dropping of scoped Mutex Guards**).
//! In those cases, the API will return an error of the internal type `DriverMutexError`.
//!
//! This crate is a work in progress to implement additional mutex types and functionality as required. Contributions, issues,
//! and discussions are welcome.
//!
//! This crate is **not** affiliated with the WDK crates provided by Microsoft, but is designed to work with them for Windows Rust Kernel Driver
//! development.
//!
//! # Tests
//!
//! Tests have been conducted on public modules.
//!
//! All tests are carried out at [wdk_mutex_tests](https://github.com/0xflux/wdk_mutex_tests),
//! a separate repository which is built as a driver to test all functionality of the `wdk-mutex` crate. If you wish to run the tests
//! yourself, or contribute, please check that repository.
//!
//! <section class="warning">
//! As this crate integrates into the wdk ecosystem, Microsoft stipulate: This project is still in early stages of development and
//! is not yet recommended for production use.
//!
//! This is licenced with an MIT Licence, conditions can be found in LICENCE in the crate GitHub repository.
//! </section>

#![no_std]

//
// Public modules
//
#[cfg(any(driver_model__driver_type = "WDM", driver_model__driver_type = "KMDF", doc))]
pub mod errors;
#[cfg(any(driver_model__driver_type = "WDM", driver_model__driver_type = "KMDF", doc))]
pub mod fast_mutex;
#[cfg(any(driver_model__driver_type = "WDM", driver_model__driver_type = "KMDF", doc))]
pub mod grt;
#[cfg(any(driver_model__driver_type = "WDM", driver_model__driver_type = "KMDF", doc))]
pub mod kmutex;

//
// Private modules
//
#[cfg(any(driver_model__driver_type = "WDM", driver_model__driver_type = "KMDF", doc))]
mod alloc;
