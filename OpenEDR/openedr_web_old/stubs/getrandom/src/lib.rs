//! Fail-closed stub implementing the `getrandom` 0.2 API surface used by
//! `rand_core 0.6` (`getrandom`, `getrandom_uninit`, `Error` + constants).
//!
//! WHY: on `wasm32-unknown-unknown` the real crate needs its `js` backend,
//! which links `wasm-bindgen` JS shims (`__wbindgen_placeholder__`) into every
//! downstream binary. This crate is `[patch]`ed in ONLY for the web build, so
//! `openedr_web.wasm` ships zero JS imports. Randomness here is unreachable
//! anyway (scan/verify-only engine: no signing, no UUID generation, no RNG
//! seeding in any executed path), so every call fails closed with
//! [`Error::UNSUPPORTED`] — mirroring upstream behavior on unsupported
//! targets — instead of hanging or trapping on missing JS.
//!
//! MUST NOT be used on targets with a real OS RNG: it would silently turn
//! every entropy request into an error.

use core::{fmt, num::NonZeroU32};

/// API-compatible error type (same codes as upstream 0.2).
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Error(NonZeroU32);

const fn internal_error(n: u16) -> Error {
    let code = Error::INTERNAL_START + (n as u32);
    Error(unsafe { NonZeroU32::new_unchecked(code) })
}

impl Error {
    /// This target/platform is not supported by `getrandom`.
    pub const UNSUPPORTED: Error = internal_error(0);
    /// The platform-specific `errno` returned a non-positive value.
    pub const ERRNO_NOT_POSITIVE: Error = internal_error(1);
    /// Encountered an unexpected situation which should not happen in practice.
    pub const UNEXPECTED: Error = internal_error(2);
    /// Call to `CCRandomGenerateBytes` failed (iOS family).
    pub const IOS_SEC_RANDOM: Error = internal_error(3);
    /// Call to Windows `RtlGenRandom` failed.
    pub const WINDOWS_RTL_GEN_RANDOM: Error = internal_error(4);
    /// RDRAND instruction failed due to a hardware issue.
    pub const FAILED_RDRAND: Error = internal_error(5);
    /// RDRAND instruction unsupported on this target.
    pub const NO_RDRAND: Error = internal_error(6);
    /// The environment does not support the Web Crypto API.
    pub const WEB_CRYPTO: Error = internal_error(7);
    /// Calling Web API `crypto.getRandomValues` failed.
    pub const WEB_GET_RANDOM_VALUES: Error = internal_error(8);
    /// On VxWorks, call to `randSecure` failed.
    pub const VXWORKS_RAND_SECURE: Error = internal_error(11);
    /// Node.js does not have the `crypto` CommonJS module.
    pub const NODE_CRYPTO: Error = internal_error(12);
    /// Calling Node.js API `crypto.randomFillSync` failed.
    pub const NODE_RANDOM_FILL_SYNC: Error = internal_error(13);
    /// Called from an ES module on Node.js (unsupported).
    pub const NODE_ES_MODULE: Error = internal_error(14);

    /// Codes below this point represent OS errors; at/above (below
    /// [`Error::CUSTOM_START`]) are reserved for `rand`/`getrandom`.
    pub const INTERNAL_START: u32 = 1 << 31;

    /// Codes at/above this point are user-definable custom errors.
    pub const CUSTOM_START: u32 = (1 << 31) + (1 << 30);

    /// Extract the raw OS error code, if any.
    #[inline]
    pub fn raw_os_error(self) -> Option<i32> {
        if self.0.get() < Self::INTERNAL_START {
            Some(self.0.get() as i32)
        } else {
            None
        }
    }

    /// Extract the bare error code.
    #[inline]
    pub const fn code(self) -> NonZeroU32 {
        self.0
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No libc here by design: stub never reports OS errors.
        if let Some(desc) = internal_desc(*self) {
            f.debug_struct("Error")
                .field("internal_code", &self.0.get())
                .field("description", &desc)
                .finish()
        } else {
            f.debug_struct("Error")
                .field("unknown_code", &self.0.get())
                .finish()
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(desc) = internal_desc(*self) {
            f.write_str(desc)
        } else {
            write!(f, "Unknown Error: {}", self.0.get())
        }
    }
}

impl From<NonZeroU32> for Error {
    fn from(code: NonZeroU32) -> Self {
        Self(code)
    }
}

impl core::error::Error for Error {}

fn internal_desc(error: Error) -> Option<&'static str> {
    match error {
        Error::UNSUPPORTED => Some("getrandom: this target is not supported"),
        Error::ERRNO_NOT_POSITIVE => Some("errno: did not return a positive value"),
        Error::UNEXPECTED => Some("unexpected situation"),
        Error::IOS_SEC_RANDOM => Some("SecRandomCopyBytes: iOS Security framework failure"),
        Error::WINDOWS_RTL_GEN_RANDOM => Some("RtlGenRandom: Windows system function failure"),
        Error::FAILED_RDRAND => Some("RDRAND: failed multiple times: CPU issue likely"),
        Error::NO_RDRAND => Some("RDRAND: instruction not supported"),
        Error::WEB_CRYPTO => Some("Web Crypto API is unavailable"),
        Error::WEB_GET_RANDOM_VALUES => Some("Calling Web API crypto.getRandomValues failed"),
        Error::VXWORKS_RAND_SECURE => Some("randSecure: VxWorks RNG module is not initialized"),
        Error::NODE_CRYPTO => Some("Node.js crypto CommonJS module is unavailable"),
        Error::NODE_RANDOM_FILL_SYNC => Some("Calling Node.js API crypto.randomFillSync failed"),
        Error::NODE_ES_MODULE => Some("Node.js ES modules are not directly supported"),
        _ => None,
    }
}

/// Always fails closed: this build has no entropy source by design.
pub fn getrandom(_dest: &mut [u8]) -> Result<(), Error> {
    Err(Error::UNSUPPORTED)
}

/// Always fails closed: this build has no entropy source by design.
pub fn getrandom_uninit(
    _dest: &mut [core::mem::MaybeUninit<u8>],
) -> Result<&mut [u8], Error> {
    Err(Error::UNSUPPORTED)
}
