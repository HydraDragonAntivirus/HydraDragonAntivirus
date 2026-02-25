#![deny(missing_docs)]
/*!
Wrapper around [`windivert_sys`] ffi crate.
*/

/// WinDivert address data structures
pub mod address;
mod divert;
/// WinDivert error types
pub mod error;
/// Layer types used for typestate pattern
pub mod layer;
/// WinDivert packet types
pub mod packet;

pub use divert::*;

/// Prelude module for [`WinDivert`].
pub mod prelude {
    pub use windivert_sys::{
        WinDivertEvent, WinDivertFlags, WinDivertLayer, WinDivertParam, WinDivertShutdownMode,
    };

    pub use crate::divert::*;
    pub use crate::error::*;
    pub use crate::layer::*;
    pub use crate::packet::*;
}
