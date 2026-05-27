/*!
Raw FFI bindings for [WinDivert].

For more information, refer to [WinDivert's documentation].

[WinDivert]: https://www.reqrypt.org/windivert.html
[WinDivert's documentation]: https://www.reqrypt.org/windivert-doc.html
*/
#[warn(missing_docs)]
#[cfg(target_os = "windows")]
mod bindings;

#[cfg(target_os = "windows")]
pub use bindings::*;
