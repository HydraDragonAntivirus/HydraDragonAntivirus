use thiserror::Error;

/**
WinDivert error for unexpected values type conversions.
*/
#[derive(Debug, Error)]
pub enum WinDivertValueError {
    /// Error produced for unexpected values in `TryFrom<u32>` for [`WinDivertLayer`](super::WinDivertLayer)
    #[error("Unexpected value for WinDivertLayer: {0}")]
    Layer(u32),
    /// Error produced for unexpected values in `TryFrom<u8>` for [`WinDivertEvent`](super::WinDivertEvent)
    #[error("Unexpected value for WinDivertEvent: {0}")]
    Event(u8),
    /// Error produced for unexpected values in `TryFrom<u32>` for [`WinDivertParameter`](super::WinDivertParam)
    #[error("Unexpected value for WinDivertParameter: {0}")]
    Parameter(u32),
    /// Error produced for unexpected values in `TryFrom<u32>` for [`WinDivertShutdownMode`](super::WinDivertShutdownMode)
    #[error("Unexpected value for WinDivertShutdownMode: {0}")]
    Shutdown(u32),
}
