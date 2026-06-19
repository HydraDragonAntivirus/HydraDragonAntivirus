#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Freshclam not found at: {0}")]
    FreshclamNotFound(String),
    #[error("Freshclam execution error: {0}")]
    FreshclamError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Other(String),
}
