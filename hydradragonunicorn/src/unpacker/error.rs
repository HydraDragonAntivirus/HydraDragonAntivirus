use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnpackerError {
    #[error("not a valid PE file: {0}")]
    InvalidPeFile(String),

    #[error("YARA error: {0}")]
    YaraError(String),

    #[error("emulator error: {0}")]
    EmulatorError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("unpacker error: {0}")]
    General(String),
}

pub type UnpackerResult<T> = Result<T, UnpackerError>;
