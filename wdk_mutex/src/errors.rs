//! Error types used by wdk-mutex

#[derive(Debug, PartialEq, Eq)]
pub enum DriverMutexError {
    IrqlTooHigh,
    IrqlNotAPCLevel,
    PagedPoolAllocFailed,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrtError {
    GrtAlreadyExists,
    GrtIsNull,
    GrtIsEmpty,
    KeyNotFound,
    KeyExists,
    DowncastError,
    DriverMutexError(DriverMutexError),
}
