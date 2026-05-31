use std::path::{Path, PathBuf};

const HYDRADRAGON_INSTALL_DIR_NAME: &str = "HydraDragonAntivirus";
const HYDRADRAGON_APP_DIR_NAME: &str = "hydradragon";
const DEFAULT_PROGRAM_FILES_ROOT: &str = r"C:\Program Files";
const DEFAULT_PROGRAM_DATA_ROOT: &str = r"C:\ProgramData";

fn program_files_root() -> PathBuf {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROGRAM_FILES_ROOT))
}

fn program_data_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_PROGRAM_DATA_ROOT))
}

pub fn resolve_install_dir() -> PathBuf {
    program_files_root()
        .join(HYDRADRAGON_INSTALL_DIR_NAME)
        .join(HYDRADRAGON_APP_DIR_NAME)
}

pub fn install_path(relative_path: impl AsRef<Path>) -> PathBuf {
    resolve_install_dir().join(relative_path)
}

pub fn runtime_data_path(relative_path: impl AsRef<Path>) -> PathBuf {
    program_data_root()
        .join(HYDRADRAGON_INSTALL_DIR_NAME)
        .join(relative_path)
}
