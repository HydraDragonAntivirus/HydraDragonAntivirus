pub mod manager;
pub mod ioctl;
pub mod service;

// to prevent requiring double driver_manager::driver_manager in imports
pub use manager::DriverHandleRaii;
pub use manager::SanctumDriverManager;
