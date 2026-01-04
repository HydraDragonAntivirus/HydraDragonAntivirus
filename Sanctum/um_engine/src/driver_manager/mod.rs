pub mod driver_manager;
pub mod ioctl;
pub mod service;

// to prevent requiring double driver_manager::driver_manager in imports
pub use driver_manager::DriverHandleRaii;
pub use driver_manager::SanctumDriverManager;
