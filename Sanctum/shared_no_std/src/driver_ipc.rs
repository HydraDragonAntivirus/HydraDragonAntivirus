//! Definitions for IPC structures shared between the user mode modules and the driver
//! for serialisation through IPC.
extern crate alloc;
use alloc::{collections::BTreeSet, string::String};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessStarted {
    pub image_name: String,
    pub command_line: String,
    pub parent_pid: u32,
    pub pid: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProcessTerminated {
    pub pid: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HandleObtained {
    pub source_pid: u64,
    pub dest_pid: u64,
    pub rights_desired: u32,
    pub rights_given: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AmsiBypassAttempt {
    pub pid: u32,
    pub function_name: String,
    pub offending_address: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GhostHunt {
    pub pid: u32,
    pub syscall_name: String,
    pub address: u64,
    pub hex_payload: String, // String for easier JSON serialization of hex
}

pub type ImageLoadQueues = BTreeSet<usize>;
