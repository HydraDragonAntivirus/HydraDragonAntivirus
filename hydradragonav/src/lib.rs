#![cfg(windows)]

pub mod bloom_filter;
pub mod boot_scanner;
pub mod disinfector;
pub mod hash_scanner;
pub mod memory_scanner;
pub mod metrics;
pub mod ml;
pub mod pipeline;
pub mod quarantine;
pub mod file_pum_scanner;
pub mod fix_registry;
pub mod registry_scanner;
pub mod remediation;
pub mod settings;
pub mod startup_scanner;
pub mod takeown;
pub mod restart_disinfect;
pub mod scanner;
pub mod types;
pub mod verdict;

/// Compile-time generated data from build.rs.
pub mod build_data {
    use std::sync::OnceLock;
    use yara_x::Rules;

    include!(concat!(env!("OUT_DIR"), "/packer_rules_bytes.rs"));

    /// Lazily compiled packer detection rules from the embedded YARA source.
    pub fn packer_rules() -> &'static Rules {
        static RULES: OnceLock<Rules> = OnceLock::new();
        RULES.get_or_init(|| {
            let mut compiler = yara_x::Compiler::new();
            // add_source on a small ~3 KB YARA file — stack should be fine at runtime
            if let Err(e) = compiler.add_source(PACKER_RULES_YAR) {
                panic!("failed to compile packer YARA rules: {e}");
            }
            compiler.build()
        })
    }

    /// The compiled YARA rules as serialized bytes (cached).
    pub fn packer_rules_bytes() -> &'static [u8] {
        static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
        BYTES.get_or_init(|| {
            packer_rules()
                .serialize()
                .expect("failed to serialize packer rules")
        })
    }
}

pub use scanner::Scanner;
pub use types::{Error, ScanResult as ClamavScanResult, CL_CLEAN, CL_VIRUS};
pub use verdict::{EngineResult, ScanResult, Verdict};
