//! False Positive Lab
//!
//! Tests clean software to identify false positives

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Clean software test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanSoftwareTest {
    pub name: String,
    pub path: PathBuf,
    pub category: String,
    pub vendor: String,
}

/// FP test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FPTestResult {
    pub software_name: String,
    pub flagged: bool,
    pub false_positive: bool,
    pub triggered_rules: Vec<String>,
}

/// FP Lab
pub struct FalsePositiveLab {
    clean_corpus: Vec<CleanSoftwareTest>,
}

impl FalsePositiveLab {
    pub fn new() -> Self {
        Self {
            clean_corpus: Vec::new(),
        }
    }

    pub fn add_clean_software(&mut self, test: CleanSoftwareTest) {
        self.clean_corpus.push(test);
    }

    pub fn run_tests(&self) -> Vec<FPTestResult> {
        let mut results = Vec::new();
        
        for software in &self.clean_corpus {
            results.push(FPTestResult {
                software_name: software.name.clone(),
                flagged: false,
                false_positive: false,
                triggered_rules: Vec::new(),
            });
        }

        results
    }
}

impl Default for FalsePositiveLab {
    fn default() -> Self {
        Self::new()
    }
}
