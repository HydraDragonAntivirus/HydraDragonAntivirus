//! ATT&CK Coverage Analyzer
//!
//! Analyzes detection coverage across all MITRE ATT&CK techniques

use super::technique_mapping::MitreTechnique;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Coverage level for a technique
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CoverageLevel {
    /// Strong coverage: Static + Dynamic + Behavioral evidence
    Strong,
    /// Medium coverage: Static + one other source
    Medium,
    /// Weak coverage: IOC/string matching only
    Weak,
    /// No coverage: No telemetry available
    None,
}

impl CoverageLevel {
    pub fn label(&self) -> &'static str {
        match self {
            CoverageLevel::Strong => "Strong",
            CoverageLevel::Medium => "Medium",
            CoverageLevel::Weak => "Weak",
            CoverageLevel::None => "None",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            CoverageLevel::Strong => "#27ae60",    // Green
            CoverageLevel::Medium => "#f39c12",    // Orange
            CoverageLevel::Weak => "#e67e22",      // Dark Orange
            CoverageLevel::None => "#95a5a6",      // Gray
        }
    }

    pub fn score(&self) -> u8 {
        match self {
            CoverageLevel::Strong => 3,
            CoverageLevel::Medium => 2,
            CoverageLevel::Weak => 1,
            CoverageLevel::None => 0,
        }
    }
}

/// Coverage information for a single technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueCoverage {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub coverage_level: CoverageLevel,
    pub detection_sources: Vec<String>,
    pub notes: String,
}

/// Complete coverage analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageAnalysis {
    pub total_techniques: usize,
    pub strong_coverage: usize,
    pub medium_coverage: usize,
    pub weak_coverage: usize,
    pub no_coverage: usize,
    pub coverage_by_tactic: HashMap<String, TacticCoverage>,
    pub technique_coverage: Vec<TechniqueCoverage>,
}

/// Coverage statistics for a tactic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic_name: String,
    pub total_techniques: usize,
    pub strong: usize,
    pub medium: usize,
    pub weak: usize,
    pub none: usize,
}

impl TacticCoverage {
    pub fn coverage_percentage(&self) -> f32 {
        if self.total_techniques == 0 {
            return 0.0;
        }
        ((self.strong + self.medium) as f32 / self.total_techniques as f32) * 100.0
    }
}

/// Coverage Analyzer
pub struct CoverageAnalyzer {
    techniques: HashMap<String, MitreTechnique>,
}

impl CoverageAnalyzer {
    pub fn new(techniques: HashMap<String, MitreTechnique>) -> Self {
        Self { techniques }
    }

    /// Analyze coverage based on available detection capabilities
    pub fn analyze_coverage(&self) -> CoverageAnalysis {
        let mut technique_coverage = Vec::new();
        let mut coverage_by_tactic: HashMap<String, TacticCoverage> = HashMap::new();

        let mut strong_count = 0;
        let mut medium_count = 0;
        let mut weak_count = 0;
        let mut none_count = 0;

        for technique in self.techniques.values() {
            let (level, sources, notes) = self.assess_technique_coverage(&technique.id);

            technique_coverage.push(TechniqueCoverage {
                technique_id: technique.id.clone(),
                technique_name: technique.name.clone(),
                tactic: technique.tactic.clone(),
                coverage_level: level,
                detection_sources: sources,
                notes,
            });

            // Update tactic coverage
            let tactic_cov = coverage_by_tactic
                .entry(technique.tactic.clone())
                .or_insert_with(|| TacticCoverage {
                    tactic_name: technique.tactic.clone(),
                    total_techniques: 0,
                    strong: 0,
                    medium: 0,
                    weak: 0,
                    none: 0,
                });

            tactic_cov.total_techniques += 1;
            match level {
                CoverageLevel::Strong => {
                    tactic_cov.strong += 1;
                    strong_count += 1;
                }
                CoverageLevel::Medium => {
                    tactic_cov.medium += 1;
                    medium_count += 1;
                }
                CoverageLevel::Weak => {
                    tactic_cov.weak += 1;
                    weak_count += 1;
                }
                CoverageLevel::None => {
                    tactic_cov.none += 1;
                    none_count += 1;
                }
            }
        }

        CoverageAnalysis {
            total_techniques: self.techniques.len(),
            strong_coverage: strong_count,
            medium_coverage: medium_count,
            weak_coverage: weak_count,
            no_coverage: none_count,
            coverage_by_tactic,
            technique_coverage,
        }
    }

    /// Assess coverage level for a specific technique
    fn assess_technique_coverage(&self, technique_id: &str) -> (CoverageLevel, Vec<String>, String) {
        // This is a simplified assessment based on technique characteristics
        // In a real implementation, this would check actual detection rules and telemetry

        let sources = self.get_detection_sources(technique_id);
        let level = self.determine_coverage_level(&sources);
        let notes = self.generate_coverage_notes(technique_id, &sources);

        (level, sources, notes)
    }

    /// Get available detection sources for a technique
    fn get_detection_sources(&self, technique_id: &str) -> Vec<String> {
        let mut sources = Vec::new();

        // Map techniques to available detection sources
        // This is a simplified mapping - real implementation would be more comprehensive
        match technique_id {
            // Process Injection techniques - Strong coverage
            id if id.starts_with("T1055") => {
                sources.push("Behavioral".to_string());
                sources.push("Hypervisor".to_string());
                sources.push("Kernel".to_string());
            }
            // PowerShell execution - Strong coverage
            "T1059.001" => {
                sources.push("Behavioral".to_string());
                sources.push("ProcessTree".to_string());
                sources.push("Network".to_string());
            }
            // Registry persistence - Medium coverage
            id if id.starts_with("T1547") => {
                sources.push("Registry".to_string());
                sources.push("Behavioral".to_string());
            }
            // Credential dumping - Strong coverage
            "T1003.001" => {
                sources.push("Behavioral".to_string());
                sources.push("Memory".to_string());
                sources.push("SelfDefense".to_string());
            }
            // Ransomware - Strong coverage
            "T1486" => {
                sources.push("Behavioral".to_string());
                sources.push("FileSystem".to_string());
                sources.push("Static".to_string());
            }
            // Network C2 - Medium coverage
            id if id.starts_with("T1071") => {
                sources.push("Network".to_string());
                sources.push("Firewall".to_string());
            }
            // Rootkit techniques - Strong coverage
            id if id.starts_with("T1014") || id.starts_with("T1542") => {
                sources.push("Rootkit".to_string());
                sources.push("Kernel".to_string());
            }
            // Default: Weak or no coverage
            _ => {
                if technique_id.starts_with("T10") {
                    sources.push("Static".to_string());
                }
            }
        }

        sources
    }

    /// Determine coverage level based on available sources
    fn determine_coverage_level(&self, sources: &[String]) -> CoverageLevel {
        if sources.is_empty() {
            return CoverageLevel::None;
        }

        let has_behavioral = sources.iter().any(|s| s == "Behavioral");
        let has_kernel = sources.iter().any(|s| s == "Kernel" || s == "Hypervisor");
        let has_static = sources.iter().any(|s| s == "Static");

        if sources.len() >= 3 && (has_behavioral || has_kernel) {
            CoverageLevel::Strong
        } else if sources.len() >= 2 {
            CoverageLevel::Medium
        } else if has_static {
            CoverageLevel::Weak
        } else {
            CoverageLevel::Medium
        }
    }

    /// Generate coverage notes
    fn generate_coverage_notes(&self, technique_id: &str, sources: &[String]) -> String {
        if sources.is_empty() {
            return "No detection telemetry available".to_string();
        }

        if sources.len() >= 3 {
            format!("Multiple detection sources: {}", sources.join(", "))
        } else if sources.len() == 2 {
            format!("Dual-source detection: {}", sources.join(", "))
        } else {
            format!("Single-source detection: {}", sources[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coverage_levels() {
        assert_eq!(CoverageLevel::Strong.score(), 3);
        assert_eq!(CoverageLevel::Medium.score(), 2);
        assert_eq!(CoverageLevel::Weak.score(), 1);
        assert_eq!(CoverageLevel::None.score(), 0);
    }

    #[test]
    fn test_coverage_analysis() {
        let mut techniques = HashMap::new();
        techniques.insert(
            "T1055".to_string(),
            MitreTechnique {
                id: "T1055".to_string(),
                name: "Process Injection".to_string(),
                tactic: "Defense Evasion".to_string(),
                description: "Test".to_string(),
                severity: 9,
            },
        );

        let analyzer = CoverageAnalyzer::new(techniques);
        let analysis = analyzer.analyze_coverage();

        assert_eq!(analysis.total_techniques, 1);
        assert!(analysis.strong_coverage > 0 || analysis.medium_coverage > 0);
    }
}
