//! Evidence Types for Detection Evidence Engine
//!
//! Defines the data structures for building evidence chains that explain
//! why a particular MITRE ATT&CK technique was detected.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Source of evidence for a detection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    /// Static analysis of file (PE headers, strings, etc.)
    Static,
    /// Dynamic behavior monitoring (process, registry, file operations)
    Dynamic,
    /// Behavioral analysis (API calls, patterns)
    Behavioral,
    /// Network activity (connections, DNS, HTTP)
    Network,
    /// YARA rule match
    Yara,
    /// Machine learning model prediction
    MachineLearning,
    /// Signature verification
    Signature,
    /// Parent-child process relationship
    ProcessTree,
    /// Registry operations
    Registry,
    /// File system operations
    FileSystem,
    /// Memory operations
    Memory,
    /// Hypervisor/VMM events
    Hypervisor,
    /// Kernel-level telemetry
    Kernel,
    /// User-mode hooks
    UserModeHook,
    /// OpenEDR telemetry
    OpenEDR,
    /// Sanctum EDR telemetry
    SanctumEDR,
    /// Firewall/network filter
    Firewall,
    /// Self-defense telemetry
    SelfDefense,
    /// Rootkit detection
    Rootkit,
}

impl EvidenceSource {
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceSource::Static => "Static Analysis",
            EvidenceSource::Dynamic => "Dynamic Behavior",
            EvidenceSource::Behavioral => "Behavioral Pattern",
            EvidenceSource::Network => "Network Activity",
            EvidenceSource::Yara => "YARA Rule",
            EvidenceSource::MachineLearning => "ML Model",
            EvidenceSource::Signature => "Digital Signature",
            EvidenceSource::ProcessTree => "Process Relationship",
            EvidenceSource::Registry => "Registry Operation",
            EvidenceSource::FileSystem => "File Operation",
            EvidenceSource::Memory => "Memory Operation",
            EvidenceSource::Hypervisor => "Hypervisor Event",
            EvidenceSource::Kernel => "Kernel Telemetry",
            EvidenceSource::UserModeHook => "User-Mode Hook",
            EvidenceSource::OpenEDR => "OpenEDR",
            EvidenceSource::SanctumEDR => "Sanctum EDR",
            EvidenceSource::Firewall => "Network Filter",
            EvidenceSource::SelfDefense => "Self-Defense",
            EvidenceSource::Rootkit => "Rootkit Detection",
        }
    }

    /// Weight of this evidence source (0.0-1.0)
    pub fn base_weight(&self) -> f32 {
        match self {
            EvidenceSource::Behavioral => 0.9,
            EvidenceSource::Hypervisor => 0.85,
            EvidenceSource::Kernel => 0.85,
            EvidenceSource::Rootkit => 0.95,
            EvidenceSource::Dynamic => 0.8,
            EvidenceSource::Network => 0.75,
            EvidenceSource::ProcessTree => 0.7,
            EvidenceSource::Memory => 0.8,
            EvidenceSource::Registry => 0.7,
            EvidenceSource::FileSystem => 0.65,
            EvidenceSource::Yara => 0.75,
            EvidenceSource::MachineLearning => 0.7,
            EvidenceSource::OpenEDR => 0.8,
            EvidenceSource::SanctumEDR => 0.85,
            EvidenceSource::Firewall => 0.75,
            EvidenceSource::SelfDefense => 0.9,
            EvidenceSource::UserModeHook => 0.75,
            EvidenceSource::Static => 0.5,
            EvidenceSource::Signature => 0.6,
        }
    }
}

/// Individual piece of evidence supporting a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Source of this evidence
    pub source: EvidenceSource,
    /// Human-readable description
    pub description: String,
    /// Weight/importance of this evidence (0.0-1.0)
    pub weight: f32,
    /// When this evidence was observed
    pub timestamp: SystemTime,
    /// Optional raw data for analyst mode
    pub raw_data: Option<String>,
    /// Optional context (e.g., command line, registry key, API name)
    pub context: Option<String>,
}

impl EvidenceItem {
    pub fn new(source: EvidenceSource, description: String) -> Self {
        let weight = source.base_weight();
        Self {
            source,
            description,
            weight,
            timestamp: SystemTime::now(),
            raw_data: None,
            context: None,
        }
    }

    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight.clamp(0.0, 1.0);
        self
    }

    pub fn with_raw_data(mut self, raw_data: String) -> Self {
        self.raw_data = Some(raw_data);
        self
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    pub fn with_timestamp(mut self, timestamp: SystemTime) -> Self {
        self.timestamp = timestamp;
        self
    }
}

/// Complete evidence chain for a detected technique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvidence {
    /// MITRE ATT&CK technique ID
    pub technique_id: String,
    /// Technique name
    pub technique_name: String,
    /// Overall confidence (0.0-1.0)
    pub confidence: f32,
    /// Chain of evidence items
    pub evidence_chain: Vec<EvidenceItem>,
    /// Correlation score (how well evidence items support each other)
    pub correlation_score: f32,
    /// Estimated false positive likelihood (0.0-1.0)
    pub false_positive_likelihood: f32,
    /// Number of independent evidence sources
    pub source_diversity: usize,
    /// Timestamp of first evidence
    pub first_seen: SystemTime,
    /// Timestamp of last evidence
    pub last_seen: SystemTime,
}

impl DetectionEvidence {
    pub fn new(technique_id: String, technique_name: String) -> Self {
        Self {
            technique_id,
            technique_name,
            confidence: 0.0,
            evidence_chain: Vec::new(),
            correlation_score: 0.0,
            false_positive_likelihood: 1.0,
            source_diversity: 0,
            first_seen: SystemTime::now(),
            last_seen: SystemTime::now(),
        }
    }

    /// Add an evidence item to the chain
    pub fn add_evidence(&mut self, evidence: EvidenceItem) {
        if self.evidence_chain.is_empty() {
            self.first_seen = evidence.timestamp;
        }
        self.last_seen = evidence.timestamp;
        self.evidence_chain.push(evidence);
        self.recalculate_metrics();
    }

    /// Recalculate confidence, correlation, and FP likelihood
    fn recalculate_metrics(&mut self) {
        if self.evidence_chain.is_empty() {
            self.confidence = 0.0;
            self.correlation_score = 0.0;
            self.false_positive_likelihood = 1.0;
            self.source_diversity = 0;
            return;
        }

        // Calculate source diversity
        let unique_sources: std::collections::HashSet<_> =
            self.evidence_chain.iter().map(|e| &e.source).collect();
        self.source_diversity = unique_sources.len();

        // Base confidence from weighted evidence
        let total_weight: f32 = self.evidence_chain.iter().map(|e| e.weight).sum();
        let evidence_count = self.evidence_chain.len() as f32;
        let base_confidence = (total_weight / evidence_count.max(1.0)).min(1.0);

        // Bonus for multiple independent sources
        let diversity_bonus = match self.source_diversity {
            0..=1 => 0.0,
            2 => 0.05,
            3 => 0.10,
            4 => 0.15,
            _ => 0.20,
        };

        // Bonus for multiple evidence items
        let quantity_bonus = match self.evidence_chain.len() {
            0..=1 => 0.0,
            2..=3 => 0.05,
            4..=6 => 0.10,
            _ => 0.15,
        };

        // Calculate correlation score (how well evidence supports each other)
        self.correlation_score = self.calculate_correlation();
        let correlation_bonus = self.correlation_score * 0.15;

        // Final confidence
        self.confidence = (base_confidence + diversity_bonus + quantity_bonus + correlation_bonus)
            .min(1.0)
            .max(0.0);

        // False positive likelihood (inverse of confidence with adjustments)
        self.false_positive_likelihood =
            if self.source_diversity >= 3 && self.evidence_chain.len() >= 4 {
                (1.0 - self.confidence) * 0.5 // Strong evidence = lower FP
            } else if self.source_diversity == 1 {
                (1.0 - self.confidence) * 1.5 // Single source = higher FP risk
            } else {
                1.0 - self.confidence
            }
            .clamp(0.0, 1.0);
    }

    /// Calculate how well evidence items correlate with each other
    fn calculate_correlation(&self) -> f32 {
        if self.evidence_chain.len() < 2 {
            return 0.5; // Neutral for single evidence
        }

        let mut correlation_score = 0.0;
        let mut comparisons = 0;

        // Check for temporal correlation (evidence close in time)
        for i in 0..self.evidence_chain.len() {
            for j in (i + 1)..self.evidence_chain.len() {
                let time_diff = self.evidence_chain[j]
                    .timestamp
                    .duration_since(self.evidence_chain[i].timestamp)
                    .unwrap_or_default()
                    .as_secs();

                // Evidence within 60 seconds is highly correlated
                let temporal_correlation = if time_diff < 5 {
                    1.0
                } else if time_diff < 30 {
                    0.8
                } else if time_diff < 60 {
                    0.6
                } else if time_diff < 300 {
                    0.4
                } else {
                    0.2
                };

                correlation_score += temporal_correlation;
                comparisons += 1;
            }
        }

        // Check for source diversity (different sources = better correlation)
        let diversity_factor = (self.source_diversity as f32 / 5.0).min(1.0);

        let base_correlation = if comparisons > 0 {
            correlation_score / comparisons as f32
        } else {
            0.5
        };

        ((base_correlation * 0.7) + (diversity_factor * 0.3)).clamp(0.0, 1.0)
    }

    /// Get confidence level as a label
    pub fn confidence_label(&self) -> &'static str {
        match (self.confidence * 100.0) as u8 {
            90..=100 => "Very High",
            75..=89 => "High",
            60..=74 => "Medium",
            40..=59 => "Low",
            _ => "Very Low",
        }
    }

    /// Get false positive risk level
    pub fn fp_risk_label(&self) -> &'static str {
        match (self.false_positive_likelihood * 100.0) as u8 {
            0..=10 => "Very Low",
            11..=25 => "Low",
            26..=50 => "Medium",
            51..=75 => "High",
            _ => "Very High",
        }
    }

    /// Generate a human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "{} ({}) - Confidence: {:.0}% ({}), FP Risk: {} ({:.0}%), Sources: {}",
            self.technique_id,
            self.technique_name,
            self.confidence * 100.0,
            self.confidence_label(),
            self.fp_risk_label(),
            self.false_positive_likelihood * 100.0,
            self.source_diversity
        )
    }
}

/// Builder for creating detection evidence
pub struct EvidenceBuilder {
    technique_id: String,
    technique_name: String,
    evidence_items: Vec<EvidenceItem>,
}

impl EvidenceBuilder {
    pub fn new(technique_id: impl Into<String>, technique_name: impl Into<String>) -> Self {
        Self {
            technique_id: technique_id.into(),
            technique_name: technique_name.into(),
            evidence_items: Vec::new(),
        }
    }

    pub fn add_evidence(mut self, evidence: EvidenceItem) -> Self {
        self.evidence_items.push(evidence);
        self
    }

    pub fn add_static_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Static,
            description.into(),
        ))
    }

    pub fn add_dynamic_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Dynamic,
            description.into(),
        ))
    }

    pub fn add_behavioral_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Behavioral,
            description.into(),
        ))
    }

    pub fn add_network_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Network,
            description.into(),
        ))
    }

    pub fn add_process_tree_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::ProcessTree,
            description.into(),
        ))
    }

    pub fn add_registry_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Registry,
            description.into(),
        ))
    }

    pub fn add_hypervisor_evidence(self, description: impl Into<String>) -> Self {
        self.add_evidence(EvidenceItem::new(
            EvidenceSource::Hypervisor,
            description.into(),
        ))
    }

    pub fn build(self) -> DetectionEvidence {
        let mut evidence = DetectionEvidence::new(self.technique_id, self.technique_name);
        for item in self.evidence_items {
            evidence.add_evidence(item);
        }
        evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_builder() {
        let evidence = EvidenceBuilder::new("T1059.001", "PowerShell Execution")
            .add_process_tree_evidence("Parent: winword.exe")
            .add_behavioral_evidence("PowerShell with -enc flag")
            .add_network_evidence("Connection after execution")
            .build();

        assert_eq!(evidence.technique_id, "T1059.001");
        assert_eq!(evidence.evidence_chain.len(), 3);
        assert_eq!(evidence.source_diversity, 3);
        assert!(evidence.confidence > 0.5);
    }

    #[test]
    fn test_confidence_calculation() {
        let mut evidence =
            DetectionEvidence::new("T1055".to_string(), "Process Injection".to_string());

        // Single weak evidence
        evidence.add_evidence(EvidenceItem::new(
            EvidenceSource::Static,
            "Suspicious import".to_string(),
        ));
        assert!(evidence.confidence < 0.6);

        // Add strong behavioral evidence
        evidence.add_evidence(EvidenceItem::new(
            EvidenceSource::Behavioral,
            "VirtualAlloc + WriteProcessMemory + CreateRemoteThread".to_string(),
        ));
        assert!(evidence.confidence > 0.7);

        // Add network evidence
        evidence.add_evidence(EvidenceItem::new(
            EvidenceSource::Network,
            "C2 connection after injection".to_string(),
        ));
        assert!(evidence.confidence > 0.8);
    }

    #[test]
    fn test_source_weights() {
        assert!(EvidenceSource::Rootkit.base_weight() > EvidenceSource::Static.base_weight());
        assert!(EvidenceSource::Behavioral.base_weight() > EvidenceSource::Yara.base_weight());
        assert!(
            EvidenceSource::Hypervisor.base_weight() > EvidenceSource::FileSystem.base_weight()
        );
    }
}
