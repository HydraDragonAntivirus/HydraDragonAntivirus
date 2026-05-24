//! Enhanced Confidence Scoring
//!
//! Advanced confidence calculation with ML integration

use super::evidence_types::DetectionEvidence;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Confidence breakdown showing how score was calculated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBreakdown {
    pub technique_id: String,
    pub base_score: f32,
    pub diversity_bonus: f32,
    pub quantity_bonus: f32,
    pub correlation_bonus: f32,
    pub historical_adjustment: f32,
    pub final_confidence: f32,
    pub factors: Vec<String>,
}

/// Enhanced confidence scorer
pub struct EnhancedConfidenceScorer {
    historical_accuracy: HashMap<String, f32>,
}

impl EnhancedConfidenceScorer {
    pub fn new() -> Self {
        Self {
            historical_accuracy: HashMap::new(),
        }
    }

    /// Calculate enhanced confidence with detailed breakdown
    pub fn calculate_confidence(&self, evidence: &DetectionEvidence) -> ConfidenceBreakdown {
        let base_score = self.calculate_base_score(evidence);
        let diversity_bonus = self.calculate_diversity_bonus(evidence);
        let quantity_bonus = self.calculate_quantity_bonus(evidence);
        let correlation_bonus = evidence.correlation_score * 0.15;
        let historical_adjustment = self.get_historical_adjustment(&evidence.technique_id);

        let final_confidence = (base_score
            + diversity_bonus
            + quantity_bonus
            + correlation_bonus
            + historical_adjustment)
            .min(1.0)
            .max(0.0);

        let factors = self.identify_confidence_factors(evidence);

        ConfidenceBreakdown {
            technique_id: evidence.technique_id.clone(),
            base_score,
            diversity_bonus,
            quantity_bonus,
            correlation_bonus,
            historical_adjustment,
            final_confidence,
            factors,
        }
    }

    fn calculate_base_score(&self, evidence: &DetectionEvidence) -> f32 {
        if evidence.evidence_chain.is_empty() {
            return 0.0;
        }

        let total_weight: f32 = evidence.evidence_chain.iter().map(|e| e.weight).sum();
        let count = evidence.evidence_chain.len() as f32;
        (total_weight / count).min(1.0)
    }

    fn calculate_diversity_bonus(&self, evidence: &DetectionEvidence) -> f32 {
        match evidence.source_diversity {
            0..=1 => 0.0,
            2 => 0.05,
            3 => 0.10,
            4 => 0.15,
            _ => 0.20,
        }
    }

    fn calculate_quantity_bonus(&self, evidence: &DetectionEvidence) -> f32 {
        match evidence.evidence_chain.len() {
            0..=1 => 0.0,
            2..=3 => 0.05,
            4..=6 => 0.10,
            _ => 0.15,
        }
    }

    fn get_historical_adjustment(&self, technique_id: &str) -> f32 {
        self.historical_accuracy
            .get(technique_id)
            .copied()
            .unwrap_or(0.0)
    }

    fn identify_confidence_factors(&self, evidence: &DetectionEvidence) -> Vec<String> {
        let mut factors = Vec::new();

        if evidence.source_diversity >= 3 {
            factors.push("Multiple independent sources".to_string());
        }

        if evidence.correlation_score > 0.8 {
            factors.push("Strong temporal correlation".to_string());
        }

        if evidence.false_positive_likelihood < 0.1 {
            factors.push("Low false positive risk".to_string());
        }

        if evidence.evidence_chain.len() >= 4 {
            factors.push("Multiple evidence items".to_string());
        }

        factors
    }

    /// Update historical accuracy based on feedback
    pub fn update_historical_accuracy(&mut self, technique_id: String, accuracy: f32) {
        self.historical_accuracy.insert(technique_id, accuracy);
    }
}

impl Default for EnhancedConfidenceScorer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitre_attack::evidence_types::EvidenceBuilder;

    #[test]
    fn test_confidence_calculation() {
        let evidence = EvidenceBuilder::new("T1055", "Process Injection")
            .add_behavioral_evidence("VirtualAlloc called")
            .add_behavioral_evidence("WriteProcessMemory called")
            .add_hypervisor_evidence("Memory manipulation detected")
            .build();

        let scorer = EnhancedConfidenceScorer::new();
        let breakdown = scorer.calculate_confidence(&evidence);

        assert!(breakdown.final_confidence > 0.7);
        assert!(breakdown.diversity_bonus > 0.0);
    }
}
