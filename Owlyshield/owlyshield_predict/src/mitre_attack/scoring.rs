//! Threat Scoring Engine
//!
//! Provides a scoring system similar to Triage for threat assessment

use super::technique_mapping::MitreTechnique;
use super::timeline::{AttackTimeline, EventSeverity};
use serde::{Deserialize, Serialize};

/// Overall threat score for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatScore {
    pub total_score: u32,
    pub normalized_score: f32, // 0.0 - 10.0 scale
    pub threat_level: ThreatLevel,
    pub confidence: f32, // 0.0 - 1.0
    pub category_scores: CategoryScores,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Benign,
    Suspicious,
    Malicious,
    Critical,
}

impl ThreatLevel {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s < 3.0 => ThreatLevel::Benign,
            s if s < 5.0 => ThreatLevel::Suspicious,
            s if s < 8.0 => ThreatLevel::Malicious,
            _ => ThreatLevel::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ThreatLevel::Benign => "Benign",
            ThreatLevel::Suspicious => "Suspicious",
            ThreatLevel::Malicious => "Malicious",
            ThreatLevel::Critical => "Critical",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            ThreatLevel::Benign => "#2ecc71",
            ThreatLevel::Suspicious => "#f39c12",
            ThreatLevel::Malicious => "#e67e22",
            ThreatLevel::Critical => "#e74c3c",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScores {
    pub defense_evasion: u32,
    pub persistence: u32,
    pub credential_access: u32,
    pub discovery: u32,
    pub collection: u32,
    pub command_and_control: u32,
    pub exfiltration: u32,
    pub impact: u32,
    pub execution: u32,
    pub privilege_escalation: u32,
}

impl Default for CategoryScores {
    fn default() -> Self {
        CategoryScores {
            defense_evasion: 0,
            persistence: 0,
            credential_access: 0,
            discovery: 0,
            collection: 0,
            command_and_control: 0,
            exfiltration: 0,
            impact: 0,
            execution: 0,
            privilege_escalation: 0,
        }
    }
}

impl CategoryScores {
    fn add_technique(&mut self, technique: &MitreTechnique) {
        let score = technique.severity as u32;
        match technique.tactic.as_str() {
            "Defense Evasion" => self.defense_evasion += score,
            "Persistence" => self.persistence += score,
            "Credential Access" => self.credential_access += score,
            "Discovery" => self.discovery += score,
            "Collection" => self.collection += score,
            "Command and Control" => self.command_and_control += score,
            "Exfiltration" => self.exfiltration += score,
            "Impact" => self.impact += score,
            "Execution" => self.execution += score,
            "Privilege Escalation" => self.privilege_escalation += score,
            _ => {}
        }
    }

    pub fn total(&self) -> u32 {
        self.defense_evasion
            + self.persistence
            + self.credential_access
            + self.discovery
            + self.collection
            + self.command_and_control
            + self.exfiltration
            + self.impact
            + self.execution
            + self.privilege_escalation
    }

    pub fn highest_category(&self) -> (&'static str, u32) {
        let categories = vec![
            ("Defense Evasion", self.defense_evasion),
            ("Persistence", self.persistence),
            ("Credential Access", self.credential_access),
            ("Discovery", self.discovery),
            ("Collection", self.collection),
            ("Command and Control", self.command_and_control),
            ("Exfiltration", self.exfiltration),
            ("Impact", self.impact),
            ("Execution", self.execution),
            ("Privilege Escalation", self.privilege_escalation),
        ];

        categories
            .into_iter()
            .max_by_key(|(_, score)| *score)
            .unwrap_or(("Unknown", 0))
    }
}

pub struct ScoringEngine;

impl ScoringEngine {
    /// Calculate threat score from attack timeline
    pub fn calculate_score(timeline: &AttackTimeline) -> ThreatScore {
        let mut category_scores = CategoryScores::default();
        let mut total_score = 0u32;
        let mut high_severity_count = 0;
        let mut critical_severity_count = 0;

        // Analyze all events and techniques
        for event in &timeline.events {
            // Count severity levels
            match event.severity {
                EventSeverity::High => high_severity_count += 1,
                EventSeverity::Critical => critical_severity_count += 1,
                _ => {}
            }

            // Add technique scores
            for technique in &event.mitre_techniques {
                category_scores.add_technique(technique);
                total_score += technique.severity as u32;
            }
        }

        // Calculate normalized score (0-10 scale)
        let normalized_score = if timeline.events.is_empty() {
            0.0
        } else {
            // Base score from techniques
            let base_score = (total_score as f32 / 10.0).min(8.0);

            // Bonus for multiple high/critical events
            let severity_bonus =
                (high_severity_count as f32 * 0.2) + (critical_severity_count as f32 * 0.5);

            // Bonus for diverse tactics (indicates sophisticated attack)
            let unique_tactics = timeline.get_tactics_summary().len();
            let diversity_bonus = if unique_tactics > 3 {
                (unique_tactics as f32 - 3.0) * 0.3
            } else {
                0.0
            };

            (base_score + severity_bonus + diversity_bonus).min(10.0)
        };

        // Determine threat level
        let threat_level = ThreatLevel::from_score(normalized_score);

        // Calculate confidence based on number of indicators
        let confidence = if timeline.events.len() < 3 {
            0.5
        } else if timeline.events.len() < 10 {
            0.7
        } else {
            0.9
        };

        ThreatScore {
            total_score,
            normalized_score,
            threat_level,
            confidence,
            category_scores,
        }
    }

    /// Generate a detailed scoring report
    pub fn generate_report(timeline: &AttackTimeline, score: &ThreatScore) -> String {
        let mut report = String::new();

        report.push_str(&format!("=== Threat Assessment Report ===\n\n"));
        report.push_str(&format!("Process: {}\n", timeline.process_name));
        report.push_str(&format!("Path: {}\n", timeline.process_path));
        report.push_str(&format!("GID: {}\n\n", timeline.gid));

        report.push_str(&format!(
            "Overall Threat Level: {} (Score: {:.2}/10.0)\n",
            score.threat_level.label(),
            score.normalized_score
        ));
        report.push_str(&format!("Confidence: {:.0}%\n\n", score.confidence * 100.0));

        report.push_str("Category Breakdown:\n");
        let categories = vec![
            ("Defense Evasion", score.category_scores.defense_evasion),
            ("Persistence", score.category_scores.persistence),
            ("Credential Access", score.category_scores.credential_access),
            ("Discovery", score.category_scores.discovery),
            ("Collection", score.category_scores.collection),
            (
                "Command and Control",
                score.category_scores.command_and_control,
            ),
            ("Exfiltration", score.category_scores.exfiltration),
            ("Impact", score.category_scores.impact),
            ("Execution", score.category_scores.execution),
            (
                "Privilege Escalation",
                score.category_scores.privilege_escalation,
            ),
        ];

        for (name, score_val) in categories {
            if score_val > 0 {
                report.push_str(&format!("  - {}: {}\n", name, score_val));
            }
        }

        let (highest_cat, highest_score) = score.category_scores.highest_category();
        report.push_str(&format!(
            "\nPrimary Threat Category: {} ({})\n\n",
            highest_cat, highest_score
        ));

        report.push_str(&format!("Total Events: {}\n", timeline.events.len()));
        report.push_str(&format!(
            "Unique Techniques: {}\n",
            timeline.get_unique_techniques().len()
        ));
        report.push_str(&format!(
            "Max Event Severity: {}\n\n",
            timeline.max_severity.label()
        ));

        // List unique techniques
        report.push_str("MITRE ATT&CK Techniques Observed:\n");
        for technique in timeline.get_unique_techniques() {
            report.push_str(&format!(
                "  - {} ({}): {}\n",
                technique.id, technique.name, technique.tactic
            ));
        }

        report
    }

    /// Generate HTML scoring visualization
    pub fn to_html(timeline: &AttackTimeline, score: &ThreatScore) -> String {
        let mut html = String::new();

        html.push_str(&format!(
            r#"<div class="threat-score-card" style="border-left: 5px solid {}">
    <div class="score-header">
        <h3>Threat Assessment</h3>
        <div class="threat-level" style="background-color: {}; color: white;">
            {}
        </div>
    </div>
    <div class="score-main">
        <div class="score-value">{:.1}</div>
        <div class="score-label">Threat Score (out of 10)</div>
        <div class="confidence-bar">
            <div class="confidence-fill" style="width: {}%; background-color: {}"></div>
        </div>
        <div class="confidence-label">Confidence: {:.0}%</div>
    </div>
    <div class="score-categories">
        <h4>Category Breakdown</h4>
"#,
            score.threat_level.color(),
            score.threat_level.color(),
            score.threat_level.label(),
            score.normalized_score,
            score.confidence * 100.0,
            score.threat_level.color(),
            score.confidence * 100.0
        ));

        // Category bars
        let max_category_score = score.category_scores.total().max(1);
        let categories = vec![
            ("Defense Evasion", score.category_scores.defense_evasion),
            ("Persistence", score.category_scores.persistence),
            ("Credential Access", score.category_scores.credential_access),
            ("Discovery", score.category_scores.discovery),
            ("Collection", score.category_scores.collection),
            (
                "Command & Control",
                score.category_scores.command_and_control,
            ),
            ("Exfiltration", score.category_scores.exfiltration),
            ("Impact", score.category_scores.impact),
            ("Execution", score.category_scores.execution),
            (
                "Privilege Escalation",
                score.category_scores.privilege_escalation,
            ),
        ];

        for (name, cat_score) in categories {
            if cat_score > 0 {
                let percentage = (cat_score as f32 / max_category_score as f32) * 100.0;
                html.push_str(&format!(
                    r#"        <div class="category-item">
            <span class="category-name">{}</span>
            <div class="category-bar">
                <div class="category-fill" style="width: {}%"></div>
            </div>
            <span class="category-score">{}</span>
        </div>
"#,
                    name, percentage, cat_score
                ));
            }
        }

        html.push_str("    </div>\n");

        // Statistics
        html.push_str(&format!(
            r#"    <div class="score-stats">
        <div class="stat-item">
            <span class="stat-value">{}</span>
            <span class="stat-label">Events</span>
        </div>
        <div class="stat-item">
            <span class="stat-value">{}</span>
            <span class="stat-label">Techniques</span>
        </div>
        <div class="stat-item">
            <span class="stat-value">{}</span>
            <span class="stat-label">Tactics</span>
        </div>
    </div>
</div>
"#,
            timeline.events.len(),
            timeline.get_unique_techniques().len(),
            timeline.get_tactics_summary().len()
        ));

        html
    }

    /// Get CSS for scoring visualization
    pub fn get_scoring_css() -> &'static str {
        r#"
.threat-score-card {
    background: white;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.score-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
}

.score-header h3 {
    margin: 0;
    color: #2c3e50;
}

.threat-level {
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 14px;
}

.score-main {
    text-align: center;
    padding: 20px 0;
    border-bottom: 1px solid #eee;
}

.score-value {
    font-size: 48px;
    font-weight: bold;
    color: #2c3e50;
}

.score-label {
    color: #7f8c8d;
    margin-bottom: 15px;
}

.confidence-bar {
    width: 100%;
    height: 8px;
    background: #ecf0f1;
    border-radius: 4px;
    overflow: hidden;
    margin: 10px 0;
}

.confidence-fill {
    height: 100%;
    transition: width 0.3s ease;
}

.confidence-label {
    font-size: 12px;
    color: #7f8c8d;
}

.score-categories {
    padding: 20px 0;
    border-bottom: 1px solid #eee;
}

.score-categories h4 {
    margin: 0 0 15px 0;
    color: #2c3e50;
}

.category-item {
    display: flex;
    align-items: center;
    margin: 10px 0;
    gap: 10px;
}

.category-name {
    flex: 0 0 150px;
    font-size: 13px;
    color: #555;
}

.category-bar {
    flex: 1;
    height: 20px;
    background: #ecf0f1;
    border-radius: 10px;
    overflow: hidden;
}

.category-fill {
    height: 100%;
    background: linear-gradient(90deg, #3498db, #2980b9);
    transition: width 0.3s ease;
}

.category-score {
    flex: 0 0 40px;
    text-align: right;
    font-weight: bold;
    color: #2c3e50;
}

.score-stats {
    display: flex;
    justify-content: space-around;
    padding: 20px 0 0 0;
}

.stat-item {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.stat-value {
    font-size: 24px;
    font-weight: bold;
    color: #3498db;
}

.stat-label {
    font-size: 12px;
    color: #7f8c8d;
    margin-top: 5px;
}
"#
    }
}
