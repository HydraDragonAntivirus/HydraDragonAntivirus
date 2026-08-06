//! ATT&CK Coverage Heatmap Generator
//!
//! Generates visual heatmap of detection coverage across MITRE ATT&CK techniques

use super::coverage_analyzer::CoverageAnalysis;

/// Heatmap generator for coverage visualization
pub struct CoverageHeatmap;

impl CoverageHeatmap {
    /// Generate HTML heatmap visualization
    pub fn to_html(analysis: &CoverageAnalysis) -> String {
        let mut html = String::new();

        html.push_str(
            r#"
<div class="coverage-heatmap-container">
    <h2>🎯 MITRE ATT&CK Coverage Analysis</h2>
    
    <div class="coverage-summary">
        <div class="summary-card">
            <div class="summary-value">"#,
        );
        html.push_str(&format!("{}", analysis.total_techniques));
        html.push_str(
            r#"</div>
            <div class="summary-label">Total Techniques</div>
        </div>
        <div class="summary-card strong">
            <div class="summary-value">"#,
        );
        html.push_str(&format!("{}", analysis.strong_coverage));
        html.push_str(
            r#"</div>
            <div class="summary-label">Strong Coverage</div>
        </div>
        <div class="summary-card medium">
            <div class="summary-value">"#,
        );
        html.push_str(&format!("{}", analysis.medium_coverage));
        html.push_str(
            r#"</div>
            <div class="summary-label">Medium Coverage</div>
        </div>
        <div class="summary-card weak">
            <div class="summary-value">"#,
        );
        html.push_str(&format!("{}", analysis.weak_coverage));
        html.push_str(
            r#"</div>
            <div class="summary-label">Weak Coverage</div>
        </div>
        <div class="summary-card none">
            <div class="summary-value">"#,
        );
        html.push_str(&format!("{}", analysis.no_coverage));
        html.push_str(
            r#"</div>
            <div class="summary-label">No Coverage</div>
        </div>
    </div>

    <h3>Coverage by Tactic</h3>
    <div class="tactic-coverage">
"#,
        );

        // Sort tactics by coverage percentage
        let mut tactics: Vec<_> = analysis.coverage_by_tactic.values().collect();
        tactics.sort_by(|a, b| {
            b.coverage_percentage()
                .partial_cmp(&a.coverage_percentage())
                .unwrap()
        });

        for tactic in tactics {
            let coverage_pct = tactic.coverage_percentage();
            let color = if coverage_pct >= 75.0 {
                "#27ae60"
            } else if coverage_pct >= 50.0 {
                "#f39c12"
            } else if coverage_pct >= 25.0 {
                "#e67e22"
            } else {
                "#e74c3c"
            };

            html.push_str(&format!(
                r#"
        <div class="tactic-row">
            <div class="tactic-name">{}</div>
            <div class="tactic-bar">
                <div class="tactic-fill" style="width: {}%; background-color: {};"></div>
            </div>
            <div class="tactic-stats">
                <span class="stat-strong">{}</span>
                <span class="stat-medium">{}</span>
                <span class="stat-weak">{}</span>
                <span class="stat-none">{}</span>
            </div>
            <div class="tactic-percentage">{:.1}%</div>
        </div>
"#,
                tactic.tactic_name,
                coverage_pct,
                color,
                tactic.strong,
                tactic.medium,
                tactic.weak,
                tactic.none,
                coverage_pct
            ));
        }

        html.push_str(
            r#"
    </div>

    <h3>Technique Details</h3>
    <div class="technique-grid">
"#,
        );

        // Group techniques by tactic
        let mut techniques_by_tactic: std::collections::HashMap<String, Vec<_>> =
            std::collections::HashMap::new();
        for tech in &analysis.technique_coverage {
            techniques_by_tactic
                .entry(tech.tactic.clone())
                .or_insert_with(Vec::new)
                .push(tech);
        }

        for (tactic, techniques) in techniques_by_tactic {
            html.push_str(&format!(
                r#"
        <div class="tactic-section">
            <h4>{}</h4>
            <div class="technique-list">
"#,
                tactic
            ));

            for tech in techniques {
                html.push_str(&format!(
                    r#"
                <div class="technique-item" style="border-left: 4px solid {};">
                    <div class="technique-id">{}</div>
                    <div class="technique-name">{}</div>
                    <div class="technique-coverage">{} ({}/3)</div>
                    <div class="technique-sources">{}</div>
                </div>
"#,
                    tech.coverage_level.color(),
                    tech.technique_id,
                    tech.technique_name,
                    tech.coverage_level.label(),
                    tech.coverage_level.score(),
                    tech.detection_sources.join(", ")
                ));
            }

            html.push_str(
                r#"
            </div>
        </div>
"#,
            );
        }

        html.push_str(
            r#"
    </div>
</div>
"#,
        );

        html
    }

    /// Get CSS for heatmap visualization
    pub fn get_css() -> &'static str {
        r#"
.coverage-heatmap-container {
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
    margin: 20px 0;
}

.coverage-heatmap-container h2 {
    color: #2c3e50;
    margin-bottom: 20px;
}

.coverage-summary {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 15px;
    margin-bottom: 30px;
}

.summary-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    text-align: center;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    border-left: 4px solid #3498db;
}

.summary-card.strong {
    border-left-color: #27ae60;
}

.summary-card.medium {
    border-left-color: #f39c12;
}

.summary-card.weak {
    border-left-color: #e67e22;
}

.summary-card.none {
    border-left-color: #95a5a6;
}

.summary-value {
    font-size: 36px;
    font-weight: bold;
    color: #2c3e50;
}

.summary-label {
    font-size: 14px;
    color: #7f8c8d;
    margin-top: 5px;
}

.tactic-coverage {
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 30px;
}

.tactic-row {
    display: grid;
    grid-template-columns: 200px 1fr 150px 80px;
    gap: 15px;
    align-items: center;
    padding: 10px 0;
    border-bottom: 1px solid #ecf0f1;
}

.tactic-name {
    font-weight: bold;
    color: #2c3e50;
}

.tactic-bar {
    height: 30px;
    background: #ecf0f1;
    border-radius: 15px;
    overflow: hidden;
}

.tactic-fill {
    height: 100%;
    transition: width 0.3s ease;
}

.tactic-stats {
    display: flex;
    gap: 8px;
    font-size: 12px;
}

.tactic-stats span {
    padding: 4px 8px;
    border-radius: 4px;
    font-weight: bold;
}

.stat-strong {
    background: #27ae60;
    color: white;
}

.stat-medium {
    background: #f39c12;
    color: white;
}

.stat-weak {
    background: #e67e22;
    color: white;
}

.stat-none {
    background: #95a5a6;
    color: white;
}

.tactic-percentage {
    font-weight: bold;
    color: #2c3e50;
    text-align: right;
}

.technique-grid {
    display: grid;
    gap: 20px;
}

.tactic-section {
    background: white;
    padding: 20px;
    border-radius: 8px;
}

.tactic-section h4 {
    color: #2c3e50;
    margin-bottom: 15px;
}

.technique-list {
    display: grid;
    gap: 10px;
}

.technique-item {
    display: grid;
    grid-template-columns: 100px 1fr 100px 200px;
    gap: 15px;
    padding: 12px;
    background: #f8f9fa;
    border-radius: 6px;
    align-items: center;
}

.technique-id {
    font-weight: bold;
    color: #3498db;
    font-family: monospace;
}

.technique-name {
    color: #2c3e50;
}

.technique-coverage {
    font-size: 12px;
    font-weight: bold;
    text-align: center;
}

.technique-sources {
    font-size: 11px;
    color: #7f8c8d;
}

@media (max-width: 768px) {
    .tactic-row {
        grid-template-columns: 1fr;
        gap: 10px;
    }
    
    .technique-item {
        grid-template-columns: 1fr;
        gap: 8px;
    }
}
"#
    }

    /// Generate JSON export of coverage data
    pub fn to_json(analysis: &CoverageAnalysis) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(analysis)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitre_attack::coverage_analyzer::{CoverageAnalysis, TacticCoverage};
    use std::collections::HashMap;

    #[test]
    fn test_heatmap_generation() {
        let mut coverage_by_tactic = HashMap::new();
        coverage_by_tactic.insert(
            "Execution".to_string(),
            TacticCoverage {
                tactic_name: "Execution".to_string(),
                total_techniques: 10,
                strong: 5,
                medium: 3,
                weak: 2,
                none: 0,
            },
        );

        let analysis = CoverageAnalysis {
            total_techniques: 10,
            strong_coverage: 5,
            medium_coverage: 3,
            weak_coverage: 2,
            no_coverage: 0,
            coverage_by_tactic,
            technique_coverage: Vec::new(),
        };

        let html = CoverageHeatmap::to_html(&analysis);
        assert!(html.contains("Coverage Analysis"));
        assert!(html.contains("Execution"));
    }
}
