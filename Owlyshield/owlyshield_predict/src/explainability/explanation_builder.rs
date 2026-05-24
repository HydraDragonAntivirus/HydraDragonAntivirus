//! Rule Explainability System
//!
//! Generates human-readable explanations for why files were flagged

use serde::{Deserialize, Serialize};

/// Explanation for a detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionExplanation {
    pub summary: String,
    pub detailed_reasons: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub recommended_action: String,
    pub analyst_notes: Option<String>,
    pub severity_explanation: String,
}

/// Explanation builder
pub struct ExplanationBuilder {
    reasons: Vec<String>,
    techniques: Vec<String>,
    severity: String,
}

impl ExplanationBuilder {
    pub fn new() -> Self {
        Self {
            reasons: Vec::new(),
            techniques: Vec::new(),
            severity: "Unknown".to_string(),
        }
    }

    pub fn add_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }

    pub fn add_technique(mut self, technique: impl Into<String>) -> Self {
        self.techniques.push(technique.into());
        self
    }

    pub fn set_severity(mut self, severity: impl Into<String>) -> Self {
        self.severity = severity.into();
        self
    }

    pub fn build(self) -> DetectionExplanation {
        let summary = self.generate_summary();
        let recommended_action = self.generate_recommendation();
        let severity_explanation = self.generate_severity_explanation();

        DetectionExplanation {
            summary,
            detailed_reasons: self.reasons,
            mitre_techniques: self.techniques,
            recommended_action,
            analyst_notes: None,
            severity_explanation,
        }
    }

    fn generate_summary(&self) -> String {
        if self.reasons.is_empty() {
            return "This file was flagged as suspicious.".to_string();
        }

        format!(
            "HydraDragon flagged this file because it exhibits {} suspicious behaviors.",
            self.reasons.len()
        )
    }

    fn generate_recommendation(&self) -> String {
        match self.severity.as_str() {
            "Critical" | "High" => "Quarantine immediately and investigate".to_string(),
            "Medium" => "Review and monitor closely".to_string(),
            "Low" => "Monitor for additional suspicious activity".to_string(),
            _ => "Review manually".to_string(),
        }
    }

    fn generate_severity_explanation(&self) -> String {
        match self.severity.as_str() {
            "Critical" => {
                "This file shows clear signs of malicious intent with high confidence.".to_string()
            }
            "High" => "This file exhibits multiple indicators of malicious behavior.".to_string(),
            "Medium" => {
                "This file shows some suspicious characteristics that warrant investigation."
                    .to_string()
            }
            "Low" => "This file has minor suspicious indicators.".to_string(),
            _ => "Severity assessment pending.".to_string(),
        }
    }
}

impl Default for ExplanationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionExplanation {
    /// Generate HTML explanation
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(
            r#"
<div class="explanation-container">
    <h3>🔍 Why Was This Flagged?</h3>
    
    <div class="explanation-summary">
        <p>"#,
        );
        html.push_str(&self.summary);
        html.push_str(
            r#"</p>
    </div>

    <div class="explanation-reasons">
        <h4>Detailed Reasons:</h4>
        <ol>
"#,
        );

        for reason in &self.detailed_reasons {
            html.push_str(&format!("<li>{}</li>\n", reason));
        }

        html.push_str(
            r#"
        </ol>
    </div>
"#,
        );

        if !self.mitre_techniques.is_empty() {
            html.push_str(
                r#"
    <div class="explanation-techniques">
        <h4>This behavior matches these ATT&CK techniques:</h4>
        <ul>
"#,
            );

            for tech in &self.mitre_techniques {
                html.push_str(&format!("<li>{}</li>\n", tech));
            }

            html.push_str(
                r#"
        </ul>
    </div>
"#,
            );
        }

        html.push_str(
            r#"
    <div class="explanation-action">
        <h4>Recommended Action:</h4>
        <p class="action-text">"#,
        );
        html.push_str(&self.recommended_action);
        html.push_str(
            r#"</p>
    </div>

    <div class="explanation-severity">
        <p><strong>Severity Explanation:</strong> "#,
        );
        html.push_str(&self.severity_explanation);
        html.push_str(
            r#"</p>
    </div>
</div>
"#,
        );

        html
    }

    /// Get CSS for explanation display
    pub fn get_css() -> &'static str {
        r#"
.explanation-container {
    background: #fff3cd;
    border: 1px solid #ffc107;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
}

.explanation-container h3 {
    color: #856404;
    margin-top: 0;
}

.explanation-summary {
    background: white;
    padding: 15px;
    border-radius: 6px;
    margin: 15px 0;
}

.explanation-reasons {
    margin: 20px 0;
}

.explanation-reasons ol {
    padding-left: 25px;
}

.explanation-reasons li {
    margin: 8px 0;
    color: #333;
}

.explanation-techniques {
    background: #e7f3ff;
    padding: 15px;
    border-radius: 6px;
    margin: 15px 0;
}

.explanation-techniques ul {
    padding-left: 25px;
    margin: 10px 0;
}

.explanation-action {
    background: #d4edda;
    border: 1px solid #c3e6cb;
    padding: 15px;
    border-radius: 6px;
    margin: 15px 0;
}

.action-text {
    font-weight: bold;
    color: #155724;
    margin: 0;
}

.explanation-severity {
    font-size: 14px;
    color: #666;
    margin-top: 15px;
}
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explanation_builder() {
        let explanation = ExplanationBuilder::new()
            .add_reason("Launches PowerShell with encoded arguments")
            .add_reason("Creates persistence in Run key")
            .add_technique("T1059.001 - PowerShell Execution")
            .add_technique("T1547.001 - Registry Run Keys")
            .set_severity("High")
            .build();

        assert_eq!(explanation.detailed_reasons.len(), 2);
        assert_eq!(explanation.mitre_techniques.len(), 2);
        assert!(explanation.summary.contains("2 suspicious behaviors"));
    }
}
