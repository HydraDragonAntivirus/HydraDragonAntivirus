//! Detection Evidence Engine
//!
//! Builds evidence chains for MITRE ATT&CK technique detections,
//! transforming raw telemetry into explainable, confidence-scored alerts.

use super::evidence_types::*;
use super::technique_mapping::MitreTechnique;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Complete detection report with evidence chains for all detected techniques
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionReport {
    /// Process information
    pub process_name: String,
    pub process_path: String,
    pub pid: u32,
    pub gid: u64,

    /// All detected techniques with evidence
    pub detections: Vec<DetectionEvidence>,

    /// Overall threat assessment
    pub overall_confidence: f32,
    pub threat_level: ThreatLevel,
    pub primary_tactic: String,

    /// Metadata
    pub detection_timestamp: SystemTime,
    pub analysis_duration_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ThreatLevel {
    Benign,
    Suspicious,
    Malicious,
    Critical,
}

impl ThreatLevel {
    pub fn from_confidence(confidence: f32) -> Self {
        match (confidence * 100.0) as u8 {
            0..=30 => ThreatLevel::Benign,
            31..=60 => ThreatLevel::Suspicious,
            61..=85 => ThreatLevel::Malicious,
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

impl DetectionReport {
    /// Generate a human-readable text report
    pub fn to_text(&self) -> String {
        let mut report = String::new();

        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str("           HYDRADRAGON DETECTION EVIDENCE REPORT\n");
        report.push_str("═══════════════════════════════════════════════════════════════\n\n");

        report.push_str(&format!("Process: {}\n", self.process_name));
        report.push_str(&format!("Path: {}\n", self.process_path));
        report.push_str(&format!("PID: {} | GID: {}\n\n", self.pid, self.gid));

        report.push_str(&format!(
            "Threat Level: {} (Confidence: {:.0}%)\n",
            self.threat_level.label(),
            self.overall_confidence * 100.0
        ));
        report.push_str(&format!("Primary Tactic: {}\n", self.primary_tactic));
        report.push_str(&format!(
            "Techniques Detected: {}\n\n",
            self.detections.len()
        ));

        report.push_str("───────────────────────────────────────────────────────────────\n");
        report.push_str("                    DETECTION DETAILS\n");
        report.push_str("───────────────────────────────────────────────────────────────\n\n");

        for (idx, detection) in self.detections.iter().enumerate() {
            report.push_str(&format!("{}. {}\n\n", idx + 1, detection.summary()));

            report.push_str("   Evidence Chain:\n");
            for (eidx, evidence) in detection.evidence_chain.iter().enumerate() {
                let marker = if eidx == detection.evidence_chain.len() - 1 {
                    "└─"
                } else {
                    "├─"
                };
                report.push_str(&format!(
                    "   {} [{}] {}\n",
                    marker,
                    evidence.source.label(),
                    evidence.description
                ));

                if let Some(ref context) = evidence.context {
                    let continuation = if eidx == detection.evidence_chain.len() - 1 {
                        "  "
                    } else {
                        "│ "
                    };
                    report.push_str(&format!("   {}    Context: {}\n", continuation, context));
                }

                if let Some(ref raw_data) = evidence.raw_data {
                    report.push_str("         Raw Evidence:\n");
                    for line in raw_data.lines() {
                        report.push_str(&format!("           {}\n", line));
                    }
                }
            }

            report.push_str(&format!(
                "\n   Correlation Score: {:.0}%\n",
                detection.correlation_score * 100.0
            ));
            report.push_str(&format!(
                "   Source Diversity: {} independent sources\n",
                detection.source_diversity
            ));
            report.push_str(&format!(
                "   False Positive Risk: {} ({:.0}%)\n\n",
                detection.fp_risk_label(),
                detection.false_positive_likelihood * 100.0
            ));
        }

        report.push_str("═══════════════════════════════════════════════════════════════\n");
        report.push_str(&format!(
            "Analysis completed in {} ms\n",
            self.analysis_duration_ms
        ));
        report.push_str("═══════════════════════════════════════════════════════════════\n");

        report
    }

    /// Generate an HTML report with styling
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(&format!(
            r#"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>HydraDragon Detection Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .summary {{
            padding: 30px;
            border-bottom: 2px solid #e1e8ed;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        .summary-item {{
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
            border-left: 4px solid #667eea;
        }}
        .summary-label {{
            font-size: 12px;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .summary-value {{
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin-top: 5px;
        }}
        .threat-badge {{
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            background-color: {};
        }}
        .detections {{
            padding: 30px;
        }}
        .detection-card {{
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 5px solid #667eea;
        }}
        .detection-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .technique-id {{
            font-size: 18px;
            font-weight: bold;
            color: #2c3e50;
        }}
        .confidence-badge {{
            padding: 6px 12px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: bold;
            background: #28a745;
            color: white;
        }}
        .evidence-chain {{
            margin-top: 15px;
        }}
        .evidence-item {{
            display: flex;
            align-items: flex-start;
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-radius: 6px;
        }}
        .evidence-icon {{
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #667eea;
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: bold;
            margin-right: 15px;
            flex-shrink: 0;
        }}
        .evidence-content {{
            flex: 1;
        }}
        .evidence-source {{
            font-size: 12px;
            color: #667eea;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .evidence-description {{
            color: #2c3e50;
            margin-top: 5px;
        }}
        .evidence-context {{
            font-size: 12px;
            color: #6c757d;
            margin-top: 5px;
            font-family: 'Courier New', monospace;
            background: #f1f3f5;
            padding: 5px 8px;
            border-radius: 4px;
        }}
        .evidence-raw {{
            margin-top: 8px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }}
        .evidence-raw summary {{
            cursor: pointer;
            color: #495057;
            font-weight: bold;
        }}
        .evidence-raw pre {{
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            margin: 8px 0 0 0;
            padding: 10px;
            background: #111827;
            color: #d1d5db;
            border-radius: 6px;
        }}
        .metrics {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #dee2e6;
        }}
        .metric {{
            text-align: center;
        }}
        .metric-value {{
            font-size: 20px;
            font-weight: bold;
            color: #667eea;
        }}
        .metric-label {{
            font-size: 12px;
            color: #6c757d;
            margin-top: 5px;
        }}
        .footer {{
            padding: 20px 30px;
            background: #f8f9fa;
            text-align: center;
            color: #6c757d;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ HydraDragon Detection Evidence Report</h1>
            <p>Professional EDR-Grade Threat Analysis</p>
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-label">Process</div>
                    <div class="summary-value">{}</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Threat Level</div>
                    <div class="summary-value">
                        <span class="threat-badge">{}</span>
                    </div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Confidence</div>
                    <div class="summary-value">{:.0}%</div>
                </div>
                <div class="summary-item">
                    <div class="summary-label">Techniques</div>
                    <div class="summary-value">{}</div>
                </div>
            </div>
        </div>
        
        <div class="detections">
            <h2>Detection Details</h2>
"#,
            self.threat_level.color(),
            self.process_name,
            self.threat_level.label(),
            self.overall_confidence * 100.0,
            self.detections.len()
        ));

        for detection in &self.detections {
            let confidence_color = if detection.confidence > 0.8 {
                "#28a745"
            } else if detection.confidence > 0.6 {
                "#ffc107"
            } else {
                "#dc3545"
            };

            html.push_str(&format!(
                r#"
            <div class="detection-card">
                <div class="detection-header">
                    <div class="technique-id">{} - {}</div>
                    <div class="confidence-badge" style="background: {};">{:.0}%</div>
                </div>
                
                <div class="evidence-chain">
"#,
                detection.technique_id,
                detection.technique_name,
                confidence_color,
                detection.confidence * 100.0
            ));

            for (idx, evidence) in detection.evidence_chain.iter().enumerate() {
                html.push_str(&format!(
                    r#"
                    <div class="evidence-item">
                        <div class="evidence-icon">{}</div>
                        <div class="evidence-content">
                            <div class="evidence-source">{}</div>
                            <div class="evidence-description">{}</div>
"#,
                    idx + 1,
                    evidence.source.label(),
                    evidence.description
                ));

                if let Some(ref context) = evidence.context {
                    let context = html_escape(context);
                    html.push_str(&format!(
                        r#"
                            <div class="evidence-context">{}</div>
"#,
                        context
                    ));
                }

                if let Some(ref raw_data) = evidence.raw_data {
                    let raw_data = html_escape(raw_data);
                    html.push_str(&format!(
                        r#"
                            <details class="evidence-raw" open>
                                <summary>Raw evidence</summary>
                                <pre>{}</pre>
                            </details>
"#,
                        raw_data
                    ));
                }

                html.push_str(
                    r#"
                        </div>
                    </div>
"#,
                );
            }

            html.push_str(&format!(
                r#"
                </div>
                
                <div class="metrics">
                    <div class="metric">
                        <div class="metric-value">{:.0}%</div>
                        <div class="metric-label">Correlation</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">{}</div>
                        <div class="metric-label">Sources</div>
                    </div>
                    <div class="metric">
                        <div class="metric-value">{}</div>
                        <div class="metric-label">FP Risk</div>
                    </div>
                </div>
            </div>
"#,
                detection.correlation_score * 100.0,
                detection.source_diversity,
                detection.fp_risk_label()
            ));
        }

        html.push_str(&format!(
            r#"
        </div>
        
        <div class="footer">
            Analysis completed in {} ms | Generated by HydraDragon EDR v2.0
        </div>
    </div>
</body>
</html>
"#,
            self.analysis_duration_ms
        ));

        html
    }

    /// Generate a JSON report for API/SIEM integration
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

fn html_escape(value: &str) -> String {
    value
        .chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect::<Vec<_>>(),
            '>' => "&gt;".chars().collect::<Vec<_>>(),
            '"' => "&quot;".chars().collect::<Vec<_>>(),
            '\'' => "&#39;".chars().collect::<Vec<_>>(),
            _ => vec![ch],
        })
        .collect()
}

/// Evidence Engine - builds detection reports from telemetry
pub struct EvidenceEngine {
    /// Technique database
    techniques: HashMap<String, MitreTechnique>,
}

impl EvidenceEngine {
    pub fn new(techniques: HashMap<String, MitreTechnique>) -> Self {
        Self { techniques }
    }

    /// Create a detection report from collected evidence
    pub fn build_report(
        &self,
        process_name: String,
        process_path: String,
        pid: u32,
        gid: u64,
        detections: Vec<DetectionEvidence>,
        analysis_duration_ms: u64,
    ) -> DetectionReport {
        // Calculate overall confidence (weighted average)
        let overall_confidence = if detections.is_empty() {
            0.0
        } else {
            let total: f32 = detections.iter().map(|d| d.confidence).sum();
            total / detections.len() as f32
        };

        // Determine threat level
        let threat_level = ThreatLevel::from_confidence(overall_confidence);

        // Find primary tactic (most common among detections)
        let primary_tactic = self.find_primary_tactic(&detections);

        DetectionReport {
            process_name,
            process_path,
            pid,
            gid,
            detections,
            overall_confidence,
            threat_level,
            primary_tactic,
            detection_timestamp: SystemTime::now(),
            analysis_duration_ms,
        }
    }

    fn find_primary_tactic(&self, detections: &[DetectionEvidence]) -> String {
        let mut tactic_counts: HashMap<String, usize> = HashMap::new();

        for detection in detections {
            if let Some(technique) = self.techniques.get(&detection.technique_id) {
                *tactic_counts.entry(technique.tactic.clone()).or_insert(0) += 1;
            }
        }

        tactic_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(tactic, _)| tactic)
            .unwrap_or_else(|| "Unknown".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_threat_level_classification() {
        assert_eq!(ThreatLevel::from_confidence(0.2), ThreatLevel::Benign);
        assert_eq!(ThreatLevel::from_confidence(0.5), ThreatLevel::Suspicious);
        assert_eq!(ThreatLevel::from_confidence(0.75), ThreatLevel::Malicious);
        assert_eq!(ThreatLevel::from_confidence(0.95), ThreatLevel::Critical);
    }

    #[test]
    fn test_detection_report_creation() {
        let detection = EvidenceBuilder::new("T1059.001", "PowerShell Execution")
            .add_process_tree_evidence("Parent: winword.exe")
            .add_behavioral_evidence("PowerShell with -enc flag")
            .add_network_evidence("C2 connection detected")
            .build();

        let engine = EvidenceEngine::new(HashMap::new());
        let report = engine.build_report(
            "powershell.exe".to_string(),
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".to_string(),
            1234,
            5678,
            vec![detection],
            150,
        );

        assert_eq!(report.process_name, "powershell.exe");
        assert_eq!(report.detections.len(), 1);
        assert!(report.overall_confidence > 0.0);
    }

    #[test]
    fn test_text_report_generation() {
        let detection = EvidenceBuilder::new("T1486", "Ransomware")
            .add_behavioral_evidence("Mass file encryption detected")
            .add_static_evidence("Ransom note dropped")
            .build();

        let engine = EvidenceEngine::new(HashMap::new());
        let report = engine.build_report(
            "malware.exe".to_string(),
            "C:\\Temp\\malware.exe".to_string(),
            9999,
            1111,
            vec![detection],
            200,
        );

        let text = report.to_text();
        assert!(text.contains("HYDRADRAGON DETECTION EVIDENCE REPORT"));
        assert!(text.contains("T1486"));
        assert!(text.contains("Evidence Chain:"));
    }
}
