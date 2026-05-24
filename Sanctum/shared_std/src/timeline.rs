//! Sanctum Attack Timeline Integration
//!
//! Provides attack timeline and MITRE ATT&CK mapping for Sanctum EDR

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// Sanctum process timeline data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctumProcessTimeline {
    pub pid: u64,
    pub process_name: String,
    pub process_path: String,
    pub start_time: SystemTime,
    pub events: Vec<SanctumTimelineEvent>,
    pub mitre_techniques: Vec<String>,
    pub threat_score: f32,
    pub threat_level: String,
    pub is_malicious: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanctumTimelineEvent {
    pub timestamp: SystemTime,
    pub timestamp_ms: u64,
    pub event_type: String,
    pub description: String,
    pub severity: String,
    pub mitre_technique: Option<String>,
    pub details: HashMap<String, String>,
}

impl SanctumTimelineEvent {
    pub fn new(
        timestamp: SystemTime,
        event_type: String,
        description: String,
        severity: String,
    ) -> Self {
        let timestamp_ms = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        SanctumTimelineEvent {
            timestamp,
            timestamp_ms,
            event_type,
            description,
            severity,
            mitre_technique: None,
            details: HashMap::new(),
        }
    }

    pub fn with_technique(mut self, technique: String) -> Self {
        self.mitre_technique = Some(technique);
        self
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }
}

impl SanctumProcessTimeline {
    pub fn new(pid: u64, process_name: String, process_path: String) -> Self {
        SanctumProcessTimeline {
            pid,
            process_name,
            process_path,
            start_time: SystemTime::now(),
            events: Vec::new(),
            mitre_techniques: Vec::new(),
            threat_score: 0.0,
            threat_level: "Benign".to_string(),
            is_malicious: false,
        }
    }

    pub fn add_event(&mut self, event: SanctumTimelineEvent) {
        if let Some(ref technique) = event.mitre_technique {
            if !self.mitre_techniques.contains(technique) {
                self.mitre_techniques.push(technique.clone());
            }
        }
        self.events.push(event);
        self.recalculate_score();
    }

    fn recalculate_score(&mut self) {
        let mut score = 0.0;

        // Score based on event severity
        for event in &self.events {
            score += match event.severity.as_str() {
                "Critical" => 3.0,
                "High" => 2.0,
                "Medium" => 1.0,
                "Low" => 0.5,
                _ => 0.0,
            };
        }

        // Bonus for multiple MITRE techniques
        score += self.mitre_techniques.len() as f32 * 0.5;

        self.threat_score = score.min(10.0);

        // Determine threat level
        self.threat_level = if score < 3.0 {
            "Benign".to_string()
        } else if score < 5.0 {
            "Suspicious".to_string()
        } else if score < 8.0 {
            "Malicious".to_string()
        } else {
            "Critical".to_string()
        };

        self.is_malicious = score >= 5.0;
    }

    /// Generate HTML visualization for Sanctum GUI
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        let threat_color = match self.threat_level.as_str() {
            "Benign" => "#2ecc71",
            "Suspicious" => "#f39c12",
            "Malicious" => "#e67e22",
            "Critical" => "#e74c3c",
            _ => "#95a5a6",
        };

        html.push_str(&format!(
            r#"<div class="sanctum-timeline">
    <div class="timeline-header">
        <h3>Process Timeline: {}</h3>
        <div class="process-info">
            <span><strong>PID:</strong> {}</span>
            <span><strong>Path:</strong> {}</span>
        </div>
        <div class="threat-badge" style="background-color: {}; color: white;">
            {} - Score: {:.1}/10
        </div>
    </div>
"#,
            self.process_name,
            self.pid,
            self.process_path,
            threat_color,
            self.threat_level,
            self.threat_score
        ));

        // MITRE techniques
        if !self.mitre_techniques.is_empty() {
            html.push_str("<div class=\"mitre-techniques\">");
            html.push_str("<h4>MITRE ATT&CK Techniques:</h4>");
            html.push_str("<div class=\"technique-list\">");
            for technique in &self.mitre_techniques {
                html.push_str(&format!(
                    "<span class=\"technique-tag\">{}</span>",
                    technique
                ));
            }
            html.push_str("</div></div>");
        }

        // Timeline events
        html.push_str("<div class=\"timeline-events\">");
        html.push_str(&format!("<h4>Events ({})</h4>", self.events.len()));

        for event in &self.events {
            let severity_color = match event.severity.as_str() {
                "Critical" => "#e74c3c",
                "High" => "#e67e22",
                "Medium" => "#f39c12",
                "Low" => "#3498db",
                _ => "#95a5a6",
            };

            html.push_str(&format!(
                r#"<div class="timeline-event">
    <div class="event-marker" style="background-color: {}"></div>
    <div class="event-content">
        <div class="event-header">
            <span class="event-type">{}</span>
            <span class="event-severity" style="color: {}">{}</span>
        </div>
        <div class="event-description">{}</div>
"#,
                severity_color, event.event_type, severity_color, event.severity, event.description
            ));

            if let Some(ref technique) = event.mitre_technique {
                html.push_str(&format!(
                    "<div class=\"event-technique\">MITRE: {}</div>",
                    technique
                ));
            }

            if !event.details.is_empty() {
                html.push_str("<div class=\"event-details\">");
                for (key, value) in &event.details {
                    html.push_str(&format!("<div><strong>{}:</strong> {}</div>", key, value));
                }
                html.push_str("</div>");
            }

            html.push_str("</div></div>");
        }

        html.push_str("</div></div>");
        html
    }

    /// Get CSS for Sanctum timeline
    pub fn get_css() -> &'static str {
        r#"
.sanctum-timeline {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: #ffffff;
    border-radius: 8px;
    padding: 20px;
    margin: 20px 0;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.timeline-header {
    margin-bottom: 20px;
    padding-bottom: 15px;
    border-bottom: 2px solid #ecf0f1;
}

.timeline-header h3 {
    margin: 0 0 10px 0;
    color: #2c3e50;
}

.process-info {
    display: flex;
    gap: 20px;
    margin: 10px 0;
    font-size: 14px;
    color: #555;
}

.threat-badge {
    display: inline-block;
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 14px;
    margin-top: 10px;
}

.mitre-techniques {
    margin: 15px 0;
    padding: 15px;
    background: #f8f9fa;
    border-radius: 6px;
}

.mitre-techniques h4 {
    margin: 0 0 10px 0;
    color: #2c3e50;
}

.technique-list {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.technique-tag {
    display: inline-block;
    padding: 6px 12px;
    background: #e74c3c;
    color: white;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}

.timeline-events {
    margin-top: 20px;
}

.timeline-events h4 {
    margin: 0 0 15px 0;
    color: #2c3e50;
}

.timeline-event {
    position: relative;
    margin-bottom: 20px;
    padding-left: 30px;
}

.event-marker {
    position: absolute;
    left: 0;
    top: 5px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 3px solid white;
    box-shadow: 0 0 0 2px #ddd;
}

.event-content {
    padding: 12px;
    background: #f8f9fa;
    border-radius: 6px;
    border-left: 3px solid #3498db;
}

.event-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.event-type {
    font-weight: bold;
    color: #2c3e50;
    font-size: 14px;
}

.event-severity {
    font-weight: bold;
    font-size: 12px;
}

.event-description {
    color: #555;
    font-size: 13px;
    margin-bottom: 8px;
}

.event-technique {
    display: inline-block;
    padding: 4px 8px;
    background: #e74c3c;
    color: white;
    border-radius: 4px;
    font-size: 11px;
    font-weight: bold;
    margin: 5px 0;
}

.event-details {
    margin-top: 10px;
    padding: 10px;
    background: white;
    border-radius: 4px;
    font-size: 12px;
}

.event-details div {
    margin: 5px 0;
    color: #555;
}

.event-details strong {
    color: #2c3e50;
}
"#
    }
}

/// Helper to map Sanctum events to MITRE techniques
pub fn map_sanctum_event_to_mitre(event_type: &str, description: &str) -> Option<String> {
    let event_lower = event_type.to_lowercase();
    let desc_lower = description.to_lowercase();

    if event_lower.contains("injection") || desc_lower.contains("writeprocessmemory") {
        Some("T1055 - Process Injection".to_string())
    } else if event_lower.contains("credential") || desc_lower.contains("lsass") {
        Some("T1003.001 - LSASS Memory".to_string())
    } else if event_lower.contains("syscall") && desc_lower.contains("suspicious") {
        Some("T1055 - Process Injection".to_string())
    } else if event_lower.contains("shellcode") {
        Some("T1055 - Process Injection".to_string())
    } else if event_lower.contains("hook") || event_lower.contains("ghost") {
        Some("T1055 - Process Injection".to_string())
    } else if event_lower.contains("driver") {
        Some("T1068 - Exploitation for Privilege Escalation".to_string())
    } else if event_lower.contains("token") {
        Some("T1134 - Access Token Manipulation".to_string())
    } else {
        None
    }
}
