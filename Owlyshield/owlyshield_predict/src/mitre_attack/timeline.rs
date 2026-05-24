//! Attack Timeline Module
//!
//! Provides timeline visualization of attack events with MITRE ATT&CK mapping

use super::technique_mapping::MitreTechnique;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Severity level for timeline events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum EventSeverity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl EventSeverity {
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=2 => EventSeverity::Info,
            3..=4 => EventSeverity::Low,
            5..=6 => EventSeverity::Medium,
            7..=8 => EventSeverity::High,
            _ => EventSeverity::Critical,
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            EventSeverity::Info => "#3498db",      // Blue
            EventSeverity::Low => "#2ecc71",       // Green
            EventSeverity::Medium => "#f39c12",    // Orange
            EventSeverity::High => "#e67e22",      // Dark Orange
            EventSeverity::Critical => "#e74c3c",  // Red
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            EventSeverity::Info => "Info",
            EventSeverity::Low => "Low",
            EventSeverity::Medium => "Medium",
            EventSeverity::High => "High",
            EventSeverity::Critical => "Critical",
        }
    }
}

/// A single event in the attack timeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: SystemTime,
    pub timestamp_ms: u64,
    pub event_type: String,
    pub description: String,
    pub severity: EventSeverity,
    pub mitre_techniques: Vec<MitreTechnique>,
    pub details: Vec<(String, String)>, // Key-value pairs for additional details
    pub file_path: Option<String>,
    pub registry_key: Option<String>,
    pub network_destination: Option<String>,
    pub process_name: Option<String>,
    pub pid: Option<u64>,
}

impl TimelineEvent {
    pub fn new(
        timestamp: SystemTime,
        event_type: String,
        description: String,
        severity: EventSeverity,
    ) -> Self {
        let timestamp_ms = timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        TimelineEvent {
            timestamp,
            timestamp_ms,
            event_type,
            description,
            severity,
            mitre_techniques: Vec::new(),
            details: Vec::new(),
            file_path: None,
            registry_key: None,
            network_destination: None,
            process_name: None,
            pid: None,
        }
    }

    pub fn with_technique(mut self, technique: MitreTechnique) -> Self {
        self.mitre_techniques.push(technique);
        self
    }

    pub fn with_techniques(mut self, techniques: Vec<MitreTechnique>) -> Self {
        self.mitre_techniques.extend(techniques);
        self
    }

    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.push((key, value));
        self
    }

    pub fn with_file_path(mut self, path: String) -> Self {
        self.file_path = Some(path);
        self
    }

    pub fn with_registry_key(mut self, key: String) -> Self {
        self.registry_key = Some(key);
        self
    }

    pub fn with_network_destination(mut self, dest: String) -> Self {
        self.network_destination = Some(dest);
        self
    }

    pub fn with_process_info(mut self, name: String, pid: u64) -> Self {
        self.process_name = Some(name);
        self.pid = Some(pid);
        self
    }
}

/// Attack timeline containing all events for a process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTimeline {
    pub gid: u64,
    pub process_name: String,
    pub process_path: String,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub events: Vec<TimelineEvent>,
    pub total_score: u32,
    pub max_severity: EventSeverity,
}

impl AttackTimeline {
    pub fn new(gid: u64, process_name: String, process_path: String) -> Self {
        AttackTimeline {
            gid,
            process_name,
            process_path,
            start_time: SystemTime::now(),
            end_time: None,
            events: Vec::new(),
            total_score: 0,
            max_severity: EventSeverity::Info,
        }
    }

    pub fn add_event(&mut self, event: TimelineEvent) {
        // Update max severity
        if event.severity > self.max_severity {
            self.max_severity = event.severity;
        }

        // Update total score
        for technique in &event.mitre_techniques {
            self.total_score += technique.severity as u32;
        }

        self.events.push(event);
    }

    pub fn finalize(&mut self) {
        self.end_time = Some(SystemTime::now());
        // Sort events by timestamp
        self.events.sort_by_key(|e| e.timestamp_ms);
    }

    pub fn get_events_by_severity(&self, severity: EventSeverity) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    pub fn get_events_by_tactic(&self, tactic: &str) -> Vec<&TimelineEvent> {
        self.events
            .iter()
            .filter(|e| e.mitre_techniques.iter().any(|t| t.tactic == tactic))
            .collect()
    }

    pub fn get_unique_techniques(&self) -> Vec<MitreTechnique> {
        let mut techniques = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for event in &self.events {
            for technique in &event.mitre_techniques {
                if seen_ids.insert(technique.id.clone()) {
                    techniques.push(technique.clone());
                }
            }
        }

        techniques
    }

    pub fn get_tactics_summary(&self) -> std::collections::HashMap<String, usize> {
        let mut tactics = std::collections::HashMap::new();

        for event in &self.events {
            for technique in &event.mitre_techniques {
                *tactics.entry(technique.tactic.clone()).or_insert(0) += 1;
            }
        }

        tactics
    }

    /// Generate HTML visualization of the timeline
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(&format!(
            r#"<div class="attack-timeline" data-gid="{}">
<div class="timeline-header">
    <h2>Attack Timeline: {}</h2>
    <div class="timeline-summary">
        <span class="summary-item">Total Score: <strong>{}</strong></span>
        <span class="summary-item">Max Severity: <strong style="color: {}">{}</strong></span>
        <span class="summary-item">Events: <strong>{}</strong></span>
        <span class="summary-item">Techniques: <strong>{}</strong></span>
    </div>
</div>
"#,
            self.gid,
            self.process_name,
            self.total_score,
            self.max_severity.color(),
            self.max_severity.label(),
            self.events.len(),
            self.get_unique_techniques().len()
        ));

        // Tactics summary
        html.push_str("<div class=\"tactics-summary\">");
        let tactics = self.get_tactics_summary();
        for (tactic, count) in tactics.iter() {
            html.push_str(&format!(
                "<span class=\"tactic-badge\">{}: {}</span>",
                tactic, count
            ));
        }
        html.push_str("</div>");

        // Timeline events
        html.push_str("<div class=\"timeline-events\">");
        for event in &self.events {
            html.push_str(&self.event_to_html(event));
        }
        html.push_str("</div>");

        html.push_str("</div>");
        html
    }

    fn event_to_html(&self, event: &TimelineEvent) -> String {
        let time_str = format!("{:?}", event.timestamp);

        let mut html = format!(
            r#"<div class="timeline-event" data-severity="{}">
    <div class="event-marker" style="background-color: {}"></div>
    <div class="event-content">
        <div class="event-header">
            <span class="event-type">{}</span>
            <span class="event-time">{}</span>
            <span class="event-severity" style="color: {}">{}</span>
        </div>
        <div class="event-description">{}</div>
"#,
            event.severity.label(),
            event.severity.color(),
            event.event_type,
            time_str,
            event.severity.color(),
            event.severity.label(),
            event.description
        );

        // MITRE techniques
        if !event.mitre_techniques.is_empty() {
            html.push_str("<div class=\"event-techniques\">");
            for technique in &event.mitre_techniques {
                html.push_str(&format!(
                    r#"<div class="technique-badge" title="{}">
    <span class="technique-id">{}</span>
    <span class="technique-name">{}</span>
    <span class="technique-tactic">{}</span>
</div>"#,
                    technique.description, technique.id, technique.name, technique.tactic
                ));
            }
            html.push_str("</div>");
        }

        // Additional details
        if !event.details.is_empty()
            || event.file_path.is_some()
            || event.registry_key.is_some()
            || event.network_destination.is_some()
        {
            html.push_str("<div class=\"event-details\">");

            if let Some(path) = &event.file_path {
                html.push_str(&format!("<div><strong>File:</strong> {}</div>", path));
            }
            if let Some(key) = &event.registry_key {
                html.push_str(&format!("<div><strong>Registry:</strong> {}</div>", key));
            }
            if let Some(dest) = &event.network_destination {
                html.push_str(&format!("<div><strong>Network:</strong> {}</div>", dest));
            }
            if let Some(name) = &event.process_name {
                html.push_str(&format!(
                    "<div><strong>Process:</strong> {} (PID: {})</div>",
                    name,
                    event.pid.unwrap_or(0)
                ));
            }

            for (key, value) in &event.details {
                html.push_str(&format!("<div><strong>{}:</strong> {}</div>", key, value));
            }

            html.push_str("</div>");
        }

        html.push_str("</div></div>");
        html
    }

    /// Generate CSS for timeline visualization
    pub fn get_timeline_css() -> &'static str {
        r#"
.attack-timeline {
    font-family: Arial, sans-serif;
    max-width: 1200px;
    margin: 20px auto;
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}

.timeline-header h2 {
    margin: 0 0 15px 0;
    color: #2c3e50;
}

.timeline-summary {
    display: flex;
    gap: 20px;
    margin-bottom: 20px;
    padding: 15px;
    background: white;
    border-radius: 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.summary-item {
    font-size: 14px;
    color: #555;
}

.tactics-summary {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 20px;
}

.tactic-badge {
    padding: 6px 12px;
    background: #3498db;
    color: white;
    border-radius: 4px;
    font-size: 12px;
    font-weight: bold;
}

.timeline-events {
    position: relative;
    padding-left: 40px;
}

.timeline-events::before {
    content: '';
    position: absolute;
    left: 15px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #ddd;
}

.timeline-event {
    position: relative;
    margin-bottom: 25px;
    padding: 15px;
    background: white;
    border-radius: 6px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.event-marker {
    position: absolute;
    left: -32px;
    top: 20px;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 3px solid white;
    box-shadow: 0 0 0 2px #ddd;
}

.event-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 10px;
    padding-bottom: 10px;
    border-bottom: 1px solid #eee;
}

.event-type {
    font-weight: bold;
    color: #2c3e50;
    font-size: 16px;
}

.event-time {
    font-size: 12px;
    color: #7f8c8d;
}

.event-severity {
    font-weight: bold;
    font-size: 12px;
    padding: 4px 8px;
    border-radius: 4px;
    background: rgba(0,0,0,0.05);
}

.event-description {
    margin-bottom: 10px;
    color: #555;
    line-height: 1.5;
}

.event-techniques {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin: 10px 0;
}

.technique-badge {
    display: inline-flex;
    flex-direction: column;
    padding: 8px 12px;
    background: #ecf0f1;
    border-left: 3px solid #e74c3c;
    border-radius: 4px;
    font-size: 11px;
}

.technique-id {
    font-weight: bold;
    color: #e74c3c;
    margin-bottom: 2px;
}

.technique-name {
    color: #2c3e50;
    font-weight: 600;
    margin-bottom: 2px;
}

.technique-tactic {
    color: #7f8c8d;
    font-style: italic;
}

.event-details {
    margin-top: 10px;
    padding: 10px;
    background: #f8f9fa;
    border-radius: 4px;
    font-size: 13px;
    color: #555;
}

.event-details div {
    margin: 5px 0;
}

.event-details strong {
    color: #2c3e50;
}
"#
    }
}
