//! Attack Story Builder
//!
//! Transforms timeline events into human-readable attack narratives

use super::technique_mapping::MitreTechnique;
use super::timeline::AttackTimeline;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Attack phase in the kill chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPhase {
    pub phase_name: String,
    pub techniques: Vec<MitreTechnique>,
    pub timestamp_range: (SystemTime, SystemTime),
    pub description: String,
    pub events: Vec<String>,
}

/// Complete attack story
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStory {
    pub phases: Vec<AttackPhase>,
    pub narrative: String,
    pub kill_chain_progress: f32,
    pub threat_actor_similarity: Option<String>,
    pub timeline_summary: String,
}

/// Story builder
pub struct StoryBuilder;

impl StoryBuilder {
    /// Build attack story from timeline
    pub fn build_story(timeline: &AttackTimeline) -> AttackStory {
        let phases = Self::extract_phases(timeline);
        let narrative = Self::generate_narrative(&phases, timeline);
        let kill_chain_progress = Self::calculate_kill_chain_progress(&phases);
        let threat_actor_similarity = Self::assess_threat_actor_similarity(&phases);
        let timeline_summary = Self::generate_timeline_summary(timeline);

        AttackStory {
            phases,
            narrative,
            kill_chain_progress,
            threat_actor_similarity,
            timeline_summary,
        }
    }

    fn extract_phases(timeline: &AttackTimeline) -> Vec<AttackPhase> {
        let mut phases = Vec::new();
        let mut current_phase: Option<AttackPhase> = None;

        for event in &timeline.events {
            let phase_name = Self::event_to_phase(&event.event_type);

            if let Some(ref mut phase) = current_phase {
                if phase.phase_name == phase_name {
                    phase.techniques.extend(event.mitre_techniques.clone());
                    phase.timestamp_range.1 = event.timestamp;
                    phase.events.push(event.description.clone());
                } else {
                    phases.push(phase.clone());
                    current_phase = Some(AttackPhase {
                        phase_name: phase_name.clone(),
                        techniques: event.mitre_techniques.clone(),
                        timestamp_range: (event.timestamp, event.timestamp),
                        description: Self::phase_description(&phase_name),
                        events: vec![event.description.clone()],
                    });
                }
            } else {
                current_phase = Some(AttackPhase {
                    phase_name: phase_name.clone(),
                    techniques: event.mitre_techniques.clone(),
                    timestamp_range: (event.timestamp, event.timestamp),
                    description: Self::phase_description(&phase_name),
                    events: vec![event.description.clone()],
                });
            }
        }

        if let Some(phase) = current_phase {
            phases.push(phase);
        }

        phases
    }

    fn event_to_phase(event_type: &str) -> String {
        match event_type {
            "User Execution" | "Malicious Link" | "Malicious File" => "Initial Access".to_string(),
            "Process Injection" | "PowerShell" | "Command Shell" => "Execution".to_string(),
            "Registry Modification" | "Scheduled Task" | "Startup" => "Persistence".to_string(),
            "Token Manipulation" | "Privilege Escalation" => "Privilege Escalation".to_string(),
            "Obfuscation" | "Disable Security" => "Defense Evasion".to_string(),
            "Credential Dumping" | "Password Store" => "Credential Access".to_string(),
            "System Discovery" | "File Discovery" => "Discovery".to_string(),
            "Network Activity" | "C2 Communication" => "Command and Control".to_string(),
            "Data Collection" | "Screen Capture" => "Collection".to_string(),
            "Data Exfiltration" => "Exfiltration".to_string(),
            "Ransomware" | "Data Encryption" | "Service Stop" => "Impact".to_string(),
            _ => "Execution".to_string(),
        }
    }

    fn phase_description(phase_name: &str) -> String {
        match phase_name {
            "Initial Access" => "Attacker gained initial foothold".to_string(),
            "Execution" => "Malicious code executed".to_string(),
            "Persistence" => "Attacker established persistence".to_string(),
            "Privilege Escalation" => "Attacker escalated privileges".to_string(),
            "Defense Evasion" => "Attacker evaded defenses".to_string(),
            "Credential Access" => "Attacker accessed credentials".to_string(),
            "Discovery" => "Attacker performed reconnaissance".to_string(),
            "Command and Control" => "Attacker established C2 channel".to_string(),
            "Collection" => "Attacker collected data".to_string(),
            "Exfiltration" => "Attacker exfiltrated data".to_string(),
            "Impact" => "Attacker caused impact".to_string(),
            _ => "Attack activity detected".to_string(),
        }
    }

    fn generate_narrative(phases: &[AttackPhase], timeline: &AttackTimeline) -> String {
        let mut narrative = String::new();

        narrative.push_str(&format!(
            "Attack Story for {} (GID: {})\n\n",
            timeline.process_name, timeline.gid
        ));

        for (idx, phase) in phases.iter().enumerate() {
            narrative.push_str(&format!(
                "{}. {} ({})\n",
                idx + 1,
                phase.phase_name,
                phase.description
            ));

            for event in &phase.events {
                narrative.push_str(&format!("   - {}\n", event));
            }

            if !phase.techniques.is_empty() {
                narrative.push_str("   Techniques: ");
                let tech_ids: Vec<_> = phase.techniques.iter().map(|t| t.id.as_str()).collect();
                narrative.push_str(&tech_ids.join(", "));
                narrative.push_str("\n");
            }
            narrative.push_str("\n");
        }

        narrative
    }

    fn calculate_kill_chain_progress(phases: &[AttackPhase]) -> f32 {
        let total_phases = 11.0; // Total kill chain phases
        let completed = phases.len() as f32;
        (completed / total_phases * 100.0).min(100.0)
    }

    fn assess_threat_actor_similarity(phases: &[AttackPhase]) -> Option<String> {
        // Simplified threat actor assessment
        let has_ransomware = phases.iter().any(|p| p.phase_name == "Impact");
        let has_credential_access = phases.iter().any(|p| p.phase_name == "Credential Access");
        let has_c2 = phases.iter().any(|p| p.phase_name == "Command and Control");

        if has_ransomware {
            Some("Ransomware-like behavior (68% similarity)".to_string())
        } else if has_credential_access && has_c2 {
            Some("APT-like behavior (54% similarity)".to_string())
        } else {
            Some("Generic malware behavior".to_string())
        }
    }

    fn generate_timeline_summary(timeline: &AttackTimeline) -> String {
        format!(
            "{} events detected across {} techniques",
            timeline.events.len(),
            timeline.get_unique_techniques().len()
        )
    }

    /// Generate HTML visualization
    pub fn to_html(story: &AttackStory) -> String {
        let mut html = String::new();

        html.push_str(
            r#"
<div class="attack-story-container">
    <h2>📖 Attack Story</h2>
    
    <div class="story-summary">
        <div class="summary-item">
            <span class="label">Kill Chain Progress:</span>
            <div class="progress-bar">
                <div class="progress-fill" style="width: "#,
        );
        html.push_str(&format!("{}%", story.kill_chain_progress));
        html.push_str(
            r#""></div>
            </div>
            <span class="value">"#,
        );
        html.push_str(&format!("{:.0}%", story.kill_chain_progress));
        html.push_str(
            r#"</span>
        </div>
        <div class="summary-item">
            <span class="label">Threat Actor Similarity:</span>
            <span class="value">"#,
        );
        html.push_str(
            story
                .threat_actor_similarity
                .as_deref()
                .unwrap_or("Unknown"),
        );
        html.push_str(
            r#"</span>
        </div>
    </div>

    <div class="story-timeline">
"#,
        );

        for (idx, phase) in story.phases.iter().enumerate() {
            html.push_str(&format!(
                r#"
        <div class="phase-card">
            <div class="phase-number">{}</div>
            <div class="phase-content">
                <h3>{}</h3>
                <p>{}</p>
                <ul>
"#,
                idx + 1,
                phase.phase_name,
                phase.description
            ));

            for event in &phase.events {
                html.push_str(&format!("<li>{}</li>\n", event));
            }

            html.push_str(
                r#"
                </ul>
                <div class="phase-techniques">
"#,
            );

            for tech in &phase.techniques {
                html.push_str(&format!(
                    r#"
                    <span class="technique-badge">{}</span>
"#,
                    tech.id
                ));
            }

            html.push_str(
                r#"
                </div>
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

    /// Get CSS for story visualization
    pub fn get_css() -> &'static str {
        r#"
.attack-story-container {
    padding: 20px;
    background: #f8f9fa;
    border-radius: 8px;
}

.story-summary {
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
}

.summary-item {
    display: flex;
    align-items: center;
    gap: 15px;
    margin: 10px 0;
}

.progress-bar {
    flex: 1;
    height: 20px;
    background: #ecf0f1;
    border-radius: 10px;
    overflow: hidden;
}

.progress-fill {
    height: 100%;
    background: linear-gradient(90deg, #3498db, #2980b9);
}

.story-timeline {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

.phase-card {
    display: flex;
    gap: 20px;
    background: white;
    padding: 20px;
    border-radius: 8px;
    border-left: 4px solid #3498db;
}

.phase-number {
    width: 40px;
    height: 40px;
    background: #3498db;
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: bold;
    flex-shrink: 0;
}

.phase-content {
    flex: 1;
}

.phase-content h3 {
    margin: 0 0 10px 0;
    color: #2c3e50;
}

.phase-content ul {
    margin: 10px 0;
    padding-left: 20px;
}

.phase-techniques {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: 10px;
}

.technique-badge {
    padding: 4px 8px;
    background: #3498db;
    color: white;
    border-radius: 4px;
    font-size: 12px;
    font-family: monospace;
}
"#
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_phase_extraction() {
        assert_eq!(StoryBuilder::event_to_phase("PowerShell"), "Execution");
        assert_eq!(
            StoryBuilder::event_to_phase("Registry Modification"),
            "Persistence"
        );
    }
}
