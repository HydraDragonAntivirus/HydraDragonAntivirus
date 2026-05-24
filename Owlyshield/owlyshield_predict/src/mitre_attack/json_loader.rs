//! MITRE ATT&CK JSON Loader
//!
//! Loads ALL 200+ MITRE ATT&CK techniques from the official Enterprise JSON database

use super::technique_mapping::MitreTechnique;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize, Serialize)]
struct MitreBundle {
    #[serde(rename = "type")]
    bundle_type: String,
    id: String,
    objects: Vec<MitreObject>,
}

#[derive(Debug, Deserialize, Serialize)]
struct MitreObject {
    #[serde(rename = "type")]
    object_type: String,
    id: Option<String>,
    name: Option<String>,
    description: Option<String>,
    external_references: Option<Vec<ExternalReference>>,
    kill_chain_phases: Option<Vec<KillChainPhase>>,
    #[serde(rename = "x_mitre_deprecated")]
    deprecated: Option<bool>,
    #[serde(rename = "x_mitre_version")]
    version: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ExternalReference {
    source_name: Option<String>,
    external_id: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KillChainPhase {
    kill_chain_name: String,
    phase_name: String,
}

/// Load ALL MITRE ATT&CK techniques from the official Enterprise JSON
pub fn load_all_techniques_from_json() -> HashMap<String, MitreTechnique> {
    // Load from mitre_attack directory at runtime (NOT include_str!)
    let mitre_path = "C:/Program Files/HydraDragonAntivirus/hydradragon/Owlyshield/mitre_attack/mitre_attack_enterprise.json";

    match std::fs::read_to_string(mitre_path) {
        Ok(json_data) => match serde_json::from_str::<MitreBundle>(&json_data) {
            Ok(bundle) => {
                eprintln!("[MITRE] Loaded {} techniques", bundle.objects.len());
                parse_mitre_bundle(bundle)
            }
            Err(e) => {
                eprintln!("[MITRE] Failed to parse JSON: {}", e);
                HashMap::new()
            }
        },
        Err(e) => {
            eprintln!("[MITRE] Failed to load {}: {}", mitre_path, e);
            HashMap::new()
        }
    }
}

fn parse_mitre_bundle(bundle: MitreBundle) -> HashMap<String, MitreTechnique> {
    let mut techniques = HashMap::new();

    for object in bundle.objects {
        // Only process attack-pattern objects (techniques)
        if object.object_type != "attack-pattern" {
            continue;
        }

        // Skip deprecated techniques
        if object.deprecated.unwrap_or(false) {
            continue;
        }

        // Extract technique ID from external references
        let technique_id = object.external_references.as_ref().and_then(|refs| {
            refs.iter()
                .find(|r| r.source_name.as_deref() == Some("mitre-attack"))
                .and_then(|r| r.external_id.clone())
        });

        if let (Some(id), Some(name)) = (technique_id, object.name) {
            // Extract tactic from kill chain phases
            let tactic = object
                .kill_chain_phases
                .as_ref()
                .and_then(|phases| phases.first())
                .map(|phase| format_tactic_name(&phase.phase_name))
                .unwrap_or_else(|| "Unknown".to_string());

            // Calculate severity based on tactic
            let severity = calculate_severity(&tactic, &id);

            let technique = MitreTechnique {
                id: id.clone(),
                name,
                tactic,
                description: object
                    .description
                    .unwrap_or_else(|| "No description available".to_string()),
                severity,
            };

            techniques.insert(id, technique);
        }
    }

    techniques
}

fn format_tactic_name(phase_name: &str) -> String {
    // Convert kill chain phase names to readable tactic names
    match phase_name {
        "reconnaissance" => "Reconnaissance",
        "resource-development" => "Resource Development",
        "initial-access" => "Initial Access",
        "execution" => "Execution",
        "persistence" => "Persistence",
        "privilege-escalation" => "Privilege Escalation",
        "defense-evasion" => "Defense Evasion",
        "credential-access" => "Credential Access",
        "discovery" => "Discovery",
        "lateral-movement" => "Lateral Movement",
        "collection" => "Collection",
        "command-and-control" => "Command and Control",
        "exfiltration" => "Exfiltration",
        "impact" => "Impact",
        _ => phase_name,
    }
    .to_string()
}

fn calculate_severity(tactic: &str, technique_id: &str) -> u8 {
    // Assign severity based on tactic and technique characteristics
    match tactic {
        "Impact" => {
            if technique_id.contains("T1486") || technique_id.contains("T1490") {
                10 // Ransomware and system recovery inhibition
            } else {
                8
            }
        }
        "Credential Access" => {
            if technique_id.contains("T1003") {
                10 // Credential dumping
            } else {
                8
            }
        }
        "Privilege Escalation" | "Defense Evasion" => {
            if technique_id.contains("T1055") || technique_id.contains("T1068") {
                9 // Process injection and exploitation
            } else {
                7
            }
        }
        "Execution" => 6,
        "Persistence" => 7,
        "Lateral Movement" => 7,
        "Command and Control" => 6,
        "Exfiltration" => 8,
        "Collection" => 6,
        "Discovery" => 4,
        "Initial Access" => 7,
        "Reconnaissance" => 3,
        "Resource Development" => 3,
        _ => 5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_techniques() {
        let techniques = load_all_techniques_from_json();
        assert!(!techniques.is_empty(), "Should load techniques from JSON");

        // Check for some known techniques
        assert!(
            techniques.contains_key("T1486"),
            "Should contain ransomware technique"
        );
        assert!(
            techniques.contains_key("T1055"),
            "Should contain process injection"
        );
        assert!(
            techniques.contains_key("T1003"),
            "Should contain credential dumping"
        );
    }

    #[test]
    fn test_format_tactic_name() {
        assert_eq!(format_tactic_name("defense-evasion"), "Defense Evasion");
        assert_eq!(
            format_tactic_name("privilege-escalation"),
            "Privilege Escalation"
        );
        assert_eq!(
            format_tactic_name("command-and-control"),
            "Command and Control"
        );
    }
}
