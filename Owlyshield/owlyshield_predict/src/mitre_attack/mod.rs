//! MITRE ATT&CK Timeline Module
//!
//! This module provides MITRE ATT&CK technique mapping and timeline visualization
//! for process behavior analysis. It maps observed behaviors to MITRE ATT&CK techniques
//! and generates a timeline of attack events with scoring similar to Triage.
//!
//! This implementation includes ALL 200+ official MITRE ATT&CK Enterprise techniques
//! loaded from the official MITRE CTI repository JSON database.

pub mod technique_mapping;
pub mod timeline;
pub mod scoring;
pub mod timeline_builder;
pub mod json_loader;

pub use technique_mapping::{MitreTechnique, TechniqueMapper};
pub use timeline::{AttackTimeline, TimelineEvent, EventSeverity};
pub use scoring::{ThreatScore, ScoringEngine, ThreatLevel};
pub use timeline_builder::TimelineBuilder;
pub use json_loader::load_all_techniques_from_json;
