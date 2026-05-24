//! Correlation Graph Builder
//!
//! Builds graphs showing relationships between detection signals

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of detection node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum NodeType {
    FileHash,
    ProcessExecution,
    NetworkConnection,
    RegistryModification,
    APICall,
    FileOperation,
    MemoryOperation,
}

/// Detection node in the correlation graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionNode {
    pub id: String,
    pub node_type: NodeType,
    pub data: String,
    pub confidence: f32,
    pub timestamp_ms: u64,
}

/// Edge connecting two nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEdge {
    pub from_id: String,
    pub to_id: String,
    pub relationship: String,
    pub weight: f32,
}

/// Complete correlation graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationGraph {
    pub nodes: Vec<DetectionNode>,
    pub edges: Vec<CorrelationEdge>,
    pub correlation_score: f32,
}

impl CorrelationGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            correlation_score: 0.0,
        }
    }

    pub fn add_node(&mut self, node: DetectionNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: CorrelationEdge) {
        self.edges.push(edge);
    }

    pub fn calculate_correlation_score(&mut self) {
        if self.nodes.is_empty() {
            self.correlation_score = 0.0;
            return;
        }

        let avg_confidence: f32 = self.nodes.iter().map(|n| n.confidence).sum::<f32>() 
            / self.nodes.len() as f32;
        let edge_density = self.edges.len() as f32 / self.nodes.len() as f32;
        
        self.correlation_score = (avg_confidence * 0.7 + edge_density.min(1.0) * 0.3).min(1.0);
    }

    /// Generate HTML visualization
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(r#"
<div class="correlation-graph">
    <h3>🔗 Detection Correlation Graph</h3>
    <div class="graph-summary">
        <span>Nodes: "#);
        html.push_str(&self.nodes.len().to_string());
        html.push_str(r#"</span>
        <span>Edges: "#);
        html.push_str(&self.edges.len().to_string());
        html.push_str(r#"</span>
        <span>Correlation Score: "#);
        html.push_str(&format!("{:.0}%", self.correlation_score * 100.0));
        html.push_str(r#"</span>
    </div>
    <div class="graph-nodes">
"#);

        for node in &self.nodes {
            html.push_str(&format!(r#"
        <div class="graph-node">
            <div class="node-type">{:?}</div>
            <div class="node-data">{}</div>
            <div class="node-confidence">{:.0}%</div>
        </div>
"#, node.node_type, node.data, node.confidence * 100.0));
        }

        html.push_str(r#"
    </div>
</div>
"#);

        html
    }
}

impl Default for CorrelationGraph {
    fn default() -> Self {
        Self::new()
    }
}
