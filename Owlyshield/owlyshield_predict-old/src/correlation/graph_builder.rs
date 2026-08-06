//! Correlation Graph Builder
//!
//! Builds graphs showing relationships between detection signals.

use serde::{Deserialize, Serialize};

/// Type of detection node.
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

/// Detection node in the correlation graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionNode {
    pub id: String,
    pub node_type: NodeType,
    pub data: String,
    pub confidence: f32,
    pub timestamp_ms: u64,
}

/// Edge connecting two nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationEdge {
    pub from_id: String,
    pub to_id: String,
    pub relationship: String,
    pub weight: f32,
}

/// Complete correlation graph.
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

        let avg_confidence: f32 =
            self.nodes.iter().map(|n| n.confidence).sum::<f32>() / self.nodes.len() as f32;
        let edge_density = self.edges.len() as f32 / self.nodes.len() as f32;

        self.correlation_score = (avg_confidence * 0.7 + edge_density.min(1.0) * 0.3).min(1.0);
    }

    /// Generate HTML visualization.
    pub fn to_html(&self) -> String {
        let mut html = String::new();

        html.push_str(
            r#"
<div class="correlation-graph">
    <h3>Detection Correlation Graph</h3>
    <div class="graph-summary">
        <span>Nodes: "#,
        );
        html.push_str(&self.nodes.len().to_string());
        html.push_str(
            r#"</span>
        <span>Edges: "#,
        );
        html.push_str(&self.edges.len().to_string());
        html.push_str(
            r#"</span>
        <span>Correlation Score: "#,
        );
        html.push_str(&format!("{:.0}%", self.correlation_score * 100.0));
        html.push_str(
            r#"</span>
    </div>
    <div class="graph-nodes">
"#,
        );

        for node in &self.nodes {
            html.push_str(&format!(
                r#"
        <div class="graph-node">
            <div class="node-type">{:?}</div>
            <div class="node-data">{}</div>
            <div class="node-confidence">{:.0}%</div>
        </div>
"#,
                node.node_type,
                escape_html(&node.data),
                node.confidence * 100.0
            ));
        }

        html.push_str(
            r#"
    </div>
    <div class="graph-edges">
        <h4>Correlated Edges</h4>
"#,
        );

        for edge in self.edges.iter().take(80) {
            html.push_str(&format!(
                r#"
        <div class="graph-edge">
            <code>{}</code> -> <code>{}</code>
            <span>{}</span>
            <strong>{:.0}%</strong>
        </div>
"#,
                escape_html(&edge.from_id),
                escape_html(&edge.to_id),
                escape_html(&edge.relationship),
                edge.weight * 100.0
            ));
        }

        html.push_str(
            r#"
    </div>
</div>
"#,
        );

        html
    }

    pub fn get_css() -> &'static str {
        r#"
.correlation-graph {
    padding: 20px;
    background: #f8fafc;
    border-radius: 8px;
}

.graph-summary {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 18px;
}

.graph-summary span {
    background: #e0f2fe;
    color: #0f3d5c;
    padding: 8px 12px;
    border-radius: 6px;
    font-weight: 600;
}

.graph-nodes {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    gap: 10px;
}

.graph-node {
    background: white;
    border-left: 4px solid #2563eb;
    border-radius: 6px;
    padding: 12px;
    box-shadow: 0 1px 3px rgba(15,23,42,0.08);
}

.node-type {
    font-size: 11px;
    color: #475569;
    text-transform: uppercase;
    font-weight: 700;
}

.node-data {
    margin-top: 6px;
    color: #0f172a;
    word-break: break-word;
}

.node-confidence {
    margin-top: 8px;
    color: #1d4ed8;
    font-weight: 700;
}

.graph-edges {
    margin-top: 22px;
}

.graph-edge {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 8px 0;
    border-bottom: 1px solid #e2e8f0;
}

.graph-edge code {
    background: #e2e8f0;
    padding: 2px 6px;
    border-radius: 4px;
}
"#
    }
}

impl Default for CorrelationGraph {
    fn default() -> Self {
        Self::new()
    }
}

fn escape_html(value: &str) -> String {
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
