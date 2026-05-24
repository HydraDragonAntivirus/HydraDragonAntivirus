//! Signal Correlator
//!
//! Correlates weak signals into strong detections

use super::graph_builder::{CorrelationEdge, CorrelationGraph, DetectionNode};

pub struct SignalCorrelator;

impl SignalCorrelator {
    /// Correlate signals and build graph
    pub fn correlate(signals: Vec<DetectionNode>) -> CorrelationGraph {
        let mut graph = CorrelationGraph::new();

        for signal in signals {
            graph.add_node(signal);
        }

        // Build edges based on temporal and logical relationships
        Self::build_edges(&mut graph);
        graph.calculate_correlation_score();

        graph
    }

    fn build_edges(graph: &mut CorrelationGraph) {
        let nodes = graph.nodes.clone();

        for i in 0..nodes.len() {
            for j in (i + 1)..nodes.len() {
                if let Some(edge) = Self::find_relationship(&nodes[i], &nodes[j]) {
                    graph.add_edge(edge);
                }
            }
        }
    }

    fn find_relationship(node1: &DetectionNode, node2: &DetectionNode) -> Option<CorrelationEdge> {
        // Temporal correlation
        let time_diff = if node1.timestamp_ms > node2.timestamp_ms {
            node1.timestamp_ms - node2.timestamp_ms
        } else {
            node2.timestamp_ms - node1.timestamp_ms
        };

        if time_diff < 5000 {
            // Within 5 seconds
            Some(CorrelationEdge {
                from_id: node1.id.clone(),
                to_id: node2.id.clone(),
                relationship: "temporal".to_string(),
                weight: 0.8,
            })
        } else {
            None
        }
    }
}
