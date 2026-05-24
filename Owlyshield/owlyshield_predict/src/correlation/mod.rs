//! Correlation Module
//!
//! Correlates detection signals to build evidence graphs

pub mod graph_builder;
pub mod signal_correlator;

pub use graph_builder::{CorrelationEdge, CorrelationGraph, DetectionNode, NodeType};
pub use signal_correlator::SignalCorrelator;
