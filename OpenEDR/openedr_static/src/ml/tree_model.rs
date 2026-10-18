//! Pure Rust High-Performance Tree Ensemble Inference Engine
//! Executes converted ONNX LightGBM Decision Trees in microseconds without C++ dependencies.

use std::path::Path;

#[derive(Clone, Debug)]
pub struct TreeNode {
    pub node_id: u32,
    pub feature_id: u32,
    pub threshold: f32,
    pub left_child: u32,
    pub right_child: u32,
    pub is_leaf: bool,
    pub weight: f32,
}

#[derive(Clone, Debug)]
pub struct DecisionTree {
    pub nodes: Vec<TreeNode>,
}

impl DecisionTree {
    #[inline(always)]
    pub fn predict(&self, features: &[f32]) -> f32 {
        let mut cur_idx = 0usize;
        while cur_idx < self.nodes.len() {
            let node = &self.nodes[cur_idx];
            if node.is_leaf {
                return node.weight;
            }
            let f_val = features.get(node.feature_id as usize).copied().unwrap_or(0.0);
            let next_node_id = if f_val <= node.threshold {
                node.left_child
            } else {
                node.right_child
            };
            if let Some(pos) = self.nodes.iter().position(|n| n.node_id == next_node_id) {
                cur_idx = pos;
            } else {
                return node.weight;
            }
        }
        0.0
    }

    /// Index of the node with `node_id` (nodes are usually stored in id order).
    #[inline]
    fn index_of(&self, node_id: u32) -> Option<usize> {
        let i = node_id as usize;
        if self.nodes.get(i).map(|n| n.node_id) == Some(node_id) {
            return Some(i);
        }
        self.nodes.iter().position(|n| n.node_id == node_id)
    }

    /// Mean leaf weight below every node (the bundle stores no internal values,
    /// so an unweighted subtree mean stands in for the node's expected output).
    fn subtree_means(&self) -> Vec<f32> {
        fn walk(t: &DecisionTree, i: usize, out: &mut [Option<(f32, u32)>], depth: u32) -> (f32, u32) {
            if let Some(v) = out[i] {
                return v;
            }
            let n = &t.nodes[i];
            let v = if n.is_leaf || depth > 256 {
                (n.weight, 1)
            } else {
                let l = t.index_of(n.left_child).map(|c| walk(t, c, out, depth + 1)).unwrap_or((n.weight, 1));
                let r = t.index_of(n.right_child).map(|c| walk(t, c, out, depth + 1)).unwrap_or((n.weight, 1));
                (l.0 + r.0, l.1 + r.1)
            };
            out[i] = Some(v);
            v
        }
        let mut acc = vec![None; self.nodes.len()];
        if !self.nodes.is_empty() {
            walk(self, 0, &mut acc, 0);
        }
        acc.iter().map(|v| v.map(|(s, c)| s / c.max(1) as f32).unwrap_or(0.0)).collect()
    }

    /// Adds this tree's per-feature contributions to `contrib` (Saabas path
    /// attribution: each split credits its feature with the change in expected
    /// output) and returns the tree's raw output and its bias (root mean).
    pub fn explain_into(&self, features: &[f32], contrib: &mut [f32]) -> (f32, f32) {
        if self.nodes.is_empty() {
            return (0.0, 0.0);
        }
        let means = self.subtree_means();
        let mut i = 0usize;
        let bias = means[0];
        for _ in 0..4096 {
            let node = &self.nodes[i];
            if node.is_leaf {
                return (node.weight, bias);
            }
            let f_val = features.get(node.feature_id as usize).copied().unwrap_or(0.0);
            let next = if f_val <= node.threshold { node.left_child } else { node.right_child };
            let Some(j) = self.index_of(next) else { return (node.weight, bias) };
            if let Some(c) = contrib.get_mut(node.feature_id as usize) {
                *c += means[j] - means[i];
            }
            i = j;
        }
        (self.nodes[i].weight, bias)
    }
}

#[derive(Clone, Debug)]
pub struct TreeEnsembleModel {
    pub trees: Vec<DecisionTree>,
}

impl TreeEnsembleModel {
    pub fn from_bin_file(path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        Self::from_bin_bytes(&data)
    }

    pub fn from_bin_bytes(mut data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_trees = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
        // Hard caps: a corrupt/truncated bundle must fail closed, never
        // attempt a giant reservation that OOMs the host (web parity).
        if num_trees == 0 || num_trees > 100_000 {
            return None;
        }
        data = &data[4..];

        let mut trees = Vec::new();
        let mut total_nodes = 0usize;
        for _ in 0..num_trees {
            if data.len() < 4 {
                return None;
            }
            let num_nodes = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
            if num_nodes == 0 || num_nodes > 1_000_000 {
                return None;
            }
            total_nodes = total_nodes.saturating_add(num_nodes);
            if total_nodes > 10_000_000 {
                return None;
            }
            // Fail fast when the remaining bytes cannot hold the nodes.
            if data.len() - 4 < num_nodes.saturating_mul(25) {
                return None;
            }
            data = &data[4..];

            let mut nodes = Vec::with_capacity(num_nodes.min(4096));
            for _ in 0..num_nodes {
                // <IIfIIBf (25 bytes per node)
                if data.len() < 25 {
                    return None;
                }
                let node_id = u32::from_le_bytes(data[0..4].try_into().ok()?);
                let feature_id = u32::from_le_bytes(data[4..8].try_into().ok()?);
                let threshold = f32::from_le_bytes(data[8..12].try_into().ok()?);
                let left_child = u32::from_le_bytes(data[12..16].try_into().ok()?);
                let right_child = u32::from_le_bytes(data[16..20].try_into().ok()?);
                let is_leaf = data[20] != 0;
                let weight = f32::from_le_bytes(data[21..25].try_into().ok()?);
                data = &data[25..];

                nodes.push(TreeNode {
                    node_id,
                    feature_id,
                    threshold,
                    left_child,
                    right_child,
                    is_leaf,
                    weight,
                });
            }
            trees.push(DecisionTree { nodes });
        }
        Some(Self { trees })
    }

    #[inline(always)]
    pub fn predict_probability(&self, features: &[f32]) -> f32 {
        let mut raw_score = 0.0f32;
        for tree in &self.trees {
            raw_score += tree.predict(features);
        }
        // Sigmoid (Logistic) Post-Transform
        1.0 / (1.0 + (-raw_score).exp())
    }

    /// Probability plus per-feature contributions to the raw (log-odds) score,
    /// in feature order. Positive = pushed towards malware.
    pub fn explain(&self, features: &[f32]) -> TreeExplanation {
        let mut contrib = vec![0.0f32; features.len()];
        let (mut raw, mut bias) = (0.0f32, 0.0f32);
        for tree in &self.trees {
            let (out, b) = tree.explain_into(features, &mut contrib);
            raw += out;
            bias += b;
        }
        TreeExplanation { probability: 1.0 / (1.0 + (-raw).exp()), raw_score: raw, bias, contributions: contrib }
    }
}

/// Result of [`TreeEnsembleModel::explain`].
#[derive(Clone, Debug)]
pub struct TreeExplanation {
    pub probability: f32,
    /// Sum of the trees' leaf weights (before the sigmoid).
    pub raw_score: f32,
    /// Sum of the trees' expected outputs; `bias + sum(contributions) == raw_score`.
    pub bias: f32,
    pub contributions: Vec<f32>,
}
