//! Pure Rust High-Performance Tree Ensemble Inference Engine
//! Executes converted ONNX LightGBM Decision Trees in microseconds without C++ dependencies.
//! Web edition: filesystem loading removed (models arrive as bytes from JS).


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
}

#[derive(Clone, Debug)]
pub struct TreeEnsembleModel {
    pub trees: Vec<DecisionTree>,
}

impl TreeEnsembleModel {
    pub fn from_bin_bytes(mut data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let num_trees = u32::from_le_bytes(data[..4].try_into().ok()?) as usize;
        // Hard caps: a corrupt/truncated bundle must fail closed, never
        // attempt a giant reservation that OOMs the tab (phones especially).
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
}
