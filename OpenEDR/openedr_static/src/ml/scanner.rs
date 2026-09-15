use std::path::Path;

use super::pe_features;
use super::js_features;
use super::url_features;
use super::tree_model::TreeEnsembleModel;

pub struct MlScanner {
    pe_trees: Option<TreeEnsembleModel>,
    js_trees: Option<TreeEnsembleModel>,
    url_trees: Option<TreeEnsembleModel>,
}

impl MlScanner {
    pub fn new(models_dir: &Path) -> Self {
        let pe_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees.bin"));
        let js_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("js_trees.bin"));
        let url_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("url_trees.bin"));

        Self {
            pe_trees,
            js_trees,
            url_trees,
        }
    }

    pub fn predict_pe(&self, data: &[u8]) -> Option<f32> {
        let trees = self.pe_trees.as_ref()?;
        let features = pe_features::extract_pe_features(data)?;
        let arr = features.to_array();
        Some(trees.predict_probability(&arr))
    }

    pub fn predict_js(&self, source: &str) -> Option<f32> {
        let trees = self.js_trees.as_ref()?;
        let features = js_features::extract_js_features(source)?;
        let arr = features.to_array();
        Some(trees.predict_probability(&arr))
    }

    pub fn predict_url(&self, raw_url: &str) -> Option<f32> {
        let trees = self.url_trees.as_ref()?;
        let features = url_features::extract_url_features(raw_url);
        let arr = features.to_array();
        Some(trees.predict_probability(&arr))
    }

    pub fn is_loaded(&self) -> bool {
        self.pe_trees.is_some() || self.js_trees.is_some() || self.url_trees.is_some()
    }
}
