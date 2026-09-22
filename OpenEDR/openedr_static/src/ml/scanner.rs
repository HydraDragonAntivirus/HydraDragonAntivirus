use std::path::Path;

use super::pe_features;
use super::js_features;
use super::url_features;
use super::tree_model::TreeEnsembleModel;

pub struct MlScanner {
    pe_trees: Option<TreeEnsembleModel>,
    js_trees: Option<TreeEnsembleModel>,
    url_trees: Option<TreeEnsembleModel>,
    apk_trees: Option<TreeEnsembleModel>,
}

impl MlScanner {
    pub fn new(models_dir: &Path) -> Self {
        let pe_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees.bin"));
        let js_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("js_trees.bin"));
        let url_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("url_trees.bin"));
        let apk_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("apk_trees.bin"));

        Self {
            pe_trees,
            js_trees,
            url_trees,
            apk_trees,
        }
    }

    /// Runtime model load from bytes (web parity: kind 0=PE, 1=JS, 2=URL, 3=APK).
    /// Returns false when bytes don't parse or kind is unknown.
    pub fn load_model_bytes(&mut self, kind: u32, data: &[u8]) -> bool {
        let model = match TreeEnsembleModel::from_bin_bytes(data) {
            Some(m) => m,
            None => return false,
        };
        match kind {
            0 => self.pe_trees = Some(model),
            1 => self.js_trees = Some(model),
            2 => self.url_trees = Some(model),
            3 => self.apk_trees = Some(model),
            _ => return false,
        }
        true
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

    /// APK probability from our own forest (`apk_trees.bin`, 24 features —
    /// same bundle format and scorer as the PE/JS/URL trees).
    pub fn predict_apk(&self, features: &[f32; crate::apk::APK_TREE_FEATURE_COUNT]) -> Option<f32> {
        let trees = self.apk_trees.as_ref()?;
        Some(trees.predict_probability(features))
    }

    pub fn apk_loaded(&self) -> bool {
        self.apk_trees.is_some()
    }

    pub fn is_loaded(&self) -> bool {
        self.pe_trees.is_some()
            || self.js_trees.is_some()
            || self.url_trees.is_some()
            || self.apk_trees.is_some()
    }
}
