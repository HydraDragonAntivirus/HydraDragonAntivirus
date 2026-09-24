use super::js_features;
use super::pe_features;
use super::tree_model::TreeEnsembleModel;
use super::url_features;

/// Master router input width: [is_pe, is_js, is_apk, is_url, pe, js, apk, url].
pub const MASTER_FEATURE_COUNT: usize = 8;
/// Generic whole-buffer string/entropy model input width (train_generic_lgbm.py).
pub const GENERIC_FEATURE_COUNT: usize = 20;

pub struct MlScanner {
    pe_trees: Option<TreeEnsembleModel>,
    js_trees: Option<TreeEnsembleModel>,
    url_trees: Option<TreeEnsembleModel>,
    apk_trees: Option<TreeEnsembleModel>,
    master_trees: Option<TreeEnsembleModel>,
    generic_trees: Option<TreeEnsembleModel>,
}

impl MlScanner {
    pub fn new() -> Self {
        // Web edition: models arrive as bytes from JS (fetch), never from fs.
        Self {
            pe_trees: None,
            js_trees: None,
            url_trees: None,
            apk_trees: None,
            master_trees: None,
            generic_trees: None,
        }
    }

    /// kind: 0 = PE, 1 = JS, 2 = URL, 3 = APK, 4 = master router, 5 = generic.
    /// Returns false when bytes don't parse.
    pub fn load_model(&mut self, kind: u32, data: &[u8]) -> bool {
        let model = match TreeEnsembleModel::from_bin_bytes(data) {
            Some(m) => m,
            None => return false,
        };
        match kind {
            0 => self.pe_trees = Some(model),
            1 => self.js_trees = Some(model),
            2 => self.url_trees = Some(model),
            3 => self.apk_trees = Some(model),
            4 => self.master_trees = Some(model),
            5 => self.generic_trees = Some(model),
            _ => return false,
        }
        true
    }

    pub fn predict_pe(&self, data: &[u8], disasm: Option<(u64, u64, u64)>) -> Option<f32> {
        let trees = self.pe_trees.as_ref()?;
        let features = pe_features::extract_pe_features_with_disasm(data, disasm)?;
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

    /// Master router over the 8-vector [is_pe, is_js, is_apk, is_url, pe, js, apk, url].
    pub fn predict_master(&self, features: &[f32; MASTER_FEATURE_COUNT]) -> Option<f32> {
        let trees = self.master_trees.as_ref()?;
        Some(trees.predict_probability(features))
    }

    /// Generic whole-buffer string/entropy model (20 features, no file-type parsing).
    pub fn predict_generic(&self, features: &[f32; GENERIC_FEATURE_COUNT]) -> Option<f32> {
        let trees = self.generic_trees.as_ref()?;
        Some(trees.predict_probability(features))
    }

    pub fn master_loaded(&self) -> bool {
        self.master_trees.is_some()
    }

    pub fn generic_loaded(&self) -> bool {
        self.generic_trees.is_some()
    }

    pub fn is_loaded(&self) -> bool {
        self.pe_trees.is_some()
            || self.js_trees.is_some()
            || self.url_trees.is_some()
            || self.apk_trees.is_some()
            || self.master_trees.is_some()
            || self.generic_trees.is_some()
    }
}

impl Default for MlScanner {
    fn default() -> Self {
        Self::new()
    }
}
