use std::path::Path;

use super::pe_features;
use super::js_features;
use super::url_features;
use super::tree_model::TreeEnsembleModel;

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
    pub fn new(models_dir: &Path) -> Self {
        let pe_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees.bin"));
        let js_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("js_trees.bin"));
        let url_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("url_trees.bin"));
        let apk_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("apk_trees.bin"));
        let generic_trees =
            TreeEnsembleModel::from_bin_file(&models_dir.join("generic_trees.bin"));

        Self {
            pe_trees,
            js_trees,
            url_trees,
            apk_trees,
            master_trees: None,
            generic_trees,
        }
    }

    /// Runtime model load from bytes (web parity: kind 0=PE, 1=JS, 2=URL, 3=APK,
    /// 4=legacy master router, 5=generic whole-buffer model).
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
            4 => self.master_trees = Some(model),
            5 => self.generic_trees = Some(model),
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

    pub fn pe_loaded(&self) -> bool {
        self.pe_trees.is_some()
    }

    pub fn js_loaded(&self) -> bool {
        self.js_trees.is_some()
    }

    pub fn url_loaded(&self) -> bool {
        self.url_trees.is_some()
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[cfg(target_os = "windows")]
    #[test]
    fn scan_pid_self_and_invalid() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let engine = crate::engine::StaticEngine::init(&dir);
        let me = std::process::id();
        let r = engine.scan_pid(me, 64);
        assert!(
            r.regions_scanned > 0,
            "own process must yield regions"
        );
        assert!(
            r.bytes_scanned > 0 && r.bytes_scanned <= 64 << 20,
            "cap respected: {}",
            r.bytes_scanned
        );
        let bad = engine.scan_pid(999_999_999, 1);
        assert_eq!(bad.verdict, "Error");
    }

    fn models_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("models")
    }

    #[test]
    fn native_bins_load_and_score() {
        let dir = models_dir();
        let s = MlScanner::new(&dir);
        assert!(s.url_loaded(), "url_trees.bin must load");
        assert!(s.generic_loaded(), "generic_trees.bin must load");

        // Exact parity with the Python exporter (max diff ~1e-7 there; 1e-6 here).
        let g = s.predict_generic(&[0.0; GENERIC_FEATURE_COUNT]).unwrap();
        assert!((g - 5.156021e-6).abs() < 1e-6, "generic zeros20 = {g}");
    }
}
