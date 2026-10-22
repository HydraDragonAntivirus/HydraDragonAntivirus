use std::path::Path;

use super::pe_features;
use super::js_features;
use super::url_features;
use super::tree_model::TreeEnsembleModel;

/// Master router input width: [is_pe, is_js, is_apk, is_url, pe, js, apk, url].
pub const MASTER_FEATURE_COUNT: usize = 8;

pub struct MlScanner {
    pe_trees: Option<TreeEnsembleModel>,
    /// v2 PE model (`pe_trees_v2.bin`, `pe_combined` vector: shell + unpacked /
    /// extracted content + strings + .NET kind). Used instead of `pe_trees` when present.
    pe_v2_trees: Option<TreeEnsembleModel>,
    /// Dedicated model trained only on successfully unpacked inner PE features.
    pe_inner_trees: Option<TreeEnsembleModel>,
    js_trees: Option<TreeEnsembleModel>,
    url_trees: Option<TreeEnsembleModel>,
    apk_trees: Option<TreeEnsembleModel>,
    master_trees: Option<TreeEnsembleModel>,
}

impl MlScanner {
    pub fn new(models_dir: &Path) -> Self {
        let pe_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees.bin"));
        let pe_v2_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees_v2.bin"));
        let pe_inner_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("pe_trees_inner.bin"));
        let js_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("js_trees.bin"));
        let url_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("url_trees.bin"));
        let apk_trees = TreeEnsembleModel::from_bin_file(&models_dir.join("apk_trees.bin"));

        Self {
            pe_trees,
            pe_v2_trees,
            pe_inner_trees,
            js_trees,
            url_trees,
            apk_trees,
            master_trees: None,
        }
    }

    /// Runtime model load from bytes (web parity: kind 0=PE, 1=JS, 2=URL, 3=APK,
    /// 4=legacy master router; 5, the web edition's generic model, is not used here).
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
            _ => return false,
        }
        true
    }

    pub fn predict_pe(&self, data: &[u8]) -> Option<f32> {
        if let Some(arr) = super::pe_combined::extract_unpacked_inner_features(data) {
            return self.pe_inner_trees.as_ref().map(|m| m.predict_probability(&arr));
        }
        if let Some(trees) = self.pe_v2_trees.as_ref() {
            let arr = super::pe_combined::extract_pe_features_v2(data)?;
            return Some(trees.predict_probability(&arr));
        }
        let trees = self.pe_trees.as_ref()?;
        let features = pe_features::extract_pe_features(data)?;
        let arr = features.to_array();
        Some(trees.predict_probability(&arr))
    }

    /// Why the PE model scored this file: probability and every feature with its
    /// value and contribution to the log-odds, strongest first.
    pub fn explain_pe(&self, data: &[u8]) -> Option<MlExplanation> {
        if let Some(arr) = super::pe_combined::extract_unpacked_inner_features(data) {
            let inner = self.pe_inner_trees.as_ref()?;
            return Some(MlExplanation::new(inner.explain(&arr), &arr, super::pe_combined::pe_inner_feature_names_static()));
        }
        if let Some(trees) = self.pe_v2_trees.as_ref() {
            let arr = super::pe_combined::extract_pe_features_v2(data)?;
            return Some(MlExplanation::new(trees.explain(&arr), &arr, super::pe_combined::pe_v2_feature_names_static()));
        }
        let trees = self.pe_trees.as_ref()?;
        let arr = pe_features::extract_pe_features(data)?.to_array();
        Some(MlExplanation::new(trees.explain(&arr), &arr, &super::features::PeFeatureVector::NAMES))
    }

    /// Features of the PE model in use (145 for v2, 65 for v1; 0 when none is loaded).
    pub fn pe_feature_count(&self) -> usize {
        if self.pe_inner_trees.is_some() {
            super::pe_combined::PE_INNER_FEATURE_COUNT
        } else if self.pe_v2_trees.is_some() {
            super::pe_combined::PE_V2_FEATURE_COUNT
        } else if self.pe_trees.is_some() {
            super::features::PeFeatureVector::NAMES.len()
        } else {
            0
        }
    }

    /// Same as [`Self::explain_pe`] for the JavaScript model.
    pub fn explain_js(&self, source: &str) -> Option<MlExplanation> {
        let trees = self.js_trees.as_ref()?;
        let arr = js_features::extract_js_features(source)?.to_array();
        Some(MlExplanation::new(trees.explain(&arr), &arr, &super::features::JsFeatureVector::NAMES))
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
        self.pe_trees.is_some() || self.pe_v2_trees.is_some() || self.pe_inner_trees.is_some()
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

    pub fn master_loaded(&self) -> bool {
        self.master_trees.is_some()
    }

    pub fn is_loaded(&self) -> bool {
        self.pe_trees.is_some()
            || self.pe_v2_trees.is_some()
            || self.pe_inner_trees.is_some()
            || self.js_trees.is_some()
            || self.url_trees.is_some()
            || self.apk_trees.is_some()
            || self.master_trees.is_some()
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
    }
}

/// One feature's part in an ML verdict.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MlFeatureContribution {
    pub name: &'static str,
    pub value: f32,
    /// Change in log-odds this feature caused (positive = towards malware).
    pub contribution: f32,
}

/// Probability and per-feature attribution of a tree-model score.
#[derive(Clone, Debug, serde::Serialize)]
pub struct MlExplanation {
    pub probability: f32,
    pub raw_score: f32,
    pub bias: f32,
    /// Sorted by |contribution|, largest first; zero contributions dropped.
    pub features: Vec<MlFeatureContribution>,
}

impl MlExplanation {
    fn new(e: super::tree_model::TreeExplanation, values: &[f32], names: &[&'static str]) -> Self {
        let mut features: Vec<MlFeatureContribution> = e
            .contributions
            .iter()
            .enumerate()
            .filter(|(_, c)| c.abs() > 1e-6)
            .map(|(i, &c)| MlFeatureContribution {
                name: names.get(i).copied().unwrap_or("?"),
                value: values.get(i).copied().unwrap_or(0.0),
                contribution: c,
            })
            .collect();
        features.sort_by(|a, b| b.contribution.abs().partial_cmp(&a.contribution.abs()).unwrap_or(std::cmp::Ordering::Equal));
        Self { probability: e.probability, raw_score: e.raw_score, bias: e.bias, features }
    }
}
