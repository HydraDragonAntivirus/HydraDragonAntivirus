use crate::Logging;
use crate::shared_def::IOMessage;
use burn::backend::NdArray;
use burn::backend::ndarray::NdArrayDevice;
use burn::module::Module;
use burn::record::NamedMpkBytesRecorder;
use burn::record::Recorder;
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

pub type InferBackend = NdArray<f32>;

static PE_MODEL: OnceLock<Option<super::model::MalwareNet<InferBackend>>> = OnceLock::new();
static JS_MODEL: OnceLock<Option<super::model::MalwareNet<InferBackend>>> = OnceLock::new();

fn get_pe_model() -> &'static Option<super::model::MalwareNet<InferBackend>> {
    PE_MODEL.get_or_init(|| {
        let path = Path::new("models/pe_model.mpk");
        if path.exists() {
            if let Some(model) = load_ml_model(path, super::model::MalwareNetConfig::default()) {
                Logging::info(&format!(
                    "[FastDetect] Loaded PE ML model from {}",
                    path.display()
                ));
                return Some(model);
            }
        }
        Logging::error(
            "[FastDetect] PE ML model could not be found or loaded from models/pe_model.mpk",
        );
        None
    })
}

fn get_js_model() -> &'static Option<super::model::MalwareNet<InferBackend>> {
    JS_MODEL.get_or_init(|| {
        let path = Path::new("models/js_model.mpk");
        if path.exists() {
            if let Some(model) = load_ml_model(path, super::model::MalwareNetConfig::default_js()) {
                Logging::info(&format!(
                    "[FastDetect] Loaded JS ML model from {}",
                    path.display()
                ));
                return Some(model);
            }
        }
        Logging::error(
            "[FastDetect] JS ML model could not be found or loaded from models/js_model.mpk",
        );
        None
    })
}

fn load_ml_model(
    path: &Path,
    config: super::model::MalwareNetConfig,
) -> Option<super::model::MalwareNet<InferBackend>> {
    let bytes = std::fs::read(path).ok()?;
    let device = NdArrayDevice::default();
    let record = NamedMpkBytesRecorder::<burn::record::FullPrecisionSettings>::default()
        .load(bytes, &device)
        .ok()?;
    Some(super::model::MalwareNet::new(&config, &device).load_record(record))
}

#[derive(Debug, Clone)]
pub struct FastDetectionResult {
    pub detection_name: String,
    pub reason: String,
    /// The ML feature vector (feature name -> value) that produced the
    /// detection. Populated so the behavior engine can expose these values
    /// (e.g. is_obfuscated, entropy, suspicious_score) as rule conditions.
    pub features: HashMap<String, f32>,
}

pub const PE_ML_DETECTION_NAME: &str = "MaliciousPeExecutable";
pub const JS_ML_DETECTION_NAME: &str = "MaliciousJsScript";

/// Returns true if the given detection name was produced by the fast static ML
/// engine (fast_detect_file), as opposed to a behavioral rule detection.
pub fn is_ml_detection_name(name: &str) -> bool {
    name == PE_ML_DETECTION_NAME || name == JS_ML_DETECTION_NAME
}

/// Detects MZ executables and JavaScript files, applying the respective ML model if matched.
/// Uses 0.875 threshold and no custom whitelisting/signature rules as explicitly requested.
pub fn fast_detect_file(path_str: &str, _iomsg: &IOMessage) -> Option<FastDetectionResult> {
    let path = Path::new(path_str);
    if !path.exists() || !path.is_file() {
        return None;
    }

    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default();

    // Read the file bytes to check the magic MZ header
    if let Ok(bytes) = std::fs::read(path) {
        let is_mz = bytes.len() >= 2 && &bytes[0..2] == b"MZ";

        if is_mz {
            // Run PE ML model prediction.
            if let Some(model) = get_pe_model() {
                let device = NdArrayDevice::default();
                if let Some(prob) = super::inference::predict_pe(&bytes, model, &device) {
                    if prob > 0.875 {
                        let features = super::pe_features::extract_pe_features(&bytes)
                            .map(|f| f.to_map())
                            .unwrap_or_default();
                        return Some(FastDetectionResult {
                            detection_name: PE_ML_DETECTION_NAME.to_string(),
                            reason: format!(
                                "PE ML engine detected malicious executable with {:.1}% probability",
                                prob * 100.0
                            ),
                            features,
                        });
                    }
                }
            }
        } else if extension == "js" {
            // Run JS ML model prediction.
            if let Some(model) = get_js_model() {
                if let Ok(content) = std::str::from_utf8(&bytes) {
                    let device = NdArrayDevice::default();
                    if let Some(prob) = super::inference::predict_js(content, model, &device) {
                        if prob > 0.875 {
                            let features = super::js_features::extract_js_features(content)
                                .map(|f| f.to_map())
                                .unwrap_or_default();
                            return Some(FastDetectionResult {
                                detection_name: JS_ML_DETECTION_NAME.to_string(),
                                reason: format!(
                                    "JS ML engine detected malicious script with {:.1}% probability",
                                    prob * 100.0
                                ),
                                features,
                            });
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Diagnostics: loads the repo model files and runs a short inference.
    /// Fails if a model file is missing OR the architecture/burn version no
    /// longer matches — distinguishes the "JS/PE ML not scanning" root cause.
    #[test]
    fn repo_models_load_and_infer() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let pe_path = manifest_dir.join("models").join("pe_model.mpk");
        let js_path = manifest_dir.join("models").join("js_model.mpk");

        let device = NdArrayDevice::default();

        let pe_model = load_ml_model(&pe_path, super::super::model::MalwareNetConfig::default());
        assert!(
            pe_model.is_some(),
            "PE model could not be loaded: {} (file exists? architecture matches?)",
            pe_path.display()
        );

        let js_model = load_ml_model(
            &js_path,
            super::super::model::MalwareNetConfig::default_js(),
        );
        assert!(
            js_model.is_some(),
            "JS model could not be loaded: {} (file exists? architecture matches?)",
            js_path.display()
        );

        // Once the models load, verify end-to-end inference too.
        if let Some(model) = &js_model {
            let js = "var x = 1; function go(){ eval('a'+'b'); } go();";
            let prob = super::super::inference::predict_js(js, model, &device)
                .expect("predict_js must not return None for valid JS");
            println!("JS model inference prob (benign sample): {}", prob);
            assert!((0.0..=1.0).contains(&prob), "invalid prob: {}", prob);
        }
    }
}
