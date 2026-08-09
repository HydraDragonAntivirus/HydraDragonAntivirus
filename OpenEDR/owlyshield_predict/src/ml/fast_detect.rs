use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use burn::backend::NdArray;
use burn::backend::ndarray::NdArrayDevice;
use burn::module::Module;
use burn::record::NamedMpkBytesRecorder;
use burn::record::Recorder;
use crate::shared_def::IOMessage;
use crate::Logging;

pub type InferBackend = NdArray<f32>;

static PE_MODEL: OnceLock<Option<super::model::MalwareNet<InferBackend>>> = OnceLock::new();
static JS_MODEL: OnceLock<Option<super::model::MalwareNet<InferBackend>>> = OnceLock::new();

fn get_pe_model() -> &'static Option<super::model::MalwareNet<InferBackend>> {
    PE_MODEL.get_or_init(|| {
        let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        let paths = [
            exe_dir.join("models").join("pe_model.mpk"),
            exe_dir.join("pe_model.mpk"),
            PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models\pe_model.mpk"),
        ];
        for path in &paths {
            if path.exists() {
                if let Some(model) = load_ml_model(path, super::model::MalwareNetConfig::default()) {
                    Logging::info(&format!("[FastDetect] Loaded PE ML model from {}", path.display()));
                    return Some(model);
                }
            }
        }
        Logging::error("[FastDetect] PE ML model could not be found or loaded");
        None
    })
}

fn get_js_model() -> &'static Option<super::model::MalwareNet<InferBackend>> {
    JS_MODEL.get_or_init(|| {
        let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
        let paths = [
            exe_dir.join("models").join("js_model.mpk"),
            exe_dir.join("js_model.mpk"),
            PathBuf::from(r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models\js_model.mpk"),
        ];
        for path in &paths {
            if path.exists() {
                if let Some(model) = load_ml_model(path, super::model::MalwareNetConfig::default_js()) {
                    Logging::info(&format!("[FastDetect] Loaded JS ML model from {}", path.display()));
                    return Some(model);
                }
            }
        }
        Logging::error("[FastDetect] JS ML model could not be found or loaded");
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
}

/// Detects MZ executables and JavaScript files, applying the respective ML model if matched.
/// Uses 0.875 threshold and no custom whitelisting/signature rules as explicitly requested.
pub fn fast_detect_file(path_str: &str, _iomsg: &IOMessage) -> Option<FastDetectionResult> {
    let path = Path::new(path_str);
    if !path.exists() || !path.is_file() {
        return None;
    }

    let extension = path.extension()
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
                        return Some(FastDetectionResult {
                            detection_name: "MaliciousPeExecutable".to_string(),
                            reason: format!(
                                "PE ML engine detected malicious executable with {:.1}% probability",
                                prob * 100.0
                            ),
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
                            return Some(FastDetectionResult {
                                detection_name: "MaliciousJsScript".to_string(),
                                reason: format!(
                                    "JS ML engine detected malicious script with {:.1}% probability",
                                    prob * 100.0
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    None
}
