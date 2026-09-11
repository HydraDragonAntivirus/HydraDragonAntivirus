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

static PE_MODEL: OnceLock<&'static super::model::MalwareNet<InferBackend>> = OnceLock::new();
static JS_MODEL: OnceLock<&'static super::model::MalwareNet<InferBackend>> = OnceLock::new();

pub(crate) fn get_pe_model_ref() -> Option<&'static super::model::MalwareNet<InferBackend>> {
    get_pe_model()
}

pub(crate) fn get_js_model_ref() -> Option<&'static super::model::MalwareNet<InferBackend>> {
    get_js_model()
}

/// Resolve an ML model file across all runtime contexts:
/// 1. Registry HKLM\SOFTWARE\Owlyshield\SDK (DATABASE_PATH/MODELS_PATH) with 64/32-bit hive support
/// 2. Loaded module directory (owlyshield_ransom.dll or companion DLL)
/// 3. current_exe directory
/// 4. Default installation directories (Program Files)
/// 5. CWD-relative models/ (dev / tests)
fn model_path(file: &str) -> Option<std::path::PathBuf> {
    #[cfg(windows)]
    {
        use winreg::RegKey;
        use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
        for flags in [KEY_READ | KEY_WOW64_64KEY, KEY_READ] {
            if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(r"SOFTWARE\Owlyshield\SDK", flags) {
                if let Ok(p) = key.get_value::<String, _>("MODELS_PATH") {
                    let cand = std::path::PathBuf::from(&p).join(file);
                    if cand.is_file() {
                        return Some(cand);
                    }
                }
                if let Ok(p) = key.get_value::<String, _>("DATABASE_PATH") {
                    let pb = std::path::PathBuf::from(&p);
                    if let Some(parent) = pb.parent() {
                        let cand = parent.join("models").join(file);
                        if cand.is_file() {
                            return Some(cand);
                        }
                    }
                }
            }
        }
    }

    if let Some(dll_dir) = crate::utils::current_module_dir() {
        let cand = dll_dir.join("models").join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let cand = dir.join("models").join(file);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }

    for install_base in [
        r"C:\Program Files\HydraDragonAntivirus\OpenEDR\models",
        r"C:\Program Files (x86)\HydraDragonAntivirus\OpenEDR\models",
    ] {
        let cand = std::path::PathBuf::from(install_base).join(file);
        if cand.is_file() {
            return Some(cand);
        }
    }

    let cand = Path::new("models").join(file);
    if cand.is_file() {
        return Some(cand);
    }
    None
}

fn get_pe_model() -> Option<&'static super::model::MalwareNet<InferBackend>> {
    if let Some(m) = PE_MODEL.get() {
        return Some(*m);
    }

    static LAST_TRY: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    if let Ok(mut guard) = LAST_TRY.lock() {
        if let Some(prev) = *guard {
            if prev.elapsed() < std::time::Duration::from_secs(3) {
                return None;
            }
        }
        *guard = Some(std::time::Instant::now());
    }

    let Some(path) = model_path("pe_model.mpk") else {
        crate::Logging::error(
            "[FastDetect] PE ML model not found in registry, DLL dir, current_exe or models\\pe_model.mpk",
        );
        return None;
    };
    if let Some(model) = load_ml_model(&path, super::model::MalwareNetConfig::default()) {
        crate::Logging::info(&format!(
            "[FastDetect] Loaded PE ML model from {}",
            path.display()
        ));
        let leaked: &'static _ = Box::leak(Box::new(model));
        let _ = PE_MODEL.set(leaked);
        return Some(leaked);
    }
    crate::Logging::error(&format!(
        "[FastDetect] PE ML model failed to load from {}",
        path.display()
    ));
    None
}

fn get_js_model() -> Option<&'static super::model::MalwareNet<InferBackend>> {
    if let Some(m) = JS_MODEL.get() {
        return Some(*m);
    }

    static LAST_TRY: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    if let Ok(mut guard) = LAST_TRY.lock() {
        if let Some(prev) = *guard {
            if prev.elapsed() < std::time::Duration::from_secs(3) {
                return None;
            }
        }
        *guard = Some(std::time::Instant::now());
    }

    let Some(path) = model_path("js_model.mpk") else {
        crate::Logging::error(
            "[FastDetect] JS ML model not found in registry, DLL dir, current_exe or models\\js_model.mpk",
        );
        return None;
    };
    if let Some(model) = load_ml_model(&path, super::model::MalwareNetConfig::default_js()) {
        crate::Logging::info(&format!(
            "[FastDetect] Loaded JS ML model from {}",
            path.display()
        ));
        let leaked: &'static _ = Box::leak(Box::new(model));
        let _ = JS_MODEL.set(leaked);
        return Some(leaked);
    }
    crate::Logging::error(&format!(
        "[FastDetect] JS ML model failed to load from {}",
        path.display()
    ));
    None
}

fn load_ml_model(
    path: &Path,
    config: super::model::MalwareNetConfig,
) -> Option<super::model::MalwareNet<InferBackend>> {
    let bytes = crate::utils::read_file_shared(path).ok()?;
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

/// Detects PE executables and JavaScript by CONTENT (never by extension —
/// renamed samples must not escape). File typing comes from the ClamAV engine;
/// JS additionally requires an ASCII body that trial-parses as code.
/// Uses 0.875 threshold and no custom whitelisting/signature rules as explicitly requested.
pub fn fast_detect_file(path_str: &str, _iomsg: &IOMessage) -> Option<FastDetectionResult> {
    fast_detect_path(path_str)
}

/// Detects PE executables and JavaScript by CONTENT (never by extension —
/// renamed samples must not escape). File typing comes from the ClamAV engine;
/// JS additionally requires an ASCII body that trial-parses as code.
/// Uses 0.875 threshold and no custom whitelisting/signature rules as explicitly requested.
pub fn fast_detect_path(path_str: &str) -> Option<FastDetectionResult> {
    let path = Path::new(path_str);
    if !path.exists() || !path.is_file() {
        return None;
    }

    // Read the file bytes with shared permissions (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
    // so in-flight writes or file copies do not fail with ERROR_SHARING_VIOLATION.
    if let Ok(bytes) = crate::utils::read_file_shared(path) {

        if crate::clamscan::is_pe_bytes(&bytes) {
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
        }
        if crate::clamscan::is_js_candidate(&bytes) {
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
