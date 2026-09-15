use std::path::{Path, PathBuf};
use burn::backend::NdArray;
use burn::backend::ndarray::NdArrayDevice;
use burn::module::Module;
use burn::record::{NamedMpkBytesRecorder, Recorder};

use super::inference;
use super::model::MalwareNet;

pub type InferBackend = NdArray<f32>;

pub struct MlScanner {
    pe_model: Option<MalwareNet<InferBackend>>,
    js_model: Option<MalwareNet<InferBackend>>,
    device: NdArrayDevice,
}

impl MlScanner {
    pub fn new(models_dir: &Path) -> Self {
        let device = NdArrayDevice::default();
        let pe_model = Self::load_model(&models_dir.join("pe_model.mpk"), &device, super::model::MalwareNetConfig::default());
        let js_model = Self::load_model(&models_dir.join("js_model.mpk"), &device, super::model::MalwareNetConfig::default_js());

        Self {
            pe_model,
            js_model,
            device,
        }
    }

    fn load_model(path: &Path, device: &NdArrayDevice, config: super::model::MalwareNetConfig) -> Option<MalwareNet<InferBackend>> {
        if !path.is_file() {
            return None;
        }
        let bytes = std::fs::read(path).ok()?;
        let recorder = NamedMpkBytesRecorder::<burn::record::FullPrecisionSettings>::default();
        let record = recorder.load(bytes, device).ok()?;
        let model = MalwareNet::new(&config, device).load_record(record);
        Some(model)
    }

    pub fn predict_pe(&self, data: &[u8]) -> Option<f32> {
        let model = self.pe_model.as_ref()?;
        inference::predict_pe(data, model, &self.device)
    }

    pub fn predict_js(&self, source: &str) -> Option<f32> {
        let model = self.js_model.as_ref()?;
        inference::predict_js(source, model, &self.device)
    }

    pub fn is_loaded(&self) -> bool {
        self.pe_model.is_some() || self.js_model.is_some()
    }
}
