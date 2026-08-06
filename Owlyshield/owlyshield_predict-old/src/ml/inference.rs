use burn::prelude::*;
use burn::tensor::backend::Backend;

use super::features::{JsFeatureVector, PeFeatureVector};
use super::js_features;
use super::pe_features;

pub fn predict_pe<B: Backend>(
    bytes: &[u8],
    model: &super::train::MalwareNet<B>,
    device: &B::Device,
) -> Option<f32> {
    let features = pe_features::extract_pe_features(bytes)?;
    let arr = features.to_array();

    let input = Tensor::<B, 2>::from_floats(&[arr], device);
    let logits = model.forward(input);
    let probs = logits.softmax(1);
    let malware_prob = probs.slice([0..1, 1..2]).into_scalar();

    Some(malware_prob)
}

pub fn predict_js<B: Backend>(
    source: &str,
    model: &super::train::MalwareNet<B>,
    device: &B::Device,
) -> Option<f32> {
    let features = js_features::extract_js_features(source)?;
    let arr = features.to_array();

    let input = Tensor::<B, 2>::from_floats(&[arr], device);
    let logits = model.forward(input);
    let probs = logits.softmax(1);
    let malware_prob = probs.slice([0..1, 1..2]).into_scalar();

    Some(malware_prob)
}
