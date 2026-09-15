use burn::prelude::*;
use burn::tensor::activation;
use burn::tensor::backend::Backend;

use super::js_features;
use super::pe_features;

pub fn predict_pe<B: Backend>(
    bytes: &[u8],
    model: &super::model::MalwareNet<B>,
    device: &B::Device,
) -> Option<f32> {
    let features = pe_features::extract_pe_features(bytes)?;
    let arr = features.to_array();

    let input = Tensor::<B, 1>::from_floats(arr.as_slice(), device)
        .reshape([1, super::features::PeFeatureVector::LEN]);
    let logits = model.forward(input);
    let probs = activation::softmax(logits, 1);

    let malware_prob: f32 = probs.slice([0..1, 1..2]).into_scalar().elem();

    Some(malware_prob)
}

pub fn predict_js<B: Backend>(
    source: &str,
    model: &super::model::MalwareNet<B>,
    device: &B::Device,
) -> Option<f32> {
    let features = js_features::extract_js_features(source)?;
    let arr = features.to_array();

    let input = Tensor::<B, 1>::from_floats(arr.as_slice(), device)
        .reshape([1, super::features::JsFeatureVector::LEN]);
    let logits = model.forward(input);
    let probs = activation::softmax(logits, 1);

    let malware_prob: f32 = probs.slice([0..1, 1..2]).into_scalar().elem();

    Some(malware_prob)
}
