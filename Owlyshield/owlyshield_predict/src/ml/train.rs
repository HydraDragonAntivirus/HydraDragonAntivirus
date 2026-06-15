use burn::module::Module;
use burn::nn;
use burn::nn::loss::CrossEntropyLoss;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::prelude::*;
use burn::tensor::backend::ADBackend;

use super::features::PeFeatureVector;

#[derive(Debug, Clone)]
pub struct Sample {
    pub features: Vec<f32>,
    pub label: usize,
}

#[derive(Module, Debug, Clone)]
pub struct MalwareNet<B: Backend> {
    fc1: nn::Linear<B>,
    fc2: nn::Linear<B>,
    fc3: nn::Linear<B>,
    dropout: nn::Dropout,
}

#[derive(Debug, Clone)]
pub struct MalwareNetConfig {
    pub input_dim: usize,
    pub hidden_dim: usize,
    pub num_classes: usize,
}

impl Default for MalwareNetConfig {
    fn default() -> Self {
        Self {
            input_dim: PeFeatureVector::LEN,
            hidden_dim: 64,
            num_classes: 2,
        }
    }
}

impl<B: Backend> MalwareNet<B> {
    pub fn new(config: &MalwareNetConfig, device: &B::Device) -> Self {
        Self {
            fc1: nn::Linear::new(nn::LinearConfig::new(config.input_dim, config.hidden_dim), device),
            fc2: nn::Linear::new(nn::LinearConfig::new(config.hidden_dim, config.hidden_dim / 2), device),
            fc3: nn::Linear::new(nn::LinearConfig::new(config.hidden_dim / 2, config.num_classes), device),
            dropout: nn::Dropout::new(nn::DropoutConfig::new(0.3)),
        }
    }

    pub fn forward(&self, input: Tensor<B, 2>) -> Tensor<B, 2> {
        let x = self.fc1.forward(input);
        let x = x.relu();
        let x = self.dropout.forward(x);
        let x = self.fc2.forward(x);
        let x = x.relu();
        let x = self.fc3.forward(x);
        x
    }
}

fn flatten_batch(samples: &[Sample], input_dim: usize) -> (Vec<f32>, Vec<i64>) {
    let mut features = Vec::with_capacity(samples.len() * input_dim);
    let mut labels = Vec::with_capacity(samples.len());
    for s in samples {
        features.extend_from_slice(&s.features);
        labels.push(s.label as i64);
    }
    (features, labels)
}

pub fn train_model<B: ADBackend>(
    device: B::Device,
    samples: Vec<Sample>,
    config: MalwareNetConfig,
    epochs: usize,
    batch_size: usize,
    lr: f64,
) -> MalwareNet<B> {
    let mut model = MalwareNet::<B>::new(&config, &device);
    let mut optim = AdamConfig::new().init::<B, MalwareNet<B>>();
    let loss_fn = CrossEntropyLoss::new(None, &device);

    let n = samples.len();
    for epoch in 0..epochs {
        let mut total_loss = 0.0f64;
        let mut n_batches = 0usize;

        for chunk in samples.chunks(batch_size) {
            let (flat_features, flat_labels) = flatten_batch(chunk, config.input_dim);
            let batch_n = chunk.len();

            let input = Tensor::<B, 2>::from_floats(flat_features.as_slice(), &device)
                .reshape([batch_n, config.input_dim]);
            let targets = Tensor::<B, 1, Int>::from_ints(flat_labels.as_slice(), &device)
                .reshape([batch_n]);

            let output = model.forward(input);
            let loss = loss_fn.forward(output, targets);

            let grads = loss.backward();
            let grads_params = GradientsParams::from_grads(grads, &model);
            model = optim.step(lr, model, grads_params);
            model = model.to_device(&device);

            total_loss += loss.to_scalar();
            n_batches += 1;
        }

        let avg_loss = total_loss / n_batches as f64;
        log::info!("Epoch {}: loss = {:.6}", epoch + 1, avg_loss);
    }

    model
}
