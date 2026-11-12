use burn::module::Module;
use burn::nn;
use burn::nn::{DropoutConfig, LinearConfig};
use burn::prelude::*;
use burn::tensor::activation;

use super::features::{JsFeatureVector, PeFeatureVector};

#[derive(Module, Debug)]
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
            hidden_dim: 512,
            num_classes: 2,
        }
    }
}

impl MalwareNetConfig {
    pub fn default_js() -> Self {
        Self {
            input_dim: JsFeatureVector::LEN,
            hidden_dim: 256,
            num_classes: 2,
        }
    }
}

impl<B: Backend> MalwareNet<B> {
    pub fn new(config: &MalwareNetConfig, device: &B::Device) -> Self {
        Self {
            fc1: LinearConfig::new(config.input_dim, config.hidden_dim).init(device),
            fc2: LinearConfig::new(config.hidden_dim, config.hidden_dim / 2).init(device),
            fc3: LinearConfig::new(config.hidden_dim / 2, config.num_classes).init(device),
            dropout: DropoutConfig::new(0.3).init(),
        }
    }

    pub fn forward(&self, input: Tensor<B, 2>) -> Tensor<B, 2> {
        let x = self.fc1.forward(input);
        let x = activation::relu(x);
        let x = self.dropout.forward(x);
        let x = self.fc2.forward(x);
        let x = activation::relu(x);
        let x = self.dropout.forward(x);
        let x = self.fc3.forward(x);
        x
    }
}
