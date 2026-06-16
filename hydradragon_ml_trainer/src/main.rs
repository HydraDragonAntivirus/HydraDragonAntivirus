use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use burn::backend::ndarray::NdArrayDevice;
use burn::module::{AutodiffModule, Module};
use burn::nn::loss::CrossEntropyLoss;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::prelude::*;
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder};
use burn::tensor::backend::{AutodiffBackend, BackendTypes};
use clap::{Parser, Subcommand};
use rand::rng;
use rand::seq::SliceRandom;
use rayon::prelude::*;

mod ml;

use ml::features::{JsFeatureVector, PeFeatureVector};
use ml::model::{MalwareNet, MalwareNetConfig};

#[derive(Parser)]
#[command(
    name = "hydradragon-ml-trainer",
    version,
    about = "Train HydraDragonAV PE/JS ML scanner models"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Train a PE model from malicious and benign executable folders.
    Pe(TrainArgs),
    /// Train a JavaScript model from malicious and benign script folders.
    Js(TrainArgs),
}

#[derive(Parser, Debug, Clone)]
struct TrainArgs {
    /// Directory containing malicious samples.
    #[arg(long)]
    malicious: PathBuf,

    /// Directory containing benign samples.
    #[arg(long)]
    benign: PathBuf,

    /// Output model path without or with .mpk extension.
    #[arg(long)]
    output: PathBuf,

    /// Training epochs.
    #[arg(long, default_value_t = 10)]
    epochs: usize,

    /// Batch size.
    #[arg(long, default_value_t = 64)]
    batch_size: usize,

    /// Adam learning rate.
    #[arg(long, default_value_t = 0.001)]
    lr: f64,

    /// Feature extraction worker threads. 0 uses all logical CPU cores.
    #[arg(long, default_value_t = 0)]
    threads: usize,
}

#[derive(Debug, Clone)]
struct Sample {
    features: Vec<f32>,
    label: usize,
}

fn main() {
    let cli = Cli::parse();

    let threads = match &cli.command {
        Command::Pe(args) | Command::Js(args) => args.threads,
    };

    if threads > 0 {
        if let Err(err) = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
        {
            exit_with(format!("failed to configure rayon thread pool: {err}"));
        }
    }

    match cli.command {
        Command::Pe(args) => run_pe(args),
        Command::Js(args) => run_js(args),
    }
}

fn run_pe(args: TrainArgs) {
    validate_dirs(&args);

    let mut samples = Vec::new();
    collect_pe_samples(&args.malicious, 1, &mut samples);
    collect_pe_samples(&args.benign, 0, &mut samples);

    train_or_exit(samples, MalwareNetConfig::default(), args);
}

fn run_js(args: TrainArgs) {
    validate_dirs(&args);

    let mut samples = Vec::new();
    collect_js_samples(&args.malicious, 1, &mut samples);
    collect_js_samples(&args.benign, 0, &mut samples);

    train_or_exit(samples, MalwareNetConfig::default_js(), args);
}

fn validate_dirs(args: &TrainArgs) {
    if !args.malicious.is_dir() {
        exit_with(format!(
            "malicious directory not found: {}",
            args.malicious.display()
        ));
    }
    if !args.benign.is_dir() {
        exit_with(format!(
            "benign directory not found: {}",
            args.benign.display()
        ));
    }
    if args.epochs == 0 {
        exit_with("epochs must be greater than zero");
    }
    if args.batch_size == 0 {
        exit_with("batch-size must be greater than zero");
    }
}

fn collect_pe_samples(dir: &Path, label: usize, samples: &mut Vec<Sample>) {
    let files = walk_files(dir);
    let total = files.len();
    let processed = AtomicUsize::new(0);
    let valid_start = samples.len();

    let mut collected: Vec<Sample> = files
        .par_iter()
        .filter_map(|path| {
            let index = processed.fetch_add(1, Ordering::Relaxed);
            if index % 250 == 0 {
                eprintln!(
                    "pe features label={label}: {}/{} files, {} valid samples",
                    index, total, valid_start
                );
            }

            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(err) => {
                    eprintln!("skip {}: {}", path.display(), err);
                    return None;
                }
            };

            let features: PeFeatureVector = ml::pe_features::extract_pe_features(&bytes)?;

            Some(Sample {
                features: features.to_array().to_vec(),
                label,
            })
        })
        .collect();

    samples.append(&mut collected);

    eprintln!(
        "pe features label={label}: {}/{} files, {} valid samples",
        total,
        total,
        samples.len()
    );
}

fn collect_js_samples(dir: &Path, label: usize, samples: &mut Vec<Sample>) {
    let files = walk_files(dir);
    let total = files.len();
    let processed = AtomicUsize::new(0);
    let valid_start = samples.len();

    let mut collected: Vec<Sample> = files
        .par_iter()
        .filter_map(|path| {
            let index = processed.fetch_add(1, Ordering::Relaxed);
            if index % 500 == 0 {
                eprintln!(
                    "js features label={label}: {}/{} files, {} valid samples",
                    index, total, valid_start
                );
            }

            let source = match std::fs::read_to_string(&path) {
                Ok(source) => source,
                Err(err) => {
                    eprintln!("skip {}: {}", path.display(), err);
                    return None;
                }
            };

            let features: JsFeatureVector = ml::js_features::extract_js_features(&source)?;

            Some(Sample {
                features: features.to_array().to_vec(),
                label,
            })
        })
        .collect();

    samples.append(&mut collected);

    eprintln!(
        "js features label={label}: {}/{} files, {} valid samples",
        total,
        total,
        samples.len()
    );
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];

    while let Some(current) = stack.pop() {
        let entries = match std::fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!("skip directory {}: {}", current.display(), err);
                continue;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    files
}

fn train_or_exit(samples: Vec<Sample>, config: MalwareNetConfig, args: TrainArgs) {
    let malicious = samples.iter().filter(|sample| sample.label == 1).count();
    let benign = samples.len().saturating_sub(malicious);

    eprintln!("samples: {malicious} malicious, {benign} benign");
    if malicious == 0 || benign == 0 {
        exit_with("need at least one valid malicious and one valid benign sample");
    }

    type Backend = burn::backend::NdArray<f32>;
    type ADBackend = burn::backend::Autodiff<Backend>;

    let device = NdArrayDevice::Cpu;

    let model = train_model::<ADBackend>(
        <ADBackend as BackendTypes>::Device::from(device),
        samples,
        config,
        args.epochs,
        args.batch_size,
        args.lr,
    );

    let output = normalize_output_path(&args.output);
    if let Some(parent) = output.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            exit_with(format!(
                "cannot create output directory {}: {err}",
                parent.display()
            ));
        }
    }

    let infer_model: MalwareNet<Backend> = model.valid();
    let recorder = NamedMpkFileRecorder::<FullPrecisionSettings>::new();
    let save_base = output.with_extension("");
    if let Err(err) = infer_model.save_file(save_base, &recorder) {
        exit_with(format!("failed to save model: {err}"));
    }

    eprintln!("model saved: {}", output.display());
}

fn train_model<B: AutodiffBackend>(
    device: B::Device,
    mut samples: Vec<Sample>,
    config: MalwareNetConfig,
    epochs: usize,
    batch_size: usize,
    lr: f64,
) -> MalwareNet<B> {
    let mut model = MalwareNet::<B>::new(&config, &device);
    let mut optimizer = AdamConfig::new().init::<B, MalwareNet<B>>();
    let loss_fn = CrossEntropyLoss::new(None, &device);

    for epoch in 1..=epochs {
        samples.shuffle(&mut rng());

        let mut total_loss = 0.0f64;
        let mut batches = 0usize;

        for chunk in samples.chunks(batch_size) {
            let batch_len = chunk.len();
            let (features, labels) = flatten_batch(chunk, config.input_dim);

            let input = Tensor::<B, 1>::from_floats(features.as_slice(), &device)
                .reshape([batch_len, config.input_dim]);
            let targets =
                Tensor::<B, 1, Int>::from_ints(labels.as_slice(), &device).reshape([batch_len]);

            let output = model.forward(input);
            let loss = loss_fn.forward(output, targets);
            let loss_value: f32 = loss.clone().into_scalar().elem();
            let grads = loss.backward();
            let grads = GradientsParams::from_grads(grads, &model);

            model = optimizer.step(lr, model, grads);
            model = model.to_device(&device);

            total_loss += f64::from(loss_value);
            batches += 1;
        }

        eprintln!(
            "epoch {epoch}/{epochs}: loss {:.6}",
            total_loss / batches as f64
        );
    }

    model
}

fn flatten_batch(samples: &[Sample], input_dim: usize) -> (Vec<f32>, Vec<i64>) {
    let mut features = Vec::with_capacity(samples.len() * input_dim);
    let mut labels = Vec::with_capacity(samples.len());

    for sample in samples {
        if sample.features.len() != input_dim {
            continue;
        }
        features.extend_from_slice(&sample.features);
        labels.push(sample.label as i64);
    }

    (features, labels)
}

fn normalize_output_path(path: &Path) -> PathBuf {
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("mpk"))
    {
        path.to_path_buf()
    } else {
        path.with_extension("mpk")
    }
}

fn exit_with(message: impl AsRef<str>) -> ! {
    eprintln!("error: {}", message.as_ref());
    std::process::exit(1);
}
