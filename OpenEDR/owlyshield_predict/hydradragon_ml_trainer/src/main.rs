use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use burn::backend::ndarray::NdArrayDevice;
use burn::module::{AutodiffModule, Module};
use burn::nn::loss::CrossEntropyLoss;
use burn::optim::{AdamConfig, GradientsParams, Optimizer};
use burn::prelude::*;
use burn::record::{FullPrecisionSettings, NamedMpkFileRecorder};
use burn::tensor::activation;
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

    /// Validation split ratio (e.g. 0.1 for 10% validation). Set to 0 to disable.
    #[arg(long, default_value_t = 0.10)]
    val_split: f64,
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

    eprintln!("total samples collected: {malicious} malicious, {benign} benign");
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
        args.val_split,
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
    samples: Vec<Sample>,
    config: MalwareNetConfig,
    epochs: usize,
    batch_size: usize,
    lr: f64,
    val_split: f64,
) -> MalwareNet<B> {
    // Stratified train/validation split
    let mut benign_samples: Vec<Sample> = Vec::new();
    let mut mal_samples: Vec<Sample> = Vec::new();
    for s in samples {
        if s.label == 1 {
            mal_samples.push(s);
        } else {
            benign_samples.push(s);
        }
    }

    let mut rng = rng();
    benign_samples.shuffle(&mut rng);
    mal_samples.shuffle(&mut rng);

    let val_split_clamped = val_split.clamp(0.0, 0.5);
    let val_benign_count = if val_split_clamped > 0.0 && benign_samples.len() > 1 {
        ((benign_samples.len() as f64 * val_split_clamped).round() as usize)
            .clamp(1, benign_samples.len() - 1)
    } else {
        0
    };
    let val_mal_count = if val_split_clamped > 0.0 && mal_samples.len() > 1 {
        ((mal_samples.len() as f64 * val_split_clamped).round() as usize)
            .clamp(1, mal_samples.len() - 1)
    } else {
        0
    };

    let mut val_samples: Vec<Sample> = Vec::new();
    val_samples.extend(benign_samples.drain(..val_benign_count));
    val_samples.extend(mal_samples.drain(..val_mal_count));

    let train_benign = benign_samples.len();
    let train_mal = mal_samples.len();
    eprintln!(
        "train set: {} samples ({} mal, {} benign) | validation set: {} samples",
        train_mal + train_benign,
        train_mal,
        train_benign,
        val_samples.len()
    );

    eprintln!(
        "balanced batches enabled: 50% malicious / 50% benign per batch step"
    );

    let loss_fn = CrossEntropyLoss::new(None, &device);
    let mut model = MalwareNet::<B>::new(&config, &device);
    let mut optimizer = AdamConfig::new().init::<B, MalwareNet<B>>();

    let half_batch = (batch_size / 2).max(1);
    let max_class_len = train_mal.max(train_benign);
    let batches_per_epoch = (max_class_len + half_batch - 1) / half_batch;

    for epoch in 1..=epochs {
        benign_samples.shuffle(&mut rng);
        mal_samples.shuffle(&mut rng);

        let mut train_loss_sum = 0.0f64;

        for batch_idx in 0..batches_per_epoch {
            let mut batch: Vec<Sample> = Vec::with_capacity(half_batch * 2);

            for i in 0..half_batch {
                let b_idx = (batch_idx * half_batch + i) % benign_samples.len();
                batch.push(benign_samples[b_idx].clone());
            }

            for i in 0..half_batch {
                let m_idx = (batch_idx * half_batch + i) % mal_samples.len();
                batch.push(mal_samples[m_idx].clone());
            }

            batch.shuffle(&mut rng);

            let batch_len = batch.len();
            let (features, labels) = flatten_batch(&batch, config.input_dim);

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

            train_loss_sum += f64::from(loss_value);
        }

        let avg_train_loss = train_loss_sum / batches_per_epoch.max(1) as f64;

        if val_samples.is_empty() {
            eprintln!("epoch {epoch}/{epochs}: loss {:.6}", avg_train_loss);
        } else {
            let mut val_loss_sum = 0.0f64;
            let mut val_batches = 0usize;
            let mut tp = 0usize;
            let mut fn_cnt = 0usize;
            let mut tn = 0usize;
            let mut fp = 0usize;

            for chunk in val_samples.chunks(batch_size) {
                let batch_len = chunk.len();
                let (features, labels) = flatten_batch(chunk, config.input_dim);

                let input = Tensor::<B, 1>::from_floats(features.as_slice(), &device)
                    .reshape([batch_len, config.input_dim]);
                let targets = Tensor::<B, 1, Int>::from_ints(labels.as_slice(), &device)
                    .reshape([batch_len]);

                let output = model.forward(input);
                let loss = loss_fn.forward(output.clone(), targets);
                let loss_val: f32 = loss.into_scalar().elem();
                val_loss_sum += f64::from(loss_val);
                val_batches += 1;

                let probs = activation::softmax(output, 1);
                let mal_probs: Vec<f32> = probs
                    .slice([0..batch_len, 1..2])
                    .reshape([batch_len])
                    .into_data()
                    .to_vec()
                    .unwrap();

                for (mal_prob, &target) in mal_probs.into_iter().zip(labels.iter()) {
                    let pred = if mal_prob >= 0.50 { 1i64 } else { 0i64 };
                    match (target, pred) {
                        (1, 1) => tp += 1,
                        (1, 0) => fn_cnt += 1,
                        (0, 0) => tn += 1,
                        (0, 1) => fp += 1,
                        _ => {}
                    }
                }
            }

            let total_val = tp + fn_cnt + tn + fp;
            let val_acc = if total_val > 0 {
                (tp + tn) as f64 / total_val as f64 * 100.0
            } else {
                0.0
            };
            let recall = if tp + fn_cnt > 0 {
                tp as f64 / (tp + fn_cnt) as f64 * 100.0
            } else {
                0.0
            };
            let fpr = if fp + tn > 0 {
                fp as f64 / (fp + tn) as f64 * 100.0
            } else {
                0.0
            };
            let avg_val_loss = val_loss_sum / val_batches.max(1) as f64;

            eprintln!(
                "epoch {epoch}/{epochs}: loss {:.4} | val_loss {:.4} | val_acc {:.2}% | malware_recall {:.2}% | FPR {:.2}% [TP:{tp} FN:{fn_cnt} TN:{tn} FP:{fp}]",
                avg_train_loss, avg_val_loss, val_acc, recall, fpr
            );
        }
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
