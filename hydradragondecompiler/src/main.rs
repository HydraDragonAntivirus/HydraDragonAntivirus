//! CLI front-end for `hydradragondecompiler`.
//!
//! Extracts strings from a file using the library's four passes and prints them
//! either as greppable `KIND\toffset\ttext` lines or as a JSON array.

use std::process::ExitCode;

use clap::Parser;

use hydradragondecompiler::{ExtractOptions, ExtractedString, StringKind, extract_from_path};

/// Decompiler-lite string extractor for PE binaries.
#[derive(Parser, Debug)]
#[command(
    name = "hydradragondecompiler",
    version,
    about = "Pull extra strings (ascii, wide, code-referenced, stack-built) out of binaries"
)]
struct Cli {
    /// File to extract strings from.
    file: std::path::PathBuf,

    /// Minimum string length to report.
    #[arg(long, default_value_t = 4)]
    min_len: usize,

    /// Disable the ASCII pass.
    #[arg(long)]
    no_ascii: bool,

    /// Disable the UTF-16LE wide pass.
    #[arg(long)]
    no_wide: bool,

    /// Disable the code-reference pass (PE only).
    #[arg(long)]
    no_code_refs: bool,

    /// Disable the stack-string pass (PE only).
    #[arg(long)]
    no_stack_strings: bool,

    /// Emit a JSON array instead of plain lines.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<(), Box<dyn std::error::Error>> {
    let opts = ExtractOptions {
        min_len: cli.min_len,
        ascii: !cli.no_ascii,
        wide: !cli.no_wide,
        code_refs: !cli.no_code_refs,
        stack_strings: !cli.no_stack_strings,
        ..ExtractOptions::default()
    };

    let strings = extract_from_path(&cli.file, &opts)?;

    if cli.json {
        let json = serde_json::to_string_pretty(&strings)?;
        println!("{json}");
    } else {
        for s in &strings {
            println!("{}\t{}\t{}", kind_label(&s.kind), offset_label(s), s.text);
        }
    }

    Ok(())
}

/// Short uppercase tag for a string kind.
fn kind_label(kind: &StringKind) -> &'static str {
    match kind {
        StringKind::Ascii => "ASCII",
        StringKind::Wide => "WIDE",
        StringKind::CodeRef => "CODEREF",
        StringKind::StackString => "STACK",
    }
}

/// Hex offset, or "-" when the string has no file offset (stack strings).
fn offset_label(s: &ExtractedString) -> String {
    match s.offset {
        Some(off) => format!("0x{off:x}"),
        None => "-".to_string(),
    }
}
