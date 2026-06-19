use crate::database::{Database, OffsetAnchor, SourceLocation};
use crate::logical::Subsignature;
use crate::pe::{parse_pe, PeInfo};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub struct Engine {
    pub database: Database,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanOptions {
    pub strict_targets: bool,
    pub max_matches: usize,
    pub max_subsignature_matches: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            strict_targets: false,
            max_matches: 128,
            max_subsignature_matches: 4096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanMatch {
    pub name: String,
    pub kind: SignatureKind,
    pub source: SourceLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureKind {
    Extended,
    Logical,
}

pub(crate) struct ScanContext<'a> {
    pub data: &'a [u8],
    pub pe: Option<PeInfo>,
}

impl Engine {
    pub fn from_database_dir(path: impl AsRef<Path>) -> io::Result<(Self, crate::LoadReport)> {
        let (database, report) = Database::load_dir(path)?;
        Ok((Self { database }, report))
    }

    pub fn scan_path(
        &self,
        path: impl AsRef<Path>,
        options: ScanOptions,
    ) -> io::Result<Vec<ScanMatch>> {
        let data = fs::read(path)?;
        Ok(self.scan_bytes(&data, options))
    }

    pub fn scan_bytes(&self, data: &[u8], options: ScanOptions) -> Vec<ScanMatch> {
        let ctx = ScanContext {
            data,
            pe: parse_pe(data),
        };
        let mut matches = Vec::new();
        self.scan_extended(&ctx, options, &mut matches);
        if matches.len() < options.max_matches {
            self.scan_logical(&ctx, options, &mut matches);
        }
        matches
    }

    fn scan_extended(
        &self,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        for signature in &self.database.extended {
            if matches.len() >= options.max_matches {
                return;
            }
            if !target_matches(signature.target, ctx, options.strict_targets) {
                continue;
            }
            if matches!(
                signature.offset.anchor,
                OffsetAnchor::Unsupported(_)
                    | OffsetAnchor::MacroGroup(_)
                    | OffsetAnchor::VersionInfo
            ) {
                continue;
            }
            let ranges = signature
                .offset
                .scan_ranges(ctx.data.len(), ctx.pe.as_ref());
            if ranges.is_empty() {
                continue;
            }
            if signature
                .patterns
                .iter()
                .any(|pattern| !pattern.find_all(ctx.data, &ranges, 1).is_empty())
            {
                matches.push(ScanMatch {
                    name: signature.name.clone(),
                    kind: SignatureKind::Extended,
                    source: signature.source.clone(),
                });
            }
        }
    }

    fn scan_logical(
        &self,
        ctx: &ScanContext<'_>,
        options: ScanOptions,
        matches: &mut Vec<ScanMatch>,
    ) {
        for signature in &self.database.logical {
            if matches.len() >= options.max_matches {
                return;
            }
            if !target_matches(signature.target, ctx, options.strict_targets) {
                continue;
            }
            let mut counts = Vec::with_capacity(signature.subsignatures.len());
            for subsig in &signature.subsignatures {
                counts.push(match subsig {
                    Subsignature::Body {
                        offset, patterns, ..
                    } => {
                        if matches!(
                            offset.anchor,
                            OffsetAnchor::Unsupported(_)
                                | OffsetAnchor::MacroGroup(_)
                                | OffsetAnchor::VersionInfo
                        ) {
                            0
                        } else {
                            let ranges = offset.scan_ranges(ctx.data.len(), ctx.pe.as_ref());
                            if ranges.is_empty() {
                                0
                            } else {
                                count_pattern_matches(
                                    patterns,
                                    ctx.data,
                                    &ranges,
                                    options.max_subsignature_matches,
                                )
                            }
                        }
                    }
                    Subsignature::Unsupported { .. } => 0,
                });
            }

            if signature.expression.eval(&counts).matched {
                matches.push(ScanMatch {
                    name: signature.name.clone(),
                    kind: SignatureKind::Logical,
                    source: signature.source.clone(),
                });
            }
        }
    }
}

fn count_pattern_matches(
    patterns: &[crate::pattern::Pattern],
    data: &[u8],
    ranges: &[(usize, usize)],
    limit: usize,
) -> usize {
    let mut count = 0usize;
    for pattern in patterns {
        let remaining = limit.saturating_sub(count);
        if remaining == 0 {
            break;
        }
        count += pattern.find_all(data, ranges, remaining).len();
    }
    count
}

fn target_matches(target: Option<u32>, ctx: &ScanContext<'_>, strict: bool) -> bool {
    if !strict {
        return true;
    }

    match target.unwrap_or(0) {
        0 => true,
        1 => ctx.pe.is_some(),
        3 => looks_like_html(ctx.data),
        7 => looks_like_ascii_text(ctx.data),
        _ => true,
    }
}

fn looks_like_ascii_text(data: &[u8]) -> bool {
    data.iter()
        .all(|byte| matches!(*byte, b'\t' | b'\n' | b'\r' | 0x20..=0x7e))
}

fn looks_like_html(data: &[u8]) -> bool {
    let sample_len = data.len().min(4096);
    let sample = &data[..sample_len];
    contains_ascii_case_insensitive(sample, b"<html")
        || contains_ascii_case_insensitive(sample, b"<!doctype html")
        || contains_ascii_case_insensitive(sample, b"<script")
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.to_ascii_lowercase() == right.to_ascii_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{ExtendedSignature, OffsetSpec, SourceLocation};
    use crate::pattern::{compile_pattern_variants, Modifiers};
    use std::path::PathBuf;

    #[test]
    fn scans_extended_signature() {
        let source = SourceLocation {
            path: PathBuf::from("test.ndb"),
            line: 1,
        };
        let database = Database {
            extended: vec![ExtendedSignature {
                name: "Test.Signature".to_string(),
                target: Some(0),
                offset: OffsetSpec::any(),
                patterns: compile_pattern_variants("414243", Modifiers::default()).unwrap(),
                source: source.clone(),
            }],
            logical: Vec::new(),
            unsupported: Vec::new(),
        };
        let engine = Engine { database };
        let found = engine.scan_bytes(b"xxABCyy", ScanOptions::default());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Test.Signature");
        assert_eq!(found[0].source, source);
    }
}
