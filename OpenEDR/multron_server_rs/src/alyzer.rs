//! VirusKovAlyzer in the dashboard: deep look at one file (kept upload or a path on
//! this server) plus a hex editor. Port of the Lazarus `UVirusKovAlyzer` form; the
//! static report itself is `analyzer::analyze` (hashes, PE headers, sections with
//! entropy, imports, exports, strings, indicators).
//!
//! A file is opened once into memory and gets a token; the hex editor then reads
//! byte ranges, searches and saves a patched COPY by token. The original file is
//! never written. At most `MAX_DOCS` files stay open (oldest dropped first).

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::dashboard::AppState;

const MAX_DOCS: usize = 4;
/// Largest file opened (it is held in memory).
pub const MAX_OPEN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RANGE: usize = 1024 * 1024;
const MAX_STRINGS: usize = 50_000;

struct Doc {
    token: String,
    name: String,
    source: String,
    data: Arc<Vec<u8>>,
}

fn docs() -> &'static Mutex<VecDeque<Doc>> {
    static D: OnceLock<Mutex<VecDeque<Doc>>> = OnceLock::new();
    D.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn doc(token: &str) -> Option<(String, Arc<Vec<u8>>)> {
    docs().lock().unwrap().iter().find(|d| d.token == token).map(|d| (d.name.clone(), Arc::clone(&d.data)))
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[derive(Deserialize)]
pub struct OpenBody {
    /// SHA-256 of a file kept in multron_incoming.
    #[serde(default)]
    sha256: String,
    /// Or a path on this server (the dashboard only answers on localhost).
    #[serde(default)]
    path: String,
}

/// Opens a file and returns its token, the static report, the engine/human verdict
/// we already have, and the signer seen at the last scan.
pub async fn handle_open(State(app): State<Arc<AppState>>, Json(b): Json<OpenBody>) -> Response {
    let eng = Arc::clone(&app.engine);
    let sha_in = b.sha256.trim().to_ascii_uppercase();
    let path_in = b.path.trim().trim_matches('"').to_string();
    let loaded = tokio::task::spawn_blocking(move || -> Result<(String, String, Vec<u8>), String> {
        if !sha_in.is_empty() {
            let k = eng.find_kept(&sha_in).ok_or("this file is not kept on the server (not uploaded, or moved by offload)")?;
            let data = k.read().ok_or("the kept file could not be read")?;
            Ok((k.name.clone(), k.path.display().to_string(), data))
        } else if !path_in.is_empty() {
            let p = PathBuf::from(&path_in);
            let meta = std::fs::metadata(&p).map_err(|e| format!("{path_in}: {e}"))?;
            if !meta.is_file() {
                return Err(format!("{path_in} is not a file"));
            }
            if meta.len() > MAX_OPEN_BYTES {
                return Err(format!("file is larger than {} MB", MAX_OPEN_BYTES / (1024 * 1024)));
            }
            let data = std::fs::read(&p).map_err(|e| format!("{path_in}: {e}"))?;
            let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
            Ok((name, path_in, data))
        } else {
            Err("give a SHA-256 of a kept file or a path".into())
        }
    })
    .await;
    let (name, source, data) = match loaded {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return err(StatusCode::BAD_REQUEST, e),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    if data.len() as u64 > MAX_OPEN_BYTES {
        return err(StatusCode::BAD_REQUEST, format!("file is larger than {} MB", MAX_OPEN_BYTES / (1024 * 1024)));
    }
    open_doc(&app, name, source, data).await
}

async fn open_doc(app: &Arc<AppState>, name: String, source: String, data: Vec<u8>) -> Response {
    let data = Arc::new(data);
    let (d2, n2) = (Arc::clone(&data), name.clone());
    let report = match tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| crate::analyzer::analyze(&d2, &n2))).ok()
    })
    .await
    {
        Ok(Some(r)) => r,
        _ => return err(StatusCode::INTERNAL_SERVER_ERROR, "the analyzer failed on this file"),
    };
    let sha = report.hashes.sha256.to_ascii_lowercase();
    let token = format!("{}-{}", &sha[..16.min(sha.len())], chrono::Utc::now().timestamp_millis());
    {
        let mut g = docs().lock().unwrap();
        g.push_back(Doc { token: token.clone(), name: name.clone(), source: source.clone(), data: Arc::clone(&data) });
        while g.len() > MAX_DOCS {
            g.pop_front();
        }
    }
    let insight = app.threat_intel.get(&sha);
    let review = app.threat_intel.reviews.get(&sha);
    let cached = crate::cache::parse_sha(&sha).and_then(|s| app.scan_server.cache.get(&s));
    Json(serde_json::json!({
        "ok": true,
        "token": token,
        "name": name,
        "source": source,
        "size": data.len(),
        "report": report,
        "engine": insight.as_ref().map(|i| serde_json::json!({
            "verdict": i.verdict, "threat": i.threat_name, "seen": i.seen_count,
            "first_seen": i.first_seen, "last_seen": i.last_seen, "file_names": i.file_names, "folders": i.folders,
        })),
        "engine_detail": cached.as_ref().and_then(|c| c.detail.clone()),
        "signer": insight.as_ref().and_then(|i| i.signer.clone()),
        "human": review.as_ref().map(|r| r.to_dashboard_json()),
    }))
    .into_response()
}

#[derive(Deserialize)]
pub struct RangeQuery {
    token: String,
    #[serde(default)]
    offset: u64,
    #[serde(default)]
    len: usize,
}

/// Raw bytes [offset, offset+len) of an open file (len capped at 1 MB).
pub async fn handle_bytes(Query(q): Query<RangeQuery>) -> Response {
    let Some((_, data)) = doc(&q.token) else { return err(StatusCode::NOT_FOUND, "file is not open any more, open it again") };
    let start = (q.offset as usize).min(data.len());
    let end = start.saturating_add(q.len.clamp(1, MAX_RANGE)).min(data.len());
    (
        [(header::CONTENT_TYPE, "application/octet-stream"), (header::CACHE_CONTROL, "no-store")],
        data[start..end].to_vec(),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct SearchQuery {
    token: String,
    /// Hex bytes to find, e.g. "4d5a90" (the page turns ASCII / UTF-16 text into hex).
    pattern: String,
    #[serde(default)]
    from: u64,
    /// true: search backwards from `from` (exclusive).
    #[serde(default)]
    back: bool,
}

pub async fn handle_search(Query(q): Query<SearchQuery>) -> Response {
    let Some((_, data)) = doc(&q.token) else { return err(StatusCode::NOT_FOUND, "file is not open any more, open it again") };
    let pat = match hex::decode(q.pattern.replace([' ', '-'], "")) {
        Ok(p) if !p.is_empty() && p.len() <= 4096 => p,
        _ => return err(StatusCode::BAD_REQUEST, "pattern must be 1..4096 hex bytes"),
    };
    let from = (q.from as usize).min(data.len());
    let found = tokio::task::spawn_blocking(move || find(&data, &pat, from, q.back)).await.ok().flatten();
    Json(serde_json::json!({ "ok": true, "offset": found })).into_response()
}

fn find(data: &[u8], pat: &[u8], from: usize, back: bool) -> Option<usize> {
    if pat.len() > data.len() {
        return None;
    }
    let first = pat[0];
    if back {
        let mut i = from.min(data.len() - pat.len() + 1);
        while i > 0 {
            i -= 1;
            if data[i] == first && &data[i..i + pat.len()] == pat {
                return Some(i);
            }
        }
        None
    } else {
        let last_start = data.len() - pat.len();
        let mut i = from;
        while i <= last_start {
            match data[i..=last_start].iter().position(|&b| b == first) {
                Some(p) => {
                    let j = i + p;
                    if &data[j..j + pat.len()] == pat {
                        return Some(j);
                    }
                    i = j + 1;
                }
                None => return None,
            }
        }
        None
    }
}

#[derive(Deserialize)]
pub struct StringsQuery {
    token: String,
    #[serde(default)]
    min: usize,
    /// Case-insensitive filter.
    #[serde(default)]
    q: String,
}

/// Every ASCII and UTF-16LE string (with its file offset), like the Strings page of
/// the Pascal VirusKovAlyzer. At most 50,000 entries.
pub async fn handle_strings(Query(q): Query<StringsQuery>) -> Response {
    let Some((_, data)) = doc(&q.token) else { return err(StatusCode::NOT_FOUND, "file is not open any more, open it again") };
    let min = q.min.clamp(3, 64);
    let filter = q.q.to_lowercase();
    let out = tokio::task::spawn_blocking(move || extract_strings(&data, min, &filter)).await.unwrap_or_default();
    let truncated = out.len() >= MAX_STRINGS;
    Json(serde_json::json!({ "ok": true, "strings": out, "truncated": truncated })).into_response()
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

fn extract_strings(data: &[u8], min: usize, filter: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let push = |off: usize, enc: &str, s: String, out: &mut Vec<serde_json::Value>| {
        if out.len() >= MAX_STRINGS {
            return;
        }
        if filter.is_empty() || s.to_lowercase().contains(filter) {
            out.push(serde_json::json!({ "o": off, "e": enc, "s": s.chars().take(512).collect::<String>() }));
        }
    };
    // ASCII
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            if i - s >= min {
                push(s, "A", String::from_utf8_lossy(&data[s..i]).into_owned(), &mut out);
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min {
            push(s, "A", String::from_utf8_lossy(&data[s..]).into_owned(), &mut out);
        }
    }
    // UTF-16LE, both alignments
    for align in 0..2usize {
        let mut i = align;
        let mut run_start: Option<usize> = None;
        let mut buf = String::new();
        while i + 1 < data.len() {
            let (lo, hi) = (data[i], data[i + 1]);
            if hi == 0 && printable(lo) {
                run_start.get_or_insert(i);
                buf.push(lo as char);
            } else {
                if let Some(s) = run_start.take() {
                    if buf.len() >= min {
                        push(s, "W", std::mem::take(&mut buf), &mut out);
                    }
                }
                buf.clear();
            }
            i += 2;
        }
        if let Some(s) = run_start {
            if buf.len() >= min {
                push(s, "W", buf, &mut out);
            }
        }
    }
    out.sort_by_key(|v| v["o"].as_u64().unwrap_or(0));
    out
}

#[derive(Deserialize)]
pub struct SaveBody {
    token: String,
    /// [offset, "hex bytes"] pairs from the hex editor.
    patches: Vec<(u64, String)>,
    /// Open the saved copy right away (returns its report like /open).
    #[serde(default)]
    open: bool,
}

/// Writes a patched COPY to `alyzer_edited/` next to the server (never the original)
/// and returns its path and SHA-256.
pub async fn handle_save(State(app): State<Arc<AppState>>, Json(b): Json<SaveBody>) -> Response {
    let Some((name, data)) = doc(&b.token) else { return err(StatusCode::NOT_FOUND, "file is not open any more, open it again") };
    let mut out = data.as_ref().clone();
    for (off, hx) in &b.patches {
        let bytes = match hex::decode(hx) {
            Ok(v) => v,
            Err(_) => return err(StatusCode::BAD_REQUEST, format!("bad hex at offset {off}")),
        };
        let off = *off as usize;
        if off.checked_add(bytes.len()).map_or(true, |e| e > out.len()) {
            return err(StatusCode::BAD_REQUEST, format!("patch at {off} is past the end of the file"));
        }
        out[off..off + bytes.len()].copy_from_slice(&bytes);
    }
    let sha = sha256_hex(&out);
    let dir = crate::config::app_dir().join("alyzer_edited");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("{}: {e}", dir.display()));
    }
    let safe: String = name.chars().map(|c| if c.is_alphanumeric() || ".-_".contains(c) { c } else { '_' }).take(120).collect();
    let path = dir.join(format!("{}_{}.patched", &sha[..12], safe));
    if let Err(e) = std::fs::write(&path, &out) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, format!("{}: {e}", path.display()));
    }
    if b.open {
        return open_doc(&app, format!("{safe}.patched"), path.display().to_string(), out).await;
    }
    Json(serde_json::json!({ "ok": true, "path": path.display().to_string(), "sha256": sha, "size": out.len() })).into_response()
}

#[derive(Deserialize)]
pub struct TokenBody {
    token: String,
}

/// Scans the open file with the engine now (nothing is kept, the verdict cache and
/// telemetry are not touched) and returns verdict, threat, engines and signer.
pub async fn handle_scan(State(app): State<Arc<AppState>>, Json(b): Json<TokenBody>) -> Response {
    let Some((name, data)) = doc(&b.token) else { return err(StatusCode::NOT_FOUND, "file is not open any more, open it again") };
    let eng = Arc::clone(&app.engine);
    let res = tokio::task::spawn_blocking(move || {
        let sha = hex::encode_upper(Sha256::digest(data.as_slice()));
        eng.scan_blocking_opts(&data, &name, &sha, false, |_| {})
    })
    .await;
    match res {
        Ok(Ok(r)) => Json(serde_json::json!({
            "ok": true, "verdict": r.verdict, "threat": r.threat, "detail": r.detail,
            "score": r.score, "ms": r.scan_ms, "signer": r.signer,
        }))
        .into_response(),
        Ok(Err(e)) => err(StatusCode::SERVICE_UNAVAILABLE, e),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Currently open files (for the page's "recent" list).
pub async fn handle_list() -> impl IntoResponse {
    let g = docs().lock().unwrap();
    Json(serde_json::json!({
        "ok": true,
        "open": g.iter().rev().map(|d| serde_json::json!({ "token": d.token, "name": d.name, "source": d.source, "size": d.data.len() })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_forward_and_back() {
        let d = b"abcMZxxMZyy";
        assert_eq!(find(d, b"MZ", 0, false), Some(3));
        assert_eq!(find(d, b"MZ", 4, false), Some(7));
        assert_eq!(find(d, b"MZ", 11, true), Some(7));
        assert_eq!(find(d, b"MZ", 7, true), Some(3));
        assert_eq!(find(d, b"zz", 0, false), None);
        assert_eq!(find(d, b"yy", 0, false), Some(9));
    }

    #[test]
    fn strings_ascii_and_wide() {
        let mut d = b"\x00\x01hello world\x00\x02".to_vec();
        d.extend_from_slice(&[b'W', 0, b'i', 0, b'd', 0, b'e', 0, b'!', 0, 0, 0]);
        let s = extract_strings(&d, 4, "");
        let texts: Vec<_> = s.iter().map(|v| (v["e"].as_str().unwrap().to_string(), v["s"].as_str().unwrap().to_string())).collect();
        assert!(texts.contains(&("A".into(), "hello world".into())));
        assert!(texts.contains(&("W".into(), "Wide!".into())));
        assert_eq!(extract_strings(&d, 4, "world").len(), 1);
    }
}
