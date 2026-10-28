//! Why packed samples do not unpack: one JSON line per PE with the packer (Unipacker's
//! YARA rules and the section names) and how the engine's emulation of it ended. Same
//! emulation as `openedr_static::ml::pe_combined::run_emulation` (trace mode, no
//! write-execute / section-hopping stops, 20M instructions, 20 s), inside Unicorn only.
//!
//! A file an unpacker signature (`unpack_rules/default.yaml`) recognises runs its
//! recipe first (`rule`, `recipe`, `recipe_error`); the generic run follows only
//! when no rule matches or the recipe failed.
//!
//! `unpack_profile <files.lst> <out.jsonl> [packer_signatures.yar] [threads]`
//! Lines already in <out.jsonl> are skipped, so a run that stopped goes on where it was.

use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
use hydradragonunicorn::unpacker::plan::{Budget, Outcome, UnpackRules};

const MAX_INSTRUCTIONS: usize = 20_000_000;
const TIMEOUT_US: u64 = 20_000_000;
const MAX_BYTES: usize = 64 << 20;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn list(v: &[String]) -> String {
    v.iter().map(|s| format!("\"{}\"", esc(s))).collect::<Vec<_>>().join(",")
}

fn entropy(d: &[u8]) -> f64 {
    if d.is_empty() {
        return 0.0;
    }
    let mut c = [0u64; 256];
    for &b in d {
        c[b as usize] += 1;
    }
    let n = d.len() as f64;
    c.iter().filter(|&&x| x > 0).map(|&x| -(x as f64 / n) * (x as f64 / n).log2()).sum()
}

/// Section names and the highest raw-section entropy, straight from the headers.
fn sections(d: &[u8]) -> (Vec<String>, f64) {
    let rd = |o: usize, n: usize| d.get(o..o + n);
    let Some(lf) = rd(0x3c, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize) else { return (vec![], 0.0) };
    let (Some(ns), Some(opt)) = (rd(lf + 6, 2), rd(lf + 20, 2)) else { return (vec![], 0.0) };
    let (ns, opt) = (u16::from_le_bytes([ns[0], ns[1]]) as usize, u16::from_le_bytes([opt[0], opt[1]]) as usize);
    let (mut names, mut emax) = (Vec::new(), 0f64);
    for i in 0..ns.min(64) {
        let s = lf + 24 + opt + i * 40;
        let Some(h) = rd(s, 40) else { break };
        let name: String = h[..8].iter().take_while(|&&b| b != 0).map(|&b| if b.is_ascii_graphic() { b as char } else { '?' }).collect();
        let size = u32::from_le_bytes(h[16..20].try_into().unwrap()) as usize;
        let ptr = u32::from_le_bytes(h[20..24].try_into().unwrap()) as usize;
        if let Some(raw) = d.get(ptr..ptr.saturating_add(size).min(d.len())) {
            emax = emax.max(entropy(raw));
        }
        names.push(name);
    }
    (names, emax)
}

fn profile(path: &str, rules: Option<&yara_x::Rules>) -> String {
    let t = std::time::Instant::now();
    let Ok(data) = std::fs::read(path) else { return format!("{{\"path\":\"{}\",\"error\":\"read\"}}", esc(path)) };
    let (secs, emax) = sections(&data);
    let yara: Vec<String> = rules
        .and_then(|r| yara_x::Scanner::new(r).scan(&data).ok().map(|m| m.matching_rules().map(|r| r.identifier().to_string()).filter(|n| n != "pe32").collect()))
        .unwrap_or_default();
    let head = format!(
        "\"path\":\"{}\",\"size\":{},\"yara\":[{}],\"sections\":[{}],\"entropy_max\":{:.2}",
        esc(path),
        data.len(),
        list(&yara),
        list(&secs),
        emax
    );
    if data.len() > MAX_BYTES {
        return format!("{{{head},\"result\":\"too_big\"}}");
    }
    // Unpacker signature first: its recipe, and the generic run only when no rule
    // matches or a step of the recipe did not happen.
    let budget = Budget { max_instructions: MAX_INSTRUCTIONS, timeout_us: TIMEOUT_US };
    let recipe = UnpackRules::builtin().unpack(&data, budget);
    let head = match &recipe {
        None => format!("{head},\"rule\":null"),
        Some(run) => {
            let (outcome, why) = match &run.outcome {
                Outcome::Dumped(_) => ("dumped", None),
                Outcome::Failed { step, reason } => ("failed", Some(format!("step {step}: {reason}"))),
            };
            let why = why.map(|w| format!("\"{}\"", esc(&w))).unwrap_or_else(|| "null".into());
            format!("{head},\"rule\":\"{}\",\"recipe\":\"{outcome}\",\"recipe_error\":{why},\"recipe_ms\":{}", esc(&run.rule), t.elapsed().as_millis())
        }
    };
    if let Some(run) = recipe.as_ref().filter(|r| matches!(r.outcome, Outcome::Dumped(_))) {
        return format!("{{{head},\"result\":\"unpacked\",\"api_calls\":{},\"ms\":{}}}", run.trace.calls.len(), t.elapsed().as_millis());
    }
    let Ok(sample) = Sample::from_bytes(&data) else { return format!("{{{head},\"result\":\"not_pe\"}}") };
    let ep = entrypoint(&sample.opt_header);
    let is_64 = sample.opt_header.magic == 0x20b;
    let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
    if let Err(e) = eng.init_uc() {
        return format!("{{{head},\"result\":\"init_failed\",\"error\":\"{}\"}}", esc(&e.to_string()));
    }
    eng.set_controls(false, false);
    eng.set_end_addr(u64::MAX);
    let err = eng.emu_from(ep, TIMEOUT_US, MAX_INSTRUCTIONS).err().map(|e| e.to_string());
    let unpacked = eng.wx_hit.is_some();
    let result = if unpacked {
        "unpacked"
    } else if !eng.end.is_clean() {
        "failed"
    } else {
        "image"
    };
    let calls = &eng.behavior_trace().calls;
    let last: Vec<String> = calls.iter().rev().take(5).map(|c| c.api.clone()).collect();
    let distinct: HashSet<&str> = calls.iter().map(|c| c.api.as_str()).collect();
    format!(
        "{{{head},\"x64\":{is_64},\"result\":\"{result}\",\"end\":\"{:?}\",\"api_calls\":{},\"distinct_apis\":{},\"last_apis\":[{}],\"emu_error\":{},\"stop_api\":{},\"ms\":{}}}",
        eng.end,
        calls.len(),
        distinct.len(),
        list(&last),
        err.map(|e| format!("\"{}\"", esc(&e))).unwrap_or_else(|| "null".into()),
        eng.stop_api.as_deref().map(|e| format!("\"{}\"", esc(e))).unwrap_or_else(|| "null".into()),
        t.elapsed().as_millis()
    )
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        eprintln!("usage: unpack_profile <files.lst> <out.jsonl> [packer_signatures.yar] [threads]");
        std::process::exit(2);
    }
    let rules = a.get(3).filter(|p| !p.is_empty()).map(|p| {
        let src = std::fs::read_to_string(p).expect("read YARA rules");
        yara_x::compile(src.as_str()).expect("compile YARA rules")
    });
    let threads: usize = a.get(4).and_then(|v| v.parse().ok()).unwrap_or(4).max(1);
    let done: HashSet<String> = std::fs::File::open(&a[2])
        .map(|f| {
            std::io::BufReader::new(f)
                .lines()
                .map_while(Result::ok)
                .filter_map(|l| l.split("\"path\":\"").nth(1).and_then(|r| r.split("\",").next()).map(|p| p.replace("\\\\", "\\")))
                .collect()
        })
        .unwrap_or_default();
    let files: Vec<String> = std::fs::read_to_string(&a[1])
        .expect("read list")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !done.contains(*l))
        .map(String::from)
        .collect();
    eprintln!("{} files to profile ({} already done), {threads} threads", files.len(), done.len());
    let out = Mutex::new(std::fs::OpenOptions::new().create(true).append(true).open(&a[2]).expect("open output"));
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads {
            std::thread::Builder::new()
                .stack_size(64 << 20)
                .spawn_scoped(s, || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(p) = files.get(i) else { break };
                    let line = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| profile(p, rules.as_ref())))
                        .unwrap_or_else(|_| format!("{{\"path\":\"{}\",\"result\":\"panic\"}}", esc(p)));
                    let mut o = out.lock().unwrap();
                    let _ = writeln!(o, "{line}");
                    let _ = o.flush();
                    if i % 100 == 0 {
                        eprintln!("  {i}/{}", files.len());
                    }
                })
                .expect("spawn");
        }
    });
}
