use std::time::Instant;

use hydradragonclamav::Engine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: yarawarm <scan_assets_dir> <apk_path>");
        std::process::exit(2);
    }
    let base = std::path::Path::new(&args[1]);
    let mut c = match Engine::from_database_dir(base) {
        Ok((e, _)) => e,
        Err(e) => {
            eprintln!("clamav DB load failed: {e}");
            std::process::exit(1);
        }
    };
    for name in [
        "clean_rules_filtered_verified.yrc",
        "valhalla-rules_filtered_verified.yrc",
        "machine_learning_apk.yrc",
        "hydradragon.yrc",
        "hips_rules_filtered_verified.yrc",
    ] {
        let p = base.join(name);
        if p.exists() {
            c.add_compiled_yara_file(&p);
        }
    }

    let apk = std::fs::read(&args[2]).expect("read apk");
    println!("apk bytes: {} MB", apk.len() / (1024 * 1024));

    // Warm each ruleset's scanner once (automaton build), on the current thread.
    let names: Vec<String> = c.yara.iter().map(|y| y.name.clone()).collect();
    let tiny = b"hello".to_vec();
    for name in &names {
        let t0 = Instant::now();
        let _ = c.scan_bytes_named(&tiny, "test", hydradragonclamav::ScanOptions::default(), &[]);
        println!("warm {}: {}ms", name, t0.elapsed().as_millis());
    }

    // Now scan the FULL APK as a single buffer with all rulesets — this is the
    // per-buffer cost the device pays for each of its 16 extracted buffers.
    let t0 = Instant::now();
    let r = c.scan_bytes_named(&apk, &args[2], hydradragonclamav::ScanOptions::default(), &[]);
    println!("full-apk 1-buffer scan: {}ms ({} matches)", t0.elapsed().as_millis(), r.len());
}
