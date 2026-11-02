use openedr_static::memtrack::{self, Kind, TrackingAlloc};

#[global_allocator]
static ALLOC: TrackingAlloc = TrackingAlloc;

fn stat(name: &str) -> memtrack::ComponentMem {
    memtrack::snapshot().into_iter().find(|c| c.name == name).unwrap_or_else(|| panic!("{name} not counted"))
}

#[test]
fn counts_retained_peak_and_returns_live_to_zero() {
    let kept = memtrack::measure("t:loader", Kind::Load, 0, || {
        let scratch = vec![1u8; 8 << 20];
        drop(scratch);
        vec![2u8; 3 << 20]
    });
    let s = stat("t:loader");
    assert!(memtrack::installed());
    assert_eq!(s.calls, 1);
    assert!(s.retained_bytes >= 3 << 20 && s.retained_bytes < 4 << 20, "retained {}", s.retained_bytes);
    assert!(s.max_peak_bytes >= 8 << 20, "peak {}", s.max_peak_bytes);
    assert_eq!(s.live_bytes, 0, "nothing runs any more");

    // Nested: the inner stage's bytes show under it while it runs, and both lives end at 0.
    memtrack::measure("t:outer", Kind::Scan, 10, || {
        memtrack::measure("t:inner", Kind::Scan, 5, || {
            let v = vec![0u8; 2 << 20];
            assert!(stat("t:inner").live_bytes >= 2 << 20);
            std::hint::black_box(&v);
        });
    });
    assert_eq!(stat("t:inner").live_bytes, 0);
    assert_eq!(stat("t:outer").live_bytes, 0);
    assert_eq!(stat("t:inner").max_peak_input_bytes, 5);
    drop(kept);

    // A one-time load inside a scan counts under its own name, not as the scan's spike.
    let lazy = memtrack::measure("t:scan", Kind::Scan, 1, || {
        let lazy = memtrack::measure("t:lazy_load", Kind::Load, 0, || {
            drop(vec![0u8; 16 << 20]);
            vec![0u8; 4 << 20]
        });
        std::hint::black_box(vec![0u8; 1 << 20]);
        lazy
    });
    let (scan, load) = (stat("t:scan"), stat("t:lazy_load"));
    assert!(load.retained_bytes >= 4 << 20 && load.max_peak_bytes >= 16 << 20, "{load:?}");
    assert!(scan.max_peak_bytes >= 1 << 20 && scan.max_peak_bytes < 2 << 20, "{scan:?}");
    assert!(scan.retained_bytes.abs() < 1 << 20, "{scan:?}");
    assert_eq!(scan.live_bytes, 0);
    drop(lazy);
}

#[cfg(target_os = "windows")]
#[test]
fn pe_features_record_scan_stages() {
    let data = std::fs::read(r"C:\Windows\System32\notepad.exe").expect("notepad.exe");
    let v = openedr_static::ml::pe_combined::extract_pe_features_v2(&data);
    openedr_static::ml::pe_combined::forget_emulation();
    assert!(v.is_some());
    // The second call is a scan without the one-time filter load.
    openedr_static::ml::pe_combined::extract_pe_features_v2(&data);
    openedr_static::ml::pe_combined::forget_emulation();
    let f = stat("scan:ml_pe_features");
    assert!(f.calls >= 2 && f.last_peak_bytes > 0, "{f:?}");
    assert!(f.last_peak_bytes < 256 << 20, "a notepad scan should not need {} bytes", f.last_peak_bytes);
    assert_eq!(f.max_peak_input_bytes, data.len() as u64);
    assert_eq!(f.live_bytes, 0);
    let (private, ws, _) = memtrack::process_memory();
    assert!(private > 0 && ws > 0);
    eprintln!("{:#?}", memtrack::snapshot().iter().filter(|c| c.name.starts_with("scan:")).collect::<Vec<_>>());
}
