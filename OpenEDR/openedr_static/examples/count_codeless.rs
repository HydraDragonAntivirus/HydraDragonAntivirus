//! Counts PEs without code (`pe_combined::has_code`) under the given folders (read only).
fn main() {
    for d in std::env::args().skip(1) {
        let (mut pe, mut codeless) = (0u64, 0u64);
        let mut stack = vec![std::path::PathBuf::from(&d)];
        while let Some(p) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&p) else { continue };
            for e in rd.flatten() {
                let q = e.path();
                if q.is_dir() {
                    stack.push(q);
                    continue;
                }
                let Ok(data) = std::fs::read(&q) else { continue };
                if !data.starts_with(b"MZ") || openedr_static::ml::pe_features::extract_pe_features(&data).is_none() {
                    continue;
                }
                pe += 1;
                codeless += !openedr_static::ml::pe_combined::has_code(&data) as u64;
            }
        }
        println!("{d}: {pe} PE, {codeless} without code ({:.1} %)", 100.0 * codeless as f64 / pe.max(1) as f64);
    }
}
