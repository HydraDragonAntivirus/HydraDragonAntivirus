//! Deobfuscates a JavaScript file (static only) and prints the result.
fn main() {
    let p = std::env::args().nth(1).expect("path");
    let src = std::fs::read_to_string(&p).expect("read");
    let t = std::time::Instant::now();
    match hydradragonjsdeob::engine::api::JSDeobfuscator::new().deobfuscate(&src) {
        Ok(r) => {
            eprintln!("{} -> {} bytes, {} iterations, {} modifications, converged {}, {:?}", src.len(), r.code.len(), r.iterations, r.modifications, r.converged, t.elapsed());
            println!("{}", r.code);
        }
        Err(e) => eprintln!("error: {e}"),
    }
}
