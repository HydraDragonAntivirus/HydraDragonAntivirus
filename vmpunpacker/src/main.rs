use std::env;
use std::fs;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <packed_file> <unpacked_file>", args.first().map(|s| s.as_str()).unwrap_or("vmpunpacker"));
        process::exit(1);
    }

    let packed_path = &args[1];
    let unpacked_path = &args[2];

    let packed_data = match fs::read(packed_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading packed file '{}': {}", packed_path, e);
            process::exit(1);
        }
    };

    if packed_data.is_empty() {
        eprintln!("Packed file is empty.");
        process::exit(1);
    }

    println!("Packed file loaded: {}, Size: {} bytes", packed_path, packed_data.len());

    if !vmpunpacker::detect(&packed_data) {
        eprintln!("VMProtect signature not found — file may not be packed, attempting unpack anyway.");
    }

    println!("Unpacking...");

    match vmpunpacker::unpack(&packed_data) {
        Ok(unpacked) => {
            if unpacked.is_empty() {
                eprintln!("Unpacker produced empty output.");
                process::exit(1);
            }
            println!("Unpacker finished. Unpacked size: {} bytes", unpacked.len());
            if let Err(e) = fs::write(unpacked_path, &unpacked) {
                eprintln!("Error writing unpacked data to '{}': {}", unpacked_path, e);
                process::exit(1);
            }
            println!("Unpacked data written to: {}", unpacked_path);
        }
        Err(e) => {
            eprintln!("Unpack failed: {}", e);
            process::exit(1);
        }
    }
}
