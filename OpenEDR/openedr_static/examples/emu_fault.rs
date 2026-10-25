//! Diagnosis: where native PEs stop with an unmapped access (inside Unicorn only).
//! Prints the faulting instruction, its address relative to the image and the registers.
fn main() {
    use hydradragonunicorn::unpacker::engine::{entrypoint, Sample, UnpackerEngine};
    use hydradragonunicorn::unicorn_engine::RegisterX86 as R;
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
    let mut args = std::env::args().skip(1);
    let limit: usize = args.next().unwrap().parse().unwrap();
    let dir = args.next().unwrap();
    let mut files: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.path()).collect();
    files.sort();
    let mut n = 0;
    for f in files {
        if n >= limit { break; }
        let Ok(data) = std::fs::read(&f) else { continue };
        if !data.starts_with(b"MZ") || data.len() < 0x1000 || openedr_static::ml::pe_combined::dotnet_kind(&data) != 0 { continue }
        let Ok(sample) = Sample::from_bytes(&data) else { continue };
        let ep = entrypoint(&sample.opt_header);
        let is64 = sample.opt_header.magic == 0x20b;
        let base = sample.base_addr;
        let mut eng = UnpackerEngine::new(sample, "memory").with_trace_mode(true);
        if eng.init_uc().is_err() { continue }
        eng.set_controls(false, false);
        eng.set_end_addr(u64::MAX);
        let r = eng.emu_from(ep, 20_000_000, 20_000_000);
        let e = match r { Ok(_) => "ok".to_string(), Err(e) => e.to_string() };
        n += 1;
        let apis: Vec<_> = eng.apicall_counter.keys().cloned().collect();
        let end = eng.end;
        let traced: Vec<String> = eng.behavior_trace().calls.iter().map(|c| format!("{}({})", c.api, c.args.join(","))).collect();
        let not_traced: Vec<_> = eng.apicall_counter.keys().filter(|k| !eng.behavior_trace().calls.iter().any(|c| &c.api == *k)).cloned().collect();
        println!("trace {traced:?}
stopped at (counted, not traced) {not_traced:?}");
        let names: Vec<(String, u64)> = eng.sample.dllname_to_functionlist.iter().flat_map(|(d, v)| v.iter().map(move |(f, a)| (format!("{d}!{f}"), *a))).collect();
        let uc = eng.unicorn_mut().unwrap();
        let ip = uc.reg_read(if is64 { R::RIP } else { R::EIP } as i32).unwrap_or(0);
        let mut code = [0u8; 16];
        let text = if uc.mem_read(ip, &mut code).is_ok() {
            let mut d = Decoder::with_ip(if is64 { 64 } else { 32 }, &code, ip, DecoderOptions::NONE);
            let ins = d.decode();
            let mut s = String::new();
            IntelFormatter::new().format(&ins, &mut s);
            s
        } else { "<ip not mapped>".into() };
        let regs: Vec<String> = if is64 {
            [("rax", R::RAX), ("rbx", R::RBX), ("rcx", R::RCX), ("rdx", R::RDX), ("rsi", R::RSI), ("rdi", R::RDI), ("rsp", R::RSP), ("gs_base", R::GS_BASE)]
                .iter().map(|(n, r)| format!("{n}={:#x}", uc.reg_read(*r as i32).unwrap_or(0))).collect()
        } else {
            [("eax", R::EAX), ("ebx", R::EBX), ("ecx", R::ECX), ("edx", R::EDX), ("esi", R::ESI), ("edi", R::EDI), ("esp", R::ESP), ("fs", R::FS)]
                .iter().map(|(n, r)| format!("{n}={:#x}", uc.reg_read(*r as i32).unwrap_or(0))).collect()
        };
        let api_here: Vec<&String> = names.iter().filter(|(_, a)| *a == ip).map(|(n, _)| n).collect();
        let sp = uc.reg_read(if is64 { R::RSP } else { R::ESP } as i32).unwrap_or(0);
        let mut ret = [0u8; 4];
        let _ = uc.mem_read(sp, &mut ret);
        let ret = u32::from_le_bytes(ret) as u64;
        let mut before = [0u8; 8];
        let call_bytes = if ret > 8 && uc.mem_read(ret - 8, &mut before).is_ok() { format!("{:02x?}", before) } else { "-".into() };
        let rel = if ip >= base && ip < base + 0x1000_0000 { format!("image+{:#x}", ip - base) } else { format!("{ip:#x}") };
        println!("end {end:?} | api at ip {api_here:?} | ret {ret:#x} bytes before ret {call_bytes}");
        println!("{} | {} | {}{} | ep=image+{:#x} | at {rel}: {text} | {} | apis {:?}",
            f.file_name().unwrap().to_string_lossy(), e, if is64 { "x64" } else { "x86" }, "", ep - base, regs.join(" "), apis);
    }
}
