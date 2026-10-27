//! Integration test proving that Unicorn CPU Emulation extracts XOR-filter obfuscated strings.

use std::sync::{Arc, Mutex};
use hydradragonunicorn::unicorn_engine::unicorn_const::{Arch, HookType, Mode, Prot};
use hydradragonunicorn::unicorn_engine::Unicorn;

#[test]
fn test_xorfilter_obfuscated_string_recovery_with_emulator() {
    let target = b"Hello, World!";
    let str_len = target.len();
    let table_size = 64usize;
    let mut xf_table = vec![0u8; table_size];

    let get_hashes = |idx: usize| -> (usize, usize, usize) {
        let h0 = (idx * 17 + 3) % table_size;
        let h1 = (idx * 31 + 11) % table_size;
        let h2 = (idx * 53 + 29) % table_size;
        (h0, h1, h2)
    };

    for i in 0..table_size {
        xf_table[i] = ((i * 73 + 19) & 0xFF) as u8;
    }

    // Peel like a real XOR / binary fuse filter: repeatedly take a cell only one remaining
    // key touches, then fill those cells in reverse order so no later write clobbers a
    // cell an earlier key already depends on.
    let cells = |i: usize| -> [usize; 3] {
        let (h0, h1, h2) = get_hashes(i);
        [h0, h1, h2]
    };
    let mut count = vec![0usize; table_size];
    for i in 0..str_len {
        for c in cells(i) {
            count[c] += 1;
        }
    }
    let mut alive = vec![true; str_len];
    let mut order: Vec<(usize, usize)> = Vec::new();
    while order.len() < str_len {
        let (i, c) = (0..str_len)
            .filter(|&i| alive[i])
            .find_map(|i| cells(i).into_iter().find(|&c| count[c] == 1).map(|c| (i, c)))
            .expect("hash triplets are not peelable");
        alive[i] = false;
        for c in cells(i) {
            count[c] -= 1;
        }
        order.push((i, c));
    }
    for &(i, c) in order.iter().rev() {
        let [h0, h1, h2] = cells(i);
        xf_table[c] = 0;
        xf_table[c] = target[i] ^ xf_table[h0] ^ xf_table[h1] ^ xf_table[h2];
    }

    for (i, &expected_ch) in target.iter().enumerate() {
        let (h0, h1, h2) = get_hashes(i);
        let resolved = xf_table[h0] ^ xf_table[h1] ^ xf_table[h2];
        assert_eq!(resolved, expected_ch, "Math check failed at index {i}");
    }

    let table_str = String::from_utf8_lossy(&xf_table);
    assert!(!table_str.contains("Hello"), "Plaintext must not exist in table!");

    println!("\n=======================================================");
    println!("[+] XOR Filter Table generated (size: {} bytes)", xf_table.len());
    println!("[+] Raw Table bytes (first 16): {:02x?}", &xf_table[..16]);
    println!("=======================================================");

    let code_addr: u64 = 0x1000;
    let table_addr: u64 = 0x2000;
    let out_buf_addr: u64 = 0x3000;

    let captured_writes = Arc::new(Mutex::new(Vec::<(u64, u8)>::new()));
    let captured_clone = Arc::clone(&captured_writes);

    let mut uc = Unicorn::new(Arch::X86, Mode::MODE_32).expect("Init Unicorn x86-32");

    uc.mem_map(code_addr, 0x1000, Prot::ALL).expect("map code");
    uc.mem_map(table_addr, 0x1000, Prot::READ).expect("map table");
    uc.mem_map(out_buf_addr, 0x1000, Prot::ALL).expect("map output buffer");

    uc.mem_write(table_addr, &xf_table).expect("write table");

    let empty_buf = vec![0u8; str_len + 1];
    uc.mem_write(out_buf_addr, &empty_buf).expect("clear out_buf");

    let code: Vec<u8> = vec![
        0x31, 0xC9,                         // xor ecx, ecx
        // <loop_start> (offset 2)
        0x83, 0xF9, 0x0D,                   // cmp ecx, 13
        0x7D, 0x36,                         // jge <done> (+0x36 bytes)
        // h0:
        0x6B, 0xC1, 0x11,                   // imul eax, ecx, 17
        0x83, 0xC0, 0x03,                   // add eax, 3
        0x83, 0xE0, 0x3F,                   // and eax, 63
        0x8A, 0x90, 0x00, 0x20, 0x00, 0x00, // mov dl, [eax + 0x2000]
        // h1:
        0x6B, 0xC1, 0x1F,                   // imul eax, ecx, 31
        0x83, 0xC0, 0x0B,                   // add eax, 11
        0x83, 0xE0, 0x3F,                   // and eax, 63
        0x32, 0x90, 0x00, 0x20, 0x00, 0x00, // xor dl, [eax + 0x2000]
        // h2:
        0x6B, 0xC1, 0x35,                   // imul eax, ecx, 53
        0x83, 0xC0, 0x1D,                   // add eax, 29
        0x83, 0xE0, 0x3F,                   // and eax, 63
        0x32, 0x90, 0x00, 0x20, 0x00, 0x00, // xor dl, [eax + 0x2000]
        // store:
        0x88, 0x91, 0x00, 0x30, 0x00, 0x00, // mov [ecx + 0x3000], dl
        0x41,                               // inc ecx
        0xEB, 0xC5,                         // jmp loop_start (-59 bytes)
        // <done> (offset 0x3d = 61)
        0x90,                               // nop
    ];

    uc.mem_write(code_addr, &code).expect("write code");

    let _hook = uc.add_mem_hook(
        HookType::MEM_WRITE,
        out_buf_addr,
        out_buf_addr + 0x100,
        move |_, _mem_type, addr, size, value| {
            if size == 1 {
                captured_clone.lock().unwrap().push((addr, value as u8));
            }
            true
        },
    ).expect("add mem hook");

    println!("[+] Emulating x86 machine code at 0x{:x}...", code_addr);
    let end_addr = code_addr + code.len() as u64;
    uc.emu_start(code_addr, end_addr, 0, 1000).expect("emulation failed");

    println!("[+] Emulation finished successfully!");

    // Read the decrypted string from output buffer
    let result_bytes = uc.mem_read_as_vec(out_buf_addr, str_len).expect("read out_buf");
    let recovered_str = String::from_utf8(result_bytes.clone()).expect("valid utf-8");

    println!("[+] Recovered Plaintext from Emulated Memory: \"{}\"", recovered_str);
    assert_eq!(recovered_str, "Hello, World!", "String must match original target!");

    let writes = captured_writes.lock().unwrap();
    println!("[+] Total captured memory writes on target buffer: {}", writes.len());
    let mut written_text = String::new();
    for (_, b) in writes.iter() {
        written_text.push(*b as char);
    }
    println!("[+] Real-time Hooked character stream: \"{}\"", written_text);
    assert_eq!(written_text, "Hello, World!");
    println!("=======================================================\n");
}
