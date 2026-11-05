// Synthetic infected PE32 files: a host .text whose entry-point bytes were
// stolen, and a virus section added at the end that the entry point points to.

use super::*;

const BASE: u32 = 0x40_0000;
/// Original host code: mov eax, 1 / ret.
const ORIGINAL: [u8; 6] = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
/// What the "virus" left at the host entry point.
const STOLEN: [u8; 6] = [0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3];
const MAGIC: [u8; 16] = *b"HDTESTVIRUS!!!!!";

fn put32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn get32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(d[o..o + 4].try_into().unwrap())
}

/// PE32 with sections `(name, rva, data, characteristics)`.
fn build_pe(sections: &[(&str, u32, Vec<u8>, u32)], ep: u32, checksum: u32) -> Vec<u8> {
    let mut d = vec![0u8; 0x200];
    d[0] = b'M';
    d[1] = b'Z';
    put32(&mut d, 0x3C, 0x40);
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    d[coff..coff + 2].copy_from_slice(&0x14Cu16.to_le_bytes());
    d[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    d[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes());
    d[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes());
    let opt = coff + 20;
    d[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes());
    put32(&mut d, opt + 16, ep);
    put32(&mut d, opt + 28, BASE);
    put32(&mut d, opt + 32, 0x1000);
    put32(&mut d, opt + 36, 0x200);
    let last = sections.last().map(|s| s.1 + 0x1000).unwrap_or(0x1000);
    put32(&mut d, opt + 56, last);
    put32(&mut d, opt + 60, 0x200);
    put32(&mut d, opt + 64, checksum);
    d[opt + 68..opt + 70].copy_from_slice(&2u16.to_le_bytes());
    put32(&mut d, opt + 92, 16);
    let mut table = opt + 0xE0;
    for (name, rva, data, chars) in sections {
        let raw_ptr = d.len() as u32;
        let raw_size = (data.len() as u32).div_ceil(0x200) * 0x200;
        let mut n = [0u8; 8];
        n[..name.len()].copy_from_slice(name.as_bytes());
        d[table..table + 8].copy_from_slice(&n);
        put32(&mut d, table + 8, data.len() as u32);
        put32(&mut d, table + 12, *rva);
        put32(&mut d, table + 16, raw_size);
        put32(&mut d, table + 20, raw_ptr);
        put32(&mut d, table + 36, *chars);
        table += 40;
        let mut sec = data.clone();
        sec.resize(raw_size as usize, 0);
        d.extend_from_slice(&sec);
    }
    d
}

const CODE: u32 = 0x6000_0020;
const VIRUS: u32 = 0xE000_0020;

fn text_infected() -> (&'static str, u32, Vec<u8>, u32) {
    let mut t = STOLEN.to_vec();
    t.resize(0x40, 0x90);
    (".text", 0x1000, t, CODE)
}

/// Virus that keeps the OEP RVA and the stolen bytes in its body.
fn stored_virus(stored_size: u32) -> Vec<u8> {
    let mut v = vec![0xEB, 0x1E];
    v.extend_from_slice(&MAGIC);
    v.resize(0x14, 0);
    v.extend_from_slice(&0x1000u32.to_le_bytes()); // +0x14 OEP RVA
    v.extend_from_slice(&stored_size.to_le_bytes()); // +0x18 size
    v.resize(0x20, 0);
    v.extend_from_slice(&ORIGINAL[..5]); // +0x20 stolen bytes
    v.push(0xF4);
    v
}

const STORED_RULES: &str = r#"
viruses:
  - name: Test.Stored
    arch: x86
    signatures:
      - {offset: 0, hex: "EB 1E 48 44 54 45 53 54 56 49 52 55 53 21 21 21 21 21"}
    recover:
      method: stored
      oep: {mode: rva, offset: 0x14}
      restore:
        - {data_offset: 0x20, size: {offset: 0x18}, min_size: 2}
    cleanup:
      - action: remove_virus_section
"#;

/// Virus that puts the stolen bytes back itself and jumps to the host.
fn returning_virus() -> Vec<u8> {
    let mut v = vec![0xBF];
    v.extend_from_slice(&(BASE + 0x1000).to_le_bytes()); // mov edi, OEP
    v.extend_from_slice(&[0xC6, 0x07, 0xB8]); // mov byte [edi], 0xB8
    v.extend_from_slice(&[0xC7, 0x47, 0x01, 0x01, 0x00, 0x00, 0x00]); // mov dword [edi+1], 1
    v.extend_from_slice(&[0xFF, 0xE7]); // jmp edi
    v.extend_from_slice(&MAGIC);
    v
}

const RETURNING_RULES: &str = r#"
viruses:
  - name: Test.Returning
    signatures:
      - {offset: 0, hex: "BF ?? ?? ?? ?? C6 07 B8 C7 47 01 01 00 00 00 FF E7"}
      - {offset: 17, hex: "48 44 54 45 53 54"}
    recover: {method: emulate_to_host, max_restore_bytes: 64}
    cleanup:
      - action: remove_virus_section
"#;

fn assert_repaired(data: &[u8]) {
    let l = pe::layout(data).unwrap();
    assert_eq!(l.nsec, 1, "virus section removed");
    assert_eq!(pe::entry_point(data, &l), 0x1000, "entry point restored");
    assert_eq!(&data[0x200..0x206], &ORIGINAL, "original code restored");
    assert_eq!(data.len(), 0x400, "virus data cut");
    assert_eq!(get32(data, l.opt_off + 56), 0x2000, "SizeOfImage");
}

#[test]
fn non_pe_is_not_infected() {
    assert_eq!(disinfect_bytes(b"not a PE file at all"), DisinfectOutcome::NotInfected);
}

#[test]
fn clean_pe_is_not_infected() {
    let mut t = ORIGINAL.to_vec();
    t.resize(0x40, 0x90);
    let pe = build_pe(&[(".text", 0x1000, t, CODE)], 0x1000, 0);
    let rules = DisinfectRules::from_yaml_str(STORED_RULES).unwrap();
    assert_eq!(disinfect_bytes_with(&pe, &rules), DisinfectOutcome::NotInfected);
    assert_eq!(disinfect_bytes(&pe), DisinfectOutcome::NotInfected);
}

#[test]
fn stored_original_code_is_restored() {
    let pe = build_pe(&[text_infected(), (".vir", 0x2000, stored_virus(5), VIRUS)], 0x2000, 0);
    let rules = DisinfectRules::from_yaml_str(STORED_RULES).unwrap();
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { malware_name, data, removed_bytes } => {
            assert_eq!(malware_name, "Test.Stored");
            assert_eq!(removed_bytes, 0x200);
            assert_repaired(&data);
        }
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn patient_zero_is_not_repairable() {
    let pe = build_pe(&[text_infected(), (".vir", 0x2000, stored_virus(0), VIRUS)], 0x2000, 0);
    let rules = DisinfectRules::from_yaml_str(STORED_RULES).unwrap();
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::NotRepairable { reason, .. } => assert!(reason.contains("patient zero"), "{reason}"),
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn code_restored_by_the_virus_is_recovered_by_emulation() {
    let pe = build_pe(&[text_infected(), (".vir", 0x2000, returning_virus(), VIRUS)], 0x2000, 0x1234);
    let rules = DisinfectRules::from_yaml_str(RETURNING_RULES).unwrap();
    assert_eq!(detect_bytes_with(&pe, &rules).as_deref(), Some("Test.Returning"));
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { data, .. } => {
            assert_repaired(&data);
            let l = pe::layout(&data).unwrap();
            assert_ne!(pe::checksum(&data, &l), 0x1234, "checksum recomputed");
        }
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn truncate_inside_last_section_keeps_headers_consistent() {
    // Virus appended to the host's last section (no section of its own).
    let mut text = STOLEN.to_vec();
    text.resize(0x200, 0x90);
    text.extend_from_slice(&stored_virus(5));
    let pe = build_pe(&[(".text", 0x1000, text, VIRUS)], 0x1200, 0);
    let rules = DisinfectRules::from_yaml_str(
        &STORED_RULES.replace("- action: remove_virus_section", "- {action: truncate_at, at: {mode: virus_offset}}"),
    )
    .unwrap();
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { data, .. } => {
            let l = pe::layout(&data).unwrap();
            let s = pe::sections(&data, &l)[0];
            assert_eq!((s.vsize, s.raw_size), (0x200, 0x200));
            assert_eq!(data.len(), 0x400);
            assert_eq!(&data[0x200..0x206], &ORIGINAL);
            assert_eq!(pe::entry_point(&data, &l), 0x1000);
        }
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn sality_definition_matches_the_killvirus_signatures() {
    let sality = DisinfectRules::builtin().only("W32.Sality.PE");
    let rule = &sality.rules[0];
    let sig1 = [
        0xE8, 0x00, 0x00, 0x00, 0x00, 0x5D, 0x8B, 0xC5, 0x81, 0xED, 0x05, 0x10, 0x40, 0x00, 0x8A, 0x9D, 0x73, 0x27,
        0x40, 0x00, 0x84, 0xDB, 0x74, 0x13, 0x81, 0xC4,
    ];
    let sig2 = [
        0x89, 0x85, 0x54, 0x12, 0x40, 0x00, 0xEB, 0x19, 0xC7, 0x85, 0x4D, 0x14, 0x40, 0x00, 0x22, 0x22, 0x22, 0x22,
        0xC7, 0x85, 0x3A, 0x14, 0x40, 0x00, 0x33, 0x33, 0x33, 0x33, 0xE9, 0x82, 0x00, 0x00, 0x00, 0x33, 0xDB, 0x64,
        0x67, 0x8B, 0x1E, 0x30, 0x00, 0x85, 0xDB, 0x78, 0x0E, 0x8B, 0x5B, 0x0C,
    ];
    let mut buf = vec![0u8; 0x100];
    buf[..sig1.len()].copy_from_slice(&sig1);
    buf[0x23..0x23 + sig2.len()].copy_from_slice(&sig2);
    assert!(rule.matches(&buf));
    buf[0x30] ^= 0xFF;
    assert!(!rule.matches(&buf));
}

/// PE32+ (x64) builder with sections `(name, rva, data, characteristics)`.
fn build_pe64(sections: &[(&str, u32, Vec<u8>, u32)], ep: u32) -> Vec<u8> {
    let mut d = vec![0u8; 0x200];
    d[0] = b'M';
    d[1] = b'Z';
    put32(&mut d, 0x3C, 0x40);
    d[0x40..0x44].copy_from_slice(b"PE\0\0");
    let coff = 0x44;
    d[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    d[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    d[coff + 16..coff + 18].copy_from_slice(&0xF0u16.to_le_bytes());
    d[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());
    let opt = coff + 20;
    d[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
    put32(&mut d, opt + 16, ep);
    d[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    put32(&mut d, opt + 32, 0x1000);
    put32(&mut d, opt + 36, 0x200);
    let last = sections.last().map(|s| s.1 + 0x1000).unwrap_or(0x1000);
    put32(&mut d, opt + 56, last);
    put32(&mut d, opt + 60, 0x200);
    d[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    put32(&mut d, opt + 108, 16);
    let mut table = opt + 0xF0;
    for (name, rva, data, chars) in sections {
        let raw_ptr = d.len() as u32;
        let raw_size = (data.len() as u32).div_ceil(0x200) * 0x200;
        let mut n = [0u8; 8];
        n[..name.len()].copy_from_slice(name.as_bytes());
        d[table..table + 8].copy_from_slice(&n);
        put32(&mut d, table + 8, data.len() as u32);
        put32(&mut d, table + 12, *rva);
        put32(&mut d, table + 16, raw_size);
        put32(&mut d, table + 20, raw_ptr);
        put32(&mut d, table + 36, *chars);
        table += 40;
        let mut sec = data.clone();
        sec.resize(raw_size as usize, 0);
        d.extend_from_slice(&sec);
    }
    d
}

#[test]
fn epo_section_scan_and_call_function_decrypt_in_place() {
    // Host .text: entry point at 0x1000 stays untouched (starts with HLT so entry-point
    // emulation would stop immediately and never reach .vir). At 0x1020 a 5-byte CALL
    // (`E8 1B 00 00 00`) was hijacked to jump into `.vir` (`E8 DC 0F 00 00`).
    let orig_call: [u8; 5] = [0xE8, 0x1B, 0x00, 0x00, 0x00];
    let mut text = vec![0x90u8; 0x40];
    text[0] = 0xF4; // HLT at entry point: proves `section_scan` bypassed EP emulation
    text[0x20..0x25].copy_from_slice(&[0xE8, 0xDC, 0x0F, 0x00, 0x00]);

    // Virus layout in `.vir` (RVA 0x2000):
    //   +0x00: MAGIC (16 bytes)
    //   +0x10: u32 patched RVA (0x1020), +0x14: u32 size (5), +0x18: u32 seed (0x37)
    //   +0x20: cdecl decrypt_in_place(buf, len, seed):
    //          for i in 0..len: buf[i] = buf[i].rotate_right(3).wrapping_sub(seed + i)
    //   +0x40: encrypted `orig_call` (5 bytes)
    let seed: u8 = 0x37;
    let encrypted: Vec<u8> = orig_call
        .iter()
        .enumerate()
        .map(|(i, &b)| b.wrapping_add(seed.wrapping_add(i as u8)).rotate_left(3))
        .collect();
    assert_ne!(encrypted.as_slice(), &orig_call);

    let mut vir = Vec::new();
    vir.extend_from_slice(&MAGIC);
    vir.extend_from_slice(&0x1020u32.to_le_bytes());
    vir.extend_from_slice(&5u32.to_le_bytes());
    vir.extend_from_slice(&(seed as u32).to_le_bytes());
    vir.resize(0x20, 0);
    vir.extend_from_slice(&[
        0x8B, 0x4C, 0x24, 0x04, // mov ecx, [esp+4]
        0x8B, 0x54, 0x24, 0x08, // mov edx, [esp+8]
        0x8A, 0x44, 0x24, 0x0C, // mov al,  [esp+12]
        0x85, 0xD2,             // test edx, edx
        0x74, 0x0B,             // jz +11
        0xC0, 0x09, 0x03,       // ror byte ptr [ecx], 3
        0x28, 0x01,             // sub [ecx], al
        0xFE, 0xC0,             // inc al
        0x41,                   // inc ecx
        0x4A,                   // dec edx
        0x75, 0xF5,             // jnz -11
        0xC3,                   // ret
    ]);
    vir.resize(0x40, 0);
    vir.extend_from_slice(&encrypted);

    let pe = build_pe(&[(".text", 0x1000, text, CODE), (".vir", 0x2000, vir, VIRUS)], 0x1000, 0);
    let yaml = r#"
viruses:
  - name: Test.EPO.RollingDecrypt
    arch: x86
    locate: section_scan
    signatures:
      - {offset: 0, hex: "48 44 54 45 53 54 56 49 52 55 53 21 21 21 21 21"}
    recover:
      method: call_function
      func: {mode: virus_offset, add: 0x20}
      args:
        - {addr: {mode: virus_offset, add: 0x40}}
        - {value: {offset: 0x14, size: 4}}
        - {value: {offset: 0x18, size: 4}}
      restore:
        - data_offset: 0x40
          size: {offset: 0x14, size: 4}
          to: {mode: rva, offset: 0x10}
    cleanup:
      - action: remove_virus_section
"#;
    let rules = DisinfectRules::from_yaml_str(yaml).unwrap();
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { malware_name, data, .. } => {
            assert_eq!(malware_name, "Test.EPO.RollingDecrypt");
            let l = pe::layout(&data).unwrap();
            assert_eq!(l.nsec, 1, "virus section removed");
            assert_eq!(pe::entry_point(&data, &l), 0x1000, "EPO preserved original entry point");
            assert_eq!(&data[0x220..0x225], &orig_call, "rolling-encrypted CALL bytes restored");
        }
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn x64_last_section_call_function_scratch_and_return_rva() {
    // PE32+ (x64): stolen 6 bytes at RVA 0x1000, EP redirected to `.vir` (0x2000).
    // `.vir` decrypts into a mapped `scratch` buffer (RCX=dst, RDX=src, R8=len) and
    // returns OEP RVA (0x1000) in RAX.
    let encrypted: Vec<u8> = ORIGINAL
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ 0xA5u8.wrapping_add(i as u8))
        .collect();
    let mut vir = Vec::new();
    vir.extend_from_slice(&MAGIC); // +0x00 (16 bytes)
    vir.extend_from_slice(&(ORIGINAL.len() as u32).to_le_bytes()); // +0x10 len = 6
    vir.resize(0x20, 0);
    vir.extend_from_slice(&[
        0xB0, 0xA5,                   // mov al, 0xA5
        0x45, 0x85, 0xC0,             // test r8d, r8d
        0x74, 0x16,                   // jz +22
        0x44, 0x8A, 0x0A,             // mov r9b, [rdx]
        0x41, 0x30, 0xC1,             // xor r9b, al
        0x44, 0x88, 0x09,             // mov [rcx], r9b
        0xFE, 0xC0,                   // inc al
        0x48, 0xFF, 0xC2,             // inc rdx
        0x48, 0xFF, 0xC1,             // inc rcx
        0x49, 0xFF, 0xC8,             // dec r8
        0x75, 0xEA,                   // jnz -22
        0xB8, 0x00, 0x10, 0x00, 0x00, // mov eax, 0x1000
        0xC3,                         // ret
    ]);
    vir.resize(0x50, 0);
    vir.extend_from_slice(&encrypted); // +0x50

    let pe = build_pe64(&[text_infected(), (".vir", 0x2000, vir, VIRUS)], 0x2000);
    let yaml = r#"
viruses:
  - name: Test.X64.ScratchDecrypt
    arch: x64
    locate: last_section
    signatures:
      - {offset: 0, hex: "48 44 54 45 53 54 56 49 52 55 53 21 21 21 21 21"}
    recover:
      method: call_function
      func: {mode: virus_offset, add: 0x20}
      args:
        - {scratch: 0x100}
        - {addr: {mode: virus_offset, add: 0x50}}
        - {value: {offset: 0x10, size: 4}}
      oep: {mode: return_rva}
      restore:
        - scratch_index: 0
          size: {offset: 0x10, size: 4}
    cleanup:
      - action: remove_virus_section
"#;
    let rules = DisinfectRules::from_yaml_str(yaml).unwrap();
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { malware_name, data, .. } => {
            assert_eq!(malware_name, "Test.X64.ScratchDecrypt");
            let l = pe::layout(&data).unwrap();
            assert_eq!(l.nsec, 1);
            assert_eq!(pe::entry_point(&data, &l), 0x1000);
            assert_eq!(&data[0x200..0x206], &ORIGINAL);
        }
        o => panic!("unexpected outcome {o:?}"),
    }
}

#[test]
fn call_function_diff_host_and_instruction_budget() {
    // 1) `diff_host: true` captures bytes written into `.text` by an isolated restore function.
    let mut vir = MAGIC.to_vec();
    vir.push(0xBF);
    vir.extend_from_slice(&(BASE + 0x1000).to_le_bytes()); // mov edi, BASE + 0x1000
    vir.extend_from_slice(&[0xC6, 0x07, 0xB8]); // mov byte [edi], 0xB8
    vir.extend_from_slice(&[0xC7, 0x47, 0x01, 0x01, 0x00, 0x00, 0x00]); // mov dword [edi+1], 1
    vir.push(0xC3); // ret

    let yaml = r#"
viruses:
  - name: Test.CallDiffHost
    arch: x86
    locate: section_scan
    signatures:
      - {offset: 0, hex: "48 44 54 45 53 54 56 49 52 55 53 21 21 21 21 21"}
    recover:
      method: call_function
      func: {mode: virus_offset, add: 0x10}
      max_instructions: 64
      diff_host: true
    cleanup:
      - action: remove_virus_section
"#;
    let rules = DisinfectRules::from_yaml_str(yaml).unwrap();
    let pe = build_pe(&[text_infected(), (".vir", 0x2000, vir, VIRUS)], 0x1000, 0);
    match disinfect_bytes_with(&pe, &rules) {
        DisinfectOutcome::Disinfected { data, .. } => assert_repaired(&data),
        o => panic!("unexpected outcome {o:?}"),
    }

    // 2) Infinite loop (`EB FE`) inside `func` stops at `max_instructions: 64` -> NotRepairable.
    let mut runaway = MAGIC.to_vec();
    runaway.extend_from_slice(&[0xEB, 0xFE]); // jmp $
    let bad_pe = build_pe(&[text_infected(), (".vir", 0x2000, runaway, VIRUS)], 0x1000, 0);
    match disinfect_bytes_with(&bad_pe, &rules) {
        DisinfectOutcome::NotRepairable { reason, .. } => assert!(reason.contains("call_function failed"), "{reason}"),
        o => panic!("unexpected outcome {o:?}"),
    }
}
