use hydradragonsig::models::{MemoryScanContext, ScanReport, Verdict};
use hydradragonsig::rules::{
    Remediation, RemediationOptions, RuleSet, run_remediation, run_rule_remediations,
};
use hydradragonsig::{ScanOptions, scan_memory, scan_path};
use std::path::Path;

fn scan_bytes(bytes: &[u8], rules: &RuleSet, options: &ScanOptions) -> ScanReport {
    let ctx = MemoryScanContext {
        buffer: bytes.to_vec(),
        identifier: "test.bin".to_string(),
        base_address: None,
    };
    scan_memory(&ctx, rules, options).expect("scan_memory")
}

/// Build a minimal valid 32-bit PE with:
/// - Section 1 (`.text`): VA 0x1000, raw offset 0x200, raw size 0x200 (EP at RVA 0x1000)
/// - Optional Section 2 (`.rsrc`): VA 0x2000, raw offset 0x400, raw size 0x200
///   holding `RT_RCDATA` (id 10) and `RT_VERSION` (id 14)
/// - Optional overlay bytes after the last section
/// - Optional `WIN_CERTIFICATE` (PKCS#7 SignedData) appended in the security directory
fn build_test_pe(with_resources: bool, with_overlay: bool, signer_cn: Option<&str>) -> Vec<u8> {
    let num_sections: u16 = if with_resources { 2 } else { 1 };
    let raw_end = if with_resources { 0x600usize } else { 0x400usize };
    let mut buf = vec![0u8; raw_end];

    // DOS header
    buf[0..2].copy_from_slice(b"MZ");
    buf[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    // PE signature at 0x80
    let pe_off = 0x80usize;
    buf[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");

    // COFF File Header (20 bytes at 0x84)
    let coff = pe_off + 4;
    buf[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // Machine = IMAGE_FILE_MACHINE_I386
    buf[coff + 2..coff + 4].copy_from_slice(&num_sections.to_le_bytes());
    buf[coff + 16..coff + 18].copy_from_slice(&0x00e0u16.to_le_bytes()); // SizeOfOptionalHeader
    buf[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics = EXECUTABLE_IMAGE | 32BIT_MACHINE

    // Optional Header PE32 (224 bytes at 0x98)
    let opt = coff + 20;
    buf[opt..opt + 2].copy_from_slice(&0x010bu16.to_le_bytes()); // PE32 magic
    buf[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint = 0x1000
    buf[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
    buf[opt + 28..opt + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes()); // ImageBase
    buf[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    buf[opt + 36..opt + 40].copy_from_slice(&0x0200u32.to_le_bytes()); // FileAlignment
    buf[opt + 56..opt + 60].copy_from_slice(&0x3000u32.to_le_bytes()); // SizeOfImage
    buf[opt + 60..opt + 64].copy_from_slice(&0x0200u32.to_le_bytes()); // SizeOfHeaders
    buf[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes()); // Subsystem = CUI
    buf[opt + 92..opt + 96].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes = 16

    let dd_base = opt + 96;
    if with_resources {
        // DataDirectory[2] = Resource table: RVA 0x2000, size 0x200
        let rsrc_dd = dd_base + 2 * 8;
        buf[rsrc_dd..rsrc_dd + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        buf[rsrc_dd + 4..rsrc_dd + 8].copy_from_slice(&0x0200u32.to_le_bytes());
    }

    // Section headers at opt + 0xe0 = 0x178
    let sec1 = opt + 0xe0;
    buf[sec1..sec1 + 5].copy_from_slice(b".text");
    buf[sec1 + 8..sec1 + 12].copy_from_slice(&0x0200u32.to_le_bytes()); // VirtualSize
    buf[sec1 + 12..sec1 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    buf[sec1 + 16..sec1 + 20].copy_from_slice(&0x0200u32.to_le_bytes()); // SizeOfRawData
    buf[sec1 + 20..sec1 + 24].copy_from_slice(&0x0200u32.to_le_bytes()); // PointerToRawData
    buf[sec1 + 36..sec1 + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE | EXECUTE | READ

    if with_resources {
        let sec2 = sec1 + 40;
        buf[sec2..sec2 + 5].copy_from_slice(b".rsrc");
        buf[sec2 + 8..sec2 + 12].copy_from_slice(&0x0200u32.to_le_bytes()); // VirtualSize
        buf[sec2 + 12..sec2 + 16].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
        buf[sec2 + 16..sec2 + 20].copy_from_slice(&0x0200u32.to_le_bytes()); // SizeOfRawData
        buf[sec2 + 20..sec2 + 24].copy_from_slice(&0x0400u32.to_le_bytes()); // PointerToRawData
        buf[sec2 + 36..sec2 + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED_DATA | READ
    }

    // Populate .text at file offset 0x200:
    // Entry point code + repeating 16-byte block at +0x20 and +0x60
    buf[0x200..0x208].copy_from_slice(&[0x55, 0x8B, 0xEC, 0x6A, 0x01, 0x68, 0x12, 0x34]);
    let repeat_block = *b"SELF_SIMILAR_BLK";
    buf[0x220..0x230].copy_from_slice(&repeat_block);
    buf[0x260..0x270].copy_from_slice(&repeat_block);
    buf[0x290..0x2A0].copy_from_slice(&repeat_block);

    // Populate .rsrc at file offset 0x400 (RVA 0x2000)
    if with_resources {
        let base = 0x400usize;
        // Root directory at +0x00: 2 ID entries (type 10 = RT_RCDATA, type 14 = RT_VERSION)
        buf[base + 14..base + 16].copy_from_slice(&2u16.to_le_bytes());
        // Entry 0: id=10, subdir at +0x20
        buf[base + 16..base + 20].copy_from_slice(&10u32.to_le_bytes());
        buf[base + 20..base + 24].copy_from_slice(&(0x8000_0020u32).to_le_bytes());
        // Entry 1: id=14, subdir at +0x38
        buf[base + 24..base + 28].copy_from_slice(&14u32.to_le_bytes());
        buf[base + 28..base + 32].copy_from_slice(&(0x8000_0038u32).to_le_bytes());

        // Name directory for type 10 at +0x20: 1 ID entry (name=1 -> subdir +0x50)
        buf[base + 0x20 + 14..base + 0x20 + 16].copy_from_slice(&1u16.to_le_bytes());
        buf[base + 0x20 + 16..base + 0x20 + 20].copy_from_slice(&1u32.to_le_bytes());
        buf[base + 0x20 + 20..base + 0x20 + 24].copy_from_slice(&(0x8000_0050u32).to_le_bytes());

        // Name directory for type 14 at +0x38: 1 ID entry (name=1 -> subdir +0x68)
        buf[base + 0x38 + 14..base + 0x38 + 16].copy_from_slice(&1u16.to_le_bytes());
        buf[base + 0x38 + 16..base + 0x38 + 20].copy_from_slice(&1u32.to_le_bytes());
        buf[base + 0x38 + 20..base + 0x38 + 24].copy_from_slice(&(0x8000_0068u32).to_le_bytes());

        // Lang directory for type 10 at +0x50: 1 ID entry (lang=0x0409 -> data entry +0x80)
        buf[base + 0x50 + 14..base + 0x50 + 16].copy_from_slice(&1u16.to_le_bytes());
        buf[base + 0x50 + 16..base + 0x50 + 20].copy_from_slice(&0x0409u32.to_le_bytes());
        buf[base + 0x50 + 20..base + 0x50 + 24].copy_from_slice(&0x0080u32.to_le_bytes());

        // Lang directory for type 14 at +0x68: 1 ID entry (lang=0x0409 -> data entry +0x90)
        buf[base + 0x68 + 14..base + 0x68 + 16].copy_from_slice(&1u16.to_le_bytes());
        buf[base + 0x68 + 16..base + 0x68 + 20].copy_from_slice(&0x0409u32.to_le_bytes());
        buf[base + 0x68 + 20..base + 0x68 + 24].copy_from_slice(&0x0090u32.to_le_bytes());

        // Data entry for RT_RCDATA at +0x80: RVA = 0x20A0 (file offset 0x4A0), size = 19
        let rcdata = b"RCDATA_PAYLOAD_1234";
        buf[base + 0x80..base + 0x84].copy_from_slice(&0x20A0u32.to_le_bytes());
        buf[base + 0x84..base + 0x88].copy_from_slice(&(rcdata.len() as u32).to_le_bytes());
        buf[base + 0xA0..base + 0xA0 + rcdata.len()].copy_from_slice(rcdata);

        // Data entry for RT_VERSION at +0x90: RVA = 0x20C0 (file offset 0x4C0)
        let ver_blob = build_version_info_blob("Acme Corp", "Widget Setup");
        buf[base + 0x90..base + 0x94].copy_from_slice(&0x20C0u32.to_le_bytes());
        buf[base + 0x94..base + 0x98].copy_from_slice(&(ver_blob.len() as u32).to_le_bytes());
        buf[base + 0xC0..base + 0xC0 + ver_blob.len()].copy_from_slice(&ver_blob);
    }

    if with_overlay {
        buf.extend_from_slice(&[0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD]);
    }

    if let Some(cn) = signer_cn {
        let cert_off = buf.len() as u32;
        let pkcs7 = build_minimal_pkcs7_with_cn(cn);
        let win_cert_len = (8 + pkcs7.len()) as u32;
        buf.extend_from_slice(&win_cert_len.to_le_bytes());
        buf.extend_from_slice(&0x0200u16.to_le_bytes()); // wRevision
        buf.extend_from_slice(&0x0002u16.to_le_bytes()); // wCertificateType = WIN_CERT_TYPE_PKCS_SIGNED_DATA
        buf.extend_from_slice(&pkcs7);
        // Set DataDirectory[4] (SECURITY_DIRECTORY): file offset + size
        let sec_dd = dd_base + 4 * 8;
        buf[sec_dd..sec_dd + 4].copy_from_slice(&cert_off.to_le_bytes());
        buf[sec_dd + 4..sec_dd + 8].copy_from_slice(&win_cert_len.to_le_bytes());
    }

    buf
}

fn push_utf16z(out: &mut Vec<u8>, text: &str) {
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
}

fn align4(out: &mut Vec<u8>) {
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

fn build_version_field(key: &str, value: &str) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    push_utf16z(&mut b, key);
    align4(&mut b);
    let val_words = (value.encode_utf16().count() + 1) as u16;
    push_utf16z(&mut b, value);
    align4(&mut b);
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b[2..4].copy_from_slice(&val_words.to_le_bytes());
    b[4..6].copy_from_slice(&1u16.to_le_bytes());
    b
}

fn build_version_info_blob(company: &str, product: &str) -> Vec<u8> {
    let mut root = vec![0u8; 6];
    push_utf16z(&mut root, "VS_VERSION_INFO");
    align4(&mut root);

    // 52-byte VS_FIXEDFILEINFO
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    // file_version 1.2.3.4 at +8..+16
    fixed[8..12].copy_from_slice(&((1u32 << 16) | 2u32).to_le_bytes());
    fixed[12..16].copy_from_slice(&((3u32 << 16) | 4u32).to_le_bytes());
    // product_version 1.2.3.4 at +16..+24
    fixed[16..20].copy_from_slice(&((1u32 << 16) | 2u32).to_le_bytes());
    fixed[20..24].copy_from_slice(&((3u32 << 16) | 4u32).to_le_bytes());
    root.extend_from_slice(&fixed);
    align4(&mut root);

    // Language table "040904B0"
    let mut lang = vec![0u8; 6];
    push_utf16z(&mut lang, "040904B0");
    align4(&mut lang);
    lang.extend_from_slice(&build_version_field("CompanyName", company));
    lang.extend_from_slice(&build_version_field("ProductName", product));
    let lang_len = lang.len() as u16;
    lang[0..2].copy_from_slice(&lang_len.to_le_bytes());
    lang[4..6].copy_from_slice(&1u16.to_le_bytes());

    // StringFileInfo block
    let mut sfi = vec![0u8; 6];
    push_utf16z(&mut sfi, "StringFileInfo");
    align4(&mut sfi);
    sfi.extend_from_slice(&lang);
    let sfi_len = sfi.len() as u16;
    sfi[0..2].copy_from_slice(&sfi_len.to_le_bytes());
    sfi[4..6].copy_from_slice(&1u16.to_le_bytes());

    root.extend_from_slice(&sfi);
    let root_len = root.len() as u16;
    root[0..2].copy_from_slice(&root_len.to_le_bytes());
    root[2..4].copy_from_slice(&(fixed.len() as u16).to_le_bytes());
    root[4..6].copy_from_slice(&0u16.to_le_bytes());
    root
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = body.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(body);
    out
}

fn build_minimal_pkcs7_with_cn(cn: &str) -> Vec<u8> {
    // AttributeTypeAndValue := SEQ { OID(2.5.4.3), UTF8String(cn) }
    let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let val_cn = der_tlv(0x0C, cn.as_bytes());
    let mut atv_body = oid_cn;
    atv_body.extend_from_slice(&val_cn);
    let atv = der_tlv(0x30, &atv_body);
    let rdn = der_tlv(0x31, &atv);
    let name = der_tlv(0x30, &rdn);

    // tbsCertificate := SEQ { version [0], serial INT, sig SEQ, issuer Name }
    let mut tbs_body = Vec::new();
    tbs_body.extend_from_slice(&der_tlv(0xA0, &der_tlv(0x02, &[2])));
    tbs_body.extend_from_slice(&der_tlv(0x02, &[1]));
    tbs_body.extend_from_slice(&der_tlv(0x30, &[]));
    tbs_body.extend_from_slice(&name);
    let tbs = der_tlv(0x30, &tbs_body);
    let cert = der_tlv(0x30, &tbs);
    let certs = der_tlv(0xA0, &cert);

    // SignedData := SEQ { version INT, digestAlgs SET, contentInfo SEQ, [0] certs }
    let mut sd_body = Vec::new();
    sd_body.extend_from_slice(&der_tlv(0x02, &[1]));
    sd_body.extend_from_slice(&der_tlv(0x31, &[]));
    sd_body.extend_from_slice(&der_tlv(0x30, &[]));
    sd_body.extend_from_slice(&certs);
    let signed_data = der_tlv(0x30, &sd_body);

    // ContentInfo := SEQ { oid, [0] signed_data }
    let mut ci_body = der_tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]);
    ci_body.extend_from_slice(&der_tlv(0xA0, &signed_data));
    der_tlv(0x30, &ci_body)
}

#[test]
fn pe_anchor_and_byte_repeat_conditions() {
    let pe_bytes = build_test_pe(true, true, None);
    let yaml = r#"
rules:
  - id: TEST-PE-ANCHORS
    title: "PE anchor pattern and byte repeat"
    severity: high
    verdict: malware
    logic: all
    conditions:
      - type: pe_anchor_pattern
        anchor: entry
        patterns: ["55 8B EC 6A ?? 68 1? ?4"]
      - type: pe_anchor_pattern
        anchor: section
        section: 1
        offset: 4
        patterns: ["!! 68 12 34"]
      - type: pe_anchor_pattern
        anchor: overlay
        offset: 2
        patterns: ["AA BB !! DD"]
      - type: pe_anchor_pattern
        anchor: entry
        patterns: ["DE AD BE EF"]
        negate: true
      - type: byte_repeat
        anchor: section_1
        offset: 32
        length: 16
        min: 2
"#;
    let rules = RuleSet::from_yaml_str_strict(yaml).expect("valid rules");
    let report = scan_bytes(&pe_bytes, &rules, &ScanOptions::default());
    assert_eq!(report.verdict, Verdict::Malware);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule_id, "TEST-PE-ANCHORS");
}

#[test]
fn resources_version_and_authenticode_conditions() {
    let signed_pe = build_test_pe(true, false, Some("Acme Signer Ltd"));
    let bare_pe = build_test_pe(false, false, None);

    let md5_rcdata = hydradragonsig::rules::system_windows::md5_hex(b"RCDATA_PAYLOAD_1234");
    let yaml = format!(
        r#"
rules:
  - id: TEST-RICH-PE
    title: "Matches resources, version_info and authenticode"
    severity: high
    verdict: malware
    logic: all
    conditions:
      - type: authenticode
        signed: true
        subject_glob: "Acme * Ltd"
      - type: version_info
        fields:
          CompanyName: "Acme*"
          "8": "Widget*"
          "3": "1.2.3.4"
      - type: resource_match
        type_glob: "RT_RCDATA:0409"
        size_min: 10
        size_max: 64
        data_patterns: ["52 43 44 41 54 41"]
      - type: resource_hash_any
        values: ["{md5_rcdata}"]

  - id: TEST-BARE-PE
    title: "Matches unsigned resource-less PE"
    severity: medium
    verdict: suspicious
    logic: all
    conditions:
      - type: authenticode
        signed: false
      - type: version_info
        absent: true
      - type: resources_absent
"#
    );

    let rules = RuleSet::from_yaml_str_strict(&yaml).expect("valid rules");
    let rep_signed = scan_bytes(&signed_pe, &rules, &ScanOptions::default());
    assert_eq!(rep_signed.findings.len(), 1);
    assert_eq!(rep_signed.findings[0].rule_id, "TEST-RICH-PE");

    let rep_bare = scan_bytes(&bare_pe, &rules, &ScanOptions::default());
    assert_eq!(rep_bare.findings.len(), 1);
    assert_eq!(rep_bare.findings[0].rule_id, "TEST-BARE-PE");
}

#[test]
fn not_mz_path_glob_and_feature_bounds() {
    let raw = b"\xEB\x3C\x90NTFS    bootsector payload data";
    let dir = std::env::temp_dir().join("hydradragonsig_test_glob");
    let _ = std::fs::create_dir_all(&dir);
    let sample_path = dir.join("c_01k46.nls");
    std::fs::write(&sample_path, raw).unwrap();

    let yaml = r#"
rules:
  - id: TEST-NONMZ-GLOB
    title: "Non-MZ file with path glob and feature bounds"
    severity: high
    verdict: malware
    logic: all
    conditions:
      - type: not_mz
      - type: path_glob
        pattern: "**\\c_#####.nls"
      - type: pe_anchor_pattern
        anchor: absolute
        offset: 3
        patterns: ["4E 54 46 53"]
      - type: feature_bounds
        bounds:
          - feature: file_entropy_bits_per_byte
            min: 0.5
            max: 7.5
"#;
    let rules = RuleSet::from_yaml_str_strict(yaml).expect("valid rules");
    let report = scan_path(&sample_path, &rules, &ScanOptions::default()).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(report.verdict, Verdict::Malware);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn declarative_remediation_dry_run_and_apply() {
    let dir = std::env::temp_dir().join("hydradragonsig_test_remediation");
    let _ = std::fs::create_dir_all(&dir);
    let hosts_file = dir.join("hosts_mock.txt");
    let prefs_file = dir.join("prefs_mock.js");
    let drop_file = dir.join("dropper.bin");

    std::fs::write(
        &hosts_file,
        "127.0.0.1 localhost\n123.123.123.123 hijack.example\n",
    )
    .unwrap();
    std::fs::write(
        &prefs_file,
        "user_pref(\"startup\", \"http://bad.example/\");\n",
    )
    .unwrap();
    std::fs::write(&drop_file, b"dropper").unwrap();

    let yaml = format!(
        r#"
rules:
  - id: TEST-REMEDIATE-001
    title: "Remediation test"
    severity: high
    verdict: malware
    conditions:
      - type: not_mz
    remediation:
      - type: text_delete_line
        path: '{}'
        pattern: "123.123.123.123 hijack.example"
      - type: text_replace
        path: '{}'
        pattern: "http://bad.example/"
        replacement: "https://clean.example/"
      - type: file_delete
      - type: command
        program: "cmd.exe"
        args: ["/c", "echo", "remediated"]
"#,
        hosts_file.display().to_string().replace('\'', "''"),
        prefs_file.display().to_string().replace('\'', "''"),
    );

    let rules = RuleSet::from_yaml_str_strict(&yaml).expect("valid rules");
    let rule = &rules.rules()[0];

    // 1. Dry-run: nothing is modified on disk
    let dry = run_rule_remediations(
        rule,
        Some(drop_file.as_path()),
        RemediationOptions {
            apply: false,
            allow_commands: false,
        },
    );
    assert_eq!(dry.len(), 4);
    assert!(dry.iter().all(|o| !o.applied && o.success));
    assert!(drop_file.exists());

    // 2. Apply without allow_commands: text and file ops apply, command is skipped
    let applied = run_rule_remediations(
        rule,
        Some(drop_file.as_path()),
        RemediationOptions {
            apply: true,
            allow_commands: false,
        },
    );
    assert!(applied[0].applied && applied[0].success);
    assert!(applied[1].applied && applied[1].success);
    assert!(applied[2].applied && applied[2].success);
    assert!(!applied[3].applied && !applied[3].success);

    let hosts_after = std::fs::read_to_string(&hosts_file).unwrap();
    assert_eq!(hosts_after, "127.0.0.1 localhost\n");
    let prefs_after = std::fs::read_to_string(&prefs_file).unwrap();
    assert!(prefs_after.contains("https://clean.example/"));
    assert!(!drop_file.exists());

    // 3. text_delete_string
    let del_str_out = run_remediation(
        "TEST-REMEDIATE-001",
        &Remediation::TextDeleteString {
            path: prefs_file.display().to_string(),
            pattern: "https://clean.example/".into(),
        },
        Some(Path::new("")),
        RemediationOptions {
            apply: true,
            allow_commands: false,
        },
    );
    assert!(del_str_out.applied);
    assert!(!std::fs::read_to_string(&prefs_file).unwrap().contains("clean.example"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(windows)]
#[test]
fn windows_registry_conditions_evaluate() {
    let yaml = r#"
rules:
  - id: TEST-WIN-REG
    title: "Windows registry probe"
    severity: info
    verdict: suspicious
    logic: all
    conditions:
      - type: registry_key
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        value_pattern: "^ProductName$"
      - type: registry_value
        key: "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        value_regex: "^ProductName$"
        data_regex: ".+"
"#;
    let rules = RuleSet::from_yaml_str_strict(yaml).expect("valid rules");
    let report = scan_bytes(b"probe", &rules, &ScanOptions::default());
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn section_hashes_summary_crc32_sha1_and_file_metadata_conditions() {
    let mut pe = build_test_pe(true, false, None);
    // Set IMAGE_FILE_HEADER.TimeDateStamp at PE + 8 (0x88) to 0x5D5B7417
    pe[0x88..0x8C].copy_from_slice(&0x5D5B_7417u32.to_le_bytes());

    let file_sha1 = hydradragonsig::utils::hash::sha1_hex(&pe);
    let file_crc32 = hydradragonsig::utils::hash::crc32_hex(&pe);
    let text_slice = &pe[0x200..0x400];
    let text_md5 = hydradragonsig::utils::hash::md5_hex(text_slice);
    let text_crc32 = hydradragonsig::utils::hash::crc32_hex(text_slice);
    let all_sections_slice = &pe[0x200..0x600];
    let sections_md5 = hydradragonsig::utils::hash::md5_hex(all_sections_slice);
    let sections_crc32 = hydradragonsig::utils::hash::crc32_hex(all_sections_slice);

    let dir = std::env::temp_dir().join(format!("hydradragonsig_meta_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sample_path = dir.join("sample_client.exe");
    std::fs::write(&sample_path, &pe).unwrap();

    let yaml = format!(
        r#"
rules:
  - id: TEST-EXTENDED-PE-AND-META
    title: "PE section index/hash, sections summary, export hash, crc32/sha1 and file metadata"
    severity: high
    verdict: malware
    score: 90
    logic: all
    conditions:
      - type: hash_sha1
        value: "{file_sha1}"
      - type: hash_crc32
        value: "{file_crc32}"
      - type: pe_timestamp
        hex: "5D5B7417"
      - type: pe_section
        index: 0
        name: ".text"
        raw_offset: 0x200
        raw_size: 512
        virtual_address: 0x1000
        virtual_size: 0x200
        characteristics: 0x60000020
        md5: "{text_md5}"
        crc32: "{text_crc32}"
      - type: pe_sections_summary
        count: 2
        total_raw_size: 1024
        md5: "{sections_md5}"
        crc32: "{sections_crc32}"
      - type: export_hash_any
        values:
          - "D41D8CD98F00B204E9800998ECF8427E"
      - type: file_timestamp
        age_days_max: 1
      - type: file_attributes
        spec: "A+D-H-L-R-S-"
"#
    );

    let rules = RuleSet::from_yaml_str_strict(&yaml).expect("valid rules");
    let report = scan_path(&sample_path, &rules, &ScanOptions::default()).expect("scan_path ok");
    let ids: Vec<&str> = report.findings.iter().map(|f| f.rule_id.as_str()).collect();
    assert!(
        ids.contains(&"TEST-EXTENDED-PE-AND-META"),
        "expected TEST-EXTENDED-PE-AND-META in {ids:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
