use std::path::Path;
use std::sync::Arc;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SignerRuleFile {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub rules: Vec<SignerRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerRule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
    /// Why the rule exists. Carried into the detection's `details` so the
    /// dashboard can say *why* a publisher is listed, not only that it is.
    #[serde(default)]
    pub description: String,
    /// `info` / `low` / `medium` / `high` / `critical` (any case). Metadata
    /// only: the score still comes from the list the rule lands in.
    #[serde(default)]
    pub severity: String,
    /// `trusted`, `malware` (alias `malicious`) or `pua`. The shipped files
    /// are already split by verdict, so the loader ignores this there; for
    /// analyst rules (one mixed document) it decides the list.
    #[serde(default)]
    pub verdict: String,
    /// Malware family the certificate is known for (`Trojan.FakeAV`). When set
    /// it becomes the detection name, which is what an analyst searches for.
    #[serde(default)]
    pub family: String,
    #[serde(default)]
    pub conditions: Vec<SignerCondition>,
}

/// Per-rule metadata kept next to every pattern a rule contributed, so a match
/// can report the rule that fired instead of only the list it came from. One
/// `Arc` per rule, shared by all of its conditions.
#[derive(Debug, Clone, Default)]
pub struct SignerRuleMeta {
    pub id: String,
    pub title: String,
    pub description: String,
    pub family: Option<String>,
    pub severity: Option<String>,
}

impl SignerRuleMeta {
    fn from_rule(rule: &SignerRule) -> Self {
        let opt = |s: &str| {
            let t = s.trim();
            (!t.is_empty()).then(|| t.to_string())
        };
        Self {
            id: rule.id.trim().to_string(),
            title: rule.title.trim().to_string(),
            description: rule.description.trim().to_string(),
            family: opt(&rule.family),
            severity: opt(&rule.severity),
        }
    }

    /// `"<title>: <description>"`, or whichever of the two is present. `None`
    /// when the rule carried neither, so callers fall back to their old text.
    pub fn summary(&self) -> Option<String> {
        match (self.title.is_empty(), self.description.is_empty()) {
            (false, false) => Some(format!("{}: {}", self.title, self.description)),
            (false, true) => Some(self.title.clone()),
            (true, false) => Some(self.description.clone()),
            (true, true) => None,
        }
    }
}

/// Condition types the loader understands. Anything else is silently ignored
/// for the shipped files (see SIGNER_RULES.md), but rejected for analyst rules,
/// where a typo must not quietly disable the rule.
const SIGNER_CONDITION_TYPES: &[&str] = &[
    "signature_signer_contains",
    "signature_signer_equals",
    "signature_issuer_contains",
    "signature_issuer_equals",
    "signature_timestamp_signer_contains",
    "signature_timestamp_signer_equals",
    "signature_thumbprint_any",
    "signature_thumbprint_equals",
];

/// Which list an analyst rule feeds. Parsed from `SignerRule::verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignerVerdict {
    Trusted,
    Malware,
    Pua,
}

impl SignerVerdict {
    fn parse(v: &str) -> Option<Self> {
        match v.trim().to_ascii_lowercase().as_str() {
            "trusted" => Some(Self::Trusted),
            "malware" | "malicious" => Some(Self::Malware),
            "pua" => Some(Self::Pua),
            _ => None,
        }
    }
}

/// `aa:bb:..`, `aa bb ..`, `aa-bb-..` or bare hex to 40 lowercase hex chars.
/// Strict: any other character is an error rather than being dropped, so a
/// pasted value with stray text cannot collapse into a different digest.
fn normalize_thumbprint_strict(value: &str) -> Result<String, String> {
    let mut hex = String::with_capacity(40);
    for c in value.trim().chars() {
        if c.is_ascii_hexdigit() {
            hex.push(c.to_ascii_lowercase());
        } else if !matches!(c, ':' | ' ' | '-') {
            return Err(format!("thumbprint contains invalid character {c:?}"));
        }
    }
    if hex.len() != 40 {
        return Err(format!("thumbprint must be 40 hex chars (SHA-1), got {}", hex.len()));
    }
    Ok(hex)
}

/// Validate an analyst signer-rule document (same schema as the shipped
/// `signer_rules/*.yaml`). Stricter than the shipped loader on purpose: every
/// rule needs a non-empty `id` and `title`, a `verdict` of `trusted`,
/// `malware` (`malicious`) or `pua`, at least one condition, and only known
/// condition types. Trusted rules may only use `signature_signer_*`, because
/// trust is only ever decided on the publisher (`SignerDb::is_trusted`).
///
/// Conditions of one rule are independent (any one matching is a hit), exactly
/// as in the shipped files.
///
/// Returns the rule count.
pub fn validate_signer_rules_yaml(src: &str) -> Result<usize, String> {
    parse_analyst_signer_rules(src).map(|rules| rules.len())
}

fn parse_analyst_signer_rules(src: &str) -> Result<Vec<(SignerVerdict, SignerRule)>, String> {
    let file: SignerRuleFile =
        serde_yaml::from_str(src).map_err(|e| format!("YAML parse error: {e}"))?;
    if file.rules.is_empty() {
        return Err("document contains no rules".to_string());
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(file.rules.len());
    for (idx, rule) in file.rules.into_iter().enumerate() {
        let id = rule.id.trim();
        if id.is_empty() {
            return Err(format!("rule #{}: missing `id`", idx + 1));
        }
        if !seen.insert(id.to_string()) {
            return Err(format!("rule {id}: duplicate `id`"));
        }
        if rule.title.trim().is_empty() {
            return Err(format!("rule {id}: missing `title`"));
        }
        let verdict = SignerVerdict::parse(&rule.verdict).ok_or_else(|| {
            format!(
                "rule {id}: `verdict` must be trusted, malware (malicious) or pua, got {:?}",
                rule.verdict
            )
        })?;
        if rule.conditions.is_empty() {
            return Err(format!("rule {id}: needs at least one condition"));
        }
        for (ci, cond) in rule.conditions.iter().enumerate() {
            let t = cond.cond_type.as_str();
            if !SIGNER_CONDITION_TYPES.contains(&t) {
                return Err(format!(
                    "rule {id}: condition #{}: unsupported type {t:?} (supported: {})",
                    ci + 1,
                    SIGNER_CONDITION_TYPES.join(", ")
                ));
            }
            if cond.value.trim().is_empty() {
                return Err(format!("rule {id}: condition #{} ({t}): empty `value`", ci + 1));
            }
            if verdict == SignerVerdict::Trusted && !t.starts_with("signature_signer_") {
                return Err(format!(
                    "rule {id}: condition #{} ({t}): trusted rules only support signature_signer_contains / signature_signer_equals",
                    ci + 1
                ));
            }
            if t.starts_with("signature_thumbprint_") {
                normalize_thumbprint_strict(&cond.value)
                    .map_err(|e| format!("rule {id}: condition #{} ({t}): {e}", ci + 1))?;
            }
        }
        out.push((verdict, rule));
    }
    Ok(out)
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignerCondition {
    #[serde(rename = "type")]
    pub cond_type: String,
    #[serde(default)]
    pub value: String,
    #[serde(default)]
    pub nocase: bool,
}

/// Everything the engine needs to know about a file's Authenticode signature.
///
/// Replaces the positional tuple this used to return: five fields were already
/// the limit, and the certificate identity (issuer, chain, thumbprint,
/// validity) needs more than that.
#[derive(Debug, Clone, Default)]
pub struct AuthenticodeInfo {
    /// A signature exists and WinVerifyTrust (or the catalog fallback) could
    /// read a chain from it.
    pub is_signed: bool,
    /// WinVerifyTrust returned `ERROR_SUCCESS` for the embedded or catalog
    /// signature. Independent of `signer_rules/`.
    pub is_trusted: bool,
    /// Publisher display name of the leaf certificate.
    pub signer_name: Option<String>,
    /// Display name of the CA that issued the leaf.
    pub issuer: Option<String>,
    /// `trusted` / `signed_untrusted` / `unsigned`, or an error string.
    pub status: String,
    /// Signed through the Windows Catalog rather than an embedded PKCS#7.
    pub is_catalog_signed: bool,
    /// Certificates in the verified chain, leaf first.
    pub chain_len: usize,
    /// SHA-1 of the leaf certificate, lowercase hex.
    pub thumbprint: Option<String>,
    /// Leaf certificate validity window, Unix seconds.
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// The signature carries a countersignature - RFC 3161 or legacy PKCS#9.
    /// Malware routinely strips or re-mints these so a certificate looks
    /// permanently fresh, which makes "signed but never timestamped" a signal
    /// in its own right.
    pub timestamped: bool,
    /// `rfc3161` or `pkcs9`.
    pub timestamp_kind: Option<String>,
    /// Common name of the TSA / countersigner.
    pub timestamp_signer: Option<String>,
    /// `genTime` of the RFC 3161 token, Unix seconds. Always `None` for a
    /// legacy PKCS#9 countersignature, which carries no timestamp value.
    pub timestamp_time: Option<i64>,
}

impl AuthenticodeInfo {
    /// Placeholder verdict for platforms without WinTrust. Only the
    /// `#[cfg(not(windows))]` stub builds it.
    #[cfg_attr(windows, allow(dead_code))]
    fn unsupported(reason: &str) -> Self {
        Self { status: reason.to_string(), ..Default::default() }
    }

    /// True when the leaf certificate was past `not_after` at scan time.
    /// WinVerifyTrust already fails an expired leaf, so this only ever fires on
    /// the `signed_untrusted` path — which is exactly the interesting one.
    pub fn is_expired(&self, now: i64) -> bool {
        self.not_after.map(|t| now > t).unwrap_or(false)
    }

    /// True when the leaf certificate is not valid yet.
    pub fn is_not_yet_valid(&self, now: i64) -> bool {
        self.not_before.map(|t| now < t).unwrap_or(false)
    }

    /// Expired, and no timestamp keeps the signature valid. A timestamped
    /// (countersigned) signature made while the certificate was valid stays valid
    /// after the certificate expires; Windows accepts it the same way. So this
    /// fires only without a timestamp, or with a timestamp outside the
    /// certificate's validity window (signed after it expired, or before it was
    /// issued). A legacy PKCS#9 countersignature carries no time: accepted, as
    /// Windows does.
    pub fn is_expired_untimestamped(&self, now: i64) -> bool {
        if !self.is_expired(now) {
            return false;
        }
        if !self.timestamped {
            return true;
        }
        match self.timestamp_time {
            Some(t) => self.not_after.is_some_and(|to| t > to) || self.not_before.is_some_and(|from| t < from),
            None => false,
        }
    }

    /// Signed, trusted, and carrying no countersignature at all.
    ///
    /// Only meaningful for embedded signatures: a catalog-signed file has no
    /// PKCS#7 of its own, so the catalog is not "missing" a timestamp and this
    /// must not fire on it.
    pub fn is_undated(&self) -> bool {
        self.is_signed && !self.timestamped && !self.is_catalog_signed
    }
}

#[derive(Debug, Clone)]
pub struct PatternItem {
    pub value: String,
    pub is_exact: bool,
    /// The rule this pattern came from. `None` only for patterns built without
    /// a rule document.
    pub meta: Option<Arc<SignerRuleMeta>>,
}

#[derive(Debug, Clone, Default)]
pub struct SignerDb {
    trusted: Vec<PatternItem>,
    malicious: Vec<PatternItem>,
    pua: Vec<PatternItem>,
    /// Issuing CAs. A certificate is abused by the CA that minted it, not by
    /// the publisher string it carries, so these lists are matched against
    /// `AuthenticodeInfo::issuer` and catch certificates whose subject has
    /// nothing to do with the abusive CA.
    malicious_issuers: Vec<PatternItem>,
    pua_issuers: Vec<PatternItem>,
    /// Timestamp authorities behind the countersignature. A separate trust
    /// domain from the code-signing certificate: an attacker who cannot get a
    /// code-signing cert can still occasionally talk a friendly TSA into dating
    /// a signature.
    malicious_tsas: Vec<PatternItem>,
    /// Leaf certificate SHA-1 fingerprints, lowercase hex. Pins one exact
    /// certificate - the only way to name a revoked-but-still-trusted one.
    /// `PatternItem` (always exact) rather than a bare string so a pin can
    /// report the rule that set it.
    pinned_thumbprints: Vec<PatternItem>,
    /// SHA-256 benign whitelist (`.xf`, BinaryFuse32 only). Owned by the signer side on
    /// purpose: this is the file-identity trust table, and it sits next to the
    /// vendor lists so `SignerDb` stays the single authority for "is this file
    /// trusted" — the answer libedr and owlyshield_predict already ask this
    /// object for.
    benign: Option<BinaryFuse32Filter>,
}

/// File name of the SHA-256 benign whitelist, under `xorfilter_rules/`.
pub const BENIGN_XF: &str = "benign_sha256.xf";

/// File name of the URL/domain/IP whitelist (BinaryFuse16 `.xf`, Tranco 1M),
/// under `xorfilter_rules/`. Web parity: `openedr_web`'s `url_whitelist`.
pub const URL_WHITELIST_XF: &str = "url_whitelist.xf";

impl SignerDb {
    pub fn pattern_counts(&self) -> (usize, usize, usize) {
        (self.trusted.len(), self.malicious.len(), self.pua.len())
    }

    /// True when the SHA-256 whitelist was loaded and can answer queries.
    pub fn benign_loaded(&self) -> bool {
        self.benign.is_some()
    }

    pub fn load_from_dir(dir: &Path) -> Self {
        let mut db = Self::default();
        if !dir.is_dir() {
            return db;
        }

        let trusted = Self::load_file(&dir.join("trusted_signers.yaml"));
        let malicious = Self::load_file(&dir.join("malicious_vendors.yaml"));
        let pua = Self::load_file(&dir.join("pua_vendors.yaml"));

        db.trusted = trusted.names;
        db.malicious = malicious.names;
        db.malicious_issuers = malicious.issuers;
        db.malicious_tsas = malicious.tsas;
        db.pinned_thumbprints = malicious.thumbprints;
        db.pua = pua.names;
        db.pua_issuers = pua.issuers;
        db
    }

    /// Append an analyst signer-rule document (see
    /// [`validate_signer_rules_yaml`]) to the loaded corpus. Each rule lands in
    /// the lists of its own `verdict`: trusted -> publishers; malware ->
    /// publishers / issuers / TSAs / pinned thumbprints; pua -> publishers /
    /// issuers (the PUA side has no TSA or pin list, so those conditions on a
    /// PUA rule are accepted but, like in `pua_vendors.yaml`, never consulted).
    ///
    /// All-or-nothing: the document is validated in full before anything is
    /// added. Returns the rule count.
    pub fn add_rules_yaml(&mut self, src: &str) -> Result<usize, String> {
        let rules = parse_analyst_signer_rules(src)?;
        let count = rules.len();
        for (verdict, rule) in rules {
            let loaded = LoadedConditions::from_rules(std::slice::from_ref(&rule));
            match verdict {
                SignerVerdict::Trusted => self.trusted.extend(loaded.names),
                SignerVerdict::Malware => {
                    self.malicious.extend(loaded.names);
                    self.malicious_issuers.extend(loaded.issuers);
                    self.malicious_tsas.extend(loaded.tsas);
                    self.pinned_thumbprints.extend(loaded.thumbprints);
                }
                SignerVerdict::Pua => {
                    self.pua.extend(loaded.names);
                    self.pua_issuers.extend(loaded.issuers);
                }
            }
        }
        Ok(count)
    }

    /// Load the SHA-256 benign whitelist from `xorfilter_rules/benign_sha256.xf`.
    ///
    /// Returns `false` when the file is missing or is not a valid filter; the
    /// whitelist then simply stays disabled, which is not an error — an install
    /// built without a corpus ships no `.xf`.
    pub fn load_benign_whitelist(&mut self, xf_path: &Path) -> bool {
        let Ok(bytes) = std::fs::read(xf_path) else {
            return false;
        };
        match BinaryFuse32Filter::load(&bytes) {
            Ok(f) => {
                self.benign = Some(f);
                true
            }
            Err(e) => {
                eprintln!("[signers] {}: {e}", xf_path.display());
                false
            }
        }
    }

    /// Install a filter loaded from bytes at runtime (FFI parity with the web
    /// engine, which receives the `.xf` over `wasm-bindgen`).
    pub fn set_benign_whitelist(&mut self, data: &[u8]) -> bool {
        match BinaryFuse32Filter::from_bytes(data) {
            Some(f) => {
                self.benign = Some(f);
                true
            }
            None => false,
        }
    }

    /// SHA-256 whitelist hit. Web parity (`openedr_web`: `is_benign(sha256_hex)`).
    ///
    /// The key is the bare lowercase-or-uppercase hex digest, folded to lowercase
    /// by `BinaryFuse16Filter::key`, so digest casing can never cause a miss.
    pub fn is_benign(&self, sha256_hex: &str) -> bool {
        if sha256_hex.is_empty() {
            return false;
        }
        match &self.benign {
            Some(f) => f.contains(sha256_hex),
            None => false,
        }
    }
}

/// Condition values collected from one `signer_rules/*.yaml` file.
///
/// `signature_signer_*` addresses the publisher (the leaf subject);
/// `signature_issuer_*` addresses the CA that minted the certificate. They are
/// kept apart because a compromised CA signs for arbitrary subjects, so a rule
/// written only against publishers never sees it.
#[derive(Default)]
struct LoadedConditions {
    names: Vec<PatternItem>,
    issuers: Vec<PatternItem>,
    /// Timestamp authorities behind the countersignature.
    tsas: Vec<PatternItem>,
    /// Leaf SHA-1 fingerprints, colon-stripped and lowercased.
    thumbprints: Vec<PatternItem>,
}

impl SignerDb {
    pub fn is_malicious(&self, signer: &str) -> bool {
        self.malicious_match(signer).is_some()
    }

    pub fn is_pua(&self, signer: &str) -> bool {
        self.pua_match(signer).is_some()
    }

    pub fn is_trusted(&self, signer: &str) -> bool {
        self.trusted_match(signer).is_some()
    }

    /// Issuing CA is listed as a malware certificate source.
    pub fn is_malicious_issuer(&self, issuer: &str) -> bool {
        self.malicious_issuer_match(issuer).is_some()
    }

    /// Issuing CA is listed as a PUA / unwanted-software certificate source.
    pub fn is_pua_issuer(&self, issuer: &str) -> bool {
        self.pua_issuer_match(issuer).is_some()
    }

    /// Leaf certificate is pinned by exact SHA-1.
    pub fn is_pinned_thumbprint(&self, thumbprint: &str) -> bool {
        self.pinned_thumbprint_match(thumbprint).is_some()
    }

    /// Timestamp authority behind the countersignature is listed as abusive.
    ///
    /// The TSA is a different trust domain from the code-signing certificate:
    /// an attacker who cannot get a code-signing cert can still occasionally
    /// talk a friendly TSA into dating a signature.
    pub fn is_malicious_tsa(&self, tsa: &str) -> bool {
        self.malicious_tsa_match(tsa).is_some()
    }

    // --- `*_match`: same decisions as the `is_*` above, but returning the
    // pattern that fired so the caller can report its rule (`PatternItem::meta`).

    pub fn malicious_match(&self, signer: &str) -> Option<&PatternItem> {
        Self::find_in_list(&self.malicious, signer)
    }

    pub fn pua_match(&self, signer: &str) -> Option<&PatternItem> {
        Self::find_in_list(&self.pua, signer)
    }

    /// A malicious or PUA listing always wins over a trusted one.
    pub fn trusted_match(&self, signer: &str) -> Option<&PatternItem> {
        if self.is_malicious(signer) || self.is_pua(signer) {
            return None;
        }
        Self::find_in_list(&self.trusted, signer)
    }

    pub fn malicious_issuer_match(&self, issuer: &str) -> Option<&PatternItem> {
        Self::find_in_list(&self.malicious_issuers, issuer)
    }

    pub fn pua_issuer_match(&self, issuer: &str) -> Option<&PatternItem> {
        Self::find_in_list(&self.pua_issuers, issuer)
    }

    pub fn pinned_thumbprint_match(&self, thumbprint: &str) -> Option<&PatternItem> {
        if self.pinned_thumbprints.is_empty() || thumbprint.is_empty() {
            return None;
        }
        let t = thumbprint.trim().to_ascii_lowercase();
        self.pinned_thumbprints.iter().find(|p| p.value == t)
    }

    pub fn malicious_tsa_match(&self, tsa: &str) -> Option<&PatternItem> {
        Self::find_in_list(&self.malicious_tsas, tsa)
    }

    /// `(publisher, issuer, pinned fingerprints)` sizes of the loaded corpus,
    /// for diagnostics.
    pub fn issuer_counts(&self) -> (usize, usize, usize) {
        (self.malicious_issuers.len(), self.pua_issuers.len(), self.pinned_thumbprints.len())
    }

    /// First pattern in `list` matching `signer` (case-insensitive; `_equals`
    /// exact, `_contains` substring). First, so the shipped order decides which
    /// rule is reported when several name the same publisher.
    fn find_in_list<'a>(list: &'a [PatternItem], signer: &str) -> Option<&'a PatternItem> {
        if list.is_empty() || signer.is_empty() {
            return None;
        }
        let lower = signer.to_lowercase();
        list.iter().find(|p| {
            if p.is_exact {
                lower == p.value
            } else {
                lower.contains(&p.value)
            }
        })
    }

    fn load_file(path: &Path) -> LoadedConditions {
        if !path.is_file() {
            return LoadedConditions::default();
        }
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return LoadedConditions::default(),
        };
        let file: SignerRuleFile = match serde_yaml::from_str(&content) {
            Ok(f) => f,
            Err(_) => return LoadedConditions::default(),
        };
        LoadedConditions::from_rules(&file.rules)
    }
}

impl LoadedConditions {
    /// Split the conditions of `rules` into the per-field lists, each pattern
    /// carrying its rule's metadata. Lenient like the shipped loader always was:
    /// empty values, unknown types and malformed thumbprints are skipped.
    fn from_rules(rules: &[SignerRule]) -> Self {
        let mut out = LoadedConditions::default();
        for rule in rules {
            let meta = Arc::new(SignerRuleMeta::from_rule(rule));
            for cond in &rule.conditions {
                if cond.value.is_empty() {
                    continue;
                }
                let value = cond.value.to_lowercase();
                let item = PatternItem {
                    value,
                    is_exact: cond.cond_type.ends_with("_equals"),
                    meta: Some(meta.clone()),
                };
                match cond.cond_type.as_str() {
                    "signature_signer_contains" | "signature_signer_equals" => {
                        out.names.push(item);
                    }
                    "signature_issuer_contains" | "signature_issuer_equals" => {
                        out.issuers.push(item);
                    }
                    "signature_timestamp_signer_contains"
                    | "signature_timestamp_signer_equals" => {
                        out.tsas.push(item);
                    }
                    "signature_thumbprint_any" | "signature_thumbprint_equals" => {
                        // Accept `aa:bb:cc`, `aa bb cc` and bare hex.
                        let hex: String = cond
                            .value
                            .chars()
                            .filter(|c| c.is_ascii_hexdigit())
                            .collect::<String>()
                            .to_ascii_lowercase();
                        if hex.len() == 40 {
                            out.thumbprints.push(PatternItem { value: hex, is_exact: true, ..item });
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

/// Self-contained BinaryFuse16 filter (web parity, zero deps).
///
/// Same on-disk format and query path as `hydradragonxorfilter` and as
/// `openedr_web::engine::BinaryFuse16Filter` (tag 16, version 2, FNV-1a
/// lowercased key): a `.xf` built offline with `xorfilter_writer` loads here
/// byte-for-byte. Kept inline so `openedr_static` builds with plain
/// `cargo build` — no AES/SSE2 RUSTFLAGS (the shared crate pulls `gxhash`,
/// which requires them).
#[derive(Clone)]
pub struct BinaryFuse16Filter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    count: usize,
    fingerprints: Vec<u16>,
}

impl std::fmt::Debug for BinaryFuse16Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryFuse16Filter")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

impl BinaryFuse16Filter {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes[0] != 16 || bytes[1] != 2 {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let seg_len = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let seg_len_mask = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let seg_count_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let count = usize::try_from(u64::from_le_bytes(bytes[24..32].try_into().ok()?)).ok()?;
        if 32 + count.checked_mul(2)? > bytes.len() {
            return None;
        }
        let mut fingerprints = Vec::with_capacity(count);
        for i in 0..count {
            let off = 32 + i * 2;
            fingerprints.push(u16::from_le_bytes([bytes[off], bytes[off + 1]]));
        }
        Some(Self {
            seed,
            seg_len,
            seg_len_mask,
            seg_count_len,
            count,
            fingerprints,
        })
    }

    /// Number of `u16` fingerprints in the filter (≈ keys × 1.23).
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn contains(&self, s: &str) -> bool {
        self.contains_key(Self::key(s))
    }

    pub fn contains_key(&self, k: u64) -> bool {
        let hash = Self::mix64(k.wrapping_add(self.seed));
        let f = hash as u16;
        let (h0, h1, h2) = Self::hash_of_hash(hash, self.seg_len, self.seg_len_mask, self.seg_count_len);
        let c = self.count;
        if h0 as usize >= c || h1 as usize >= c || h2 as usize >= c {
            return false;
        }
        let fp = self.fingerprints[h0 as usize] ^ self.fingerprints[h1 as usize] ^ self.fingerprints[h2 as usize];
        f ^ fp == 0
    }

    /// FNV-1a-64 over the ASCII-lowercased bytes. Deterministic and platform
    /// independent, and case-insensitive so signer/hex casing can never cause a
    /// miss.
    #[inline(always)]
    fn key(s: &str) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = OFFSET;
        for b in s.bytes() {
            h ^= b.to_ascii_lowercase() as u64;
            h = h.wrapping_mul(PRIME);
        }
        h
    }

    #[inline(always)]
    fn mix64(k: u64) -> u64 {
        const MIX_C1: u64 = 0xff51_afd7_ed55_8ccd;
        let r = (k as u128).wrapping_mul(MIX_C1 as u128);
        (r ^ (r >> 64)) as u64
    }

    #[inline(always)]
    fn hash_of_hash(hash: u64, seg_len: u32, seg_len_mask: u32, seg_count_len: u32) -> (u32, u32, u32) {
        let hi = ((hash as u128 * seg_count_len as u128) >> 64) as u64;
        let h0 = hi as u32;
        let mut h1 = h0 + seg_len;
        let mut h2 = h1 + seg_len;
        h1 ^= ((hash >> 18) as u32) & seg_len_mask;
        h2 ^= (hash as u32) & seg_len_mask;
        (h0, h1, h2)
    }
}

/// BinaryFuse32 filter (tag 32, `xorfilter_writer --bf32`): the same format and query
/// as [`BinaryFuse16Filter`] with 32-bit fingerprints. For blocklists, where a false
/// match flags a clean item: one in ~4.3 billion lookups instead of one in 65 536.
#[derive(Clone)]
pub struct BinaryFuse32Filter {
    seed: u64,
    seg_len: u32,
    seg_len_mask: u32,
    seg_count_len: u32,
    fingerprints: Vec<u32>,
}

impl std::fmt::Debug for BinaryFuse32Filter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryFuse32Filter")
            .field("count", &self.fingerprints.len())
            .finish_non_exhaustive()
    }
}

impl BinaryFuse32Filter {
    /// Loads a `.xf` file for a whitelist or a blocklist: BinaryFuse32 only. A
    /// BinaryFuse16 file (one false match in 65 536 lookups: a whitelist would skip
    /// the scan of a file not on it, a blocklist would flag a clean one) is refused
    /// with a message that says to rebuild it.
    pub fn load(bytes: &[u8]) -> Result<Self, String> {
        match bytes.first() {
            Some(16) => Err("BinaryFuse16 refused (one false match in 65 536 lookups); rebuild it as BinaryFuse32 with xorfilter_writer".into()),
            _ => Self::from_bytes(bytes).ok_or_else(|| "not a BinaryFuse32 .xf file".into()),
        }
    }

    /// `None` for anything but a well-formed tag-32 file (a BF16 file included).
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 32 || bytes[0] != 32 || bytes[1] != 2 {
            return None;
        }
        let seed = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let seg_len = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
        let seg_len_mask = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
        let seg_count_len = u32::from_le_bytes(bytes[20..24].try_into().ok()?);
        let count = usize::try_from(u64::from_le_bytes(bytes[24..32].try_into().ok()?)).ok()?;
        let body = bytes.get(32..32usize.checked_add(count.checked_mul(4)?)?)?;
        let fingerprints = body.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        Some(Self { seed, seg_len, seg_len_mask, seg_count_len, fingerprints })
    }

    /// Number of fingerprints (≈ keys × 1.13).
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    pub fn contains(&self, s: &str) -> bool {
        self.contains_key(BinaryFuse16Filter::key(s))
    }

    /// `contains` for a key already derived (the same 64-bit key as BinaryFuse16).
    pub fn contains_key(&self, k: u64) -> bool {
        let hash = BinaryFuse16Filter::mix64(k.wrapping_add(self.seed));
        let (h0, h1, h2) = BinaryFuse16Filter::hash_of_hash(hash, self.seg_len, self.seg_len_mask, self.seg_count_len);
        let fp = |i: u32| self.fingerprints.get(i as usize).copied();
        match (fp(h0), fp(h1), fp(h2)) {
            (Some(a), Some(b), Some(c)) => (hash as u32) ^ a ^ b ^ c == 0,
            _ => false,
        }
    }
}

#[cfg(windows)]
use windows::core::{PCWSTR, PWSTR};
#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use std::sync::OnceLock;
#[cfg(windows)]
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, HWND};
#[cfg(windows)]
use windows::Win32::Security::Cryptography::{
    CertGetCertificateContextProperty, CertGetNameStringW, CERT_CONTEXT,
    CERT_NAME_SIMPLE_DISPLAY_TYPE,
};

/// `CERT_SHA1_HASH_PROP_ID`. Not exported by the `windows` crate.
#[cfg(windows)]
const CERT_SHA1_HASH_PROP_ID: u32 = 3;

/// `FILETIME` (100 ns ticks since 1601-01-01) to Unix seconds.
#[cfg(windows)]
fn filetime_to_unix(ft: windows::Win32::Foundation::FILETIME) -> i64 {
    let ticks = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    (ticks as i64 - 116_444_736_000_000_000) / 10_000_000
}

/// Everything `signer_subject_from_state` could see in the verified chain, and a
/// little more. Read while the `WTD_STATEACTION_VERIFY` state is still open —
/// the state is closed right after, so this is the only window onto the chain.
#[cfg(windows)]
#[derive(Debug, Clone, Default)]
pub struct ChainInfo {
    /// Simple display name of the leaf, i.e. the publisher.
    pub subject: Option<String>,
    /// Simple display name of the CA that issued the leaf.
    pub issuer: Option<String>,
    /// Certificates in the chain, leaf first.
    pub chain_len: usize,
    /// SHA-1 of the leaf certificate, lowercase hex.
    pub thumbprint: Option<String>,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
}

/// SHA-1 of a certificate context, as the lowercase hex everyone publishes.
#[cfg(windows)]
unsafe fn cert_thumbprint(cert: *const CERT_CONTEXT) -> Option<String> {
    if cert.is_null() {
        return None;
    }
    let mut size: u32 = 0;
    let ok = unsafe {
        CertGetCertificateContextProperty(cert, CERT_SHA1_HASH_PROP_ID, None, &mut size as *mut u32)
    };
    if ok.is_err() || size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA1_HASH_PROP_ID,
            Some(buf.as_mut_ptr() as *mut std::ffi::c_void),
            &mut size as *mut u32,
        )
    };
    if ok.is_err() {
        return None;
    }
    Some(buf.iter().take(size as usize).map(|b| format!("{:02x}", b)).collect())
}
#[cfg(windows)]
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData,
};

#[cfg(windows)]
/// Cached WinTrust verdict. Catalog verification is the most expensive part
/// of a file scan (hash the file, walk CatRoot .cat members, WinVerifyTrust
/// per candidate), and the same executable is rescanned on every minifilter
/// event (create/write/change/close). Cache on (path, size, mtime) so a
/// rewritten or replaced binary re-verifies automatically.
#[derive(Clone, Debug)]
struct AuthenticodeCacheEntry {
    key: String,
    result: AuthenticodeInfo,
}

/// Bounded FIFO-ish cache: 4096 entries is far beyond the working set of
/// recently touched executables and keeps memory trivial.
#[cfg(windows)]
const AUTHENTICODE_CACHE_CAP: usize = 4096;

#[cfg(windows)]
fn authenticode_cache() -> &'static Mutex<Vec<AuthenticodeCacheEntry>> {
    static CACHE: OnceLock<Mutex<Vec<AuthenticodeCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Vec::new()))
}

/// Identity of the on-disk content for cache invalidation: size + last write
/// time. Cheap; a same-size rewrite still bumps mtime.
#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::windows::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    Some((md.file_size(), md.last_write_time()))
}

#[cfg(windows)]
fn authenticate_cached(
    path: &Path,
) -> Option<AuthenticodeInfo> {
    let (size, mtime) = file_identity(path)?;
    let key = format!("{}\u{0}{size}\u{0}{mtime}", path.to_string_lossy().to_lowercase());
    if let Ok(cache) = authenticode_cache().lock() {
        if let Some(hit) = cache.iter().find(|e| e.key == key) {
            return Some(hit.result.clone());
        }
    }
    None
}

#[cfg(windows)]
fn authenticate_store(
    path: &Path,
    result: AuthenticodeInfo,
) {
    let Some((size, mtime)) = file_identity(path) else {
        return;
    };
    let key = format!("{}\u{0}{size}\u{0}{mtime}", path.to_string_lossy().to_lowercase());
    let Ok(mut cache) = authenticode_cache().lock() else {
        return;
    };
    if cache.iter().any(|e| e.key == key) {
        return;
    }
    if cache.len() >= AUTHENTICODE_CACHE_CAP {
        // Drop the oldest half in one pass: cheaper and simpler than LRU and
        // keeps the cache bounded without per-insert bookkeeping.
        let half = AUTHENTICODE_CACHE_CAP / 2;
        cache.drain(0..half);
    }
    cache.push(AuthenticodeCacheEntry { key, result });
}

#[cfg(windows)]
pub fn verify_authenticode(path: &Path) -> AuthenticodeInfo {
    if let Some(hit) = authenticate_cached(path) {
        return hit;
    }
    let result = verify_authenticode_uncached(path);
    authenticate_store(path, result.clone());
    result
}

/// Publisher display name of the certificate that actually signed the file.
#[cfg(windows)]
unsafe fn signer_subject_from_state(state: HANDLE) -> Option<String> {
    unsafe { cert_chain_from_state(state) }.and_then(|c| c.subject)
}

/// Read the verified chain while the WinTrust state is still open.
///
/// The publisher name used to be `CertEnumCertificatesInStore(store, None)` on a
/// store opened with `CryptQueryObject(..., PKCS7_SIGNED_EMBED, ...)`, which
/// returns whichever certificate happens to sit first in the store - the CA, not
/// the publisher. Every Microsoft binary therefore reported "Microsoft Windows
/// Production PCA 2011" instead of "Microsoft Windows", so no entry in
/// `signer_rules/trusted_signers.yaml` could ever match and the signer field was
/// useless for trust decisions.
///
/// `pasCertChain[0].pCert` is the signer certificate itself. This also works for
/// catalog-signed files (cmd.exe, conhost.exe, ...), where the embedded PKCS#7
/// route is unavailable - the catalog SIP puts the member's own certificate at
/// the head of the chain.
///
/// Safety: `state` must be the live `hWVTStateData` of a `WTD_STATEACTION_VERIFY`
/// WinVerifyTrust call that has not yet been closed with `WTD_STATEACTION_CLOSE`.
#[cfg(windows)]
unsafe fn cert_chain_from_state(state: HANDLE) -> Option<ChainInfo> {
    if state.is_invalid() {
        return None;
    }
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return None;
        }
        let sgnr = &*sgnr;
        if sgnr.pasCertChain.is_null() || sgnr.csCertChain == 0 {
            return None;
        }
        let leaf = &*sgnr.pasCertChain;
        if leaf.pCert.is_null() {
            return None;
        }

        let mut info = ChainInfo { chain_len: sgnr.csCertChain as usize, ..Default::default() };

        let mut name_buf = [0u16; 256];
        let len = CertGetNameStringW(
            leaf.pCert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            None,
            Some(&mut name_buf),
        );
        if len > 1 {
            info.subject = Some(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]));
        }

        // The issuer is the next certificate up when the chain has one. A
        // self-signed or single-certificate chain has no such neighbour, and
        // naming the leaf's own issuer string is the only thing left to report.
        if sgnr.csCertChain > 1 {
            let next = &*sgnr.pasCertChain.add(1);
            if !next.pCert.is_null() {
                let mut issuer_buf = [0u16; 256];
                let len = CertGetNameStringW(
                    next.pCert,
                    CERT_NAME_SIMPLE_DISPLAY_TYPE,
                    0,
                    None,
                    Some(&mut issuer_buf),
                );
                if len > 1 {
                    info.issuer = Some(String::from_utf16_lossy(&issuer_buf[..(len as usize - 1)]));
                }
            }
        }

        info.thumbprint = cert_thumbprint(leaf.pCert);

        // `CRYPT_PROVIDER_CERT` has no certificate-info pointer; the validity
        // window lives on the certificate context itself.
        if !leaf.pCert.is_null() {
            let cert_info = (*leaf.pCert).pCertInfo;
            if !cert_info.is_null() {
                let cert_info = &*cert_info;
                info.not_before = Some(filetime_to_unix(cert_info.NotBefore));
                info.not_after = Some(filetime_to_unix(cert_info.NotAfter));
            }
        }

        Some(info)
    }
}

#[cfg(windows)]
fn verify_authenticode_uncached(path: &Path) -> AuthenticodeInfo {
    use std::os::windows::ffi::OsStrExt;

    if !path.is_file() {
        return AuthenticodeInfo {
            status: "File not found".to_string(),
            ..Default::default()
        };
    }

    let path_wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(path_wide.as_ptr()),
        hFile: windows::Win32::Foundation::HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut win_trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: windows::Win32::Security::WinTrust::WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
        pwszURLReference: PWSTR::null(),
        dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0x00000010 | 0x00001000),
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
        Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
    };

    let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let result = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action_guid,
            &mut win_trust_data as *mut _ as _,
        )
    };

    let mut is_trusted = result == ERROR_SUCCESS.0 as i32;

    // Read the whole verified chain while the state is still open: publisher,
    // issuing CA, depth, leaf thumbprint and validity all come out of the same
    // `pasCertChain` walk, so this costs no extra I/O. The state is then closed;
    // it used to be left open on this path, leaking a handle per verified file.
    let chain = unsafe { cert_chain_from_state(win_trust_data.hWVTStateData) };
    let mut signer_name = chain.as_ref().and_then(|c| c.subject.clone());
    if !win_trust_data.hWVTStateData.is_invalid() {
        win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        let _ = unsafe {
            WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            )
        };
    }

    // Catalog-signed files (conhost.exe, notepad.exe, cmd.exe, ...) often carry
    // no embedded PKCS#7 signature: WTD_CHOICE_FILE reports them unsigned even
    // though they are signed via the Windows Catalog database. Fall back to
    // catalog membership verification for every file type (including
    // extensionless ones) so signed files are not misclassified.
    // (Ported from owlyshield signature_verification.rs; extension gate removed.)
    let mut is_catalog_signed = false;
    if !is_trusted {
        if let Some(catalog_signer) = unsafe { verify_catalog_signature(&path_wide) } {
            is_catalog_signed = true;
            is_trusted = true;
            if signer_name.is_none() {
                signer_name = Some(catalog_signer);
            }
        }
    }

    let is_signed = is_trusted || signer_name.is_some();
    let status = if is_trusted {
        "trusted".to_string()
    } else if is_signed {
        "signed_untrusted".to_string()
    } else {
        "unsigned".to_string()
    };

    // Countersignature, read from the file's own embedded PKCS#7. Skipped for
    // catalog-signed files: they carry no PKCS#7, so the catalog is not
    // "missing" a timestamp. `is_undated()` respects that too.
    let mut timestamped = false;
    let mut timestamp_kind = None;
    let mut timestamp_signer = None;
    let mut timestamp_time = None;
    if let Ok(bytes) = std::fs::read(path) {
        if let Some(pkcs7) = crate::auth_timestamp::embedded_pkcs7(&bytes) {
            if let Some(ts) = crate::auth_timestamp::parse_authenticode_timestamp(pkcs7) {
                timestamped = true;
                timestamp_kind = Some(
                    match ts.kind {
                        crate::auth_timestamp::TimestampKind::Rfc3161 => "rfc3161",
                        crate::auth_timestamp::TimestampKind::Pkcs9 => "pkcs9",
                    }
                    .to_string(),
                );
                timestamp_signer = ts.signer;
                timestamp_time = ts.time;
            }
        }
    }

    AuthenticodeInfo {
        is_signed,
        is_trusted,
        signer_name,
        issuer: chain.as_ref().and_then(|c| c.issuer.clone()),
        status,
        is_catalog_signed,
        chain_len: chain.as_ref().map_or(0, |c| c.chain_len),
        thumbprint: chain.as_ref().and_then(|c| c.thumbprint.clone()),
        not_before: chain.as_ref().and_then(|c| c.not_before),
        not_after: chain.as_ref().and_then(|c| c.not_after),
        timestamped,
        timestamp_kind,
        timestamp_signer,
        timestamp_time,
    }
}

#[repr(C)]
struct CatalogInfo {
    cb_struct: u32,
    catalog_file: [u16; 260],
}

#[link(name = "wintrust")]
unsafe extern "system" {
    fn CryptCATAdminAcquireContext(
        ph_cat_admin: *mut *mut std::ffi::c_void,
        pg_subsystem: *const std::ffi::c_void,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminCalcHashFromFileHandle(
        h_file: windows::Win32::Foundation::HANDLE,
        pcb_hash: *mut u32,
        pb_hash: *mut u8,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminEnumCatalogFromHash(
        h_cat_admin: *mut std::ffi::c_void,
        pb_hash: *const u8,
        cb_hash: u32,
        dw_flags: u32,
        ph_prev_cat_info: *mut *mut std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn CryptCATCatalogInfoFromContext(
        h_cat_info: *mut std::ffi::c_void,
        ps_cat_info: *mut CatalogInfo,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseCatalogContext(
        h_cat_admin: *mut std::ffi::c_void,
        h_cat_info: *mut std::ffi::c_void,
        dw_flags: u32,
    ) -> i32;
    fn CryptCATAdminReleaseContext(h_cat_admin: *mut std::ffi::c_void, dw_flags: u32) -> i32;
}

/// Verifies a file against the Windows Catalog database (CatRoot .cat files).
/// Returns the publisher name (e.g. "Microsoft Windows")
/// when the file hash matches a member of a valid, trusted catalog.
unsafe fn verify_catalog_signature(path_wide: &[u16]) -> Option<String> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::WinTrust::WTD_CHOICE_CATALOG;
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_MODE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows::core::PCWSTR;

    const GENERIC_READ: u32 = 0x8000_0000;
    unsafe {
        let file_handle = match CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            GENERIC_READ,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0),
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            Some(HANDLE::default()),
        ) {
            Ok(h) => h,
            Err(_) => return None,
        };

        let mut cat_admin: *mut std::ffi::c_void = std::ptr::null_mut();
        if CryptCATAdminAcquireContext(&mut cat_admin, std::ptr::null(), 0) == 0 {
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut hash_size: u32 = 0;
        if CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, std::ptr::null_mut(), 0)
            == 0
        {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }
        let mut hash: Vec<u8> = vec![0u8; hash_size as usize];
        if CryptCATAdminCalcHashFromFileHandle(file_handle, &mut hash_size, hash.as_mut_ptr(), 0)
            == 0
        {
            let _ = CryptCATAdminReleaseContext(cat_admin, 0);
            let _ = windows::Win32::Foundation::CloseHandle(file_handle);
            return None;
        }

        let mut prev: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut trusted_signer: Option<String> = None;

        loop {
            let cat_info =
                CryptCATAdminEnumCatalogFromHash(cat_admin, hash.as_ptr(), hash_size, 0, &mut prev);
            if cat_info.is_null() {
                break;
            }
            prev = cat_info;

            let mut cat_info_struct = CatalogInfo {
                cb_struct: std::mem::size_of::<CatalogInfo>() as u32,
                catalog_file: [0u16; 260],
            };
            if CryptCATCatalogInfoFromContext(cat_info, &mut cat_info_struct, 0) == 0 {
                let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
                continue;
            }

            let mut catalog_file_info = WINTRUST_CATALOG_INFO {
                cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
                dwCatalogVersion: 0,
                pcwszCatalogFilePath: PCWSTR(cat_info_struct.catalog_file.as_ptr()),
                pcwszMemberTag: PCWSTR::null(),
                pcwszMemberFilePath: PCWSTR(path_wide.as_ptr()),
                hMemberFile: file_handle,
                pbCalculatedFileHash: hash.as_mut_ptr(),
                cbCalculatedFileHash: hash_size,
                pcCatalogContext: std::ptr::null_mut(),
                hCatAdmin: cat_admin as isize,
            };

            let mut win_trust_data = WINTRUST_DATA {
                cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                pPolicyCallbackData: std::ptr::null_mut(),
                pSIPClientData: std::ptr::null_mut(),
                dwUIChoice: WTD_UI_NONE,
                fdwRevocationChecks: windows::Win32::Security::WinTrust::WTD_REVOKE_NONE,
                dwUnionChoice: WTD_CHOICE_CATALOG,
                dwStateAction: WTD_STATEACTION_VERIFY,
                hWVTStateData: HANDLE::default(),
                pwszURLReference: PWSTR::null(),
                dwProvFlags: windows::Win32::Security::WinTrust::WINTRUST_DATA_PROVIDER_FLAGS(0),
                dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                pSignatureSettings: std::ptr::null_mut(),
                Anonymous: windows::Win32::Security::WinTrust::WINTRUST_DATA_0 {
                    pCatalog: &mut catalog_file_info,
                },
            };

            let mut action_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            let verify_result = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            );

            // Read the signer while the state is still open.
            let catalog_signer = signer_subject_from_state(win_trust_data.hWVTStateData);

            win_trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND::default(),
                &mut action_guid,
                &mut win_trust_data as *mut _ as _,
            );

            if verify_result == ERROR_SUCCESS.0 as i32 {
                trusted_signer = catalog_signer.or_else(|| Some("Microsoft Windows".to_string()));
                let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
                break;
            }

            let _ = CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0);
        }

        let _ = CryptCATAdminReleaseContext(cat_admin, 0);
        let _ = windows::Win32::Foundation::CloseHandle(file_handle);
        trusted_signer
    }
}

struct PeAuthenticodeHashes {
    sha256: [u8; 32],
    sha1: [u8; 20],
    has_trailing_bytes: bool,
    pieces_ranges: [(usize, usize); 3],
}

fn pe_authenticode_hashes(data: &[u8]) -> Option<PeAuthenticodeHashes> {
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    if data.len() < 0x40 || &data[..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(data.get(0x3C..0x40)?.try_into().ok()?) as usize;
    if data.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = e_lfanew + 24;
    let magic = u16::from_le_bytes(data.get(opt..opt + 2)?.try_into().ok()?);
    let dirs = match magic {
        0x10B => opt + 96,
        0x20B => opt + 112,
        _ => return None,
    };
    let num_dirs = u32::from_le_bytes(data.get(dirs - 4..dirs)?.try_into().ok()?);
    let checksum = opt + 64;
    if checksum + 4 > data.len() {
        return None;
    }

    let (cert_entry, cert_off, cert_size) = if num_dirs >= 5 {
        let entry = dirs + 4 * 8;
        let off = u32::from_le_bytes(data.get(entry..entry + 4)?.try_into().ok()?) as usize;
        let sz = u32::from_le_bytes(data.get(entry + 4..entry + 8)?.try_into().ok()?) as usize;
        (entry, off, sz)
    } else {
        (checksum + 4, 0, 0)
    };

    let (hash_end, has_trailing_bytes) = if cert_off > 0 && cert_size > 0 {
        let cert_end = cert_off.checked_add(cert_size)?;
        if cert_off < cert_entry + 8 || cert_end > data.len() {
            return None;
        }
        (cert_off, cert_end != data.len())
    } else {
        (data.len(), false)
    };

    let r0 = (0, checksum);
    let r1 = if num_dirs >= 5 {
        (checksum + 4, cert_entry)
    } else {
        (checksum + 4, checksum + 4)
    };
    let r2 = if num_dirs >= 5 {
        (cert_entry + 8, hash_end)
    } else {
        (checksum + 4, hash_end)
    };
    if r0.1 > r1.0 || r1.1 > r2.0 || r2.1 > data.len() {
        return None;
    }

    let mut h256 = Sha256::new();
    let mut h1 = Sha1::new();
    for &(start, end) in &[r0, r1, r2] {
        let slice = &data[start..end];
        h256.update(slice);
        h1.update(slice);
    }

    Some(PeAuthenticodeHashes {
        sha256: h256.finalize().into(),
        sha1: h1.finalize().into(),
        has_trailing_bytes,
        pieces_ranges: [r0, r1, r2],
    })
}

/// Fast in-memory check whether `data` matches any catalog entry in the local
/// Windows `CatRoot` database. Zero disk writes.
#[cfg(windows)]
pub fn is_in_windows_catalog_bytes(data: &[u8]) -> bool {
    use std::cell::Cell;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    struct ThreadCatAdmin(Cell<*mut std::ffi::c_void>);
    impl Drop for ThreadCatAdmin {
        fn drop(&mut self) {
            let p = self.0.get();
            if !p.is_null() {
                unsafe {
                    let _ = CryptCATAdminReleaseContext(p, 0);
                }
            }
        }
    }
    thread_local! {
        static CAT_ADMIN: ThreadCatAdmin = const { ThreadCatAdmin(Cell::new(std::ptr::null_mut())) };
    }

    let (sha256, sha1): ([u8; 32], [u8; 20]) = if let Some(pe) = pe_authenticode_hashes(data) {
        (pe.sha256, pe.sha1)
    } else {
        (Sha256::digest(data).into(), Sha1::digest(data).into())
    };

    CAT_ADMIN.with(|cell| {
        let mut admin = cell.0.get();
        if admin.is_null() {
            let ok = unsafe { CryptCATAdminAcquireContext(&mut admin, std::ptr::null(), 0) };
            if ok == 0 || admin.is_null() {
                return false;
            }
            cell.0.set(admin);
        }

        for hash in [&sha256[..], &sha1[..]] {
            let mut prev: *mut std::ffi::c_void = std::ptr::null_mut();
            let cat_info = unsafe {
                CryptCATAdminEnumCatalogFromHash(
                    admin,
                    hash.as_ptr(),
                    hash.len() as u32,
                    0,
                    &mut prev,
                )
            };
            if !cat_info.is_null() {
                unsafe {
                    let _ = CryptCATAdminReleaseCatalogContext(admin, cat_info, 0);
                }
                return true;
            }
        }
        false
    })
}

/// In-memory verification of an embedded PE Authenticode PKCS#7 signature.
/// Returns `None` if `data` has no embedded PE PKCS#7 signature.
#[cfg(windows)]
pub fn verify_authenticode_bytes(data: &[u8]) -> Option<AuthenticodeInfo> {
    use windows::Win32::Security::Cryptography::{
        CertCloseStore, CertFreeCertificateChain, CertFreeCertificateContext,
        CertGetCertificateChain, CertGetNameStringW, CertGetSubjectCertificateFromStore,
        CertVerifyCertificateChainPolicy, CryptMsgClose, CryptMsgControl, CryptMsgGetParam,
        CryptQueryObject, CERT_CHAIN_CONTEXT, CERT_CHAIN_PARA, CERT_CHAIN_POLICY_AUTHENTICODE,
        CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_CONTEXT, CERT_INFO,
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
        CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_BLOB, CMSG_CONTENT_PARAM,
        CMSG_CTRL_VERIFY_SIGNATURE, CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CRYPT_INTEGER_BLOB,
        HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
    };

    let pkcs7 = crate::auth_timestamp::embedded_pkcs7(data)?;
    let pe_hashes = pe_authenticode_hashes(data)?;

    let blob = CRYPT_INTEGER_BLOB {
        cbData: pkcs7.len() as u32,
        pbData: pkcs7.as_ptr() as *mut u8,
    };

    let mut hstore = HCERTSTORE::default();
    let mut hmsg = Default::default();
    let queried = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_BLOB,
            &blob as *const _ as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut hstore),
            Some(&mut hmsg),
            None,
        )
    };
    if queried.is_err() || hmsg.is_null() {
        if !hstore.0.is_null() {
            unsafe {
                let _ = CertCloseStore(Some(hstore), 0);
            }
        }
        return Some(AuthenticodeInfo {
            status: "unsigned".to_string(),
            ..Default::default()
        });
    }

    let mut signer_info_size: u32 = 0;
    let mut signer_info_buf = Vec::new();
    let got_signer = unsafe {
        CryptMsgGetParam(hmsg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_info_size).is_ok()
            && signer_info_size as usize >= std::mem::size_of::<CMSG_SIGNER_INFO>()
            && {
                signer_info_buf.resize(signer_info_size as usize, 0);
                CryptMsgGetParam(
                    hmsg,
                    CMSG_SIGNER_INFO_PARAM,
                    0,
                    Some(signer_info_buf.as_mut_ptr() as *mut std::ffi::c_void),
                    &mut signer_info_size,
                )
                .is_ok()
            }
    };

    let mut leaf_cert: *const CERT_CONTEXT = std::ptr::null();
    if got_signer && !hstore.0.is_null() {
        let signer_info = unsafe { &*(signer_info_buf.as_ptr() as *const CMSG_SIGNER_INFO) };
        let mut lookup_info = CERT_INFO {
            Issuer: signer_info.Issuer,
            SerialNumber: signer_info.SerialNumber,
            ..Default::default()
        };
        leaf_cert = unsafe {
            CertGetSubjectCertificateFromStore(
                hstore,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                &mut lookup_info,
            )
        };
    }

    let mut sig_valid = false;
    let mut chain_trusted = false;
    let mut signer_name = None;
    let mut issuer = None;
    let mut thumbprint = None;
    let mut not_before = None;
    let mut not_after = None;
    let mut chain_len = 0usize;

    if !leaf_cert.is_null() {
        unsafe {
            let leaf_ref = &*leaf_cert;
            if !leaf_ref.pCertInfo.is_null() {
                sig_valid = CryptMsgControl(
                    hmsg,
                    0,
                    CMSG_CTRL_VERIFY_SIGNATURE,
                    Some(leaf_ref.pCertInfo as *const std::ffi::c_void),
                )
                .is_ok();

                let cert_info = &*leaf_ref.pCertInfo;
                not_before = Some(filetime_to_unix(cert_info.NotBefore));
                not_after = Some(filetime_to_unix(cert_info.NotAfter));
            }
            thumbprint = cert_thumbprint(leaf_cert);

            let mut name_buf = [0u16; 256];
            let len = CertGetNameStringW(
                leaf_cert,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                None,
                Some(&mut name_buf),
            );
            if len > 1 {
                signer_name = Some(String::from_utf16_lossy(&name_buf[..(len as usize - 1)]));
            }

            let chain_para = CERT_CHAIN_PARA {
                cbSize: std::mem::size_of::<CERT_CHAIN_PARA>() as u32,
                ..Default::default()
            };
            let mut chain_ctx: *mut CERT_CHAIN_CONTEXT = std::ptr::null_mut();
            if CertGetCertificateChain(
                None,
                leaf_cert,
                None,
                Some(hstore),
                &chain_para,
                0,
                None,
                &mut chain_ctx,
            )
            .is_ok()
                && !chain_ctx.is_null()
            {
                let ctx_ref = &*chain_ctx;
                if ctx_ref.cChain > 0 && !ctx_ref.rgpChain.is_null() {
                    let simple_chain = &**ctx_ref.rgpChain;
                    chain_len = simple_chain.cElement as usize;
                    if simple_chain.cElement > 1 && !simple_chain.rgpElement.is_null() {
                        let next_elem = &**simple_chain.rgpElement.add(1);
                        if !next_elem.pCertContext.is_null() {
                            let mut issuer_buf = [0u16; 256];
                            let ilen = CertGetNameStringW(
                                next_elem.pCertContext,
                                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                0,
                                None,
                                Some(&mut issuer_buf),
                            );
                            if ilen > 1 {
                                issuer = Some(String::from_utf16_lossy(&issuer_buf[..(ilen as usize - 1)]));
                            }
                        }
                    }
                }

                let mut policy_para = CERT_CHAIN_POLICY_PARA {
                    cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
                    ..Default::default()
                };
                let mut policy_status = CERT_CHAIN_POLICY_STATUS {
                    cbSize: std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
                    ..Default::default()
                };
                if CertVerifyCertificateChainPolicy(
                    CERT_CHAIN_POLICY_AUTHENTICODE,
                    chain_ctx,
                    &mut policy_para,
                    &mut policy_status,
                )
                .as_bool()
                {
                    chain_trusted = policy_status.dwError == 0;
                }
                CertFreeCertificateChain(chain_ctx);
            }
            let _ = CertFreeCertificateContext(Some(leaf_cert));
        }
    }

    // Verify signed SpcIndirectDataContent digest matches PE Authenticode digest.
    let mut digest_matches = false;
    let mut content_size: u32 = 0;
    let mut content_buf = Vec::new();
    let got_content = unsafe {
        CryptMsgGetParam(hmsg, CMSG_CONTENT_PARAM, 0, None, &mut content_size).is_ok()
            && content_size > 0
            && {
                content_buf.resize(content_size as usize, 0);
                CryptMsgGetParam(
                    hmsg,
                    CMSG_CONTENT_PARAM,
                    0,
                    Some(content_buf.as_mut_ptr() as *mut std::ffi::c_void),
                    &mut content_size,
                )
                .is_ok()
            }
    };
    if got_content && !pe_hashes.has_trailing_bytes {
        use md5::Md5;
        use sha2::{Digest, Sha384, Sha512};
        let contains_digest = |d: &[u8]| !d.is_empty() && content_buf.windows(d.len()).any(|w| w == d);
        if contains_digest(&pe_hashes.sha256) || contains_digest(&pe_hashes.sha1) {
            digest_matches = true;
        } else {
            let hash_with = |mut h: Box<dyn FnMut(&[u8])>| {
                for &(s, e) in &pe_hashes.pieces_ranges {
                    h(&data[s..e]);
                }
            };
            let mut h384 = Sha384::new();
            let mut h512 = Sha512::new();
            let mut hmd5 = Md5::new();
            hash_with(Box::new(|sl| {
                h384.update(sl);
                h512.update(sl);
                hmd5.update(sl);
            }));
            digest_matches = contains_digest(&h384.finalize())
                || contains_digest(&h512.finalize())
                || contains_digest(&hmd5.finalize());
        }
    }

    unsafe {
        let _ = CryptMsgClose(Some(hmsg));
        if !hstore.0.is_null() {
            let _ = CertCloseStore(Some(hstore), 0);
        }
    }

    let is_trusted = sig_valid && digest_matches && chain_trusted;
    let is_signed = is_trusted || signer_name.is_some();
    let status = if is_trusted {
        "trusted".to_string()
    } else if is_signed {
        "signed_untrusted".to_string()
    } else {
        "unsigned".to_string()
    };

    let mut timestamped = false;
    let mut timestamp_kind = None;
    let mut timestamp_signer = None;
    let mut timestamp_time = None;
    if let Some(ts) = crate::auth_timestamp::parse_authenticode_timestamp(pkcs7) {
        timestamped = true;
        timestamp_kind = Some(
            match ts.kind {
                crate::auth_timestamp::TimestampKind::Rfc3161 => "rfc3161",
                crate::auth_timestamp::TimestampKind::Pkcs9 => "pkcs9",
            }
            .to_string(),
        );
        timestamp_signer = ts.signer;
        timestamp_time = ts.time;
    }

    Some(AuthenticodeInfo {
        is_signed,
        is_trusted,
        signer_name,
        issuer,
        status,
        is_catalog_signed: false,
        chain_len,
        thumbprint,
        not_before,
        not_after,
        timestamped,
        timestamp_kind,
        timestamp_signer,
        timestamp_time,
    })
}

#[cfg(not(windows))]
pub fn is_in_windows_catalog_bytes(_data: &[u8]) -> bool {
    false
}

#[cfg(not(windows))]
pub fn verify_authenticode_bytes(_data: &[u8]) -> Option<AuthenticodeInfo> {
    None
}

#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> AuthenticodeInfo {
    AuthenticodeInfo::unsupported("unsupported_platform")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-built BinaryFuse16 image that contains exactly one key.
    ///
    /// With `seg_count_len = 1` and `seg_len_mask = 0` the three slots always
    /// resolve to indices 0, 1 and 2, so storing the key's fingerprint in slot 0
    /// and zeroing the other two makes `contains()` true for that key alone.
    /// Building it here keeps the test independent of any shipped `.xf`.
    fn one_key_filter(item: &str) -> Vec<u8> {
        const SEED: u64 = 0x0123_4567_89ab_cdef;
        let fingerprint = BinaryFuse16Filter::mix64(
            BinaryFuse16Filter::key(item).wrapping_add(SEED),
        ) as u16;

        let mut bytes = Vec::with_capacity(32 + 6);
        bytes.push(16); // tag
        bytes.push(2); // version
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&SEED.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_len
        bytes.extend_from_slice(&0u32.to_le_bytes()); // seg_len_mask
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_count_len
        bytes.extend_from_slice(&3u64.to_le_bytes()); // count
        bytes.extend_from_slice(&fingerprint.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes
    }

    /// The BinaryFuse32 form of `one_key_filter`: three 32-bit slots, one key.
    fn one_key_filter32(item: &str) -> Vec<u8> {
        const SEED: u64 = 0x0123_4567_89ab_cdef;
        let fingerprint = BinaryFuse16Filter::mix64(BinaryFuse16Filter::key(item).wrapping_add(SEED)) as u32;
        let mut bytes = vec![32, 2, 0, 0];
        bytes.extend_from_slice(&SEED.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_len
        bytes.extend_from_slice(&0u32.to_le_bytes()); // seg_len_mask
        bytes.extend_from_slice(&1u32.to_le_bytes()); // seg_count_len
        bytes.extend_from_slice(&3u64.to_le_bytes()); // count
        bytes.extend_from_slice(&fingerprint.to_le_bytes());
        bytes.extend_from_slice(&[0; 8]);
        bytes
    }

    #[test]
    fn filter_rejects_garbage_headers() {
        assert!(BinaryFuse16Filter::from_bytes(b"").is_none());
        assert!(BinaryFuse16Filter::from_bytes(b"nope").is_none());
        assert!(BinaryFuse16Filter::from_bytes(&[16u8, 2, 0, 0]).is_none());
        // Right tag/version but a fingerprint count that runs past the buffer.
        let mut truncated = vec![0u8; 32];
        truncated[0] = 16;
        truncated[1] = 2;
        truncated[24..32].copy_from_slice(&16u64.to_le_bytes());
        assert!(BinaryFuse16Filter::from_bytes(&truncated).is_none());
    }

    #[test]
    fn filter_round_trips_one_key_and_is_case_insensitive() {
        let hash = "000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2";
        let f = BinaryFuse16Filter::from_bytes(&one_key_filter(hash)).expect("must parse");

        assert_eq!(f.len(), 3);
        assert!(!f.is_empty());
        assert!(f.contains(hash));
        // The key fold lowercases every byte, so an uppercase digest must still
        // hit — same guarantee the web engine relies on.
        assert!(f.contains(&hash.to_ascii_uppercase()));
        assert!(!f.contains("aa".repeat(32).as_str()));
    }

    #[test]
    fn missing_filter_or_empty_sha256_never_whitelists() {
        let mut db = SignerDb::default();
        assert!(!db.benign_loaded());
        assert!(!db.is_benign("aabb"));
        assert!(!db.set_benign_whitelist(b"not a filter"));
        assert!(!db.is_benign(""));

        let hash = "000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2";
        // BinaryFuse16 is refused: one false match in 65 536 would skip scans.
        assert!(!db.set_benign_whitelist(&one_key_filter(hash)));
        assert!(BinaryFuse32Filter::load(&one_key_filter(hash)).unwrap_err().contains("BinaryFuse16"));
        assert!(!db.benign_loaded());
        assert!(db.set_benign_whitelist(&one_key_filter32(hash)));
        assert!(db.benign_loaded());
        assert!(db.is_benign(hash));
        assert!(db.is_benign(&hash.to_ascii_uppercase()));
        assert!(!db.is_benign("aa".repeat(32).as_str()));
        assert!(!db.is_benign(""));
    }

    #[test]
    fn native_and_web_engines_fold_the_key_identically() {
        // Web parity contract: `openedr_web::engine::BinaryFuse16Filter::key` and
        // this copy must produce the same u64, otherwise a `.xf` built once for
        // the web demo would answer differently here. Both are FNV-1a-64 over the
        // ASCII-lowercased bytes; this pins the value so a change to one side
        // cannot silently desync the other.
        assert_eq!(
            BinaryFuse16Filter::key("000027cd05cdf4f81da50a0be2b719d7ffc80f886e85387d0e467a2056aa9cf2"),
            0xcb7f_4c3d_3da9_f5a1,
        );
    }

    /// Write a throwaway `signer_rules` directory and load it.
    fn db_from_yaml(tag: &str, malicious: &str) -> (SignerDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "openedr-signer-rules-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("malicious_vendors.yaml"), malicious).expect("write rules");
        let db = SignerDb::load_from_dir(&dir);
        (db, dir)
    }

    #[test]
    fn issuer_rules_are_kept_apart_from_publisher_rules() {
        // A compromised CA mints certificates for arbitrary publisher names, so
        // the two lists must not bleed into each other.
        let (db, dir) = db_from_yaml("issuer_rules_are_kept_apart_from_publisher_rules", 
            r#"
name: t
rules:
  - id: issuer-abuse
    title: "Abusive CA"
    conditions:
      - type: signature_issuer_contains
        value: "ReviverSoft Root"
      - type: signature_signer_contains
        value: "Some Publisher"
"#,
        );

        assert!(db.is_malicious_issuer("ReviverSoft Root CA"));
        assert!(db.is_malicious_issuer("reviversoft root ca")); // case-insensitive
        assert!(!db.is_malicious("ReviverSoft Root CA")); // publisher list unaffected
        assert!(db.is_malicious("Some Publisher Ltd"));
        assert!(!db.is_malicious_issuer("DigiCert Assured ID Root CA"));
        assert_eq!(db.issuer_counts().0, 1);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn thumbprints_accept_colons_spaces_and_case() {
        let (db, dir) = db_from_yaml("thumbprints_accept_colons_spaces_and_case", 
            r#"
name: t
rules:
  - id: pinned
    title: "Revoked leaf"
    conditions:
      - type: signature_thumbprint_any
        value: "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
"#,
        );
        let want = "aabbccddeeff00112233445566778899aabbccdd";
        assert!(db.is_pinned_thumbprint(want));
        assert!(db.is_pinned_thumbprint(&want.to_ascii_uppercase()));
        assert!(db.is_pinned_thumbprint(&format!("{} ", want)));
        assert!(!db.is_pinned_thumbprint(&"ff".repeat(20)));
        assert!(!db.is_pinned_thumbprint(""));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_thumbprint_that_is_not_sha1_is_dropped() {
        // 32 hex chars is a truncated digest, not a certificate thumbprint;
        // silently accepting it would pin nothing.
        let (db, dir) = db_from_yaml("a_thumbprint_that_is_not_sha1_is_dropped", 
            r#"
name: t
rules:
  - id: bad
    title: "bad"
    conditions:
      - type: signature_thumbprint_any
        value: "aabbccdd"
"#,
        );
        assert!(!db.is_pinned_thumbprint("aabbccdd"));
        assert_eq!(db.issuer_counts().2, 0);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signer_equals_does_not_match_a_longer_subject() {
        let (db, dir) = db_from_yaml("signer_equals_does_not_match_a_longer_subject", 
            r#"
name: t
rules:
  - id: exact
    title: "exact"
    conditions:
      - type: signature_signer_equals
        value: "Contoso Ltd"
"#,
        );
        assert!(db.is_malicious("Contoso Ltd"));
        assert!(!db.is_malicious("Contoso Ltd Evil Corp"));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn cert_validity_window_is_reported() {
        let info = AuthenticodeInfo {
            is_signed: true,
            not_before: Some(1_600_000_000),
            not_after: Some(1_700_000_000),
            ..Default::default()
        };
        assert!(!info.is_expired(1_650_000_000));
        assert!(info.is_expired(1_700_000_001));
        assert!(!info.is_not_yet_valid(1_650_000_000));
        assert!(info.is_not_yet_valid(1_500_000_000));

        // Expired but timestamped while valid: still valid (no detection).
        let ts = |t: Option<i64>| AuthenticodeInfo {
            is_signed: true,
            not_before: Some(1_600_000_000),
            not_after: Some(1_700_000_000),
            timestamped: true,
            timestamp_time: t,
            ..Default::default()
        };
        let now = 1_800_000_000;
        assert!(info.is_expired_untimestamped(now), "expired, no timestamp");
        assert!(!ts(Some(1_650_000_000)).is_expired_untimestamped(now), "timestamped inside the window");
        assert!(!ts(None).is_expired_untimestamped(now), "legacy countersignature without a time");
        assert!(ts(Some(1_750_000_000)).is_expired_untimestamped(now), "timestamped after expiry");
        assert!(ts(Some(1_500_000_000)).is_expired_untimestamped(now), "timestamped before issue");
        assert!(!info.is_expired_untimestamped(1_650_000_000), "not expired yet");

        // No window reported (catalog-signed, or a chain we could not read)
        // must not be read as "expired".
        let unknown = AuthenticodeInfo { is_signed: true, ..Default::default() };
        assert!(!unknown.is_expired(i64::MAX));
        assert!(!unknown.is_not_yet_valid(0));
    }

    /// End-to-end against a real signed binary: the publisher, the issuing CA,
    /// the leaf thumbprint, the chain depth and the validity window must all come
    /// out of one `WinVerifyTrust` call.
    ///
    /// Only meaningful on Windows with the target present, so it asserts the
    /// shape of the answer rather than any particular value.
    #[test]
    fn reads_certificate_identity_from_a_real_signed_binary() {
        let Ok(info) = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll") else {
            eprintln!("kernel32.dll not reachable, skipping");
            return;
        };
        assert!(info.is_file());
        let info = verify_authenticode(Path::new("C:\\Windows\\System32\\kernel32.dll"));
        assert!(info.is_signed, "a shipping system binary must read as signed");
        assert!(info.is_trusted, "and as trusted");

        let signer = info.signer_name.clone().expect("publisher");
        assert!(!signer.is_empty());
        assert!(!signer.contains("Production PCA"),
            "leaf, not the CA: got {signer:?}");

        assert!(info.issuer.is_some(), "issuing CA is now reported");
        assert!(info.chain_len >= 2, "leaf plus at least one CA, got {}", info.chain_len);

        let tp = info.thumbprint.clone().expect("leaf thumbprint");
        assert_eq!(tp.len(), 40, "lowercase SHA-1 hex");
        assert!(tp.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        assert!(info.not_before.unwrap_or(0) > 0);
        assert!(info.not_after.unwrap_or(0) > info.not_before.unwrap_or(0));
    }

    /// The countersignature has to survive the whole path, not just the parser:
    /// PE table -> PKCS#7 -> TSA name -> rule match.
    #[test]
    fn a_real_binary_is_timestamped_and_matches_a_tsa_rule() {
        let Ok(meta) = std::fs::metadata("C:\\Windows\\System32\\kernel32.dll") else {
            eprintln!("kernel32.dll not reachable, skipping");
            return;
        };
        assert!(meta.is_file());
        let info = verify_authenticode(Path::new("C:\\Windows\\System32\\kernel32.dll"));

        assert!(info.timestamped, "a shipping system binary is countersigned");
        assert!(info.timestamp_kind.is_some());
        assert!(info.timestamp_time.is_some(), "RFC 3161 carries a genTime");
        let tsa = info.timestamp_signer.clone().expect("TSA common name");
        assert!(!tsa.is_empty());
        // Not undated: the distinction is what the UndatedSignature rule reads.
        assert!(!info.is_undated());

        let (db, dir) = db_from_yaml(
            "a_real_binary_is_timestamped_and_matches_a_tsa_rule",
            &format!(
                r#"
name: t
rules:
  - id: bad-tsa
    title: "Abusive TSA"
    conditions:
      - type: signature_timestamp_signer_contains
        value: "{tsa}"
"#
            ),
        );
        assert!(db.is_malicious_tsa(&tsa));
        assert!(db.is_malicious_tsa(&tsa.to_lowercase()), "case-insensitive");
        assert!(!db.is_malicious_tsa("Some Other Authority"),
            "the publisher list must not be reused for TSAs");
        assert!(!db.is_malicious(&tsa),
            "a TSA is not the publisher of the file");

        let _ = std::fs::remove_dir_all(dir);
    }

    const ANALYST_SIGNERS: &str = r#"
rules:
  - id: analyst-mal-1
    title: "Fake updater certificate"
    description: "Seen signing FakeAV droppers"
    verdict: malicious
    family: "Trojan.FakeAV"
    severity: high
    conditions:
      - type: signature_signer_contains
        value: "Evil Updates Ltd"
      - type: signature_thumbprint_any
        value: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd"
  - id: analyst-trust-1
    title: "In-house build signer"
    verdict: trusted
    conditions:
      - type: signature_signer_equals
        value: "Contoso Build"
"#;

    #[test]
    fn validate_signer_rules_accepts_analyst_document() {
        assert_eq!(validate_signer_rules_yaml(ANALYST_SIGNERS), Ok(2));
    }

    #[test]
    fn validate_signer_rules_rejects_bad_rules() {
        let no_verdict = "rules:\n  - id: r1\n    title: T\n    conditions:\n      - type: signature_signer_contains\n        value: x\n";
        assert!(validate_signer_rules_yaml(no_verdict).unwrap_err().contains("r1"));

        let bad_type = "rules:\n  - id: r2\n    title: T\n    verdict: pua\n    conditions:\n      - type: signature_signer_like\n        value: x\n";
        assert!(validate_signer_rules_yaml(bad_type).unwrap_err().contains("unsupported type"));

        let trusted_issuer = "rules:\n  - id: r3\n    title: T\n    verdict: trusted\n    conditions:\n      - type: signature_issuer_contains\n        value: x\n";
        assert!(validate_signer_rules_yaml(trusted_issuer).unwrap_err().contains("trusted rules only"));

        let short_tp = "rules:\n  - id: r4\n    title: T\n    verdict: malware\n    conditions:\n      - type: signature_thumbprint_any\n        value: abcd\n";
        assert!(validate_signer_rules_yaml(short_tp).unwrap_err().contains("40 hex"));

        let no_title = "rules:\n  - id: r5\n    verdict: malware\n    conditions:\n      - type: signature_signer_contains\n        value: x\n";
        assert!(validate_signer_rules_yaml(no_title).unwrap_err().contains("title"));

        assert!(validate_signer_rules_yaml("rules: []").is_err());
    }

    #[test]
    fn add_rules_yaml_routes_by_verdict_and_keeps_metadata() {
        let mut db = SignerDb::default();
        assert_eq!(db.add_rules_yaml(ANALYST_SIGNERS), Ok(2));

        let hit = db.malicious_match("EVIL UPDATES LTD").expect("malicious publisher");
        let meta = hit.meta.as_deref().unwrap();
        assert_eq!(meta.family.as_deref(), Some("Trojan.FakeAV"));
        assert_eq!(
            meta.summary().as_deref(),
            Some("Fake updater certificate: Seen signing FakeAV droppers")
        );
        assert!(db.is_pinned_thumbprint("aabbccddeeff00112233445566778899aabbccdd"));

        let trusted = db.trusted_match("Contoso Build").expect("trusted publisher");
        assert_eq!(trusted.meta.as_deref().unwrap().title, "In-house build signer");
        assert!(!db.is_malicious("Contoso Build"));

        // A rejected document adds nothing.
        assert!(db.add_rules_yaml("rules:\n  - id: x\n    title: T\n    verdict: nope\n    conditions: []\n").is_err());
        assert_eq!(db.pattern_counts(), (1, 1, 0));
    }
}
