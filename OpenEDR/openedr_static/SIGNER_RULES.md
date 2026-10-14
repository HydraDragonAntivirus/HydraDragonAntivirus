# `signer_rules/` — Authenticode rule schema

Rules for `openedr_static`'s signer layer. The corpus is loaded by
`SignerDb::load_from_dir()` from three files:

| File | Role |
|---|---|
| `trusted_signers.yaml` | publishers that make a file trusted |
| `malicious_vendors.yaml` | abusive publishers / issuing CAs |
| `pua_vendors.yaml` | unwanted-software publishers / issuing CAs |

The canonical copy lives in `HydraDragonAVPortable/hydradragonsig_rules/`; the
installer copies it to `<app>\signer_rules\` byte-for-byte.

## What the engine measures first

`signers::verify_authenticode(path)` runs `WinVerifyTrust` with
`WINTRUST_ACTION_GENERIC_VERIFY_V2`, falls back to Windows Catalog membership
for files with no embedded PKCS#7 (`cmd.exe`, `notepad.exe`, ...), and caches
the verdict on `(path, size, mtime)`. It returns:

| Field | Meaning |
|---|---|
| `is_signed` | a signature exists and a chain could be read from it |
| `is_trusted` | WinVerifyTrust returned `ERROR_SUCCESS` |
| `signer_name` | publisher display name of the leaf certificate |
| `issuer` | display name of the CA that issued the leaf |
| `status` | `trusted` / `signed_untrusted` / `unsigned`, or an error string |
| `is_catalog_signed` | signed through the Catalog rather than an embedded PKCS#7 |
| `chain_len` | certificates in the verified chain, leaf first |
| `thumbprint` | SHA-1 of the leaf certificate, lowercase hex |
| `not_before` / `not_after` | leaf validity window, Unix seconds |

All of it comes out of the `pasCertChain` walk WinVerifyTrust already did, so
nothing here costs extra I/O.

**A file is trusted only when `is_trusted` *and* its publisher is listed in
`trusted_signers.yaml`.** Trust is never granted by the signature alone.

## Conditions

Every condition is `{ type, value }`. Matching is case-insensitive throughout.
Unknown `type` values are ignored, so a typo silently disables a rule — keep
the list below in sync when adding one.

| Type | Value | Matches when |
|---|---|---|
| `signature_signer_contains` | publisher substring | the publisher string contains `value` |
| `signature_signer_equals` | exact publisher | the publisher string equals `value` |
| `signature_issuer_contains` | CA substring | the **issuing CA** string contains `value` |
| `signature_issuer_equals` | exact CA | the issuing CA string equals `value` |
| `signature_thumbprint_any` | 40 hex chars | the leaf SHA-1 equals `value` |
| `signature_timestamp_signer_contains` | TSA substring | the countersigning **authority** contains `value` |
| `signature_timestamp_signer_equals` | exact TSA | the countersigning authority equals `value` |

`signature_thumbprint_any` accepts `aa:bb:cc:...`, spaced or bare hex, any case;
everything that is not a hex digit is dropped and the value must end up exactly
40 characters, so a truncated digest pins nothing instead of pinning something
wrong.

## Why both publisher *and* issuer

Certificate abuse is a property of the **CA**, not of the publisher string it
happens to carry. A compromised CA mints certificates for arbitrary subjects, so
a corpus written only against publishers never sees it, and a publisher rule
kept forever keeps firing after the abuse stops. Use `signature_issuer_*` for
the abuse case and `signature_signer_*` for vendors whose certificates stay
reputable in the wrong hands.

## How a match scores

| Match | Layer | Score | Verdict |
|---|---|---|---|
| malicious publisher | `SignerRule` / `MaliciousSigner` | 1.00 | malware |
| malicious issuer | `SignerRule` / `MaliciousCertIssuer` | 1.00 | malware |
| pinned thumbprint | `SignerRule` / `PinnedCertificate` | 1.00 | malware |
| PUA publisher | `SignerRule` / `PuaSigner` | 0.85 (below the 0.85 malware cut-off) | suspicious |
| PUA issuer | `SignerRule` / `PuaCertIssuer` | 0.85 | suspicious |
| signer certificate past `not_after`, or before `not_before` | `SignerRule` / `SignerCertificate expired` | 0.85 | suspicious |

Malicious checks run before PUA checks, and both run before the benign
whitelist, so a listed certificate cannot be whitewashed by a clean SHA-256.
`signature_thumbprint_any` is the only way to name a single revoked-but-still-
trusted certificate; its publisher and issuer usually look ordinary.

## Countersignatures

The embedded PKCS#7 is walked for a countersignature in both shapes Windows
emits: RFC 3161 (`1.3.6.1.4.1.311.3.3.1`, preferred) and legacy PKCS#9
(`1.2.840.113549.1.9.6`). What comes out is the TSA common name and, for RFC
3161, the `genTime` of the TSTInfo as Unix seconds.

Only the RSA-less facts are read, not the TSA's own chain: WinTrust has already
decided whether the signature is valid, so this reports what the countersignature
says rather than re-judging it. A PKCS#9 countersignature carries no timestamp
value, so it yields a signer name and `timestamped: true` with no time.

Catalog-signed files have no embedded PKCS#7 of their own, so they report "no
timestamp". That is not the same as "undated" and is not treated as such:
`is_undated()` requires an embedded signature.

Rules can name a TSA:

```yaml
- condition: signature_timestamp_signer_contains
  value: "Timestamping Authority"
```

A timestamp authority the rules call abusive is its own signal. Malware re-mints
countersignatures to keep a revoked certificate looking current, so a binary
whose signing time and whose countersignature disagree is worth reporting even
when neither side is listed. `UndatedSignature` covers the simpler case: signed,
trusted, and carrying no countersignature at all.

## Example

See `examples/signer_rules_certificate_abuse.yaml`. It is documentation only and
is not loaded by the engine; copying entries from it into the real corpus is
what makes them active.