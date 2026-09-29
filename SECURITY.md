# Security Policy

## 📦 Supported Versions

Hydra Dragon Antivirus is an active, community-driven project. Security fixes are
shipped for the current release line and the latest `main` branch only. Older
lines do not receive backported fixes — please upgrade before reporting an issue
against them.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| `2.6.x` | ✅ |
| `< 2.6` | ❌ |

## ⚠️ Scope & Threat Model

> **Reminder:** this is a **real security product**, not a UI shell. Hydra Dragon
> ships a kernel minifilter driver, an ELAM/PPL early-launch component, a kernel
> filter driver, a privileged service, and a native scanning engine
> (`openedr_static`) that parses untrusted files with YARA-X, ClamAV, Capstone,
> pefile-rs and Unicorn. A bug in any of these is a bug in a privileged component.

In-scope, and treated as real vulnerabilities:

- Local privilege escalation, or code execution in a privileged context (driver, service, ELAM runner)
- Bypassing the product's own protection: tamper protection, self-exclusion, or trust decisions that let an attacker-supplied binary be treated as trusted
- Detection evasion that is a *code* defect rather than a missing signature (e.g. a parser that silently skips the signature block, or a trust check that fails open)
- Memory-safety and parsing issues reachable from untrusted input, including denial of service in the scanning engine
- Unsafe IPC, named-pipe or driver-control-surface handling that lets a low-privileged process influence the driver
- Accidentally shipped secrets, signing keys or credentials
- Supply-chain compromise of our own artifacts or of the update path

Explicitly **in scope** here, unlike in most UI projects: "a known test file is
not detected" and "a malicious sample is not detected" are legitimate reports when
they trace to a code defect. Reports that only describe a missing signature are
routed to the signature project instead.

Out of scope:

- Vulnerabilities in vendored third-party trees (`clamav\`, `hayabusa\`, `unicorn-engine-sys\`, `Owlyshield\HyperDbg\`, `Owlyshield\RedDbg\`, `eprj\` SDKs, …) — report those upstream; see below
- Deprecated directories kept in the tree for reference (everything outside `OpenEDR\`, `MBRFilter\`, `Sanctum\`)
- Missing detection of a specific sample with no code defect
- Vulnerabilities that require an attacker to already hold administrator rights and rely only on that

## 🐛 Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report privately:

1. **GitHub Security Advisories** (preferred) — use the
   [**"Report a vulnerability"**](https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/security/advisories/new)
   button in the Security tab of this repository. This creates a private
   advisory only maintainers can see.
2. **GitHub contact** — if advisories are not available to you, open a private
   channel with the maintainers through the organization page rather than a
   public issue.

If you are reporting a bug in a vendored component, please report it to that
project's own security process and let us know so we can update the subtree.

### What to include

A good vulnerability report contains:

- A clear description of the issue and its impact, and which component it is in (driver, service, `openedr_static`, installer, …)
- Reproduction steps or a minimal proof-of-concept
- Affected versions / commit hashes
- Any suggested mitigation
- Your name/handle for credit (or a note if you wish to remain anonymous)

Driver and service issues: tell us which Windows build and whether ELAM/PPL is
active, since that changes what an attacker can reach.

## ⏱️ Response Timeline

We aim to:

| Step | Target |
|---|---|
| Acknowledge receipt of your report | Within **72 hours** |
| Provide an initial assessment | Within **7 days** |
| Ship a fix (or a mitigation plan) | Within **30 days** for high/critical severity |
| Publish a public advisory + credit | After the fix is released |

These are best-effort targets from a volunteer-maintained project. Issues in the
kernel driver or in a privileged service are prioritised over the rest of the
queue within the same targets.

## 🤝 Disclosure Policy

We follow **coordinated disclosure**:

1. You report privately through the channel above.
2. We triage, reproduce, develop a fix, and prepare a release.
3. Once the fix is publicly available, we publish an advisory crediting the reporter (unless anonymity is requested).

Please give us a reasonable window to ship a fix before public disclosure. We
appreciate responsible reporting deeply.

## 🙏 Credits

Security researchers who responsibly disclose valid vulnerabilities will be
acknowledged in:

- The published GitHub Security Advisory
- The GitHub release notes for the release that carries the fix

Thank you for helping keep Hydra Dragon and its users safe!
