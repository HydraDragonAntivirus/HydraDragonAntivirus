# Security Policy

## 📦 Supported Versions

DefenderUI is an active, community-driven project. Only the latest `main` branch and the most recent tagged release receive security fixes.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| `1.0.x` | ✅ |
| `< 1.0` | ❌ |

## ⚠️ Scope & Threat Model

> **Reminder:** DefenderUI is a **frontend-only UI/UX concept**. It does **not** include any real antivirus engine, threat scanner, or security-critical functionality. All data is mocked.
>
> As such, the primary security concerns for this project are:
>
> - Accidentally shipped secrets / credentials in source
> - Unsafe handling of user input (even if mocked)
> - Vulnerable transitive NuGet dependencies
> - XAML injection, insecure file I/O patterns, or unsafe `Process.Start` usage
> - Supply-chain risks (malicious packages, tampered releases)
>
> Reports that depend on DefenderUI actually *being* an antivirus (e.g. "it doesn't detect EICAR") are **out of scope** — that is by design.

## 🐛 Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please report them privately using one of the following channels:

1. **GitHub Security Advisories** (preferred) — use the [**"Report a vulnerability"**](https://github.com/caymazyusuf72/defenderui/security/advisories/new) button in the Security tab of this repository. This creates a private advisory that only maintainers can see.
2. **GitHub contact** — reach the maintainer via [@caymazyusuf72](https://github.com/caymazyusuf72) for a private channel if advisories are not available.

### What to include

A good vulnerability report contains:

- A clear description of the issue and its impact
- Reproduction steps or a proof-of-concept
- Affected versions / commits
- Any suggested mitigation
- Your name/handle for credit (or a note if you wish to remain anonymous)

## ⏱️ Response Timeline

We aim to:

| Step | Target |
|---|---|
| Acknowledge receipt of your report | Within **72 hours** |
| Provide an initial assessment | Within **7 days** |
| Ship a fix (or a mitigation plan) | Within **30 days** for high/critical severity |
| Publish a public advisory + credit | After the fix is released |

These are best-effort targets from a volunteer-maintained project.

## 🤝 Disclosure Policy

DefenderUI follows **coordinated disclosure**:

1. You report privately via the channels above.
2. We triage, develop a fix, and prepare a release.
3. Once the fix is publicly available, we publish an advisory crediting the reporter (unless anonymity is requested).

Please give us a reasonable window to ship a fix before public disclosure. We appreciate responsible reporting deeply.

## 🙏 Credits

Security researchers who responsibly disclose valid vulnerabilities will be acknowledged in:

- The published GitHub Security Advisory
- The project [`CHANGELOG.md`](CHANGELOG.md)

Thank you for helping keep DefenderUI and its users safe!