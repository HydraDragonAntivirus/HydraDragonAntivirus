# Firewall SDK Feature Quick Reference

This SDK surfaces reusable primitives for packet inspection, enrichment, and signature-based detections. Use this page as a compact wiki-style checklist of what is available today.

## Packet & Context Helpers
- `RawPacket::from_parts` captures metadata (source/destination, ports, protocol), payload preview, and a hex dump for offline analysis.
- TLS hostname/context enrichment via the HTTPS hook path (when process permissions allow injection).
- DNS query extraction routed through the engine for keyword and signature checks.
- File magic hints via `file_magic` for basic content-type insight.

## Signature Registry
- Centralized registry API for adding/removing signatures and listing registered entries with metadata.
- Built-in enable/disable toggles per signature plus “enabled by default” bookkeeping.
- Thread-safe evaluation helper to run all enabled signatures over packet data and return hit metadata in one call.

## Built-in Signatures
- Keyword-pattern checks (raw and reversed) to catch obfuscated strings.
- PowerShell encoded-command regex detection with severity/category metadata.
- Suspicious reversed-command detector for common evasion tricks.
- DNS keyword blocker that operates before general keyword checks.
- Placeholder-safe metadata cloning so UI/alert layers can safely render category, severity, and descriptions.

## Result Metadata
- `SdkFinding` values surface: signature name, category, severity, matching pattern, optional process context, and a human-readable reason string.
- Helper formatting for alert reasons in the engine so UI copy remains consistent.

## How to Extend
1. Implement `SecuritySignature` for a new detection (e.g., protocol-specific parser, regex, heuristic).
2. Register it via the registry helper; include category/severity for consistent UI and logging.
3. Use the registry evaluation helper in the engine or any consumer to obtain aggregated findings.

## Operational Notes
- HTTPS hook injection may be skipped for protected/system processes if Windows denies `OpenProcess`; this is normal. The engine logs an informational entry and suppresses retries for that PID.
- Registry-backed evaluation is invoked by default in the engine, so new signatures become active once registered.

