#!/usr/bin/env python3
"""CLI for openedr_static.dll via the Python SDK."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, Iterable, List, Optional

from openedr_sdk import OpenEdrScanner

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_PORTABLE = os.path.join(REPO_ROOT, "OpenMalwareScannerPortable")
DEFAULT_DLL = os.path.join(DEFAULT_PORTABLE, "openedr_static.dll")

FLAGGED = {"Malicious", "Suspicious", "Error"}


def repo_defaults() -> tuple[str, str]:
    dll = DEFAULT_DLL if os.path.isfile(DEFAULT_DLL) else "openedr_static.dll"
    rules = DEFAULT_PORTABLE if os.path.isdir(DEFAULT_PORTABLE) else os.path.dirname(dll)
    return dll, rules


def load_scanner(dll: Optional[str], rules: Optional[str]) -> OpenEdrScanner:
    default_dll, default_rules = repo_defaults()
    return OpenEdrScanner(dll_path=dll or default_dll, rules_dir=rules or default_rules)


def print_json(obj: Any) -> None:
    json.dump(obj, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


def verdict_line(report: Dict[str, Any]) -> str:
    verdict = report.get("verdict", "Unknown")
    score = report.get("max_threat_score")
    target = report.get("target") or report.get("target_url") or report.get("query_path") or ""
    sha = report.get("sha256") or ""
    parts = [verdict]
    if score is not None:
        parts.append(f"score={score}")
    if sha:
        parts.append(sha)
    if target:
        parts.append(target)
    return " ".join(str(p) for p in parts)


def print_report(report: Dict[str, Any], raw: bool) -> None:
    if raw or report.get("error"):
        print_json(report)
        return
    print(verdict_line(report))
    signer = report.get("signer_info") or {}
    if signer:
        print(
            "  signer  trusted={trusted} catalog={catalog} status={status} name={name}".format(
                trusted=signer.get("is_trusted"),
                catalog=signer.get("is_catalog_signed"),
                status=signer.get("status"),
                name=signer.get("signer_name"),
            )
        )
    dets = report.get("detections") or []
    if dets:
        print(f"  detections ({len(dets)}):")
        for det in dets:
            extra = ""
            if det.get("details"):
                extra = f" — {det['details']}"
            print(f"    [{det.get('layer')}] {det.get('name')} ({det.get('score')}){extra}")
    matches = report.get("pua_registry_matches") or report.get("matched_patterns") or []
    if matches:
        print("  matches:")
        for m in matches:
            print(f"    {m}")
    if "malware_probability" in report:
        print(f"  malware_probability={report.get('malware_probability')}")
    if "scan_time_ms" in report:
        print(f"  scan_time_ms={report.get('scan_time_ms')}")


def walk_files(root: str, recursive: bool) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return
    if not os.path.isdir(root):
        raise FileNotFoundError(root)
    if not recursive:
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isfile(path):
                yield path
        return
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            yield os.path.join(dirpath, name)


def cmd_scan(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    flagged = 0
    reports: List[Dict[str, Any]] = []
    for path in walk_files(args.path, args.recursive):
        report = scanner.scan_file(os.path.abspath(path))
        reports.append(report)
        if (report.get("verdict") or "") in FLAGGED:
            flagged += 1
        if not args.json:
            print_report(report, raw=False)
    if args.json:
        print_json(reports if len(reports) != 1 else reports[0])
    return 1 if flagged else 0


def cmd_bytes(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    with open(args.path, "rb") as fh:
        data = fh.read()
    name = args.name or os.path.basename(args.path)
    report = scanner.scan_bytes(data, name)
    print_report(report, args.json)
    return 1 if (report.get("verdict") or "") in FLAGGED else 0


def cmd_url(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    report = scanner.scan_url(args.url)
    print_report(report, args.json)
    return 1 if (report.get("verdict") or "") in FLAGGED else 0


def cmd_registry(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    report = scanner.check_registry(args.path)
    print_report(report, args.json)
    return 1 if report.get("is_pua_autostart") or report.get("matched_patterns") else 0


def cmd_evtx(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    report = scanner.scan_evtx(os.path.abspath(args.path))
    print_report(report if isinstance(report, dict) else {"matches": report}, args.json)
    return 0


def cmd_events(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    report = scanner.scan_system_events()
    print_report(report if isinstance(report, dict) else {"matches": report}, args.json)
    return 0


def cmd_hosts(scanner: OpenEdrScanner, args: argparse.Namespace) -> int:
    if args.restore:
        report = scanner.restore_hosts_file(args.path, create_backup=not args.no_backup)
    else:
        report = scanner.check_hosts_file(args.path)
    print_report(report, args.json)
    return 0


def build_parser() -> argparse.ArgumentParser:
    default_dll, default_rules = repo_defaults()
    p = argparse.ArgumentParser(
        prog="openedr_cli",
        description="Scan files, URLs, registry, EVTX, and hosts via openedr_static.dll",
    )
    p.add_argument("--dll", default=default_dll, help="path to openedr_static.dll")
    p.add_argument("--rules", default=default_rules, help="rules/database directory next to the DLL")
    p.add_argument("--json", action="store_true", help="print raw JSON")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path")
    scan.add_argument("-r", "--recursive", action="store_true")
    scan.set_defaults(func=cmd_scan)

    b = sub.add_parser("bytes", help="scan file contents through scan_bytes")
    b.add_argument("path")
    b.add_argument("--name", help="virtual filename for extension matching")
    b.set_defaults(func=cmd_bytes)

    u = sub.add_parser("url", help="scan a URL")
    u.add_argument("url")
    u.set_defaults(func=cmd_url)

    r = sub.add_parser("registry", help="check a registry path against PUA rules")
    r.add_argument("path")
    r.set_defaults(func=cmd_registry)

    e = sub.add_parser("evtx", help="scan an EVTX log with Hayabusa rules")
    e.add_argument("path")
    e.set_defaults(func=cmd_evtx)

    ev = sub.add_parser("events", help="scan live Windows event logs")
    ev.set_defaults(func=cmd_events)

    h = sub.add_parser("hosts", help="check or restore the hosts file")
    h.add_argument("--path", help="custom hosts path (default: system hosts)")
    h.add_argument("--restore", action="store_true")
    h.add_argument("--no-backup", action="store_true")
    h.set_defaults(func=cmd_hosts)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        scanner = load_scanner(args.dll, args.rules)
    except Exception as exc:
        print(f"init failed: {exc}", file=sys.stderr)
        return 2
    try:
        return int(args.func(scanner, args))
    except FileNotFoundError as exc:
        print(f"not found: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"scan failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
