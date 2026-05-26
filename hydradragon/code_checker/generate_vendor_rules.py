#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate HydraDragonStatic malicious vendor YAML rules with malware types."""

import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MALVENDOR_DB = REPO_ROOT / "hydradragon" / "Owlyshield" / "signature" / "malvendor.db"
OUTPUTS = (
    REPO_ROOT
    / "hydradragon"
    / "Owlyshield"
    / "static_rules"
    / "malicious_vendors_complete.yaml",
    REPO_ROOT
    / "Owlyshield"
    / "hydradragonstatic"
    / "examples"
    / "malicious_vendors_complete.yaml",
)


def yaml_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def tag_from_malware_type(malware_type: str) -> str:
    tag = re.sub(r"[^a-z0-9]+", "-", malware_type.lower()).strip("-")
    return tag or "malware-generic"


def read_vendor_records() -> list[tuple[str, str]]:
    records = []
    with MALVENDOR_DB.open("r", encoding="utf-8-sig") as db:
        for line in db:
            if "|" not in line:
                continue
            vendor, malware_type = (part.strip() for part in line.split("|", 1))
            vendor = vendor.lstrip("\ufeff")
            if not vendor:
                continue
            records.append((vendor, malware_type or "Malware.Generic"))
    return records


def render_rule(rule_id: int, vendor: str, malware_type: str) -> str:
    malware_tag = tag_from_malware_type(malware_type)
    title = f"Malicious Vendor: {vendor}"
    description = f"Detects files signed by {vendor} (Known for: {malware_type})"

    return f"""  - id: malicious-vendor-{rule_id:04d}
    title: {yaml_quote(title)}
    description: {yaml_quote(description)}
    severity: High
    verdict: malware
    confidence: 90
    score: 50
    family: {yaml_quote(malware_type)}
    tags:
      - signature
      - malware
      - certificate-abuse
      - {malware_tag}
    logic: all
    conditions:
      - type: signature_signer_contains
        value: {yaml_quote(vendor)}
        nocase: true

"""


def render_yaml(records: list[tuple[str, str]]) -> str:
    rules = [
        render_rule(index, vendor, malware_type)
        for index, (vendor, malware_type) in enumerate(records, start=1)
    ]
    return f"""# Malicious Vendor Detection Rules
# Auto-generated from malvendor.db - Complete database with all {len(rules)} vendors
# Each rule includes the vendor name and associated malware type
# These rules detect files signed by known malicious certificate authorities

name: HydraDragonStatic Malicious Vendor Rules
version: "1"
rules:
{''.join(rules)}"""


def main() -> None:
    records = read_vendor_records()
    yaml_content = render_yaml(records)

    for output in OUTPUTS:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(yaml_content, encoding="utf-8", newline="\n")

    print(f"Created complete YAML with {len(records)} vendor rules including malware types")


if __name__ == "__main__":
    main()
