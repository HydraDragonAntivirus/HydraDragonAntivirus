#!/usr/bin/env python3
"""Convert a Windows Code Integrity (WDAC / App Control) deny policy, such as
Microsoft's recommended vulnerable driver blocklist, into HydraDragonSig rules.

    python tools/wdac_to_hds.py VulnerableDriverBlockList/DriverPolicy_Enforced.xml \
        -o OpenMalwareScannerPortable/hydradragonsig_rules/vulnerable_driver_blocklist.yaml

Every deny the kernel signing scenario of the policy enforces becomes a rule:

* `<Deny Hash=...>` rules, grouped per driver name: `authentihash_any`
  (`values` = "Hash Sha1/Sha256", the Authenticode image digest; `pages` =
  "Hash Page Sha1/Sha256", the first-page digest).
* `<Deny FileName=...>` rules: `version_info` (OriginalFilename and the
  version bounds).
* `<DeniedSigner>`s: `authenticode` (`cert_tbs_any` = CertRoot TBS,
  `publisher` = CertPublisher, `oem_id` = CertOemID), one rule per referenced
  `<FileAttrib>` (WDAC ORs them), each with its `version_info`.

All rules start with `pe_subsystem: [native]`, so only kernel-mode images pay
for the digests. Microsoft's policy is the source of truth: re-run this script
on a new download instead of editing the output.
"""

from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET

NS = {"s": "urn:schemas-microsoft-com:sipolicy"}
KERNEL_SCENARIO = "131"
NO_MIN = "0.0.0.0"
NO_MAX = "65535.65535.65535.65535"
# WDAC file attribute -> VS_VERSIONINFO string key (WDAC "FileName" is OriginalFilename).
ATTR_FIELDS = {
    "FileName": "OriginalFilename",
    "InternalName": "InternalName",
    "ProductName": "ProductName",
    "FileDescription": "FileDescription",
}
GLOB_CHARS = set("*?#")
HASH_NAME = re.compile(r"^(?P<name>.*?) Hash (?P<page>Page )?(?P<alg>Sha1|Sha256)\s*$", re.I)


def q(text: str) -> str:
    """YAML double-quoted scalar."""
    out = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{out}"'


def safe_token(text: str) -> str:
    text = re.sub(r"\.sys$", "", text.strip(), flags=re.I)
    token = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_")
    return token or "Unnamed"


class Writer:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.ids: set[str] = set()

    def unique_id(self, base: str) -> str:
        rid, n = base, 2
        while rid in self.ids:
            rid, n = f"{base}-{n}", n + 1
        self.ids.add(rid)
        return rid

    def rule(self, *, rid: str, title: str, description: str, family: str, confidence: int,
             tags: list[str], references: list[str], conditions: list[list[str]]) -> None:
        w = self.lines.append
        w(f"  - id: {rid}")
        w(f"    title: {q(title)}")
        w(f"    description: {q(description)}")
        w("    severity: high")
        w("    verdict: pua")
        w(f"    confidence: {confidence}")
        w("    score: 60")
        w(f"    family: {q(family)}")
        w(f"    tags: [{', '.join(tags)}]")
        w("    references:")
        for ref in references:
            w(f"      - {q(ref)}")
        w("    logic: all")
        w("    conditions:")
        w("      - type: pe_subsystem")
        w("        values: [native]")
        for cond in conditions:
            w(f"      - {cond[0]}")
            for line in cond[1:]:
                w(f"        {line}")
        w("")


def version_condition(attrs: dict[str, str]) -> list[str] | None:
    fields = {}
    for wdac_key, vi_key in ATTR_FIELDS.items():
        value = attrs.get(wdac_key)
        if value:
            if GLOB_CHARS & set(value) or value.startswith("!"):
                raise SystemExit(f"{wdac_key}={value!r} holds glob characters; version_info has no escape")
            fields[vi_key] = value
    lo, hi = attrs.get("MinimumFileVersion"), attrs.get("MaximumFileVersion")
    lines = ["type: version_info"]
    if fields:
        lines.append("fields:")
        lines += [f"  {k}: {q(v)}" for k, v in fields.items()]
    if lo and lo != NO_MIN:
        lines.append(f"file_version_min: {q(lo)}")
    if hi and hi != NO_MAX:
        lines.append(f"file_version_max: {q(hi)}")
    if not fields:
        return None  # WDAC never has a version-only file rule; refuse to invent one
    return lines


def display_name(friendly: str, fallback: str) -> str:
    m = HASH_NAME.match(friendly or "")
    name = m.group("name") if m else (friendly or fallback)
    name = name.split("\\")[0].strip()  # "Agent64\<sha256 of sample>"
    name = re.sub(r"\s+(FileRule|FileAttribute)$", "", name)
    return name or fallback


def convert(xml_path: str, source: str, enforced_only: bool = False) -> tuple[str, dict[str, int]]:
    root = ET.parse(xml_path).getroot()
    version = root.findtext("s:VersionEx", default="?", namespaces=NS)
    policy_name = "?"
    for setting in root.iterfind(".//s:Setting", NS):
        if setting.get("ValueName") == "Name":
            policy_name = setting.findtext(".//s:String", default="?", namespaces=NS)

    file_rules = {r.get("ID"): r for r in root.find("s:FileRules", NS)}
    signers = {s.get("ID"): s for s in root.iterfind(".//s:Signers/s:Signer", NS)}

    scenario = next(
        (sc for sc in root.iterfind(".//s:SigningScenario", NS) if sc.get("Value") == KERNEL_SCENARIO),
        None,
    )
    if scenario is None:
        raise SystemExit("no kernel (131) signing scenario in the policy")
    denied_rule_ids = [r.get("RuleID") for r in scenario.iterfind(".//s:FileRulesRef/s:FileRuleRef", NS)]
    denied_signer_ids = [d.get("SignerId") for d in scenario.iterfind(".//s:DeniedSigners/s:DeniedSigner", NS)]

    out = Writer()
    stats = {"hash_rules": 0, "hashes": 0, "page_hashes": 0, "filename_rules": 0, "signer_rules": 0,
             "skipped_allow": 0}
    base_refs = [f"{policy_name} {version} ({source})"]
    tags = ["vulnerable-driver", "byovd", "wdac-blocklist"]

    # 1) Hash denies, grouped per driver name in policy order. Denies the
    #    policy defines but no signing scenario references (Windows does not
    #    enforce them yet) follow, marked as such, unless --enforced-only.
    referenced = set()
    for sc in root.iterfind(".//s:SigningScenario", NS):
        referenced.update(r.get("RuleID") for r in sc.iterfind(".//s:FileRuleRef", NS))
    referenced.update(r.get("RuleID") for r in root.iterfind(".//s:FileAttribRef", NS))
    unreferenced = [i for i, r in file_rules.items() if i not in referenced and r.tag.endswith("}Deny")]

    groups: dict[tuple[bool, str], dict] = {}
    filename_denies = []
    for enforced, ids in ((True, denied_rule_ids), (False, [] if enforced_only else unreferenced)):
        for rid in ids:
            rule = file_rules.get(rid)
            if rule is None:
                raise SystemExit(f"FileRuleRef {rid} has no FileRules entry")
            if rule.tag.endswith("}Allow"):
                stats["skipped_allow"] += 1
                continue
            if not rule.tag.endswith("}Deny"):
                raise SystemExit(f"unexpected file rule {rule.tag} ({rid})")
            digest = rule.get("Hash")
            if not digest:
                if not enforced:
                    raise SystemExit(f"unreferenced non-hash deny {rid}: not supported")
                filename_denies.append(rule)
                continue
            friendly = rule.get("FriendlyName", "")
            m = HASH_NAME.match(friendly)
            is_page = bool(m and m.group("page"))
            name = display_name(friendly, rid)
            g = groups.setdefault((enforced, name.lower()),
                                  {"name": name, "values": [], "pages": [], "ids": [], "enforced": enforced})
            (g["pages"] if is_page else g["values"]).append(digest.lower())
            g["ids"].append(rid)
            stats["page_hashes" if is_page else "hashes"] += 1
            if not enforced:
                stats["unenforced_hashes"] = stats.get("unenforced_hashes", 0) + 1

    for g in groups.values():
        token = safe_token(g["name"])
        cond = ["type: authentihash_any"]
        if g["values"]:
            cond.append("values:")
            cond += [f"  - {v}" for v in dict.fromkeys(g["values"])]
        if g["pages"]:
            cond.append("pages:")
            cond += [f"  - {v}" for v in dict.fromkeys(g["pages"])]
        note = "denied by" if g["enforced"] else "listed (not yet enforced by Windows) in"
        out.rule(
            rid=out.unique_id(f"MSVDB-HASH-{token}" if g["enforced"] else f"MSVDB-STAGED-{token}"),
            title=f"Vulnerable driver (Microsoft blocklist): {g['name']}",
            description=f"Authenticode / page hash of {g['name']} {note} the Microsoft vulnerable driver blocklist.",
            family=f"PUA.WinNT.VulnerableDriver.{token}",
            confidence=95 if g["enforced"] else 80,
            tags=tags if g["enforced"] else tags + ["wdac-unenforced"],
            references=base_refs + [f"WDAC rules: {', '.join(g['ids'])}"],
            conditions=[cond],
        )
        stats["hash_rules"] += 1

    # 2) File name denies.
    for rule in filename_denies:
        vc = version_condition(rule.attrib)
        if vc is None:
            raise SystemExit(f"deny {rule.get('ID')} has neither a hash nor a file name")
        name = rule.get("FileName") or display_name(rule.get("FriendlyName", ""), rule.get("ID"))
        token = safe_token(name)
        out.rule(
            rid=out.unique_id(f"MSVDB-NAME-{token}"),
            title=f"Vulnerable driver (Microsoft blocklist): {name}",
            description=f"{rule.get('FriendlyName') or name}: file name / version denied by the Microsoft vulnerable driver blocklist.",
            family=f"PUA.WinNT.VulnerableDriver.{token}",
            confidence=75,
            tags=tags,
            references=base_refs + [f"WDAC rule: {rule.get('ID')}"],
            conditions=[vc],
        )
        stats["filename_rules"] += 1

    # 3) Denied signers.
    for sid in denied_signer_ids:
        signer = signers.get(sid)
        if signer is None:
            raise SystemExit(f"DeniedSigner {sid} has no Signer entry")
        kids = {c.tag.split("}")[1] for c in signer}
        unknown = kids - {"CertRoot", "CertPublisher", "CertOemID", "FileAttribRef"}
        if unknown:
            raise SystemExit(f"signer {sid} uses {sorted(unknown)}: not supported")
        roots = signer.findall("s:CertRoot", NS)
        if any(r.get("Type") != "TBS" for r in roots):
            raise SystemExit(f"signer {sid}: only CertRoot Type=TBS is supported")
        auth = ["type: authenticode", "cert_tbs_any:"] + [f"  - {r.get('Value').lower()}" for r in roots]
        pub = signer.find("s:CertPublisher", NS)
        oem = signer.find("s:CertOemID", NS)
        if pub is not None:
            auth.append(f"publisher: {q(pub.get('Value'))}")
        if oem is not None:
            auth.append(f"oem_id: {q(oem.get('Value'))}")
        signer_desc = signer.get("Name", sid)
        who = " / ".join(x for x in [
            pub.get("Value") if pub is not None else None,
            oem.get("Value") if oem is not None else None,
        ] if x) or signer_desc
        attrib_refs = [r.get("RuleID") for r in signer.findall("s:FileAttribRef", NS)]
        if not attrib_refs:
            token = safe_token(who)
            out.rule(
                rid=out.unique_id(f"MSVDB-SIGNER-{token}"),
                title=f"Vulnerable driver signer (Microsoft blocklist): {who}",
                description=f"Kernel image signed through {signer_desc}, a signer denied by the Microsoft vulnerable driver blocklist.",
                family=f"PUA.WinNT.VulnerableDriver.{token}",
                confidence=85,
                tags=tags,
                references=base_refs + [f"WDAC signer: {sid}"],
                conditions=[auth],
            )
            stats["signer_rules"] += 1
            continue
        for ref in attrib_refs:
            attrib = file_rules.get(ref)
            if attrib is None or not attrib.tag.endswith("}FileAttrib"):
                raise SystemExit(f"signer {sid}: FileAttribRef {ref} is not a FileAttrib")
            vc = version_condition(attrib.attrib)
            if vc is None:
                raise SystemExit(f"FileAttrib {ref} names no file")
            name = next((attrib.get(k) for k in ATTR_FIELDS if attrib.get(k)), ref)
            token = safe_token(name)
            out.rule(
                rid=out.unique_id(f"MSVDB-SIGNED-{token}"),
                title=f"Vulnerable driver (Microsoft blocklist): {name} signed by {who}",
                description=f"{name} signed through {signer_desc}, denied by the Microsoft vulnerable driver blocklist.",
                family=f"PUA.WinNT.VulnerableDriver.{token}",
                confidence=85,
                tags=tags,
                references=base_refs + [f"WDAC signer: {sid}, file attribute: {ref}"],
                conditions=[auth, vc],
            )
            stats["signer_rules"] += 1

    header = [
        "# Generated by hydradragonsig/tools/wdac_to_hds.py - do not edit by hand.",
        f"# Source: {source} ({policy_name} {version}).",
        "# Re-run the converter on a new Microsoft download instead.",
        f"# {stats}",
        "",
        "name: Microsoft vulnerable driver blocklist",
        f"version: {q(version)}",
        "rules:",
        "",
    ]
    return "\n".join(header + out.lines), stats


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("policy", help="WDAC policy XML (DriverPolicy_Enforced.xml)")
    ap.add_argument("-o", "--output", required=True, help="HydraDragonSig YAML to write")
    ap.add_argument("--source", default="https://aka.ms/VulnerableDriverBlockList",
                    help="where the policy came from (copied to every rule's references)")
    ap.add_argument("--enforced-only", action="store_true",
                    help="leave out hash denies no signing scenario references (not enforced by Windows)")
    args = ap.parse_args()
    text, stats = convert(args.policy, args.source, args.enforced_only)
    with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print(f"wrote {args.output}: {stats}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
