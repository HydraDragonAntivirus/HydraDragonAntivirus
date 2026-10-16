#!/usr/bin/env python3
"""Regenerates the "## Reference" part of ../API.md from the server code.

    python tools/gen_api_doc.py            # rewrite API.md
    python tools/gen_api_doc.py --check    # exit 1 when API.md is out of date

Reads the route tables (`dashboard_router` in src/dashboard.rs, `ScanServer::router` in
src/scan_server.rs), each handler's `///` doc comment and the fields of its Query / Json
request struct (with their `///` comments). Everything above "## Reference" in API.md is
hand-written and kept as it is. To document an endpoint, write the doc comment on its
handler in the code, then run this.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "..", "src")
DOC = os.path.join(HERE, "..", "API.md")
MARKER = "## Reference"

FILES = {
    f: open(os.path.join(SRC, f), encoding="utf-8", errors="replace").read().replace("\r\n", "\n")
    for f in os.listdir(SRC)
    if f.endswith(".rs")
}


def routes(text):
    out = []
    for m in re.finditer(r'\.route\(\s*(&?[\w"/:\-\.]+)\s*,\s*((?:get|post)\([^)]*\)(?:\.(?:get|post)\([^)]*\))*)', text):
        path = m.group(1).strip('"')
        for mm in re.finditer(r"(get|post)\(([\w:]+)\)", m.group(2)):
            full = mm.group(2)
            module = full.split("::")[1] + ".rs" if full.startswith("crate::") else None
            out.append((mm.group(1).upper(), path, full.split("::")[-1], module))
    return out


def doc_before(text, idx):
    """`///` lines directly above `idx` (attributes in between are skipped)."""
    lines = text[:idx].split("\n")[:-1]
    doc = []
    while lines:
        line = lines[-1].strip()
        if line.startswith("///"):
            doc.insert(0, line[3:].strip())
        elif not line.startswith("#["):
            break
        lines.pop()
    return " ".join(doc).strip()


def find_fn(name, prefer):
    order = ([prefer] if prefer in FILES else []) + [f for f in FILES if f != prefer]
    for f in order:
        t = FILES[f]
        m = re.search(r"(?:pub(?:\(crate\))?\s+)?async fn " + re.escape(name) + r"\s*\(", t)
        if m:
            return f, t, m.start(), t[m.start():t.find("{", m.end())]
    return None


def struct_fields(name):
    for t in FILES.values():
        m = re.search(r"(?:pub\s+)?struct " + re.escape(name) + r"\s*\{", t)
        if not m:
            continue
        depth, i = 1, m.end()
        while depth and i < len(t):
            depth += {"{": 1, "}": -1}.get(t[i], 0)
            i += 1
        fields, doc, has_default = [], [], False
        for line in t[m.end():i - 1].split("\n"):
            s = line.strip()
            if s.startswith("///"):
                doc.append(s[3:].strip())
                continue
            if s.startswith("#["):
                has_default |= "default" in s
                continue
            fm = re.match(r"(?:pub\s+)?(\w+)\s*:\s*(.+?),?$", s)
            if fm:
                ty = fm.group(2).rstrip(",")
                fields.append((fm.group(1), ty, has_default or ty.startswith("Option<"), " ".join(doc)))
            doc, has_default = [], False
        return fields
    return None


def nice(ty):
    ty = ty.strip()
    m = re.match(r"Option<(.+)>$", ty)
    if m:
        ty = m.group(1)
    m = re.match(r"Vec<(.+)>$", ty)
    if m:
        return "array of " + nice(m.group(1))
    return {"String": "string", "&str": "string", "bool": "boolean", "f64": "number", "f32": "number"}.get(
        ty, "integer" if re.fullmatch(r"[ui](8|16|32|64|size)", ty) else ty)


def cell(s):
    return s.replace("|", "\\|")


def section(out, title, text, base, default_file):
    out.append(f"\n### {title}\n")
    for method, path, handler, module in routes(text):
        if path.startswith("&"):
            path = base
        out.append(f"#### `{method} {path}`\n")
        found = find_fn(handler, module or default_file)
        if not found:
            out.append(f"Handler `{handler}`.\n")
            continue
        f, t, idx, sig = found
        d = doc_before(t, idx)
        out.append((d or "(No doc comment on the handler yet.)") + "\n")
        if re.search(r"Path\(\w+\)\s*:\s*Path<", sig):
            out.append("Path parameter: the `:` segment of the URL.\n")
        for kind, mt in (("Query parameters", re.search(r"Query\(\w+\)\s*:\s*Query<(\w+)>", sig)),
                         ("JSON body", re.search(r"Json\((?:mut\s+)?\w+\)\s*:\s*Json<(\w+)>", sig))):
            if not mt:
                continue
            fields = struct_fields(mt.group(1))
            if not fields:
                out.append(f"{kind}: `{mt.group(1)}`.\n")
                continue
            out.append(f"{kind}:\n\n| Name | Type | Required | Description |\n|---|---|---|---|")
            for name, ty, optional, dd in fields:
                out.append(f"| `{name}` | `{cell(nice(ty))}` | {'no' if optional else 'yes'} | {cell(dd)} |")
            out.append("")
        out.append(f"<sub>Handler: `src/{f}` → `{handler}`</sub>\n")


def reference():
    out = [MARKER, "", "Generated by `tools/gen_api_doc.py` from the code; edit the handler doc comments, not this part."]
    d = FILES["dashboard.rs"]
    section(out, "Dashboard API (127.0.0.1:9440)",
            d[d.index("pub fn dashboard_router"):d.index("const ARCHIVE_ALLOWED")], "/", "dashboard.rs")
    s = FILES["scan_server.rs"]
    start = s.index("pub fn router(self: &Arc<Self>")
    section(out, "Scan server (port 5306, public through the tunnel)",
            s[start:s.index(".with_state", start)], "/ws", "scan_server.rs")
    return "\n".join(out).rstrip() + "\n"


def main():
    current = open(DOC, encoding="utf-8").read() if os.path.exists(DOC) else ""
    head = current.split("\n" + MARKER, 1)[0].rstrip() + "\n\n" if MARKER in current else current
    new = head + reference()
    if "--check" in sys.argv:
        if new != current:
            print("API.md is out of date: run python tools/gen_api_doc.py")
            sys.exit(1)
        print("API.md is up to date")
        return
    with open(DOC, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(new)
    print(f"wrote {os.path.normpath(DOC)}")


if __name__ == "__main__":
    main()
