#!/usr/bin/env python3
"""
Convert an EmergingThreats Suricata ruleset (emerging-all.rules) into the
HydraDragonFirewall SDK YAML format (SdkRuleFile, see src/sdk.rs).

Best-effort mapping (documented limitations):
  * alert          -> action: traffic_attack
  * drop / reject  -> action: block
  * pass           -> action: allow
  * proto          -> tcp|udp|icmp, everything else -> omitted (any)
  * IP / CIDR literals -> src_ip / dst_ip IpMatcher
    ($HOME_NET, $EXTERNAL_NET, other $vars, negations '!' -> treated as any)
  * ports          -> src_port / dst_port PortMatcher
    ($vars and negations -> treated as any)
  * content        -> regex term (payload contains, in order, joined by
    bounded '.' gaps instead of '.*?' whenever offset/depth/within/distance
    are present; '\\A' anchors offset/depth of the first term;
    'startswith'/'endswith' anchor the whole regex to the buffer start/end)
    hex |..| segments are decoded to raw bytes; the resulting byte string is
    lossy-decoded exactly like the SDK (String::from_utf8_lossy), so binary
    patterns match only when they also survive the SDK's lossy payload decode.
  * pcre           -> regex term (delimiters/flags stripped; /i -> (?i:...))
  * sticky buffers (dotted keywords: http.request_line, http.header,
    http.request_body, http.method, http.uri, dns.query, tls.sni, file.data,
    ...) -> tracked and applied to every content/pcre that follows them,
    not just the one they happen to precede in the option list; pkt_data
    resets back to the raw payload buffer. Legacy non-dotted post-content
    modifiers (nocase, startswith, endswith, fast_pattern, http_uri,
    http_host, dns_query, ...) still apply only to the content they follow.
  * content w/ http.host|host|dns.query|tls.sni -> domain.domains
    (works whether the sticky buffer appears before or after the content)
  * ip_proto:N     -> ip_proto (numeric IP protocol; known names mapped)
  * dsize:...      -> dsize (exact / min:max / >n / <n / min:max:mod:offset)
  * byte_test:...  -> byte_test (nbytes/op/value/offset, big|little, string,
    relative [treated as absolute offset], dec|hex|oct, no_case)
  * flow:...       -> flow (established, to_client, to_server, stateless)
  * flowbits:...   -> flowbits ops (set/unset/toggle/isset/isnotset);
    flowbits:noalert -> private: true (rule still sets flags, emits no alert)
  * threshold/classtype/reference/metadata and other cosmetic modifiers ->
    ignored (best effort). Content positional modifiers offset/depth/within/
    distance ARE honored (see content above); within/distance of a content
    that has no preceding content, or offset/depth on a non-first content,
    cannot be expressed and fall back to '.*?'.
  * bidirectional '<>' rules -> kept forward-only

Every well-formed rule is converted. Negated content (content:!"..") cannot be
expressed in the SDK, so the negated term is dropped and the rule is kept with
its remaining positive matchers. Only lines that are not valid Suricata rules
(unparseable header/action) are skipped.

Usage:
    python convert_emerging_rules.py [input.rules] [output.rules.yaml]
"""

import re
import sys
from pathlib import Path

DEFAULT_INPUT = (
    Path(__file__).resolve().parent.parent.parent
    /"emerging-all.rules"
)
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent
    / "rules.yaml"
)

ACTION_MAP = {"alert": "traffic_attack", "drop": "block", "reject": "block", "pass": "allow"}

PROTO_MAP = {"tcp": "tcp", "udp": "udp", "icmp": "icmp",
             "tcp-pkt": "tcp", "udp-pkt": "udp"}

# Host-like content modifiers -> domain matcher
HOST_MODIFIERS = {"http.host", "host", "dns.query", "tls.sni"}

DISABLED_SIDS = {2100640, 2009247, 2009285}

stats = {"lines": 0, "rules": 0, "skipped_header": 0, "skipped_action": 0,
         "dropped_negated": 0, "dropped_bad_content": 0, "no_matchers": 0,
         "content_patterns": 0, "pcre_rules": 0, "overridden": 0}

# No content-to-regex overrides. Binary Suricata `content:` is kept byte-native.


# ---------------------------------------------------------------------------
# YAML emission (small subset: maps/lists of scalars, double-quoted strings)
# ---------------------------------------------------------------------------

def yaml_quote(value: str) -> str:
    out = []
    for ch in value:
        code = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20 or 0x7F <= code <= 0x9F or code in (0x85, 0x2028, 0x2029):
            out.append("\\u%04x" % code)
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def emit_ip_matcher(indent: str, key: str, matcher) -> list:
    addresses = matcher.get("addresses", [])
    cidrs = matcher.get("cidr_ranges", [])
    lines = ["%s%s:" % (indent, key)]
    if addresses:
        lines.append("%s  addresses:" % indent)
        lines += ["%s    - %s" % (indent, yaml_quote(a)) for a in addresses]
    else:
        lines.append("%s  addresses: []" % indent)
    if cidrs:
        lines.append("%s  cidr_ranges:" % indent)
        lines += ["%s    - %s" % (indent, yaml_quote(c)) for c in cidrs]
    else:
        lines.append("%s  cidr_ranges: []" % indent)
    return lines


def emit_port_matcher(indent: str, key: str, matcher) -> list:
    lines = ["%s%s:" % (indent, key)]
    ports = matcher.get("ports", [])
    ranges = matcher.get("ranges", [])
    if ports:
        lines.append("%s  ports: [%s]" % (indent, ", ".join(str(p) for p in ports)))
    else:
        lines.append("%s  ports: []" % indent)
    if ranges:
        lines.append("%s  ranges: [%s]" % (
            indent, ", ".join("[%d, %d]" % (a, b) for a, b in ranges)))
    else:
        lines.append("%s  ranges: []" % indent)
    return lines


def emit_rule(rule: dict) -> list:
    lines = ["  - name: %s" % yaml_quote(rule["name"])]
    if rule.get("description"):
        lines.append("    description: %s" % yaml_quote(rule["description"]))
    if rule.get("severity"):
        lines.append("    severity: %s" % yaml_quote(rule["severity"]))
    enabled = rule.get("enabled", True)
    lines.append("    enabled: %s" % ("true" if enabled else "false"))
    if rule.get("protocol"):
        lines.append("    protocol: %s" % rule["protocol"])
    lines.append("    action: %s" % rule["action"])
    if rule.get("src_ip"):
        lines += emit_ip_matcher("    ", "src_ip", rule["src_ip"])
    if rule.get("dst_ip"):
        lines += emit_ip_matcher("    ", "dst_ip", rule["dst_ip"])
    if rule.get("src_port"):
        lines += emit_port_matcher("    ", "src_port", rule["src_port"])
    if rule.get("dst_port"):
        lines += emit_port_matcher("    ", "dst_port", rule["dst_port"])
    if rule.get("domain"):
        lines.append("    domain:")
        lines.append("      domains: [%s]" % ", ".join(yaml_quote(d) for d in rule["domain"]["domains"]))
        lines.append("      case_insensitive: %s" % ("true" if rule["domain"].get("case_insensitive") else "false"))
    if rule.get("contents"):
        lines.append("    contents:")
        for content in rule["contents"]:
            lines.append("      - hex: %s" % yaml_quote(content["hex"]))
            lines.append("        case_insensitive: %s" % ("true" if content.get("case_insensitive") else "false"))
            if content.get("offset") is not None:
                lines.append("        offset: %d" % content["offset"])
            if content.get("depth") is not None:
                lines.append("        depth: %d" % content["depth"])
            if content.get("within") is not None:
                lines.append("        within: %d" % content["within"])
            if content.get("distance") is not None:
                lines.append("        distance: %d" % content["distance"])
            if content.get("startswith"):
                lines.append("        startswith: true")
            if content.get("endswith"):
                lines.append("        endswith: true")
    if rule.get("regex"):
        lines.append("    regex:")
        lines.append("      pattern: %s" % yaml_quote(rule["regex"]["pattern"]))
        lines.append("      case_insensitive: %s" % ("true" if rule["regex"].get("case_insensitive") else "false"))
    if rule.get("ip_proto") is not None:
        lines.append("    ip_proto: %d" % rule["ip_proto"])
    if rule.get("dsize"):
        d = rule["dsize"]
        lines.append("    dsize:")
        for k in ("exact", "min", "max", "mod_divisor", "mod_offset"):
            if d.get(k) is not None:
                lines.append("      %s: %d" % (k, d[k]))
    if rule.get("byte_test"):
        lines.append("    byte_test:")
        for bt in rule["byte_test"]:
            lines.append("      - nbytes: %d" % bt["nbytes"])
            lines.append("        operator: %s" % yaml_quote(bt["operator"]))
            lines.append("        value: %d" % bt["value"])
            lines.append("        offset: %d" % bt["offset"])
            lines.append("        relative: %s" % ("true" if bt["relative"] else "false"))
            lines.append("        big_endian: %s" % ("true" if bt["big_endian"] else "false"))
            lines.append("        string: %s" % ("true" if bt["string"] else "false"))
            lines.append("        base: %s" % bt["base"])
            lines.append("        no_case: %s" % ("true" if bt["no_case"] else "false"))
    if rule.get("flow"):
        f = rule["flow"]
        lines.append("    flow:")
        for k in ("established", "to_client", "to_server", "stateless"):
            if f.get(k):
                lines.append("      %s: true" % k)
    if rule.get("flowbits"):
        lines.append("    flowbits:")
        for op in rule["flowbits"]:
            lines.append("      - op: %s" % op["op"])
            lines.append("        flag: %s" % yaml_quote(op["flag"]))
    if rule.get("private"):
        lines.append("    private: true")
    return lines


# ---------------------------------------------------------------------------
# Suricata parsing helpers
# ---------------------------------------------------------------------------

def split_options(body: str):
    """Split the option list on ';' outside double quotes.

    Quote tracking is key-aware: inside a pcre option the pattern is enclosed
    in '/.../' and may itself contain '"' (e.g. ["']) and '/' inside character
    classes (e.g. [A-Za-z0-9+/]), neither of which may close the option value.
    pcre_state: 0=not started, 1=in /pattern/, 2=in trailing flags."""
    parts, cur, in_quote, escaped, key = [], [], False, False, None
    pcre_state, in_class = 0, False
    for ch in body:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == "\\":
            cur.append(ch)
            escaped = True
            continue
        if in_quote:
            cur.append(ch)
            if key == "pcre":
                if pcre_state == 0:
                    if ch == "/":
                        pcre_state, in_class = 1, False
                    elif ch == '"':
                        in_quote = False
                elif pcre_state == 1:
                    if in_class:
                        if ch == "]":
                            in_class = False
                        # '[' inside a class is a literal char; everything else literal
                    elif ch == "[":
                        in_class = True
                    elif ch == "/":
                        pcre_state = 2
                    elif ch == '"':
                        in_quote = False
                elif ch == '"':
                    in_quote = False
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            cur.append(ch)
            continue
        if ch == ";":
            parts.append("".join(cur))
            cur, key, in_quote, escaped = [], None, False, False
            pcre_state, in_class = 0, False
            continue
        cur.append(ch)
        if key is None and ch == ":":
            k = "".join(cur).strip().lower()
            if k.endswith(":"):
                key = k[:-1]
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def parse_ip_list(token: str):
    """Return (any, addresses, cidrs). $vars/negations/groups-with-negs -> any."""
    token = token.strip()
    if token == "any" or token.startswith("$"):
        return True, [], []
    if token.startswith("!"):
        return True, [], []
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]
    addresses, cidrs = [], []
    for item in token.split(","):
        item = item.strip()
        if not item or item == "any" or item.startswith("$") or item.startswith("!"):
            return True, [], []
        if "/" in item:
            cidrs.append(item)
        elif re.match(r"^[\d.]+$|^[0-9a-fA-F:]+$", item):
            addresses.append(item)
        else:
            # IP ranges like 1.2.3.4-1.2.3.10, hostnames, etc -> can't map
            return True, [], []
    if not addresses and not cidrs:
        return True, [], []
    return False, addresses, cidrs


def parse_port_list(token: str):
    """Return (any, ports, ranges). $vars/negations -> any."""
    token = token.strip()
    if token == "any" or token.startswith("$") or token.startswith("!"):
        return True, [], []
    if token.startswith("[") and token.endswith("]"):
        token = token[1:-1]
    ports, ranges = [], []
    for item in token.split(","):
        item = item.strip()
        if not item or item == "any" or item.startswith("$") or item.startswith("!"):
            return True, [], []
        if ":" in item:
            low, _, high = item.partition(":")
            try:
                a = int(low) if low else 0
                b = int(high) if high else 65535
            except ValueError:
                return True, [], []
            ranges.append((a, b))
        else:
            try:
                ports.append(int(item))
            except ValueError:
                return True, [], []
    if not ports and not ranges:
        return True, [], []
    return False, ports, ranges


IP_PROTO_MAP = {
    "tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "ipv6-icmp": 58,
    "igmp": 2, "ggp": 3, "ipv4": 4, "st": 5, "egp": 8, "igp": 9,
    "gre": 47, "esp": 50, "ah": 51, "sctp": 132, "dccp": 33,
}


def parse_ip_proto(value: str):
    """ip_proto:N -> int or None. Accepts numbers and common protocol names."""
    v = value.strip()
    try:
        return int(v, 0)
    except ValueError:
        return IP_PROTO_MAP.get(v.lower())


def parse_dsize(value: str):
    """dsize:!?N | dsize:>N | dsize:<N | dsize:min:max[:mod:offset] -> dict or None."""
    v = value.strip()
    if v.startswith("!"):
        return None  # negated size cannot be expressed
    m = {}
    if v.startswith(">"):
        # Suricata 'dsize:>N' means size > N (strict); SDK min is inclusive.
        try:
            m["min"] = int(v[1:]) + 1
            return m
        except ValueError:
            return None
    if v.startswith("<"):
        # Suricata 'dsize:<N' means size < N (strict); SDK max is inclusive.
        try:
            m["max"] = int(v[1:]) - 1
            return m
        except ValueError:
            return None
    parts = v.split(":")
    try:
        if len(parts) == 1:
            m["exact"] = int(parts[0])
        elif len(parts) == 2:
            m["min"] = int(parts[0])
            m["max"] = int(parts[1])
        elif len(parts) == 4:
            m["min"] = int(parts[0])
            m["max"] = int(parts[1])
            m["mod_divisor"] = int(parts[2])
            m["mod_offset"] = int(parts[3])
        else:
            return None
    except ValueError:
        return None
    return m


def _int_base(value: str, radix: int):
    """Parse int honoring 0x/0o/0b prefixes (Suricata allows them regardless of
    the base modifier), otherwise parse in the given radix."""
    s = value.strip()
    try:
        if s.lower().startswith(("0x", "0o", "0b")):
            return int(s, 0)
        return int(s, radix)
    except ValueError:
        return None


def parse_byte_test(value: str):
    """byte_test:bytes_to_convert,operator,value,offset[,mods...] -> dict or None."""
    v = value.strip().strip('"')
    parts = v.split(",")
    if len(parts) < 4:
        return None
    try:
        nbytes = int(parts[0])
        operator = parts[1]
    except ValueError:
        return None
    mods = set(p.strip().lower() for p in parts[4:] if p.strip())
    base = "dec"
    if "hex" in mods:
        base = "hex"
    elif "oct" in mods:
        base = "oct"
    radix = 16 if base == "hex" else 8 if base == "oct" else 10
    value_num = _int_base(parts[2], radix)
    offset = _int_base(parts[3], radix)
    if value_num is None or offset is None:
        return None  # variable offsets (e.g. from isdataat) not expressible
    if nbytes not in (1, 2, 4, 8):
        nbytes = 1
    return {
        "nbytes": nbytes,
        "operator": operator,
        "value": value_num,
        "offset": offset,
        "relative": "relative" in mods,
        "big_endian": "little" not in mods,
        "string": "string" in mods,
        "base": base,
        "no_case": "no_case" in mods,
    }


def parse_flow(value: str):
    """flow:established,to_client,to_server,stateless,... -> dict or None."""
    mods = set(v.strip().lower() for v in value.split(","))
    m = {}
    if "established" in mods:
        m["established"] = True
    if "to_client" in mods:
        m["to_client"] = True
    if "to_server" in mods:
        m["to_server"] = True
    if "stateless" in mods:
        m["stateless"] = True
    return m or None


def parse_flowbits(value: str):
    """flowbits:op,flag[,flag...] -> (noalert, ops list)."""
    parts = [p.strip() for p in value.split(",")]
    op = parts[0].lower()
    flags = [p for p in parts[1:] if p]
    if op == "noalert":
        return True, []
    if op not in ("set", "unset", "isset", "isnotset", "toggle"):
        return False, []
    ops = [{"op": op, "flag": f} for f in flags]
    return False, ops


def decode_content(value: str):
    """Decode a Suricata content pattern (ascii + |hex| segments) to raw bytes.
    Hex groups may be multi-byte, e.g. |2822| == 0x28 0x22."""
    pattern = bytearray()
    i, n = 0, len(value)
    while i < n:
        if value[i] == "|":
            j = value.find("|", i + 1)
            if j == -1:
                return None
            hexpart = "".join(value[i + 1:j].split())
            if not hexpart or len(hexpart) % 2 != 0:
                return None
            for k in range(0, len(hexpart), 2):
                try:
                    pattern.append(int(hexpart[k:k + 2], 16))
                except ValueError:
                    return None
            i = j + 1
        else:
            j = value.find("|", i)
            seg = value[i:] if j == -1 else value[i:j]
            pattern.extend(seg.encode("latin-1", errors="replace"))
            i = n if j == -1 else j
    return bytes(pattern)


def parse_content(value: str):
    """Return (raw_bytes, negated) for a content:value."""
    v = value.strip()
    negated = False
    if v.startswith("!"):
        negated = True
        v = v[1:].strip()
    if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
        v = v[1:-1]
    raw = decode_content(v)
    return raw, negated


def parse_pcre(value: str):
    """Return (regex_pattern, case_insensitive) for a pcre:/pattern/flags."""
    v = value.strip()
    if len(v) >= 2 and v.startswith('"') and v.endswith('"'):
        v = v[1:-1]
    if not v.startswith("/"):
        return None, False
    last = v.rfind("/")
    if last <= 0:
        return None, False
    pattern = v[1:last].replace("\\/", "/")
    flags = v[last + 1:]
    return pattern, "i" in flags


def lossy(text: bytes) -> str:
    return text.decode("utf-8", errors="replace")


def bytes_to_hex(data: bytes) -> str:
    """Serialize raw Suricata content bytes without converting them to text."""
    return data.hex(" ").upper()


# ---------------------------------------------------------------------------
# Rule conversion
# ---------------------------------------------------------------------------

def convert_line(line: str, rule_index: int = 0):
    lp = line.find("(")
    rp = line.rfind(")")
    if lp == -1 or rp == -1 or rp < lp:
        stats["skipped_header"] += 1
        return None
    header = line[:lp].strip()
    body = line[lp + 1:rp]

    tokens = re.split(r"\s+", header)
    if len(tokens) != 7:
        stats["skipped_header"] += 1
        return None

    action, proto, src_ip_tok, src_port_tok, direction, dst_ip_tok, dst_port_tok = tokens
    if direction not in ("->", "<>"):
        stats["skipped_header"] += 1
        return None

    rule_action = ACTION_MAP.get(action)
    if rule_action is None:
        stats["skipped_action"] += 1
        return None

    protocol = PROTO_MAP.get(proto)

    any_src_ip, src_ips, src_cidrs = parse_ip_list(src_ip_tok)
    any_dst_ip, dst_ips, dst_cidrs = parse_ip_list(dst_ip_tok)
    any_src_port, src_ports, src_ranges = parse_port_list(src_port_tok)
    any_dst_port, dst_ports, dst_ranges = parse_port_list(dst_port_tok)

    description = ""
    sid = None
    severity = None
    domains = []
    domain_case_insensitive = False
    regex_terms = []
    ip_proto = None
    dsize = None
    byte_tests = []
    flow = None
    flowbits_ops = []
    noalert = False

    contents = []  # list of (raw, negated, modifiers_set, positional_dict)
    pcres = []     # list of (pattern, ci)
    current = None
    # Suricata "sticky buffer" keywords (dotted names: http.request_line,
    # http.header, http.request_body, dns.query, tls.sni, file.data, ...)
    # SELECT which buffer subsequent content/pcre terms match against, and
    # stay active until another sticky buffer keyword (or pkt_data/file_data
    # reset) appears. They normally appear BEFORE the content(s) they apply
    # to, so they must be remembered and applied at content-creation time,
    # not just attached to whatever content happened to precede them.
    sticky_buffer = set()

    for opt_raw in split_options(body):
        opt = opt_raw.strip()
        if not opt:
            continue
        if ":" not in opt:
            if opt == "pkt_data":
                # Explicit reset back to the raw packet/payload buffer.
                sticky_buffer = set()
                continue
            if "." in opt or opt == "file_data":
                # Sticky buffer selector: applies going forward, and also
                # to the immediately preceding content if one is already
                # open (covers rules that mix legacy post-modifiers with a
                # sticky buffer on the same content).
                sticky_buffer = {opt}
                if current is not None:
                    current[2].add(opt)
            else:
                # Legacy per-content modifier (nocase, startswith, endswith,
                # fast_pattern, http_uri, http_host, dns_query, ...):
                # applies only to the content it directly follows.
                if current is not None:
                    current[2].add(opt)
            continue
        key, _, value = opt.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "content":
            raw, negated = parse_content(value)
            if raw is None:
                stats["dropped_bad_content"] += 1
                current = None
                continue
            current = [raw, negated, set(sticky_buffer), {}]
            contents.append(current)
        elif key in ("offset", "depth", "within", "distance"):
            if current is not None:
                try:
                    current[3][key] = int(value)
                except ValueError:
                    pass
        elif key == "pcre":
            pat, ci = parse_pcre(value)
            if pat is None:
                continue
            pcres.append((pat, ci))
        elif key == "msg":
            description = value
            if len(description) >= 2 and description.startswith('"') and description.endswith('"'):
                description = description[1:-1]
            description = description.encode("utf-8", errors="replace").decode("utf-8")
        elif key == "sid":
            try:
                sid = int(value)
            except ValueError:
                pass
        elif key == "ip_proto":
            parsed = parse_ip_proto(value)
            if parsed is not None:
                ip_proto = parsed
        elif key == "dsize":
            parsed = parse_dsize(value)
            if parsed is not None:
                dsize = parsed
        elif key == "byte_test":
            parsed = parse_byte_test(value)
            if parsed is not None:
                byte_tests.append(parsed)
        elif key == "flow":
            parsed = parse_flow(value)
            if parsed is not None:
                flow = parsed
        elif key == "flowbits":
            noalert_fb, ops = parse_flowbits(value)
            if noalert_fb:
                noalert = True
            flowbits_ops.extend(ops)
        elif key == "metadata":
            # Extract EmergingThreats `signature_severity` from metadata:
            # metadata:..., signature_severity Informational, ... (case-insensitive)
            m = re.search(
                r"\bsignature_severity\s+([A-Za-z]+)",
                value,
                flags=re.IGNORECASE,
            )
            if m:
                severity = m.group(1).lower()
        else:
            # classtype, reference, metadata, threshold, etc.
            continue

    # Dispatch contents. Suricata `content:` stays byte-native.
    content_patterns = []
    for raw, negated, mods, pos in contents:
        lower_mods = {m.lower() for m in mods}
        if negated:
            stats["dropped_negated"] += 1
            continue

        if lower_mods & HOST_MODIFIERS:
            domains.append(lossy(raw))
            if "nocase" in lower_mods:
                domain_case_insensitive = True
            continue

        item = {
            "hex": bytes_to_hex(raw),
            "case_insensitive": "nocase" in lower_mods,
        }
        for key in ("offset", "depth", "within", "distance"):
            if key in pos:
                item[key] = pos[key]
        if "startswith" in lower_mods:
            item["startswith"] = True
        if "endswith" in lower_mods:
            item["endswith"] = True

        content_patterns.append(item)
        stats["content_patterns"] += 1

    regex_terms = []
    if pcres:
        regex_terms = [({"pattern": pat, "case_insensitive": ci}) for pat, ci in pcres]
        stats["pcre_rules"] += 1

    has_matchers = bool(domains or content_patterns or regex_terms or src_ports or src_ranges
                        or dst_ports or dst_ranges or src_ips or src_cidrs
                        or dst_ips or dst_cidrs
                        or ip_proto is not None or dsize is not None
                        or byte_tests or flow is not None or flowbits_ops)
    if not has_matchers:
        stats["no_matchers"] += 1

    rule = {
        "name": "sid:%d" % sid if sid is not None else None,
        "description": description,
        "action": rule_action,
        "domain": None,
        "contents": None,
        "regex": None,
        "enabled": sid not in DISABLED_SIDS,
    }
    if severity is not None:
        rule["severity"] = severity
    if rule["name"] is None:
        rule["name"] = "rule:%d" % rule_index
    if protocol:
        rule["protocol"] = protocol
    if not any_src_ip and (src_ips or src_cidrs):
        rule["src_ip"] = {"addresses": src_ips, "cidr_ranges": src_cidrs}
    if not any_dst_ip and (dst_ips or dst_cidrs):
        rule["dst_ip"] = {"addresses": dst_ips, "cidr_ranges": dst_cidrs}
    if not any_src_port and (src_ports or src_ranges):
        rule["src_port"] = {"ports": src_ports, "ranges": src_ranges}
    if not any_dst_port and (dst_ports or dst_ranges):
        rule["dst_port"] = {"ports": dst_ports, "ranges": dst_ranges}
    if domains:
        rule["domain"] = {"domains": domains, "case_insensitive": domain_case_insensitive}
    if content_patterns:
        rule["contents"] = content_patterns
    if regex_terms:
        rule["regex"] = regex_terms[0]
    if ip_proto is not None:
        rule["ip_proto"] = ip_proto
    if dsize is not None:
        rule["dsize"] = dsize
    if byte_tests:
        rule["byte_test"] = byte_tests
    if flow is not None:
        rule["flow"] = flow
    if flowbits_ops:
        rule["flowbits"] = flowbits_ops
    if noalert:
        rule["private"] = True

    return rule


def main():
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT

    print("Source: %s" % input_path)
    print("Output: %s" % output_path)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    out_lines = [
        "# Generated by convert_emerging_rules.py from %s" % input_path.name,
        "# Source: EmergingThreats Suricata ruleset. Best-effort conversion;",
        "# binary/hex payload patterns only match if they survive the SDK's lossy decode.",
        "rules:",
    ]

    rule_count = 0
    with open(input_path, "r", encoding="utf-8", errors="replace") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            stats["lines"] += 1
            if not line or line.startswith("#"):
                continue
            rule = convert_line(line, rule_count)
            if rule is None:
                continue
            out_lines += emit_rule(rule)
            rule_count += 1

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(out_lines) + "\n")

    print("\nConverted rules written: %d" % rule_count)
    print("Total lines read: %d" % stats["lines"])
    for key in ("skipped_header", "skipped_action", "dropped_negated",
                "dropped_bad_content", "no_matchers", "content_patterns",
                "pcre_rules", "overridden"):
        if stats[key]:
            print("  %s: %d" % (key, stats[key]))

    size = output_path.stat().st_size
    print("Output size: %.1f MB" % (size / (1024 * 1024)))


if __name__ == "__main__":
    main()
