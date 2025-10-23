#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import base64

# IPv4 patterns (standard and all variations)
IPv4_pattern_standard = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

# IPv6 patterns (standard and all variations)
IPv6_pattern_standard = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}::'

# Discord webhook patterns (normal, reversed, base64, base32, reversed base64)
discord_webhook_pattern = (
    r'https://discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3Mv[A-Za-z0-9+/]+'
    r'|/skoohbew/ipa/moc\.drocsid//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q='
    r'|=Q4G6X4O35X6SHIHDT4IH2BEPD3YWQZNJDI4WXFNCDIKGZFNCDIKGF2MT4OGXFNUL6SHAQUEEVS33SGW5NDDIKGZFNCDIKGZFMT4TKXXBN'
    r'|=m9vaG9ibmVifaXBhL21vYy5kcm9jc2lkLy86c3B0dGhh[A-Za-z0-9+/]+'
)

# Discord attachment patterns (normal, reversed, base64, base32, reversed base64)
discord_attachment_pattern = (
    r'https://cdn\.discordapp\.com/attachments/[0-9]+/[0-9]+/[A-Za-z0-9_.-]+'
    r'|aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMv[A-Za-z0-9+/]+'
    r'|/stnemhcatta/moc\.ppadrocsid\.ndc//:sptth'
    r'|NBXXK4TFMNQWWZLDMN2GKIDCNFZGKIDBNR4XAYLTORSW45DFON2C4ZDPNRXXEZJAMFZGC4TUORUW4ZY='
    r'|=YZ4WUROUTCGZFMAJZEXRRNPDZ4C2NOFD54WSROSOLTYA4XRNBDIKGZFNCDIKGZ2MDLZWWQNMFT4KXXBN'
    r'|=c3RuZW1oY2F0dGEvbW9jLnBwYWRyb2NzaWQubmRjLy86c3B0dGhh[A-Za-z0-9+/]+'
)

# Discord Canary webhook patterns (normal, reversed, base64, base32, reversed base64)
discord_canary_webhook_pattern = (
    r'https://canary\.discord\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
    r'|aHR0cHM6Ly9jYW5hcnkuZGlzY29yZC5jb20vYXBpL3dlYmhvb2tzL[A-Za-z0-9+/]+'
    r'|/skoohbew/ipa/moc\.drocsid\.yranac//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64TJNF2GS4DFOQQGC3DJMRZXIZJ5'
    r'|5JZIXZRMJD3CGQOFD4SG2FNJT46G6X4O35X6SHIHDT4IH2BEPD3YWQZNJDI4WXFNCDIKGZFNCDIKGZFMT4OGXFNUL6SHAQUEEVS33SGW5NDDIKGZFNCDIKGZFMT4TKXXBN'
    r'|=c2tob29oYmV3L2lwaS9tb2MuZHJvY3NpZC55cmFuYWMvLzpzcHR0aGE[A-Za-z0-9+/]+'
)

# CDN attachment patterns (normal, reversed, base64, base32)
cdn_attachment_pattern = re.compile(
    r'https://(?:cdn\.discordapp\.com|media\.discordapp\.net)/attachments/\d+/\d+/[A-Za-z0-9_\-\.%]+(?:\?size=\d+)?'
    r'|aHR0cHM6Ly9jZG4uZGlzY29yZGFwcC5jb20vYXR0YWNobWVudHMv[A-Za-z0-9+/]+'
    r'|aHR0cHM6Ly9tZWRpYS5kaXNjb3JkYXBwLm5ldC9hdHRhY2htZW50cy8=[A-Za-z0-9+/]*'
    r'|/stnemhcatta/moc\.ppadrocsid\.ndc//:sptth'
    r'|/stnemhcatta/ten\.ppadrocsid\.aidem//:sptth'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q=[A-Z2-7]*'
    r'|NBXXK4TFMFZGKIDCNFZGKIDDN5WGS33VEAQHS6LUNFXGO4TFMF2GKIDCNFZGKIDCNFXW4IDJNZQWY3DPEB2HI4DTHIXS653XO4XG64Q=[A-Z2-7]*'
)

# Telegram token patterns (normal, reversed, base64, base32)
telegram_token_pattern = (
    r'\d{9,10}:[A-Za-z0-9_-]{35}'
    r'|[A-Za-z0-9_-]{35}:\d{9,10}'
    r'|[A-Za-z0-9+/]{35}:\d{9,10}[A-Za-z0-9+/]*={0,2}'
    r'|\d{9,10}:[A-Za-z0-9+/]{35}={0,2}'
    r'|[A-Z2-7]{35}:\d{9,10}[A-Z2-7]*={0,6}'
    r'|\d{9,10}:[A-Z2-7]{35}={0,6}'
)

# Telegram keyword patterns (normal, reversed, base64, base32)
telegram_keyword_pattern = (
    r'\b(?:telegram|token)\b'
    r'|dGVsZWdyYW0=|dG9rZW4='
    r'|bWFyZ2VsZXQ=|bmVrb3Q='
    r'|ORSXG5DJNZTSA===|ORZXIZLB'
    r'|===ASTZNDJD5GXSRO|BLIZXRO'
    r'|margelet|nekot'
)

# Discord webhook (standard)
discord_webhook_pattern_standard = r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'

# Discord attachment (standard)
discord_attachment_pattern_standard = r'https://cdn\.discord\.com/api/attachments/\d+/[A-Za-z0-9_-]+'

# Discord Canary webhook (standard)
discord_canary_webhook_pattern_standard = r'https://canary\.discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+'

# Discord CDN attachments (standard)
cdn_attachment_pattern_standard = re.compile(
    r'https://(?:cdn\.discordapp\.com|media\.discordapp\.net)/attachments/\d+/\d+/[A-Za-z0-9_\-\.%]+(?:\?size=\d+)?'
)

# Telegram bot (standard)
telegram_token_pattern_standard = (
    r'https?://api\.telegram\.org/bot\d{9,10}:[A-Za-z0-9_-]{35}'
    r'|\b\d{9,10}:[A-Za-z0-9_-]{35}\b'
)

# UBlock regex (improved with more variations)
UBLOCK_REGEX = re.compile(
    r'^https:\/\/s[cftz]y?[ace][aemnu][a-z]{1,4}o[mn][a-z]{4,8}[iy][a-z]?\.com\/$'
    r'|^aHR0cHM6Ly9z[A-Za-z0-9+/]*o[A-Za-z0-9+/]*\.Y29t[A-Za-z0-9+/]*={0,2}$'
    r'|^\/moc\.[a-z]*[yi][a-z]{4,8}[nm]o[a-z]{1,4}[une][eca][a-z]?y?[zftc]s\/\/:sptth$'
)

# Pattern for a single zip-based join obfuscation (chr((x-y)%128) generator)
ZIP_JOIN = re.compile(
    r'''(?:""?|''?)(?:\w*\.)?join\(\s*\(chr\(\(x\s*-\s*y\)\s*%\s*128\)\s*for\s*x\s*,\s*y\s*in\s*zip\(\s*(\[[^\]]*\])\s*,\s*(\[[^\]]*\])\s*\)\)\)''',
    re.DOTALL
)

# Pattern for chained .join calls: literal.join(...).join(...)
CHAINED_JOIN = re.compile(
    r"(\(['\"][^'\"]*['\"]\))\.(?:join\([^)]*\))+"
)

# Pattern for base64 literals inside b64decode
B64_LITERAL = re.compile(r"base64\.b64decode\(\s*(['\"])([A-Za-z0-9+/=]+)\1\s*\)")

# Module-level regexes
EMAIL_RE = re.compile(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', re.IGNORECASE)
# Stricter/anchored version for verification
EMAIL_FULLMATCH_RE = re.compile(r'^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$', re.IGNORECASE)

# --------------------------------------------------------------------------
# Helpers for decoding regex fragments
def _dec(b64: str) -> str:
    """Decode Base64-encoded ASCII/UTF-8 text fragments (robust to missing padding)."""
    # add padding if needed
    pad = (-len(b64)) % 4
    try:
        return base64.b64decode(b64 + ('=' * pad)).decode("utf-8", errors="replace")
    except Exception:
        return ""  # fail gracefully

def _dec32(b32: str) -> str:
    """Decode Base32-encoded ASCII/UTF-8 text fragments (robust to missing padding)."""
    pad = (-len(b32)) % 8
    try:
        return base64.b32decode(b32.upper() + ('=' * pad)).decode("utf-8", errors="replace")
    except Exception:
        return ""  # fail gracefully


def build_url_regex():
    parts = [
        # Normal protocols
        r'https?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'ftp://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Obfuscated protocols (hxxps://, hxxp://, fxp://)
        r'hxxps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'fxp://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # X-obfuscated protocols (more variations)
        r'h[tx]{2}ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'f[tx]p://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Bracket-obfuscated domains (e.g., example[.]com, test[dot]com)
        r'https?://[^\s<>"\'{}|\\^`\[\]]*\[(?:\.|dot)\][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'hxxps?://[^\s<>"\'{}|\\^`\[\]]*\[(?:\.|dot)\][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
        r'h[tx]{2}ps?://[^\s<>"\'{}|\\^`\[\]]*\[(?:\.|dot)\][^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Specific bracket patterns for domains
        r'[a-zA-Z0-9-]+\[(?:\.|dot)\][a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',
        r'[a-zA-Z0-9-]+\(\.\)[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',
        r'[a-zA-Z0-9-]+\{(?:\.|dot)\}[a-zA-Z0-9.-]*[a-zA-Z]{2,}(?:/[^\s]*)?',

        # Base64-obfuscated protocols
        _dec("aHR0cHM6Ly8") + r"[A-Za-z0-9+/]*={0,2}",   # https://
        _dec("aHR0cDovL") + r"[A-Za-z0-9+/]*={0,2}",    # http://
        _dec("ZnRwOi8v") + r"[A-Za-z0-9+/]*={0,2}",     # ftp://

        # Reversed/obfuscated
        r'//:[a-z]{4,5}sptth',
        r'//:[a-z]{4}ptth',
        r'//:[a-z]{3}ptf',

        # Base32 obfuscations — DECODED USING _dec32 (escaped for safe regex insertion)
        re.escape(_dec32("NBXXK4TFMFZGKIDCNFZGKIDDOJSWCZ3P")) + r'[A-Z2-7]*={0,6}',
        re.escape(_dec32("NBXXK4TFMFZGKIDCMJUWC2LP")) + r'[A-Z2-7]*={0,6}',
        re.escape(_dec32("MZXW6IDCMFZWK4Q=")) + r'[A-Z2-7]*={0,6}',

        # Additional obfuscation patterns
        r'h\*\*ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',  # h**ps://
        r'ht\*ps?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',   # ht*ps://
        r'htt\*s?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',   # htt*s://

        # Protocol with underscores
        r'h_t_t_p_s?://[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',

        # Spaced protocols
        r'h\s*t\s*t\s*p\s*s?\s*:\s*/\s*/[^\s<>"\'{}|\\^`\[\]]*[^\s<>"\'{}|\\^`\[\].,;:]',
    ]
    return re.compile(r'|'.join(parts), re.IGNORECASE)

# --------------------------------------------------------------------------
# Build IPv4/IPv6 regex at runtime
def build_ip_patterns():
    """
    Returns (patterns_list, find_ips) where:
      - patterns_list is [(compiled_regex, 'IPv4'|'IPv6'), ...] (backwards-compatible)
      - find_ips(text) scans text for plain + obfuscated IPs, decodes when possible,
        and returns a list of match dicts:
          {'type': 'IPv4'|'IPv6',
           'value': '1.2.3.4' or '2001:db8::1',
           'span': (start,end),
           'source': 'plain'|'base64'|'base32'|'reversed',
           'original_fragment': matched_fragment}
    """
    # IPv4/IPv6 building blocks
    octet = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv4_standard = r'\b(?:(?:' + octet + r')\.){3}(?:' + octet + r')\b'
    ipv4_nonstandard = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    # keep a compact IPv4 matcher for decoded content searches (no word-boundary to catch mid-string)
    ipv4_inner = r'(?:(?:' + octet + r')\.){3}(?:' + octet + r')'

    h16 = r'[0-9a-fA-F]{1,4}'
    full_ipv6 = r'\b(?:' + h16 + r':){7}' + h16 + r'\b'
    compressed_leading = r'::(?:' + h16 + r':){0,6}' + h16
    compressed_trailing = r'(?:' + h16 + r':){1,7}::'
    various_compressed = r'(?:' + h16 + r':){1,6}:' + h16
    flexible = r'[0-9a-fA-F:]{15,39}'
    ipv6_inner = r'(?:' + h16 + r':){1,7}' + h16 + r'|' + r'[0-9a-fA-F:]{15,39}'

    IPv4_pattern = r'|'.join([ipv4_standard, ipv4_nonstandard])
    IPv6_pattern = r'|'.join([full_ipv6, compressed_leading, compressed_trailing, various_compressed, flexible])

    compiled_ipv4 = re.compile(IPv4_pattern)
    compiled_ipv6 = re.compile(IPv6_pattern, re.IGNORECASE)

    # patterns for finding encoded candidate blobs (we will attempt to decode them then search inside)
    base64_candidate = re.compile(r'([A-Za-z0-9+/]{8,64}={0,2})')
    base32_candidate = re.compile(r'([A-Z2-7]{8,64}={0,6})')

    # helper: search for plain matches (returns dicts)
    def _collect_plain(text):
        results = []
        for m in compiled_ipv4.finditer(text):
            results.append({'type': 'IPv4', 'value': m.group(0), 'span': m.span(), 'source': 'plain', 'original_fragment': m.group(0)})
        for m in compiled_ipv6.finditer(text):
            results.append({'type': 'IPv6', 'value': m.group(0), 'span': m.span(), 'source': 'plain', 'original_fragment': m.group(0)})
        return results

    # helper: attempt decode of base64/base32 candidate and search inside decoded text
    def _collect_from_encoded(text):
        results = []

        # base64 candidates
        for m in base64_candidate.finditer(text):
            frag = m.group(1)
            dec = _dec(frag)
            if not dec:
                continue
            # look for IPv4/IPv6 inside decoded
            for im in re.finditer(ipv4_inner, dec):
                results.append({'type': 'IPv4', 'value': im.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'base64', 'original_fragment': frag})
            for im in re.finditer(ipv6_inner, dec, re.IGNORECASE):
                results.append({'type': 'IPv6', 'value': im.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'base64', 'original_fragment': frag})

        # base32 candidates
        for m in base32_candidate.finditer(text):
            frag = m.group(1)
            dec = _dec32(frag)
            if not dec:
                continue
            for im in re.finditer(ipv4_inner, dec):
                results.append({'type': 'IPv4', 'value': im.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'base32', 'original_fragment': frag})
            for im in re.finditer(ipv6_inner, dec, re.IGNORECASE):
                results.append({'type': 'IPv6', 'value': im.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'base32', 'original_fragment': frag})

        return results

    # helper: reversed strings (e.g., '1.2.3.4' reversed inside text, or 'http' reversed etc)
    def _collect_from_reversed(text):
        results = []
        # we will search for likely reversed substrings containing digits and dots/colons,
        # reverse them and test for IPs.
        reversed_candidates = re.finditer(r'([0-9\.\:\-\/_=A-Za-z+]{6,80})', text)
        for m in reversed_candidates:
            frag = m.group(1)
            rev = frag[::-1]
            # quick check: does reversed fragment contain an IPv4 or IPv6?
            ipv4_match = re.search(ipv4_inner, rev)
            ipv6_match = re.search(ipv6_inner, rev, re.IGNORECASE)
            if ipv4_match:
                results.append({'type': 'IPv4', 'value': ipv4_match.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'reversed', 'original_fragment': frag})
            if ipv6_match:
                results.append({'type': 'IPv6', 'value': ipv6_match.group(0), 'span': (m.start(1), m.end(1)),
                                'source': 'reversed', 'original_fragment': frag})
        return results

    # public function: find_ips(text)
    def find_ips(text):
        """
        Scan text for plain and obfuscated IPs.
        Returns list of dicts (see docstring above).
        """
        found = []
        # 1) Plain matches
        found.extend(_collect_plain(text))

        # 2) Encoded (base64/base32)
        try:
            found.extend(_collect_from_encoded(text))
        except Exception:
            # fail gracefully if decoding internals throw
            pass

        # 3) Reversed / simple reversed-like obfuscations
        try:
            found.extend(_collect_from_reversed(text))
        except Exception:
            pass

        # deduplicate by (type,value,source,original_fragment) keeping earliest span
        seen = {}
        deduped = []
        for item in found:
            key = (item['type'], item['value'], item['source'], item.get('original_fragment'))
            if key not in seen or item['span'][0] < seen[key]:
                seen[key] = item['span'][0]
                # replace to keep earliest (we'll rebuild after loop)
        # build unique list preserving earliest occurrence
        unique_keys = sorted(seen.items(), key=lambda kv: kv[1])
        for k, _ in unique_keys:
            typ, val, src, orig = k
            # find first matching item to get full dict (span)
            for item in found:
                if item['type'] == typ and item['value'] == val and item['source'] == src and item.get('original_fragment') == orig:
                    deduped.append(item)
                    break

        return deduped

    # maintain backwards-compatible return (list of tuples) but also provide the helper
    patterns_list = [(re.compile(IPv4_pattern), 'IPv4'), (re.compile(IPv6_pattern, re.IGNORECASE), 'IPv6')]
    return patterns_list, find_ips
