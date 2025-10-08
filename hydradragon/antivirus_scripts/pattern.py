import re

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
telegram_pattern_standard = (
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
    # IPv4
    octet = r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
    ipv4_standard = r'\b(?:(?:' + octet + r')\.){3}(?:' + octet + r')\b'
    ipv4_nonstandard = r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}'
    ipv4_base64 = r'[A-Za-z0-9+/]{8,24}={0,2}'
    ipv4_base32 = r'[A-Z2-7]{8,40}={0,6}'
    ipv4_reversed_like = r'\b[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'

    IPv4_pattern = r'|'.join([
        ipv4_standard,
        ipv4_nonstandard,
        ipv4_base64,
        ipv4_base32,
        ipv4_reversed_like,
    ])

    # IPv6
    h16 = r'[0-9a-fA-F]{1,4}'
    full_ipv6 = r'\b(?:' + h16 + r':){7}' + h16 + r'\b'
    compressed_leading = r'::(?:' + h16 + r':){0,6}' + h16
    compressed_trailing = r'(?:' + h16 + r':){1,7}::'
    various_compressed = r'(?:' + h16 + r':){1,6}:' + h16
    flexible = r'[0-9a-fA-F:]{15,39}'
    ipv6_base64 = r'[A-Za-z0-9+/]{16,64}={0,2}'
    ipv6_base32 = r'[A-Z2-7]{16,64}={0,6}'
    reversed_compressed_leading = r'::(?:[Ff][A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{1,4}'
    reversed_compressed_trailing = r'(?:[A-Fa-f0-9]{1,4}:){1,7}::'

    IPv6_pattern = r'|'.join([
        full_ipv6,
        compressed_leading,
        compressed_trailing,
        various_compressed,
        flexible,
        ipv6_base64,
        ipv6_base32,
        reversed_compressed_leading,
        reversed_compressed_trailing,
    ])

    return [
        (IPv4_pattern, 'IPv4'),
        (IPv6_pattern, 'IPv6'),
    ]
