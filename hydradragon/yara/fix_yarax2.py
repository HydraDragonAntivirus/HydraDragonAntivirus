"""
Fix clean_rules.yar for yara-x compatibility.

Strategy for regex fixes:
- Find all /regex/ string literals in YARA rules
- Inside each regex, escape { and } that are NOT part of valid quantifiers {n}, {n,}, {n,m}
- Also fix specific known issues
"""
import re

path = 'hydradragon/yara/clean_rules.yar'

with open(path, 'r', encoding='utf-8-sig') as f:
    content = f.read()

fixes = []

# Fix 1: pe.exports("Crash") & pe.characteristics  (E002 wrong type)
old = 'pe.exports("Crash") & pe.characteristics'
new = 'pe.exports("Crash") and (pe.characteristics & 0xFFFF) != 0'
n = content.count(old)
if n:
    content = content.replace(old, new)
    fixes.append(f'pe.exports & characteristics: {n}')

# Fix 2: @mz[0] -> @mz[1]  (E007 number out of range)
old = '$pe in (@mz[0]..0x200)'
new = '$pe in (@mz[1]..0x200)'
n = content.count(old)
if n:
    content = content.replace(old, new)
    fixes.append(f'@mz[0] -> @mz[1]: {n}')

# Fix 3: Undefined rule identifiers used in conditions  (E009)
undefined_ids = ['ApacheModule', 'ObfuscatedPhp', 'PasswordProtection',
                  'DodgyPhp', 'DangerousPhp', 'isRTF']
for ident in undefined_ids:
    # Match as standalone identifier (not inside strings or comments)
    pattern = r'(?<!["\'/\w])' + re.escape(ident) + r'(?!["\'\w])'
    matches = re.findall(pattern, content)
    if matches:
        content = re.sub(pattern, 'false', content)
        fixes.append(f'{ident} -> false: {len(matches)}')

# Fix 4: any of (file_*) wildcard rule reference not supported in yara-x  (E001)
n = len(re.findall(r'\bany of \(file_\*\)', content))
if n:
    content = re.sub(r'\bany of \(file_\*\)', 'false', content)
    fixes.append(f'any of (file_*) -> false: {n}')

# Fix 5: Regex strings - escape { } that are NOT valid quantifiers
# Valid quantifiers: {n}, {n,}, {n,m} where n,m are digits
# We need to escape { that are NOT followed by digits+}
# and } that are NOT preceded by digits (closing a quantifier)

def fix_regex_braces(regex_body):
    """
    In a regex body, escape { and } that are not part of valid quantifiers.
    Valid quantifier forms: {n}, {n,}, {n,m}
    Also escape { that are not part of any quantifier.
    """
    result = []
    i = 0
    while i < len(regex_body):
        ch = regex_body[i]
        if ch == '\\':
            # Already escaped, keep as-is (consume next char too)
            result.append(ch)
            if i + 1 < len(regex_body):
                result.append(regex_body[i+1])
                i += 2
            else:
                i += 1
        elif ch == '{':
            # Check if this is a valid quantifier {n}, {n,}, {n,m}
            m = re.match(r'\{(\d+)(,\d*)?}', regex_body[i:])
            if m:
                # Valid quantifier, keep as-is
                result.append(regex_body[i:i+len(m.group(0))])
                i += len(m.group(0))
            else:
                # Not a quantifier, escape it
                result.append('\\{')
                i += 1
        elif ch == '}':
            # Check if this closes a quantifier we kept
            # Simple heuristic: if not preceded by digits/comma, escape it
            # Look back in result for {digits...
            prev = ''.join(result[-10:]) if len(result) >= 10 else ''.join(result)
            if re.search(r'\{\d+(,\d*)?\Z', prev):
                result.append('}')
            else:
                result.append('\\}')
            i += 1
        else:
            result.append(ch)
            i += 1
    return ''.join(result)


def fix_yara_regex_strings(text):
    """
    Find all /regex/ patterns in YARA rule strings sections and fix braces.
    Only fixes regex strings (delimited by /), not hex strings or plain strings.
    """
    # Match regex strings: = /.../ with optional modifiers
    # Need to be careful not to match inside comments or string values
    regex_count = 0

    def replace_regex(m):
        nonlocal regex_count
        prefix = m.group(1)   # = /
        body = m.group(2)     # regex body
        suffix = m.group(3)   # / + modifiers
        fixed = fix_regex_braces(body)
        if fixed != body:
            regex_count += 1
        return prefix + fixed + suffix

    # Pattern: assignment = /body/ optionally followed by modifiers
    # Use a non-greedy match, avoid matching across newlines carelessly
    result = re.sub(
        r'(=\s*/)((?:[^/\\]|\\.)*?)(/(?:nocase|ascii|wide|fullword|\s)*)',
        replace_regex,
        text
    )
    return result, regex_count


content, rx_count = fix_yara_regex_strings(content)
if rx_count:
    fixes.append(f'regex brace escaping in {rx_count} regex strings')

print('Fixes applied:')
for f_item in fixes:
    print(' -', f_item)

with open(path, 'w', encoding='utf-8', newline='') as f:
    f.write(content)
print('Saved.')
