import re

def fix_regex_braces(regex_body):
    result = []
    i = 0
    while i < len(regex_body):
        ch = regex_body[i]
        if ch == '\\':
            result.append(ch)
            if i + 1 < len(regex_body):
                result.append(regex_body[i+1])
                i += 2
            else:
                i += 1
        elif ch == '{':
            m = re.match(r'\{(\d+)(,\d*)?}', regex_body[i:])
            if m:
                result.append(regex_body[i:i+len(m.group(0))])
                i += len(m.group(0))
            else:
                result.append('\\{')
                i += 1
        elif ch == '}':
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

tests = [
    ('{default}', '\\{default\\}'),
    ('{1,20}', '{1,20}'),
    ('{0,512}', '{0,512}'),
    (r'\{default\}', r'\{default\}'),
    ('{unconstrained:true}', '\\{unconstrained:true\\}'),
    ('.{1,20}@', '.{1,20}@'),
    (r'if ?\(\$_POST\[Submit\]\) ?{', r'if ?\(\$_POST\[Submit\]\) ?\{'),
]
ok = True
for inp, expected in tests:
    got = fix_regex_braces(inp)
    status = 'OK' if got == expected else 'FAIL'
    if status == 'FAIL':
        ok = False
    print(f'{status}: {inp!r} -> {got!r} (expected {expected!r})')
print('All OK' if ok else 'SOME FAILED')
