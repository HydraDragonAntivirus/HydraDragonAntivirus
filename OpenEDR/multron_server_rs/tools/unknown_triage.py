"""Triage the files a multron_server keeps in a category folder (default: unknown).

    python unknown_triage.py C:\\viruskov_archive
    python unknown_triage.py C:\\viruskov_archive --category suspicious --out triage.csv

Reads multron_incoming\\<category>\\** (files named <SHA-256>_<name>), the telemetry
(threat_insights.jsonl: signer, folders, engine detections) and the human verdicts
(analyst_signatures\\human_verdicts.jsonl), and writes a CSV with one row per file
that has no completed human verdict: a group, a suggested verdict and the facts behind
it. Nothing is written to the server's data: the analyst decides.

Groups (first that applies):
  1  engine signatures matched                               review
  1v file-infector structure (the Virus.Generic.Appender rules)  malicious
  2b signed, but by a PUA / bundler publisher or a look-alike name  review
  2  trusted Authenticode / catalog signature                clean
  3  known non-executable data format                         clean
  3b unknown / no extension / .bin (not MZ)                   review
  4  script / shortcut / archive / installer                  review
  4b document / html / container (may hold active content)    review
  4c named .exe/.dll but not a PE                             review
  5  PE signed but not trusted                                review
  6  unsigned PE in a user-writable folder                    review
  7  unsigned PE in Windows / Program Files                   review
  8  unsigned PE, location unknown                            review
Big files are read only in part (headers, the last section), so a run over tens of
thousands of files takes minutes, not hours.
"""
import argparse
import collections
import csv
import json
import math
import os
import struct
import sys

SCRIPT = {'.js', '.mjs', '.cjs', '.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.bat', '.cmd', '.py', '.pyw', '.hta', '.wsf',
          '.jse', '.lnk', '.sh', '.jar', '.msi', '.msix', '.appx', '.scr', '.reg', '.inf', '.au3', '.sct'}
DOCS = {'.html', '.htm', '.svg', '.xhtml', '.chm', '.pdf', '.doc', '.docx', '.docm', '.xls', '.xlsx', '.xlsm', '.rtf', '.one',
        '.iso', '.img', '.vhd', '.url', '.mht'}
PE_EXT = {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.efi', '.com'}
DATA = {'.ini', '.package', '.qm', '.lng', '.json', '.pak', '.lang', '.nsh', '.srt', '.cat', '.po', '.rcc', '.mui', '.txt', '.xml',
        '.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp', '.webp', '.svgz', '.ttf', '.otf', '.woff', '.woff2', '.mo', '.pot', '.css',
        '.map', '.md', '.log', '.cfg', '.conf', '.toml', '.csv', '.dat', '.db', '.sqlite', '.manifest', '.mf', '.properties', '.pyi',
        '.pyc', '.h', '.c', '.cpp', '.hpp', '.lib', '.a', '.pdb', '.nls', '.tlb', '.winmd', '.etl', '.evtx', '.wav', '.mp3', '.ogg',
        '.mp4', '.dic', '.aff', '.sbi', '.cvd', '.cld', '.ndb', '.hdb', '.ldb', '.sig', '.store', '.locale', '.resx', '.resources',
        '.xaml', '.res', '.icns', '.dmp'}
# Publishers whose signed files are bundlers / PUA, and a look-alike of IObit.
PUA_PUBLISHERS = ('lobit', 'driver information technology', 'orange view', 'innovative connecting', 'fortect', 'nielsen',
                  'digital wave', 'iobit')
USER_DIRS = ('downloads', '\\temp', 'appdata', 'desktop', 'documents', '%temp%', 'onedrive')


def sha_lines(path, wanted):
    """Last JSON object per SHA-256 in `wanted` from an append-only .jsonl (merged for insights)."""
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, 'rb') as fh:
        for line in fh:
            i = line.find(b'"sha256":"')
            if i < 0:
                continue
            s = line[i + 10:i + 74].decode('ascii', 'replace').lower()
            if s in wanted:
                try:
                    out.setdefault(s, []).append(json.loads(line))
                except ValueError:
                    pass
    return out


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def infector(path):
    """The Virus.Generic.Appender structure: (rule, detail) or None."""
    try:
        with open(path, 'rb') as fh:
            h = fh.read(4096)
            if h[:2] != b'MZ':
                return None
            pe = struct.unpack_from('<I', h, 0x3c)[0]
            if pe > 3900 or h[pe:pe + 4] != b'PE\0\0':
                return None
            ns = struct.unpack_from('<H', h, pe + 6)[0]
            opt = struct.unpack_from('<H', h, pe + 20)[0]
            is64 = struct.unpack_from('<H', h, pe + 24)[0] == 0x20b
            ep = struct.unpack_from('<I', h, pe + 40)[0]
            dd = pe + 24 + (112 if is64 else 96)
            dirs = [struct.unpack_from('<II', h, dd + 8 * k) for k in range(15)]
            o = pe + 24 + opt + 40 * (ns - 1)
            if ns == 0 or o + 40 > len(h):
                return None
            name = h[o:o + 8].split(b'\0')[0].decode('latin1')
            vs, va, rs, rp = struct.unpack_from('<IIII', h, o + 8)
            ch = struct.unpack_from('<I', h, o + 36)[0]
            if rs < 32768:
                return None
            fh.seek(rp)
            e = entropy(fh.read(rs))
    except (OSError, struct.error):
        return None
    size = max(vs, rs)
    inside = [k for k, (a, s) in enumerate(dirs) if s and va <= a < va + size]
    rwx = ch & 0x80000000 and ch & 0x20000000
    code = ch & 0x20
    share = sum(dirs[k][1] for k in inside if k in (1, 3, 5)) / size
    if 5 in inside and not code and e >= 7.8:
        return 'RELOC', f'{name} {rs // 1024} KB entropy {e:.2f}, relocations inside'
    if va <= ep < va + size and rwx and e >= 7.8:
        return 'EP', f'{name} RWX entropy {e:.2f}, entry point inside'
    if rwx and not va <= ep < va + size and e >= 7.6 and rs >= 262144 and 0 not in inside:
        return 'RWX', f'{name} RWX {rs // 1024} KB entropy {e:.2f}, entry point elsewhere'
    if any(k in (1, 3, 5) for k in inside) and not code and e >= 7.8 and rs >= 262144 and share <= 0.12 and 0 not in inside:
        return 'DIR', f'{name} {rs // 1024} KB entropy {e:.2f}, small host table + encrypted body'
    if ch & 0x80000000 and not ch & 0x20000000 and not code and not inside and rs >= 614400 and e >= 7.9:
        return 'DATA', f'{name} {rs // 1024} KB entropy {e:.2f}, nothing points inside'
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('archive', help='server folder (holds multron_incoming, threat_insights.jsonl)')
    ap.add_argument('--category', default='unknown')
    ap.add_argument('--out', default=None, help='CSV path (default: <archive>/reports/<category>_triage.csv)')
    a = ap.parse_args()

    base = os.path.join(a.archive, 'multron_incoming', a.category)
    files = {}
    for root, _, names in os.walk(base):
        for n in names:
            s = n[:64].lower()
            if len(s) == 64 and all(c in '0123456789abcdef' for c in s):
                files[s] = (os.path.join(root, n), n[65:], os.path.basename(root))
    print(f'{len(files)} files in {base}', file=sys.stderr)

    ins = {}
    for s, lines in sha_lines(os.path.join(a.archive, 'threat_insights.jsonl'), files).items():
        m = {}
        for j in lines:
            m.update({k: v for k, v in j.items() if v not in (None, [], {})})
        ins[s] = m
    hum = {s: v[-1] for s, v in sha_lines(os.path.join(a.archive, 'analyst_signatures', 'human_verdicts.jsonl'), files).items()}

    rows, count = [], collections.Counter()
    for s, (p, name, typ) in files.items():
        h = hum.get(s, {})
        if h.get('status') == 'completed' and not h.get('deleted'):
            continue
        j = ins.get(s, {})
        sg = j.get('signer') or {}
        trusted = sg.get('trusted') or sg.get('catalog') or sg.get('status') in ('trusted', 'catalog')
        publisher = sg.get('name') or ''
        try:
            with open(p, 'rb') as fh:
                head = fh.read(4)
        except OSError:
            head = b''
        ext = os.path.splitext(name.strip())[1].lower()
        folders = ';'.join(j.get('folders', []))[:300]
        fl = folders.lower()
        pe = head[:2] == b'MZ'
        det = j.get('detections') or []
        inf = infector(p) if pe else None
        if inf:
            g, v, why = '1v file-infector structure (' + inf[0] + ')', 'malicious', inf[1]
        elif det:
            g, v, why = '1 engine signatures matched', 'review', ''
        elif trusted and any(b in publisher.lower() for b in PUA_PUBLISHERS):
            g, v, why = '2b signed: PUA / bundler publisher or look-alike', 'review', ''
        elif trusted:
            g, v, why = '2 signed: trusted Authenticode / catalog', 'clean', ''
        elif not pe and ext in DOCS:
            g, v, why = '4b document / html / container', 'review', ''
        elif not pe and ext in PE_EXT:
            g, v, why = '4c PE name but not a PE file', 'review', ''
        elif not pe and ext in DATA:
            g, v, why = '3 data: known non-executable format', 'clean', ''
        elif ext in SCRIPT or head.startswith(b'PK'):
            g, v, why = '4 script / shortcut / archive / installer', 'review', ''
        elif not pe and not head.startswith(b'\x7fELF'):
            g, v, why = '3b data: unknown / no extension / .bin', 'review', ''
        elif pe and sg.get('signed'):
            g, v, why = '5 PE: signed but not trusted', 'review', ''
        elif pe and any(u in fl for u in USER_DIRS):
            g, v, why = '6 PE: unsigned, user-writable folder', 'review', ''
        elif pe and ('%windir%' in fl or 'program files' in fl or '%programfiles' in fl):
            g, v, why = '7 PE: unsigned, Windows / Program Files', 'review', ''
        elif pe:
            g, v, why = '8 PE: unsigned, location unknown', 'review', ''
        else:
            g, v, why = '9 other executable (ELF etc.)', 'review', ''
        count[(g, v)] += 1
        rows.append([g, v, s, name, typ, j.get('file_size', ''), sg.get('status', ''), publisher, folders,
                     ';'.join(map(str, det))[:200], why, h.get('status', '')])

    out = a.out or os.path.join(a.archive, 'reports', f'{a.category}_triage.csv')
    os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
    with open(out, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(['group', 'suggested', 'sha256', 'file_name', 'clamav_type', 'size', 'signer_status', 'signer', 'folders',
                    'detections', 'why', 'queue'])
        w.writerows(sorted(rows))
    for (g, v), n in sorted(count.items()):
        print(f'{n:6}  {v:9}  {g}')
    print(f'{len(rows)} open files -> {out}')


if __name__ == '__main__':
    main()
