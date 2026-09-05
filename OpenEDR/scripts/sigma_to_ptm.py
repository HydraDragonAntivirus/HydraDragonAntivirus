# -*- coding: utf-8 -*-
"""
General Sigma -> OpenEDR PTM converter.

Reads inspired_rules/rules/sigma/builtin/** (minus deprecated/unsupported/
placeholder), converts mappable rules into ptm.local.src pattern blocks and
reports per-reason skip counts. Idempotent (refuses to run twice).

Proven building blocks only (verified against the policy compiler source
and shipped policies):
  - ops: and/or/not(single-arg)/imatch with compiler anchor modes
    (*v*=contains, v*=startswith, *v=endswith, v=exact)
  - fields: childProcess.*, process.imageFile.*, process.parent.imageFile.*,
    file.*, registry.*, connection.remote.port (unused: no IP field proven)
  - eventTypes: LLE_PROCESS_CREATE / LLE_FILE_CREATE / LLE_REGISTRY_KEY_CREATE /
    LLE_REGISTRY_VALUE_SET / LLE_NETWORK_CONNECT_OUT / LLE_NETWORK_CONNECT_IN

Soundness policy (fail-safe direction):
  - AND child unmappable  -> whole AND unmappable (never broaden).
  - OR child unmappable   -> dropped (narrows = miss, never FP).
  - NOT child unmappable  -> whole construct unmappable.
  - tautology (Channel, consistent EventID) -> dropped silently.
  - top-level True (match-all) or False (dead) -> rule skipped.
  - Sigma re/base64*/cidr/fieldref/wide values, int/bool/None/dict values
    (except EventID routing), empty strings -> value skipped.
  - `windash` values -> original + dash-flipped variant (ORed).
  - quarantineTarget only for level critical/high (godmode precedent);
    medium/low/informational -> alert-only.

Usage:
  python OpenEDR/scripts/sigma_to_ptm.py
"""
import fnmatch
import glob
import json
import os
import re
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILTIN = os.path.normpath(os.path.join(REPO, '..', 'inspired_rules', 'rules',
                                         'sigma', 'builtin'))
PTM = os.path.join(REPO, 'edrav2', 'iprj', 'edrdata', 'ptm.local.src')
SKIP_DIRS = {'deprecated', 'unsupported', 'placeholder'}

T = '\t'

MLE = {
    'process': ('MLE_SIGMA_PROCESS', 1000017),
    'registry': ('MLE_SIGMA_REGISTRY', 1000018),
    'script': ('MLE_SIGMA_SCRIPT', 1000019),
    'network': ('MLE_SIGMA_NETWORK', 1000020),
}
MLE_CONST_BLOCK = 'sigmaEventBaseType'

CHILD_IMG = ['@event.childProcess.imagePath',
             '@event.childProcess.imageFile.abstractPath',
             '@event.childProcess.imageFile.rawPath']
PARENT_IMG = ['@event.process.imageFile.abstractPath',
              '@event.process.imageFile.rawPath']
GRANDPARENT_IMG = ['@event.process.parent.imageFile.abstractPath',
                   '@event.process.parent.imageFile.rawPath']
PROC_IMG = ['@event.process.imageFile.abstractPath',
            '@event.process.imageFile.rawPath']

PROCESS_FIELDS = {
    'NewProcessName': CHILD_IMG,
    'ProcessName': CHILD_IMG,
    'CommandLine': ['@event.childProcess.cmdLine',
                    '@event.childProcess.scriptContent'],
    'OriginalFileName': 'ENDSWITH_BASENAME',
    'ParentProcessName': PARENT_IMG,
}
REGISTRY_FIELDS = {
    'ObjectName': ['@event.registry.abstractPath', '@event.registry.rawPath'],
    'TargetObject': ['@event.registry.abstractPath', '@event.registry.rawPath'],
    'NewValue': ['@event.registry.data'],
    'Details': ['@event.registry.data'],
    'ProcessName': PROC_IMG,
    'Image': PROC_IMG,
}
SCRIPT_FIELDS = {
    'ScriptBlockText': ['@event.childProcess.scriptContent'],
}
NETWORK_FIELDS = {
    'ImagePath': PROC_IMG,
    'Application': PROC_IMG,
    'ParentImage': GRANDPARENT_IMG,
}

# Sigma audit DWORD text ("DWORD (0x00000001)") never matches the engine's
# decimal string form ("1"); normalize bare exact values so they can fire.
_DWORD_RE = re.compile(r'DWORD\s*\(\s*0[xX]([0-9A-Fa-f]+)\s*\)')


class Unmappable(Exception):
    pass


def to_pattern(value, anchor):
    s = value.lower()
    if '*' in s or '?' in s:
        return s
    if anchor == 'contains':
        return '*' + s + '*'
    if anchor == 'startswith':
        return s + '*'
    if anchor == 'endswith':
        return '*' + s
    return s


def flip_dash(s):
    return ''.join('/' if c == '-' else '-' if c == '/' else c for c in s)


def im_leaf(field, pattern):
    return ('{\n'
            + T * 8 + '"$operation": "imatch",\n'
            + T * 8 + '"pattern": %s,\n' % json.dumps(pattern, ensure_ascii=False)
            + T * 8 + '"args": [ "%s" ]\n' % field
            + T * 7 + '}')


def and_node(children):
    flat = [c for c in children if c is not True]
    if any(c is False for c in children):
        return False
    if not flat:
        return True
    if len(flat) == 1:
        return flat[0]
    return ('{\n' + T * 6 + '"$operation": "and",\n' + T * 6 + '"args": [\n'
            + (',\n').join(T * 7 + x for x in flat)
            + '\n' + T * 6 + ']\n' + T * 5 + '}')


def or_node(children):
    flat = [c for c in children if c is not False]
    if any(c is True for c in children):
        return True
    if not flat:
        return False
    if len(flat) == 1:
        return flat[0]
    return ('{\n' + T * 6 + '"$operation": "or",\n' + T * 6 + '"args": [\n'
            + (',\n').join(T * 7 + x for x in flat)
            + '\n' + T * 6 + ']\n' + T * 5 + '}')


def not_node(child):
    if child is True:
        return False
    if child is False:
        return True
    return ('{\n' + T * 6 + '"$operation": "not",\n' + T * 6 + '"args": [\n'
            + T * 7 + child + '\n' + T * 6 + ']\n' + T * 5 + '}')


def field_condition(base, mods, values, field_table):
    if base in ('EventID', 'Channel'):
        return True
    if base == '':
        raise Unmappable('empty-field-name')
    anchor, is_all, windash = 'exact', False, False
    for m in mods:
        if m in ('contains', 'startswith', 'endswith'):
            anchor = m
        elif m == 'all':
            is_all = True
        elif m == 'windash':
            windash = True
        else:
            raise Unmappable('unsupported-modifier:' + m)
    paths = field_table.get(base)
    if paths is None:
        raise Unmappable('unsupported-field:' + base)
    if not isinstance(values, list):
        values = [values]
    per_value = []
    for v in values:
        if isinstance(v, (bool, dict)) or v is None or isinstance(v, int):
            continue
        s = str(v)
        if s == '':
            continue
        if base in ('NewValue', 'Details') and anchor == 'exact':
            sl = s.strip().lower()
            if sl in ('(empty)', 'binary data'):
                continue
            m = _DWORD_RE.fullmatch(s.strip())
            if m:
                s = str(int(m.group(1), 16))
        if base == 'OriginalFileName':
            pats = ['*\\' + s.lower()]
            flds = CHILD_IMG[:2]
        else:
            pats = [to_pattern(s, anchor)]
            if windash:
                f = flip_dash(pats[0])
                if f != pats[0]:
                    pats.append(f)
            flds = paths
        node = or_node([im_leaf(f, p) for f in flds for p in pats])
        if node is not False:
            per_value.append(node)
    if not per_value:
        return False
    return and_node(per_value) if is_all else or_node(per_value)


def selection_node(sel, field_table):
    if isinstance(sel, list):
        # OR of variants: drop unmappable branches (narrows = safe).
        kids = []
        for s in sel:
            try:
                kids.append(selection_node(s, field_table))
            except Unmappable:
                pass
        return or_node(kids)
    if not isinstance(sel, dict):
        raise Unmappable('bad-selection-shape')
    kids = []
    for fk, fv in sel.items():
        parts = str(fk).split('|')
        kids.append(field_condition(parts[0], tuple(parts[1:]), fv, field_table))
    return and_node(kids)


TOKEN_RE = re.compile(r'\(|\)|(?:\d+|all)\s+of\s+[^\s()]+|[^\s()]+',
                        re.IGNORECASE)


def parse_condition(cond, groups):
    toks = TOKEN_RE.findall(cond)
    pos = [0]

    def peek():
        return toks[pos[0]].lower() if pos[0] < len(toks) else ''

    def nxt():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def names_for(pat):
        if pat.lower() == 'them':
            return list(groups.keys())
        found = [k for k in groups.keys() if fnmatch.fnmatchcase(k, pat)]
        if not found:
            raise Unmappable('dangling-ref:' + pat)
        return found

    def parse_or():
        node = parse_and()
        while peek() == 'or':
            nxt()
            node = or_node([node, parse_and()])
        return node

    def parse_and():
        node = parse_unary()
        while peek() == 'and':
            nxt()
            node = and_node([node, parse_unary()])
        return node

    def parse_unary():
        if peek() == 'not':
            nxt()
            return not_node(parse_unary())
        return parse_primary()

    def parse_primary():
        if peek() == '(':
            nxt()
            node = parse_or()
            if peek() != ')':
                raise Unmappable('bad-parens')
            nxt()
            return node
        t = nxt()
        m = re.match(r'(\d+|all)\s+of\s+(\S+)', t, re.IGNORECASE)
        if m:
            names = names_for(m.group(2))
            if m.group(1).lower() == '1':
                return or_node([groups[k] for k in names]) if names else False
            return and_node([groups[k] for k in names]) if names else True
        if t.lower() == 'them':
            return or_node([groups[k] for k in groups.keys()])
        if t not in groups:
            raise Unmappable('dangling-ref:' + t)
        return groups[t]

    node = parse_or()
    if pos[0] != len(toks):
        raise Unmappable('trailing-tokens')
    return node


def strip_routing(sel, family):
    """Drop routing/noise keys; network Direction handled by caller."""
    if isinstance(sel, list):
        return [strip_routing(s, family) for s in sel]
    if not isinstance(sel, dict):
        return sel
    drop = {'EventID', 'Channel'}
    if family == 'network':
        drop = drop | {'Direction'}
    return {k: v for k, v in sel.items() if str(k).split('|')[0] not in drop}


def route(logs, det):
    cat = (logs.get('category') or '').lower()
    evids = set()

    def collect(sel):
        if isinstance(sel, list):
            for s in sel:
                collect(s)
        elif isinstance(sel, dict):
            for fk, fv in sel.items():
                if str(fk).split('|')[0] == 'EventID':
                    vv = fv if isinstance(fv, list) else [fv]
                    for e in vv:
                        evids.add(str(e))

    for k, v in det.items():
        if k in ('condition', 'timeframe', 'aggregation'):
            continue
        collect(v)
    if 'aggregation' in det or 'timeframe' in det:
        return None, 'aggregation'
    if cat == 'process_creation':
        if evids and evids != {'4688'}:
            return None, 'eventid-mismatch'
        return ('process', ['LLE_PROCESS_CREATE'], PROCESS_FIELDS), None
    if cat in ('registry_set', 'registry_add'):
        if evids and not evids <= {'4657'}:
            return None, 'eventid-mismatch'
        return ('registry', ['LLE_REGISTRY_KEY_CREATE', 'LLE_REGISTRY_VALUE_SET'],
                REGISTRY_FIELDS), None
    if cat == 'registry_event':
        evs = []
        for e in (evids or {'12', '13'}):
            if e == '12':
                evs.append('LLE_REGISTRY_KEY_CREATE')
            elif e == '13':
                evs.append('LLE_REGISTRY_VALUE_SET')
            else:
                return None, 'eventid-mismatch'
        return ('registry', sorted(set(evs)), REGISTRY_FIELDS), None
    if cat == 'ps_script':
        if evids and evids != {'4104'}:
            return None, 'eventid-mismatch'
        return ('script', ['LLE_PROCESS_CREATE'], SCRIPT_FIELDS), None
    if cat == 'network_connection':
        return ('network', ['OUT'], NETWORK_FIELDS), None
    return None, 'unsupported-logsource:%s' % (cat or '-')


def network_directions(det):
    dirs = set()
    for k, v in det.items():
        if k in ('condition', 'timeframe', 'aggregation'):
            continue
        sels = v if isinstance(v, list) else [v]
        for s in sels:
            if isinstance(s, dict) and 'Direction' in s:
                dv = s['Direction']
                for x in (dv if isinstance(dv, list) else [dv]):
                    if str(x) == '%%14593':
                        dirs.add('OUT')
                    elif str(x) == '%%14592':
                        dirs.add('IN')
    return sorted(dirs) or ['OUT']


def build_object(event_type, cond, meta, quarantine):
    q = meta['qtarget']
    L = []
    A = L.append
    A(T * 2 + '{')
    A(T * 3 + '"eventType": "%s",' % event_type)
    A(T * 3 + '"rule": {')
    A(T * 4 + '"condition": %s,' % cond)
    A(T * 4 + '"createEvent": {')
    A(T * 5 + '"eventType": "%s",' % meta['mle'])
    A(T * 5 + '"destination": "OUT",')
    A(T * 5 + '"clone": false,')
    A(T * 5 + '"data": [')
    A(T * 6 + '{ "name": "baseType", "value": "@const.%s.%s" },'
      % (MLE_CONST_BLOCK, meta['mle']))
    A(T * 6 + '{ "name": "process", "value": "%s" },' % meta['procfield'])
    A(T * 6 + '{ "name": "processes", "value": "@event.processes" },')
    A(T * 6 + '{ "name": "time", "value": "@event.time" },')
    A(T * 6 + '{ "name": "tickTime", "value": "@event.tickTime" },')
    if quarantine:
        A(T * 6 + '{ "name": "quarantineTarget", "value": "%s" },' % q)
    trust = 'false' if quarantine else 'true'
    A(T * 6 + '{ "name": "should_trust_company_whitelist", "value": %s },' % trust)
    A(T * 6 + '{ "name": "should_trust_comodo_fls_cloud", "value": %s }' % trust)
    A(T * 5 + ']')
    A(T * 4 + '}')
    A(T * 3 + '}')
    A(T * 2 + '}')
    return '\n'.join(L)


def main():
    files = [f for f in glob.glob(BUILTIN + '/**/*.yml', recursive=True)
             if not any(('/%s/' % d) in f.replace('\\', '/') for d in SKIP_DIRS)]
    skips = {}
    converted = 0
    per_family = {}
    out_blocks = {}
    leaf_total = [0]

    for f in sorted(files):
        try:
            docs = [d for d in yaml.safe_load_all(open(f, encoding='utf-8')) if d]
        except Exception:
            skips['yaml-parse-fail'] = skips.get('yaml-parse-fail', 0) + 1
            continue
        for d in docs:
            if not isinstance(d, dict):
                skips['non-dict-doc'] = skips.get('non-dict-doc', 0) + 1
                continue
            if str(d.get('status', '')).lower() == 'deprecated':
                skips['status-deprecated'] = skips.get('status-deprecated', 0) + 1
                continue
            det = d.get('detection') or {}
            if not isinstance(det, dict):
                skips['no-detection'] = skips.get('no-detection', 0) + 1
                continue
            routed, why = route(d.get('logsource') or {}, det)
            if routed is None:
                skips[why] = skips.get(why, 0) + 1
                continue
            family, evts, ftable = routed
            groups = {}
            bad = None
            for k, v in det.items():
                if k in ('condition', 'timeframe', 'aggregation'):
                    continue
                if not isinstance(k, str):
                    bad = 'non-string-group-key'
                    break
                try:
                    groups[k] = selection_node(strip_routing(v, family), ftable)
                except Unmappable as e:
                    bad = 'selection:%s' % e
                    break
            if bad:
                skips[bad] = skips.get(bad, 0) + 1
                continue
            cond_src = det.get('condition', '')
            if cond_src is None:
                cond_src = ''
            cond_src = str(cond_src)
            if cond_src.strip() in ('', '-'):
                if any(k.lower().startswith('filter') for k in groups):
                    skips['implicit-cond-with-filters'] = skips.get(
                        'implicit-cond-with-filters', 0) + 1
                    continue
                node = and_node(list(groups.values()))
            else:
                try:
                    node = parse_condition(cond_src, groups)
                except Unmappable as e:
                    skips['condition:%s' % e] = skips.get('condition:%s' % e, 0) + 1
                    continue
            if node is True:
                skips['match-all'] = skips.get('match-all', 0) + 1
                continue
            if node is False:
                skips['dead-rule'] = skips.get('dead-rule', 0) + 1
                continue
            if family == 'network':
                ev_list = ['LLE_NETWORK_CONNECT_OUT' if dd == 'OUT'
                           else 'LLE_NETWORK_CONNECT_IN'
                           for dd in network_directions(det)]
            else:
                ev_list = list(evts)
            level = str(d.get('level', 'medium')).lower()
            quarantine = level in ('critical', 'high')
            mle, _mleid = MLE[family]
            sid = str(d.get('id', os.path.basename(f)))
            title = str(d.get('title', sid)).replace('\n', ' ')[:170]
            meta = {'mle': mle,
                    'qtarget': ('@event.childProcess.imagePath'
                                if family in ('process', 'script')
                                else '@event.process.imageFile.abstractPath'),
                    'procfield': ('@event.childProcess'
                                  if family in ('process', 'script')
                                  else '@event.process')}
            comment = T * 3 + '// SIGMA %s [%s] %s' % (sid, level, title)
            for ev in ev_list:
                out_blocks.setdefault(family, []).append(
                    comment + '\n' + build_object(ev, node, meta, quarantine))
            converted += 1
            per_family[family] = per_family.get(family, 0) + 1
            if isinstance(node, str):
                leaf_total[0] += node.count('imatch')

    print('files: %d converted rules: %d' % (len(files), converted))
    print('per family:', per_family)
    print('imatch leaves:', leaf_total[0])
    print('== skips ==')
    for k in sorted(skips, key=lambda x: -skips[x])[:35]:
        print(' %5d %s' % (skips[k], k))

    if not any(out_blocks.values()):
        print('nothing to emit')
        return

    t = open(PTM, encoding='utf-8').read()
    for fam in out_blocks:
        marker = '"SIGMA_%s": [' % fam.upper()
        assert marker not in t, 'already inserted: ' + fam
    # --- constants: sigmaEventBaseType next to the other *EventBaseType blocks
    mle_entries = []
    for fam in ['process', 'registry', 'script', 'network']:
        if fam in out_blocks:
            name, num = MLE[fam]
            mle_entries.append((name, num))
    const_anchors = ['"MLE_GODMODE_ACTIVITY": 1000016\n\t\t}',
                     '"MLE_PUA_REGISTRY_WRITE": 1000015\n\t\t}']
    const_anchor = next((a for a in const_anchors if a in t), None)
    assert const_anchor is not None, 'const anchor missing'
    const_block = (',\n' + T * 2 + '"%s": {\n' % MLE_CONST_BLOCK
                   + ',\n'.join(T * 3 + '"%s": %d' % (n, i) for n, i in mle_entries)
                   + '\n' + T * 2 + '}')
    t = t.replace(const_anchor, const_anchor + const_block, 1)
    # --- common.src MLE registration (same IDs) ---
    cpath = os.path.join(REPO, 'edrav2', 'iprj', 'edrdata', 'common.src')
    c = open(cpath, encoding='utf-8').read()
    for name, num in mle_entries:
        assert '"%s"' % name not in c, 'common already has ' + name
    reg_anchors = ['"MLE_GODMODE_ACTIVITY": 1000016',
                   '"MLE_PUA_REGISTRY_WRITE": 1000015',
                   '"MLE_PROCESS_INJECTION_TAMPERING": 1000014']
    reg_anchor = next((a for a in reg_anchors if a in c), None)
    assert reg_anchor is not None, 'common base anchor missing'
    c = c.replace(reg_anchor, reg_anchor + ''.join(
        ',\n\t\t\t"%s": %d' % (n, i) for n, i in mle_entries), 1)
    types_anchor = None
    for cand in ['"MLE_GODMODE_ACTIVITY",', '"MLE_PUA_REGISTRY_WRITE",',
                 '"MLE_PROCESS_INJECTION_TAMPERING",']:
        if cand in c:
            types_anchor = cand
            break
    assert types_anchor is not None, 'common types anchor missing'
    c = c.replace(types_anchor, types_anchor + ''.join(
        '\n\t\t\t"%s",' % n for n, i in mle_entries), 1)
    open(cpath, 'w', encoding='utf-8').write(c)
    print('common.src registered:', [n for n, i in mle_entries])
    tail = t.rstrip()
    assert tail.endswith('\t}\n}'), repr(tail[-20:])
    fam_order = ['process', 'registry', 'script', 'network']
    blocks = []
    for fam in fam_order:
        if fam not in out_blocks:
            continue
        blocks.append(T * 2 + '"SIGMA_%s": [\n' % fam.upper()
                      + (',\n').join(out_blocks[fam])
                      + '\n' + T * 2 + ']')
    t = tail[: -len('\t}\n}')] + ',\n' + ',\n'.join(blocks) + '\n\t}\n}\n'
    open(PTM, 'w', encoding='utf-8').write(t)
    print('inserted %d families, new size %d' % (len(blocks), len(t)))
    print('MLE families used:', sorted(out_blocks.keys()))


if __name__ == '__main__':
    main()
