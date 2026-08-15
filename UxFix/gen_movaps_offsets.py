from capstone import *
import struct

path = r'C:\Windows\System32\ntdll.dll'
b = open(path, 'rb').read()
e_lfanew = struct.unpack_from('<I', b, 0x3C)[0]
nsec = struct.unpack_from('<H', b, e_lfanew + 6)[0]
opt = e_lfanew + 24
imgbase = struct.unpack_from('<Q', b, opt + 24)[0]
size_opt = struct.unpack_from('<H', b, e_lfanew + 20)[0]
sec = opt + size_opt
sections = {}
for i in range(nsec):
    va = struct.unpack_from('<I', b, sec + i*40 + 12)[0]
    vsz = struct.unpack_from('<I', b, sec + i*40 + 8)[0]
    raw = struct.unpack_from('<I', b, sec + i*40 + 20)[0]
    rsiz = struct.unpack_from('<I', b, sec + i*40 + 16)[0]
    name = b[sec + i*40 : sec + i*40 + 8].rstrip(b'\0').decode()
    sections[name] = (va, vsz, raw, rsiz)

def rva2off(rva):
    for name, (va, vsz, raw, rsiz) in sections.items():
        if va <= rva < va + max(vsz, rsiz):
            return raw + (rva - va)
    return None

def off2rva(off):
    for name, (va, vsz, raw, rsiz) in sections.items():
        if raw <= off < raw + rsiz:
            return va + (off - raw)
    return None

# exports
eoff = rva2off(struct.unpack_from('<I', b, opt + 112)[0])  # ExportDirectory RVA
nfuncs = struct.unpack_from('<I', b, eoff + 20)[0]
addrfun = rva2off(struct.unpack_from('<I', b, eoff + 28)[0])
exports = []
for i in range(nfuncs):
    fnrva = struct.unpack_from('<I', b, addrfun + i*4)[0]
    if fnrva:
        exports.append(fnrva)

# pdata
pva, pvsz, praw, prsiz = sections['.pdata']
ncnt = prsiz // 12
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
movaps = set()

def scan_range(rva_start, rva_end):
    if rva_end <= rva_start or rva_start >= 0x170000:
        return
    off = rva2off(rva_start)
    if off is None:
        return
    data = b[off : off + (rva_end - rva_start)]
    for ins in md.disasm(data, imgbase + rva_start):
        if ins.mnemonic == 'movaps':
            fo = off + (ins.address - (imgbase + rva_start))
            movaps.add(fo)

funcs = set()
for i in range(ncnt):
    ba = struct.unpack_from('<I', b, praw + i*12)[0]
    ea = struct.unpack_from('<I', b, praw + i*12 + 4)[0]
    if ba and ea > ba:
        funcs.add((ba, ea))
        scan_range(ba, ea)

for e in exports:
    funcs.add((e, e + 0x1000))

# sort, merge overlapping
fl = sorted(funcs)
merged = []
for s, e in fl:
    if merged and s < merged[-1][1]:
        merged[-1] = (merged[-1][0], max(merged[-1][1], e))
    else:
        merged.append((s, e))
for s, e in merged:
    scan_range(s, e)

mo = sorted(movaps)
print('total functions:', len(merged))
print('real movaps count (recursive from pdata+exports):', len(mo))
# classify memory vs reg operands
mem = []
for fo in mo:
    rva = off2rva(fo)
    modrm = b[fo + 2]
    reg = (modrm >> 3) & 7
    is_mem = (modrm >> 6) != 3
    mem.append((fo, rva, is_mem))
memonly = [x for x in mem if x[2]]
print('memory-operand movaps:', len(memonly))

out = []
for fo, rva, ismem in mem:
    out.append('0x%X (rva 0x%X) %s' % (fo, rva, 'MEM' if ismem else 'reg'))
text = '\n'.join(out)
print('\n'.join(out))
open(r'C:\Users\semae\AppData\Local\Temp\opencode\nt_all_movaps.txt', 'w').write(text)

alloffs = sorted(fo for fo, _, _ in mem)
memoffs = sorted(fo for fo, _, ismem in mem if ismem)
print('C# int[] allMovaps = new int[]{%s};' % ', '.join('0x%X' % x for x in alloffs))
print('C# int[] memMovaps = new int[]{%s};' % ', '.join('0x%X' % x for x in memoffs))

chunks = []
chunks.append('internal static class MovapsOffsets')
chunks.append('{')
chunks.append('    internal static readonly int[] MemoryOperand = new int[]')
chunks.append('    {')
line = []
for x in memoffs:
    line.append('0x%X,' % x)
    if len(line) == 12:
        chunks.append('        ' + ' '.join(line))
        line = []
if line:
    chunks.append('        ' + ' '.join(line))
chunks.append('    };')
chunks.append('}')
open(r'C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\UxFix\MovapsOffsets.cs', 'w').write('\n'.join(chunks) + '\n')
print('wrote MovapsOffsets.cs (%d entries)' % len(memoffs))