/* openedr_web browser demo glue (no bundler, no wasm-bindgen CLI needed).
 *
 * Vendor libs (optional, drop-in):
 *   vendor/capstone.js    - capstone.js build (global MCapstone) for disasm counts
 *   vendor/unicorn_x86.js - unicorn.js x86 build (global MUnicorn) for unpack assist
 * Models (fetch at runtime, NOT in git):
 *   models/pe_trees.bin, models/js_trees.bin, models/url_trees.bin
 *   registry_rules/pua_registry_rules.yaml   (optional)
 *   hash_rules/benign_sha256.txt             (optional)
 */
'use strict';

const FLAG = new Set(['Malicious', 'Suspicious']);
let wasm = null;          // { memory, exports... }
let CS = null;            // capstone module promise (or null)
let UC = null;            // unicorn module promise (or null)
const statusEl = document.getElementById('status');
const outEl = document.getElementById('out');

/* ---------- wasm plumbing ---------- */
async function loadWasm() {
  const bytes = await (await fetch('openedr_web.wasm')).arrayBuffer();
  const mod = await WebAssembly.instantiate(bytes, {});
  wasm = mod.instance.exports;
}

function writeBytes(u8) {
  const ptr = wasm.web_alloc(u8.length);
  new Uint8Array(wasm.memory.buffer, ptr, u8.length).set(u8);
  return ptr;
}
function writeStr(s) {
  const u8 = new TextEncoder().encode(s);
  return { ptr: writeBytes(u8), len: u8.length };
}
function readStr(ptr) {
  const len = wasm.web_output_len();
  const s = new TextDecoder().decode(new Uint8Array(wasm.memory.buffer, ptr, len));
  wasm.web_free_str(ptr);
  return JSON.parse(s);
}
function loadBlob(kind, u8) {
  const ptr = writeBytes(u8);
  const ok = wasm.web_load_model(kind, ptr, u8.length);
  wasm.web_free(ptr, u8.length);
  return ok === 1;
}
function setText(fn, s) {
  const { ptr, len } = writeStr(s);
  const r = fn(ptr, len);
  wasm.web_free(ptr, len);
  return r;
}

/* ---------- optional vendor libs ---------- */
function loadScript(src) {
  return new Promise((resolve) => {
    const el = document.createElement('script');
    el.src = src;
    el.onload = () => resolve(true);
    el.onerror = () => { el.remove(); resolve(false); };
    document.head.appendChild(el);
  });
}
async function initVendors() {
  if (await loadScript('vendor/capstone.js')) {
    try {
      if (typeof MCapstone !== 'undefined') CS = MCapstone();
    } catch { CS = null; }
  }
  if (await loadScript('vendor/unicorn_x86.js')) {
    try {
      if (typeof MUnicorn !== 'undefined') UC = MUnicorn();
    } catch { UC = null; }
  }
}

/* ---------- minimal PE parsing (shared by pre-passes) ---------- */
function le32(u8, off) {
  return (u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16) | (u8[off + 3] << 24)) >>> 0;
}
function le16(u8, off) { return u8[off] | (u8[off + 1] << 8); }
function parsePE(u8) {
  // returns { is64, sections:[{rva, rawPtr, rawSize}], entryRva, imageSize } or null
  try {
    if (u8.length < 64 || u8[0] !== 0x4D || u8[1] !== 0x5A) return null;
    const e = le32(u8, 0x3C);
    if (e + 24 > u8.length || u8[e] !== 0x50 || u8[e + 1] !== 0x45) return null;
    const nSec = le16(u8, e + 6), optSize = le16(u8, e + 20);
    const opt = e + 24;
    const magic = le16(u8, opt);
    const is64 = magic === 0x20B;
    const epRva = le32(u8, opt + 16);
    const imgSize = le32(u8, is64 ? opt + 56 : opt + 56);
    const sOff = opt + optSize;
    const sections = [];
    for (let i = 0; i < Math.min(nSec, 96); i++) {
      const o = sOff + i * 40;
      if (o + 40 > u8.length) break;
      sections.push({
        rawSize: le32(u8, o + 16), rawPtr: le32(u8, o + 20),
        rva: le32(u8, o + 12),
      });
    }
    return { is64, sections, entryRva: epRva, imageSize: imgSize };
  } catch { return null; }
}

/* ---------- capstone pre-pass: add/mov/total counts ---------- */
async function disasmCounts(u8) {
  // returns [total, add, mov] or null
  try {
    if (!CS) return null;
    const cs = await CS;
    const pe = parsePE(u8);
    if (!pe || !pe.sections.length) return null;
    const d = new cs.Capstone(cs.ARCH_X86, pe.is64 ? cs.MODE_64 : cs.MODE_32);
    let total = 0, add = 0, mov = 0;
    for (const s of pe.sections) {
      if (!s.rawSize || s.rawPtr >= u8.length) continue;
      const chunk = u8.slice(s.rawPtr, Math.min(s.rawPtr + s.rawSize, u8.length, s.rawPtr + 65536));
      if (!chunk.length) continue;
      const insns = d.disasm(Array.from(chunk), 0);
      for (const ins of insns) {
        total++;
        const m = (ins.mnemonic || '').toLowerCase();
        if (m === 'add') add++;
        else if (m === 'mov') mov++;
      }
      if (total > 200000) break;
    }
    d.close();
    return total ? [total, add, mov] : null;
  } catch { return null; }
}

/* ---------- unicorn unpack assist: emulate entry, diff memory ---------- */
async function unpackAssist(u8) {
  // returns array of dumped Uint8Array (possibly empty)
  const dumps = [];
  try {
    if (!UC) return dumps;
    const uc = await UC;
    const pe = parsePE(u8);
    if (!pe || !pe.sections.length || !pe.entryRva) return dumps;
    const BASE = 0x400000, STACK_BASE = 0x100000, STACK_SIZE = 65536;
    const PROT = (uc.PROT_ALL !== undefined) ? uc.PROT_ALL : 7;
    const e = new uc.Unicorn(uc.ARCH_X86, pe.is64 ? uc.MODE_64 : uc.MODE_32);
    const span = Math.max(u8.length + 0x1000, 0x100000);
    e.mem_map(BASE, span, PROT);
    e.mem_map(STACK_BASE, STACK_SIZE, PROT);
    const head = Math.min(u8.length, 0x1000);
    e.mem_write(BASE, Array.from(u8.slice(0, head)));
    for (const s of pe.sections) {
      if (!s.rawSize || s.rawPtr >= u8.length) continue;
      const n = Math.min(s.rawSize, u8.length - s.rawPtr);
      e.mem_write(BASE + s.rva, Array.from(u8.slice(s.rawPtr, s.rawPtr + n)));
    }
    const RIP = (uc.X86_REG_RIP !== undefined) ? uc.X86_REG_RIP : uc.X86_REG_EIP;
    const RSP = (uc.X86_REG_RSP !== undefined) ? uc.X86_REG_RSP : uc.X86_REG_ESP;
    const entry = BASE + pe.entryRva;
    try { e.reg_write_i32(RSP, STACK_BASE + STACK_SIZE - 16); } catch {}
    try { e.reg_write_i32(RIP, entry); } catch {}
    try { e.emu_start(entry, entry + 0x100000, 2 * 1000 * 1000, 200000); } catch { /* partial state kept */ }
    const before = new Map();
    for (const s of pe.sections) {
      if (!s.rawSize || s.rawPtr >= u8.length) continue;
      const n = Math.min(s.rawSize, u8.length - s.rawPtr, 1 << 20);
      try {
        const cur = e.mem_read(BASE + s.rva, n);
        const orig = u8.slice(s.rawPtr, s.rawPtr + n);
        let diff = 0;
        for (let i = 0; i < n; i++) if (cur[i] !== orig[i]) diff++;
        if (diff > 64 && n >= 4096 && dumps.length < 3) dumps.push(Uint8Array.from(cur));
      } catch {}
    }
    try { e.close(); } catch {}
  } catch { /* static-only fallback */ }
  return dumps;
}

/* ---------- scan orchestration ---------- */
function scanBuffer(u8, name, counts) {
  const p = writeBytes(u8);
  const { ptr: np, len: nl } = writeStr(name);
  let out;
  if (counts) {
    out = wasm.web_scan_bytes_ex(p, u8.length, np, nl, 1, counts[0], counts[1], counts[2]);
  } else {
    out = wasm.web_scan_bytes(p, u8.length, np, nl);
  }
  wasm.web_free(p, u8.length);
  wasm.web_free(np, nl);
  if (!out) return { verdict: 'Error', detections: [] };
  return readStr(out);
}
function mergeVerdict(base, extra) {
  // extra: report for an unpacked dump; fold its score/detections into base
  let score = base.max_threat_score || 0;
  const dets = (base.detections || []).slice();
  for (const d of (extra.detections || [])) {
    dets.push({ layer: d.layer, name: 'Unpacked:' + d.name, score: d.score, details: d.details });
    if (typeof d.score === 'number') score = Math.max(score, d.score);
  }
  let verdict = base.verdict;
  if (score >= 0.85) verdict = 'Malicious';
  else if (score >= 0.50 || dets.length) verdict = 'Suspicious';
  return { ...base, verdict, max_threat_score: score, detections: dets };
}
function render(rep, el) {
  const dets = (rep.detections || []).map((d) =>
    `<tr><td><code>${d.layer || ''}</code></td><td><code>${d.name || ''}</code></td>` +
    `<td>${d.score ?? ''}</td><td><code>${(d.details || '').slice(0, 160)}</code></td></tr>`).join('');
  el.innerHTML =
    `<div>Verdict: <span class="badge ${rep.verdict}">${rep.verdict}</span> ` +
    `score=${rep.max_threat_score ?? ''} size=${rep.file_size ?? ''}<br>` +
    `<code class="mut">sha256=${rep.sha256 || ''}</code></div>` +
    (dets ? `<table><tr><th>layer</th><th>name</th><th>score</th><th>details</th></tr>${dets}</table>`
          : `<p class="mut">No detections.</p>`);
}

async function boot() {
  const lights = [];
  try {
    await loadWasm();
    lights.push(['<span class="dot ok"></span>wasm', true]);
  } catch (e) {
    statusEl.innerHTML = `<span class="dot no"></span>failed to load openedr_web.wasm: ${e}`;
    return;
  }
  if (wasm.web_self_test() !== 1) {
    statusEl.innerHTML = `<span class="dot no"></span>wasm self-test FAILED`;
    return;
  }
  lights.push(['<span class="dot ok"></span>self-test', true]);
  await initVendors();
  lights.push([`<span class="dot ${CS ? 'ok' : 'no'}"></span>capstone.js`, true]);
  lights.push([`<span class="dot ${UC ? 'ok' : 'no'}"></span>unicorn.js (x86)`, true]);
  // models (each optional; engine degrades gracefully)
  for (const [kind, file] of [[0, 'pe_trees.bin'], [1, 'js_trees.bin'], [2, 'url_trees.bin']]) {
    try {
      const r = await fetch('models/' + file);
      if (!r.ok) throw 0;
      const u8 = new Uint8Array(await r.arrayBuffer());
      const p = writeBytes(u8);
      const ok = wasm.web_load_model(kind, p, u8.length);
      wasm.web_free(p, u8.length);
      lights.push([`<span class="dot ${ok ? 'ok' : 'no'}"></span>${file}`, true]);
    } catch { lights.push([`<span class="dot no"></span>${file}`, true]); }
  }
  // rules (.yrc bundle preferred; falls back to source)
  try {
    const r = await fetch('yara_rules/valhalla-rules.yrc');
    if (!r.ok) throw 0;
    const u8 = new Uint8Array(await r.arrayBuffer());
    const p = writeBytes(u8);
    const ok = wasm.web_load_yara(p, u8.length);
    wasm.web_free(p, u8.length);
    lights.push([`<span class="dot ${ok ? 'ok' : 'no'}"></span>yara .yrc`, true]);
  } catch { lights.push([`<span class="dot no"></span>yara .yrc`, true]); }
  for (const [fn, file, label] of [
    [wasm.web_set_registry_rules, 'registry_rules/pua_registry_rules.yaml', 'registry rules'],
    [wasm.web_set_benign, 'hash_rules/benign_sha256.txt', 'benign list'],
  ]) {
    try {
      const r = await fetch(file);
      if (!r.ok) throw 0;
      const n = setText(fn, await r.text());
      lights.push([`<span class="dot ok"></span>${label} (${n})`, true]);
    } catch { lights.push([`<span class="dot no"></span>${label}`, true]); }
  }
  statusEl.innerHTML = lights.map((l) => l[0]).join(' &nbsp; ');

  document.getElementById('scanFile').onclick = async () => {
    const f = document.getElementById('file').files[0];
    if (!f) return;
    outEl.innerHTML = '<span class="mut">Scanning…</span>';
    const u8 = new Uint8Array(await f.arrayBuffer());
    const counts = (u8[0] === 0x4D && u8[1] === 0x5A) ? await disasmCounts(u8) : null;
    let rep = scanBuffer(u8, f.name, counts);
    if (u8[0] === 0x4D && u8[1] === 0x5A) {
      for (const dump of await unpackAssist(u8)) {
        const extra = scanBuffer(dump, f.name + '.unpacked', null);
        rep = mergeVerdict(rep, extra);
        if (rep.verdict === 'Malicious') break;
      }
    }
    render(rep, outEl);
  };
  document.getElementById('scanUrl').onclick = () => {
    const url = document.getElementById('url').value.trim();
    if (!url) return;
    const { ptr, len } = writeStr(url);
    const out = wasm.web_scan_url(ptr, len);
    wasm.web_free(ptr, len);
    render(out ? readStr(out) : { verdict: 'Error', detections: [] }, outEl);
  };
}
boot();
