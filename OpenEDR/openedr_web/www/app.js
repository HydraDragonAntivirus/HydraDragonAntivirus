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
const histEl = document.getElementById('hist');
const HKEY = 'openedr_scan_history_v1';

/* ---------- scan history (localStorage) ---------- */
function loadHist() {
  try { return JSON.parse(localStorage.getItem(HKEY) || '[]'); }
  catch { return []; }
}
function saveHist(h) {
  try { localStorage.setItem(HKEY, JSON.stringify(h.slice(0, 50))); } catch {}
}
function addHist(rep, target) {
  const h = loadHist();
  h.unshift({
    t: new Date().toISOString(),
    target: target || 'unnamed',
    verdict: rep.verdict || 'Error',
    score: rep.max_threat_score ?? '',
    sha: rep.sha256 || '',
    rep: rep
  });
  saveHist(h);
  renderHist();
}
function renderHist() {
  if (!histEl) return;
  const h = loadHist();
  if (!h.length) { histEl.innerHTML = '<span class="mut">Empty.</span>'; return; }
  histEl.innerHTML = '<table><tr><th>time</th><th>target</th><th>verdict</th><th>score</th><th>sha256</th></tr>' +
    h.map((e, idx) => `<tr class="hist-row" data-idx="${idx}" title="Click to view full scan result">` +
      `<td><code>${(e.t || '').slice(0, 19).replace('T', ' ')}</code></td>` +
      `<td><code>${(e.target || '').slice(0, 50)}</code></td>` +
      `<td><span class="badge ${e.verdict}">${e.verdict}</span></td>` +
      `<td>${e.score !== '' ? e.score : '-'}</td>` +
      `<td><code>${(e.sha || '').slice(0, 16)}…</code></td></tr>`).join('') +
    '</table>';
  histEl.querySelectorAll('tr.hist-row').forEach((row) => {
    row.onclick = () => {
      const idx = parseInt(row.getAttribute('data-idx'), 10);
      const entry = h[idx];
      if (entry && entry.rep) {
        render(entry.rep, outEl);
        outEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
    };
  });
}
function exportHist() {
  const h = loadHist();
  if (!h.length) { alert('No history to export.'); return; }
  const blob = new Blob([JSON.stringify(h, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan_history_${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

/* ---------- wasm plumbing ---------- */
async function loadWasm() {
  const candidates = ['./openedr_web_bg.wasm', 'openedr_web_bg.wasm', 'webdemo/openedr_web_bg.wasm'];
  let lastErr = null;
  for (const p of candidates) {
    try {
      const res = await fetch(p);
      if (!res.ok) continue;
      const bytes = await res.arrayBuffer();
      const u8 = new Uint8Array(bytes);
      if (u8.length >= 4 && u8[0] === 0x00 && u8[1] === 0x61 && u8[2] === 0x73 && u8[3] === 0x6d) {
        wasm = await wasm_bindgen({ module_or_path: bytes });
        return;
      }
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error('Valid openedr_web_bg.wasm binary not found at candidate paths.');
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
  if (await loadScript('https://cdn.jsdelivr.net/npm/@alexaltea/capstone-js/dist/capstone.js')) {
    try {
      if (typeof MCapstone !== 'undefined') CS = MCapstone();
    } catch { CS = null; }
  }
  if (await loadScript('https://cdn.jsdelivr.net/npm/@alexaltea/unicorn-js/dist/unicorn_x86.js')) {
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
    const RIP = pe.is64 ? (uc.X86_REG_RIP ?? uc.X86_REG_EIP) : (uc.X86_REG_EIP ?? uc.X86_REG_RIP);
    const RSP = pe.is64 ? (uc.X86_REG_RSP ?? uc.X86_REG_ESP) : (uc.X86_REG_ESP ?? uc.X86_REG_RSP);
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
  let out = 0;
  try {
    if (counts) {
      out = wasm.web_scan_bytes_ex(p, u8.length, np, nl, 1, counts[0], counts[1], counts[2]);
    } else {
      out = wasm.web_scan_bytes(p, u8.length, np, nl);
    }
  } catch (e) {
    out = 0;
  }
  wasm.web_free(p, u8.length);
  wasm.web_free(np, nl);
  if (!out) return { verdict: 'Error', detections: [] };
  try {
    return readStr(out);
  } catch {
    return { verdict: 'Error', detections: [] };
  }
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
  if (rep.target_url) {
    const isWl = rep.whitelisted;
    const isBypassed = rep.whitelist_bypassed;
    const lv = rep.liveness_obj || (rep.liveness ? { status: rep.liveness } : null);
    let lvBadge = '';
    if (lv) {
      if (lv.status === 'ACTIVE') {
        lvBadge = `<span style="color:#38bdf8;font-weight:600;margin-left:8px">🌐 Online (${lv.http === 'ONLINE' ? 'HTTP Reachable' : 'DNS Active'})</span>`;
      } else if (lv.status === 'INACTIVE') {
        lvBadge = `<span style="color:#f59e0b;font-weight:600;margin-left:8px">⚠️ Inactive / Dead (NXDOMAIN)</span>`;
      } else {
        lvBadge = `<span style="color:#94a3b8;font-weight:600;margin-left:8px">⚠️ Host Unreachable</span>`;
      }
    let wlBadge = '';
    if (rep.unwhitelisted_for_ml) {
      wlBadge = `<span style="color:#38bdf8;font-weight:bold;margin-left:8px">⚡ Unwhitelisted for ML (Subdomain Rule)</span>`;
    } else if (isBypassed) {
      wlBadge = `<span style="color:#ffb454;font-weight:bold;margin-left:8px">⚠️ Whitelist Bypassed (${rep.bypass_reason || 'Threat Rule'})</span>`;
    } else if (isWl) {
      wlBadge = `<span style="color:#4cc38a;font-weight:bold;margin-left:8px">✓ Whitelisted (Tranco 1M / CIDR Subnet)</span>`;
    }

    const contentBadge = rep.content_scanned
      ? `<span style="color:#38bdf8;font-weight:600;margin-left:8px">📄 Content Scanned</span>`
      : '';

    const dets = (rep.detections || []).map((d) =>
      `<tr><td><code>${d.rule_id || d.layer || ''}</code></td><td><code>${d.title || d.name || ''}</code></td>` +
      `<td>${d.score ?? ''}</td><td><code>${(d.details || '').slice(0, 180)}</code></td></tr>`).join('');

    const reasonBlock = rep.verdict_reason
      ? `<div style="color:#dbe2f1;font-size:13px;margin:8px 0 6px"><strong>Final Verdict:</strong> ${rep.verdict_reason}</div>`
      : '';

    el.innerHTML =
      `<div>Verdict: <span class="badge ${rep.verdict}">${rep.verdict}</span> ` +
      `score=${rep.risk_score ?? Math.round((rep.malware_probability ?? 0) * 100)} ` +
      `scheme=<code>${rep.scheme || 'http'}</code> host=<code>${rep.host || ''}</code>` +
      `${wlBadge}${lvBadge}${contentBadge}<br>` +
      `<code class="mut">url=${rep.target_url}</code>${reasonBlock}</div>` +
      (dets ? `<table><tr><th>rule</th><th>title</th><th>score</th><th>details</th></tr>${dets}</table>`
            : `<p class="mut">No threat rules triggered.</p>`);
    return;
  }
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
  // Tranco 1M + IP whitelist (.xf binary)
  try {
    const r = await fetch('models/url_whitelist.xf');
    if (!r.ok) throw 0;
    const u8 = new Uint8Array(await r.arrayBuffer());
    const p = writeBytes(u8);
    const fn = wasm.web_load_url_whitelist;
    const ok = fn ? fn(p, u8.length) : 0;
    wasm.web_free(p, u8.length);
    lights.push([`<span class="dot ${ok ? 'ok' : 'no'}"></span>whitelist (1.4M)`, true]);
  } catch { lights.push(['<span class="dot no"></span>whitelist', true]); }
  // Compile valhalla-rules.yar via YARA-X
  let yaraLoaded = false;
  try {
    const r = await fetch('yara_rules/valhalla-rules.yar');
    if (r.ok) {
      const text = await r.text();
      if (typeof wasm.web_load_yara_src === 'function') {
        const enc = new TextEncoder().encode(text);
        const p = writeBytes(enc);
        if (wasm.web_load_yara_src(p, enc.length) === 1) yaraLoaded = true;
        wasm.web_free(p, enc.length);
      }
    }
  } catch {}
  lights.push([`<span class="dot ${yaraLoaded ? 'ok' : 'no'}"></span>YARA rules (${yaraLoaded ? 'compiled' : 'failed'})`, true]);
  for (const [fn, file, label] of [
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
  renderHist();

  const exportBtn = document.getElementById('exportHist');
  if (exportBtn) exportBtn.onclick = exportHist;
  const clearBtn = document.getElementById('clearHist');
  if (clearBtn) clearBtn.onclick = () => { saveHist([]); renderHist(); };

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
    addHist(rep, f.name);
  };
async function checkDomainLiveness(domain, rawUrl) {
  const isIP = /^(\d{1,3}\.){3}\d{1,3}$/.test(domain);
  let dnsOk = false;
  let dnsStatus = 'UNKNOWN';

  if (!isIP) {
    try {
      const ctrl = new AbortController();
      const tid = setTimeout(() => ctrl.abort(), 2500);
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
        headers: { 'accept': 'application/dns-json' },
        signal: ctrl.signal,
      });
      clearTimeout(tid);
      if (res.ok) {
        const data = await res.json();
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          dnsOk = true;
          dnsStatus = 'ACTIVE';
        } else if (data.Status === 3 || !data.Answer) {
          dnsOk = false;
          dnsStatus = 'INACTIVE';
        }
      }
    } catch {}
  } else {
    dnsOk = true;
    dnsStatus = 'IP_TARGET';
  }

  let httpOk = false;
  let targetUrl = rawUrl.includes('://') ? rawUrl : ('https://' + rawUrl);
  try {
    const ctrl = new AbortController();
    const tid = setTimeout(() => ctrl.abort(), 2500);
    await fetch(targetUrl, { method: 'HEAD', mode: 'no-cors', signal: ctrl.signal });
    clearTimeout(tid);
    httpOk = true;
  } catch {
    if (!rawUrl.startsWith('https://')) {
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 1500);
        await fetch('http://' + domain, { method: 'HEAD', mode: 'no-cors', signal: ctrl.signal });
        clearTimeout(tid);
        httpOk = true;
      } catch {}
    }
  }

  const active = dnsOk || httpOk;
  return {
    status: active ? 'ACTIVE' : (dnsStatus === 'INACTIVE' ? 'INACTIVE' : 'UNREACHABLE'),
    dns: dnsStatus,
    http: httpOk ? 'ONLINE' : (dnsOk ? 'UNRESPONSIVE' : 'OFFLINE'),
  };
}

  document.getElementById('scanUrl').onclick = async () => {
    const url = document.getElementById('url').value.trim();
    if (!url) return;
    outEl.innerHTML = '<span class="mut">Inspecting URL threats & testing domain liveness…</span>';

    let domain = '';
    try {
      domain = new URL(url.includes('://') ? url : 'https://' + url).hostname;
    } catch {
      domain = url.split('/')[0].split('?')[0];
    }

    let livenessCode = 0; // 0 = unknown, 1 = active, 2 = inactive/dead
    let livenessObj = null;
    if (domain) {
      livenessObj = await checkDomainLiveness(domain, url);
      if (livenessObj.status === 'ACTIVE') {
        livenessCode = 1;
      } else if (livenessObj.status === 'INACTIVE') {
        livenessCode = 2;
      }
    }

    let pageContent = document.getElementById('pageContent') ? document.getElementById('pageContent').value.trim() : '';

    if (!pageContent && livenessCode === 1 && typeof fetch === 'function') {
      try {
        const ctrl = new AbortController();
        const tid = setTimeout(() => ctrl.abort(), 2000);
        const fetchTarget = url.includes('://') ? url : ('https://' + url);
        const r = await fetch(fetchTarget, { method: 'GET', signal: ctrl.signal });
        clearTimeout(tid);
        if (r.ok) {
          const txt = await r.text();
          if (txt && txt.length > 0) {
            pageContent = txt.slice(0, 1024 * 1024);
          }
        }
      } catch {}
    }

    const { ptr, len } = writeStr(url);
    let out = 0;
    if (pageContent && typeof wasm.web_inspect_url_content === 'function') {
      const c = writeStr(pageContent);
      out = wasm.web_inspect_url_content(ptr, len, livenessCode, c.ptr, c.len);
      wasm.web_free(c.ptr, c.len);
    } else if (typeof wasm.web_inspect_url === 'function') {
      out = wasm.web_inspect_url(ptr, len, livenessCode);
    } else if (typeof wasm.web_scan_url === 'function') {
      out = wasm.web_scan_url(ptr, len);
    }
    wasm.web_free(ptr, len);
    const rep = out ? readStr(out) : { verdict: 'Error', detections: [] };

    if (livenessObj) {
      rep.liveness_obj = livenessObj;
    }

    render(rep, outEl);
    addHist(rep, url);
  };
}
boot();
