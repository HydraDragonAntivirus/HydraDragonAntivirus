/* VIRUSKOV — file report page (VirusKovAlyzer + verdicts + human analysis) */
(function () {
  'use strict';
  var API = 'https://api.viruskov.com/api/v1';
  var KEY_STORE = 'viruskov_sample_key';

  var L = {
    tr: {
      title: 'Dosya raporu', notFound: 'Bu hash VIRUSKOV ağında henüz görülmedi.', scanIt: 'Dosyayı canlı tarayıcıda tara',
      invalid: '64 karakterlik geçerli bir SHA-256 girin.', loading: 'Rapor yükleniyor…', neterr: 'Rapor alınamadı',
      rate: 'Sorgu sınırı aşıldı, biraz sonra tekrar deneyin.',
      v: { malicious: 'Zararlı', suspicious: 'Şüpheli', clean: 'Temiz', possible_clean: 'Muhtemelen temiz', unknown: 'Bilinmiyor' },
      human: 'İnsan analizi', engine: 'Motor', engineVerdict: 'Motor kararı', copy: 'Kopyala', copied: 'Kopyalandı',
      vt: 'VirusTotal\'da aç', download: 'Örneği indir (.zip)', keyPh: 'Araştırmacı API anahtarı', keyNote: 'Arşiv şifresi: infected. Yalnızca zararlı ve şüpheli dosyalar paylaşılır.',
      dlErr: 'İndirilemedi', haCard: 'İnsan analizi', haNone: 'Henüz bir analist bakmadı.', haPending: 'Analist kuyruğunda', waiting: 'bekliyor',
      request: 'İnsan analizi iste', requested: 'Kuyruğa eklendi.', resp: 'Yanıt süresi', analyst: 'Analist', reviewed: 'Karar zamanı', note: 'Not',
      tele: 'Telemetri', first: 'İlk görülme', last: 'Son görülme', seen: 'Gözlem', prev: 'Yayılım', names: 'Dosya adları',
      basic: 'Dosya', type: 'Tür', size: 'Boyut', entropy: 'Entropi', bytes: 'bayt',
      pe: 'PE başlığı', kind: 'Biçim', machine: 'Mimari', compiled: 'Derleme zamanı', entry: 'Giriş noktası', subsystem: 'Alt sistem',
      imageBase: 'ImageBase', flags: 'Özellikler', signature: 'Authenticode', signed: 'imza bloğu var', unsigned: 'yok', overlay: 'Overlay',
      sections: 'Bölümler', name: 'Ad', vsize: 'Sanal boyut', rsize: 'Ham boyut', perms: 'İzin',
      imports: 'Importlar', exports: 'Exportlar', funcs: 'fonksiyon', noImports: 'Import tablosu yok.', noExports: 'Export yok.',
      strings: 'Stringler', urls: 'URL', ips: 'IP', registry: 'Registry', paths: 'Dosya yolu', commands: 'Komut', crypto_wallets: 'Cüzdan', sample: 'Örnek', none: 'Bu kategoride string yok.',
      sim: 'Benzer dosyalar (TLSH)', simNote: 'Mesafe ne kadar küçükse dosyalar o kadar benzer. 0–30 çok yakın, 30–80 aynı aileden olabilir. Benzerlik tek başına karar değildir.', dist: 'Mesafe', list: 'TLSH kara listesi', noSim: 'Yakın bir dosya bulunmadı.',
      ind: 'Statik göstergeler', noInd: 'Kayda değer bir statik gösterge bulunmadı.', noReport: 'Bu dosya için statik rapor henüz yok (yalnızca hash ile görüldü). Dosyayı tarayıcıya yüklediğinizde oluşturulur.',
      sev: { high: 'yüksek', medium: 'orta', low: 'düşük', info: 'bilgi' }, ago: 'önce'
    },
    en: {
      title: 'File report', notFound: 'This hash has not been seen on the VIRUSKOV network yet.', scanIt: 'Scan the file in the live scanner',
      invalid: 'Enter a valid 64-character SHA-256.', loading: 'Loading report…', neterr: 'Could not load the report',
      rate: 'Rate limit reached, please try again shortly.',
      v: { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean', possible_clean: 'Possibly clean', unknown: 'Unknown' },
      human: 'Human analysis', engine: 'Engine', engineVerdict: 'Engine verdict', copy: 'Copy', copied: 'Copied',
      vt: 'Open on VirusTotal', download: 'Download sample (.zip)', keyPh: 'Researcher API key', keyNote: 'Archive password: infected. Only malicious and suspicious files are shared.',
      dlErr: 'Download failed', haCard: 'Human analysis', haNone: 'No analyst has looked at it yet.', haPending: 'In the analyst queue', waiting: 'waiting',
      request: 'Request human analysis', requested: 'Added to the queue.', resp: 'Response time', analyst: 'Analyst', reviewed: 'Reviewed', note: 'Note',
      tele: 'Telemetry', first: 'First seen', last: 'Last seen', seen: 'Sightings', prev: 'Prevalence', names: 'File names',
      basic: 'File', type: 'Type', size: 'Size', entropy: 'Entropy', bytes: 'bytes',
      pe: 'PE header', kind: 'Format', machine: 'Machine', compiled: 'Compiled', entry: 'Entry point', subsystem: 'Subsystem',
      imageBase: 'ImageBase', flags: 'Flags', signature: 'Authenticode', signed: 'signature block present', unsigned: 'none', overlay: 'Overlay',
      sections: 'Sections', name: 'Name', vsize: 'Virtual size', rsize: 'Raw size', perms: 'Perms',
      imports: 'Imports', exports: 'Exports', funcs: 'functions', noImports: 'No import table.', noExports: 'No exports.',
      strings: 'Strings', urls: 'URLs', ips: 'IPs', registry: 'Registry', paths: 'Paths', commands: 'Commands', crypto_wallets: 'Wallets', sample: 'Sample', none: 'No strings in this category.',
      sim: 'Similar files (TLSH)', simNote: 'The smaller the distance, the more alike. 0–30 is very close, 30–80 may be the same family. Similarity alone is not a verdict.', dist: 'Distance', list: 'TLSH blacklist', noSim: 'No close files found.',
      ind: 'Static indicators', noInd: 'No notable static indicators.', noReport: 'No static report for this file yet (seen by hash only). It is created when the file is uploaded to the scanner.',
      sev: { high: 'high', medium: 'medium', low: 'low', info: 'info' }, ago: 'ago'
    }
  };
  var COLORS = { malicious: 'var(--accent-red)', suspicious: 'var(--accent-amber)', clean: 'var(--accent-green)', possible_clean: '#6fcf97', unknown: 'var(--text-muted)' };

  var lang = function () { return window.ViruskovI18n ? window.ViruskovI18n.getLang() : 'tr'; };
  var t = function () { return L[lang()] || L.tr; };
  var esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };
  var fmt = function (n) { return Number(n || 0).toLocaleString(lang() === 'tr' ? 'tr-TR' : 'en-US'); };
  var when = function (iso) { var d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleString(lang() === 'tr' ? 'tr-TR' : 'en-US'); };
  function dur(s) {
    if (s == null) return '—';
    var tr = lang() === 'tr';
    if (s < 60) return s + (tr ? ' sn' : ' s');
    if (s < 3600) return Math.round(s / 60) + (tr ? ' dk' : ' min');
    if (s < 86400) return (s / 3600).toFixed(1).replace('.0', '') + (tr ? ' sa' : ' h');
    return (s / 86400).toFixed(1).replace('.0', '') + (tr ? ' gün' : ' d');
  }
  function badge(v) {
    v = COLORS[v] ? v : 'unknown';
    return '<span class="p-badge" style="color:' + COLORS[v] + '">' + esc(t().v[v]) + '</span>';
  }
  function kv(rows) {
    return '<dl class="p-kv">' + rows.filter(Boolean).map(function (r) {
      return '<dt>' + esc(r[0]) + '</dt><dd' + (r[2] ? ' class="m"' : '') + '>' + r[1] + '</dd>';
    }).join('') + '</dl>';
  }

  var state = { data: null, sha: '', tab: 'urls' };
  var root = document.getElementById('fileRoot');
  var input = document.getElementById('fileSha');

  function shaFromUrl() {
    var q = new URLSearchParams(location.search);
    return (q.get('sha256') || q.get('sha') || location.hash.replace('#', '') || '').trim().toLowerCase();
  }

  function load(sha) {
    state.sha = sha;
    if (input) input.value = sha;
    if (!/^[0-9a-f]{64}$/.test(sha)) {
      root.innerHTML = sha ? '<div class="p-error">' + esc(t().invalid) + '</div>' : '';
      return;
    }
    root.innerHTML = '<div class="p-card p-empty">' + esc(t().loading) + '</div>';
    fetch(API + '/report/' + sha).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { r: r, d: d }; });
    }).then(function (o) {
      if (o.r.status === 404) {
        state.data = null;
        root.innerHTML = '<div class="p-card"><p class="vk-body">' + esc(t().notFound) + '</p><p style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">' +
          '<a class="vk-btn vk-btn-light" href="../scan/index.html">' + esc(t().scanIt) + '</a>' +
          '<a class="vk-btn vk-btn-ghost" target="_blank" rel="noopener" href="https://www.virustotal.com/gui/file/' + sha + '">' + esc(t().vt) + ' &#8599;</a></p></div>';
        return;
      }
      if (o.r.status === 429) { root.innerHTML = '<div class="p-error">' + esc(t().rate) + '</div>'; return; }
      if (!o.r.ok) { root.innerHTML = '<div class="p-error">' + esc(t().neterr) + '</div>'; return; }
      state.data = o.d;
      render();
    }).catch(function (e) {
      root.innerHTML = '<div class="p-error">' + esc(t().neterr) + ': ' + esc(e.message) + '</div>';
    });
  }

  function render() {
    var d = state.data;
    if (!d) return;
    var T = t();
    var rep = d.report || null;
    var pe = rep && rep.pe;
    var tele = d.telemetry || null;
    var h = d.human_analysis || null;
    var v = COLORS[d.verdict] ? d.verdict : 'unknown';
    var name = (rep && rep.file_name) || (tele && tele.file_names && tele.file_names[0]) || '';
    document.title = 'VIRUSKOV — ' + (d.threat_name || name || T.title);

    var html = '';
    // ---- hero
    html += '<section class="p-hero" style="--vcol:' + COLORS[v] + '"><div>' +
      '<div>' + badge(v) + (d.verdict_source === 'human' ? '<span class="p-source">' + esc(T.human) + '</span>' : '<span class="p-source" style="color:var(--text-dim)">' + esc(T.engine) + '</span>') + '</div>' +
      '<h1>' + esc(d.threat_name || T.v[v]) + '</h1>' +
      (name ? '<div class="p-file">' + esc(name) + (rep ? ' · ' + esc(rep.file_type) + ' · ' + fmt(rep.size) + ' ' + esc(T.bytes) : '') + '</div>' : '') +
      '<div class="p-sha"><span>' + esc(d.sha256) + '</span><button type="button" data-copy="' + esc(d.sha256) + '">' + esc(T.copy) + '</button></div>' +
      '</div><div class="p-actions">' +
      '<a class="vk-btn vk-btn-ghost" target="_blank" rel="noopener" href="' + esc(d.virustotal) + '">' + esc(T.vt) + ' &#8599;</a>' +
      (d.sample_sharing ? '<div class="p-keyrow"><input id="sampleKey" type="password" placeholder="' + esc(T.keyPh) + '"></div>' +
        '<button type="button" class="vk-btn vk-btn-light" id="sampleDl">' + esc(T.download) + '</button><div class="p-note" id="sampleNote">' + esc(T.keyNote) + '</div>' : '') +
      '</div></section>';

    html += '<div class="p-grid">';

    // ---- human analysis
    var hBody;
    if (h && h.status === 'completed') {
      hBody = kv([
        [T.human, badge(h.verdict) + (h.threat_name ? ' <b style="margin-left:6px">' + esc(h.threat_name) + '</b>' : '')],
        h.note ? [T.note, esc(h.note)] : null,
        [T.analyst, esc(h.analyst || '—')],
        [T.resp, esc(dur(h.response_secs))],
        [T.reviewed, esc(when(h.reviewed_at))],
        d.verdict_source === 'human' && d.engine_verdict ? [T.engineVerdict, badge(d.engine_verdict)] : null
      ]);
    } else if (h && h.status === 'pending') {
      var waited = Math.max(0, Math.round((Date.now() - Date.parse(h.requested_at)) / 1000));
      hBody = '<p class="vk-body"><span class="p-badge" style="color:var(--accent-amber)">' + esc(T.haPending) + '</span> ' + esc(dur(waited)) + ' ' + esc(T.waiting) + '</p>';
    } else {
      hBody = '<p class="vk-body">' + esc(T.haNone) + '</p><p style="margin-top:12px"><button type="button" class="vk-btn vk-btn-ghost" id="reqHuman">' + esc(T.request) + '</button> <span class="p-note" id="reqMsg"></span></p>';
    }
    html += '<section class="p-card"><h2>' + esc(T.haCard) + '</h2>' + hBody + '</section>';

    // ---- telemetry
    if (tele) {
      html += '<section class="p-card"><h2>' + esc(T.tele) + '</h2>' + kv([
        [T.first, esc(when(tele.first_seen))],
        [T.last, esc(when(tele.last_seen))],
        [T.seen, esc(fmt(tele.seen_count))],
        [T.prev, esc(String(tele.prevalence || '').toUpperCase())],
        tele.file_names && tele.file_names.length ? [T.names, esc(tele.file_names.join(', '))] : null
      ]) + '</section>';
    }

    if (!rep) {
      html += '<section class="p-card p-wide"><p class="vk-body">' + esc(T.noReport) + '</p></section></div>';
      root.innerHTML = html;
      bind();
      return;
    }

    // ---- basic file info + hashes
    var hs = rep.hashes || {};
    html += '<section class="p-card"><h2>' + esc(T.basic) + '</h2>' + kv([
      [T.type, esc(rep.file_type) + ' <span class="p-note">(' + esc(rep.mime) + ')</span>'],
      [T.size, esc(fmt(rep.size)) + ' ' + esc(T.bytes)],
      [T.entropy, esc(rep.entropy)],
      ['MD5', esc(hs.md5), 1], ['SHA-1', esc(hs.sha1), 1], ['SHA-256', esc(hs.sha256), 1], ['CRC32', esc(hs.crc32), 1],
      hs.imphash ? ['Imphash', esc(hs.imphash), 1] : null,
      hs.tlsh ? ['TLSH', esc(hs.tlsh), 1] : null,
      hs.dex_tlsh ? ['DEX TLSH', esc(hs.dex_tlsh), 1] : null
    ]) + '</section>';
    // ---- APK (package, signer, manifest)
    var ap = rep.apk;
    if (ap) {
      var lst = function (o) { return (o || []).length; };
      html += '<section class="p-card"><h2>APK</h2>' + kv([
        ['Package', esc(ap.package), 1],
        ['Signer', (ap.signers || []).map(function (x) { return esc(x); }).join('<br>') + ' <span class="p-note">(' + esc(ap.signature_scheme || '?') + (ap.test_key ? ', debug/test key' : '') + ')</span>', 1],
        ['Permissions', (ap.permissions || []).map(function (x) { return esc(String(x).replace(/^android\.permission\./, '')); }).join(', ') || '—'],
        ['Components', esc(ap.activities + ' activities · ' + lst(ap.services) + ' services · ' + lst(ap.receivers) + ' receivers · ' + lst(ap.providers) + ' providers')],
        ['DEX / native', esc(ap.dex_count + ' DEX · ' + lst(ap.native_libs) + ' .so')]
      ]) + '</section>';
    }

    // ---- PE
    if (pe) {
      html += '<section class="p-card"><h2>' + esc(T.pe) + '</h2>' + kv([
        [T.kind, esc(pe.kind)],
        [T.machine, esc(pe.machine)],
        [T.compiled, pe.timestamp_utc ? esc(when(pe.timestamp_utc)) : '0x' + esc(Number(pe.timestamp).toString(16))],
        [T.entry, esc(pe.entry_point) + (pe.entry_section ? ' (' + esc(pe.entry_section) + ')' : ''), 1],
        [T.imageBase, esc(pe.image_base), 1],
        [T.subsystem, esc(pe.subsystem)],
        [T.flags, '<span class="p-tags">' + pe.characteristics.concat(pe.dll_characteristics).map(function (f) { return '<span class="vk-tag">' + esc(f) + '</span>'; }).join('') + '</span>'],
        [T.signature, esc(pe.has_signature ? T.signed : T.unsigned)],
        [T.overlay, pe.overlay_size ? esc(fmt(pe.overlay_size)) + ' ' + esc(T.bytes) + (pe.overlay_entropy != null ? ' · H ' + esc(pe.overlay_entropy) : '') : '—']
      ]) + '</section>';
    }

    // ---- indicators
    var ind = rep.indicators || [];
    html += '<section class="p-card' + (pe ? '' : ' p-wide') + '"><h2>' + esc(T.ind) + '</h2>' + (ind.length ?
      '<ul class="p-ind">' + ind.map(function (i) {
        return '<li><span class="sev ' + esc(i.severity) + '">' + esc(T.sev[i.severity] || i.severity) + '</span><span class="d">' + esc(i.detail) + '</span></li>';
      }).join('') + '</ul>' : '<p class="vk-body">' + esc(T.noInd) + '</p>') + '</section>';

    // ---- similar files
    var sim = d.similar || [];
    html += '<section class="p-card p-wide p-table-wrap"><h2 style="padding:20px 24px 0">' + esc(T.sim) + '</h2>' +
      '<p class="p-note" style="padding:0 24px 12px">' + esc(T.simNote) + '</p>' + (sim.length ?
      '<table class="p-table"><thead><tr><th>' + esc(T.dist) + '</th><th>' + esc(T.v.unknown === 'Unknown' ? 'Verdict' : 'Karar') + '</th><th>SHA-256 / TLSH</th></tr></thead><tbody>' +
      sim.map(function (x) {
        var target = x.sha256 ? '<a href="?sha256=' + esc(x.sha256) + '">' + esc(x.sha256) + '</a>' : '<span title="' + esc(x.tlsh) + '">' + esc(T.list) + ' · ' + esc(x.tlsh.slice(0, 20)) + '…</span>';
        return '<tr><td class="m">' + esc(x.distance) + '</td><td>' + badge(x.verdict) + (x.verdict_source === 'human' ? ' <span class="p-source">' + esc(T.human) + '</span>' : '') +
          (x.threat_name ? ' <b style="margin-left:6px">' + esc(x.threat_name) + '</b>' : '') + '</td><td class="m">' + target + '</td></tr>';
      }).join('') + '</tbody></table>' : '<p class="vk-body" style="padding:0 24px 20px">' + esc(T.noSim) + '</p>') + '</section>';

    // ---- sections
    if (pe && pe.sections.length) {
      html += '<section class="p-card p-wide p-table-wrap"><h2 style="padding:20px 24px 0">' + esc(T.sections) + '</h2><table class="p-table"><thead><tr>' +
        '<th>' + esc(T.name) + '</th><th>VA</th><th>' + esc(T.vsize) + '</th><th>' + esc(T.rsize) + '</th><th>' + esc(T.perms) + '</th><th>' + esc(T.entropy) + '</th></tr></thead><tbody>' +
        pe.sections.map(function (s) {
          return '<tr><td><b>' + esc(s.name) + '</b></td><td class="m">' + esc(s.virtual_address) + '</td><td class="m">' + esc(fmt(s.virtual_size)) + '</td><td class="m">' + esc(fmt(s.raw_size)) +
            '</td><td class="m">' + esc(s.perms) + '</td><td><span class="p-ent ' + esc(s.class) + '"><i style="width:' + Math.round((s.entropy / 8) * 80) + 'px"></i>' + esc(s.entropy) + '</span></td></tr>';
        }).join('') + '</tbody></table></section>';
    }

    // ---- imports / exports
    if (pe) {
      html += '<section class="p-card"><h2>' + esc(T.imports) + ' · ' + esc(fmt(pe.import_count)) + '</h2>' + (pe.imports.length ?
        '<div class="p-imports">' + pe.imports.map(function (imp) {
          return '<details><summary>' + esc(imp.dll) + '<span>' + imp.functions.length + ' ' + esc(T.funcs) + '</span></summary><ul>' +
            imp.functions.map(function (f) { return '<li>' + esc(f) + '</li>'; }).join('') + '</ul></details>';
        }).join('') + '</div>' : '<p class="vk-body">' + esc(T.noImports) + '</p>') + '</section>';
      html += '<section class="p-card"><h2>' + esc(T.exports) + ' · ' + esc(fmt(pe.exports.length)) + (pe.export_name ? ' · ' + esc(pe.export_name) : '') + '</h2>' + (pe.exports.length ?
        '<ul class="p-strings">' + pe.exports.slice(0, 500).map(function (e) {
          return '<li>#' + e.ordinal + ' ' + esc(e.name || '(ordinal)') + ' <span style="color:var(--text-dim)">' + esc(e.rva) + (e.forwarder ? ' → ' + esc(e.forwarder) : '') + '</span></li>';
        }).join('') + '</ul>' : '<p class="vk-body">' + esc(T.noExports) + '</p>') + '</section>';
    }

    // ---- strings
    var st = rep.strings || {};
    var kinds = ['urls', 'ips', 'registry', 'paths', 'commands', 'crypto_wallets', 'sample'];
    if (!st[state.tab] || !st[state.tab].length) {
      state.tab = kinds.filter(function (k) { return st[k] && st[k].length; })[0] || 'urls';
    }
    var list = st[state.tab] || [];
    html += '<section class="p-card p-wide"><h2>' + esc(T.strings) + ' · ' + esc(fmt(st.total)) + '</h2><div class="p-tabs">' +
      kinds.map(function (k) {
        return '<button type="button" data-tab="' + k + '" class="' + (k === state.tab ? 'on' : '') + '">' + esc(T[k]) + '<i>' + ((st[k] || []).length) + '</i></button>';
      }).join('') + '</div>' + (list.length ? '<ul class="p-strings">' + list.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ul>' : '<p class="vk-body">' + esc(T.none) + '</p>') + '</section>';

    html += '</div>';
    root.innerHTML = html;
    bind();
  }

  function bind() {
    var T = t();
    root.querySelectorAll('[data-copy]').forEach(function (b) {
      b.onclick = function () {
        try { navigator.clipboard.writeText(b.getAttribute('data-copy')); b.textContent = T.copied; } catch (_) {}
      };
    });
    root.querySelectorAll('[data-tab]').forEach(function (b) {
      b.onclick = function () { state.tab = b.getAttribute('data-tab'); render(); };
    });
    var req = document.getElementById('reqHuman');
    if (req) req.onclick = function () {
      req.disabled = true;
      fetch(API + '/reviews/request/' + state.sha, { method: 'POST' }).then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
        .then(function (o) {
          if (o.ok && o.d.human_analysis) { state.data.human_analysis = o.d.human_analysis; render(); }
          else { req.disabled = false; document.getElementById('reqMsg').textContent = o.d.error || ''; }
        }).catch(function () { req.disabled = false; });
    };
    var key = document.getElementById('sampleKey');
    var dl = document.getElementById('sampleDl');
    if (key) { try { key.value = localStorage.getItem(KEY_STORE) || ''; } catch (_) {} }
    if (dl) dl.onclick = function () {
      var k = key.value.trim();
      try { localStorage.setItem(KEY_STORE, k); } catch (_) {}
      var note = document.getElementById('sampleNote');
      dl.disabled = true;
      fetch(API + '/sample/' + state.sha, { headers: { 'X-API-Key': k } }).then(function (r) {
        if (!r.ok) return r.json().catch(function () { return {}; }).then(function (d) { throw new Error(d.error || r.status); });
        return r.blob();
      }).then(function (blob) {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = state.sha + '.zip';
        a.click();
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
        note.textContent = T.keyNote;
      }).catch(function (e) { note.textContent = T.dlErr + ': ' + e.message; })
        .finally(function () { dl.disabled = false; });
    };
  }

  document.getElementById('fileSearch').addEventListener('submit', function (e) {
    e.preventDefault();
    var sha = input.value.trim().toLowerCase();
    history.replaceState(null, '', '?sha256=' + sha);
    load(sha);
  });
  window.addEventListener('viruskov_lang_changed', function () { render(); });
  load(shaFromUrl());
})();
