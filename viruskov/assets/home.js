/* VIRUSKOV — homepage behaviour: kernel console demo, live telemetry, hash lookup */
(function () {
  'use strict';
  var API = 'https://api.viruskov.com/api/v1';
  var T = function (k, fb) {
    var v = window.ViruskovI18n ? window.ViruskovI18n.t(k) : null;
    return v == null ? fb : v;
  };
  var lang = function () { return window.ViruskovI18n ? window.ViruskovI18n.getLang() : 'tr'; };
  var fmt = function (n) { return Number(n || 0).toLocaleString(lang() === 'tr' ? 'tr-TR' : 'en-US'); };
  var esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  };

  /* ---------------- Kernel console demo ---------------- */
  var SCRIPT = [
    ['', 't', 'PID 4412', 'proc', 'invoice_viewer.exe', 'spawn'],
    ['', '', 'IRP_MJ_READ', 'op', 'C:\\Users\\eu\\Documents\\tez.docx', '64 KiB'],
    ['', '', 'IRP_MJ_WRITE', 'op', 'C:\\Users\\eu\\Documents\\tez.docx', 'H 7.98'],
    ['cnt', '', 'distinctCounter', 'op', 'target 1 / 3', '0.4s'],
    ['', '', 'MAP_WRITE', 'op', 'C:\\Users\\eu\\Pictures\\ada.jpg', 'H 7.97'],
    ['cnt', '', 'distinctCounter', 'op', 'target 2 / 3', '1.1s'],
    ['', '', 'SET_INFORMATION', 'op', 'butce.xlsx  \u2192  butce.xlsx.lck', 'rename'],
    ['cnt', '', 'distinctCounter', 'op', 'target 3 / 3  \u00b7  window 60s', '1.9s'],
    ['sep'],
    ['alert', '', 'MLE_RANSOM_BEHAVIOR', 'op', '9/9 filters \u00b7 destination OUT', 'MATCH', 0],
    ['ok', '', 'KILL', 'op', 'IOCTL MESSAGE_KILL_ONLY_GID 4412', 'OK', 1],
    ['ok', '', 'QUARANTINE', 'op', 'invoice_viewer.exe', 'OK', 2],
    ['ok', '', 'ROLLBACK', 'op', '3 files \u2190 HydraDragonBackups', 'OK', 3]
  ];

  function stamp(base, ms) {
    var d = new Date(base.getTime() + ms);
    var p = function (n, l) { return String(n).padStart(l || 2, '0'); };
    return p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()) + '.' + p(d.getMilliseconds(), 3);
  }

  function runConsole() {
    var body = document.getElementById('consoleBody');
    var steps = document.querySelectorAll('#consoleSteps span');
    if (!body) return;
    var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var maxLines = 14;

    function line(row, base, i) {
      var el = document.createElement('div');
      if (row[0] === 'sep') { el.className = 'h-line sep'; return el; }
      el.className = 'h-line' + (row[0] ? ' ' + row[0] : '');
      el.innerHTML =
        '<span class="t">' + stamp(base, i * 173) + '</span>' +
        '<span class="op">' + esc(row[2]) + '</span>' +
        '<span>' + esc(row[4]) + '</span>' +
        '<span class="v">' + esc(row[5] || '') + '</span>';
      return el;
    }

    function setStep(n) {
      steps.forEach(function (s, idx) {
        s.classList.toggle('is-done', n >= 0 && idx < n);
        s.classList.toggle('is-on', idx === n);
      });
      if (n === 4) steps.forEach(function (s) { s.classList.remove('is-on'); s.classList.add('is-done'); });
    }

    if (reduce) {
      var b = new Date();
      SCRIPT.forEach(function (r, i) { body.appendChild(line(r, b, i)); });
      setStep(4);
      return;
    }

    var i = 0, base = new Date();
    function tick() {
      if (i === 0) { base = new Date(); setStep(-1); }
      if (i < SCRIPT.length) {
        var row = SCRIPT[i];
        body.appendChild(line(row, base, i));
        while (body.children.length > maxLines) body.removeChild(body.firstChild);
        if (typeof row[6] === 'number') setStep(row[6]);
        if (i === SCRIPT.length - 1) setStep(4);
        var delay = row[0] === 'alert' ? 900 : row[0] === 'ok' ? 650 : row[0] === 'sep' ? 300 : 520;
        i++;
        setTimeout(tick, delay);
      } else {
        setTimeout(function () {
          body.style.transition = 'opacity .5s';
          body.style.opacity = '0';
          setTimeout(function () {
            body.innerHTML = '';
            body.style.opacity = '1';
            i = 0;
            tick();
          }, 550);
        }, 4200);
      }
    }
    setTimeout(tick, 600);
  }

  /* ---------------- Live telemetry ---------------- */
  var lastTelemetry = null;
  function paintTelemetry() {
    var t = lastTelemetry;
    if (!t) return;
    var v = t.verdicts || {};
    var m = +v.malicious || 0, s = +v.suspicious || 0, c = +v.clean || 0, pc = +v.possible_clean || 0, u = +v.unknown || 0;
    var total = m + s + c + pc + u;
    document.querySelectorAll('.js-total-hashes').forEach(function (el) { el.textContent = fmt(t.total_unique_hashes); });
    var set = function (id, val) { var el = document.getElementById(id); if (el) el.textContent = val; };
    set('tiMalicious', fmt(m)); set('tiSuspicious', fmt(s)); set('tiClean', fmt(c)); set('tiPossibleClean', fmt(pc)); set('tiUnknown', fmt(u));
    if (total > 0) {
      var pct = function (x) { return (x / total) * 100; };
      [['Malicious', m], ['Suspicious', s], ['Clean', c], ['PossibleClean', pc], ['Unknown', u]].forEach(function (p) {
        var bar = document.getElementById('bar' + p[0]);
        if (bar) bar.style.width = pct(p[1]).toFixed(2) + '%';
        set('pct' + p[0], '%' + pct(p[1]).toFixed(1));
      });
    }
  }

  function setApiState(ok) {
    document.querySelectorAll('.js-api-dot').forEach(function (d) { d.classList.toggle('is-off', !ok); });
    document.querySelectorAll('.js-api-status').forEach(function (d) {
      d.textContent = ok ? 'api.viruskov.com' : T('h.i.offline', 'api.viruskov.com · bağlantı yok');
    });
  }

  function pollTelemetry() {
    fetch(API + '/insights/stats').then(function (r) { return r.ok ? r.json() : null; }).then(function (data) {
      if (data && data.status === 'success' && data.telemetry) {
        lastTelemetry = data.telemetry;
        paintTelemetry();
        setApiState(true);
      } else setApiState(false);
    }).catch(function () { setApiState(false); });
  }

  /* ---------------- Hash lookup ---------------- */
  var VERDICT = {
    malicious: ['var(--accent-red)', 'h.v.mal', 'Zararlı'],
    suspicious: ['var(--accent-amber)', 'h.v.sus', 'Şüpheli'],
    clean: ['var(--accent-green)', 'h.v.cln', 'Temiz'],
    possible_clean: ['#6fcf97', 'h.v.pcl', 'Muhtemelen temiz'],
    unknown: ['var(--text-muted)', 'h.v.unk', 'Bilinmiyor']
  };

  function dur(sec) {
    if (sec == null) return '—';
    var tr = lang() === 'tr';
    if (sec < 60) return sec + (tr ? ' sn' : ' s');
    if (sec < 3600) return Math.round(sec / 60) + (tr ? ' dk' : ' min');
    if (sec < 86400) return (sec / 3600).toFixed(1).replace('.0', '') + (tr ? ' sa' : ' h');
    return (sec / 86400).toFixed(1).replace('.0', '') + (tr ? ' gün' : ' d');
  }
  function since(iso) {
    var t = Date.parse(iso);
    return isNaN(t) ? null : Math.max(0, Math.round((Date.now() - t) / 1000));
  }
  function badge(v) {
    var x = VERDICT[v] || VERDICT.unknown;
    return '<span class="r-badge" style="color:' + x[0] + '">' + esc(T(x[1], x[2]).toUpperCase()) + '</span>';
  }
  function vtLink(sha) {
    return '<a class="h-vt" href="file/index.html?sha256=' + esc(sha) + '">' + esc(T('h.ha.report', 'Tam rapor')) + ' &rarr;</a>' +
      '<a class="h-vt h-vt2" href="https://www.virustotal.com/gui/file/' + esc(sha) + '" target="_blank" rel="noopener">VirusTotal &#8599;</a>';
  }

  /* Human analysis block inside a lookup result */
  function humanBlock(h, sha, canRequest) {
    if (h && h.status === 'completed' && h.verdict) {
      return '<div class="h-human">' +
        '<div class="h-human-top"><span class="h-human-k">' + esc(T('h.ha.human', 'İnsan analizi')) + '</span>' + badge(h.verdict) +
        (h.threat_name ? '<b>' + esc(h.threat_name) + '</b>' : '') + '</div>' +
        (h.note ? '<p>' + esc(h.note) + '</p>' : '') +
        '<div class="h-human-meta">' + (h.analyst ? esc(h.analyst) + ' · ' : '') +
        esc(T('h.ha.resp', 'yanıt')) + ' ' + dur(h.response_secs) +
        (h.timed && h.analysis_secs != null ? ' · ' + esc(T('h.ha.analysis', 'analiz')) + ' ' + dur(h.analysis_secs) : '') +
        (h.reviewed_at ? ' · ' + esc(new Date(h.reviewed_at).toLocaleString()) : '') + '</div></div>';
    }
    if (h && h.status === 'pending' && h.started_at) {
      return '<div class="h-human is-pending"><span class="h-human-k">' + esc(T('h.ha.inprogress', 'Analist inceliyor')) + '</span>' +
        '<span>' + (h.started_by ? esc(h.started_by) + ' · ' : '') + dur(since(h.started_at)) + '</span></div>';
    }
    if (h && h.status === 'pending') {
      return '<div class="h-human is-pending"><span class="h-human-k">' + esc(T('h.ha.queued', 'İnsan analizi kuyruğunda')) + '</span>' +
        '<span>' + dur(since(h.requested_at)) + ' ' + esc(T('h.ha.waiting', 'bekliyor')) + '</span></div>';
    }
    if (canRequest) {
      return '<div class="h-human is-ask"><button type="button" class="vk-btn vk-btn-ghost" data-request="' + esc(sha) + '">' +
        esc(T('h.ha.request', 'İnsan analizi iste')) + '</button><span class="h-small h-dim">' + esc(T('h.ha.override', 'Analist kararı motorun kararından önce gelir.')) + '</span></div>';
    }
    return '';
  }

  function row(k, fb, val) {
    return '<div class="r-row"><b>' + esc(T(k, fb)) + '</b><span>' + val + '</span></div>';
  }

  function initLookup() {
    var form = document.getElementById('lookupForm');
    var input = document.getElementById('tiHashInput');
    var box = document.getElementById('tiResultBox');
    if (!form || !input || !box) return;

    input.addEventListener('input', function () { input.classList.remove('is-bad'); });

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var hash = input.value.trim().toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(hash)) {
        input.classList.add('is-bad');
        box.hidden = false;
        box.innerHTML = '<span style="color:var(--accent-red)">' + esc(T('h.i.bad_hash', '64 karakterlik geçerli bir SHA-256 girin.')) + '</span>';
        return;
      }
      box.hidden = false;
      box.innerHTML = '<span>' + esc(T('h.i.searching', 'Telemetri ağında aranıyor…')) + '</span>';

      fetch(API + '/insights/' + hash).then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) { return { res: res, data: data }; });
      }).then(function (o) {
        var res = o.res, data = o.data || {};
        var human = data.human_analysis || null;
        if (res.ok && data.status === 'success') {
          var html = '<div class="r-head">' + badge(data.verdict) +
            (data.verdict_source === 'human' ? '<span class="h-human-k">' + esc(T('h.ha.human', 'İnsan analizi')) + '</span>' :
              '<span>' + esc(T('h.i.score', 'Skor')) + ' ' + esc(data.score) + '/100</span>') + vtLink(hash) + '</div>';
          html += humanBlock(human, hash, true);
          if (data.verdict_source === 'human' && data.engine_verdict) html += row('h.ha.engine', 'Motor', badge(data.engine_verdict));
          if (data.threat_name) html += row('h.i.sig', 'İmza', '<span style="color:var(--accent-red)">' + esc(data.threat_name) + '</span>');
          html += row('h.i.prev', 'Yayılım', esc(String(data.prevalence || 'unknown').toUpperCase()) + ' · ' + fmt(data.seen_count) + ' ' + esc(T('h.i.sightings', 'gözlem')));
          if (data.first_seen) html += row('h.i.first', 'İlk görülme', esc(new Date(data.first_seen).toLocaleString()));
          if (data.last_seen) html += row('h.i.last', 'Son görülme', esc(new Date(data.last_seen).toLocaleString()));
          if (data.file_names && data.file_names.length) html += row('h.i.names', 'Dosya adları', esc(data.file_names.join(', ')));
          if (data.file_size) html += row('h.i.size', 'Boyut', fmt(data.file_size) + ' B');
          box.innerHTML = html;
        } else if (res.status === 429) {
          box.innerHTML = '<span style="color:var(--accent-amber)">' +
            esc(T('h.i.rate', 'Sorgu sınırı aşıldı (10/dk). Lütfen biraz sonra tekrar deneyin.')) + '</span>';
        } else if (human) {
          box.innerHTML = '<div class="r-head">' + badge(data.verdict) + vtLink(hash) + '</div>' + humanBlock(human, hash, false);
        } else {
          box.innerHTML = '<div class="r-head"><span class="r-badge" style="color:var(--text-muted)">NOT SEEN</span>' + vtLink(hash) + '</div>' +
            '<span>' + esc(T('h.i.notseen', 'Bu hash henüz ağda görülmedi. Dosyayı canlı tarayıcıya yükleyerek ilk analizi başlatabilirsiniz.')) + '</span>' +
            ' <a href="scan/index.html" style="color:var(--text-main)">' + esc(T('h.i.goscan', 'Tarayıcıyı aç')) + ' &rarr;</a>';
        }
      }).catch(function (err) {
        box.innerHTML = '<span style="color:var(--accent-red)">' + esc(T('h.i.neterr', 'Bağlantı hatası')) + ': ' + esc(err.message) + '</span>';
      });
    });
  }

  function initRequest() {
    var box = document.getElementById('tiResultBox');
    if (!box) return;
    box.addEventListener('click', function (e) {
      var btn = e.target.closest('[data-request]');
      if (!btn) return;
      var sha = btn.getAttribute('data-request');
      btn.disabled = true;
      fetch(API + '/reviews/request/' + sha, { method: 'POST' }).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, d: d }; });
      }).then(function (o) {
        var wrap = btn.parentNode;
        if (o.ok && o.d.human_analysis) {
          wrap.outerHTML = humanBlock(o.d.human_analysis, sha, false) ||
            '<div class="h-human is-pending"><span class="h-human-k">' + esc(T('h.ha.requested', 'İnsan analizi kuyruğuna eklendi.')) + '</span></div>';
          loadDesk();
        } else {
          btn.disabled = false;
          wrap.querySelector('.h-small').textContent = T('h.ha.req_fail', 'Kuyruğa eklenemedi') + (o.d.error ? ': ' + o.d.error : '');
        }
      }).catch(function () { btn.disabled = false; });
    });
  }

  /* Analyst desk: response times + latest published verdicts */
  var lastDesk = null;
  function paintDesk() {
    var d = lastDesk;
    if (!d) return;
    var st = d.stats || {};
    var set = function (id, v) { var el = document.getElementById(id); if (el) el.textContent = v; };
    set('haAvg', dur(st.avg_response_secs));
    set('haAnalysis', dur(st.avg_analysis_secs));
    set('haActive', fmt(st.in_progress || 0));
    set('haPending', fmt(st.pending || 0));
    set('haDay', fmt(st.completed_24h || 0));
    var list = document.getElementById('haList');
    if (!list || !d.recent || !d.recent.length) return;
    list.innerHTML = d.recent.slice(0, 8).map(function (r) {
      var ago = since(r.reviewed_at);
      return '<li><div class="h-desk-row">' + badge(r.verdict) +
        (r.threat_name ? '<b>' + esc(r.threat_name) + '</b>' : '') +
        '<a class="h-desk-hash" href="file/index.html?sha256=' + esc(r.sha256) + '">' +
        esc(r.sha256.slice(0, 12) + '…' + r.sha256.slice(-6)) + ' &rarr;</a></div>' +
        (r.note ? '<p>' + esc(r.note) + '</p>' : '') +
        '<div class="h-desk-meta">' + (r.analyst ? esc(r.analyst) + ' · ' : '') + esc(T('h.ha.resp', 'yanıt')) + ' ' + dur(r.response_secs) +
        (r.timed && r.analysis_secs != null ? ' · ' + esc(T('h.ha.analysis', 'analiz')) + ' ' + dur(r.analysis_secs) : '') +
        (ago != null ? ' · ' + dur(ago) + ' ' + esc(T('h.ha.ago', 'önce')) : '') + '</div></li>';
    }).join('');
  }
  function loadDesk() {
    fetch(API + '/reviews?limit=8').then(function (r) { return r.ok ? r.json() : null; }).then(function (d) {
      if (d && d.status === 'success') { lastDesk = d; paintDesk(); }
    }).catch(function () {});
  }

  function init() {
    runConsole();
    initLookup();
    initRequest();
    pollTelemetry();
    loadDesk();
    setInterval(pollTelemetry, 15000);
    setInterval(loadDesk, 60000);
    window.addEventListener('viruskov_lang_changed', function () { paintTelemetry(); paintDesk(); });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
