/* VIRUSKOV — daily threat list (MalwareBazaar-style) */
(function () {
  'use strict';
  var API = 'https://api.viruskov.com/api/v1';
  var L = {
    tr: { v: { malicious: 'Zararlı', suspicious: 'Şüpheli', clean: 'Temiz', possible_clean: 'Muhtemelen temiz', unknown: 'Bilinmiyor' }, human: 'insan', empty: 'Bu gün için kayıt yok.', err: 'Liste alınamadı', loading: 'Yükleniyor…' },
    en: { v: { malicious: 'Malicious', suspicious: 'Suspicious', clean: 'Clean', possible_clean: 'Possibly clean', unknown: 'Unknown' }, human: 'human', empty: 'No entries for this day.', err: 'Could not load the list', loading: 'Loading…' }
  };
  var COLORS = { malicious: 'var(--accent-red)', suspicious: 'var(--accent-amber)', clean: 'var(--accent-green)', possible_clean: '#6fcf97', unknown: 'var(--text-muted)' };
  var lang = function () { return window.ViruskovI18n ? window.ViruskovI18n.getLang() : 'tr'; };
  var t = function () { return L[lang()] || L.tr; };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };

  var dateEl = document.getElementById('feedDate');
  var allEl = document.getElementById('feedAll');
  var body = document.getElementById('feedBody');
  var dls = document.getElementById('feedDownloads');
  var last = null;

  var today = new Date().toISOString().slice(0, 10);
  var q = new URLSearchParams(location.search);
  dateEl.value = /^\d{4}-\d{2}-\d{2}$/.test(q.get('date') || '') ? q.get('date') : today;
  dateEl.max = today;
  allEl.checked = q.get('all') === '1';

  function url(fmt) {
    return API + '/feed/daily?date=' + dateEl.value + (allEl.checked ? '&all=1' : '') + (fmt ? '&format=' + fmt : '');
  }

  function paint() {
    var T = t();
    if (!last) return;
    if (!last.items || !last.items.length) { body.innerHTML = '<tr><td colspan="6" class="p-empty">' + esc(T.empty) + '</td></tr>'; return; }
    body.innerHTML = last.items.map(function (i) {
      var v = COLORS[i.verdict] ? i.verdict : 'unknown';
      var time = new Date(i.first_seen);
      return '<tr><td class="m">' + esc(isNaN(time) ? i.first_seen : time.toLocaleTimeString(lang() === 'tr' ? 'tr-TR' : 'en-US')) + '</td>' +
        '<td><span class="p-badge" style="color:' + COLORS[v] + '">' + esc(T.v[v]) + '</span>' + (i.verdict_source === 'human' ? ' <span class="p-source" style="margin-left:4px">' + esc(T.human) + '</span>' : '') + '</td>' +
        '<td>' + esc(i.threat_name || '—') + '</td>' +
        '<td>' + esc(i.file_name || '—') + '</td>' +
        '<td class="m"><a href="file/index.html?sha256=' + esc(i.sha256) + '">' + esc(i.sha256.slice(0, 16)) + '…' + esc(i.sha256.slice(-8)) + '</a></td>' +
        '<td class="m">' + esc(i.seen_count) + '</td></tr>';
    }).join('');
  }

  function load() {
    history.replaceState(null, '', '?date=' + dateEl.value + (allEl.checked ? '&all=1' : ''));
    dls.innerHTML = ['json', 'csv', 'txt'].map(function (f) { return '<a href="' + url(f) + '" target="_blank" rel="noopener">' + f.toUpperCase() + '</a>'; }).join('');
    body.innerHTML = '<tr><td colspan="6" class="p-empty">' + esc(t().loading) + '</td></tr>';
    fetch(url()).then(function (r) { return r.json(); }).then(function (d) {
      if (d.status !== 'success') throw new Error(d.error || 'error');
      last = d; paint();
    }).catch(function (e) { body.innerHTML = '<tr><td colspan="6" class="p-empty">' + esc(t().err) + ': ' + esc(e.message) + '</td></tr>'; });
  }

  dateEl.addEventListener('change', load);
  allEl.addEventListener('change', load);
  window.addEventListener('viruskov_lang_changed', paint);
  load();
})();
