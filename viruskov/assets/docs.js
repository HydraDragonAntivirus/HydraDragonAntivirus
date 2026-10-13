/* VIRUSKOV — documentation helpers: reading progress, TOC scroll-spy, EULA contents list */
(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () {
    // 1. Reading progress bar
    var bar = document.createElement('div');
    bar.className = 'dc-progress';
    bar.setAttribute('aria-hidden', 'true');
    document.body.appendChild(bar);
    var ticking = false;
    function progress() {
      ticking = false;
      var h = document.documentElement;
      var max = h.scrollHeight - h.clientHeight;
      bar.style.setProperty('--p', max > 0 ? Math.min(1, h.scrollTop / max) : 0);
    }
    window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(progress); } }, { passive: true });
    progress();

    // 2. EULA: build a sticky contents list from the section titles
    var grid = document.querySelector('.sections-grid');
    if (grid && !document.querySelector('.eula-layout')) {
      var layout = document.createElement('div');
      layout.className = 'eula-layout';
      var toc = document.createElement('aside');
      toc.className = 'toc';
      grid.parentNode.insertBefore(layout, grid);
      layout.appendChild(toc);
      layout.appendChild(grid);

      var buildToc = function () {
        var lang = (window.ViruskovI18n && window.ViruskovI18n.getLang && window.ViruskovI18n.getLang()) || 'tr';
        var html = '<div class="toc-title">' + (lang === 'en' ? 'Contents' : 'İçindekiler') + '</div>';
        grid.querySelectorAll('.eula-card').forEach(function (card, i) {
          if (!card.id) card.id = 'b' + (i + 1);
          var t = card.querySelector('.eula-card-title');
          var label = t ? t.textContent.replace(/\s+/g, ' ').trim() : '';
          html += '<a href="#' + card.id + '">' + label.replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }) + '</a>';
        });
        toc.innerHTML = html;
        spy();
      };
      buildToc();
      window.addEventListener('viruskov_lang_changed', function () { setTimeout(buildToc, 0); });
    }

    // 3. Scroll-spy: highlight the TOC entry of the section being read
    var observer = null;
    function spy() {
      var links = Array.prototype.slice.call(document.querySelectorAll('.toc a[href^="#"]'));
      if (!links.length || !('IntersectionObserver' in window)) return;
      var map = {};
      var targets = [];
      links.forEach(function (a) {
        var id = decodeURIComponent(a.getAttribute('href').slice(1));
        var el = id && document.getElementById(id);
        if (el) { (map[id] = map[id] || []).push(a); targets.push(el); }
      });
      if (observer) observer.disconnect();
      var visible = {};
      observer = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting ? e.boundingClientRect.top : undefined; });
        var best = null, bestTop = Infinity;
        Object.keys(visible).forEach(function (id) {
          var top = visible[id];
          if (top !== undefined && top < bestTop) { bestTop = top; best = id; }
        });
        if (!best) return;
        links.forEach(function (a) { a.classList.remove('is-active'); });
        (map[best] || []).forEach(function (a) {
          a.classList.add('is-active');
          var box = a.closest('.toc');
          if (box && box.scrollHeight > box.clientHeight) {
            var r = a.getBoundingClientRect(), b = box.getBoundingClientRect();
            if (r.top < b.top || r.bottom > b.bottom) box.scrollTop += r.top - b.top - b.height / 2;
          }
        });
      }, { rootMargin: '-90px 0px -55% 0px', threshold: 0 });
      targets.forEach(function (el) { observer.observe(el); });
    }
    spy();
    window.addEventListener('viruskov_lang_changed', function () { setTimeout(spy, 0); });

    // 4. Collapsible contents on narrow screens
    var narrow = window.matchMedia('(max-width: 1060px)');
    document.querySelectorAll('.toc').forEach(function (toc) {
      if (narrow.matches) toc.classList.add('is-collapsed');
      toc.addEventListener('click', function (e) {
        if (!narrow.matches) return;
        if (e.target.closest('.toc-title')) toc.classList.toggle('is-collapsed');
        else if (e.target.closest('a')) toc.classList.add('is-collapsed');
      });
    });
  });
})();
