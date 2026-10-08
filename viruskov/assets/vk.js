/* VIRUSKOV — shared site behaviour (header, mobile drawer, reveal-on-scroll) */
(function () {
  function ready(fn) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn);
    else fn();
  }

  ready(function () {
    var header = document.querySelector('.vk-header');
    var drawer = document.querySelector('.vk-drawer');
    var menuBtn = document.querySelector('.vk-menu-btn');

    // Header border once the page scrolls
    function onScroll() {
      if (header) header.classList.toggle('is-scrolled', window.scrollY > 8);
    }
    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });

    // Mobile drawer
    function setDrawer(open) {
      if (!drawer || !menuBtn) return;
      drawer.classList.toggle('is-open', open);
      document.body.classList.toggle('vk-locked', open);
      menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }
    if (menuBtn) {
      menuBtn.addEventListener('click', function () {
        setDrawer(!drawer.classList.contains('is-open'));
      });
    }
    if (drawer) {
      drawer.addEventListener('click', function (e) {
        if (e.target.closest('a')) setDrawer(false);
      });
    }
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') setDrawer(false);
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth > 1020) setDrawer(false);
    });

    // Reveal on scroll
    var items = document.querySelectorAll('.vk-reveal');
    if (!('IntersectionObserver' in window)) {
      items.forEach(function (el) { el.classList.add('is-in'); });
      return;
    }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) {
          entry.target.classList.add('is-in');
          io.unobserve(entry.target);
        }
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    items.forEach(function (el) { io.observe(el); });
  });
})();
