/* =====================================================
   LAN Sentinel - shared script (runs on EVERY page)
   Automatically adds:
     1. Back-to-top button
     2. Previous / Next page buttons (before the footer)
     3. Active highlight on the current navbar link
     4. Scroll-reveal animation
   To add a page: add one line to PAGES below.
   Each <body> needs:  data-page="home"  data-base="" (or "../" inside /pages)
   ===================================================== */
(function () {
  'use strict';

  var PAGES = [
    { key: 'home',       title: 'Home',                 file: 'index.html',            icon: 'bi-house' },
    { key: 'about',      title: 'About the Study',      file: 'pages/about.html',      icon: 'bi-journal-text' },
    { key: 'scope',      title: 'Scope & Limitations',  file: 'pages/scope.html',      icon: 'bi-sliders2' },
    { key: 'comparison', title: 'Comparison',           file: 'pages/comparison.html', icon: 'bi-table' },
    { key: 'literature', title: 'Literature & References', file: 'pages/literature.html', icon: 'bi-book' }
  ];

  var body = document.body;
  var current = body.getAttribute('data-page') || '';
  var base = body.getAttribute('data-base') || '';

  /* 1. Back-to-top button */
  var btn = document.createElement('button');
  btn.id = 'backToTop';
  btn.type = 'button';
  btn.setAttribute('aria-label', 'Back to top');
  btn.innerHTML = '<i class="bi bi-arrow-up"></i>';
  btn.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });
  body.appendChild(btn);
  function toggleBtn() { btn.classList.toggle('show', window.scrollY > 300); }
  window.addEventListener('scroll', toggleBtn, { passive: true });
  toggleBtn();

  /* 2. Previous / Next buttons */
  var idx = PAGES.findIndex(function (p) { return p.key === current; });
  var footer = document.querySelector('footer');
  if (idx !== -1 && footer) {
    var prev = PAGES[idx - 1], next = PAGES[idx + 1];
    var wrap = document.createElement('section');
    wrap.className = 'page-pager py-4';
    wrap.setAttribute('aria-label', 'Page navigation');
    var html = '<div class="container"><div class="row g-3">';
    html += '<div class="col-md-6">' + (prev ? card(prev, 'prev') : '') + '</div>';
    html += '<div class="col-md-6">' + (next ? card(next, 'next') : '') + '</div>';
    html += '</div></div>';
    wrap.innerHTML = html;
    footer.parentNode.insertBefore(wrap, footer);
  }
  function card(p, dir) {
    var arrow = dir === 'prev' ? 'bi-arrow-left' : 'bi-arrow-right';
    var label = dir === 'prev' ? 'Previous' : 'Next';
    var inner = '<div><small>' + label + '</small><strong>' + p.title + '</strong></div>';
    var icon = '<i class="bi ' + arrow + '"></i>';
    return '<a class="pager-btn ' + dir + '" href="' + base + p.file + '">' +
      (dir === 'prev' ? icon + inner : inner + icon) + '</a>';
  }

  /* 3. Active navbar link */
  var here = (location.pathname.split('/').pop() || 'index.html').toLowerCase();
  document.querySelectorAll('.navbar .nav-link').forEach(function (a) {
    var href = (a.getAttribute('href') || '').split('#')[0].split('/').pop().toLowerCase();
    if (href && href === here) { a.classList.add('active'); a.setAttribute('aria-current', 'page'); }
    else if (a.classList.contains('active') && href !== here && !a.hasAttribute('data-keep')) { a.classList.remove('active'); a.removeAttribute('aria-current'); }
  });

  /* 4. Scroll-reveal */
  var items = document.querySelectorAll('.reveal');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { threshold: .12 });
    items.forEach(function (el) { io.observe(el); });
  } else { items.forEach(function (el) { el.classList.add('in'); }); }

  /* Year in footer */
  document.querySelectorAll('[data-year]').forEach(function (el) { el.textContent = new Date().getFullYear(); });
})();
