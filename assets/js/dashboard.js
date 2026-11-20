/* =====================================================
   LAN Sentinel - dashboard demo
   ALL DATA HERE IS SAMPLE DATA for the interface preview.
   Replace the arrays below (or fetch() from your backend) when the
   real detection engine is ready.
   ===================================================== */
(function () {
  'use strict';

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var hex2 = function () { return ('0' + Math.floor(Math.random() * 256).toString(16)).slice(-2).toUpperCase(); };
  var pad = function (n) { return (n < 10 ? '0' : '') + n; };
  var clock = function (d) { d = d || new Date(); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); };

  /* ---------- Sample data ---------- */
  var TYPES = {
    'Port Scan':           { icon: 'bi-radar',          sev: 'medium', msg: 'Sequential connection attempts across many ports' },
    'ARP Spoofing':        { icon: 'bi-shuffle',        sev: 'high',   msg: 'Conflicting MAC replies for the gateway IP' },
    'DoS Flooding':        { icon: 'bi-lightning-charge', sev: 'high', msg: 'Packet rate far above the learned baseline' },
    'Unauthorized Device': { icon: 'bi-hdd-network',    sev: 'medium', msg: 'MAC address not in the known-device list' }
  };

  var devices = [
    { name: 'Admin-Laptop',   ip: '192.168.1.10', mac: 'A4:83:E7:2C:11:90', status: 'known' },
    { name: 'Lab-PC-01',      ip: '192.168.1.21', mac: '3C:52:82:A1:07:5E', status: 'known' },
    { name: 'Lab-PC-02',      ip: '192.168.1.22', mac: '3C:52:82:A1:08:12', status: 'known' },
    { name: 'Office-Printer', ip: '192.168.1.40', mac: '00:1B:A9:6F:42:D3', status: 'known' },
    { name: 'File-Server',    ip: '192.168.1.5',  mac: 'B8:27:EB:90:3A:44', status: 'known' },
    { name: 'Faculty-Phone',  ip: '192.168.1.63', mac: 'F0:98:9D:5B:C2:71', status: 'known' },
    { name: 'Unknown device', ip: '192.168.1.87', mac: '02:5E:9C:44:B1:0A', status: 'unknown' }
  ];

  var now = Date.now();
  var alerts = [
    mk('Unauthorized Device', '192.168.1.87', '02:5E:9C:44:B1:0A', now - 38 * 60000, 'New'),
    mk('Port Scan',           '192.168.1.87', '02:5E:9C:44:B1:0A', now - 31 * 60000, 'New'),
    mk('ARP Spoofing',        '192.168.1.87', '02:5E:9C:44:B1:0A', now - 17 * 60000, 'Reviewed'),
    mk('DoS Flooding',        '192.168.1.87', '02:5E:9C:44:B1:0A', now - 9 * 60000,  'New')
  ];
  var seq = 100;
  function mk(type, ip, mac, t, status) {
    return { id: ++seq, type: type, ip: ip, mac: mac, time: new Date(t), sev: TYPES[type].sev, status: status || 'New' };
  }

  /* ---------- Live signal monitor (canvas, no library) ---------- */
  var BASE = { lo: 150, hi: 330 };          /* learned baseline band (sample) */
  var MAXV = 1000, N = 90, TICK = 450;      /* visible samples, ms per sample */
  var buf = [], tickNo = 0, lastTick = performance.now(), paused = false, attack = null;
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
  var cv = $('#signalCanvas'), cx = cv.getContext('2d');

  function normal(t) { return 235 + 38 * Math.sin(t / 9) + 14 * Math.sin(t / 2.3) + (Math.random() - .5) * 34; }
  function nextSample() {
    tickNo++;
    if (attack && attack.left > 0) {
      attack.left--;
      var v, k = attack.total - attack.left;
      if (attack.type === 'DoS Flooding')        v = 720 + Math.random() * 230;
      else if (attack.type === 'Port Scan')      v = k % 2 ? 470 + Math.random() * 130 : 260 + Math.random() * 60;
      else if (attack.type === 'ARP Spoofing')   v = 380 + Math.random() * 90;
      else                                       v = 350 + Math.random() * 60;
      return v;
    }
    return normal(tickNo);
  }
  for (var i = 0; i <= N; i++) buf.push(normal(++tickNo));

  function fit() {
    var dpr = window.devicePixelRatio || 1, w = cv.clientWidth, h = cv.clientHeight;
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    cx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function draw(now) {
    var W = cv.clientWidth, H = cv.clientHeight, L = 46, R = 12, T = 12, B = 24;
    var pw = W - L - R, ph = H - T - B, dx = pw / (N - 1);
    var frac = (paused || reduce) ? 0 : Math.min((now - lastTick) / TICK, 1);
    var X = function (i) { return L + (i - frac) * dx; };
    var Y = function (v) { return T + (1 - Math.min(v, MAXV) / MAXV) * ph; };
    cx.clearRect(0, 0, W, H);

    /* horizontal grid + labels */
    cx.font = '11px system-ui, sans-serif'; cx.textAlign = 'right'; cx.textBaseline = 'middle';
    for (var g = 0; g <= 4; g++) {
      var gv = (MAXV / 4) * g, gy = Y(gv);
      cx.strokeStyle = 'rgba(148,163,184,.14)'; cx.lineWidth = 1;
      cx.beginPath(); cx.moveTo(L, gy); cx.lineTo(W - R, gy); cx.stroke();
      cx.fillStyle = '#7c8db0'; cx.fillText(gv, L - 8, gy);
    }
    cx.save(); cx.beginPath(); cx.rect(L, 0, pw, H); cx.clip();

    /* moving vertical grid (scrolls with the data) */
    for (var k = 0; k <= N; k++) {
      if ((tickNo - N + k) % 10 === 0) {
        var gx = X(k); cx.strokeStyle = 'rgba(148,163,184,.10)';
        cx.beginPath(); cx.moveTo(gx, T); cx.lineTo(gx, T + ph); cx.stroke();
      }
    }
    /* baseline band + threshold */
    cx.fillStyle = 'rgba(34,211,238,.08)'; cx.fillRect(L, Y(BASE.hi), pw, Y(BASE.lo) - Y(BASE.hi));
    cx.setLineDash([6, 5]); cx.strokeStyle = 'rgba(248,113,113,.75)'; cx.lineWidth = 1;
    cx.beginPath(); cx.moveTo(L, Y(BASE.hi)); cx.lineTo(W - R, Y(BASE.hi)); cx.stroke(); cx.setLineDash([]);

    /* area under the line */
    var grad = cx.createLinearGradient(0, T, 0, T + ph);
    grad.addColorStop(0, 'rgba(34,211,238,.28)'); grad.addColorStop(1, 'rgba(34,211,238,0)');
    cx.beginPath(); cx.moveTo(X(0), T + ph);
    buf.forEach(function (v, i) { cx.lineTo(X(i), Y(v)); });
    cx.lineTo(X(buf.length - 1), T + ph); cx.closePath(); cx.fillStyle = grad; cx.fill();

    /* main line (glow) */
    cx.lineJoin = 'round'; cx.lineWidth = 2; cx.strokeStyle = '#22d3ee';
    cx.shadowColor = 'rgba(34,211,238,.9)'; cx.shadowBlur = 8;
    cx.beginPath(); buf.forEach(function (v, i) { i ? cx.lineTo(X(i), Y(v)) : cx.moveTo(X(i), Y(v)); }); cx.stroke();

    /* anomaly segments in red */
    cx.strokeStyle = '#f43f5e'; cx.shadowColor = 'rgba(244,63,94,.95)'; cx.lineWidth = 2.4;
    for (var j = 1; j < buf.length; j++) {
      if (buf[j] > BASE.hi || buf[j - 1] > BASE.hi) { cx.beginPath(); cx.moveTo(X(j - 1), Y(buf[j - 1])); cx.lineTo(X(j), Y(buf[j])); cx.stroke(); }
    }
    cx.shadowBlur = 0;

    /* pulsing marker on the strongest recent anomaly + leading dot */
    var recent = buf.length - 1, peak = -1;
    for (var m = buf.length - 1; m > buf.length - 14 && m > 0; m--) if (buf[m] > BASE.hi && (peak < 0 || buf[m] > buf[peak])) peak = m;
    if (peak > 0) {
      var ph2 = (now / 500) % 1, px = X(peak), py = Y(buf[peak]);
      cx.strokeStyle = 'rgba(244,63,94,' + (1 - ph2) + ')'; cx.lineWidth = 2;
      cx.beginPath(); cx.arc(px, py, 5 + ph2 * 14, 0, 6.2832); cx.stroke();
      cx.fillStyle = '#f43f5e'; cx.beginPath(); cx.arc(px, py, 4, 0, 6.2832); cx.fill();
    }
    var lx = X(recent), ly = Y(buf[recent]), hot = buf[recent] > BASE.hi;
    cx.fillStyle = hot ? '#f43f5e' : '#67e8f9'; cx.shadowColor = cx.fillStyle; cx.shadowBlur = 12;
    cx.beginPath(); cx.arc(lx, ly, 4, 0, 6.2832); cx.fill(); cx.shadowBlur = 0;
    cx.restore();

    cx.fillStyle = '#67e8f9'; cx.textAlign = 'left'; cx.fillText('Learned baseline (sample)', L + 6, Y(BASE.hi) - 8);
    cx.fillStyle = '#fca5a5'; cx.textAlign = 'right'; cx.fillText('Anomaly threshold ' + BASE.hi, W - R - 4, Y(BASE.hi) - 8);
    cx.fillStyle = '#7c8db0'; cx.textAlign = 'left'; cx.fillText('older', L, H - 8);
    cx.textAlign = 'right'; cx.fillText('now', W - R, H - 8);
    cx.save(); cx.translate(12, T + ph / 2); cx.rotate(-Math.PI / 2); cx.textAlign = 'center'; cx.fillText('packets / s', 0, 0); cx.restore();
  }

  function readout() {
    var v = Math.round(buf[buf.length - 1]), hot = v > BASE.hi;
    var flagged = buf.filter(function (x) { return x > BASE.hi; }).length;
    $('#sigPps').textContent = v;
    $('#sigFlag').textContent = flagged;
    var st = $('#sigStatus');
    st.textContent = hot ? 'ANOMALY DETECTED' : (paused ? 'PAUSED' : 'NORMAL');
    st.className = 'sig-chip ' + (hot ? 'sig-hot' : (paused ? 'sig-pause' : 'sig-ok'));
    $('#sigLive').classList.toggle('off', paused);
  }

  function frame(now) {
    if (!paused && now - lastTick >= TICK) {
      var steps = Math.min(Math.floor((now - lastTick) / TICK), 5);
      for (var s = 0; s < steps; s++) { buf.push(nextSample()); buf.shift(); }
      lastTick = now; readout();
    }
    draw(now);
    requestAnimationFrame(frame);
  }

  function startAttack(type) {
    var total = type === 'DoS Flooding' ? 16 : type === 'Port Scan' ? 14 : type === 'ARP Spoofing' ? 12 : 8;
    attack = { type: type, left: total, total: total };
  }
  window.addEventListener('resize', fit);
  fit(); readout(); requestAnimationFrame(frame);

  /* ---------- Renderers ---------- */
  var filter = 'all';

  function renderStats() {
    var known = devices.filter(function (d) { return d.status === 'known'; }).length;
    $('#statDevices').textContent = devices.length;
    $('#statUnknown').textContent = devices.length - known;
    $('#statAlerts').textContent = alerts.length;
    $('#statHigh').textContent = alerts.filter(function (a) { return a.sev === 'high' && a.status === 'New'; }).length;
    $('#alertCount').textContent = alerts.length;
  }

  function renderAlerts(newId) {
    var rows = alerts.filter(function (a) { return filter === 'all' || a.type === filter; });
    var tb = $('#alertBody');
    if (!rows.length) { tb.innerHTML = '<tr><td colspan="6" class="text-center text-muted py-4">No alerts for this filter.</td></tr>'; return; }
    tb.innerHTML = rows.map(function (a) {
      var t = TYPES[a.type];
      return '<tr class="' + (a.id === newId ? 'alert-new' : '') + '">' +
        '<td class="text-nowrap">' + clock(a.time) + '</td>' +
        '<td class="text-nowrap"><i class="bi ' + t.icon + ' text-brand me-1"></i>' + a.type + '<div class="small text-muted d-none d-xl-block">' + t.msg + '</div></td>' +
        '<td><code>' + a.ip + '</code><div class="small text-muted">' + a.mac + '</div></td>' +
        '<td><span class="badge sev-badge-' + a.sev + '">' + a.sev.charAt(0).toUpperCase() + a.sev.slice(1) + '</span></td>' +
        '<td><span class="badge text-bg-' + (a.status === 'New' ? 'warning' : 'success') + '">' + a.status + '</span></td>' +
        '<td class="text-end">' + (a.status === 'New' ? '<button class="btn btn-sm btn-outline-secondary" data-review="' + a.id + '">Mark reviewed</button>' : '<i class="bi bi-check2-circle text-success"></i>') + '</td></tr>';
    }).join('');
  }

  function renderDevices() {
    $('#deviceBody').innerHTML = devices.map(function (d, i) {
      var known = d.status === 'known';
      return '<tr><td class="fw-semibold">' + d.name + '</td><td><code>' + d.ip + '</code></td><td class="d-none d-md-table-cell"><code>' + d.mac + '</code></td>' +
        '<td><span class="badge text-bg-' + (known ? 'success' : 'danger') + '">' + (known ? 'Known' : 'Unknown') + '</span></td>' +
        '<td class="text-end">' + (known ? '' : '<button class="btn btn-sm btn-brand" data-trust="' + i + '">Trust device</button>') + '</td></tr>';
    }).join('');
  }

  function toast(msg) {
    var el = $('#liveStatus');
    el.textContent = msg;
    var t = $('#demoToast');
    $('.toast-body', t).textContent = msg;
    bootstrap.Toast.getOrCreateInstance(t, { delay: 3500 }).show();
  }

  /* ---------- Events ---------- */
  document.addEventListener('click', function (e) {
    var r = e.target.closest('[data-review]');
    if (r) { var id = +r.getAttribute('data-review'); alerts.forEach(function (a) { if (a.id === id) a.status = 'Reviewed'; }); renderAlerts(); renderStats(); return; }
    var tr = e.target.closest('[data-trust]');
    if (tr) { var d = devices[+tr.getAttribute('data-trust')]; d.status = 'known'; d.name = 'Trusted device'; renderDevices(); renderStats(); toast('Device ' + d.mac + ' added to the known-device list.'); return; }
    var f = e.target.closest('[data-filter]');
    if (f) { filter = f.getAttribute('data-filter'); $$('[data-filter]').forEach(function (b) { b.classList.toggle('active', b === f); }); renderAlerts(); }
  });

  $('#simulateBtn').addEventListener('click', function () {
    var keys = Object.keys(TYPES), pick = $('#attackType').value;
    var type = pick === 'random' ? keys[Math.floor(Math.random() * keys.length)] : pick;
    var a = mk(type, '192.168.1.' + (10 + Math.floor(Math.random() * 200)), '02:' + [1, 2, 3, 4, 5].map(hex2).join(':'), Date.now(), 'New');
    alerts.unshift(a);
    startAttack(type);
    if (paused) { paused = false; $('#pauseBtn').innerHTML = '<i class="bi bi-pause-fill me-1"></i>Pause'; }
    renderAlerts(a.id); renderStats();
    toast('Simulated alert: ' + type + ' from ' + a.ip);
  });

  $('#pauseBtn').addEventListener('click', function () {
    paused = !paused; lastTick = performance.now();
    this.innerHTML = paused ? '<i class="bi bi-play-fill me-1"></i>Resume' : '<i class="bi bi-pause-fill me-1"></i>Pause';
    readout();
  });

  $('#resetBtn').addEventListener('click', function () { location.reload(); });

  /* Sidebar highlight: click sets it at once; scrolling follows the section in view */
  var links = $$('.sidebar .nav-link[href^="#"], #mobileMenu .nav-link[href^="#"]');
  var secs = $$('.dash-section');
  var lock = 0;
  function setActive(id) { links.forEach(function (l) { l.classList.toggle('active', l.getAttribute('href') === '#' + id); }); }
  function spy() {
    if (Date.now() < lock) return;
    var y = window.scrollY + 120, cur = secs[0].id;
    secs.forEach(function (s) { if (s.offsetTop <= y) cur = s.id; });
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = secs[secs.length - 1].id;
    setActive(cur);
  }
  links.forEach(function (l) {
    l.addEventListener('click', function () { setActive(l.getAttribute('href').slice(1)); lock = Date.now() + 900; });
  });
  window.addEventListener('scroll', spy, { passive: true });
  spy();
  /* Close the mobile menu after choosing a link */
  $$('#mobileMenu .nav-link[href^="#"]').forEach(function (l) {
    l.addEventListener('click', function () { var o = bootstrap.Offcanvas.getInstance($('#mobileMenu')); if (o) o.hide(); });
  });

  /* Init */
  renderAlerts(); renderDevices(); renderStats();
})();
