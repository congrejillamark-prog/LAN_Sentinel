/* =====================================================
   LAN Sentinel - Login / Sign Up (front-end demo only)
   There is no server yet, so nothing is stored or sent.
   When a backend exists, replace the redirect lines with fetch().
   ===================================================== */
(function () {
  'use strict';
  var form = document.querySelector('form[data-auth]');
  if (!form) return;
  var mode = form.getAttribute('data-auth'); /* "login" or "signup" */

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var ok = form.checkValidity();
    if (mode === 'signup') {
      var p = form.querySelector('#password'), c = form.querySelector('#confirm');
      if (p.value !== c.value) { c.setCustomValidity('Passwords do not match'); ok = false; } else { c.setCustomValidity(''); }
    }
    form.classList.add('was-validated');
    if (!ok) { var bad = form.querySelector(':invalid'); if (bad) bad.focus(); return; }
    var btn = form.querySelector('button[type=submit]');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" aria-hidden="true"></span>' + (mode === 'login' ? 'Signing in...' : 'Creating account...');
    setTimeout(function () { location.href = mode === 'login' ? 'dashboard.html' : 'login.html'; }, 700);
  });

  var c2 = form.querySelector('#confirm');
  if (c2) c2.addEventListener('input', function () { c2.setCustomValidity(''); });

  /* Show / hide password buttons */
  document.querySelectorAll('[data-toggle-pass]').forEach(function (b) {
    b.addEventListener('click', function () {
      var input = document.querySelector(b.getAttribute('data-toggle-pass'));
      var show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      b.innerHTML = '<i class="bi ' + (show ? 'bi-eye-slash' : 'bi-eye') + '"></i>';
      b.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    });
  });
})();
