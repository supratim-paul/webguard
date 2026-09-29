const $ = (s, r = document) => r.querySelector(s), $$ = (s, r = document) => [...r.querySelectorAll(s)];
const R = document.documentElement;
const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} }, del: (k) => { try { localStorage.removeItem(k); } catch {} } };
if (store.get('wg-theme')) R.dataset.theme = store.get('wg-theme');
const isDark = () => R.dataset.theme ? R.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme:dark)').matches;
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function logout() { store.del('wg-token'); location.href = '/login.html'; }
async function api(p, o = {}) {
  const t = store.get('wg-token');
  const r = await fetch('/api' + p, { method: o.method || 'GET', headers: { 'Content-Type': 'application/json', ...(t ? { Authorization: 'Bearer ' + t } : {}) }, body: o.body ? JSON.stringify(o.body) : undefined });
  const j = r.status === 204 ? {} : await r.json().catch(() => ({}));
  if (r.status === 401 && o.auth) logout();
  if (!r.ok) throw new Error(j.error || 'Request failed');
  return j;
}
function toast(m) { const t = document.createElement('div'); t.className = 'toast'; t.textContent = m; document.body.append(t); requestAnimationFrame(() => t.classList.add('show')); setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 500); }, 2800); }
function count(el, T) { if (!T) { el.textContent = '0'; return; } const f = T % 1; let s = 0; const iv = setInterval(() => { s += T / 40; if (s >= T) { s = T; clearInterval(iv); } el.textContent = f ? s.toFixed(1) : Math.round(s).toLocaleString(); }, 25); }

// shared nav + footer
const path = location.pathname.replace(/\.html$/, '') || '/';
const links = [['/', 'Home'], ['/features', 'Features'], ['/dashboard', 'Dashboard']];
const nav = $('#nav');
if (nav) nav.innerHTML = `<a class="logo" href="/"><svg width="26" height="26" viewBox="0 0 24 24"><path d="M12 2l8 3v6c0 5-3.5 9-8 11-4.5-2-8-6-8-11V5z" fill="#6d7dff"/></svg>WebGuard</a>
<div class="links">${links.map(([h, t]) => `<a href="${h}" class="${path === h ? 'on' : ''}">${t}</a>`).join('')}</div>
<div class="r"><button class="tg" id="tg" aria-label="Toggle theme"><i id="ti"></i></button>${store.get('wg-token') ? '<button class="btn g" id="lo">Sign out</button>' : '<a class="btn" href="/login">Get Started</a>'}</div>`;
const ti = $('#ti'); const sync = () => { if (ti) ti.textContent = isDark() ? '☾' : '☀'; }; sync();
$('#tg') && ($('#tg').onclick = () => { const n = isDark() ? 'light' : 'dark'; R.dataset.theme = n; store.set('wg-theme', n); sync(); });
$('#lo') && ($('#lo').onclick = logout);
const ft = $('#ft'); if (ft) ft.textContent = '© 2026 WebGuard — Secure. Monitor. Stay ahead.';

// typing
const ty = $('#ty'); if (ty) { const tx = ty.textContent; ty.textContent = ''; let i = 0; (function t() { if (i <= tx.length) { ty.textContent = tx.slice(0, i++); setTimeout(t, 28); } })(); }
// shield tilt
const st = $('#stage'), sh = $('#sh');
if (st && sh) { st.onmousemove = (e) => { const b = st.getBoundingClientRect(), x = (e.clientX - b.left) / b.width - .5, y = (e.clientY - b.top) / b.height - .5; sh.style.transform = `rotateY(${x * 30}deg) rotateX(${-y * 30}deg)`; }; st.onmouseleave = () => sh.style.transform = ''; }
// particles
const cv = $('#cv');
if (cv) {
  const c = cv.getContext('2d'); let P = [];
  const rs = () => { cv.width = cv.offsetWidth; cv.height = cv.offsetHeight; P = Array.from({ length: 55 }, () => ({ x: Math.random() * cv.width, y: Math.random() * cv.height, vx: (Math.random() - .5) * .4, vy: (Math.random() - .5) * .4 })); };
  rs(); addEventListener('resize', rs);
  (function d() {
    c.clearRect(0, 0, cv.width, cv.height); const col = getComputedStyle(R).getPropertyValue('--ac').trim() || '#5b6cff'; c.fillStyle = col; c.strokeStyle = col;
    P.forEach((p, a) => { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > cv.width) p.vx *= -1; if (p.y < 0 || p.y > cv.height) p.vy *= -1; c.globalAlpha = .5; c.beginPath(); c.arc(p.x, p.y, 1.8, 0, 7); c.fill();
      for (let b = a + 1; b < P.length; b++) { const q = P[b], dd = Math.hypot(p.x - q.x, p.y - q.y); if (dd < 110) { c.globalAlpha = (1 - dd / 110) * .25; c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(q.x, q.y); c.stroke(); } } });
    requestAnimationFrame(d);
  })();
}
// reveal + static counters
const io = new IntersectionObserver((es) => es.forEach((e) => { if (!e.isIntersecting) return; e.target.classList.add('vis'); $$('[data-n]', e.target).forEach((n) => count(n, +n.dataset.n)); io.unobserve(e.target); }), { threshold: .15 });
$$('.rv').forEach((e) => io.observe(e));
