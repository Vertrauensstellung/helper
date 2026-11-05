/* subtrack dashboard – dependency-free single page app.
 *
 * Security: everything that comes from scans (titles, headers, hosts, tags) is attacker-controlled.
 * It is only ever rendered through h()/textContent – never innerHTML – and links to targets are
 * restricted to http(s). The CSP (script-src 'self') blocks inline scripts on top of that. */
'use strict';

// =============================================================================================
// DOM helpers
// =============================================================================================
const $ = (sel, root = document) => root.querySelector(sel);
const SVGNS = 'http://www.w3.org/2000/svg';

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  setProps(el, props);
  return append(el, children);
}
function sv(tag, props, ...children) {
  const el = document.createElementNS(SVGNS, tag);
  setProps(el, props);
  return append(el, children);
}
function setProps(el, props) {
  if (!props) return;
  for (const [k, v] of Object.entries(props)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.setAttribute('class', v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'vars') for (const [name, val] of Object.entries(v)) el.style.setProperty(name, val);
    else if (k === 'style') Object.assign(el.style, v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
}
function append(el, ...children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
function replace(el, ...children) { return append(clear(el), children); }

const ICONS = {
  overview: 'M4 4h7v7H4z|M13 4h7v7h-7z|M4 13h7v7H4z|M13 13h7v7h-7z',
  assets: 'M12 3 3 8l9 5 9-5-9-5Z|M3 12.5l9 5 9-5|M3 16.5l9 5 9-5',
  changes: 'M3 12h4l3-8 4 16 3-8h4',
  scans: 'M21 12a9 9 0 1 1-9-9|M17 12a5 5 0 1 1-5-5|M12 12l7-7',
  domains: 'M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18Z|M3.5 9h17|M3.5 15h17|M12 3c2.8 3 2.8 15 0 18|M12 3c-2.8 3-2.8 15 0 18',
  tags: 'M3 12V4a1 1 0 0 1 1-1h8l9 9-9 9-9-9Z|M7.5 7.5h.01',
  search: 'M11 4a7 7 0 1 0 0 14 7 7 0 1 0 0-14Z|M20 20l-4-4',
  plus: 'M12 5v14|M5 12h14',
  external: 'M14 4h6v6|M20 4l-9 9|M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5',
  copy: 'M9 9h10v10H9z|M5 15V5h10',
  close: 'M6 6l12 12|M18 6 6 18',
  chevronDown: 'M6 9l6 6 6-6', chevronRight: 'M9 6l6 6-6 6', chevronLeft: 'M15 6l-6 6 6 6', chevronUp: 'M6 15l6-6 6 6',
  sun: 'M12 8a4 4 0 1 0 0 8 4 4 0 1 0 0-8Z|M12 2v2|M12 20v2|M4.9 4.9l1.4 1.4|M17.7 17.7l1.4 1.4|M2 12h2|M20 12h2|M4.9 19.1l1.4-1.4|M17.7 6.3l1.4-1.4',
  moon: 'M20 14.5A8 8 0 1 1 9.5 4a6.5 6.5 0 0 0 10.5 10.5Z',
  download: 'M12 4v11|M7 10l5 5 5-5|M5 20h14',
  filter: 'M4 5h16l-6 8v6l-4-2v-4Z',
  check: 'M5 12.5l4.5 4.5L19 7',
  expand: 'M15 4h5v5|M9 20H4v-5|M20 4l-6 6|M4 20l6-6',
  menu: 'M4 6h16|M4 12h16|M4 18h16',
  keyboard: 'M3 7h18v10H3z|M7 11h.01|M11 11h.01|M15 11h.01|M8 14h8',
  bookmark: 'M6 4h12v16l-6-4-6 4Z',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7|M20 4v7h-7',
  trash: 'M4 7h16|M9 7V4h6v3|M6 7l1 13h10l1-13',
  alert: 'M12 4 2.5 20h19L12 4Z|M12 10v4|M12 17h.01',
  info: 'M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18Z|M12 11v5|M12 8h.01',
  lock: 'M6 11h12v9H6z|M8 11V8a4 4 0 0 1 8 0v3',
  globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18Z|M3 12h18|M12 3c3 3.5 3 14.5 0 18',
  server: 'M4 4h16v7H4z|M4 13h16v7H4z|M8 7.5h.01|M8 16.5h.01',
  density: 'M4 5h16|M4 10h16|M4 15h16|M4 20h16',
  arrowRight: 'M5 12h14|M13 6l6 6-6 6',
  clock: 'M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18Z|M12 7v5l3 2',
  layers: 'M12 3 3 8l9 5 9-5-9-5Z|M3 16l9 5 9-5',
};
function icon(name, cls = '') {
  const el = sv('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.8', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: `icon ${cls}`, 'aria-hidden': 'true' });
  for (const d of (ICONS[name] || '').split('|')) el.appendChild(sv('path', { d }));
  return el;
}

// =============================================================================================
// formatting, storage, api
// =============================================================================================
const store = {
  get(key, fallback) { try { const v = localStorage.getItem('subtrack:' + key); return v === null ? fallback : JSON.parse(v); } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem('subtrack:' + key, JSON.stringify(value)); } catch { /* private mode etc. */ } },
};
const num = (n) => (n ?? 0).toLocaleString();
function compact(n) {
  n = n ?? 0;
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1).replace(/\.0$/, '') + 'M';
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(n >= 1e5 ? 0 : 1).replace(/\.0$/, '') + 'K';
  return n.toLocaleString();
}
const pct = (a, b) => (b ? Math.round((a / b) * 100) : 0);
function parseTs(ts) { if (!ts) return null; const d = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(ts) ? ts : ts + 'Z'); return isNaN(d) ? null : d; }
function fmtDateTime(ts) {
  const d = parseTs(ts); if (!d) return '–';
  return d.toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function shortDate(ts) {
  const d = parseTs(ts); if (!d) return '–';
  return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
}
function fmtDate(ts) { const d = parseTs(ts); return d ? d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '–'; }
function fmtTime(ts) { const d = parseTs(ts); return d ? d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }) : ''; }
function utcTitle(ts) { const d = parseTs(ts); return d ? d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : ''; }
function rel(ts) {
  const d = parseTs(ts); if (!d) return '–';
  const s = (Date.now() - d.getTime()) / 1000;
  const fut = s < 0; const a = Math.abs(s);
  let out;
  if (a < 45) return fut ? 'in a moment' : 'just now';
  if (a < 3600) out = `${Math.round(a / 60)}m`;
  else if (a < 86400) out = `${Math.round(a / 3600)}h`;
  else if (a < 86400 * 45) out = `${Math.round(a / 86400)}d`;
  else return shortDate(ts);
  return fut ? `in ${out}` : `${out} ago`;
}
function when(ts) { return h('span', { title: utcTitle(ts) }, rel(ts)); }
function duration(a, b) {
  const s = (parseTs(b) - parseTs(a)) / 1000; if (!isFinite(s) || s < 0) return '–';
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
  return `${Math.floor(s / 86400)}d ${Math.floor((s % 86400) / 3600)}h`;
}
function daysUntil(ts) { const d = parseTs(ts); return d ? Math.floor((d - Date.now()) / 86400e3) : null; }
function dayKey(ts) { const d = parseTs(ts); return d ? `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}` : ''; }
function dayLabel(key) {
  const today = dayKey(new Date().toISOString());
  const y = new Date(); y.setDate(y.getDate() - 1);
  if (key === today) return 'Today';
  if (key === dayKey(y.toISOString())) return 'Yesterday';
  const [Y, M, D] = key.split('-').map(Number);
  const d = new Date(Y, M - 1, D);
  return d.toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: Y === new Date().getFullYear() ? undefined : 'numeric' });
}
function shortDay(iso) { const [Y, M, D] = iso.split('-').map(Number); return new Date(Y, M - 1, D).toLocaleDateString(undefined, { day: 'numeric', month: 'short' }); }
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function safeUrl(url) { try { const u = new URL(url); return ['http:', 'https:'].includes(u.protocol) ? u.href : null; } catch { return null; } }
function extLink(url, children, cls) {
  const href = safeUrl(url);
  return href ? h('a', { href, target: '_blank', rel: 'noopener noreferrer', class: cls, title: href, onclick: (e) => e.stopPropagation() }, children ?? url) : h('span', null, children ?? url ?? '');
}
function copy(text, what = 'Copied') { navigator.clipboard.writeText(text).then(() => toast(what), () => toast('Clipboard not available', true)); }

function toParams(obj) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(obj || {})) {
    if (Array.isArray(v)) v.forEach((x) => { if (x !== '' && x != null) p.append(k, x); });
    else if (v !== '' && v !== null && v !== undefined && v !== false) p.set(k, v);
  }
  return p;
}
const qs = (obj) => { const s = toParams(obj).toString(); return s ? '?' + s : ''; };

async function api(path, { method = 'GET', body } = {}) {
  const opts = { method, headers: { 'X-Subtrack': '1' } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch { /* not json */ }
    throw new Error(msg);
  }
  return res.json();
}

// =============================================================================================
// small components
// =============================================================================================
function toast(msg, isError = false) {
  const el = h('div', { class: 'toast' + (isError ? ' error' : '') }, icon(isError ? 'alert' : 'check'), h('span', null, msg));
  $('#toasts').append(el);
  setTimeout(() => el.remove(), isError ? 6500 : 2800);
}
const STATUS_LABEL = { active: 'Active', offline: 'Offline' };
function statusEl(status, title) { return h('span', { class: `status ${status}`, title }, h('span', { class: 'dot' }), STATUS_LABEL[status] || status); }
const EV_LABEL = { new: 'New', changed: 'Changed', offline: 'Went offline', back_online: 'Back online' };
const EV_ORDER = ['offline', 'new', 'changed', 'back_online'];   // validated palette order (stacks, legends)
function evEl(type) { return h('span', { class: `ev ${type}` }, EV_LABEL[type] || type); }
function pill(status, title) { return h('span', { class: `pill ${status}`, title }, h('span', { class: 'dot' }), status.replace('_', ' ')); }
function codeEl(code) {
  if (code === null || code === undefined) return h('span', { class: 'muted' }, '–');
  return h('span', { class: `code c${String(code)[0]}` }, code);
}
function tagChip(tag, onRemove) {
  return h('span', { class: 'chip tag', vars: { '--tag': tag.color || '#6b7280' }, title: tag.name }, tag.name,
    onRemove ? h('button', { 'aria-label': `Remove tag ${tag.name}`, onclick: (e) => { e.stopPropagation(); onRemove(); } }, icon('close')) : null);
}
function chips(items, max = 3, onClick) {
  if (!items || !items.length) return h('span', { class: 'muted' }, '–');
  const out = items.slice(0, max).map((t) => h(onClick ? 'button' : 'span', { class: 'chip' + (onClick ? ' link' : ''), title: t, onclick: onClick ? (e) => { e.stopPropagation(); onClick(t); } : null }, t));
  if (items.length > max) out.push(h('span', { class: 'chip', title: items.slice(max).join(', ') }, `+${items.length - max}`));
  return h('div', { class: 'cell-chips' }, out);
}
function selectEl(options, value, onchange, attrs = {}) {
  return h('select', { onchange: (e) => onchange(e.target.value), ...attrs },
    options.map(([v, label]) => h('option', { value: v, selected: String(v) === String(value ?? '') }, label)));
}
function seg(options, value, onchange, attrs = {}) {
  return h('div', { class: 'seg', role: 'group', ...attrs }, options.map(([v, label, n]) =>
    h('button', { class: String(v) === String(value) ? 'on' : '', 'aria-pressed': String(String(v) === String(value)), onclick: () => onchange(v) }, label, n !== undefined ? h('span', { class: 'n' }, compact(n)) : null)));
}
function card(title, sub, body, actions, extra = {}) {
  return h('section', { class: 'card', ...extra },
    title ? h('div', { class: 'card-head' }, h('h3', null, title), sub ? h('span', { class: 'sub' }, sub) : null, actions ? h('div', { class: 'actions' }, actions) : null) : null,
    body);
}
function empty(title, text, iconName = 'search') {
  return h('div', { class: 'empty' }, h('div', { class: 'icon-wrap' }, icon(iconName, 'lg')), h('h4', null, title), text ? h('div', null, text) : null);
}
function menu(button, items) {
  const wrap = h('div', { class: 'menu' });
  const pop = h('div', { class: 'menu-pop', role: 'menu' }, items.map((it) => it === '-' ? h('div', { class: 'sep' }) :
    h('button', { role: 'menuitem', onclick: () => { wrap.classList.remove('open'); it.action(); } }, it.icon ? icon(it.icon) : null, it.label)));
  button.addEventListener('click', (e) => { e.stopPropagation(); document.querySelectorAll('.menu.open').forEach((m) => m !== wrap && m.classList.remove('open')); wrap.classList.toggle('open'); });
  return append(wrap, [button, pop]);
}
document.addEventListener('click', () => document.querySelectorAll('.menu.open').forEach((m) => m.classList.remove('open')));

function modal(title, content, footer, { wide = false } = {}) {
  const dlg = $('#modal');
  dlg.className = 'modal' + (wide ? ' wide' : '');
  replace(dlg, h('div', { class: 'modal-box' },
    h('div', { class: 'modal-head' }, h('h3', null, title), h('span', { class: 'grow' }), h('button', { class: 'btn ghost icon sm', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('close'))),
    h('div', { class: 'modal-content' }, content),
    footer ? h('div', { class: 'modal-foot' }, footer) : null));
  if (!dlg.open) dlg.showModal();
  return dlg;
}
dialogBackdropClose($('#modal'));
function dialogBackdropClose(dlg) { dlg.addEventListener('click', (e) => { if (e.target === dlg) dlg.close(); }); }
function jsonModal(title, data) {
  const text = JSON.stringify(data, null, 2);
  modal(title, h('pre', { class: 'json' }, text), [
    h('button', { class: 'btn', onclick: () => copy(text, 'JSON copied') }, icon('copy'), 'Copy'),
    h('button', { class: 'btn primary', onclick: () => $('#modal').close() }, 'Close')], { wide: true });
}

// =============================================================================================
// charts (inline SVG; validated palette via CSS classes; hover layer on every plot)
// =============================================================================================
const tip = $('#viz-tip');
function showTip(evOrRect, title, rows) {
  replace(tip, title ? h('div', { class: 't' }, title) : null, rows.map((r) =>
    h('div', { class: 'r' }, r.cls ? h('i', { class: r.cls, style: { background: `var(${r.colorVar})` } }) : null, h('b', null, r.value), h('span', null, r.label))));
  tip.style.display = 'block';
  const x = evOrRect.clientX ?? (evOrRect.left + evOrRect.width / 2);
  const y = evOrRect.clientY ?? evOrRect.top;
  const w = tip.offsetWidth, hgt = tip.offsetHeight;
  let left = x + 14, top = y - hgt - 12;
  if (left + w > window.innerWidth - 8) left = x - w - 14;
  if (top < 8) top = y + 16;
  tip.style.left = `${Math.max(8, left)}px`; tip.style.top = `${top}px`;
}
function hideTip() { tip.style.display = 'none'; }

function chartBox(height, draw) {
  const el = h('div', { class: 'chart', style: { height: `${height}px` } });
  let lastW = 0;
  new ResizeObserver((entries) => {
    const w = Math.floor(entries[0].contentRect.width);
    if (w > 0 && w !== lastW) { lastW = w; clear(el); draw(el, w, height); }
  }).observe(el);
  return el;
}
function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0, 1];
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = Math.max(1, [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw));
  const top = Math.ceil(max / step) * step;
  const out = [];
  for (let v = 0; v <= top + 1e-9; v += step) out.push(Math.round(v * 100) / 100);
  return out;
}
function topRoundedRect(x, y, w, hgt, r) {
  r = Math.max(0, Math.min(r, hgt, w / 2));
  return `M${x},${y + hgt}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + hgt}Z`;
}

/* Line chart: [{key, name, values, cls, colorVar, emphasis}] over `dates`. Crosshair + tooltip. */
function lineChart({ dates, series, height = 268 }) {
  return chartBox(height, (el, W, H) => {
    const m = { l: 40, r: 64, t: 12, b: 26 };
    const pw = W - m.l - m.r, ph = H - m.t - m.b;
    const n = dates.length;
    const max = Math.max(1, ...series.flatMap((s) => s.values));
    const ticks = niceTicks(max);
    const top = ticks[ticks.length - 1];
    const X = (i) => m.l + (n <= 1 ? pw / 2 : (i / (n - 1)) * pw);
    const Y = (v) => m.t + ph - (v / top) * ph;
    const svg = sv('svg', { width: W, height: H, role: 'img', 'aria-label': series.map((s) => `${s.name}: ${s.values[n - 1]}`).join(', ') });
    for (const t of ticks) {
      svg.append(sv('line', { class: t === 0 ? 'baseline' : 'grid-line', x1: m.l, x2: m.l + pw, y1: Math.round(Y(t)) + 0.5, y2: Math.round(Y(t)) + 0.5 }));
      svg.append(sv('text', { x: m.l - 8, y: Y(t) + 4, 'text-anchor': 'end' }, compact(t)));
    }
    const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 90))));
    for (let i = 0; i < n; i += labelEvery) svg.append(sv('text', { x: X(i), y: H - 6, 'text-anchor': i === 0 ? 'start' : 'middle' }, shortDay(dates[i])));
    for (const s of series) {
      const d = s.values.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join('');
      if (s.emphasis) svg.append(sv('path', { d: `${d}L${X(n - 1)},${Y(0)}L${X(0)},${Y(0)}Z`, class: s.cls, style: { stroke: 'none', fillOpacity: '0.1' } }));
      svg.append(sv('path', { d, class: `line ${s.cls}`, style: { fill: 'none' } }));
    }
    // end labels (skipped when they would collide – legend + tooltip carry the values then)
    const ends = series.map((s) => ({ s, y: Y(s.values[n - 1]) }));
    const collide = ends.length > 1 && Math.abs(ends[0].y - ends[1].y) < 30;
    for (const { s, y } of ends) {
      svg.append(sv('circle', { cx: X(n - 1), cy: y, r: 4, class: s.cls, style: { stroke: 'var(--surface)', strokeWidth: '2' } }));
      if (!collide) {
        svg.append(sv('text', { x: X(n - 1) + 10, y: y - 1, class: 'end-label' }, compact(s.values[n - 1])));
        svg.append(sv('text', { x: X(n - 1) + 10, y: y + 13, class: 'end-label sub' }, s.name));
      }
    }
    const cross = sv('line', { class: 'crosshair', y1: m.t, y2: m.t + ph, x1: 0, x2: 0, visibility: 'hidden' });
    const dots = series.map((s) => sv('circle', { r: 4, cx: 0, cy: 0, visibility: 'hidden', class: s.cls, style: { stroke: 'var(--surface)', strokeWidth: '2', pointerEvents: 'none' } }));
    svg.append(cross, ...dots);
    const hit = sv('rect', { x: m.l, y: m.t, width: pw, height: ph, fill: 'transparent', tabindex: '0', 'aria-label': 'Chart: use arrow keys to read values' });
    let idx = n - 1;
    const show = (i, evt) => {
      idx = Math.max(0, Math.min(n - 1, i));
      const x = X(idx);
      cross.setAttribute('x1', x); cross.setAttribute('x2', x); cross.setAttribute('visibility', 'visible');
      series.forEach((s, k) => { dots[k].setAttribute('cx', x); dots[k].setAttribute('cy', Y(s.values[idx])); dots[k].setAttribute('visibility', 'visible'); });
      const r = hit.getBoundingClientRect();
      showTip(evt || { clientX: r.left + (x - m.l), clientY: r.top + 10 }, shortDay(dates[idx]),
        series.map((s) => ({ value: num(s.values[idx]), label: s.name, cls: 'k', colorVar: s.colorVar })));
    };
    const reset = () => { cross.setAttribute('visibility', 'hidden'); dots.forEach((d) => d.setAttribute('visibility', 'hidden')); hideTip(); };
    hit.addEventListener('pointermove', (e) => { const r = hit.getBoundingClientRect(); show(Math.round(((e.clientX - r.left) / r.width) * (n - 1)), e); });
    hit.addEventListener('pointerleave', reset);
    hit.addEventListener('focus', () => show(idx));
    hit.addEventListener('blur', reset);
    hit.addEventListener('keydown', (e) => { if (e.key === 'ArrowLeft') { e.preventDefault(); show(idx - 1); } if (e.key === 'ArrowRight') { e.preventDefault(); show(idx + 1); } });
    svg.append(hit);
    el.append(svg);
  });
}

/* Stacked columns: buckets [{label, title, values:{key:n}}], keys [{key, name}] bottom→top. */
function stackedColumns({ buckets, keys, height = 300, onClick }) {
  return chartBox(height, (el, W, H) => {
    const m = { l: 36, r: 8, t: 10, b: 26 };
    const pw = W - m.l - m.r, ph = H - m.t - m.b;
    const n = buckets.length;
    const totals = buckets.map((b) => keys.reduce((a, k) => a + (b.values[k.key] || 0), 0));
    const ticks = niceTicks(Math.max(1, ...totals));
    const top = ticks[ticks.length - 1];
    const Y = (v) => m.t + ph - (v / top) * ph;
    const band = pw / Math.max(1, n);
    const cw = Math.max(2, Math.min(24, band * 0.64));
    const svg = sv('svg', { width: W, height: H, role: 'img', 'aria-label': 'Changes per period' });
    for (const t of ticks) {
      svg.append(sv('line', { class: t === 0 ? 'baseline' : 'grid-line', x1: m.l, x2: m.l + pw, y1: Math.round(Y(t)) + 0.5, y2: Math.round(Y(t)) + 0.5 }));
      svg.append(sv('text', { x: m.l - 8, y: Y(t) + 4, 'text-anchor': 'end' }, compact(t)));
    }
    const labelEvery = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(pw / 64))));
    buckets.forEach((b, i) => {
      const cx = m.l + band * i + band / 2;
      if (i % labelEvery === 0) svg.append(sv('text', { x: cx, y: H - 6, 'text-anchor': 'middle' }, b.label));
      const g = sv('g', { class: 'col' });
      let base = Y(0);
      const present = keys.filter((k) => b.values[k.key] > 0);
      present.forEach((k, j) => {
        const hgt = (b.values[k.key] / top) * ph;
        const gap = j > 0 ? 2 : 0;                       // 2px surface gap between stacked segments
        const y0 = base - hgt;
        const segH = Math.max(1, hgt - gap);
        const isTop = j === present.length - 1;
        g.append(isTop ? sv('path', { d: topRoundedRect(cx - cw / 2, y0, cw, segH, 4), class: `f-${k.key}` })
          : sv('rect', { x: cx - cw / 2, y: y0, width: cw, height: segH, class: `f-${k.key}` }));
        base = y0;
      });
      const hit = sv('rect', { x: m.l + band * i, y: m.t, width: band, height: ph, fill: 'transparent', tabindex: '0', 'aria-label': `${b.title}: ${keys.map((k) => `${k.name} ${b.values[k.key] || 0}`).join(', ')}`,
        style: { cursor: onClick ? 'pointer' : 'default' } });
      const show = (e) => { g.classList.add('hover'); showTip(e.clientX !== undefined ? e : hit.getBoundingClientRect(), b.title, [...keys].reverse().map((k) => ({ value: num(b.values[k.key] || 0), label: k.name, cls: 'k', colorVar: `--ev-${k.key}` }))); };
      const hide = () => { g.classList.remove('hover'); hideTip(); };
      hit.addEventListener('pointermove', show); hit.addEventListener('pointerleave', hide);
      hit.addEventListener('focus', show); hit.addEventListener('blur', hide);
      if (onClick) hit.addEventListener('click', () => onClick(b));
      svg.append(g, hit);
    });
    el.append(svg);
  });
}

function sparkline(values, { width = 96, height = 30 } = {}) {
  const svg = sv('svg', { class: 'spark', width, height, viewBox: `0 0 ${width} ${height}`, 'aria-hidden': 'true' });
  if (!values || values.length < 2) return svg;
  const min = Math.min(...values), max = Math.max(...values);
  const span = max - min || 1;
  const X = (i) => 2 + (i / (values.length - 1)) * (width - 6);
  const Y = (v) => height - 4 - ((v - min) / span) * (height - 8);
  svg.append(sv('path', { class: 'line', d: values.map((v, i) => `${i ? 'L' : 'M'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join('') }));
  svg.append(sv('circle', { class: 'end', cx: X(values.length - 1), cy: Y(values[values.length - 1]), r: 3.5 }));
  return svg;
}

/* Ranked horizontal bars, one hue; every bar is a link into the filtered asset list. */
function barList(items, { onClick, format = num, max: maxItems = 8 } = {}) {
  const list = items.slice(0, maxItems);
  if (!list.length) return h('div', { class: 'muted small' }, 'No data yet');
  const max = Math.max(...list.map((i) => i.count));
  return h('div', { class: 'barlist' }, list.map((i) => h('button', { class: 'b', title: `${i.name}: ${num(i.count)}`, onclick: () => onClick && onClick(i) },
    h('span', { class: 'name' }, i.label ?? i.name), h('span', { class: 'v' }, format(i.count)),
    h('span', { class: 'track' }, h('i', { style: { width: `${Math.max(1, (i.count / max) * 100)}%` } })))));
}

/* Tall segmented bar (one whole, ≤6 parts). Parts carry their share where it fits; legend names only. */
function segBar(parts, { onClick } = {}) {
  const total = parts.reduce((a, p) => a + p.count, 0);
  if (!total) return h('div', { class: 'muted small' }, 'No data yet');
  const bar = h('div', { class: 'segbar', role: 'img', 'aria-label': parts.map((p) => `${p.name} ${p.count} (${pct(p.count, total)}%)`).join(', ') },
    parts.filter((p) => p.count > 0).map((p) => {
      const share = p.count / total;
      const el = h('div', { class: p.darkInk ? 'dark-ink' : '', tabindex: '0', style: { flexGrow: String(p.count), flexBasis: '0', background: `var(${p.colorVar})` },
        onclick: () => onClick && onClick(p) }, share >= 0.09 ? `${Math.round(share * 100)}%` : '');
      const show = (e) => showTip(e.clientX !== undefined ? e : el.getBoundingClientRect(), p.name, [{ value: num(p.count), label: `${Math.round(share * 100)}% of ${num(total)}` }]);
      el.addEventListener('pointermove', show); el.addEventListener('pointerleave', hideTip);
      el.addEventListener('focus', show); el.addEventListener('blur', hideTip);
      return el;
    }));
  const legend = h('div', { class: 'legend', style: { marginTop: '10px' } }, parts.map((p) => h('span', null, h('i', { style: { background: `var(${p.colorVar})` } }), p.name)));
  return h('div', null, bar, legend);
}
function meter(value, total) {
  return h('div', { class: 'meter', role: 'meter', 'aria-valuemin': '0', 'aria-valuemax': String(total), 'aria-valuenow': String(value) },
    h('i', { style: { width: `${total ? (value / total) * 100 : 0}%` } }));
}

// =============================================================================================
// shell: navigation, routing, chrome
// =============================================================================================
const NAV = [
  { view: 'overview', label: 'Overview', icon: 'overview' },
  { view: 'assets', label: 'Assets', icon: 'assets', count: 'total' },
  { view: 'changes', label: 'Changes', icon: 'changes', count: 'changes_7d' },
  { view: 'scans', label: 'Scans', icon: 'scans' },
  { view: 'domains', label: 'Domains', icon: 'domains', count: 'roots' },
  { view: 'tags', label: 'Tags', icon: 'tags', count: 'tags' },
];
const TITLES = { overview: 'Overview', assets: 'Assets', host: 'Host', changes: 'Changes', scans: 'Scans', domains: 'Domains', tags: 'Tags' };
let chromeStats = {};

function renderNav(active) {
  replace($('#nav'), h('div', { class: 'nav-label' }, 'Workspace'), NAV.map((n) => {
    const count = n.count ? chromeStats[n.count] : null;
    return h('a', { class: 'nav-item' + (n.view === active ? ' active' : ''), href: `#/${n.view}`, onclick: () => closeSidebar() },
      icon(n.icon), n.label, count ? h('span', { class: 'count' }, compact(count)) : null);
  }));
}

function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '') || 'overview';
  const [path, query = ''] = raw.split('?');
  return { parts: path.split('/').filter(Boolean), params: new URLSearchParams(query) };
}
function go(path, params) { location.hash = '#/' + path + qs(params || {}); }
function setHashQuiet(path, params) { history.replaceState(null, '', '#/' + path + qs(params || {})); }

const routes = {};
let renderToken = 0;
async function render() {
  const { parts, params } = parseHash();
  const view = routes[parts[0]] ? parts[0] : 'overview';
  const navView = view === 'host' ? 'assets' : view;
  renderNav(navView);
  replace($('#crumbs'), h('h1', null, TITLES[view] || 'subtrack'));
  const token = ++renderToken;
  const app = $('#app');
  document.querySelectorAll('.selbar').forEach((el) => el.remove());
  if (view !== 'assets') assetsKeys = null;
  app.classList.add('loading');
  try {
    const node = await routes[view](parts.slice(1), params, () => token === renderToken);
    if (token !== renderToken) return;
    replace(app, node);
    window.scrollTo(0, 0);
  } catch (err) {
    if (token === renderToken) replace(app, h('div', { class: 'card' }, empty('Something went wrong', err.message, 'alert')));
  } finally {
    if (token === renderToken) app.classList.remove('loading');
  }
}
window.addEventListener('hashchange', () => { hideTip(); render(); });
window.addEventListener('scroll', () => $('#topbar').classList.toggle('scrolled', window.scrollY > 4), { passive: true });

// =============================================================================================
// Overview
// =============================================================================================
function bucketSeries(series) {
  const n = series.length;
  const size = n <= 45 ? 1 : n <= 200 ? 7 : 30;
  const out = [];
  for (let i = 0; i < n; i += size) {
    const chunk = series.slice(i, i + size);
    const values = {};
    for (const k of EV_ORDER) values[k] = chunk.reduce((a, d) => a + (d[k] || 0), 0);
    const first = chunk[0].date, last = chunk[chunk.length - 1].date;
    out.push({ label: shortDay(first), title: size === 1 ? shortDay(first) : `${shortDay(first)} – ${shortDay(last)}`, values, from: first, to: last });
  }
  return { buckets: out, size };
}

routes.overview = async (_parts, params) => {
  const state = { root: params.get('root') || '', days: params.get('days') || '30' };
  const data = await api('/api/insights' + qs(state));
  const k = data.kpis;
  const update = (c) => go('overview', { ...state, ...c });
  const rootAssets = (extra = {}) => ({ ...(state.root ? { root: state.root } : {}), ...extra });
  const facets = await api('/api/facets');

  const filterRow = h('div', { class: 'row', style: { marginBottom: '16px' } },
    selectEl([['', 'All domains'], ...facets.roots.map((r) => [r, r])], state.root, (v) => update({ root: v }), { 'aria-label': 'Domain' }),
    seg([['30', '30 days'], ['90', '90 days'], ['365', '1 year'], ['all', 'All time']], state.days, (v) => update({ days: v }), { 'aria-label': 'Time range' }),
    h('span', { class: 'grow' }),
    h('span', { class: 'muted small' }, `${shortDay(data.range.start)} – ${shortDay(data.range.end)}`));

  if (!k.total) {
    return h('div', null, head('Overview', 'Your attack surface at a glance.'), card(null, null, empty('No assets yet',
      h('span', null, 'Run your first scan: ', h('code', null, 'make scan domain=example.com')), 'scans')));
  }

  const s = data.series;
  const tail = (key) => s.slice(-30).map((d) => d[key]);
  const offlineSeries = s.slice(-30).map((d) => d.total - d.active);
  const delta = (cur, prev, upIsBad) => {
    const d = cur - prev;
    const cls = d === 0 || upIsBad === null ? '' : (d > 0) === upIsBad ? 'bad' : 'good';
    return h('span', { class: `delta ${cls}` }, `${d > 0 ? '+' : d < 0 ? '−' : '±'}${Math.abs(d)}`, h('span', null, ' vs prev. 7d'));
  };
  const kpi = (label, value, foot, onClick, extra = {}) => h('button', { class: 'kpi' + (extra.hero ? ' hero' : ''), onclick: onClick },
    h('span', { class: 'label' }, extra.dot ? h('span', { class: 'dot', style: { background: `var(${extra.dot})` } }) : null, label),
    h('span', { class: 'value' }, compact(value)), h('span', { class: 'foot' }, foot));
  const kpis = h('div', { class: 'kpis' },
    kpi('Tracked hosts', k.total, [h('span', { class: 'delta' }, `${k.roots} domain${k.roots === 1 ? '' : 's'}`), sparkline(tail('total'))], () => go('assets', rootAssets()), { hero: true }),
    kpi('Active', k.active, [h('span', { class: 'delta' }, `${pct(k.active, k.total)}% available`), sparkline(tail('active'))], () => go('assets', rootAssets({ status: 'active' })), { dot: '--good' }),
    kpi('Offline', k.offline, [h('span', { class: 'delta' }, `${k.back_online_7d} back this week`), sparkline(offlineSeries)], () => go('assets', rootAssets({ status: 'offline' })), { dot: '--critical' }),
    kpi('New · 7 days', k.new_7d, [delta(k.new_7d, k.new_prev_7d, null), sparkline(tail('new'))], () => go('assets', rootAssets({ new_days: 7 })), { dot: '--ev-new' }),
    kpi('Changed · 7 days', k.changed_7d, [delta(k.changed_7d, k.changed_prev_7d, null), sparkline(tail('changed'))], () => go('assets', rootAssets({ event: 'changed', event_days: 7 })), { dot: '--ev-changed' }),
    kpi('Went offline · 7 days', k.offline_7d, [delta(k.offline_7d, k.offline_prev_7d, true), sparkline(tail('offline'))], () => go('assets', rootAssets({ event: 'offline', event_days: 7 })), { dot: '--ev-offline' }));

  // ---- attack surface over time
  const surface = card('Attack surface', 'hosts over time', h('div', { class: 'card-body' },
    h('div', { class: 'legend', style: { marginBottom: '8px' } },
      h('span', null, h('i', { class: 'line-key', style: { background: 'var(--series-1)' } }), 'Active ', h('b', null, num(k.active))),
      h('span', null, h('i', { class: 'line-key', style: { background: 'var(--series-muted)' } }), 'Tracked (all time) ', h('b', null, num(k.total)))),
    lineChart({ dates: s.map((d) => d.date), series: [
      { key: 'total', name: 'Tracked', values: s.map((d) => d.total), cls: 's-total', colorVar: '--series-muted' },
      { key: 'active', name: 'Active', values: s.map((d) => d.active), cls: 's-active', colorVar: '--series-1', emphasis: true }] })));

  // ---- response mix
  const cc = data.code_classes;
  const classParts = [
    { name: '2xx', count: cc['2xx'] || 0, colorVar: '--s1', code: '2xx' }, { name: '3xx', count: cc['3xx'] || 0, colorVar: '--s2', code: '3xx' },
    { name: '4xx', count: cc['4xx'] || 0, colorVar: '--s3', code: '4xx' }, { name: '5xx', count: cc['5xx'] || 0, colorVar: '--s4', code: '5xx', darkInk: true }];
  const cdnTotal = data.cdn.reduce((a, c) => a + c.count, 0);
  const mix = card('Response mix', 'active hosts', h('div', { class: 'card-body stack' },
    segBar(classParts, { onClick: (p) => go('assets', rootAssets({ status: 'active', code: p.code })) }),
    h('div', { class: 'stack sm' },
      h('div', { class: 'meter-row' }, h('span', { class: 'nowrap' }, 'Availability'), meter(k.active, k.total), h('b', { class: 'tnum' }, `${pct(k.active, k.total)}%`)),
      h('div', { class: 'meter-row' }, h('span', { class: 'nowrap' }, 'Behind CDN/WAF'), meter(cdnTotal, k.active), h('b', { class: 'tnum' }, `${pct(cdnTotal, k.active)}%`))),
    h('div', null, h('div', { class: 'label' }, 'Top status codes'),
      barList(data.codes.map((c) => ({ name: String(c.name), count: c.count })), { onClick: (i) => go('assets', rootAssets({ status: 'active', code: i.name })), max: 5 }))));

  // ---- changes chart + feed
  const { buckets, size } = bucketSeries(s);
  const totalsByType = Object.fromEntries(EV_ORDER.map((t) => [t, s.reduce((a, d) => a + d[t], 0)]));
  const changesCard = card('Changes', size === 1 ? 'per day' : size === 7 ? 'per week' : 'per month', h('div', { class: 'card-body' },
    h('div', { class: 'legend', style: { marginBottom: '8px' } }, EV_ORDER.map((t) => h('span', null, h('i', { style: { background: `var(--ev-${t})` } }), EV_LABEL[t], ' ', h('b', null, num(totalsByType[t]))))),
    stackedColumns({ buckets, keys: EV_ORDER.map((t) => ({ key: t, name: EV_LABEL[t] })) })),
  h('a', { class: 'btn ghost sm', href: '#/changes' + qs({ root: state.root, days: state.days === 'all' ? '' : state.days }) }, 'View all', icon('arrowRight', 'sm')));
  const feed = card('Latest changes', null, h('div', { class: 'card-body flush' }, data.recent_events.length ? h('ul', { class: 'feed' }, data.recent_events.map(eventRow)) : empty('Nothing yet', null, 'changes')),
    h('a', { class: 'btn ghost sm', href: '#/changes' }, 'All', icon('arrowRight', 'sm')));

  // ---- breakdowns
  const tech = card('Technologies', 'active hosts', h('div', { class: 'card-body' }, barList(data.tech, { onClick: (i) => go('assets', rootAssets({ status: 'active', tech: i.name })) })));
  const servers = card('Web servers', 'active hosts', h('div', { class: 'card-body' }, barList(data.servers, { onClick: (i) => go('assets', rootAssets({ status: 'active', server: i.name })) })));
  const sources = card('Discovered by', 'validated hosts per source', h('div', { class: 'card-body' }, barList(data.sources, { onClick: (i) => go('assets', rootAssets({ q: `source:${i.name}` })) })));

  // ---- domains + watchlist
  const domains = card('Domains', `${data.domains.length} tracked`, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
    h('thead', null, h('tr', null, h('th', null, 'Domain'), h('th', { class: 'num' }, 'Hosts'), h('th', null, 'Availability'), h('th', { class: 'num' }, 'New · 7d'), h('th', null, 'Last scan'))),
    h('tbody', null, data.domains.map((r) => h('tr', { class: 'clickable', onclick: () => go('assets', { root: r.domain }) },
      h('td', { class: 'mono' }, r.domain), h('td', { class: 'num' }, num(r.total)),
      h('td', { style: { minWidth: '170px' } }, h('div', { class: 'meter-row' }, meter(r.active, r.total), h('span', { class: 'tnum nowrap' }, `${num(r.active)} / ${num(r.total)}`))),
      h('td', { class: 'num' }, r.new_7d ? `+${num(r.new_7d)}` : '–'),
      h('td', { class: 'when' }, r.last_scan_at ? [when(r.last_scan_at), ' ', r.last_scan_status && r.last_scan_status !== 'success' ? pill(r.last_scan_status) : null] : '–'))))))
    , h('a', { class: 'btn ghost sm', href: '#/domains' }, 'Manage', icon('arrowRight', 'sm')));
  const watch = card('Watchlist', null, h('div', { class: 'card-body flush' },
    h('div', { class: 'card-head', style: { paddingTop: '4px' } }, h('span', { class: 'sub' }, icon('lock', 'sm')), h('span', { class: 'sub', style: { color: 'var(--text-2)', fontWeight: 600 } }, 'TLS certificates expiring ≤ 30 days')),
    data.expiring_tls.length ? h('ul', { class: 'mini-list', style: { marginTop: '6px' } }, data.expiring_tls.slice(0, 5).map((c) => {
      const d = daysUntil(c.tls_not_after);
      return h('li', { class: 'clickable', onclick: () => openHost(c.id) }, h('span', { class: 'host' }, c.host),
        h('span', { class: 'r' }, h('span', { class: `pill ${d < 0 ? 'failed' : d <= 7 ? 'partial' : ''}`, title: utcTitle(c.tls_not_after) }, d < 0 ? 'expired' : `${d}d left`)));
    })) : h('div', { class: 'muted small', style: { padding: '6px 18px 12px' } }, 'Nothing expiring soon.'),
    h('div', { class: 'card-head', style: { paddingTop: '10px' } }, h('span', { class: 'sub' }, icon('alert', 'sm')), h('span', { class: 'sub', style: { color: 'var(--text-2)', fontWeight: 600 } }, 'Possible takeovers (dangling CNAME)')),
    data.takeover_candidates.length ? h('ul', { class: 'mini-list', style: { marginTop: '6px' } }, data.takeover_candidates.slice(0, 5).map((c) =>
      h('li', { class: 'clickable', onclick: () => openHost(c.id), title: c.cname.join(', ') }, h('span', { class: 'host' }, c.host), h('span', { class: 'r muted small mono ellipsis', style: { maxWidth: '45%' } }, c.cname[0] || '')))) :
      h('div', { class: 'muted small', style: { padding: '6px 18px 14px' } }, 'No offline hosts with a CNAME.')));

  // ---- scans
  const scans = card('Recent scans', null, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
    h('tbody', null, data.scans.map((sc) => h('tr', { class: 'clickable', onclick: () => go(`scans/${sc.id}`) },
      h('td', null, pill(sc.status, sc.error || null)), h('td', { class: 'mono nowrap' }, `#${sc.id}`),
      h('td', { class: 'when' }, when(sc.started_at)), h('td', { class: 'when' }, sc.finished_at ? duration(sc.started_at, sc.finished_at) : 'running…'),
      h('td', { class: 'small text-2 ellipsis', style: { maxWidth: '260px' } }, sc.roots.map((r) => r.domain).join(', ')),
      h('td', null, scanTotals(sc.totals))))))), h('a', { class: 'btn ghost sm', href: '#/scans' }, 'All scans', icon('arrowRight', 'sm')));

  return h('div', null, head('Overview', 'Your attack surface at a glance – click anything to drill down.'), filterRow,
    h('div', { class: 'stack' }, kpis,
      h('div', { class: 'grid cols-2-1' }, surface, mix),
      h('div', { class: 'grid cols-2-1' }, changesCard, feed),
      h('div', { class: 'grid cols-3' }, tech, servers, sources),
      h('div', { class: 'grid cols-2-1' }, domains, watch),
      scans));
};
function head(title, text, actions) {
  return h('div', { class: 'page-head' }, h('div', null, h('h2', null, title), text ? h('p', null, text) : null), h('span', { class: 'grow' }), actions || null);
}
function scanTotals(t) {
  t = t || {};
  return h('div', { class: 'metric-row' },
    h('span', { title: 'alive' }, h('b', null, num(t.alive)), 'alive'),
    t.new ? h('span', { class: 'ev new' }, h('b', null, `+${num(t.new)}`)) : null,
    t.went_offline ? h('span', { class: 'ev offline' }, h('b', null, `−${num(t.went_offline)}`)) : null,
    t.back_online ? h('span', { class: 'ev back_online' }, h('b', null, `↑${num(t.back_online)}`)) : null,
    t.changed ? h('span', { class: 'ev changed' }, h('b', null, `~${num(t.changed)}`)) : null);
}

// =============================================================================================
// events (shared by overview, changes, host timeline)
// =============================================================================================
function fmtVal(v) {
  if (v === null || v === undefined || v === '') return '∅';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '∅';
  return String(v);
}
function eventSummary(e) {
  const d = e.details || {};
  if (e.type === 'new') return [d.status_code ? `${d.status_code} ` : '', d.title ? `“${d.title}”` : 'no title', d.sources && d.sources.length ? ` · via ${d.sources.join(', ')}` : ''].join('');
  if (e.type === 'offline') return `${d.reason === 'dns' ? 'DNS no longer resolves' : 'No HTTP(S) response'} · last seen ${rel(d.last_seen)}`;
  if (e.type === 'back_online') return `Back after ${duration(d.offline_since, e.created_at)} offline` + (d.changes && Object.keys(d.changes).length ? ` · ${Object.keys(d.changes).join(', ')} changed` : '');
  if (e.type === 'changed') return Object.entries(d.changes || {}).map(([f, c]) => `${f}: ${fmtVal(c.old)} → ${fmtVal(c.new)}`).join(' · ');
  return '';
}
function diffBlock(changes) {
  const entries = Object.entries(changes || {});
  if (!entries.length) return null;
  return h('div', { class: 'diff' }, entries.map(([f, c]) => [h('span', { class: 'f' }, f), h('span', null, h('del', null, fmtVal(c.old)), h('span', { class: 'arrow' }, '→'), h('ins', null, fmtVal(c.new)))]));
}
function eventRow(e) {
  return h('li', { class: 'clickable', onclick: () => openHost(e.subdomain_id) },
    h('span', { class: 'evcol' }, evEl(e.type)),
    h('div', { style: { minWidth: 0 } }, h('div', { class: 'host ellipsis' }, e.host), h('div', { class: 'desc', title: eventSummary(e) }, eventSummary(e))),
    h('span', { class: 't', title: utcTitle(e.created_at) }, rel(e.created_at)));
}

// =============================================================================================
// Assets – faceted search
// =============================================================================================
const MULTI = ['root', 'status', 'code', 'tech', 'server', 'tag'];
const SINGLE = ['q', 'untagged', 'new_days', 'event', 'event_days', 'sort', 'order', 'page', 'per_page'];
const FILTER_KEYS = [...MULTI, 'q', 'untagged', 'new_days', 'event', 'event_days'];
const FACET_LABEL = { root: 'Domain', status: 'Status', code: 'Code', tech: 'Tech', server: 'Server', tag: 'Tag' };
const QUICK_VIEWS = [
  { name: 'All assets', st: {} },
  { name: 'Active', st: { status: ['active'] } },
  { name: 'New this week', st: { new_days: '7' } },
  { name: 'Went offline · 7d', st: { event: 'offline', event_days: '7' } },
  { name: 'Changed · 7d', st: { event: 'changed', event_days: '7' } },
  { name: 'Server errors', st: { status: ['active'], code: ['5xx'] } },
  { name: 'Auth walls 401/403', st: { status: ['active'], code: ['401', '403'] } },
  { name: 'Untagged', st: { untagged: '1' } },
];
const SORTS = [['first_seen:desc', 'Newest first'], ['last_seen:desc', 'Recently seen'], ['status_changed_at:desc', 'Recent status change'],
  ['host:asc', 'Host A → Z'], ['status_code:asc', 'Status code'], ['seen_count:desc', 'Most scans']];

function readState(p) {
  const st = {};
  for (const k of MULTI) st[k] = p.getAll(k);
  for (const k of SINGLE) st[k] = p.get(k) || '';
  st.sort ||= 'first_seen'; st.order ||= 'desc';
  st.page = Math.max(1, +st.page || 1);
  st.per_page = +st.per_page || store.get('per_page', 50);
  return st;
}
function filterPart(st) { const out = {}; for (const k of FILTER_KEYS) { const v = st[k]; if (Array.isArray(v) ? v.length : v) out[k] = v; } return out; }
function sameFilters(a, b) {
  const A = filterPart(a), B = filterPart(b);
  const ka = Object.keys(A), kb = Object.keys(B);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => JSON.stringify([].concat(A[k]).map(String).sort()) === JSON.stringify([].concat(B[k] ?? []).map(String).sort()));
}
let globalFacets = null;
async function getGlobalFacets(force = false) { if (!globalFacets || force) globalFacets = await api('/api/facets'); return globalFacets; }

routes.assets = async (_parts, params) => {
  const st = readState(params);
  const selected = new Set();
  let current = { items: [], total: 0 };
  let facetData = null;
  let cursor = -1;
  const expanded = new Set();
  let facetsOpen = false;
  await getGlobalFacets(true);

  // ---------- containers
  const facetsEl = h('aside', { class: 'facets', 'aria-label': 'Filters' });
  const chipsEl = h('div', { class: 'active-filters' });
  const viewsEl = h('div', { class: 'views' });
  const countEl = h('div', { class: 'count' });
  const tbody = h('tbody');
  const pagerEl = h('div', { class: 'pager' });
  const tableCard = h('div', { class: 'card table-card' + (store.get('dense', false) ? ' dense' : '') });
  const selbar = h('div', { class: 'selbar', role: 'toolbar', 'aria-label': 'Selection actions' });
  document.querySelectorAll('.selbar').forEach((el) => el.remove());
  document.body.append(selbar);

  // ---------- state handling
  function hashParams() {
    const p = filterPart(st);
    if (st.sort !== 'first_seen' || st.order !== 'desc') { p.sort = st.sort; p.order = st.order; }
    if (st.page > 1) p.page = st.page;
    if (st.per_page !== store.get('per_page', 50)) p.per_page = st.per_page;
    return p;
  }
  function update(changes, { resetPage = true } = {}) {
    Object.assign(st, changes);
    if (resetPage) st.page = 1;
    setHashQuiet('assets', hashParams());
    load();
  }
  function toggleValue(key, value) {
    const set = new Set(st[key].map(String));
    set.has(String(value)) ? set.delete(String(value)) : set.add(String(value));
    update({ [key]: [...set] });
  }

  // ---------- search box with suggestions
  const search = searchBox({
    value: st.q,
    onInput: debounce((q) => update({ q }), 260),
    onSubmit: (q) => { update({ q }); rememberSearch(q); },
    onFilter: (key, value) => { if (MULTI.includes(key)) { const set = new Set(st[key]); set.add(value); update({ [key]: [...set] }); } else update({ [key]: value }); },
  });

  // ---------- render pieces
  function paintViews() {
    const saved = store.get('views', []);
    replace(viewsEl, QUICK_VIEWS.map((v) => h('button', { class: 'view' + (sameFilters(st, v.st) ? ' on' : ''), onclick: () => applyView(v.st) }, v.name)),
      saved.map((v, i) => {
        const vst = readState(new URLSearchParams(v.query));
        return h('button', { class: 'view' + (sameFilters(st, vst) ? ' on' : ''), onclick: () => applyView(vst), title: 'Saved view' }, icon('bookmark', 'sm'), v.name,
          h('span', { class: 'x', role: 'button', 'aria-label': `Delete view ${v.name}`, onclick: (e) => { e.stopPropagation(); saved.splice(i, 1); store.set('views', saved); paintViews(); } }, icon('close')));
      }));
  }
  function applyView(vst) {
    const reset = Object.fromEntries(FILTER_KEYS.map((k) => [k, MULTI.includes(k) ? [] : '']));
    Object.assign(reset, JSON.parse(JSON.stringify(vst)));
    search.setValue(reset.q || '');
    update(reset);
  }
  function paintChips() {
    const items = [];
    for (const k of MULTI) for (const v of st[k]) items.push([FACET_LABEL[k], k === 'status' ? STATUS_LABEL[v] || v : v, () => toggleValue(k, v)]);
    if (st.new_days) items.push(['First seen', `last ${st.new_days === '1' ? '24 hours' : st.new_days + ' days'}`, () => update({ new_days: '' })]);
    if (st.event) items.push(['Event', `${EV_LABEL[st.event] || st.event} · ${st.event_days || '?'}d`, () => update({ event: '', event_days: '' })]);
    if (st.untagged) items.push(['Tags', 'untagged', () => update({ untagged: '' })]);
    if (st.q) items.push(['Search', st.q, () => { search.setValue(''); update({ q: '' }); }]);
    replace(chipsEl, items.map(([k, v, rm]) => h('span', { class: 'filter-chip' }, h('span', { class: 'k' }, `${k}:`), h('span', { class: 'ellipsis', style: { maxWidth: '260px' } }, v),
      h('button', { 'aria-label': `Remove filter ${k} ${v}`, onclick: rm }, icon('close', 'sm')))),
    items.length > 1 ? h('button', { class: 'btn ghost xs', onclick: () => applyView({}) }, 'Clear all') : null);
    chipsEl.classList.toggle('hidden', !items.length);
  }
  function facetSection(key, title, rows, { searchable = false, radio = false, note, limit = 6 } = {}) {
    const isOpen = expanded.has(key);
    const max = Math.max(1, ...rows.map((r) => r.count || 0));
    const filterInput = searchable && isOpen ? h('input', { type: 'search', class: 'facet-filter', placeholder: `Filter ${title.toLowerCase()}…`,
      oninput: (e) => { const q = e.target.value.toLowerCase(); list.querySelectorAll('.fopt').forEach((b) => b.classList.toggle('hidden', !b.dataset.name.toLowerCase().includes(q))); } }) : null;
    const visible = isOpen ? rows : rows.slice(0, limit);
    const list = h('div', null, visible.map((r) => h('button', { class: `fopt${radio ? ' radio' : ''}${r.on ? ' on' : ''}${r.count === 0 && !r.on ? ' zero' : ''}`, dataset: { name: r.label },
      'aria-pressed': String(!!r.on), onclick: r.toggle, title: r.label },
    h('span', { class: 'box' }, r.on && !radio ? icon('check') : null), r.color ? h('span', { class: 'tagdot', vars: { '--tag': r.color } }) : null,
    h('span', { class: 'name' }, r.label), r.count !== undefined ? h('span', { class: 'cnt' }, compact(r.count)) : null,
    !radio && r.count !== undefined ? h('span', { class: 'bar' }, h('i', { style: { width: `${(r.count / max) * 100}%` } })) : null)));
    return h('div', { class: 'facet' },
      h('h4', null, title, rows.length > limit ? h('button', { onclick: () => { isOpen ? expanded.delete(key) : expanded.add(key); paintFacets(); } }, isOpen ? 'Less' : `All ${rows.length}`) : null),
      filterInput, list, note ? h('div', { class: 'hint', style: { padding: '0 6px' } }, note) : null);
  }
  function rowsFor(key, items, label = (x) => x.name) {
    const sel = new Set(st[key].map(String));
    const rows = items.map((x) => ({ value: String(x.name), label: label(x), count: x.count, on: sel.has(String(x.name)), color: x.color, toggle: () => toggleValue(key, x.name) }));
    for (const v of sel) if (!rows.some((r) => r.value === v)) rows.unshift({ value: v, label: v, count: 0, on: true, toggle: () => toggleValue(key, v) });
    rows.sort((a, b) => (b.on - a.on));
    return rows;
  }
  function paintFacets() {
    const f = facetData;
    if (!f) return;
    const status = ['active', 'offline'].map((v) => ({ name: v, count: f.status[v] || 0 }));
    const classes = ['2xx', '3xx', '4xx', '5xx'].map((c) => ({ name: c, count: f.codes.filter((x) => String(x.code)[0] === c[0]).reduce((a, x) => a + x.count, 0) }));
    const codeRows = rowsFor('code', [...classes, ...f.codes.map((c) => ({ name: String(c.code), count: c.count }))]);
    const newRows = [['', 'Any time'], ['1', 'Last 24 hours'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days']].map(([v, label]) => ({
      label, count: v ? f.new[v] : f.total, on: st.new_days === v, toggle: () => update({ new_days: v }) }));
    const tagRows = rowsFor('tag', f.tags.map((t) => ({ name: t.name, count: t.count, color: t.color })));
    tagRows.push({ label: 'Untagged only', on: !!st.untagged, toggle: () => update({ untagged: st.untagged ? '' : '1' }) });
    replace(facetsEl,
      facetSection('status', 'Status', rowsFor('status', status, (x) => STATUS_LABEL[x.name])),
      f.root_counts.length > 1 || st.root.length ? facetSection('root', 'Domain', rowsFor('root', f.root_counts), { searchable: true }) : null,
      facetSection('code', 'Response', codeRows, { limit: 4 }),
      facetSection('tech', 'Technology', rowsFor('tech', f.tech), { searchable: true }),
      facetSection('server', 'Web server', rowsFor('server', f.servers), { searchable: true }),
      facetSection('tag', 'Tags', tagRows, { note: st.tag.length > 1 ? 'Assets must have all selected tags.' : null, limit: 8 }),
      facetSection('new_days', 'First seen', newRows, { radio: true, limit: 5 }));
    facetsEl.classList.toggle('open', facetsOpen);
  }
  const sortHead = (key, label, cls = '') => h('th', { class: `sortable ${cls}`, onclick: () => update({ sort: key, order: st.sort === key && st.order === 'desc' ? 'asc' : (key === 'host' ? 'asc' : 'desc') }, { resetPage: false }),
    'aria-sort': st.sort === key ? (st.order === 'asc' ? 'ascending' : 'descending') : null }, label, st.sort === key ? h('span', { class: 'arrow' }, st.order === 'asc' ? '↑' : '↓') : null);
  const headCheck = h('input', { type: 'checkbox', 'aria-label': 'Select all on this page', onchange: (e) => {
    current.items.forEach((i) => (e.target.checked ? selected.add(i.id) : selected.delete(i.id))); paintRows(); paintSelbar(); } });
  function paintTable() {
    replace(tableCard,
      h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
        h('thead', null, h('tr', null, h('th', { class: 'chk' }, headCheck), sortHead('host', 'Host'), sortHead('status', 'Status'), sortHead('status_code', 'Code'),
          h('th', null, 'Technologies'), h('th', { class: 'col-ip' }, 'IP / CDN'), sortHead('last_seen', 'Seen'), h('th', null, 'Tags'))),
        tbody)),
      pagerEl);
  }
  function paintRows() {
    clear(tbody);
    if (!current.items.length) {
      const any = Object.keys(filterPart(st)).length;
      tbody.append(h('tr', null, h('td', { colspan: 8 }, any ? empty('No assets match', h('span', null, 'Try removing a filter, or ', h('button', { class: 'btn xs', onclick: () => applyView({}) }, 'clear all filters')))
        : empty('No assets yet', h('span', null, 'Run a scan: ', h('code', null, 'make scan domain=example.com')), 'scans'))));
      return;
    }
    current.items.forEach((s, i) => {
      const box = h('input', { type: 'checkbox', checked: selected.has(s.id), 'aria-label': `Select ${s.host}`, onclick: (e) => e.stopPropagation(),
        onchange: (e) => { e.target.checked ? selected.add(s.id) : selected.delete(s.id); tr.classList.toggle('selected', e.target.checked); paintSelbar(); } });
      const sub = [s.title, s.webserver].filter(Boolean).join(' · ') || (s.location ? `→ ${s.location}` : '');
      const tr = h('tr', { class: `clickable${selected.has(s.id) ? ' selected' : ''}${i === cursor ? ' cursor' : ''}`, dataset: { i: String(i) }, onclick: () => { cursor = i; markCursor(); openHost(s.id, current.items.map((x) => x.id)); } },
        h('td', { class: 'chk' }, box),
        h('td', { class: 'host-cell' }, h('div', { class: 'h' }, h('span', { class: 'ellipsis' }, s.host), s.url ? extLink(s.url, icon('external', 'sm'), 'ext') : null),
          sub ? h('div', { class: 'sub', title: sub }, sub) : null),
        h('td', null, statusEl(s.status, s.status === 'offline' ? `Offline since ${fmtDateTime(s.status_changed_at)} – ${s.offline_reason === 'dns' ? 'DNS no longer resolves' : 'no HTTP response'}` : `Active since ${fmtDateTime(s.status_changed_at)}`)),
        h('td', null, codeEl(s.status_code)),
        h('td', null, chips(s.tech, 2, (t) => toggleValue('tech', t))),
        h('td', { class: 'nowrap col-ip' }, h('div', { class: 'mono small', title: (s.ips || []).join(', ') }, s.ips && s.ips.length ? s.ips[0] + (s.ips.length > 1 ? ` +${s.ips.length - 1}` : '') : '–'),
          s.cdn_name ? h('div', { class: 'muted small' }, s.cdn_name) : null),
        h('td', { class: 'when' }, h('div', { title: `last seen ${utcTitle(s.last_seen)}` }, rel(s.last_seen)),
          h('div', { class: 'muted small', title: `first seen ${utcTitle(s.first_seen)}` }, `since ${shortDate(s.first_seen)}`)),
        h('td', null, h('div', { class: 'cell-chips' }, s.tags.map((t) => tagChip(t)))));
      tbody.append(tr);
    });
  }
  function markCursor() { tbody.querySelectorAll('tr').forEach((tr) => tr.classList.toggle('cursor', +tr.dataset.i === cursor)); }
  function paintPager() {
    const pages = Math.max(1, Math.ceil(current.total / st.per_page));
    const from = current.total ? (st.page - 1) * st.per_page + 1 : 0;
    const to = Math.min(current.total, st.page * st.per_page);
    const nums = [];
    const add = (p) => nums.push(h('button', { class: p === st.page ? 'on' : '', onclick: () => update({ page: p }, { resetPage: false }), 'aria-label': `Page ${p}` }, p));
    const win = [1, st.page - 1, st.page, st.page + 1, pages].filter((p, i, a) => p >= 1 && p <= pages && a.indexOf(p) === i).sort((a, b) => a - b);
    win.forEach((p, i) => { if (i && p - win[i - 1] > 1) nums.push(h('span', { class: 'muted' }, '…')); add(p); });
    replace(pagerEl, h('span', { class: 'muted small tnum' }, `${num(from)}–${num(to)} of ${num(current.total)}`),
      selectEl([[25, '25 / page'], [50, '50 / page'], [100, '100 / page'], [250, '250 / page'], [1000, '1000 / page']], st.per_page, (v) => { store.set('per_page', +v); update({ per_page: +v }); }, { 'aria-label': 'Rows per page', style: { height: '30px' } }),
      h('div', { class: 'pages' },
        h('button', { disabled: st.page <= 1, onclick: () => update({ page: st.page - 1 }, { resetPage: false }), 'aria-label': 'Previous page' }, '‹'), nums,
        h('button', { disabled: st.page >= pages, onclick: () => update({ page: st.page + 1 }, { resetPage: false }), 'aria-label': 'Next page' }, '›')));
  }
  function paintSelbar() {
    headCheck.checked = current.items.length > 0 && current.items.every((i) => selected.has(i.id));
    selbar.classList.toggle('show', selected.size > 0);
    if (!selected.size) return;
    const input = h('input', { type: 'text', placeholder: 'tag name…', list: 'tag-names', 'aria-label': 'Tag name' });
    const run = async (mode, all = false) => {
      const name = input.value.trim(); if (!name) { input.focus(); return; }
      const body = all ? { filter: filterPart(st) } : { ids: [...selected] };
      body[mode] = [name];
      try { const r = await api('/api/bulk/tags', { method: 'POST', body }); toast(`${mode === 'add' ? 'Tagged' : 'Untagged'} ${num(r.updated)} assets with “${name}”`); selected.clear(); load(); }
      catch (e) { toast(e.message, true); }
    };
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') run('add'); });
    replace(selbar, h('strong', null, `${num(selected.size)} selected`), input,
      h('datalist', { id: 'tag-names' }, (globalFacets?.tags || []).map((t) => h('option', { value: t.name }))),
      h('button', { class: 'btn primary sm', onclick: () => run('add') }, icon('plus', 'sm'), 'Add tag'),
      h('button', { class: 'btn ghost sm', onclick: () => run('remove') }, 'Remove tag'),
      current.total > selected.size ? h('button', { class: 'btn ghost sm', title: 'Apply to every asset matching the current filters', onclick: () => run('add', true) }, `Tag all ${num(current.total)} matches`) : null,
      h('button', { class: 'btn ghost sm icon', 'aria-label': 'Clear selection', onclick: () => { selected.clear(); paintRows(); paintSelbar(); } }, icon('close')));
  }

  let loadToken = 0;
  async function load() {
    const token = ++loadToken;
    tableCard.style.opacity = '.6';
    try {
      const apiParams = { ...filterPart(st), sort: st.sort, order: st.order, page: st.page, per_page: st.per_page };
      const [list, f] = await Promise.all([api('/api/subdomains' + qs(apiParams)), api('/api/facets' + qs(filterPart(st)))]);
      if (token !== loadToken) return;
      current = list; facetData = f; cursor = Math.min(cursor, list.items.length - 1);
      replace(countEl, `${num(list.total)} `, h('span', null, list.total === 1 ? 'asset' : 'assets'));
      paintViews(); paintChips(); paintFacets(); paintRows(); paintPager(); paintSelbar();
    } catch (e) { toast(e.message, true); }
    finally { if (token === loadToken) tableCard.style.opacity = ''; }
  }

  // ---------- keyboard: j/k/x/enter on the table
  assetsKeys = (e) => {
    if (!current.items.length) return false;
    if (e.key === 'j') { cursor = Math.min(current.items.length - 1, cursor + 1); markCursor(); scrollCursor(); if (drawerOpen()) openHost(current.items[cursor].id, current.items.map((x) => x.id)); return true; }
    if (e.key === 'k') { cursor = Math.max(0, cursor - 1); markCursor(); scrollCursor(); if (drawerOpen()) openHost(current.items[cursor].id, current.items.map((x) => x.id)); return true; }
    if (e.key === 'Enter' && cursor >= 0) { openHost(current.items[cursor].id, current.items.map((x) => x.id)); return true; }
    if (e.key === 'x' && cursor >= 0) { const id = current.items[cursor].id; selected.has(id) ? selected.delete(id) : selected.add(id); paintRows(); paintSelbar(); return true; }
    return false;
  };
  function scrollCursor() { const tr = tbody.querySelector(`tr[data-i="${cursor}"]`); if (tr) tr.scrollIntoView({ block: 'nearest' }); }

  const sortSel = selectEl(SORTS, `${st.sort}:${st.order}`, (v) => { const [sort, order] = v.split(':'); update({ sort, order }, { resetPage: false }); }, { 'aria-label': 'Sort', style: { height: '32px' } });
  const exportMenu = menu(h('button', { class: 'btn' }, icon('download'), 'Export', icon('chevronDown', 'sm')),
    [['csv', 'CSV (all columns)'], ['json', 'JSON'], ['txt', 'Host list (.txt)'], ['urls', 'URL list (.txt)']].map(([fmt, label]) => ({ label, action: () => { window.location.href = '/api/export' + qs({ ...filterPart(st), format: fmt }); } })));
  const saveBtn = h('button', { class: 'btn', onclick: () => saveViewDialog(hashParams()) }, icon('bookmark'), 'Save view');
  const densityBtn = h('button', { class: 'btn ghost icon sm', title: 'Toggle compact rows', 'aria-label': 'Toggle compact rows', onclick: () => { const d = !store.get('dense', false); store.set('dense', d); tableCard.classList.toggle('dense', d); } }, icon('density'));
  const filtersBtn = h('button', { class: 'btn filters-toggle', onclick: () => { facetsOpen = !facetsOpen; facetsEl.classList.toggle('open', facetsOpen); } }, icon('filter'), 'Filters');

  paintTable();
  await load();
  return h('div', null,
    head('Assets', 'Every host httpx has ever validated – search, filter, tag.', [saveBtn, exportMenu]),
    h('div', { class: 'row' }, search.el),
    viewsEl, chipsEl,
    h('div', { class: 'assets-layout' }, facetsEl,
      h('div', { style: { minWidth: 0 } },
        h('div', { class: 'results-head' }, countEl, h('span', { class: 'grow' }), filtersBtn, densityBtn, sortSel),
        tableCard)));
};
let assetsKeys = null;

function saveViewDialog(params) {
  const name = h('input', { type: 'text', placeholder: 'e.g. Prod login pages', style: { width: '100%' } });
  const save = () => {
    const n = name.value.trim(); if (!n) return name.focus();
    const views = store.get('views', []);
    views.push({ name: n, query: toParams(params).toString() });
    store.set('views', views);
    $('#modal').close(); toast(`Saved view “${n}”`); render();
  };
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') save(); });
  modal('Save view', h('div', null, h('label', { class: 'label' }, 'Name'), name, h('div', { class: 'hint' }, 'Saved in this browser. Views appear next to the quick filters.')),
    [h('button', { class: 'btn', onclick: () => $('#modal').close() }, 'Cancel'), h('button', { class: 'btn primary', onclick: save }, 'Save')]);
  setTimeout(() => name.focus(), 30);
}
function rememberSearch(q) {
  if (!q) return;
  const recent = store.get('recent', []).filter((x) => x !== q);
  recent.unshift(q); store.set('recent', recent.slice(0, 6));
}

// ---------- the search box: field hints, value suggestions from facets, host jump
const FIELD_HINTS = [
  ['host', 'host name contains'], ['title', 'page title contains'], ['tech', 'technology (wappalyzer)'], ['server', 'web server header'],
  ['code', 'status code or class, e.g. 4xx'], ['status', 'active or offline'], ['tag', 'has tag'], ['domain', 'root domain'],
  ['ip', 'IP address contains'], ['cname', 'CNAME contains'], ['cdn', 'CDN / WAF name'], ['source', 'discovered by'],
  ['port', 'port of an alive URL'], ['url', 'URL contains'], ['location', 'redirect target contains'], ['tls', 'certificate subject'],
  ['issuer', 'certificate issuer'], ['hash', 'body sha256'], ['favicon', 'favicon mmh3'], ['type', 'content type'], ['notes', 'your notes'],
];
const STRUCTURED = { tech: 'tech', server: 'server', tag: 'tag', domain: 'root', root: 'root', status: 'status', code: 'code' };
function searchBox({ value, onInput, onSubmit, onFilter }) {
  const input = h('input', { type: 'search', value, placeholder: 'Search hosts, titles, technologies…   try  tech:nginx  code:4xx  -tag:ignore', 'aria-label': 'Search assets',
    autocomplete: 'off', spellcheck: 'false', role: 'combobox', 'aria-expanded': 'false', 'aria-controls': 'suggest-list', id: 'asset-search' });
  const panel = h('div', { class: 'suggest hidden', id: 'suggest-list', role: 'listbox' });
  const el = h('div', { class: 'searchbox' }, h('div', { class: 'field' }, icon('search', 'lg'), input, h('span', { class: 'kbd' }, '/')), panel);
  let items = [], idx = -1, hostReq = 0;

  function token() {
    const v = input.value, pos = input.selectionStart ?? v.length;
    const start = v.lastIndexOf(' ', pos - 1) + 1;
    let end = v.indexOf(' ', pos); if (end < 0) end = v.length;
    return { text: v.slice(start, end), start, end };
  }
  function replaceToken(text, { submit = false } = {}) {
    const t = token();
    const v = input.value;
    input.value = (v.slice(0, t.start) + text + v.slice(t.end)).replace(/\s{2,}/g, ' ');
    const caret = t.start + text.length;
    input.setSelectionRange(caret, caret);
    if (submit) { close(); onSubmit(input.value.trim()); } else refresh();
  }
  function removeToken() { replaceToken(''); input.value = input.value.trim(); onInput(input.value.trim()); }
  function close() { panel.classList.add('hidden'); input.setAttribute('aria-expanded', 'false'); idx = -1; }
  function paint() {
    clear(panel);
    if (!items.length) { close(); return; }
    let group = null;
    items.forEach((it, i) => {
      if (it.group !== group) { group = it.group; panel.append(h('div', { class: 'group' }, group)); }
      panel.append(h('div', { class: 'item' + (i === idx ? ' on' : ''), role: 'option', 'aria-selected': String(i === idx), onmousedown: (e) => { e.preventDefault(); it.run(); }, onmousemove: () => { if (idx !== i) { idx = i; paint(); } } },
        icon(it.icon || 'search', 'sm'), h('span', { class: 'lbl' }, it.label), it.hint ? h('span', { class: 'hint' }, it.hint) : null));
    });
    panel.append(h('div', { class: 'foot' }, h('span', null, h('span', { class: 'kbd' }, '↑↓'), ' navigate'), h('span', null, h('span', { class: 'kbd' }, '↵'), ' apply'), h('span', null, h('span', { class: 'kbd' }, 'Tab'), ' complete'), h('span', null, h('span', { class: 'kbd' }, 'Esc'), ' close')));
    panel.classList.remove('hidden'); input.setAttribute('aria-expanded', 'true');
  }
  function valuesFor(field) {
    const f = globalFacets || { tech: [], servers: [], tags: [], root_counts: [], codes: [] };
    if (field === 'tech') return f.tech.map((x) => [x.name, x.count]);
    if (field === 'server') return f.servers.map((x) => [x.name, x.count]);
    if (field === 'tag') return f.tags.map((x) => [x.name, x.count]);
    if (field === 'root') return f.root_counts.map((x) => [x.name, x.count]);
    if (field === 'status') return [['active', f.status?.active], ['offline', f.status?.offline]];
    if (field === 'code') return [['2xx'], ['3xx'], ['4xx'], ['5xx'], ...f.codes.map((c) => [String(c.code), c.count])];
    return [];
  }
  function refresh() {
    const t = token();
    const text = t.text;
    items = [];
    if (!text) {
      const recent = store.get('recent', []);
      items.push(...recent.map((q) => ({ group: 'Recent searches', label: q, icon: 'clock', run: () => { input.value = q; close(); onSubmit(q); } })));
      items.push(...FIELD_HINTS.slice(0, 8).map(([f, hint]) => ({ group: 'Search by field', label: `${f}:`, hint, icon: 'filter', run: () => replaceToken(`${f}:`) })));
      idx = -1; paint(); return;
    }
    const neg = text.startsWith('-');
    const body = neg ? text.slice(1) : text;
    const colon = body.indexOf(':');
    if (colon > 0) {
      const field = body.slice(0, colon).toLowerCase();
      const val = body.slice(colon + 1).replace(/^"|"$/g, '').toLowerCase();
      const key = STRUCTURED[field];
      if (key) {
        const vals = valuesFor(key).filter(([v]) => String(v).toLowerCase().includes(val)).slice(0, 10);
        items = vals.map(([v, n]) => ({ group: `${FACET_LABEL[key]} values`, label: String(v), hint: n !== undefined ? `${compact(n)} hosts` : '', icon: 'filter',
          run: () => { if (neg) replaceToken(`-${field}:${/\s/.test(v) ? `"${v}"` : v} `, { submit: true }); else { removeToken(); close(); onFilter(key, String(v)); } } }));
      } else if (field === 'source') {
        items = ['bruteforce', 'tls-san', 'import', 'input', 'subfinder:crtsh', 'subfinder:virustotal', 'subfinder:chaos', 'subfinder:github'].filter((v) => v.includes(val))
          .map((v) => ({ group: 'Sources', label: v, icon: 'filter', run: () => replaceToken(`${neg ? '-' : ''}source:${v} `, { submit: true }) }));
      }
      items.push({ group: 'Search', label: `${text}`, hint: 'search this', icon: 'search', run: () => { close(); onSubmit(input.value.trim()); } });
      idx = 0; paint(); return;
    }
    // plain word: matching fields, matching facet values, matching hosts, free text
    const lw = body.toLowerCase();
    const fields = FIELD_HINTS.filter(([f]) => f.startsWith(lw) && f !== lw).slice(0, 3);
    items.push(...fields.map(([f, hint]) => ({ group: 'Fields', label: `${f}:`, hint, icon: 'filter', run: () => replaceToken(`${neg ? '-' : ''}${f}:`) })));
    if (!neg && lw.length >= 2) {
      for (const key of ['tech', 'server', 'tag', 'root']) {
        for (const [v, n] of valuesFor(key).filter(([v]) => String(v).toLowerCase().includes(lw)).slice(0, key === 'tech' ? 3 : 2)) {
          items.push({ group: 'Filters', label: `${FACET_LABEL[key]}: ${v}`, hint: `${compact(n)} hosts`, icon: 'filter', run: () => { removeToken(); close(); onFilter(key, String(v)); } });
        }
      }
    }
    items.push({ group: 'Search', label: `“${input.value.trim()}”`, hint: 'everywhere', icon: 'search', run: () => { close(); onSubmit(input.value.trim()); } });
    idx = items.length > 1 ? items.findIndex((i) => i.group === 'Search') : 0;
    paint();
    if (!neg && lw.length >= 2) {
      const req = ++hostReq;
      api('/api/subdomains' + qs({ q: `host:${body}`, per_page: 5, sort: 'host', order: 'asc' })).then((r) => {
        if (req !== hostReq || token().text !== text || !r.items.length) return;
        const hosts = r.items.map((s) => ({ group: 'Jump to host', label: s.host, hint: s.status, icon: 'arrowRight', run: () => { close(); openHost(s.id); } }));
        const at = items.findIndex((i) => i.group === 'Search');
        items.splice(at, 0, ...hosts);
        if (idx >= at) idx += hosts.length;
        paint();
      }).catch(() => {});
    }
  }
  input.addEventListener('input', () => { refresh(); onInput(input.value.trim()); });
  input.addEventListener('focus', refresh);
  input.addEventListener('blur', () => setTimeout(close, 120));
  input.addEventListener('keydown', (e) => {
    const open = !panel.classList.contains('hidden');
    if (e.key === 'ArrowDown') { e.preventDefault(); if (!open) refresh(); idx = Math.min(items.length - 1, idx + 1); paint(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(0, idx - 1); paint(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (open && idx >= 0 && items[idx]) items[idx].run(); else { close(); onSubmit(input.value.trim()); } }
    else if (e.key === 'Tab' && open && idx >= 0 && items[idx] && items[idx].group !== 'Search') { e.preventDefault(); items[idx].run(); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); if (open) close(); else input.blur(); }  // never let Esc clear the query
  });
  return { el, input, setValue: (v) => { input.value = v; } };
}

// =============================================================================================
// Host detail (drawer + full page)
// =============================================================================================
let drawerList = [];
let drawerId = null;
function drawerOpen() { return $('#drawer').classList.contains('open'); }
async function openHost(id, list) {
  drawerList = list || (drawerList.includes(id) ? drawerList : []);
  drawerId = id;
  const drawer = $('#drawer');
  drawer.classList.add('open'); drawer.setAttribute('aria-hidden', 'false');
  $('#scrim').classList.add('show');
  const body = $('#drawer-body');
  body.style.opacity = '.6';
  try {
    const node = await hostDetail(id, 'drawer');
    replace(body, node);
    body.scrollTop = 0;
  } catch (e) { replace(body, empty('Could not load host', e.message, 'alert')); }
  finally { body.style.opacity = ''; }
}
function closeDrawer() {
  const drawer = $('#drawer');
  if (!drawer.classList.contains('open')) return false;
  drawer.classList.remove('open'); drawer.setAttribute('aria-hidden', 'true');
  if (!$('#sidebar').classList.contains('open')) $('#scrim').classList.remove('show');
  return true;
}
routes.host = async ([id]) => {
  const node = await hostDetail(+id, 'page');
  return h('div', null, h('div', { class: 'crumbs', style: { margin: '8px 0 14px' } }, h('a', { href: '#/assets' }, 'Assets'), icon('chevronRight', 'sm'), h('span', null, 'Host')), node);
};

async function hostDetail(id, mode) {
  const [s, hist, tags] = await Promise.all([api(`/api/subdomains/${id}`), api(`/api/subdomains/${id}/history`), api('/api/tags')]);
  let tab = store.get('host-tab', 'overview');
  const content = h('div', { class: 'hd-content' });
  const tabsEl = h('div', { class: 'tabs', role: 'tablist' });
  const answered = new Set(hist.results.map((r) => r.scan_id));
  const probeRows = [...hist.results, ...hist.scans.filter((sc) => !answered.has(sc.scan_id)).map((sc) => ({ missed: true, scan_id: sc.scan_id, observed_at: sc.started_at }))]
    .sort((a, b) => b.scan_id - a.scan_id || (a.missed ? 1 : 0) - (b.missed ? 1 : 0));
  const TABS = [['overview', 'Overview'], ['timeline', 'Timeline', hist.events.length], ['probes', 'Probes', hist.results.length], ['dns', 'DNS', hist.dns.length], ['json', 'Raw JSON']];
  const filterTo = (params) => { closeDrawer(); go('assets', params); };

  function paintTabs() {
    replace(tabsEl, TABS.map(([k, label, n]) => h('button', { class: k === tab ? 'on' : '', role: 'tab', 'aria-selected': String(k === tab), onclick: () => { tab = k; store.set('host-tab', k); paintTabs(); paintContent(); } },
      label, n !== undefined ? h('span', { class: 'n' }, n) : null)));
  }
  // ---- tags & notes
  const tagBox = h('div', { class: 'chips' });
  const paintTags = (list) => replace(tagBox, list.length ? list.map((t) => tagChip(t, async () => {
    try { s.tags = (await api(`/api/subdomains/${id}/tags/${t.id}`, { method: 'DELETE' })).tags; paintTags(s.tags); } catch (e) { toast(e.message, true); }
  })) : h('span', { class: 'muted small' }, 'No tags yet'));
  const addTag = async (name) => {
    name = (name || '').trim(); if (!name) return;
    try { s.tags = (await api(`/api/subdomains/${id}/tags`, { method: 'POST', body: { name } })).tags; paintTags(s.tags); tagInput.value = ''; globalFacets = null; }
    catch (e) { toast(e.message, true); }
  };
  const tagInput = h('input', { type: 'text', placeholder: 'Add a tag…', list: `tags-${id}`, 'aria-label': 'Add tag', onkeydown: (e) => { if (e.key === 'Enter') addTag(tagInput.value); } });
  const notes = h('textarea', { rows: 4, placeholder: 'Notes – findings, owner, context…' });
  notes.value = s.notes || '';
  const saveNotes = async () => { try { await api(`/api/subdomains/${id}`, { method: 'PATCH', body: { notes: notes.value } }); toast('Notes saved'); } catch (e) { toast(e.message, true); } };

  function factCard(title, iconName, rows) {
    const shown = rows.filter((r) => r);
    return card(null, null, h('div', { class: 'card-body' }, h('div', { class: 'row', style: { marginBottom: '10px', color: 'var(--text-2)' } }, icon(iconName, 'sm'), h('strong', { class: 'small', style: { textTransform: 'uppercase', letterSpacing: '.05em' } }, title)),
      h('dl', { class: 'kv' }, shown.map(([k, v]) => [h('dt', null, k), h('dd', null, v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length) ? h('span', { class: 'muted' }, '–') : v)]))));
  }
  function overviewTab() {
    const lr = s.last_result || {};
    const tls = lr.tls || {};
    const left = daysUntil(s.tls_not_after);
    const scans = [...hist.scans].sort((a, b) => a.scan_id - b.scan_id).slice(-48);
    const uptime = h('div', null,
      h('div', { class: 'uptime', role: 'img', 'aria-label': `Answered in ${scans.filter((x) => answered.has(x.scan_id)).length} of ${scans.length} scans` },
        scans.map((x) => { const ok = answered.has(x.scan_id); const i = h('i', { class: ok ? '' : 'miss', tabindex: '0' });
          const show = (e) => showTip(e.clientX !== undefined ? e : i.getBoundingClientRect(), `Scan #${x.scan_id}`, [{ value: ok ? 'answered' : 'no response', label: fmtDateTime(x.started_at) }]);
          i.addEventListener('pointermove', show); i.addEventListener('pointerleave', hideTip); i.addEventListener('focus', show); i.addEventListener('blur', hideTip); return i; })),
      h('div', { class: 'uptime-legend' }, h('span', null, h('i'), 'answered'), h('span', null, h('i', { class: 'miss' }), 'no response'),
        h('span', { class: 'grow' }), h('span', null, `${num(s.seen_count)} of ${num(hist.scans.length)} scans`)));
    const facts = h('div', { class: mode === 'page' ? 'facts' : 'facts one' },
      factCard('Response', 'globe', [
        ['URLs', (s.urls || []).length ? h('div', { class: 'stack sm' }, s.urls.map((u) => h('span', { class: 'mono' }, extLink(u)))) : null],
        ['Status', codeEl(s.status_code)], ['Title', s.title], ['Server', s.webserver],
        ['Redirect', s.location ? h('span', { class: 'mono' }, s.location) : null],
        ['Content', s.content_type ? `${s.content_type} · ${num(s.content_length)} bytes` : null],
        ['Technologies', chips(s.tech, 30, (t) => filterTo({ tech: t }))]]),
      factCard('Network', 'server', [
        ['IPs', (s.ips || []).length ? h('span', { class: 'mono' }, s.ips.join(', ')) : null],
        ['CNAME', (s.cname || []).length ? h('span', { class: 'mono' }, s.cname.join(', ')) : null],
        ['CDN / WAF', s.cdn_name],
        ['DNS (last)', s.dns ? (s.dns.resolves ? h('span', { class: 'mono' }, [...s.dns.a, ...s.dns.aaaa].join(', ') || 'resolves') : h('span', { class: 'pill failed' }, 'no answer')) : null]]),
      factCard('TLS', 'lock', [
        ['Subject', s.tls_subject_cn], ['Issuer', s.tls_issuer],
        ['Expires', s.tls_not_after ? h('span', null, fmtDate(s.tls_not_after), ' ', h('span', { class: `pill ${left < 0 ? 'failed' : left <= 14 ? 'partial' : ''}` }, left < 0 ? 'expired' : `${left}d left`)) : null],
        ['SANs', (tls.subject_an || []).length ? chips(tls.subject_an, 10) : null], ['Version', tls.tls_version]]),
      factCard('Fingerprints & history', 'layers', [
        ['Favicon', s.favicon ? h('button', { class: 'chip link mono', title: 'Find hosts with the same favicon', onclick: () => filterTo({ q: `favicon:${s.favicon}` }) }, s.favicon) : null],
        ['Body hash', s.body_hash ? h('button', { class: 'chip link mono', title: 'Find hosts serving an identical page', onclick: () => filterTo({ q: `hash:${s.body_hash}` }) }, s.body_hash.slice(0, 16) + '…') : null],
        ['Discovered by', chips(s.sources, 12, (src) => filterTo({ q: `source:${src}` }))],
        ['First seen', h('span', { title: utcTitle(s.first_seen) }, `${fmtDateTime(s.first_seen)} · scan #${s.first_scan_id}`)],
        ['Last seen', h('span', { title: utcTitle(s.last_seen) }, fmtDateTime(s.last_seen))],
        ['Last checked', h('span', { title: utcTitle(s.last_checked) }, fmtDateTime(s.last_checked))]]));
    const tagsCard = card('Tags', null, h('div', { class: 'card-body' }, tagBox,
      h('div', { class: 'tag-editor' }, tagInput, h('button', { class: 'btn', onclick: () => addTag(tagInput.value) }, 'Add')),
      h('datalist', { id: `tags-${id}` }, tags.map((t) => h('option', { value: t.name }))),
      h('div', { class: 'quick-tags' }, ['interesting', 'in-scope', 'out-of-scope', 'ignore', 'reported'].filter((n) => !s.tags.some((t) => t.name === n))
        .map((n) => h('button', { class: 'btn ghost xs', onclick: () => addTag(n) }, `+ ${n}`)))));
    const notesCard = card('Notes', null, h('div', { class: 'card-body' }, notes, h('div', { class: 'row', style: { marginTop: '8px' } }, h('span', { class: 'grow' }), h('button', { class: 'btn primary sm', onclick: saveNotes }, 'Save notes'))));
    return [
      s.status === 'offline' ? h('div', { class: 'callout bad' }, icon('alert'), h('div', null, h('strong', null, `Offline since ${fmtDateTime(s.status_changed_at)}. `),
        s.offline_reason === 'dns' ? 'DNS no longer resolves.' : 'DNS resolves, but nothing answers on HTTP(S).', ` The data below is from the last time it was alive (${rel(s.last_seen)}).`)) : null,
      card('Availability', `last ${scans.length} scans of ${s.root}`, h('div', { class: 'card-body' }, uptime)),
      h('div', { class: mode === 'page' ? 'grid cols-1-1' : 'stack' }, tagsCard, notesCard),
      facts,
    ];
  }
  function timelineTab() {
    if (!hist.events.length) return empty('No events', null, 'changes');
    return card(null, null, h('div', { class: 'card-body' }, h('ul', { class: 'timeline' }, hist.events.map((e) => h('li', { vars: { '--ev-c': `var(--ev-${e.type})` } },
      h('span', { class: 'mk' }), h('div', { class: 'when', title: utcTitle(e.created_at) }, `${fmtDateTime(e.created_at)} · scan #${e.scan_id}`),
      h('div', { class: 'what' }, evEl(e.type), ' ', h('span', { class: 'text-2' }, e.type === 'changed' ? '' : eventSummary(e))),
      diffBlock((e.details || {}).changes))))));
  }
  function probesTab() {
    return card(null, null, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['Scan', 'When', 'URL', 'Code', 'Title', 'Bytes', ''].map((t) => h('th', null, t)))),
      h('tbody', null, probeRows.length ? probeRows.map((r) => r.missed
        ? h('tr', null, h('td', { class: 'mono' }, h('a', { href: `#/scans/${r.scan_id}`, onclick: closeDrawer }, `#${r.scan_id}`)), h('td', { class: 'when' }, fmtDateTime(r.observed_at)), h('td', { colspan: 5, class: 'muted' }, 'no response in this scan'))
        : h('tr', null, h('td', { class: 'mono' }, h('a', { href: `#/scans/${r.scan_id}`, onclick: closeDrawer }, `#${r.scan_id}`)), h('td', { class: 'when' }, fmtDateTime(r.observed_at)),
          h('td', { class: 'mono small' }, r.url, r.phase !== 'main' ? h('span', { class: 'pill', style: { marginLeft: '6px' } }, r.phase) : null), h('td', null, codeEl(r.status_code)),
          h('td', { class: 'ellipsis', style: { maxWidth: '220px' }, title: r.title || '' }, r.title || ''), h('td', { class: 'num' }, num(r.content_length)),
          h('td', null, h('button', { class: 'btn xs', onclick: async () => jsonModal(`httpx JSON · ${r.url} · scan #${r.scan_id}`, await api(`/api/results/${r.id}`)) }, 'JSON'))))
        : h('tr', null, h('td', { colspan: 7 }, empty('No probes recorded')))))));
  }
  function dnsTab() {
    return card(null, null, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['Scan', 'When', 'Answer', 'A / AAAA', 'CNAME'].map((t) => h('th', null, t)))),
      h('tbody', null, hist.dns.length ? hist.dns.map((d) => h('tr', null, h('td', { class: 'mono' }, `#${d.scan_id}`), h('td', { class: 'when' }, fmtDateTime(d.observed_at)),
        h('td', null, d.resolves ? statusEl('active', null) : h('span', { class: 'pill failed' }, 'no answer')),
        h('td', { class: 'mono small' }, [...d.a, ...d.aaaa].join(', ')), h('td', { class: 'mono small' }, d.cname.join(', '))))
        : h('tr', null, h('td', { colspan: 5 }, empty('No DNS history')))))));
  }
  function jsonTab() {
    const text = JSON.stringify(s.last_result, null, 2);
    return [h('div', { class: 'row' }, h('span', { class: 'muted small' }, 'Full httpx output of the latest successful probe.'), h('span', { class: 'grow' }),
      h('button', { class: 'btn sm', onclick: () => copy(text, 'JSON copied') }, icon('copy', 'sm'), 'Copy')), h('pre', { class: 'json' }, text)];
  }
  function paintContent() {
    const map = { overview: overviewTab, timeline: timelineTab, probes: probesTab, dns: dnsTab, json: jsonTab };
    replace(content, (map[tab] || overviewTab)());
  }
  paintTags(s.tags); paintTabs(); paintContent();

  const pos = drawerList.indexOf(id);
  const header = h('div', { class: 'hd-head' },
    h('div', { class: 'hd-top' },
      h('div', { class: 'hd-title' }, h('h2', null, s.host),
        h('div', { class: 'meta' }, statusEl(s.status), codeEl(s.status_code), s.title ? h('span', { class: 't ellipsis', style: { maxWidth: '320px' }, title: s.title }, s.title) : null,
          h('span', { class: 'mono small' }, s.root))),
      h('div', { class: 'hd-actions' },
        mode === 'drawer' && pos >= 0 ? [
          h('button', { class: 'btn icon sm', title: 'Previous (k)', 'aria-label': 'Previous host', disabled: pos <= 0, onclick: () => openHost(drawerList[pos - 1]) }, icon('chevronUp')),
          h('button', { class: 'btn icon sm', title: 'Next (j)', 'aria-label': 'Next host', disabled: pos >= drawerList.length - 1, onclick: () => openHost(drawerList[pos + 1]) }, icon('chevronDown'))] : null,
        h('button', { class: 'btn icon sm', title: 'Copy host', 'aria-label': 'Copy host', onclick: () => copy(s.host, 'Host copied') }, icon('copy')),
        s.url && safeUrl(s.url) ? h('a', { class: 'btn icon sm', href: safeUrl(s.url), target: '_blank', rel: 'noopener noreferrer', title: 'Open in new tab', 'aria-label': 'Open in new tab' }, icon('external')) : null,
        mode === 'drawer' ? h('a', { class: 'btn icon sm', href: `#/host/${id}`, title: 'Open as page', 'aria-label': 'Open as page', onclick: closeDrawer }, icon('expand')) : null,
        mode === 'drawer' ? h('button', { class: 'btn icon sm', title: 'Close (Esc)', 'aria-label': 'Close', onclick: closeDrawer }, icon('close')) : null)),
    tabsEl);
  return h('div', null, header, content);
}

// =============================================================================================
// Changes
// =============================================================================================
routes.changes = async (_parts, params) => {
  const st = { type: params.get('type') || '', root: params.get('root') || '', days: params.has('days') ? params.get('days') : '30', q: params.get('q') || '' };
  const facets = await getGlobalFacets();
  let page = 1, items = [], total = 0, counts = {};
  const listEl = h('div');
  const segEl = h('div', { style: { minWidth: '0', maxWidth: '100%' } });
  const moreEl = h('div', { class: 'row', style: { justifyContent: 'center', marginTop: '8px' } });
  const update = (c) => { Object.assign(st, c); setHashQuiet('changes', st); page = 1; items = []; load(); };
  const q = h('input', { type: 'search', placeholder: 'Host contains…', value: st.q, 'aria-label': 'Host filter', style: { width: '220px' } });
  q.addEventListener('input', debounce(() => update({ q: q.value.trim() }), 280));
  function paint() {
    const all = Object.values(counts).reduce((a, b) => a + b, 0);
    replace(segEl, seg([['', 'All', all], ...['new', 'changed', 'offline', 'back_online'].map((t) => [t, EV_LABEL[t], counts[t] || 0])], st.type, (v) => update({ type: v }), { 'aria-label': 'Event type' }));
    if (!items.length) { replace(listEl, card(null, null, empty('No changes in this range', 'Try a longer period or another domain.', 'changes'))); clear(moreEl); return; }
    const groups = [];
    for (const e of items) { const k = dayKey(e.created_at); let g = groups[groups.length - 1]; if (!g || g.key !== k) { g = { key: k, items: [] }; groups.push(g); } g.items.push(e); }
    replace(listEl, groups.map((g) => h('div', { class: 'day-group' }, h('h4', null, dayLabel(g.key), h('span', null, `${g.items.length} event${g.items.length === 1 ? '' : 's'}`)),
      card(null, null, h('ul', { class: 'feed' }, g.items.map((e) => h('li', { class: 'clickable', onclick: () => openHost(e.subdomain_id) },
        h('span', { class: 'evcol' }, evEl(e.type)),
        h('div', { style: { minWidth: 0 } }, h('div', { class: 'host ellipsis' }, e.host),
          e.type === 'changed' ? diffBlock(e.details.changes) : h('div', { class: 'desc', title: eventSummary(e) }, eventSummary(e))),
        h('span', { class: 't' }, h('div', null, fmtTime(e.created_at)), h('div', { class: 'mono' }, e.root)))))))));
    replace(moreEl, items.length < total ? h('button', { class: 'btn', onclick: () => { page += 1; load(true); } }, `Load more (${num(total - items.length)} left)`) : h('span', { class: 'muted small' }, `${num(total)} events`));
  }
  async function load(more = false) {
    try {
      const r = await api('/api/events' + qs({ ...st, page, per_page: 100 }));
      items = more ? items.concat(r.items) : r.items; total = r.total; counts = r.type_counts || {};
      paint();
    } catch (e) { toast(e.message, true); }
  }
  await load();
  return h('div', null, head('Changes', 'Everything that appeared, changed, disappeared or came back.'),
    h('div', { class: 'row', style: { marginBottom: '18px' } }, segEl, h('span', { class: 'grow' }), q,
      selectEl([['', 'All domains'], ...facets.roots.map((r) => [r, r])], st.root, (v) => update({ root: v }), { 'aria-label': 'Domain' }),
      selectEl([['1', 'Last 24 hours'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days'], ['365', 'Last year'], ['', 'All time']], st.days, (v) => update({ days: v }), { 'aria-label': 'Period' })),
    listEl, moreEl);
};

// =============================================================================================
// Scans
// =============================================================================================
routes.scans = async ([scanId]) => {
  if (scanId) return scanDetail(scanId);
  const [scans, requests, ov] = await Promise.all([api('/api/scans?per_page=100'), api('/api/scan-requests'), api('/api/overview')]);
  const queue = requests.filter((r) => ['queued', 'running'].includes(r.status) || Date.now() - parseTs(r.requested_at) < 86400e3 * 3);
  return h('div', null,
    head('Scans', 'Every run with its funnel, warnings and results.', h('button', { class: 'btn primary', onclick: newScanDialog }, icon('plus'), 'New scan')),
    !ov.worker.online && requests.some((r) => r.status === 'queued') ? h('div', { class: 'callout warn', style: { marginBottom: '16px' } }, icon('alert'),
      h('div', null, 'Scans are queued, but no worker is running. Start it with ', h('code', null, 'make worker'), ' – or run scans from the command line.')) : null,
    h('div', { class: 'stack' },
      queue.length ? card('Queue', 'scans requested from the dashboard', h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
        h('thead', null, h('tr', null, ['Status', 'Domains', 'Options', 'Requested', 'Scan', ''].map((t) => h('th', null, t)))),
        h('tbody', null, queue.map((r) => h('tr', null, h('td', null, pill(r.status, r.error || null)), h('td', { class: 'mono small' }, r.domains),
          h('td', { class: 'muted small' }, Object.entries(r.params).map(([k, v]) => `${k}=${v}`).join(' ') || 'defaults'), h('td', { class: 'when' }, when(r.requested_at)),
          h('td', null, r.scan_id ? h('a', { class: 'mono', href: `#/scans/${r.scan_id}` }, `#${r.scan_id}`) : '–'),
          h('td', null, r.status === 'queued' ? h('button', { class: 'btn xs danger', onclick: async () => { try { await api(`/api/scan-requests/${r.id}`, { method: 'DELETE' }); render(); } catch (e) { toast(e.message, true); } } }, 'Cancel') : null))))))) : null,
      card('History', `${num(scans.total)} scans`, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
        h('thead', null, h('tr', null, ['Status', 'Scan', 'Started', 'Duration', 'Domains', 'Result', ''].map((t) => h('th', null, t)))),
        h('tbody', null, scans.items.length ? scans.items.map((sc) => {
          const warn = sc.roots.reduce((a, r) => a + r.warnings.length, 0);
          return h('tr', { class: 'clickable', onclick: () => go(`scans/${sc.id}`) },
            h('td', null, pill(sc.status, sc.error || null)), h('td', null, h('div', { class: 'mono' }, `#${sc.id}`), h('div', { class: 'muted small' }, sc.trigger)),
            h('td', { class: 'when' }, h('div', null, when(sc.started_at)), h('div', { class: 'muted small' }, fmtDateTime(sc.started_at))),
            h('td', { class: 'when' }, sc.finished_at ? duration(sc.started_at, sc.finished_at) : 'running…'),
            h('td', null, chips(sc.roots.map((r) => r.domain), 3)), h('td', null, scanTotals(sc.totals)),
            h('td', null, warn ? h('span', { class: 'pill partial', title: 'Warnings' }, icon('alert', 'sm'), warn) : null));
        }) : h('tr', null, h('td', { colspan: 7 }, empty('No scans yet', h('span', null, 'Run one: ', h('code', null, 'make scan domain=example.com')), 'scans')))))))));
};

async function scanDetail(id) {
  const s = await api(`/api/scans/${id}`);
  const funnel = (st) => {
    const steps = [['Candidates', st.candidates], ['Resolve', st.resolved], ['Probed', st.probed], ['Alive', st.alive]].filter(([, v]) => v !== undefined);
    return barList(steps.map(([name, count]) => ({ name, count: count || 0 })), { max: 4 });
  };
  return h('div', null,
    h('div', { class: 'crumbs', style: { margin: '8px 0 10px' } }, h('a', { href: '#/scans' }, 'Scans'), icon('chevronRight', 'sm'), h('span', null, `#${s.id}`)),
    head(`Scan #${s.id}`, `${fmtDateTime(s.started_at)} · ${s.finished_at ? duration(s.started_at, s.finished_at) : 'running'} · ${s.trigger}`, pill(s.status)),
    s.error ? h('div', { class: 'callout bad', style: { marginBottom: '16px' } }, icon('alert'), s.error) : null,
    h('div', { class: 'stack' },
      s.roots.map((r) => {
        const st = r.stats || {};
        return card(r.domain, null, h('div', { class: 'card-body grid cols-1-1' },
          h('div', null, h('div', { class: 'label' }, 'Validation funnel'), funnel(st)),
          h('div', { class: 'stack sm' },
            h('div', { class: 'label' }, 'Discovery'),
            h('div', { class: 'metric-row' }, h('span', null, h('b', null, num(st.passive)), 'subfinder'), h('span', null, h('b', null, num(st.brute)), `brute force (${num(st.wordlist_size)} words)`),
              h('span', null, h('b', null, num(st.tls_san)), 'TLS SANs'), st.imported ? h('span', null, h('b', null, num(st.imported)), 'imported') : null,
              st.brute_wildcard_filtered ? h('span', null, h('b', null, num(st.brute_wildcard_filtered)), 'wildcard answers dropped') : null),
            h('div', { class: 'label', style: { marginTop: '8px' } }, 'Changes'),
            h('div', { class: 'metric-row' }, ['new', 'changed', 'went_offline', 'back_online'].map((k) => h('span', { class: `ev ${k === 'went_offline' ? 'offline' : k}` }, h('b', null, num(st[k])), EV_LABEL[k === 'went_offline' ? 'offline' : k].toLowerCase())),
              h('span', null, h('b', null, num(st.still_offline)), 'still offline'), h('span', null, h('b', null, num(st.unchanged)), 'unchanged')),
            h('div', { class: 'metric-row', style: { marginTop: '8px' } }, h('span', null, icon('clock', 'sm'), st.duration_s ? `${st.duration_s}s` : '–'), st.rechecked ? h('span', null, `${num(st.rechecked)} rechecked`) : null),
            r.warnings.length ? h('div', { class: 'callout warn', style: { marginTop: '8px' } }, icon('alert'), h('ul', { class: 'warnings' }, r.warnings.map((w) => h('li', null, w)))) : null,
            r.error ? h('div', { class: 'callout bad' }, icon('alert'), r.error) : null)),
        [pill(r.status), st.wildcard ? h('span', { class: 'pill', title: 'wildcard DNS detected' }, 'wildcard') : null,
          h('a', { class: 'btn ghost sm', href: '#/assets' + qs({ root: r.domain }) }, 'Assets'), h('a', { class: 'btn ghost sm', href: '#/changes' + qs({ root: r.domain, days: '' }) }, 'Changes')]);
      }),
      card('Parameters & tool versions', null, h('div', { class: 'card-body' }, h('pre', { class: 'json' }, JSON.stringify({ tool_versions: s.tool_versions, params: s.params, output_dir: s.output_dir }, null, 2))))));
}

// =============================================================================================
// Domains & Tags
// =============================================================================================
routes.domains = async () => {
  const roots = await api('/api/roots');
  return h('div', null,
    head('Domains', `${roots.length} root domain${roots.length === 1 ? '' : 's'} tracked`, [
      h('button', { class: 'btn', onclick: () => queueScan('all') }, icon('refresh'), 'Re-scan all'), h('button', { class: 'btn primary', onclick: newScanDialog }, icon('plus'), 'Add domain')]),
    roots.length ? h('div', { class: 'domain-grid' }, roots.map((r) => h('div', { class: 'card domain-card' },
      h('div', { class: 'top' }, icon('globe'), h('a', { class: 'name', href: '#/assets' + qs({ root: r.domain }), title: r.domain }, r.domain),
        r.wildcard ? h('span', { class: 'pill', title: 'Wildcard DNS detected' }, 'wildcard') : null, h('span', { class: 'grow' }),
        r.last_scan_status && r.last_scan_status !== 'success' ? pill(r.last_scan_status) : null),
      h('div', { class: 'nums' }, h('div', null, h('b', null, compact(r.total)), h('span', null, 'hosts')), h('div', null, h('b', null, compact(r.active)), h('span', null, 'active')),
        h('div', null, h('b', null, r.new_7d ? `+${compact(r.new_7d)}` : '0'), h('span', null, 'new · 7d'))),
      h('div', { class: 'meter-row' }, meter(r.active, r.total), h('span', { class: 'tnum' }, `${pct(r.active, r.total)}% available`)),
      h('div', { class: 'bottom' }, icon('clock', 'sm'), r.last_scan_id ? h('a', { href: `#/scans/${r.last_scan_id}`, title: utcTitle(r.last_scan_at) }, `scanned ${rel(r.last_scan_at)}`) : 'never scanned',
        h('span', { class: 'grow' }), h('a', { class: 'btn ghost xs', href: '#/changes' + qs({ root: r.domain }) }, 'Changes'), h('button', { class: 'btn xs', onclick: () => queueScan(r.domain) }, icon('refresh', 'sm'), 'Re-scan')))))
      : card(null, null, empty('No domains yet', h('span', null, 'Add one with “Add domain”, or run ', h('code', null, 'make scan domain=example.com')), 'domains')));
};

routes.tags = async () => {
  const tags = await api('/api/tags');
  const name = h('input', { type: 'text', placeholder: 'New tag name', 'aria-label': 'New tag name', style: { width: '240px' } });
  const color = h('input', { type: 'color', value: '#4f46e5', 'aria-label': 'Tag color' });
  const create = async () => {
    if (!name.value.trim()) return name.focus();
    try { await api('/api/tags', { method: 'POST', body: { name: name.value.trim(), color: color.value } }); globalFacets = null; render(); } catch (e) { toast(e.message, true); }
  };
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') create(); });
  return h('div', null,
    head('Tags', 'Active / offline is tracked automatically – tags are yours.', h('div', { class: 'row' }, name, color, h('button', { class: 'btn primary', onclick: create }, icon('plus'), 'Create'))),
    tags.length ? h('div', { class: 'tag-grid' }, tags.map((t) => {
      const input = h('input', { type: 'text', value: t.name, 'aria-label': 'Tag name' });
      const col = h('input', { type: 'color', value: t.color, 'aria-label': 'Tag color' });
      const save = async () => { try { await api(`/api/tags/${t.id}`, { method: 'PATCH', body: { name: input.value.trim(), color: col.value } }); globalFacets = null; toast('Tag saved'); } catch (e) { toast(e.message, true); } };
      input.addEventListener('change', save); col.addEventListener('change', save);
      return h('div', { class: 'card tag-card' }, col, input,
        h('a', { class: 'btn ghost sm', href: '#/assets' + qs({ tag: t.name }), title: 'Show tagged assets' }, num(t.count)),
        h('button', { class: 'btn ghost icon sm danger', 'aria-label': `Delete tag ${t.name}`, onclick: async () => {
          if (!confirm(`Delete tag "${t.name}"? It is removed from ${t.count} assets – the assets stay.`)) return;
          try { await api(`/api/tags/${t.id}`, { method: 'DELETE' }); globalFacets = null; render(); } catch (e) { toast(e.message, true); }
        } }, icon('trash')));
    })) : card(null, null, empty('No tags yet', 'Select rows in Assets and add a tag, or tag a host from its detail panel.', 'tags')));
};

// =============================================================================================
// scan dialog, command palette, shortcuts
// =============================================================================================
async function queueScan(domains, params = {}) {
  try {
    const r = await api('/api/scan-requests', { method: 'POST', body: { domains, params } });
    const ov = await api('/api/overview');
    toast(ov.worker.online ? `Scan request #${r.id} queued` : `Queued #${r.id} – start the worker (make worker) to run it`, !ov.worker.online);
    refreshChrome();
    if (parseHash().parts[0] === 'scans') render();
  } catch (e) { toast(e.message, true); }
}
async function newScanDialog() {
  const ov = await api('/api/overview').catch(() => ({ worker: { online: false } }));
  const domains = h('textarea', { rows: 4, placeholder: 'example.com\nexample.org', class: 'mono' });
  const sw = (key, label, hint, checked) => h('label', { class: 'switch' }, h('input', { type: 'checkbox', checked, dataset: { key } }), h('span', null, h('b', null, label), h('small', null, hint)));
  const opts = h('div', { class: 'form-grid' },
    sw('passive', 'Passive sources', 'subfinder, all sources', true), sw('brute', 'DNS brute force', 'dnsx, wildcard-safe', true),
    sw('san', 'TLS certificate names', 'probe in-scope SANs', true), sw('force', 'Force offline marking', 'bypass the safety guard', false));
  const ports = h('input', { type: 'text', placeholder: '80,443,8080,8443  (optional)', style: { width: '100%' } });
  const submit = async () => {
    const list = domains.value.trim(); if (!list) return domains.focus();
    const params = {};
    opts.querySelectorAll('input[type=checkbox]').forEach((b) => { params[b.dataset.key] = b.checked; });
    if (ports.value.trim()) params.ports = ports.value.trim();
    await queueScan(list.split(/[\s,]+/).filter(Boolean).join(','), params);
    $('#modal').close();
  };
  modal('New scan', h('div', { class: 'stack' },
    !ov.worker.online ? h('div', { class: 'callout warn' }, icon('alert'), h('div', null, 'No worker is running, so this scan will wait in the queue. Start it with ', h('code', null, 'make worker'), ', or run ', h('code', null, 'make scan domain=…'), ' instead.')) : null,
    h('div', null, h('label', { class: 'label' }, 'Root domains'), domains, h('div', { class: 'hint' }, 'One per line or comma separated – everything below each domain is in scope.')),
    opts, h('div', null, h('label', { class: 'label' }, 'Ports'), ports)),
  [h('button', { class: 'btn', onclick: () => $('#modal').close() }, 'Cancel'), h('button', { class: 'btn primary', onclick: submit }, icon('scans'), 'Queue scan')]);
  setTimeout(() => domains.focus(), 30);
}

function openPalette() {
  const dlg = $('#palette');
  const input = h('input', { type: 'text', placeholder: 'Search hosts, jump to pages, run actions…', 'aria-label': 'Command palette', autocomplete: 'off', spellcheck: 'false' });
  const list = h('div', { class: 'palette-list', role: 'listbox' });
  let items = [], idx = 0, req = 0;
  const base = () => [
    ...NAV.map((n) => ({ group: 'Pages', label: n.label, icon: n.icon, run: () => go(n.view) })),
    { group: 'Actions', label: 'New scan…', icon: 'plus', run: newScanDialog },
    { group: 'Actions', label: 'Re-scan all domains', icon: 'refresh', run: () => queueScan('all') },
    { group: 'Actions', label: 'Toggle dark mode', icon: 'moon', run: toggleTheme },
    { group: 'Actions', label: 'Keyboard shortcuts', icon: 'keyboard', run: shortcutsDialog },
    ...(globalFacets?.roots || []).map((r) => ({ group: 'Domains', label: r, icon: 'globe', run: () => go('assets', { root: r }) })),
    ...(globalFacets?.tags || []).slice(0, 20).map((t) => ({ group: 'Tags', label: t.name, icon: 'tags', run: () => go('assets', { tag: t.name }) })),
  ];
  const paint = () => {
    clear(list);
    let group = null;
    items.forEach((it, i) => {
      if (it.group !== group) { group = it.group; list.append(h('div', { class: 'suggest group' }, group)); }
      list.append(h('div', { class: 'suggest item' + (i === idx ? ' on' : ''), role: 'option', onmousedown: (e) => { e.preventDefault(); exec(it); }, onmousemove: () => { if (idx !== i) { idx = i; paint(); } } },
        icon(it.icon || 'search', 'sm'), h('span', { class: 'lbl' }, it.label), it.hint ? h('span', { class: 'hint' }, it.hint) : null));
    });
    if (!items.length) list.append(h('div', { class: 'muted small', style: { padding: '14px' } }, 'No matches'));
    const on = list.querySelector('.item.on'); if (on) on.scrollIntoView({ block: 'nearest' });
  };
  const exec = (it) => { dlg.close(); it.run(); };
  const refreshList = () => {
    const q = input.value.trim().toLowerCase();
    items = base().filter((it) => !q || it.label.toLowerCase().includes(q));
    if (q) items.push({ group: 'Search', label: `Search assets for “${input.value.trim()}”`, icon: 'search', run: () => go('assets', { q: input.value.trim() }) });
    idx = 0; paint();
    if (q.length >= 2) {
      const r = ++req;
      api('/api/subdomains' + qs({ q: `host:${q}`, per_page: 8, sort: 'host', order: 'asc' })).then((res) => {
        if (r !== req || !res.items.length) return;
        items = [...res.items.map((s) => ({ group: 'Hosts', label: s.host, hint: s.title || s.status, icon: 'assets', run: () => openHost(s.id) })), ...items];
        idx = 0; paint();
      }).catch(() => {});
    }
  };
  input.addEventListener('input', refreshList);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); idx = Math.min(items.length - 1, idx + 1); paint(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); idx = Math.max(0, idx - 1); paint(); }
    else if (e.key === 'Enter') { e.preventDefault(); if (items[idx]) exec(items[idx]); }
  });
  replace(dlg, h('div', { class: 'palette-box' }, h('div', { class: 'palette-input' }, icon('search', 'lg'), input, h('span', { class: 'kbd' }, 'Esc')), list,
    h('div', { class: 'palette-foot' }, h('span', null, h('span', { class: 'kbd' }, '↑↓'), ' navigate'), h('span', null, h('span', { class: 'kbd' }, '↵'), ' open'), h('span', null, h('span', { class: 'kbd' }, '?'), ' all shortcuts'))));
  getGlobalFacets().then(refreshList).catch(refreshList);
  if (!dlg.open) dlg.showModal();
  input.focus();
}
dialogBackdropClose($('#palette'));

function shortcutsDialog() {
  const rows = [[['⌘', 'K'], 'Command palette – hosts, pages, actions'], [['/'], 'Search assets'], [['j'], 'Next row / next host in the panel'], [['k'], 'Previous row / host'],
    [['↵'], 'Open the highlighted row'], [['x'], 'Select the highlighted row'], [['Esc'], 'Close panel / dialog'], [['g', 'o'], 'Go to Overview'], [['g', 'a'], 'Go to Assets'],
    [['g', 'c'], 'Go to Changes'], [['g', 's'], 'Go to Scans'], [['g', 'd'], 'Go to Domains'], [['g', 't'], 'Go to Tags'], [['?'], 'This help']];
  modal('Keyboard shortcuts', h('div', { class: 'shortcuts' }, rows.map(([keys, label]) => [h('span', { class: 'keys' }, keys.map((k) => h('span', { class: 'kbd' }, k))), h('span', null, label)])));
}

// =============================================================================================
// chrome: theme, worker status, sidebar, keyboard
// =============================================================================================
function currentTheme() { return document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); }
function paintThemeButton() { replace($('#theme-toggle'), icon(currentTheme() === 'dark' ? 'sun' : 'moon'), currentTheme() === 'dark' ? 'Light' : 'Dark'); }
function toggleTheme() { document.documentElement.dataset.theme = currentTheme() === 'dark' ? 'light' : 'dark'; store.set('theme', document.documentElement.dataset.theme); paintThemeButton(); }
async function refreshChrome() {
  try {
    const ov = await api('/api/overview');
    const changes = Object.values(ov.events_7d || {}).reduce((a, b) => a + b, 0);
    const tags = globalFacets?.tags?.length;
    chromeStats = { total: ov.total, roots: ov.roots, changes_7d: changes, tags };
    renderNav(document.querySelector('.nav-item.active')?.getAttribute('href')?.slice(2) || parseHash().parts[0] || 'overview');
    const w = $('#worker');
    const queued = (ov.queue.queued || 0) + (ov.queue.running || 0);
    w.className = 'worker' + (ov.running_scans ? ' busy' : ov.worker.online ? ' on' : '');
    replace(w, h('span', { class: 'dot' }), h('span', null, ov.running_scans ? `Scanning${queued ? ` · ${queued} queued` : '…'}` : ov.worker.online ? `Worker online${queued ? ` · ${queued} queued` : ''}` : 'Worker offline'));
    w.title = ov.worker.online ? `Last heartbeat ${fmtDateTime(ov.worker.heartbeat)}` : 'Only needed for scans started from the dashboard: make worker';
    $('#version').textContent = `v${ov.version}`;
  } catch { /* ignore */ }
}
function closeSidebar() { $('#sidebar').classList.remove('open'); if (!drawerOpen()) $('#scrim').classList.remove('show'); }

let gPending = false;
document.addEventListener('keydown', (e) => {
  const typing = e.target.closest && e.target.closest('input, textarea, select, [contenteditable]');
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
  if (e.key === 'Escape') { if ($('#modal').open || $('#palette').open) return; if (closeDrawer()) return; closeSidebar(); return; }
  if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
  if (gPending) {
    gPending = false;
    const map = { o: 'overview', a: 'assets', c: 'changes', s: 'scans', d: 'domains', t: 'tags' };
    if (map[e.key]) { e.preventDefault(); closeDrawer(); go(map[e.key]); }
    return;
  }
  if (e.key === 'g') { gPending = true; setTimeout(() => { gPending = false; }, 1200); return; }
  if (e.key === '/') { e.preventDefault(); const s = $('#asset-search'); if (s && !drawerOpen()) s.focus(); else openPalette(); return; }
  if (e.key === '?') { e.preventDefault(); shortcutsDialog(); return; }
  if (parseHash().parts[0] === 'assets' && assetsKeys && assetsKeys(e)) { e.preventDefault(); return; }
  if (drawerOpen() && (e.key === 'j' || e.key === 'k') && drawerList.length) {
    const next = drawerList[drawerList.indexOf(drawerId) + (e.key === 'j' ? 1 : -1)];
    if (next) openHost(next);
  }
});

function init() {
  const saved = store.get('theme', null);
  if (saved) document.documentElement.dataset.theme = saved;
  paintThemeButton();
  $('#theme-toggle').addEventListener('click', toggleTheme);
  append($('#shortcuts-btn'), icon('keyboard'));
  $('#shortcuts-btn').addEventListener('click', shortcutsDialog);
  append($('#menu-btn'), icon('menu'));
  $('#menu-btn').addEventListener('click', () => { $('#sidebar').classList.add('open'); $('#scrim').classList.add('show'); });
  $('#scrim').addEventListener('click', () => { closeDrawer(); closeSidebar(); });
  append($('#search-trigger'), icon('search'), h('span', null, 'Search hosts, pages, actions…'), h('span', { class: 'kbd' }, navigator.platform.includes('Mac') ? '⌘K' : 'Ctrl K'));
  $('#search-trigger').addEventListener('click', openPalette);
  append($('#new-scan'), icon('plus'), h('span', null, 'New scan'));
  $('#new-scan').addEventListener('click', newScanDialog);
  getGlobalFacets().catch(() => {}).finally(refreshChrome);
  setInterval(refreshChrome, 20000);
  render();
}
init();
