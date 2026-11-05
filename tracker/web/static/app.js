/* subtrack dashboard – dependency-free SPA.
 * Security: scanned data (titles, headers, hosts) is attacker-controlled. Everything is rendered with
 * textContent via h(); innerHTML is never used with data. Links to targets are restricted to http(s). */
'use strict';

// ------------------------------------------------------------------ helpers
const $ = (sel, root = document) => root.querySelector(sel);

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'vars') for (const [name, val] of Object.entries(v)) el.style.setProperty(name, val);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = !!v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, children);
  return el;
}
function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }

function safeUrl(url) {
  try { const u = new URL(url); return (u.protocol === 'http:' || u.protocol === 'https:') ? u.href : null; }
  catch { return null; }
}
function extLink(url, label) {
  const href = safeUrl(url);
  if (!href) return h('span', null, label ?? url ?? '');
  return h('a', { href, target: '_blank', rel: 'noopener noreferrer' }, label ?? url);
}

function parseTs(ts) { return ts ? new Date(ts.endsWith('Z') ? ts : ts + 'Z') : null; }
function fmtDate(ts) {
  const d = parseTs(ts); if (!d || isNaN(d)) return '–';
  return d.toISOString().replace('T', ' ').slice(0, 16);
}
function rel(ts) {
  const d = parseTs(ts); if (!d || isNaN(d)) return '–';
  const s = (Date.now() - d.getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 86400 * 60) return `${Math.floor(s / 86400)}d ago`;
  return fmtDate(ts).slice(0, 10);
}
function when(ts) { return h('span', { title: fmtDate(ts) + ' UTC' }, rel(ts)); }
function duration(a, b) {
  const s = (parseTs(b) - parseTs(a)) / 1000; if (!isFinite(s)) return '–';
  if (s < 60) return `${Math.round(s)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}
const num = (n) => (n ?? 0).toLocaleString();
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

function toast(msg, isError = false) {
  const el = $('#toast');
  el.textContent = msg; el.className = 'toast' + (isError ? ' error' : ''); el.hidden = false;
  clearTimeout(toast._t); toast._t = setTimeout(() => { el.hidden = true; }, isError ? 6000 : 2500);
}

async function api(path, { method = 'GET', body, raw = false } = {}) {
  const opts = { method, headers: { 'X-Subtrack': '1' } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch { /* not json */ }
    throw new Error(msg);
  }
  return raw ? res : res.json();
}
function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== '' && v !== null && v !== undefined && v !== false) p.set(k, v);
  const s = p.toString(); return s ? '?' + s : '';
}

// ------------------------------------------------------------------ small components
function statusBadge(status, title) { return h('span', { class: `badge ${status}`, title }, status.replace('_', ' ')); }
function codeEl(code) {
  if (code === null || code === undefined) return h('span', { class: 'muted' }, '–');
  return h('span', { class: `code c${String(code)[0]}` }, code);
}
function tagChip(tag, onRemove) {
  return h('span', { class: 'chip tag', vars: { '--tag': tag.color || '#6b7280' }, title: tag.name },
    tag.name, onRemove ? h('button', { title: `Remove tag ${tag.name}`, 'aria-label': `Remove tag ${tag.name}`, onclick: onRemove }, '×') : null);
}
function chipList(items, max = 3) {
  if (!items || !items.length) return h('span', { class: 'muted' }, '–');
  const shown = items.slice(0, max).map((t) => h('span', { class: 'chip', title: t }, t));
  if (items.length > max) shown.push(h('span', { class: 'chip muted', title: items.slice(max).join(', ') }, `+${items.length - max}`));
  return h('div', { class: 'cell-chips' }, shown);
}
function select(options, value, onchange, attrs = {}) {
  return h('select', { onchange: (e) => onchange(e.target.value), ...attrs },
    options.map(([v, label]) => h('option', { value: v, selected: String(v) === String(value ?? '') }, label)));
}
function emptyRow(cols, text) { return h('tr', null, h('td', { colspan: cols, class: 'empty' }, text)); }

function openModal(title, content, footer) {
  const dlg = $('#modal');
  clear($('#modal-body')).append(
    h('div', { class: 'modal-head' }, h('h2', null, title), h('button', { class: 'btn ghost icon', 'aria-label': 'Close', onclick: () => dlg.close() }, '✕')),
    h('div', { class: 'modal-content' }, content),
    footer ? h('div', { class: 'modal-foot' }, footer) : null);
  if (!dlg.open) dlg.showModal();
  return dlg;
}
function jsonModal(title, data) {
  const text = JSON.stringify(data, null, 2);
  openModal(title, h('pre', { class: 'json' }, text), [
    h('button', { class: 'btn', onclick: () => navigator.clipboard.writeText(text).then(() => toast('Copied JSON')) }, 'Copy'),
    h('button', { class: 'btn primary', onclick: () => $('#modal').close() }, 'Close')]);
}

// ------------------------------------------------------------------ routing
const routes = {};
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, '') || 'assets';
  const [path, query = ''] = raw.split('?');
  return { parts: path.split('/').filter(Boolean), params: Object.fromEntries(new URLSearchParams(query)) };
}
function go(path, params) { location.hash = '#/' + path + qs(params || {}); }
function setHashQuiet(path, params) { history.replaceState(null, '', '#/' + path + qs(params)); }

let renderToken = 0;
async function render() {
  const { parts, params } = parseHash();
  const view = parts[0] || 'assets';
  document.querySelectorAll('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.view === view || (view === 'host' && a.dataset.view === 'assets')));
  const token = ++renderToken;
  const app = $('#app');
  try {
    const node = await (routes[view] || routes.assets)(parts.slice(1), params, () => token === renderToken);
    if (token === renderToken && node) { clear(app).append(node); window.scrollTo(0, 0); }
  } catch (err) {
    if (token === renderToken) clear(app).append(h('div', { class: 'card card-pad' }, h('h2', null, 'Something went wrong'), h('p', { class: 'muted' }, err.message)));
  }
}
window.addEventListener('hashchange', render);

// ------------------------------------------------------------------ Assets view
const FILTER_KEYS = ['q', 'root', 'status', 'code', 'tech', 'server', 'tag', 'untagged', 'new_days', 'event', 'event_days', 'sort', 'order', 'page', 'per_page'];

routes.assets = async (_parts, params) => {
  const state = Object.fromEntries(FILTER_KEYS.map((k) => [k, params[k] ?? '']));
  state.sort ||= 'first_seen'; state.order ||= 'desc'; state.page ||= '1'; state.per_page ||= '50';
  const selected = new Set();
  let current = { items: [], total: 0 };

  const [overview, facets] = await Promise.all([api('/api/overview'), api('/api/facets' + qs({ root: state.root }))]);
  const tagsById = Object.fromEntries(facets.tags.map((t) => [t.name.toLowerCase(), t]));

  const tbody = h('tbody');
  const totalEl = h('span', { class: 'muted' });
  const pagerInfo = h('span', { class: 'muted small' });
  const bulk = h('div', { class: 'bulkbar hidden' });
  const headCheck = h('input', { type: 'checkbox', 'aria-label': 'Select all on page', onchange: (e) => {
    current.items.forEach((i) => (e.target.checked ? selected.add(i.id) : selected.delete(i.id)));
    paintRows(); paintBulk();
  } });

  function update(changes, resetPage = true) {
    Object.assign(state, changes);
    if (resetPage) state.page = '1';
    const visible = Object.fromEntries(Object.entries(state).filter(([k, v]) => v && !(k === 'sort' && v === 'first_seen') && !(k === 'order' && v === 'desc') && !(k === 'page' && v === '1') && !(k === 'per_page' && v === '50')));
    setHashQuiet('assets', visible);
    load();
  }

  // --- stats strip
  const ev = overview.events_7d || {};
  const statDefs = [
    ['Total', overview.total, '', {}],
    ['Active', overview.active, 'ok', { status: 'active' }],
    ['Offline', overview.offline, 'bad', { status: 'offline' }],
    ['New · 7d', overview.new_7d, 'info', { new_days: '7' }],
    ['Changed · 7d', ev.changed || 0, 'warn', { event: 'changed', event_days: '7' }],
    ['Went offline · 7d', ev.offline || 0, 'bad', { event: 'offline', event_days: '7' }],
  ];
  const stats = h('div', { class: 'stats' }, statDefs.map(([label, value, cls, f]) =>
    h('button', { class: `card stat ${cls}`, onclick: () => update({ status: '', new_days: '', event: '', event_days: '', ...f }) },
      h('div', { class: 'label' }, label), h('div', { class: 'value' }, num(value)))));

  // --- toolbar
  const search = h('input', { type: 'search', class: 'search', value: state.q, placeholder: 'Search…  e.g.  title:login  code:2xx  tech:nginx  -tag:ignore  ip:10.0.', 'aria-label': 'Search' });
  search.addEventListener('input', debounce(() => update({ q: search.value.trim() }), 300));
  const tagSelect = select([['', '+ tag filter'], ...facets.tags.map((t) => [t.name, `${t.name} (${t.count})`])], '', (v) => {
    if (!v) return; const tags = new Set(state.tag.split(',').filter(Boolean)); tags.add(v); update({ tag: [...tags].join(',') });
  });
  const tagFilterChips = h('div', { class: 'chips' }, state.tag.split(',').filter(Boolean).map((name) =>
    tagChip(tagsById[name.toLowerCase()] || { name }, () => update({ tag: state.tag.split(',').filter((t) => t && t !== name).join(',') }))));
  const exportMenu = select([['', 'Export…'], ['csv', 'CSV'], ['json', 'JSON'], ['txt', 'Hosts (.txt)'], ['urls', 'URLs (.txt)']], '', (fmt) => {
    if (!fmt) return;
    const f = Object.fromEntries(Object.entries(state).filter(([k, v]) => v && !['page', 'per_page'].includes(k)));
    window.location.href = '/api/export' + qs({ ...f, format: fmt });
  });
  const toolbar = h('div', { class: 'card toolbar' },
    h('div', { class: 'row' }, search,
      h('button', { class: 'btn', title: 'Search syntax', onclick: searchHelp }, '?'),
      h('button', { class: 'btn ghost', onclick: () => go('assets') }, 'Reset'), exportMenu),
    h('div', { class: 'row' },
      select([['', 'All domains'], ...facets.roots.map((r) => [r, r])], state.root, (v) => update({ root: v }), { 'aria-label': 'Domain' }),
      select([['', 'Any status'], ['active', 'Active'], ['offline', 'Offline']], state.status, (v) => update({ status: v }), { 'aria-label': 'Status' }),
      select([['', 'Any code'], ['2xx', '2xx'], ['3xx', '3xx'], ['4xx', '4xx'], ['5xx', '5xx'], ...facets.codes.map((c) => [c.code, `${c.code} (${c.count})`])], state.code, (v) => update({ code: v }), { 'aria-label': 'Status code' }),
      select([['', 'Any technology'], ...facets.tech.map((t) => [t.name, `${t.name} (${t.count})`])], state.tech, (v) => update({ tech: v }), { 'aria-label': 'Technology' }),
      select([['', 'Any server'], ...facets.servers.map((s) => [s.name, `${s.name} (${s.count})`])], state.server, (v) => update({ server: v }), { 'aria-label': 'Web server' }),
      select([['', 'First seen: any time'], ['1', 'New · 24h'], ['7', 'New · 7 days'], ['30', 'New · 30 days'], ['90', 'New · 90 days']], state.new_days, (v) => update({ new_days: v }), { 'aria-label': 'First seen' }),
      tagSelect,
      h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: state.untagged === '1', onchange: (e) => update({ untagged: e.target.checked ? '1' : '' }) }), 'untagged'),
      state.event ? h('span', { class: 'chip filter', title: 'Remove filter', onclick: () => update({ event: '', event_days: '' }) }, `had “${state.event}” event · ${state.event_days}d ×`) : null,
      tagFilterChips));

  // --- table
  const sortHead = (key, label) => h('th', { class: 'sortable', onclick: () => update({ sort: key, order: state.sort === key && state.order === 'desc' ? 'asc' : 'desc' }, false) },
    label, state.sort === key ? (state.order === 'asc' ? ' ▲' : ' ▼') : '');
  const table = h('table', { class: 'data' },
    h('thead', null, h('tr', null, h('th', null, headCheck), sortHead('host', 'Host'), sortHead('status', 'Status'), sortHead('status_code', 'Code'),
      sortHead('title', 'Title'), h('th', null, 'Tech'), sortHead('webserver', 'Server'), h('th', null, 'IP'),
      sortHead('first_seen', 'First seen'), sortHead('last_seen', 'Last seen'), h('th', null, 'Tags'))),
    tbody);
  const pager = h('div', { class: 'pager' }, pagerInfo,
    select([['25', '25 / page'], ['50', '50 / page'], ['100', '100 / page'], ['250', '250 / page'], ['1000', '1000 / page']], state.per_page, (v) => update({ per_page: v })),
    h('button', { class: 'btn sm', onclick: () => { if (+state.page > 1) update({ page: String(+state.page - 1) }, false); } }, '‹ Prev'),
    h('button', { class: 'btn sm', onclick: () => { if (+state.page * +state.per_page < current.total) update({ page: String(+state.page + 1) }, false); } }, 'Next ›'));

  function paintRows() {
    clear(tbody);
    if (!current.items.length) { tbody.append(emptyRow(11, overview.total ? 'No assets match these filters.' : 'No assets yet – run a scan:  make scan domain=example.com')); return; }
    for (const s of current.items) {
      const box = h('input', { type: 'checkbox', checked: selected.has(s.id), 'aria-label': `Select ${s.host}`, onchange: (e) => { e.target.checked ? selected.add(s.id) : selected.delete(s.id); paintBulk(); tr.classList.toggle('selected', e.target.checked); } });
      const tr = h('tr', { class: selected.has(s.id) ? 'selected' : '' },
        h('td', null, box),
        h('td', { class: 'host' }, h('a', { href: `#/host/${s.id}` }, s.host), s.url ? h('span', { class: 'ext' }, extLink(s.url, '↗')) : null),
        h('td', null, statusBadge(s.status, s.status === 'offline' ? `offline since ${fmtDate(s.status_changed_at)} (${s.offline_reason === 'dns' ? 'DNS no longer resolves' : 'no HTTP response'})` : `active since ${fmtDate(s.status_changed_at)}`)),
        h('td', null, codeEl(s.status_code)),
        h('td', { class: 'title' }, h('div', { title: s.title || '' }, s.title || h('span', { class: 'muted' }, '–'))),
        h('td', null, chipList(s.tech, 2)),
        h('td', { class: 'ellipsis', title: s.webserver || '' }, s.webserver || h('span', { class: 'muted' }, '–')),
        h('td', { class: 'mono nowrap', title: (s.ips || []).join(', ') }, s.ips && s.ips.length ? s.ips[0] + (s.ips.length > 1 ? ` +${s.ips.length - 1}` : '') : '–'),
        h('td', { class: 'when' }, when(s.first_seen)),
        h('td', { class: 'when' }, when(s.last_seen)),
        h('td', null, h('div', { class: 'cell-chips' }, s.tags.map((t) => tagChip(t)))));
      tbody.append(tr);
    }
  }
  function paintBulk() {
    headCheck.checked = current.items.length > 0 && current.items.every((i) => selected.has(i.id));
    clear(bulk);
    bulk.classList.toggle('hidden', selected.size === 0);
    if (!selected.size) return;
    const input = h('input', { type: 'text', placeholder: 'tag name', list: 'tag-names', 'aria-label': 'Tag name' });
    const run = async (mode, useFilter = false) => {
      const name = input.value.trim(); if (!name) { input.focus(); return; }
      const body = useFilter ? { filter: filterOnly() } : { ids: [...selected] };
      body[mode] = [name];
      try { const r = await api('/api/bulk/tags', { method: 'POST', body }); toast(`${mode === 'add' ? 'Tagged' : 'Untagged'} ${num(r.updated)} assets`); selected.clear(); load(); }
      catch (e) { toast(e.message, true); }
    };
    append(bulk, [h('strong', null, `${selected.size} selected`), input,
      h('datalist', { id: 'tag-names' }, facets.tags.map((t) => h('option', { value: t.name }))),
      h('button', { class: 'btn sm primary', onclick: () => run('add') }, 'Add tag'),
      h('button', { class: 'btn sm', onclick: () => run('remove') }, 'Remove tag'),
      current.total > selected.size ? h('button', { class: 'btn sm', title: 'Apply to every asset matching the current filters', onclick: () => run('add', true) }, `Add to all ${num(current.total)} matches`) : null,
      h('button', { class: 'btn sm ghost', onclick: () => { selected.clear(); paintRows(); paintBulk(); } }, 'Clear')]);
  }
  function filterOnly() { return Object.fromEntries(Object.entries(state).filter(([k, v]) => v && !['page', 'per_page', 'sort', 'order'].includes(k))); }

  async function load() {
    try {
      current = await api('/api/subdomains' + qs(state));
      const from = current.total ? (current.page - 1) * current.per_page + 1 : 0;
      pagerInfo.textContent = `${num(from)}–${num(Math.min(current.total, current.page * current.per_page))} of ${num(current.total)}`;
      totalEl.textContent = `${num(current.total)} matching`;
      paintRows(); paintBulk();
    } catch (e) { toast(e.message, true); }
  }
  await load();
  return h('div', null, stats, toolbar, bulk, h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, table), pager));
};

function searchHelp() {
  const rows = [
    ['login', 'free text in host, title, server, tech, IPs, URLs, CNAME, notes'],
    ['title:"sign in"', 'quoted phrase'], ['host:dev', 'host contains'], ['code:200  code:4xx  code:301,302', 'status codes / classes'],
    ['tech:wordpress', 'technology (wappalyzer)'], ['server:nginx', 'web server header'], ['ip:10.0.', 'IP contains'],
    ['cname:cloudfront', 'CNAME contains'], ['cdn:cloudflare', 'CDN/WAF'], ['tag:prod', 'has tag'], ['status:offline', 'active / offline'],
    ['source:bruteforce', 'discovered by (subfinder:crtsh, bruteforce, tls-san, import, input)'], ['port:8443', 'port of an alive URL'],
    ['tls:example', 'TLS certificate CN'], ['-tag:ignore', 'prefix any term with - to negate'],
  ];
  openModal('Search syntax', h('table', { class: 'data' }, h('tbody', null, rows.map(([q, d]) => h('tr', null, h('td', { class: 'mono nowrap' }, q), h('td', null, d))))),
    h('button', { class: 'btn primary', onclick: () => $('#modal').close() }, 'Got it'));
}

// ------------------------------------------------------------------ Host detail
routes.host = async ([id]) => {
  const [s, hist, tags] = await Promise.all([api(`/api/subdomains/${id}`), api(`/api/subdomains/${id}/history`), api('/api/tags')]);
  const tagBox = h('div', { class: 'chips' });
  const paintTags = (list) => {
    clear(tagBox).append(...(list.length ? list.map((t) => tagChip(t, async () => {
      try { paintTags((await api(`/api/subdomains/${id}/tags/${t.id}`, { method: 'DELETE' })).tags); } catch (e) { toast(e.message, true); }
    })) : [h('span', { class: 'muted small' }, 'No tags yet')]));
  };
  paintTags(s.tags);
  const tagInput = h('input', { type: 'text', placeholder: 'add tag…', list: 'all-tags', 'aria-label': 'Add tag' });
  const addTag = async () => {
    const name = tagInput.value.trim(); if (!name) return;
    try { paintTags((await api(`/api/subdomains/${id}/tags`, { method: 'POST', body: { name } })).tags); tagInput.value = ''; }
    catch (e) { toast(e.message, true); }
  };
  tagInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') addTag(); });
  const quickTags = ['interesting', 'in-scope', 'out-of-scope', 'ignore', 'reported'].filter((n) => !s.tags.some((t) => t.name === n));

  const notes = h('textarea', { rows: 6, placeholder: 'Notes (markdown/plain text)…' });
  notes.value = s.notes || '';
  const saveNotes = async () => { try { await api(`/api/subdomains/${id}`, { method: 'PATCH', body: { notes: notes.value } }); toast('Notes saved'); } catch (e) { toast(e.message, true); } };

  const lr = s.last_result || {};
  const tls = lr.tls || {};
  const kv = (label, value) => [h('dt', null, label), h('dd', null, value === null || value === undefined || value === '' || (Array.isArray(value) && !value.length) ? h('span', { class: 'muted' }, '–') : value)];
  const overview = h('dl', { class: 'kv' },
    kv('URLs', (s.urls || []).length ? h('div', { class: 'stack' }, s.urls.map((u) => h('span', { class: 'mono' }, extLink(u)))) : null),
    kv('Status code', codeEl(s.status_code)),
    kv('Title', s.title),
    kv('Web server', s.webserver),
    kv('Technologies', chipList(s.tech, 50)),
    kv('Redirect', s.location ? h('span', { class: 'mono' }, s.location) : null),
    kv('IPs', (s.ips || []).length ? h('span', { class: 'mono' }, s.ips.join(', ')) : null),
    kv('CNAME', (s.cname || []).length ? h('span', { class: 'mono' }, s.cname.join(', ')) : null),
    kv('CDN / WAF', s.cdn_name),
    kv('Content', s.content_type ? `${s.content_type} · ${num(s.content_length)} bytes` : null),
    kv('TLS', s.tls_subject_cn ? `${s.tls_subject_cn} · issuer ${s.tls_issuer || '?'} · expires ${fmtDate(s.tls_not_after)}` : null),
    kv('TLS SANs', (tls.subject_an || []).length ? chipList(tls.subject_an, 12) : null),
    kv('Favicon mmh3', s.favicon ? h('span', { class: 'mono' }, s.favicon) : null),
    kv('Body sha256', s.body_hash ? h('span', { class: 'mono', title: s.body_hash }, s.body_hash.slice(0, 16) + '…') : null),
    kv('DNS (last)', s.dns ? (s.dns.resolves ? h('span', { class: 'mono' }, [...s.dns.a, ...s.dns.aaaa].join(', ') || 'resolves') : h('span', { class: 'badge offline' }, 'NXDOMAIN / no address')) : null),
    kv('Discovered by', chipList(s.sources, 20)),
    kv('First seen', `${fmtDate(s.first_seen)} UTC (scan #${s.first_scan_id})`),
    kv('Last seen alive', `${fmtDate(s.last_seen)} UTC`),
    kv('Last checked', `${fmtDate(s.last_checked)} UTC`),
    kv('Seen in', `${num(s.seen_count)} scan(s)`));

  const timeline = h('ul', { class: 'timeline' }, hist.events.length ? hist.events.map((e) => h('li', null,
    h('span', { class: 'muted small nowrap', title: fmtDate(e.created_at) }, fmtDate(e.created_at)),
    h('span', null, statusBadge(e.type)),
    eventDetails(e))) : h('li', null, h('span', { class: 'muted' }, 'No events')));

  // one row per probe result, plus a row for every scan of this root in which the host did not answer
  const answered = new Set(hist.results.map((r) => r.scan_id));
  const rows = [...hist.results, ...hist.scans.filter((sc) => !answered.has(sc.scan_id)).map((sc) => ({ missed: true, scan_id: sc.scan_id, observed_at: sc.started_at }))]
    .sort((a, b) => b.scan_id - a.scan_id || (a.missed ? 1 : 0) - (b.missed ? 1 : 0));
  const histBody = h('tbody', null, rows.length ? rows.map((r) => r.missed ? h('tr', null,
    h('td', null, h('a', { href: `#/scans/${r.scan_id}` }, `#${r.scan_id}`)), h('td', { class: 'when' }, fmtDate(r.observed_at)),
    h('td', null), h('td', { colspan: 7, class: 'muted' }, 'no response in this scan')) : h('tr', null,
    h('td', null, h('a', { href: `#/scans/${r.scan_id}` }, `#${r.scan_id}`)), h('td', { class: 'when' }, fmtDate(r.observed_at)),
    h('td', null, r.phase === 'main' ? '' : h('span', { class: 'badge neutral' }, r.phase)),
    h('td', { class: 'mono' }, r.url), h('td', null, codeEl(r.status_code)), h('td', { class: 'title' }, h('div', { title: r.title || '' }, r.title || '')),
    h('td', null, r.webserver || ''), h('td', { class: 'right' }, num(r.content_length)),
    h('td', { class: 'mono', title: r.body_hash || '' }, (r.body_hash || '').slice(0, 10)),
    h('td', null, h('button', { class: 'btn sm', onclick: async () => jsonModal(`httpx JSON · ${r.url} · scan #${r.scan_id}`, await api(`/api/results/${r.id}`)) }, 'JSON')))) : emptyRow(10, 'No probes recorded'));

  const dnsBody = h('tbody', null, hist.dns.map((d) => h('tr', null,
    h('td', null, `#${d.scan_id}`), h('td', { class: 'when' }, fmtDate(d.observed_at)),
    h('td', null, d.resolves ? statusBadge('active') : h('span', { class: 'badge offline' }, 'no answer')),
    h('td', { class: 'mono' }, [...d.a, ...d.aaaa].join(', ')), h('td', { class: 'mono' }, d.cname.join(', ')))));

  return h('div', null,
    h('div', { class: 'detail-head' },
      h('a', { class: 'btn ghost sm', href: '#/assets', onclick: (e) => { if (history.length > 1) { e.preventDefault(); history.back(); } } }, '← Back'),
      h('h1', null, s.host), statusBadge(s.status, s.offline_reason ? `reason: ${s.offline_reason}` : null), codeEl(s.status_code),
      h('span', { class: 'muted' }, s.root),
      h('span', { class: 'grow' }),
      h('button', { class: 'btn', onclick: () => navigator.clipboard.writeText(s.host).then(() => toast('Copied')) }, 'Copy host'),
      s.url && safeUrl(s.url) ? h('a', { class: 'btn primary', href: safeUrl(s.url), target: '_blank', rel: 'noopener noreferrer' }, 'Open ↗') : null),
    s.status === 'offline' ? h('div', { class: 'callout' }, `Offline since ${fmtDate(s.status_changed_at)} UTC – ${s.offline_reason === 'dns' ? 'DNS no longer resolves' : 'DNS resolves but no HTTP(S) answer'}. Data below is from the last time it was alive (${fmtDate(s.last_seen)}).`) : null,
    s.status === 'offline' ? h('div', { class: 'spacer' }) : null,
    h('div', { class: 'grid-2' },
      h('div', { class: 'card card-pad' }, h('h3', null, 'Overview'), overview),
      h('div', { class: 'stack' },
        h('div', { class: 'card card-pad' }, h('h3', null, 'Tags'), tagBox,
          h('div', { class: 'tag-input' }, tagInput, h('button', { class: 'btn', onclick: addTag }, 'Add')),
          h('datalist', { id: 'all-tags' }, tags.map((t) => h('option', { value: t.name }))),
          quickTags.length ? h('div', { class: 'chips' }, h('span', { class: 'muted small' }, 'quick:'), quickTags.map((n) =>
            h('button', { class: 'btn sm ghost', onclick: () => { tagInput.value = n; addTag(); } }, '+ ' + n))) : null),
        h('div', { class: 'card card-pad' }, h('h3', null, 'Notes'), notes, h('div', { class: 'row' }, h('span', { class: 'grow' }), h('button', { class: 'btn primary sm', onclick: saveNotes }, 'Save notes'))),
        h('div', { class: 'card card-pad' }, h('h3', null, 'Timeline'), timeline))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'card' }, h('div', { class: 'card-pad' }, h('h3', null, `Probe history (${hist.results.length} responses)`)),
      h('div', { class: 'table-wrap' }, h('table', { class: 'data' }, h('thead', null, h('tr', null, ['Scan', 'When', '', 'URL', 'Code', 'Title', 'Server', 'Bytes', 'Body hash', ''].map((t) => h('th', null, t)))), histBody))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'card card-pad' }, h('details', null, h('summary', null, `DNS history (${hist.dns.length})`), h('div', { class: 'spacer' }),
      h('div', { class: 'table-wrap' }, h('table', { class: 'data' }, h('thead', null, h('tr', null, ['Scan', 'When', 'Resolves', 'A / AAAA', 'CNAME'].map((t) => h('th', null, t)))), dnsBody)))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'card card-pad' }, h('details', null, h('summary', null, 'Latest raw httpx JSON'), h('div', { class: 'spacer' }), h('pre', { class: 'json' }, JSON.stringify(s.last_result, null, 2)))));
};

function fmtVal(v) {
  if (v === null || v === undefined || v === '') return '∅';
  if (Array.isArray(v)) return v.length ? v.join(', ') : '∅';
  return String(v);
}
function eventDetails(e) {
  const d = e.details || {};
  const changes = d.changes || {};
  const parts = [];
  if (e.type === 'new') parts.push(h('span', null, [d.status_code ? `${d.status_code} ` : '', d.title ? `“${d.title}”` : '', d.sources && d.sources.length ? h('span', { class: 'muted' }, ` via ${d.sources.join(', ')}`) : '']));
  if (e.type === 'offline') parts.push(h('span', null, d.reason === 'dns' ? 'DNS no longer resolves' : 'no HTTP(S) response', h('span', { class: 'muted' }, ` · last seen ${fmtDate(d.last_seen)}`)));
  if (e.type === 'back_online') parts.push(h('span', null, `back after ${duration(d.offline_since, e.created_at)} offline`));
  for (const [field, { old, new: nw }] of Object.entries(changes)) {
    parts.push(h('div', { class: 'change' }, h('span', { class: 'field' }, field + ': '), h('del', null, fmtVal(old)), ' → ', h('ins', null, fmtVal(nw))));
  }
  return h('div', null, parts);
}

// ------------------------------------------------------------------ Changes view
routes.changes = async (_parts, params) => {
  const state = { type: params.type || '', root: params.root || '', days: params.days || '30', q: params.q || '', page: params.page || '1' };
  const facets = await api('/api/facets');
  const list = h('tbody');
  const info = h('span', { class: 'muted small' });
  const update = (c, resetPage = true) => { Object.assign(state, c); if (resetPage) state.page = '1'; setHashQuiet('changes', state); load(); };
  const types = [['', 'All event types'], ['new', 'New'], ['changed', 'Changed'], ['offline', 'Went offline'], ['back_online', 'Back online']];
  const q = h('input', { type: 'search', placeholder: 'host contains…', value: state.q, 'aria-label': 'Host filter' });
  q.addEventListener('input', debounce(() => update({ q: q.value.trim() }), 300));
  let total = 0;
  async function load() {
    const r = await api('/api/events' + qs({ ...state, per_page: 100 }));
    total = r.total;
    info.textContent = `${num(r.total)} events · page ${r.page}`;
    clear(list).append(...(r.items.length ? r.items.map((e) => h('tr', null,
      h('td', { class: 'when' }, when(e.created_at)), h('td', null, statusBadge(e.type)),
      h('td', { class: 'host' }, h('a', { href: `#/host/${e.subdomain_id}` }, e.host)), h('td', null, eventDetails(e)),
      h('td', null, h('a', { href: `#/scans/${e.scan_id}`, class: 'muted' }, `#${e.scan_id}`)))) : [emptyRow(5, 'No events in this range')]));
  }
  await load();
  return h('div', null,
    h('div', { class: 'page-head' }, h('h1', null, 'Changes'), h('span', { class: 'muted' }, 'Everything that appeared, changed, disappeared or came back.')),
    h('div', { class: 'card toolbar' }, h('div', { class: 'row' }, q,
      select(types, state.type, (v) => update({ type: v })),
      select([['', 'All domains'], ...facets.roots.map((r) => [r, r])], state.root, (v) => update({ root: v })),
      select([['1', 'Last 24h'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days'], ['365', 'Last year'], ['', 'All time']], state.days, (v) => update({ days: v })))),
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['When', 'Event', 'Host', 'Details', 'Scan'].map((t) => h('th', null, t)))), list)),
    h('div', { class: 'pager' }, info,
      h('button', { class: 'btn sm', onclick: () => { if (+state.page > 1) update({ page: String(+state.page - 1) }, false); } }, '‹ Prev'),
      h('button', { class: 'btn sm', onclick: () => { if (+state.page * 100 < total) update({ page: String(+state.page + 1) }, false); } }, 'Next ›'))));
};

// ------------------------------------------------------------------ Scans view
routes.scans = async ([scanId]) => {
  if (scanId) return scanDetail(scanId);
  const [scans, requests, overview] = await Promise.all([api('/api/scans'), api('/api/scan-requests'), api('/api/overview')]);
  const statLine = (t) => `alive ${num(t.alive)} · new ${num(t.new)} · offline ${num(t.went_offline)} · back ${num(t.back_online)} · changed ${num(t.changed)}`;
  const queue = requests.filter((r) => ['queued', 'running'].includes(r.status) || Date.now() - parseTs(r.requested_at) < 86400e3 * 7);
  return h('div', null,
    h('div', { class: 'page-head' }, h('h1', null, 'Scans'), h('span', { class: 'grow' }), h('button', { class: 'btn primary', onclick: newScanDialog }, 'New scan')),
    !overview.worker.online && requests.some((r) => r.status === 'queued') ? h('div', { class: 'callout' }, 'Scans are queued but no worker is running. Start one with ', h('code', null, 'docker compose --profile worker up -d worker'), ' or run them from the CLI.') : null,
    queue.length ? h('div', { class: 'card' }, h('div', { class: 'card-pad' }, h('h3', null, 'Queue (dashboard requests)')),
      h('div', { class: 'table-wrap' }, h('table', { class: 'data' }, h('thead', null, h('tr', null, ['#', 'Requested', 'Domains', 'Options', 'Status', 'Scan', ''].map((t) => h('th', null, t)))),
        h('tbody', null, queue.map((r) => h('tr', null, h('td', null, r.id), h('td', { class: 'when' }, when(r.requested_at)),
          h('td', { class: 'mono' }, r.domains), h('td', { class: 'muted small' }, Object.entries(r.params).map(([k, v]) => `${k}=${v}`).join(' ') || 'defaults'),
          h('td', null, statusBadge(r.status, r.error || null)), h('td', null, r.scan_id ? h('a', { href: `#/scans/${r.scan_id}` }, `#${r.scan_id}`) : '–'),
          h('td', null, r.status === 'queued' ? h('button', { class: 'btn sm danger', onclick: async () => { try { await api(`/api/scan-requests/${r.id}`, { method: 'DELETE' }); render(); } catch (e) { toast(e.message, true); } } }, 'Cancel') : null)))))))
      : null,
    queue.length ? h('div', { class: 'spacer' }) : null,
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['#', 'Started', 'Duration', 'Status', 'Trigger', 'Domains', 'Result'].map((t) => h('th', null, t)))),
      h('tbody', null, scans.items.length ? scans.items.map((s) => h('tr', null,
        h('td', null, h('a', { href: `#/scans/${s.id}` }, `#${s.id}`)), h('td', { class: 'when' }, fmtDate(s.started_at)),
        h('td', { class: 'when' }, s.finished_at ? duration(s.started_at, s.finished_at) : 'running…'),
        h('td', null, statusBadge(s.status, s.error || null)), h('td', { class: 'muted small' }, s.trigger),
        h('td', { class: 'mono small' }, s.roots.map((r) => r.domain).slice(0, 4).join(', ') + (s.roots.length > 4 ? ` +${s.roots.length - 4}` : '')),
        h('td', { class: 'small' }, statLine(s.totals), s.roots.some((r) => r.warnings.length) ? h('span', { class: 'badge partial' }, 'warnings') : null))) : emptyRow(7, 'No scans yet'))))));
};

async function scanDetail(id) {
  const s = await api(`/api/scans/${id}`);
  return h('div', null,
    h('div', { class: 'detail-head' }, h('a', { class: 'btn ghost sm', href: '#/scans' }, '← Scans'), h('h1', null, `Scan #${s.id}`), statusBadge(s.status),
      h('span', { class: 'muted' }, `${fmtDate(s.started_at)} UTC · ${s.finished_at ? duration(s.started_at, s.finished_at) : 'running'} · ${s.trigger}`),
      h('span', { class: 'grow' }), h('a', { class: 'btn', href: '#/changes?days=' }, 'All changes')),
    s.error ? h('div', { class: 'callout' }, s.error) : null,
    h('div', { class: 'stack' }, s.roots.map((r) => h('div', { class: 'card card-pad' },
      h('div', { class: 'row' }, h('h2', { class: 'mono' }, r.domain), statusBadge(r.status), r.stats.wildcard ? h('span', { class: 'badge neutral' }, 'wildcard DNS') : null,
        h('span', { class: 'grow' }), h('a', { class: 'btn sm', href: '#/assets?' + new URLSearchParams({ root: r.domain }) }, 'Assets')),
      h('dl', { class: 'kv' },
        h('dt', null, 'Discovery'), h('dd', null, `subfinder ${num(r.stats.passive)} · brute force ${num(r.stats.brute)} (${num(r.stats.wordlist_size)} words${r.stats.brute_wildcard_filtered ? `, ${num(r.stats.brute_wildcard_filtered)} wildcard answers dropped` : ''}) · TLS SANs ${num(r.stats.tls_san)}${r.stats.imported ? ` · imported ${num(r.stats.imported)}` : ''}`),
        h('dt', null, 'Validation'), h('dd', null, `${num(r.stats.candidates)} candidates → ${num(r.stats.resolved)} resolve → ${num(r.stats.probed)} probed → ${num(r.stats.alive)} alive`),
        h('dt', null, 'Changes'), h('dd', null, `new ${num(r.stats.new)} · changed ${num(r.stats.changed)} · went offline ${num(r.stats.went_offline)} · back online ${num(r.stats.back_online)} · still offline ${num(r.stats.still_offline)} · unchanged ${num(r.stats.unchanged)}`),
        h('dt', null, 'Duration'), h('dd', null, r.stats.duration_s ? `${r.stats.duration_s}s` : '–'),
        r.error ? [h('dt', null, 'Error'), h('dd', null, r.error)] : null),
      r.warnings.length ? h('ul', { class: 'warnings' }, r.warnings.map((w) => h('li', null, w))) : null,
      h('div', { class: 'spacer' }), h('a', { href: '#/changes?' + new URLSearchParams({ root: r.domain, days: '' }), class: 'small' }, 'Events for this domain →')))),
    h('div', { class: 'spacer' }),
    h('div', { class: 'card card-pad' }, h('details', null, h('summary', null, 'Parameters & tool versions'), h('div', { class: 'spacer' }),
      h('pre', { class: 'json' }, JSON.stringify({ tool_versions: s.tool_versions, params: s.params, output_dir: s.output_dir }, null, 2)))));
}

// ------------------------------------------------------------------ Domains view
routes.domains = async () => {
  const roots = await api('/api/roots');
  return h('div', null,
    h('div', { class: 'page-head' }, h('h1', null, 'Domains'), h('span', { class: 'muted' }, `${roots.length} root domains tracked`), h('span', { class: 'grow' }),
      h('button', { class: 'btn', onclick: () => queueScan('all') }, 'Re-scan all'), h('button', { class: 'btn primary', onclick: newScanDialog }, 'Add domain')),
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['Domain', 'Assets', 'Active', 'Offline', 'Last scan', 'Added', ''].map((t) => h('th', null, t)))),
      h('tbody', null, roots.length ? roots.map((r) => h('tr', null,
        h('td', { class: 'host' }, h('a', { href: '#/assets?' + new URLSearchParams({ root: r.domain }) }, r.domain), r.wildcard ? h('span', { class: 'badge neutral', title: 'wildcard DNS detected' }, ' *') : null),
        h('td', null, num(r.total)), h('td', null, h('a', { href: '#/assets?' + new URLSearchParams({ root: r.domain, status: 'active' }) }, num(r.active))),
        h('td', null, h('a', { href: '#/assets?' + new URLSearchParams({ root: r.domain, status: 'offline' }) }, num(r.offline))),
        h('td', { class: 'when' }, r.last_scan_id ? [when(r.last_scan_at), ' ', h('a', { href: `#/scans/${r.last_scan_id}` }, `#${r.last_scan_id}`)] : '–'),
        h('td', { class: 'when' }, fmtDate(r.created_at).slice(0, 10)),
        h('td', { class: 'right' }, h('button', { class: 'btn sm', onclick: () => queueScan(r.domain) }, 'Re-scan')))) : emptyRow(7, 'No domains yet – add one or run  make scan domain=example.com'))))));
};

// ------------------------------------------------------------------ Tags view
routes.tags = async () => {
  const tags = await api('/api/tags');
  const name = h('input', { type: 'text', placeholder: 'new tag name', 'aria-label': 'New tag name' });
  const color = h('input', { type: 'color', value: '#2563eb', 'aria-label': 'Tag color' });
  const create = async () => {
    if (!name.value.trim()) return name.focus();
    try { await api('/api/tags', { method: 'POST', body: { name: name.value.trim(), color: color.value } }); render(); } catch (e) { toast(e.message, true); }
  };
  name.addEventListener('keydown', (e) => { if (e.key === 'Enter') create(); });
  return h('div', null,
    h('div', { class: 'page-head' }, h('h1', null, 'Tags'), h('span', { class: 'muted' }, 'Status (active/offline) is tracked automatically – tags are yours.')),
    h('div', { class: 'card toolbar' }, h('div', { class: 'row' }, name, color, h('button', { class: 'btn primary', onclick: create }, 'Create tag'))),
    h('div', { class: 'card' }, h('div', { class: 'table-wrap' }, h('table', { class: 'data' },
      h('thead', null, h('tr', null, ['Tag', 'Color', 'Assets', 'Created', ''].map((t) => h('th', null, t)))),
      h('tbody', null, tags.length ? tags.map((t) => {
        const input = h('input', { type: 'text', value: t.name, 'aria-label': 'Tag name' });
        const col = h('input', { type: 'color', value: t.color, 'aria-label': 'Tag color' });
        const save = async () => { try { await api(`/api/tags/${t.id}`, { method: 'PATCH', body: { name: input.value.trim(), color: col.value } }); toast('Saved'); } catch (e) { toast(e.message, true); } };
        input.addEventListener('change', save); col.addEventListener('change', save);
        return h('tr', null, h('td', null, input), h('td', null, col),
          h('td', null, h('a', { href: '#/assets?' + new URLSearchParams({ tag: t.name }) }, num(t.count))), h('td', { class: 'when' }, fmtDate(t.created_at).slice(0, 10)),
          h('td', { class: 'right' }, h('button', { class: 'btn sm danger', onclick: async () => {
            if (!confirm(`Delete tag "${t.name}"? It will be removed from ${t.count} assets (the assets stay).`)) return;
            try { await api(`/api/tags/${t.id}`, { method: 'DELETE' }); render(); } catch (e) { toast(e.message, true); }
          } }, 'Delete')));
      }) : emptyRow(5, 'No tags yet. Tag assets from the asset list (select rows) or the detail page.'))))));
};

// ------------------------------------------------------------------ New scan dialog
async function queueScan(domains, params = {}) {
  try {
    const r = await api('/api/scan-requests', { method: 'POST', body: { domains, params } });
    const ov = await api('/api/overview');
    toast(ov.worker.online ? `Queued scan request #${r.id}` : `Queued #${r.id} – start the worker to run it`, !ov.worker.online);
    if (parseHash().parts[0] === 'scans') render();
  } catch (e) { toast(e.message, true); }
}
async function newScanDialog() {
  const ov = await api('/api/overview').catch(() => ({ worker: { online: false } }));
  const domains = h('textarea', { rows: 4, placeholder: 'example.com\nexample.org' });
  const opt = (key, label, checked, hint) => { const box = h('input', { type: 'checkbox', checked, dataset: { key } }); return [h('label', { class: 'check' }, box, label), h('div', { class: 'hint' }, hint)]; };
  const options = h('div', { class: 'form-grid' },
    opt('passive', 'Passive sources (subfinder)', true, 'all subfinder sources; API keys in config/'),
    opt('brute', 'DNS brute force (dnsx)', true, 'built-in common-subdomain wordlist, wildcard-safe'),
    opt('san', 'Follow TLS certificate names', true, 'probe in-scope SANs found in certificates'),
    opt('force', 'Force offline marking', false, 'bypass the mass-offline safety guard'));
  const ports = h('input', { type: 'text', placeholder: 'ports (optional), e.g. 80,443,8080,8443' });
  const submit = async () => {
    const params = {};
    options.querySelectorAll('input[type=checkbox]').forEach((b) => { params[b.dataset.key] = b.checked; });
    if (ports.value.trim()) params.ports = ports.value.trim();
    const list = domains.value.trim(); if (!list) return domains.focus();
    await queueScan(list.split(/[\s,]+/).filter(Boolean).join(','), params);
    $('#modal').close();
  };
  openModal('New scan', h('div', { class: 'stack' },
    !ov.worker.online ? h('div', { class: 'callout' }, 'No scan worker is running, so queued scans will wait. Start it with ', h('code', null, 'docker compose --profile worker up -d worker'), ' – or skip the queue and run ', h('code', null, 'make scan domain=example.com'), '.') : null,
    h('div', null, h('h3', null, 'Root domains'), domains, h('div', { class: 'hint' }, 'One per line (or comma separated). Everything below each domain is in scope.')),
    options, ports),
    [h('button', { class: 'btn', onclick: () => $('#modal').close() }, 'Cancel'), h('button', { class: 'btn primary', onclick: submit }, 'Queue scan')]);
  domains.focus();
}

// ------------------------------------------------------------------ chrome
async function refreshWorker() {
  try {
    const ov = await api('/api/overview');
    const pill = $('#worker-pill');
    const queued = (ov.queue.queued || 0) + (ov.queue.running || 0);
    clear(pill).append(h('span', { class: 'dot' }), ov.running_scans ? `scanning… ${queued ? `(${queued} queued)` : ''}` : ov.worker.online ? `worker online${queued ? ` · ${queued} queued` : ''}` : 'worker offline');
    pill.className = 'pill' + (ov.worker.online || ov.running_scans ? ' on' : '');
    pill.title = ov.worker.online ? `last heartbeat ${fmtDate(ov.worker.heartbeat)} UTC` : 'Start with: docker compose --profile worker up -d worker (only needed for scans queued from the dashboard)';
  } catch { /* ignore */ }
}
function initTheme() {
  const saved = (() => { try { return localStorage.getItem('subtrack-theme'); } catch { return null; } })();
  if (saved) document.documentElement.dataset.theme = saved;
  $('#theme-toggle').addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme ? document.documentElement.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('subtrack-theme', document.documentElement.dataset.theme); } catch { /* ignore */ }
  });
}

initTheme();
$('#new-scan').addEventListener('click', newScanDialog);
refreshWorker();
setInterval(refreshWorker, 20000);
render();
