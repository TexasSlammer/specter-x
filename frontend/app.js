/*
 * SPECTER X — investigation dashboard frontend.
 *
 * Vanilla ES2020, no frameworks, no build step. The ONLY dependency is the
 * vendored vis-network bundle (frontend/vendor/vis-network.min.js), which
 * exposes the global `vis` (vis.Network). Everything else is fetch() against
 * the API contract in CONTRACTS.md §5.
 *
 * SECURITY NOTE — XSS-safe rendering is a feature of this tool:
 * Every value that originates from API data is passed through esc() before
 * being interpolated into an HTML template. No innerHTML assignment anywhere
 * in this file ever receives raw, unescaped API data. If you add a view,
 * keep that invariant.
 *
 * All data-driven strings (labels, names, reasons, ids, kinds) come from the
 * API; hardcoded strings here are UI chrome only (titles, buttons, states).
 */
'use strict';

/* ==================================================================
 * Constants & state
 * ================================================================== */

const TOKEN_KEY = 'specter.token';

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV_COLOR = { critical: 'var(--red)', high: 'var(--high)', medium: 'var(--amber)', low: 'var(--green)' };

/* Risk §4 component caps, used when the API omits a per-component max. */
const COMPONENT_MAX = {
  signal_component: 55, signal: 55,
  access_component: 30, access: 30,
  blast_component: 15, blast: 15, blast_radius: 15
};

const SEV_CHIPS = [
  ['', 'All'],
  ['critical', 'Critical'],
  ['high', 'High'],
  ['medium', 'Medium'],
  ['low', 'Low']
];

const RESPOND_META = {
  consent_revoke: {
    label: 'Revoke consent',
    desc: 'Revokes OAuth consent grants (APP_CONSENT) issued by this identity. The third-party app loses its delegated scopes.',
    confirm: 'Revoke consent'
  },
  account_disable: {
    label: 'Disable account',
    desc: 'Disables the account. Interactive sign-in is blocked immediately.',
    confirm: 'Disable account'
  },
  session_revoke: {
    label: 'Revoke sessions',
    desc: 'Invalidates all active sign-in sessions for this identity. The user must re-authenticate everywhere.',
    confirm: 'Revoke sessions'
  }
};

const state = {
  token: lsGet(TOKEN_KEY) || '',
  validated: false,
  alertsSeverity: '',          // '' = all severities
  identityQuery: '',
  identitiesCache: [],         // for id -> display_name mapping
  network: null                // active vis.Network instance (destroyed on nav)
};

let renderSeq = 0;             // guards against stale async renders

/* ==================================================================
 * Tiny helpers
 * ================================================================== */

function $(sel, root) { return (root || document).querySelector(sel); }
function VIEW() { return document.getElementById('view'); }

function lsGet(key) { try { return window.localStorage.getItem(key); } catch (e) { return null; } }
function lsSet(key, val) { try { window.localStorage.setItem(key, val); } catch (e) { /* private mode */ } }
function lsDel(key) { try { window.localStorage.removeItem(key); } catch (e) { /* ignore */ } }

/*
 * esc() — HTML-escape any value before it touches innerHTML.
 * This is the XSS-safety invariant of the whole dashboard (see header note).
 */
function esc(value) {
  return String(value === null || value === undefined ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function num(x) {
  const n = Number(x);
  return Number.isFinite(n) ? n : null;
}

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

/* UTC timestamps, SOC-style: 2026-11-05 09:14:00Z */
function fmtTime(ts) {
  if (ts === null || ts === undefined || ts === '') return '—';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return String(ts);
  return d.toISOString().replace('T', ' ');
}

function sevRank(sev) {
  const s = String(sev || '').toLowerCase();
  return Object.prototype.hasOwnProperty.call(SEV_ORDER, s) ? SEV_ORDER[s] : 9;
}

function scoreColor(score) {
  if (score === null) return 'var(--dim)';
  if (score >= 80) return 'var(--red)';
  if (score >= 60) return 'var(--orange)';
  if (score >= 40) return 'var(--amber)';
  return 'var(--green)';
}

/* ==================================================================
 * API wrapper — Bearer auth, 401 => back to login
 * ================================================================== */

async function api(path, opts) {
  const options = opts || {};
  const headers = {};
  if (state.token) headers['Authorization'] = 'Bearer ' + state.token;
  if (options.body !== undefined && options.body !== null) headers['Content-Type'] = 'application/json';

  let res;
  try {
    res = await fetch(path, {
      method: options.method || 'GET',
      headers: headers,
      body: options.body !== undefined && options.body !== null ? JSON.stringify(options.body) : undefined
    });
  } catch (e) {
    throw { status: 0, message: 'network error — cannot reach the API' };
  }

  if (res.status === 401) {
    logout('Token rejected (401). Authenticate again.');
    throw { status: 401, message: '401 unauthorized' };
  }

  let data = null;
  try {
    const text = await res.text();
    data = text ? JSON.parse(text) : null;
  } catch (e) {
    data = null;
  }

  if (!res.ok) {
    const detail = data && (data.detail || data.error || data.message);
    throw { status: res.status, message: detail ? String(detail) : ('HTTP ' + res.status), data: data };
  }
  return data;
}

/* ==================================================================
 * Auth / login overlay / token status
 * ================================================================== */

function showLogin(message) {
  const overlay = document.getElementById('login-overlay');
  overlay.classList.remove('hidden');
  const errEl = document.getElementById('login-error');
  if (message) {
    errEl.textContent = message;
    errEl.classList.remove('hidden');
  } else {
    errEl.classList.add('hidden');
  }
  const input = document.getElementById('token-input');
  if (input && !input.value) input.focus();
}

function showLoginError(message) {
  const errEl = document.getElementById('login-error');
  errEl.textContent = message;
  errEl.classList.remove('hidden');
}

function hideLogin() {
  document.getElementById('login-overlay').classList.add('hidden');
  document.getElementById('login-error').classList.add('hidden');
}

function logout(message) {
  state.token = '';
  state.validated = false;
  lsDel(TOKEN_KEY);
  destroyNetwork();
  renderTokenStatus();
  VIEW().innerHTML = '';
  showLogin(message || 'Authentication required.');
}

/* Validate a token against the cheapest authenticated endpoint. */
async function validateToken(token) {
  state.token = token;
  try {
    await api('/api/identities?limit=1');
    state.validated = true;
    lsSet(TOKEN_KEY, token);
    renderTokenStatus();
    return true;
  } catch (err) {
    state.token = '';
    lsDel(TOKEN_KEY);
    renderTokenStatus();
    if (err && err.status === 401) {
      showLoginError('Token rejected (401 — unknown token). Enter a valid token.');
    } else if (err && err.status === 0) {
      showLoginError('Cannot reach the API (' + (err.message || 'network error') + '). Is the backend up?');
    } else {
      showLoginError('Validation failed: ' + ((err && err.message) || 'unknown error'));
    }
    return false;
  }
}

async function onLoginSubmit(e) {
  e.preventDefault();
  const input = document.getElementById('token-input');
  const btn = document.getElementById('login-submit');
  const token = (input.value || '').trim();
  if (!token) {
    showLoginError('Enter a bearer token.');
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Validating…';
  const ok = await validateToken(token);
  btn.disabled = false;
  btn.textContent = 'Authenticate';
  if (ok) {
    input.value = '';
    hideLogin();
    toast('Authenticated.', 'success');
    route();
  } else {
    input.value = '';
    input.focus();
  }
}

function renderTokenStatus() {
  const el = document.getElementById('token-status');
  if (!el) return;
  if (!state.token) {
    el.innerHTML = '<span class="status-dot off"></span><span class="dim">not authenticated</span>';
    return;
  }
  const t = state.token;
  const masked = t.length <= 8 ? '••••' : t.slice(0, 3) + '…' + t.slice(-4);
  el.innerHTML =
    '<span class="status-dot on" title="token active"></span>' +
    '<span class="mono dim" title="bearer token (masked)">' + esc(masked) + '</span>' +
    '<button type="button" class="btn btn-ghost btn-sm" id="logout-btn">Sign out</button>';
  const btn = document.getElementById('logout-btn');
  if (btn) btn.addEventListener('click', function () { logout('Signed out.'); });
}

/* ==================================================================
 * Generic state blocks (loading / error / empty)
 * ================================================================== */

function loadingHTML(label, inset) {
  return '<div class="state' + (inset ? ' state-inset' : '') + '">' +
    '<div class="spinner" aria-hidden="true"></div>' +
    '<div class="state-text">' + esc(label || 'Loading…') + '</div>' +
    '</div>';
}

function errorHTML(err, label) {
  const status = err && err.status ? err.status : 0;
  const msg = (err && err.message) ? err.message : 'unknown error';
  return '<div class="state state-error">' +
    '<div class="state-icon" aria-hidden="true">⚠</div>' +
    '<div class="state-text">' + esc(label || 'Failed to load') + '</div>' +
    '<div class="state-sub">' + esc('HTTP ' + status + ' — ' + msg) + '</div>' +
    '<button type="button" class="btn" data-retry>Retry</button>' +
    '</div>';
}

function emptyHTML(title, sub) {
  return '<div class="state">' +
    '<div class="state-icon" aria-hidden="true">∅</div>' +
    '<div class="state-text">' + esc(title || 'Nothing here') + '</div>' +
    (sub ? '<div class="state-sub">' + esc(sub) + '</div>' : '') +
    '</div>';
}

/* ==================================================================
 * Shared render fragments
 * ================================================================== */

function sevBadge(sev) {
  const s = String(sev || '').toLowerCase();
  if (Object.prototype.hasOwnProperty.call(SEV_COLOR, s)) {
    return '<span class="badge sev-' + s + '">' + s + '</span>';
  }
  return '<span class="badge">' + esc(sev || 'n/a') + '</span>';
}

function kindBadge(kind) {
  const k = String(kind || '').toLowerCase();
  if (k === 'user') return '<span class="badge kind-badge kind-user">user</span>';
  if (k === 'service_account') return '<span class="badge kind-badge kind-service_account">service_account</span>';
  return '<span class="badge kind-badge">' + esc(kind || 'unknown') + '</span>';
}

function statusBadge(status) {
  const s = String(status || '').toLowerCase();
  if (s === 'open' || s === 'contained' || s === 'closed') {
    return '<span class="badge status-' + s + '">' + s + '</span>';
  }
  return '<span class="badge">' + esc(status || 'unknown') + '</span>';
}

function bandBadge(band, score) {
  const b = String(band || '').toLowerCase();
  if (Object.prototype.hasOwnProperty.call(SEV_COLOR, b)) return sevBadge(b);
  /* derive a display band from the score when the API omits severity_band */
  const derived = score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low';
  return sevBadge(derived);
}

function privBadge(privileged) {
  return privileged ? '<span class="badge badge-priv">privileged</span>' : '';
}

function copyBtn(text) {
  return '<button type="button" class="copy-btn" data-copy="' + esc(text) + '" ' +
    'title="Copy ' + esc(text) + '">copy</button>';
}

async function copyText(text, btn) {
  let ok = false;
  try {
    await navigator.clipboard.writeText(text);
    ok = true;
  } catch (e) {
    /* fallback for non-secure contexts */
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      ok = document.execCommand('copy');
      ta.remove();
    } catch (e2) { ok = false; }
  }
  if (btn) {
    const prev = btn.textContent;
    btn.textContent = ok ? 'copied ✓' : 'copy failed';
    if (ok) btn.classList.add('ok'); /* classList.add('') throws — guard it */
    setTimeout(function () {
      btn.textContent = prev;
      btn.classList.remove('ok');
    }, 1300);
  }
}

function toast(message, kind, simulated) {
  const root = document.getElementById('toast-root');
  if (!root) return;
  while (root.children.length >= 4) root.removeChild(root.firstChild);
  const el = document.createElement('div');
  el.className = 'toast toast-' + (kind || 'info');
  el.innerHTML = esc(message) + (simulated ? ' <span class="badge badge-simulated">simulated</span>' : '');
  root.appendChild(el);
  setTimeout(function () {
    el.classList.add('fade');
    setTimeout(function () { el.remove(); }, 400);
  }, 4200);
}

function downloadJSON(obj, filename) {
  const safe = String(filename || 'export.json').replace(/[^\w.-]+/g, '_');
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safe;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
}

/* ==================================================================
 * Router
 * ================================================================== */

function destroyNetwork() {
  if (state.network) {
    try { state.network.destroy(); } catch (e) { /* already gone */ }
    state.network = null;
  }
}

function setActiveTab(name) {
  document.querySelectorAll('#nav-tabs .tab').forEach(function (tab) {
    tab.classList.toggle('active', tab.getAttribute('data-tab') === name);
  });
}

async function route() {
  if (!state.token) {
    showLogin();
    return;
  }
  destroyNetwork(); // vis instances must not outlive their container
  const hash = location.hash || '#/alerts';
  const parts = hash.replace(/^#\/?/, '').split('/').filter(Boolean);
  const page = parts[0] || 'alerts';
  try {
    if (page === 'alerts') {
      await viewAlerts();
    } else if (page === 'identities') {
      await viewIdentities();
    } else if (page === 'identity' && parts[1]) {
      await viewIdentityDetail(decodeURIComponent(parts[1]));
    } else if (page === 'cases') {
      await viewCases();
    } else if (page === 'case' && parts[1]) {
      await viewCaseDetail(decodeURIComponent(parts[1]));
    } else {
      location.hash = '#/alerts';
    }
  } catch (err) {
    /* last-resort guard: never leave a blank page or log console errors */
    if (!(err && err.status === 401)) {
      VIEW().innerHTML = errorHTML(err, 'View failed to render');
    }
  }
}

function beginRender() { renderSeq += 1; return renderSeq; }
function isStale(seq) { return seq !== renderSeq; }

/* Delegated clicks inside #view: copy buttons, clickable rows, retry. */
function delegatedViewClick(e) {
  if (!e.target || typeof e.target.closest !== 'function') return;
  const copyBtnEl = e.target.closest('[data-copy]');
  if (copyBtnEl) {
    copyText(copyBtnEl.getAttribute('data-copy') || '', copyBtnEl);
    return;
  }
  const retry = e.target.closest('[data-retry]');
  if (retry) {
    route();
    return;
  }
  if (e.target.closest('a, button, input, select, textarea')) return;
  const row = e.target.closest('[data-href]');
  if (row) {
    const href = row.getAttribute('data-href');
    if (href) location.hash = href;
  }
}

/* ==================================================================
 * View: Alerts  (#/alerts)
 * ================================================================== */

async function viewAlerts() {
  const seq = beginRender();
  setActiveTab('alerts');
  const v = VIEW();

  const chipsHTML = SEV_CHIPS.map(function (pair) {
    const val = pair[0];
    const label = pair[1];
    let cls = 'chip-btn';
    if (val) cls += ' sev-' + val;
    if (state.alertsSeverity === val) cls += ' active';
    return '<button type="button" class="' + cls + '" data-sev="' + val + '">' + esc(label) + '</button>';
  }).join('');

  v.innerHTML =
    '<div class="page-head">' +
      '<div><h1>Alerts</h1><div class="page-sub mono">GET /api/alerts' +
      (state.alertsSeverity ? '?severity=' + esc(state.alertsSeverity) : '') + '</div></div>' +
      '<div class="chips" id="sev-chips">' + chipsHTML + '</div>' +
    '</div>' +
    '<div id="alerts-body">' + loadingHTML('Loading alerts…') + '</div>';

  v.querySelectorAll('#sev-chips [data-sev]').forEach(function (chip) {
    chip.addEventListener('click', function () {
      state.alertsSeverity = chip.getAttribute('data-sev') || '';
      viewAlerts();
    });
  });

  const body = $('#alerts-body', v);
  let alerts, nameById;
  try {
    const q = new URLSearchParams({ limit: '200' });
    if (state.alertsSeverity) q.set('severity', state.alertsSeverity);
    const results = await Promise.allSettled([
      api('/api/alerts?' + q.toString()),
      api('/api/identities?limit=500')
    ]);
    if (isStale(seq)) return;
    if (results[0].status === 'rejected') throw results[0].reason;
    const raw = results[0].value;
    alerts = Array.isArray(raw) ? raw : ((raw && raw.alerts) || []);
    nameById = new Map();
    if (results[1].status === 'fulfilled') {
      const ids = Array.isArray(results[1].value) ? results[1].value : ((results[1].value && results[1].value.identities) || []);
      ids.forEach(function (i) { if (i && i.identity_id) nameById.set(i.identity_id, i.display_name || i.identity_id); });
    }
  } catch (err) {
    if (isStale(seq) || (err && err.status === 401)) return;
    body.innerHTML = errorHTML(err, 'Failed to load alerts');
    return;
  }

  if (!alerts.length) {
    body.innerHTML = emptyHTML(
      'No alerts' + (state.alertsSeverity ? ' with severity “' + state.alertsSeverity + '”' : ''),
      'Detectors (D1–D6) have not fired for this filter, or the dataset has not been ingested yet.'
    );
    return;
  }

  const rows = alerts.map(function (a) {
    const t = a.created_at || a.timestamp || '';
    const conf = num(a.confidence);
    const href = a.case_id
      ? '#/case/' + encodeURIComponent(a.case_id)
      : '#/identity/' + encodeURIComponent(a.identity_id || '');
    const identityName = a.identity_id && nameById.has(a.identity_id) ? nameById.get(a.identity_id) : (a.identity_id || '—');
    return '<tr class="row-click" data-href="' + esc(href) + '">' +
      '<td class="mono dim nowrap">' + esc(fmtTime(t)) + '</td>' +
      '<td>' + sevBadge(a.severity) + '</td>' +
      '<td class="mono nowrap" title="' + (conf !== null ? esc('confidence ' + conf) : '') + '">' + esc(a.detection_id || '—') + '</td>' +
      '<td><span class="id-name">' + esc(identityName) + '</span>' +
        '<span class="id-sub mono">' + esc(a.identity_id || '') + '</span></td>' +
      '<td class="reason-cell">' + esc(a.reason || '—') + '</td>' +
      '<td>' + (a.case_id
        ? '<a class="case-link" href="#/case/' + encodeURIComponent(a.case_id) + '" title="' + esc(a.case_id) + '">case →</a>'
        : '<span class="faint">—</span>') + '</td>' +
    '</tr>';
  }).join('');

  body.innerHTML =
    '<div class="table-scroll"><table>' +
      '<thead><tr>' +
        '<th>Time (UTC)</th><th>Severity</th><th>Detection</th><th>Identity</th><th>Reason</th><th>Case</th>' +
      '</tr></thead>' +
      '<tbody>' + rows + '</tbody>' +
    '</table></div>' +
    '<div class="page-sub" style="margin-top:8px">showing ' + alerts.length + ' alert' + (alerts.length === 1 ? '' : 's') + ' · newest first · click a row to open the ' +
      'case or identity</div>';
}

/* ==================================================================
 * View: Identities  (#/identities)
 * ================================================================== */

async function viewIdentities() {
  const seq = beginRender();
  setActiveTab('identities');
  const v = VIEW();

  v.innerHTML =
    '<div class="page-head">' +
      '<div><h1>Identities</h1><div class="page-sub mono">GET /api/identities</div></div>' +
      '<div class="head-actions">' +
        '<input type="search" class="search-input" id="identity-search" ' +
        'placeholder="filter by name / id / department…" value="' + esc(state.identityQuery) + '" ' +
        'aria-label="Filter identities">' +
      '</div>' +
    '</div>' +
    '<div id="identities-body">' + loadingHTML('Loading identities…') + '</div>';

  let identities;
  try {
    const data = await api('/api/identities?limit=500');
    if (isStale(seq)) return;
    identities = Array.isArray(data) ? data : ((data && data.identities) || []);
  } catch (err) {
    if (isStale(seq) || (err && err.status === 401)) return;
    $('#identities-body', v).innerHTML = errorHTML(err, 'Failed to load identities');
    return;
  }

  state.identitiesCache = identities;

  const body = $('#identities-body', v);
  if (!identities.length) {
    body.innerHTML = emptyHTML('No identities', 'Ingest events and run evaluation to populate the directory.');
    return;
  }

  body.innerHTML =
    '<div class="table-scroll"><table>' +
      '<thead><tr><th>Identity</th><th>Department</th><th>Kind</th><th>Risk score</th><th>Band</th></tr></thead>' +
      '<tbody id="ident-rows"></tbody>' +
    '</table></div>' +
    '<div class="page-sub" id="ident-count" style="margin-top:8px"></div>';

  const search = $('#identity-search', v);
  search.addEventListener('input', function () {
    state.identityQuery = search.value;
    renderIdentityRows(seq);
  });

  renderIdentityRows(seq);
}

function renderIdentityRows(seq) {
  if (seq !== renderSeq) return;
  const tbody = document.getElementById('ident-rows');
  const count = document.getElementById('ident-count');
  if (!tbody) return;

  const q = state.identityQuery.trim().toLowerCase();
  const list = state.identitiesCache.filter(function (i) {
    if (!q) return true;
    return [i.display_name, i.identity_id, i.department, i.kind, i.severity_band]
      .some(function (field) { return String(field || '').toLowerCase().indexOf(q) !== -1; });
  });

  if (!list.length) {
    tbody.innerHTML = '<tr><td colspan="5"><div class="empty-note">No identities match “' +
      esc(state.identityQuery) + '”.</div></td></tr>';
    if (count) count.textContent = '';
    return;
  }

  tbody.innerHTML = list.map(function (i) {
    const score = num(i.score);
    const width = score === null ? 0 : clamp(score, 0, 100);
    const href = '#/identity/' + encodeURIComponent(i.identity_id || '');
    return '<tr class="row-click" data-href="' + esc(href) + '">' +
      '<td><span class="id-name">' + esc(i.display_name || i.identity_id) + '</span>' +
        '<span class="id-sub mono">' + esc(i.identity_id || '') + '</span></td>' +
      '<td>' + esc(i.department || '—') + '</td>' +
      '<td>' + kindBadge(i.kind) + '</td>' +
      '<td class="score-cell">' +
        '<span class="score-inline" style="color:' + scoreColor(score) + '">' + (score === null ? '—' : score) + '</span>' +
        '<span class="score-track"><span style="width:' + width + '%;background:' + scoreColor(score) + '"></span></span>' +
      '</td>' +
      '<td>' + bandBadge(i.severity_band, score === null ? 0 : score) + '</td>' +
    '</tr>';
  }).join('');

  if (count) {
    count.textContent = 'showing ' + list.length + ' of ' + state.identitiesCache.length + ' identities';
  }
}

/* ==================================================================
 * View: Identity detail  (#/identity/:id)
 * ================================================================== */

/*
 * §5 says the detail endpoint returns "identity + alerts + reachable sensitive
 * resources with paths + score breakdown" without pinning exact key names.
 * This normalizer accepts the plausible shapes so the UI degrades gracefully.
 */
function normalizeIdentityDetail(data, fallbackId) {
  const d = data || {};
  const identity = (d.identity && typeof d.identity === 'object') ? d.identity : {
    identity_id: d.identity_id || fallbackId,
    display_name: d.display_name || d.name || d.identity_id || fallbackId,
    kind: d.kind,
    department: d.department,
    privileged: d.privileged,
    active: d.active
  };
  identity.identity_id = identity.identity_id || fallbackId;

  const risk = (d.risk && typeof d.risk === 'object') ? d.risk : {};
  const breakdown = (d.score_breakdown && typeof d.score_breakdown === 'object') ? d.score_breakdown : {};
  const score = num(d.score) !== null ? num(d.score)
    : num(identity.score) !== null ? num(identity.score)
    : num(risk.score);

  let components = d.components || risk.components || breakdown.components || [];
  if (!Array.isArray(components)) components = [];

  let explanation = d.explanation || risk.explanation || breakdown.explanation || [];
  if (!Array.isArray(explanation)) explanation = [String(explanation)];

  let alerts = d.alerts || [];
  if (!Array.isArray(alerts)) alerts = [];

  let reachable = d.reachable_sensitive_resources || d.reachable_resources || d.reachable || d.sensitive_resources || [];
  if (!Array.isArray(reachable)) reachable = [];

  return {
    identity: identity,
    score: score,
    band: d.severity_band || identity.severity_band || risk.severity_band || '',
    components: components,
    explanation: explanation,
    alerts: alerts,
    reachable: reachable,
    raw: d            // kept for findConsentedAppId (embedded consent lists)
  };
}

async function viewIdentityDetail(id) {
  const seq = beginRender();
  setActiveTab('identities');
  const v = VIEW();
  v.innerHTML = loadingHTML('Loading identity ' + id + '…');

  /* detail + graph in parallel; a graph failure must not kill the page */
  const results = await Promise.allSettled([
    api('/api/identities/' + encodeURIComponent(id)),
    api('/api/graph?identity_id=' + encodeURIComponent(id))
  ]);
  if (isStale(seq)) return;
  if (results[0].status === 'rejected') {
    const err = results[0].reason;
    if (err && err.status === 401) return;
    v.innerHTML = errorHTML(err, 'Failed to load identity ' + id);
    return;
  }

  const norm = normalizeIdentityDetail(results[0].value, id);
  const identity = norm.identity;
  const graph = results[1].status === 'fulfilled' ? results[1].value : null;
  const graphErr = results[1].status === 'rejected' ? results[1].reason : null;
  const labelMap = graph && Array.isArray(graph.nodes)
    ? new Map(graph.nodes.map(function (n) { return [n.id, n.label || n.id]; }))
    : new Map();

  /* alerts: prefer the embedded list, else filter the global feed */
  let alerts = Array.isArray(norm.alerts) ? norm.alerts : [];
  if (!alerts.length) {
    try {
      const feed = await api('/api/alerts?limit=200');
      if (isStale(seq)) return;
      const all = Array.isArray(feed) ? feed : ((feed && feed.alerts) || []);
      alerts = all.filter(function (a) { return a && a.identity_id === identity.identity_id; });
    } catch (e) { alerts = []; }
  }
  alerts = alerts.slice().sort(function (a, b) {
    return sevRank(a.severity) - sevRank(b.severity) ||
      String(b.created_at || '').localeCompare(String(a.created_at || ''));
  });

  const score = norm.score;
  const displayName = identity.display_name || identity.identity_id || id;

  /* ---- header ---- */
  const headerHTML =
    '<div class="detail-head">' +
      '<div>' +
        '<div class="id-title-line">' +
          '<h1 class="id-title">' + esc(displayName) + '</h1>' +
          kindBadge(identity.kind) + privBadge(identity.privileged === true) +
          '<span class="mono faint">' + esc(identity.identity_id || id) + '</span>' +
        '</div>' +
        '<div class="id-meta">' +
          '<span>dept: <strong>' + esc(identity.department || '—') + '</strong></span>' +
          '<span>status: <strong>' + (identity.active === false ? 'disabled' : 'active') + '</strong></span>' +
        '</div>' +
      '</div>' +
      '<div class="score-box">' +
        '<span class="score-num" style="color:' + scoreColor(score) + '">' + (score === null ? '—' : score) + '</span>' +
        '<span class="score-max"> /100</span>' +
        '<div>' + bandBadge(norm.band, score === null ? 0 : score) + '</div>' +
      '</div>' +
    '</div>';

  /* ---- score breakdown (§4) ---- */
  const compHTML = norm.components.length
    ? norm.components.map(function (c) {
        const name = String(c.name || c.component || c.kind || c.id || 'component');
        // CONTRACTS §4 wire shape: components carry `points` (value/c.score kept for tolerance)
        const value = num(c.points) !== null ? num(c.points)
          : num(c.value) !== null ? num(c.value)
          : num(c.score) !== null ? num(c.score) : 0;
        const max = num(c.max) !== null ? num(c.max)
          : num(c.cap) !== null ? num(c.cap)
          : (Object.prototype.hasOwnProperty.call(COMPONENT_MAX, name) ? COMPONENT_MAX[name] : null);
        const ratio = max && max > 0 ? clamp(value / max, 0, 1) : 0;
        const fill = max ? (ratio >= 0.8 ? 'var(--red)' : ratio >= 0.5 ? 'var(--amber)' : 'var(--green)') : 'var(--dim)';
        const just = c.justification || c.detail || c.reason || '';
        return '<div class="comp">' +
          '<div class="comp-head">' +
            '<span class="comp-name">' + esc(name) + '</span>' +
            '<span class="comp-val">' + value + (max ? ' / ' + max : '') + '</span>' +
          '</div>' +
          '<div class="bar"><div class="bar-fill" style="width:' + Math.round(ratio * 100) + '%;background:' + fill + '"></div></div>' +
          (just ? '<div class="comp-just">' + esc(just) + '</div>' : '') +
        '</div>';
      }).join('')
    : '<div class="empty-note">No score components returned.</div>';

  const explainHTML = norm.explanation.length
    ? '<div class="card-subtitle">Explanation</div>' +
      '<ul class="explain-list">' + norm.explanation.map(function (line) {
        return '<li>' + esc(line) + '</li>';
      }).join('') + '</ul>'
    : '';

  /* ---- reachable sensitive resources ---- */
  const resItemsHTML = norm.reachable.length
    ? norm.reachable.map(function (r) {
        const rid = r.resource_id || r.id || '';
        const rlabel = r.label || r.name || rid;
        const sens = String(r.sensitivity || (r.sensitive === true ? 'sensitive' : '')).toLowerCase();
        const paths = Array.isArray(r.paths) ? r.paths : (r.path ? [r.path] : []);
        const viaStr = typeof r.via === 'string' ? r.via : '';
        const pathsHTML = paths.map(function (p) {
          return '<div class="path"><span class="via-label">via</span>' + pathChipsHTML(p, labelMap) + '</div>';
        }).join('');
        return '<div class="res-item">' +
          '<div class="res-head">' +
            '<span class="res-name">' + esc(rlabel) + '</span>' +
            '<span class="res-id mono">' + esc(rid) + '</span>' +
            (sens ? '<span class="badge sev-critical res-sens">' + esc(sens) + '</span>' : '') +
          '</div>' +
          (pathsHTML ? '<div class="res-paths">' + pathsHTML + '</div>' : '') +
          (!pathsHTML && viaStr ? '<div class="res-paths"><div class="path"><span class="via-label">via</span>' +
            '<span class="path-chip">' + esc(viaStr) + '</span></div></div>' : '') +
        '</div>';
      }).join('')
    : '<div class="empty-note">No sensitive resources are reachable from this identity — access_component is 0.</div>';

  /* ---- alerts for this identity ---- */
  const alertsHTML = alerts.length
    ? alerts.map(function (a) {
        const sev = String(a.severity || '').toLowerCase();
        const sevCls = Object.prototype.hasOwnProperty.call(SEV_COLOR, sev) ? ' sev-' + sev : '';
        const refs = Array.isArray(a.event_refs) ? a.event_refs : [];
        return '<div class="alert-item' + sevCls + '">' +
          '<div class="alert-item-head">' +
            sevBadge(a.severity) +
            '<span class="mono">' + esc(a.detection_id || '') + '</span>' +
            (a.case_id ? '<a class="case-link" href="#/case/' + encodeURIComponent(a.case_id) + '">case →</a>' : '') +
            '<span class="mono faint" style="margin-left:auto">' + esc(fmtTime(a.created_at || a.timestamp)) + '</span>' +
          '</div>' +
          '<div class="alert-reason">' + esc(a.reason || '') + '</div>' +
          (refs.length
            ? '<div class="alert-refs"><span class="via-label">refs</span>' +
              refs.map(function (r) { return '<span class="ref-chip">' + esc(r) + '</span>'; }).join('') +
              copyBtn(refs.join(',')) + '</div>'
            : '') +
        '</div>';
      }).join('')
    : '<div class="empty-note">No alerts for this identity.</div>';

  /* ---- respond actions (admin only; 403 => "admin role required") ---- */
  const respondHTML =
    '<div class="card" id="respond-card">' +
      '<div class="card-title">Respond <span class="badge badge-simulated">simulation-only</span></div>' +
      '<p class="respond-note">Containment actions write to the response audit log and never touch external systems. Requires the admin role.</p>' +
      '<div class="respond-grid">' +
        '<button type="button" class="btn btn-danger" data-action="consent_revoke">' + esc(RESPOND_META.consent_revoke.label) + '</button>' +
        '<button type="button" class="btn btn-danger" data-action="account_disable">' + esc(RESPOND_META.account_disable.label) + '</button>' +
        '<button type="button" class="btn btn-danger" data-action="session_revoke">' + esc(RESPOND_META.session_revoke.label) + '</button>' +
      '</div>' +
      '<div class="respond-result" id="respond-result"></div>' +
    '</div>';

  /* ---- attack graph ---- */
  const graphBody = graphErr
    ? errorHTML(graphErr, 'Failed to load attack graph')
    : (graph && Array.isArray(graph.nodes) && graph.nodes.length === 0
      ? emptyHTML('Empty graph', 'No grants involve this identity.')
      : '<div class="graph-canvas" id="attack-graph"></div>');

  const graphHTML =
    '<div class="card graph-card">' +
      '<div class="card-title">Attack graph <span class="mono dim">GET /api/graph?identity_id=' + esc(id) + '</span></div>' +
      '<div class="graph-wrap" id="graph-wrap">' + graphBody + legendHTML() + '</div>' +
    '</div>';

  v.innerHTML =
    headerHTML +
    '<div class="detail-grid">' +
      '<div class="detail-col">' +
        '<div class="card"><div class="card-title">Score breakdown</div>' + compHTML + explainHTML + '</div>' +
        respondHTML +
      '</div>' +
      '<div class="detail-col">' +
        '<div class="card"><div class="card-title">Reachable sensitive resources' +
          '<span class="count-pill">' + norm.reachable.length + '</span></div>' + resItemsHTML + '</div>' +
        '<div class="card"><div class="card-title">Alerts<span class="count-pill">' + alerts.length + '</span></div>' + alertsHTML + '</div>' +
      '</div>' +
    '</div>' +
    graphHTML;

  /* wire respond buttons */
  v.querySelectorAll('#respond-card [data-action]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      handleRespond(btn.getAttribute('data-action'), identity, norm, graph, seq);
    });
  });

  /* render graph last, once the container is in the DOM */
  if (!graphErr && graph && Array.isArray(graph.nodes) && graph.nodes.length) {
    renderAttackGraph(document.getElementById('attack-graph'), graph, collectHighlight(norm.reachable));
  }
}

/* "via" path chips; path entries may be node-id strings or {id,label} objects */
function pathChipsHTML(path, labelMap) {
  const entries = Array.isArray(path) ? path : [path];
  return entries.map(function (p) {
    if (p && typeof p === 'object') {
      const pid = p.id || p.node_id || p.node || '';
      const plabel = p.label || p.display_name || labelMap.get(pid) || pid;
      const kind = String(p.kind || '').toLowerCase();
      const cls = (kind === 'app' || kind === 'resource' || kind === 'group' || kind === 'role' || kind === 'service_account')
        ? ' k-' + kind : '';
      return '<span class="path-chip' + cls + '" title="' + esc(pid) + '">' + esc(plabel || pid || '?') + '</span>';
    }
    const key = String(p);
    return '<span class="path-chip" title="' + esc(key) + '">' + esc(labelMap.get(key) || key) + '</span>';
  }).join('<span class="chip-arrow">→</span>');
}

/*
 * Collect path hints used to highlight graph edges: grant ids and consecutive
 * node-id pairs found in the reachable-resources payload. Edges may also carry
 * their own on_path/in_path flags — those are honored in renderAttackGraph.
 */
function collectHighlight(resources) {
  const grants = new Set();
  const pairs = new Set();
  function addPath(path) {
    if (!path) return;
    const entries = Array.isArray(path) ? path : [path];
    const ids = [];
    entries.forEach(function (p) {
      if (typeof p === 'string') { ids.push(p); return; }
      if (p && typeof p === 'object') {
        if (p.grant_id) grants.add(p.grant_id);
        ids.push(p.id || p.node_id || p.node || '');
      }
    });
    const clean = ids.filter(Boolean);
    for (let i = 0; i < clean.length - 1; i++) {
      pairs.add(clean[i] + '→' + clean[i + 1]);
      pairs.add(clean[i + 1] + '→' + clean[i]); // direction-tolerant
    }
  }
  (resources || []).forEach(function (r) {
    const paths = Array.isArray(r.paths) ? r.paths : (r.path ? [r.path] : []);
    paths.forEach(addPath);
    (r.grant_ids || r.grants || []).forEach(function (g) {
      if (typeof g === 'string') grants.add(g);
      else if (g && g.grant_id) grants.add(g.grant_id);
    });
  });
  return { grants: grants, pairs: pairs, any: grants.size > 0 || pairs.size > 0 };
}

/* ==================================================================
 * Respond actions
 * ================================================================== */

function findConsentedAppId(norm, graph) {
  const d = norm && norm.raw ? norm.raw : {};
  const lists = [d.consented_apps, d.consents, d.apps];
  for (let i = 0; i < lists.length; i++) {
    const list = lists[i];
    if (Array.isArray(list) && list.length) {
      const first = list[0];
      if (typeof first === 'string') return first;
      if (first && (first.app_id || first.id)) return first.app_id || first.id;
    }
  }
  if (graph && Array.isArray(graph.nodes)) {
    const appNode = graph.nodes.find(function (n) { return String(n.kind || '').toLowerCase() === 'app'; });
    if (appNode) return appNode.id;
  }
  return null;
}

async function handleRespond(action, identity, norm, graph, seq) {
  const meta = RESPOND_META[action];
  if (!meta) return;

  const target = String(identity.display_name || identity.identity_id || '');
  const appId = action === 'consent_revoke' ? findConsentedAppId(norm, graph) : null;
  const scopeLine = appId
    ? 'Target app: <span class="mono">' + esc(appId) + '</span>'
    : 'Target: <span class="mono">' + esc(identity.identity_id || '') + '</span>';

  const ok = await confirmDialog({
    title: meta.label + ' — ' + target,
    bodyHTML: '<p>' + esc(meta.desc) + '</p><p>' + scopeLine + '</p>',
    confirmLabel: meta.confirm
  });
  if (!ok) return;

  const resultEl = document.getElementById('respond-result');
  const buttons = document.querySelectorAll('#respond-card [data-action]');
  buttons.forEach(function (b) { b.disabled = true; });
  if (resultEl) resultEl.innerHTML = '<span class="dim">Submitting ' + esc(meta.label.toLowerCase()) + '…</span>';

  /* §5 body: {"app_id"|"identity_id", "confirm": true} */
  const body = { confirm: true };
  if (action === 'consent_revoke' && appId) body.app_id = appId;
  else body.identity_id = identity.identity_id;

  try {
    const res = await api('/api/respond/' + action, { method: 'POST', body: body });
    if (isStale(seq)) return;
    const simulated = !!(res && res.simulated === true);
    const auditId = res && res.audit_id ? ' (audit ' + res.audit_id + ')' : '';
    const msg = meta.label + ' recorded' + auditId + '.';
    if (resultEl) {
      resultEl.innerHTML = '<div class="respond-ok">' + esc(msg) +
        (simulated ? ' <span class="badge badge-simulated">simulated</span>' : '') + '</div>';
    }
    toast(msg, 'success', simulated);
  } catch (err) {
    if (isStale(seq)) return;
    if (err && err.status === 401) return;
    const msg = err && err.status === 403
      ? 'admin role required'
      : ((err && err.message) || 'request failed');
    if (resultEl) resultEl.innerHTML = '<div class="respond-error">' + esc(msg) + '</div>';
    if (err && err.status !== 403) toast(msg, 'error');
  } finally {
    buttons.forEach(function (b) { b.disabled = false; });
  }
}

function confirmDialog(opts) {
  return new Promise(function (resolve) {
    const root = document.getElementById('modal-root');
    root.innerHTML =
      '<div class="overlay modal-overlay" id="modal-overlay">' +
        '<div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title">' +
          '<div class="modal-title" id="modal-title">' + esc(opts.title || 'Confirm') + '</div>' +
          '<div class="modal-body">' + (opts.bodyHTML || '') + '</div>' +
          '<div class="modal-note">Response actions are simulation-only. Every action is written to the response audit table with your actor role.</div>' +
          '<div class="modal-actions">' +
            '<button type="button" class="btn" id="modal-cancel">Cancel</button>' +
            '<button type="button" class="btn btn-danger" id="modal-confirm">' + esc(opts.confirmLabel || 'Confirm') + '</button>' +
          '</div>' +
        '</div>' +
      '</div>';

    function done(val) {
      root.innerHTML = '';
      document.removeEventListener('keydown', onKey);
      resolve(val);
    }
    function onKey(e) { if (e.key === 'Escape') done(false); }

    document.addEventListener('keydown', onKey);
    $('#modal-cancel').addEventListener('click', function () { done(false); });
    $('#modal-confirm').addEventListener('click', function () { done(true); });
    $('#modal-overlay').addEventListener('click', function (e) {
      if (e.target.id === 'modal-overlay') done(false);
    });
    $('#modal-confirm').focus();
  });
}

/* ==================================================================
 * Attack graph (vis-network)
 * ================================================================== */

function legendHTML() {
  const items = [
    ['#f85149', '◆', 'sensitive resource'],
    ['#4d6a85', '■', 'resource (non-sensitive)'],
    ['#f0883e', '●', 'privileged identity'],
    ['#58a6ff', '●', 'user'],
    ['#39c5cf', '●', 'service account'],
    ['#a371f7', '⬢', 'app'],
    ['#8b949e', '◯', 'group / role']
  ];
  return '<div class="legend"><div class="legend-title">Legend</div>' +
    items.map(function (it) {
      return '<div class="legend-item"><span class="lg-glyph" style="color:' + it[0] + '">' + it[1] + '</span>' +
        esc(it[2]) + '</div>';
    }).join('') +
    '<div class="legend-item"><span class="lg-line"></span>reachable path (width 3)</div>' +
    '</div>';
}

/*
 * Node visual per CONTRACTS §2 + task spec:
 * red=sensitive resource, orange=privileged identity, blue=normal user,
 * purple=app, gray=group/role. Service accounts get cyan; plain resources
 * a muted square.
 */
function nodeVisual(n) {
  const kind = String(n.kind || '').toLowerCase();
  const sensitive = n.sensitive === true || String(n.sensitivity || '').toLowerCase() === 'sensitive';
  if (kind === 'resource' || kind.indexOf('res') === 0) {
    return sensitive
      ? { bg: '#2a1214', border: '#f85149', shape: 'diamond', size: 14, glyph: '◆' }
      : { bg: '#141c26', border: '#4d6a85', shape: 'square', size: 12, glyph: '■' };
  }
  if (kind === 'app' || kind === 'service_principal') {
    return { bg: '#221a30', border: '#a371f7', shape: 'hexagon', size: 13, glyph: '⬢' };
  }
  if (kind === 'group' || kind === 'role') {
    return { bg: '#20262e', border: '#8b949e', shape: 'ellipse', size: 13, glyph: '◯' };
  }
  if (n.privileged === true) {
    return { bg: '#f0883e', border: '#12161c', shape: 'dot', size: 11, glyph: '●' };
  }
  if (kind === 'service_account' || kind.indexOf('svc') === 0) {
    return { bg: '#39c5cf', border: '#12161c', shape: 'dot', size: 10, glyph: '●' };
  }
  return { bg: '#58a6ff', border: '#12161c', shape: 'dot', size: 10, glyph: '●' };
}

function renderAttackGraph(container, graph, highlight) {
  destroyNetwork();
  if (!container) return;

  const visRef = window.vis;
  if (!visRef || typeof visRef.Network !== 'function') {
    container.outerHTML =
      '<div class="state state-error state-inset"><div class="state-icon">⚠</div>' +
      '<div class="state-text">Graph library unavailable</div>' +
      '<div class="state-sub">vendor/vis-network.min.js failed to load or does not expose window.vis</div></div>';
    return;
  }

  const nodeList = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edgeList = Array.isArray(graph.edges) ? graph.edges : [];

  const nodes = nodeList.map(function (n) {
    const v = nodeVisual(n);
    const kind = String(n.kind || '').toLowerCase();
    const flags = [];
    if (n.privileged === true) flags.push('privileged');
    if (n.sensitive === true || String(n.sensitivity || '').toLowerCase() === 'sensitive') flags.push('SENSITIVE');
    flags.push(kind || 'node');
    flags.push(n.id);
    return {
      id: n.id,
      label: n.label || n.id,
      shape: v.shape,
      size: v.size,
      color: {
        background: v.bg,
        border: v.border,
        highlight: { background: v.bg, border: '#f0f6fc' },
        hover: { background: v.bg, border: '#c9d1d9' }
      },
      borderWidth: flags.indexOf('privileged') !== -1 || flags.indexOf('SENSITIVE') !== -1 ? 2 : 1.5,
      font: { color: '#c9d1d9', size: 12, face: '-apple-system, Segoe UI, sans-serif' },
      title: esc(flags.join(' · '))
    };
  });

  const edges = edgeList.map(function (e, i) {
    /* path highlight: explicit flags > grant ids > consecutive path node pairs */
    const onPath = e.on_path === true || e.in_path === true ||
      (highlight && highlight.grants && highlight.grants.has(e.grant_id)) ||
      (highlight && highlight.pairs && (highlight.pairs.has(e.from + '→' + e.to)));
    const hasHighlight = highlight && highlight.any;
    return {
      id: e.grant_id || ('e' + i),
      from: e.from,
      to: e.to,
      label: e.kind || '',
      arrows: { to: { enabled: true, scaleFactor: 0.55 } },
      color: {
        color: onPath ? '#f85149' : (hasHighlight ? '#2c3540' : '#39424e'),
        highlight: '#f0f6fc',
        hover: '#8b949e'
      },
      width: onPath ? 3 : 1.2,             /* path edges: width 3 */
      dashes: false,
      smooth: { enabled: false },
      font: {
        size: 10,
        color: onPath ? '#f85149' : '#6e7681',
        face: 'SF Mono, Consolas, monospace',
        strokeWidth: 4,
        strokeColor: '#0a0e14'
      }
    };
  });

  const options = {
    autoResize: true,
    layout: { improvedLayout: true },
    physics: {
      enabled: true,
      solver: 'forceAtlas2Based',
      forceAtlas2Based: {
        gravitationalConstant: -55,
        centralGravity: 0.015,
        springLength: 105,
        springConstant: 0.045,
        damping: 0.45
      },
      stabilization: { enabled: true, iterations: 400, fit: true }
    },
    interaction: {
      hover: true,
      tooltipDelay: 150,
      keyboard: false,
      navigationButtons: false
    },
    nodes: {
      borderWidth: 1.5,
      borderWidthSelected: 2.5,
      shapeProperties: { borderDontIncludeLabel: false }
    },
    edges: {
      selectionWidth: 2,
      hoverWidth: 1.5,
      labelHighlightBold: false
    }
  };

  try {
    const network = new visRef.Network(container, { nodes: nodes, edges: edges }, options);
    state.network = network;
    /* animation off — snap the viewport, no easing */
    const fitNow = function () { try { network.fit({ animation: false }); } catch (e) { /* noop */ } };
    network.once('afterDrawing', fitNow);
    network.once('stabilizationIterationsDone', fitNow);
  } catch (err) {
    container.innerHTML =
      '<div class="state state-error state-inset"><div class="state-icon">⚠</div>' +
      '<div class="state-text">Failed to render graph</div>' +
      '<div class="state-sub">' + esc(err && err.message ? err.message : 'vis.Network error') + '</div></div>';
  }
}

/* ==================================================================
 * View: Cases  (#/cases)
 * ================================================================== */

async function viewCases() {
  const seq = beginRender();
  setActiveTab('cases');
  const v = VIEW();
  v.innerHTML =
    '<div class="page-head"><div><h1>Cases</h1><div class="page-sub mono">GET /api/cases</div></div></div>' +
    '<div id="cases-body">' + loadingHTML('Loading cases…') + '</div>';

  let cases;
  try {
    const data = await api('/api/cases?limit=200');
    if (isStale(seq)) return;
    cases = Array.isArray(data) ? data : ((data && data.cases) || []);
  } catch (err) {
    if (isStale(seq) || (err && err.status === 401)) return;
    $('#cases-body', v).innerHTML = errorHTML(err, 'Failed to load cases');
    return;
  }

  const body = $('#cases-body', v);
  if (!cases.length) {
    body.innerHTML = emptyHTML('No cases', 'Cases are opened when alerts are correlated by the backend.');
    return;
  }

  body.innerHTML =
    '<div class="table-scroll"><table>' +
      '<thead><tr><th>Case</th><th>Severity</th><th>Status</th><th>Identity</th><th>Opened</th></tr></thead>' +
      '<tbody>' +
      cases.map(function (c) {
        const href = '#/case/' + encodeURIComponent(c.case_id || '');
        return '<tr class="row-click" data-href="' + esc(href) + '">' +
          '<td><span class="id-name">' + esc(c.title || c.case_id) + '</span>' +
            '<span class="id-sub mono">' + esc(c.case_id || '') +
              (num(c.alert_count) !== null ? ' · ' + c.alert_count + ' alerts' : '') + '</span></td>' +
          '<td>' + sevBadge(c.severity) + '</td>' +
          '<td>' + statusBadge(c.status) + '</td>' +
          '<td class="mono">' + esc(c.identity_id || '—') + '</td>' +
          '<td class="mono dim nowrap">' + esc(fmtTime(c.created_at || c.timestamp)) + '</td>' +
        '</tr>';
      }).join('') +
      '</tbody>' +
    '</table></div>' +
    '<div class="page-sub" style="margin-top:8px">showing ' + cases.length + ' case' + (cases.length === 1 ? '' : 's') + '</div>';
}

/* ==================================================================
 * View: Case detail  (#/case/:id)
 * ================================================================== */

function tlField(it, keys) {
  for (let i = 0; i < keys.length; i++) {
    const val = it[keys[i]];
    if (val !== undefined && val !== null && val !== '') return val;
  }
  return '';
}

function timelineItemHTML(it) {
  const kind = String(tlField(it, ['kind', 'type']) || (it.alert_id ? 'alert' : 'event')).toLowerCase();
  const isAlert = kind.indexOf('alert') !== -1;
  const sev = String(it.severity || '').toLowerCase();
  const t = fmtTime(tlField(it, ['timestamp', 'time', 'created_at', 'ts']));
  const id = tlField(it, ['event_id', 'alert_id', 'id']);
  const summary = tlField(it, ['summary', 'description', 'reason', 'detail']);
  const source = tlField(it, ['source']);
  const detection = tlField(it, ['detection_id']);

  return '<li class="tl-item ' + (isAlert ? 'kind-alert' : 'kind-event') +
    (SEV_COLOR[sev] ? ' sev-' + sev : '') + '">' +
    '<div class="tl-marker"></div>' +
    '<div class="tl-card">' +
      '<div class="tl-head">' +
        '<span class="tl-kind ' + (isAlert ? 'tl-kind-alert' : 'tl-kind-event') + '">' + (isAlert ? 'ALERT' : 'EVENT') + '</span>' +
        (isAlert && sev ? sevBadge(sev) : '') +
        (source ? '<span class="tl-src mono">' + esc(source) + '</span>' : '') +
        (detection ? '<span class="mono faint">' + esc(detection) + '</span>' : '') +
        '<span class="tl-time mono">' + esc(t) + '</span>' +
      '</div>' +
      '<div class="tl-summary">' + esc(summary || '—') + '</div>' +
      (id
        ? '<div class="tl-id-row"><span class="tl-id mono">' + esc(id) + '</span>' + copyBtn(id) + '</div>'
        : '') +
    '</div>' +
  '</li>';
}

async function viewCaseDetail(caseId) {
  const seq = beginRender();
  setActiveTab('cases');
  const v = VIEW();
  v.innerHTML = loadingHTML('Loading case ' + caseId + '…');

  let c;
  try {
    c = await api('/api/cases/' + encodeURIComponent(caseId));
  } catch (err) {
    if (isStale(seq) || (err && err.status === 401)) return;
    v.innerHTML = errorHTML(err, 'Failed to load case ' + caseId);
    return;
  }
  if (isStale(seq)) return;

  c = c || {};
  const timelineRaw = c.timeline || c.items || c.entries || [];
  const timeline = (Array.isArray(timelineRaw) ? timelineRaw : []).slice().sort(function (a, b) {
    const ta = new Date(tlField(a, ['timestamp', 'time', 'created_at', 'ts'])).getTime() || 0;
    const tb = new Date(tlField(b, ['timestamp', 'time', 'created_at', 'ts'])).getTime() || 0;
    return ta - tb; // chronological read
  });

  const alertCount = timeline.filter(function (it) {
    return String(tlField(it, ['kind', 'type']) || (it.alert_id ? 'alert' : 'event')).toLowerCase().indexOf('alert') !== -1;
  }).length;

  const conclusionRaw = c.conclusion;
  let conclusionHTML;
  if (conclusionRaw === undefined || conclusionRaw === null || conclusionRaw === '') {
    conclusionHTML = '<div class="conclusion conclusion-empty">No conclusion recorded yet.</div>';
  } else if (typeof conclusionRaw === 'string') {
    conclusionHTML = '<div class="conclusion">' + esc(conclusionRaw) + '</div>';
  } else {
    conclusionHTML = '<div class="conclusion mono" style="white-space:pre-wrap">' + esc(JSON.stringify(conclusionRaw, null, 2)) + '</div>';
  }

  v.innerHTML =
    '<div class="page-head">' +
      '<div>' +
        '<h1>' + esc(c.title || c.case_id || caseId) + '</h1>' +
        '<div class="case-meta mono">' +
          '<span class="faint">' + esc(c.case_id || caseId) + '</span>' +
          '<span>identity: <a href="#/identity/' + encodeURIComponent(c.identity_id || '') + '">' + esc(c.identity_id || '—') + '</a></span>' +
          '<span class="dim">opened ' + esc(fmtTime(c.created_at || c.timestamp)) + '</span>' +
        '</div>' +
      '</div>' +
      '<div class="head-actions">' +
        sevBadge(c.severity) +
        statusBadge(c.status) +
        '<button type="button" class="btn" id="export-case-btn">Export JSON</button>' +
      '</div>' +
    '</div>' +
    '<div class="case-grid">' +
      '<div class="detail-col">' +
        '<div class="card"><div class="card-title">Conclusion</div>' + conclusionHTML + '</div>' +
        '<div class="card"><div class="card-title">At a glance</div>' +
          '<div class="id-meta">' +
            '<span>timeline entries: <strong>' + timeline.length + '</strong></span>' +
            '<span>alert entries: <strong>' + alertCount + '</strong></span>' +
            '<span>event entries: <strong>' + (timeline.length - alertCount) + '</strong></span>' +
          '</div>' +
        '</div>' +
      '</div>' +
      '<div class="detail-col card timeline-card">' +
        '<div class="card-title">Correlated timeline<span class="count-pill">' + timeline.length + '</span>' +
          '<span class="mono dim" style="text-transform:none;letter-spacing:0">merged events + alerts, time-sorted</span></div>' +
        (timeline.length
          ? '<ol class="timeline">' + timeline.map(timelineItemHTML).join('') + '</ol>'
          : emptyHTML('Empty timeline', 'The case has no correlated entries.')) +
      '</div>' +
    '</div>';

  const exportBtn = document.getElementById('export-case-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', function () {
      downloadJSON(c, (c.case_id || caseId) + '.json');
      toast('Case exported as JSON.', 'success');
    });
  }
}

/* ==================================================================
 * Init
 * ================================================================== */

function init() {
  document.getElementById('login-form').addEventListener('submit', onLoginSubmit);
  VIEW().addEventListener('click', delegatedViewClick);
  window.addEventListener('hashchange', route);
  renderTokenStatus();

  if (state.token) {
    showLogin('Validating stored token…');
    document.getElementById('login-error').classList.add('hidden');
    validateToken(state.token).then(function (ok) {
      if (ok) {
        hideLogin();
        route();
      }
      /* on failure validateToken already surfaced the specific error */
    });
  } else {
    showLogin();
  }
}

init();
