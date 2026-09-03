/**
 * AuditSnap - popup.js
 * ------------------------------------------------------------
 * Orchestrates the full passive audit when the popup opens:
 *   1. Resolve active tab + guard against restricted URLs.
 *   2. Fetch HTTP security headers (cached from background.js,
 *      falling back to a live fetch if nothing is cached yet).
 *   3. Inspect cookies via chrome.cookies.getAll.
 *   4. Probe robots.txt / sitemap.xml / fingerprinting headers.
 *   5. Compute a 0-100 Security Posture Score.
 *   6. Render the UI (score ring, tabs/panels).
 *   7. Wire up "Copy Proposal Hook" and "Copy Markdown Report".
 * ------------------------------------------------------------
 */

'use strict';

// CONSTANTS

const FETCH_TIMEOUT_MS = 4000;

const SECURITY_HEADERS = [
  {
    key: 'content-security-policy',
    label: 'Content-Security-Policy',
    risk: 'Without a CSP, injected scripts (XSS) can run freely and exfiltrate session data or deface the page.',
    weight: 25,
  },
  {
    key: 'strict-transport-security',
    label: 'Strict-Transport-Security',
    risk: 'Missing HSTS allows attackers to downgrade connections to HTTP and intercept traffic (SSL-stripping).',
    weight: 20,
  },
  {
    key: 'x-frame-options',
    label: 'X-Frame-Options',
    risk: 'Without this, the site can be embedded in a hidden iframe, enabling clickjacking attacks on users.',
    weight: 15,
  },
  {
    key: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    risk: 'Missing this header lets browsers MIME-sniff responses, which can turn uploads into executable scripts.',
    weight: 10,
  },
  {
    key: 'referrer-policy',
    label: 'Referrer-Policy',
    risk: 'Without a Referrer-Policy, full URLs (sometimes containing tokens) may leak to third-party destinations.',
    weight: 10,
  },
];

const SENSITIVE_PATH_KEYWORDS = [
  '/admin', '/login', '/portal', '/api', '/backup',
  '/wp-admin', '/dashboard', '/config', '/.env', '/staging',
  '/internal', '/dev', '/test', '/private', '/panel',
];

const FINGERPRINT_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'];

// Score weight buckets (headers 65%, cookies 20%, surface 15%)
const COOKIE_PENALTY_PER_INSECURE = 4; // capped below
const COOKIE_PENALTY_CAP = 20;
const SURFACE_PENALTY_CAP = 15;

// STATE

const state = {
  tab: null,
  origin: null,
  headers: {},           // lowercase header name -> value
  headersSource: null,   // 'cache' | 'live-fetch' | 'unavailable'
  cookies: [],
  cookieSummary: { total: 0, insecure: 0 },
  robots: { checked: false, accessible: false, sensitivePaths: [], error: null },
  sitemap: { checked: false, accessible: false, error: null },
  fingerprint: [],
  score: 0,
  headerResults: [],
  isRestrictedPage: false,
};

// DOM REFERENCES

const el = {
  targetDomain: document.getElementById('targetDomain'),
  targetDot: document.getElementById('targetDot'),
  statusBanner: document.getElementById('statusBanner'),
  loadingState: document.getElementById('loadingState'),
  mainContent: document.getElementById('mainContent'),
  rescanBtn: document.getElementById('rescanBtn'),

  scoreValue: document.getElementById('scoreValue'),
  scoreLabel: document.getElementById('scoreLabel'),
  scoreRingFg: document.getElementById('scoreRingFg'),

  headersList: document.getElementById('headersList'),

  cookieTotal: document.getElementById('cookieTotal'),
  cookieInsecure: document.getElementById('cookieInsecure'),
  cookiesList: document.getElementById('cookiesList'),

  robotsStatus: document.getElementById('robotsStatus'),
  robotsList: document.getElementById('robotsList'),
  sitemapStatus: document.getElementById('sitemapStatus'),
  fingerprintList: document.getElementById('fingerprintList'),

  copyHookBtn: document.getElementById('copyHookBtn'),
  copyReportBtn: document.getElementById('copyReportBtn'),
  toast: document.getElementById('toast'),

  tabBtns: Array.from(document.querySelectorAll('.tab-btn')),
  panels: {
    headers: document.getElementById('panel-headers'),
    cookies: document.getElementById('panel-cookies'),
    surface: document.getElementById('panel-surface'),
  },
};

// UTILITIES

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function withTimeout(promise, ms) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error('TIMEOUT')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timeoutId));
}

function isRestrictedUrl(url) {
  if (!url) return true;
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('edge://') ||
    url.startsWith('about:') ||
    url.startsWith('devtools://') ||
    url.startsWith('view-source:') ||
    url.startsWith('chrome-search://') ||
    url.startsWith('chrome-error://')
  );
}

function showBanner(message, level) {
  el.statusBanner.textContent = message;
  el.statusBanner.classList.remove('hidden', 'error');
  if (level === 'error') el.statusBanner.classList.add('error');
}

function hideBanner() {
  el.statusBanner.classList.add('hidden');
}

function showToast(message) {
  el.toast.textContent = message;
  el.toast.classList.add('show');
  el.toast.classList.remove('hidden');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => {
    el.toast.classList.remove('show');
  }, 2200);
}

// STEP 1: ACTIVE TAB RESOLUTION

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || !tabs.length) {
    throw new Error('No active tab could be found.');
  }
  return tabs[0];
}

// STEP 2: HEADER RETRIEVAL (cache first, then live fetch fallback)

async function getCachedHeaders(tabId) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: 'AUDITSNAP_GET_HEADERS', tabId },
        (response) => {
          if (chrome.runtime.lastError) {
            resolve({ ok: false, error: chrome.runtime.lastError.message });
            return;
          }
          resolve(response || { ok: false, error: 'Empty response from background worker.' });
        }
      );
    } catch (err) {
      resolve({ ok: false, error: String(err && err.message ? err.message : err) });
    }
  });
}

async function fetchHeadersLive(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      redirect: 'follow',
      signal: controller.signal,
      cache: 'no-store',
    });
    const headers = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    return { ok: true, headers };
  } catch (err) {
    return { ok: false, error: err && err.name === 'AbortError' ? 'Request timed out.' : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

async function resolveHeaders(tab) {
  // 1) Try the background service worker's cache first (most reliable,
  //    captured from the real navigation - no duplicate request).
  const cached = await getCachedHeaders(tab.id);
  if (cached.ok && cached.data && cached.data.headers) {
    state.headers = cached.data.headers;
    state.headersSource = 'cache';
    return;
  }

  // 2) Fallback: perform a live fetch. This may be blocked by CORS for
  //    cross-origin restrictions on some sites, but for the top-level
  //    origin itself a same-origin GET generally succeeds enough to
  //    read basic response headers exposed to the page context.
  try {
    const live = await withTimeout(fetchHeadersLive(tab.url), FETCH_TIMEOUT_MS + 500);
    if (live.ok) {
      state.headers = live.headers;
      state.headersSource = 'live-fetch';
      return;
    }
    state.headers = {};
    state.headersSource = 'unavailable';
  } catch (err) {
    state.headers = {};
    state.headersSource = 'unavailable';
  }
}

// STEP 3: COOKIE INSPECTION

async function inspectCookies(tab) {
  try {
    const cookies = await chrome.cookies.getAll({ url: tab.url });
    let insecure = 0;

    const analyzed = cookies.map((c) => {
      const flags = {
        secure: !!c.secure,
        httpOnly: !!c.httpOnly,
        sameSite: c.sameSite && c.sameSite !== 'unspecified' ? c.sameSite : 'none',
      };
      const isInsecure = !flags.secure || !flags.httpOnly;
      if (isInsecure) insecure += 1;
      return { name: c.name, domain: c.domain, ...flags, isInsecure };
    });

    state.cookies = analyzed;
    state.cookieSummary = { total: analyzed.length, insecure };
  } catch (err) {
    state.cookies = [];
    state.cookieSummary = { total: 0, insecure: 0 };
    console.error('[AuditSnap] Cookie inspection failed:', err);
  }
}

// STEP 4: PASSIVE ATTACK SURFACE (robots.txt / sitemap.xml / fingerprint headers)

async function fetchTextWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      cache: 'no-store',
    });
    if (!res.ok) {
      return { accessible: false, status: res.status };
    }
    const text = await res.text();
    return { accessible: true, status: res.status, text };
  } catch (err) {
    const timedOut = err && err.name === 'AbortError';
    return { accessible: false, error: timedOut ? 'timeout' : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

function parseRobotsForSensitivePaths(text) {
  const found = new Set();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!/^disallow\s*:/i.test(line)) continue;
    const pathPart = line.split(':').slice(1).join(':').trim();
    if (!pathPart) continue;
    const lowerPath = pathPart.toLowerCase();
    for (const keyword of SENSITIVE_PATH_KEYWORDS) {
      if (lowerPath.includes(keyword)) {
        found.add(pathPart);
      }
    }
  }
  return Array.from(found);
}

async function scanAttackSurface(origin) {
  // robots.txt
  try {
    const robotsResult = await fetchTextWithTimeout(`${origin}/robots.txt`);
    if (robotsResult.accessible) {
      state.robots = {
        checked: true,
        accessible: true,
        sensitivePaths: parseRobotsForSensitivePaths(robotsResult.text || ''),
        error: null,
      };
    } else {
      state.robots = {
        checked: true,
        accessible: false,
        sensitivePaths: [],
        error: robotsResult.error || `HTTP ${robotsResult.status}`,
      };
    }
  } catch (err) {
    state.robots = { checked: true, accessible: false, sensitivePaths: [], error: String(err) };
  }

  // sitemap.xml
  try {
    const sitemapResult = await fetchTextWithTimeout(`${origin}/sitemap.xml`);
    state.sitemap = {
      checked: true,
      accessible: !!sitemapResult.accessible,
      error: sitemapResult.accessible ? null : (sitemapResult.error || `HTTP ${sitemapResult.status}`),
    };
  } catch (err) {
    state.sitemap = { checked: true, accessible: false, error: String(err) };
  }

  // Fingerprinting headers pulled from whatever headers we already resolved
  state.fingerprint = FINGERPRINT_HEADERS
    .filter((h) => state.headers[h])
    .map((h) => ({ name: h, value: state.headers[h] }));
}

// STEP 5: SCORING

function computeHeaderResults() {
  state.headerResults = SECURITY_HEADERS.map((def) => {
    const value = state.headers[def.key];
    const present = typeof value === 'string' && value.trim().length > 0;
    return {
      ...def,
      present,
      value: present ? value : null,
    };
  });
}

function computeScore() {
  // Headers: sum weights of present headers (weights already total 80)
  const headerMaxTotal = SECURITY_HEADERS.reduce((sum, h) => sum + h.weight, 0); // 80
  const headerEarned = state.headerResults.reduce((sum, h) => sum + (h.present ? h.weight : 0), 0);

  // Normalize headers portion to 65 points max
  const headersScore = headerMaxTotal > 0 ? (headerEarned / headerMaxTotal) * 65 : 0;

  // Cookies: start at 20, subtract penalty per insecure cookie (capped)
  const cookiePenalty = Math.min(
    state.cookieSummary.insecure * COOKIE_PENALTY_PER_INSECURE,
    COOKIE_PENALTY_CAP
  );
  const cookiesScore = Math.max(0, 20 - cookiePenalty);

  // Surface: start at 15, subtract for each disclosed sensitive path
  // and for each fingerprinting header exposed.
  const surfacePenalty = Math.min(
    state.robots.sensitivePaths.length * 2 + state.fingerprint.length * 2,
    SURFACE_PENALTY_CAP
  );
  const surfaceScore = Math.max(0, 15 - surfacePenalty);

  const total = Math.round(headersScore + cookiesScore + surfaceScore);
  state.score = Math.min(100, Math.max(0, total));
  return state.score;
}

function scoreLabelFor(score) {
  if (score >= 85) return { text: 'Strong Posture', color: 'var(--accent-emerald)' };
  if (score >= 60) return { text: 'Moderate Risk', color: 'var(--accent-amber)' };
  return { text: 'High Risk', color: 'var(--accent-crimson)' };
}

// RENDERING

function renderTargetRow() {
  try {
    const u = new URL(state.tab.url);
    el.targetDomain.textContent = u.hostname + (u.pathname !== '/' ? u.pathname : '');
  } catch (e) {
    el.targetDomain.textContent = state.tab.url || 'Unknown target';
  }
}

function renderScore() {
  const score = state.score;
  const { text, color } = scoreLabelFor(score);

  el.scoreValue.textContent = String(score);
  el.scoreLabel.textContent = text;
  el.scoreLabel.style.color = color;

  const circumference = 264; // 2 * PI * r(42) ≈ 263.9
  const offset = circumference - (score / 100) * circumference;
  el.scoreRingFg.style.strokeDashoffset = String(offset);
  el.scoreRingFg.style.stroke = color;

  el.targetDot.className = 'dot ' + (score >= 85 ? 'ok' : score >= 60 ? 'warn' : 'error');
}

function renderHeaders() {
  el.headersList.innerHTML = '';

  if (state.headersSource === 'unavailable') {
    const li = document.createElement('li');
    li.className = 'check-item warn';
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">Headers Unavailable</span>
        <span class="badge warn">Unknown</span>
      </div>
      <div class="check-desc">Could not retrieve response headers for this page (network restriction, CORS, or the page has not fully loaded yet). Try the re-scan button.</div>
    `;
    el.headersList.appendChild(li);
    return;
  }

  for (const h of state.headerResults) {
    const li = document.createElement('li');
    li.className = 'check-item ' + (h.present ? 'pass' : 'fail');
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">${escapeHtml(h.label)}</span>
        <span class="badge ${h.present ? 'pass' : 'fail'}">${h.present ? 'Pass' : 'Fail'}</span>
      </div>
      <div class="check-desc">${escapeHtml(h.risk)}</div>
      ${h.present ? `<div class="check-value">${escapeHtml(h.value).slice(0, 140)}</div>` : ''}
    `;
    el.headersList.appendChild(li);
  }
}

function renderCookies() {
  el.cookieTotal.textContent = String(state.cookieSummary.total);
  el.cookieInsecure.textContent = String(state.cookieSummary.insecure);
  el.cookiesList.innerHTML = '';

  if (!state.cookies.length) {
    const li = document.createElement('li');
    li.className = 'check-item';
    li.innerHTML = `<div class="check-desc">No cookies were found for this origin.</div>`;
    el.cookiesList.appendChild(li);
    return;
  }

  // Show insecure cookies first, capped to a reasonable number for popup UI.
  const sorted = [...state.cookies].sort((a, b) => Number(b.isInsecure) - Number(a.isInsecure));
  const MAX_SHOWN = 12;

  sorted.slice(0, MAX_SHOWN).forEach((c) => {
    const li = document.createElement('li');
    li.className = 'check-item ' + (c.isInsecure ? 'fail' : 'pass');
    const flagsText = `Secure: ${c.secure ? 'Yes' : 'No'} · HttpOnly: ${c.httpOnly ? 'Yes' : 'No'} · SameSite: ${c.sameSite}`;
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">${escapeHtml(c.name)}</span>
        <span class="badge ${c.isInsecure ? 'fail' : 'pass'}">${c.isInsecure ? 'Risk' : 'OK'}</span>
      </div>
      <div class="check-value">${escapeHtml(flagsText)}</div>
    `;
    el.cookiesList.appendChild(li);
  });

  if (sorted.length > MAX_SHOWN) {
    const li = document.createElement('li');
    li.className = 'check-item';
    li.innerHTML = `<div class="check-desc">+ ${sorted.length - MAX_SHOWN} more cookie(s) not shown.</div>`;
    el.cookiesList.appendChild(li);
  }
}

function renderSurface() {
  // robots.txt
  if (!state.robots.checked) {
    el.robotsStatus.textContent = 'Checking…';
  } else if (!state.robots.accessible) {
    el.robotsStatus.textContent = `Not accessible (${state.robots.error || 'no robots.txt found'}).`;
  } else if (state.robots.sensitivePaths.length === 0) {
    el.robotsStatus.textContent = 'Accessible — no high-interest disallowed paths detected.';
  } else {
    el.robotsStatus.textContent = `Accessible — ${state.robots.sensitivePaths.length} high-interest path(s) disclosed:`;
  }

  el.robotsList.innerHTML = '';
  state.robots.sensitivePaths.forEach((p) => {
    const li = document.createElement('li');
    li.className = 'chip';
    li.textContent = p;
    el.robotsList.appendChild(li);
  });

  // sitemap.xml
  if (!state.sitemap.checked) {
    el.sitemapStatus.textContent = 'Checking…';
  } else if (state.sitemap.accessible) {
    el.sitemapStatus.textContent = 'sitemap.xml is publicly accessible.';
  } else {
    el.sitemapStatus.textContent = `sitemap.xml not found or inaccessible (${state.sitemap.error || 'n/a'}).`;
  }

  // fingerprinting
  el.fingerprintList.innerHTML = '';
  if (!state.fingerprint.length) {
    const li = document.createElement('li');
    li.className = 'check-item pass';
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">No fingerprinting headers exposed</span>
        <span class="badge pass">Pass</span>
      </div>
    `;
    el.fingerprintList.appendChild(li);
  } else {
    state.fingerprint.forEach((f) => {
      const li = document.createElement('li');
      li.className = 'check-item warn';
      li.innerHTML = `
        <div class="check-item-top">
          <span class="check-name">${escapeHtml(f.name)}</span>
          <span class="badge warn">Exposed</span>
        </div>
        <div class="check-value">${escapeHtml(f.value).slice(0, 140)}</div>
      `;
      el.fingerprintList.appendChild(li);
    });
  }
}

function renderAll() {
  renderTargetRow();
  renderScore();
  renderHeaders();
  renderCookies();
  renderSurface();
}

// TABS

function setupTabs() {
  el.tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      el.tabBtns.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      Object.values(el.panels).forEach((p) => p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const target = btn.getAttribute('data-tab');
      if (el.panels[target]) el.panels[target].classList.add('active');
    });
  });
}

// EXPORT GENERATORS

function getFailedHeaderLabels() {
  return state.headerResults.filter((h) => !h.present).map((h) => h.label);
}

function buildProposalHook() {
  const domain = (() => {
    try { return new URL(state.tab.url).hostname; } catch (e) { return state.tab.url; }
  })();

  const failed = getFailedHeaderLabels();
  const issues = [];

  if (failed.length) {
    issues.push(`${failed.length} missing HTTP security header(s) (${failed.join(', ')})`);
  }
  if (state.cookieSummary.insecure > 0) {
    issues.push(`${state.cookieSummary.insecure} cookie(s) without proper Secure/HttpOnly flags`);
  }
  if (state.robots.sensitivePaths.length > 0) {
    issues.push(`${state.robots.sensitivePaths.length} sensitive endpoint(s) disclosed via robots.txt`);
  }
  if (state.fingerprint.length > 0) {
    issues.push(`server fingerprinting headers exposing backend technology`);
  }

  const issuesText = issues.length
    ? issues.map((i) => `- ${i}`).join('\n')
    : '- no major passive issues detected in this quick pass';

  return [
    `Hi there,`,
    ``,
    `I ran a quick passive security scan on ${domain} and wanted to flag a few things before they turn into a bigger problem:`,
    ``,
    issuesText,
    ``,
    `Current estimated Security Posture Score: ${state.score}/100.`,
    ``,
    `These are the kind of low-effort, high-impact gaps that attackers scan for automatically. I'd be glad to put together a full audit and a prioritized remediation plan — happy to share more detail if you're interested.`,
    ``,
    `Best,`,
  ].join('\n');
}

function buildMarkdownReport() {
  const domain = (() => {
    try { return new URL(state.tab.url).hostname; } catch (e) { return state.tab.url; }
  })();
  const date = new Date().toISOString().slice(0, 10);

  const lines = [];
  lines.push(`# Security Audit Report — ${domain}`);
  lines.push(``);
  lines.push(`**Date:** ${date}  `);
  lines.push(`**Tool:** AuditSnap (Passive Scan)  `);
  lines.push(`**Security Posture Score:** ${state.score} / 100`);
  lines.push(``);
  lines.push(`> This is a *passive* assessment based on publicly observable HTTP responses, cookies, and disclosure files. It is not a substitute for a full penetration test.`);
  lines.push(``);

  lines.push(`## 1. HTTP Security Headers`);
  lines.push(``);
  lines.push(`| Header | Status | Business Risk |`);
  lines.push(`|---|---|---|`);
  state.headerResults.forEach((h) => {
    lines.push(`| ${h.label} | ${h.present ? '✅ Present' : '❌ Missing'} | ${h.risk} |`);
  });
  lines.push(``);

  lines.push(`## 2. Cookie Security & Hygiene`);
  lines.push(``);
  lines.push(`- **Total cookies observed:** ${state.cookieSummary.total}`);
  lines.push(`- **Insecure cookies (missing Secure and/or HttpOnly):** ${state.cookieSummary.insecure}`);
  lines.push(``);
  if (state.cookies.length) {
    lines.push(`| Cookie | Secure | HttpOnly | SameSite |`);
    lines.push(`|---|---|---|---|`);
    state.cookies.forEach((c) => {
      lines.push(`| ${c.name} | ${c.secure ? 'Yes' : 'No'} | ${c.httpOnly ? 'Yes' : 'No'} | ${c.sameSite} |`);
    });
    lines.push(``);
  }

  lines.push(`## 3. Passive Attack Surface & Information Disclosure`);
  lines.push(``);
  lines.push(`**robots.txt:** ${state.robots.accessible ? 'Accessible' : 'Not accessible / not found'}`);
  if (state.robots.sensitivePaths.length) {
    lines.push(``);
    lines.push(`High-interest disallowed paths discovered:`);
    state.robots.sensitivePaths.forEach((p) => lines.push(`- \`${p}\``));
  }
  lines.push(``);
  lines.push(`**sitemap.xml:** ${state.sitemap.accessible ? 'Publicly accessible' : 'Not accessible / not found'}`);
  lines.push(``);
  if (state.fingerprint.length) {
    lines.push(`**Server fingerprinting headers exposed:**`);
    state.fingerprint.forEach((f) => lines.push(`- \`${f.name}: ${f.value}\``));
  } else {
    lines.push(`**Server fingerprinting headers exposed:** None detected.`);
  }
  lines.push(``);

  lines.push(`## Summary`);
  lines.push(``);
  lines.push(`This passive scan surfaced ${getFailedHeaderLabels().length} missing security header(s), ${state.cookieSummary.insecure} insecure cookie(s), and ${state.robots.sensitivePaths.length} disclosed sensitive path(s), resulting in an overall Security Posture Score of **${state.score}/100**.`);
  lines.push(``);
  lines.push(`_Generated with AuditSnap._`);

  return lines.join('\n');
}

// CLIPBOARD

async function copyToClipboard(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMessage);
  } catch (err) {
    // Fallback for environments where the async clipboard API is blocked.
    try {
      const textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.focus();
      textarea.select();
      const ok = document.execCommand('copy');
      document.body.removeChild(textarea);
      if (ok) {
        showToast(successMessage);
      } else {
        showToast('Copy failed — please copy manually.');
      }
    } catch (fallbackErr) {
      console.error('[AuditSnap] Clipboard copy failed:', fallbackErr);
      showToast('Copy failed — clipboard permission blocked.');
    }
  }
}

// MAIN ORCHESTRATION

function setLoading(isLoading) {
  el.loadingState.classList.toggle('hidden', !isLoading);
  el.mainContent.classList.toggle('hidden', isLoading);
}

function setActionButtonsEnabled(enabled) {
  el.copyHookBtn.disabled = !enabled;
  el.copyReportBtn.disabled = !enabled;
}

async function runAudit() {
  hideBanner();
  setLoading(true);
  setActionButtonsEnabled(false);
  el.rescanBtn.classList.add('spinning');

  try {
    const tab = await getActiveTab();
    state.tab = tab;

    if (isRestrictedUrl(tab.url)) {
      state.isRestrictedPage = true;
      el.targetDomain.textContent = tab.url || 'Restricted page';
      el.targetDot.className = 'dot error';
      showBanner(
        'This is a browser-internal page (chrome://, extension, or similar). AuditSnap can only scan regular http(s) websites. Navigate to a live site and re-scan.',
        'error'
      );
      setLoading(false);
      el.rescanBtn.classList.remove('spinning');
      return;
    }

    let originUrl;
    try {
      originUrl = new URL(tab.url).origin;
    } catch (e) {
      throw new Error('Could not parse the active tab URL.');
    }
    state.origin = originUrl;

    // Run the three passive checks. Each has its own internal error
    // handling so one failing module never blocks the others.
    await resolveHeaders(tab);
    computeHeaderResults();

    await inspectCookies(tab);

    await scanAttackSurface(originUrl);

    computeScore();
    renderAll();

    if (state.headersSource === 'unavailable') {
      showBanner(
        'Could not retrieve HTTP response headers (possible network restriction or CORS policy). Header checks are marked as unavailable and excluded from scoring accuracy.',
        'warn'
      );
    }

    setActionButtonsEnabled(true);
  } catch (err) {
    console.error('[AuditSnap] Audit failed:', err);
    showBanner(`Scan failed: ${err && err.message ? err.message : String(err)}`, 'error');
  } finally {
    setLoading(false);
    el.rescanBtn.classList.remove('spinning');
  }
}

// EVENT WIRING

function wireEvents() {
  el.rescanBtn.addEventListener('click', () => {
    runAudit();
  });

  el.copyHookBtn.addEventListener('click', () => {
    if (state.isRestrictedPage) return;
    const hook = buildProposalHook();
    copyToClipboard(hook, 'Proposal hook copied to clipboard');
  });

  el.copyReportBtn.addEventListener('click', () => {
    if (state.isRestrictedPage) return;
    const report = buildMarkdownReport();
    copyToClipboard(report, 'Markdown report copied to clipboard');
  });
}

// INIT

document.addEventListener('DOMContentLoaded', () => {
  setupTabs();
  wireEvents();
  runAudit();
});
