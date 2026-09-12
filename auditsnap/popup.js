/**
 * AuditSnap - popup.js
 * ------------------------------------------------------------
 * Orchestrates the full passive audit when the popup opens:
 *   1. Resolve active tab + guard against restricted URLs.
 *   2. Fetch HTTP security headers (cached from background.js,
 *      falling back to a live fetch if nothing is cached yet).
 *   3. Inspect cookies via chrome.cookies.getAll.
 *   4. Probe robots.txt / sitemap.xml / fingerprinting headers.
 *   5. Probe sensitive file exposure (.env, .git/config, etc).
 *   6. Probe security.txt (RFC 9116 - responsible disclosure).
 *   7. Fingerprint technology stack from headers + cookies.
 *   8. Inspect page runtime: third-party scripts, negotiated HTTP
 *      protocol (h2/h3), and mixed-content resources.
 *   9. Check HTTPS enforcement (does the plain-http origin
 *      redirect to https?).
 *  10. Check email security posture (SPF / DMARC DNS records)
 *      via a public DNS-over-HTTPS resolver.
 *  11. Compute a 0-100 Security Posture Score.
 *  12. Render the UI (score ring, tabs/panels) - every render
 *      step is null-safe so a mismatched/stale popup.html can
 *      never crash the whole scan, just log a console warning.
 *  13. Wire up "Copy Proposal Hook" and "Copy Markdown Report".
 * ------------------------------------------------------------
 */

'use strict';

// ============================================================
// CONSTANTS
// ============================================================

const FETCH_TIMEOUT_MS = 4000;
const DOH_ENDPOINT = 'https://cloudflare-dns.com/dns-query';

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

// High-value, low-noise sensitive file candidates. Kept short on purpose:
// each additional path is another network round trip from the popup.
const SENSITIVE_FILE_PATHS = [
  '/.env',
  '/.git/config',
  '/.git/HEAD',
  '/wp-config.php.bak',
  '/config.php.bak',
  '/.DS_Store',
  '/backup.zip',
  '/database.sql',
];

// Passive technology fingerprint signatures. Each `test` runs against
// already-collected headers/cookies - no extra network calls needed.
const TECH_SIGNATURES = [
  { label: 'Shopify', test: (h, c) => /shopify/i.test(h.server || '') || c.some((ck) => /^_shopify|^shopify_/i.test(ck.name)) },
  { label: 'WordPress', test: (h, c) => c.some((ck) => /^wordpress_|wp-settings/i.test(ck.name)) || /wordpress/i.test(h['x-generator'] || '') },
  { label: 'PHP', test: (h, c) => c.some((ck) => /^PHPSESSID$/i.test(ck.name)) || /php/i.test(h['x-powered-by'] || '') },
  { label: 'Java (JSESSIONID)', test: (h, c) => c.some((ck) => /^JSESSIONID$/i.test(ck.name)) },
  { label: 'Laravel', test: (h, c) => c.some((ck) => /laravel_session/i.test(ck.name)) },
  { label: 'CodeIgniter', test: (h, c) => c.some((ck) => /^ci_session/i.test(ck.name)) },
  { label: 'ASP.NET', test: (h, c) => c.some((ck) => /^ASP\.NET_SessionId$/i.test(ck.name)) || /asp\.net/i.test(h['x-powered-by'] || '') || !!h['x-aspnet-version'] },
  { label: 'Cloudflare', test: (h, c) => c.some((ck) => /^__cfduid$|^cf_clearance$/i.test(ck.name)) || /cloudflare/i.test(h.server || '') },
  { label: 'Microsoft Azure', test: (h, c) => c.some((ck) => /^ARRAffinity/i.test(ck.name)) },
  { label: 'AWS Application Load Balancer', test: (h, c) => c.some((ck) => /^AWSALB/i.test(ck.name)) },
  { label: 'Vercel', test: (h) => /vercel/i.test(h.server || '') || !!h['x-vercel-id'] },
  { label: 'Netlify', test: (h) => /netlify/i.test(h.server || '') },
  { label: 'GitHub Pages', test: (h) => /github\.com/i.test(h.server || '') },
  { label: 'Nginx', test: (h) => /nginx/i.test(h.server || '') },
  { label: 'Apache', test: (h) => /apache/i.test(h.server || '') },
  { label: 'Express.js', test: (h) => /express/i.test(h['x-powered-by'] || '') },
];

// Known third-party script hosts, mapped to a human-friendly label.
// Anything not in this map is still listed, just without a category.
const KNOWN_SCRIPT_DOMAINS = {
  'google-analytics.com': 'Google Analytics',
  'www.google-analytics.com': 'Google Analytics',
  'googletagmanager.com': 'Google Tag Manager',
  'www.googletagmanager.com': 'Google Tag Manager',
  'doubleclick.net': 'Google Ads (DoubleClick)',
  'connect.facebook.net': 'Meta Pixel',
  'facebook.net': 'Meta Pixel',
  'hotjar.com': 'Hotjar',
  'static.hotjar.com': 'Hotjar',
  'segment.com': 'Segment',
  'cdn.segment.com': 'Segment',
  'intercom.io': 'Intercom',
  'widget.intercom.io': 'Intercom',
  'sentry.io': 'Sentry (Error Tracking)',
  'js.stripe.com': 'Stripe',
  'cloudflareinsights.com': 'Cloudflare Analytics',
  'clarity.ms': 'Microsoft Clarity',
  'analytics.tiktok.com': 'TikTok Pixel',
  'cdn.jsdelivr.net': 'jsDelivr CDN',
  'cdnjs.cloudflare.com': 'cdnjs CDN',
  'ajax.googleapis.com': 'Google Hosted Libraries',
};

// Score weight buckets. Headers 55% / Cookies 20% / Surface 25%.
// "Surface" now absorbs network-level passive findings too (HTTPS
// enforcement, mixed content) alongside disclosure findings, since
// they're all observable without any active exploitation.
const HEADER_MAX_POINTS = 55;
const COOKIE_MAX_POINTS = 20;
const SURFACE_MAX_POINTS = 25;
const COOKIE_PENALTY_PER_INSECURE = 4;
const COOKIE_PENALTY_CAP = COOKIE_MAX_POINTS;
const SURFACE_PENALTY_CAP = SURFACE_MAX_POINTS;
const SENSITIVE_FILE_PENALTY_EACH = 6; // exposed source/config files are severe
const HTTPS_NOT_ENFORCED_PENALTY = 8;
const MIXED_CONTENT_PENALTY = 6;

// ============================================================
// STATE
// ============================================================

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
  sensitiveFiles: { checked: false, exposed: [], error: null },
  securityTxt: { checked: false, accessible: false, path: null, contact: null },
  techStack: [],
  thirdPartyScripts: { checked: false, list: [], error: null },
  httpsEnforcement: { checked: false, enforced: null, finalUrl: null, error: null },
  protocolInfo: { checked: false, protocol: null },
  mixedContent: { checked: false, resources: [] },
  emailSecurity: { checked: false, domain: null, spf: null, dmarc: null, error: null },
  score: 0,
  headerResults: [],
  isRestrictedPage: false,
};

// ============================================================
// DOM REFERENCES
// ============================================================

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
  sensitiveFilesStatus: document.getElementById('sensitiveFilesStatus'),
  sensitiveFilesList: document.getElementById('sensitiveFilesList'),
  securityTxtStatus: document.getElementById('securityTxtStatus'),

  techStatus: document.getElementById('techStatus'),
  techList: document.getElementById('techList'),
  thirdPartyStatus: document.getElementById('thirdPartyStatus'),
  thirdPartyList: document.getElementById('thirdPartyList'),

  httpsEnforcementStatus: document.getElementById('httpsEnforcementStatus'),
  protocolStatus: document.getElementById('protocolStatus'),
  mixedContentStatus: document.getElementById('mixedContentStatus'),
  mixedContentList: document.getElementById('mixedContentList'),
  emailSecurityStatus: document.getElementById('emailSecurityStatus'),
  emailSecurityList: document.getElementById('emailSecurityList'),

  copyHookBtn: document.getElementById('copyHookBtn'),
  copyReportBtn: document.getElementById('copyReportBtn'),
  toast: document.getElementById('toast'),

  tabBtns: Array.from(document.querySelectorAll('.tab-btn')),
  panels: {
    headers: document.getElementById('panel-headers'),
    cookies: document.getElementById('panel-cookies'),
    surface: document.getElementById('panel-surface'),
    tech: document.getElementById('panel-tech'),
    network: document.getElementById('panel-network'),
  },
};

// ============================================================
// UTILITIES
// ============================================================

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

// Null-safe DOM setters. If popup.html and popup.js ever get out of sync
// (e.g. only one file gets updated during a manual install), these guard
// against "Cannot set properties of null" crashing the entire render pass -
// a single missing element degrades gracefully instead of aborting the scan.
function setText(elem, text) {
  if (elem) elem.textContent = text;
  else console.warn('[AuditSnap] Expected DOM element not found - popup.html may be out of sync with popup.js.');
}

function clearEl(elem) {
  if (elem) elem.innerHTML = '';
}

function appendChildSafe(parent, child) {
  if (parent) parent.appendChild(child);
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

// ============================================================
// STEP 1: ACTIVE TAB RESOLUTION
// ============================================================

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs || !tabs.length) {
    throw new Error('No active tab could be found.');
  }
  return tabs[0];
}

// ============================================================
// STEP 2: HEADER RETRIEVAL (cache first, then live fetch fallback)
// ============================================================

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

// ============================================================
// STEP 3: COOKIE INSPECTION
// ============================================================

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

// ============================================================
// STEP 4: PASSIVE ATTACK SURFACE (robots.txt / sitemap.xml / fingerprint headers)
// ============================================================

async function fetchTextWithTimeout(url, options) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, Object.assign({
      method: 'GET',
      redirect: 'follow',
      credentials: 'omit',
      signal: controller.signal,
      cache: 'no-store',
    }, options || {}));
    if (!res.ok) {
      return { accessible: false, status: res.status, finalUrl: res.url };
    }
    const text = await res.text();
    return { accessible: true, status: res.status, text, finalUrl: res.url };
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

// ============================================================
// STEP 5: SENSITIVE FILE EXPOSURE
// ============================================================

async function checkPathExposed(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      credentials: 'omit',
      cache: 'no-store',
      signal: controller.signal,
    });
    const contentType = (res.headers.get('content-type') || '').toLowerCase();
    // Heuristic to cut false positives: SPA/CMS catch-all routes usually
    // return a 200 HTML page for *any* path. A real exposed .env/.git
    // file is essentially never served with a text/html content-type.
    const looksLikeHtmlFallback = contentType.includes('text/html');
    const exposed = res.status === 200 && !looksLikeHtmlFallback;
    return { exposed, status: res.status, contentType };
  } catch (err) {
    return { exposed: false, status: null, error: err && err.name === 'AbortError' ? 'timeout' : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

async function scanSensitiveFiles(origin) {
  try {
    const results = await Promise.allSettled(
      SENSITIVE_FILE_PATHS.map((p) => checkPathExposed(`${origin}${p}`))
    );
    const exposed = [];
    results.forEach((r, idx) => {
      if (r.status === 'fulfilled' && r.value && r.value.exposed) {
        exposed.push({ path: SENSITIVE_FILE_PATHS[idx], status: r.value.status });
      }
    });
    state.sensitiveFiles = { checked: true, exposed, error: null };
  } catch (err) {
    state.sensitiveFiles = { checked: true, exposed: [], error: String(err) };
  }
}

// ============================================================
// STEP 6: security.txt (RFC 9116 - responsible disclosure contact)
// ============================================================

async function scanSecurityTxt(origin) {
  try {
    let result = await fetchTextWithTimeout(`${origin}/.well-known/security.txt`);
    let path = '/.well-known/security.txt';

    if (!result.accessible) {
      const legacy = await fetchTextWithTimeout(`${origin}/security.txt`);
      if (legacy.accessible) {
        result = legacy;
        path = '/security.txt';
      }
    }

    if (result.accessible) {
      const match = (result.text || '').match(/^Contact:\s*(.+)$/im);
      state.securityTxt = {
        checked: true,
        accessible: true,
        path,
        contact: match ? match[1].trim() : null,
      };
    } else {
      state.securityTxt = { checked: true, accessible: false, path: null, contact: null };
    }
  } catch (err) {
    state.securityTxt = { checked: true, accessible: false, path: null, contact: null, error: String(err) };
  }
}

// ============================================================
// STEP 7: TECHNOLOGY FINGERPRINT (no extra network calls)
// ============================================================

function detectTechnologies(headers, cookies) {
  const found = [];
  for (const sig of TECH_SIGNATURES) {
    try {
      if (sig.test(headers || {}, cookies || [])) found.push(sig.label);
    } catch (e) {
      // A single bad signature test should never break fingerprinting.
    }
  }
  return Array.from(new Set(found));
}

// ============================================================
// STEP 8: PAGE RUNTIME INSPECTION (content-script injection)
// Covers: third-party scripts, negotiated HTTP protocol, mixed content.
// Bundled into a single injection to avoid multiple executeScript calls.
// ============================================================

function labelForScriptDomain(domain) {
  if (KNOWN_SCRIPT_DOMAINS[domain]) return KNOWN_SCRIPT_DOMAINS[domain];
  const match = Object.keys(KNOWN_SCRIPT_DOMAINS).find((key) => domain.endsWith(key));
  return match ? KNOWN_SCRIPT_DOMAINS[match] : null;
}

async function scanPageRuntime(tab) {
  try {
    const injectionResults = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        try {
          const pageHost = location.hostname;

          // --- third-party scripts ---
          const scripts = Array.from(document.scripts || []);
          const hostCounts = {};
          scripts.forEach((s) => {
            if (!s.src) return;
            try {
              const u = new URL(s.src, location.href);
              if (u.hostname && u.hostname !== pageHost) {
                hostCounts[u.hostname] = (hostCounts[u.hostname] || 0) + 1;
              }
            } catch (e) {
              // Ignore unparsable script src values.
            }
          });
          const thirdPartyScripts = Object.entries(hostCounts).map(([domain, count]) => ({ domain, count }));

          // --- negotiated HTTP protocol (h2 / h3 / http/1.1) ---
          let protocol = null;
          try {
            const navEntries = performance.getEntriesByType('navigation');
            if (navEntries && navEntries[0]) protocol = navEntries[0].nextHopProtocol || null;
          } catch (e) {
            // Performance API unavailable in this context.
          }

          // --- mixed content: http:// resources loaded on an https:// page ---
          let mixedContent = [];
          try {
            if (location.protocol === 'https:') {
              const resources = performance.getEntriesByType('resource') || [];
              const insecureUrls = new Set();
              resources.forEach((r) => {
                if (r.name && r.name.indexOf('http://') === 0) insecureUrls.add(r.name);
              });
              mixedContent = Array.from(insecureUrls).slice(0, 20);
            }
          } catch (e) {
            // Performance API unavailable in this context.
          }

          return { thirdPartyScripts, protocol, mixedContent };
        } catch (e) {
          return { thirdPartyScripts: [], protocol: null, mixedContent: [] };
        }
      },
    });

    const result = injectionResults && injectionResults[0] ? injectionResults[0].result : null;
    const safeResult = result || { thirdPartyScripts: [], protocol: null, mixedContent: [] };

    state.thirdPartyScripts = { checked: true, list: Array.isArray(safeResult.thirdPartyScripts) ? safeResult.thirdPartyScripts : [], error: null };
    state.protocolInfo = { checked: true, protocol: safeResult.protocol || null };
    state.mixedContent = { checked: true, resources: Array.isArray(safeResult.mixedContent) ? safeResult.mixedContent : [] };
  } catch (err) {
    // Injection can fail on special pages (Web Store, PDF viewer, etc.)
    // even when the URL doesn't match our isRestrictedUrl() guard.
    const errMsg = String(err && err.message ? err.message : err);
    state.thirdPartyScripts = { checked: true, list: [], error: errMsg };
    state.protocolInfo = { checked: true, protocol: null, error: errMsg };
    state.mixedContent = { checked: true, resources: [], error: errMsg };
  }
}

// ============================================================
// STEP 9: HTTPS ENFORCEMENT
// Does the plain-http origin actually redirect to https?
// ============================================================

async function checkHttpsEnforcement(origin) {
  if (!origin.startsWith('https:')) {
    state.httpsEnforcement = { checked: true, enforced: false, finalUrl: null, note: 'The site itself is not served over HTTPS.' };
    return;
  }
  try {
    const httpOrigin = origin.replace(/^https:/, 'http:');
    const result = await fetchTextWithTimeout(httpOrigin, { credentials: 'omit' });
    if (result.finalUrl) {
      state.httpsEnforcement = {
        checked: true,
        enforced: result.finalUrl.startsWith('https://'),
        finalUrl: result.finalUrl,
      };
    } else {
      // Could not resolve a final URL (e.g. plain HTTP port closed/timed out) -
      // inconclusive rather than a hard fail, since many hosts simply don't
      // listen on port 80 at all, which is itself not necessarily insecure.
      state.httpsEnforcement = { checked: true, enforced: null, finalUrl: null, error: result.error || 'Could not reach the plain-HTTP origin.' };
    }
  } catch (err) {
    state.httpsEnforcement = { checked: true, enforced: null, finalUrl: null, error: String(err) };
  }
}

// ============================================================
// STEP 10: EMAIL SECURITY (SPF / DMARC via DNS-over-HTTPS)
// ============================================================

async function fetchDnsTxt(name) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=TXT`;
    const res = await fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
      cache: 'no-store',
    });
    if (!res.ok) return [];
    const data = await res.json();
    const answers = Array.isArray(data.Answer) ? data.Answer : [];
    return answers.map((a) => (a.data || '').replace(/^"|"$/g, ''));
  } catch (err) {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

async function checkEmailSecurity(hostname) {
  try {
    // Approximate the organizational domain by stripping a single leading
    // "www." label. This covers the large majority of real-world sites
    // without needing a full public-suffix-list lookup.
    const rootGuess = hostname.replace(/^www\./i, '');

    const [spfRecords, dmarcRecords] = await Promise.all([
      fetchDnsTxt(rootGuess),
      fetchDnsTxt(`_dmarc.${rootGuess}`),
    ]);

    const spf = spfRecords.find((r) => /v=spf1/i.test(r)) || null;
    const dmarc = dmarcRecords.find((r) => /v=DMARC1/i.test(r)) || null;

    state.emailSecurity = { checked: true, domain: rootGuess, spf, dmarc, error: null };
  } catch (err) {
    state.emailSecurity = { checked: true, domain: hostname, spf: null, dmarc: null, error: String(err) };
  }
}

// ============================================================
// STEP 11: SCORING
// ============================================================

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
  // Headers: sum weights of present headers (weights already total 80),
  // normalized into the HEADER_MAX_POINTS bucket.
  const headerMaxTotal = SECURITY_HEADERS.reduce((sum, h) => sum + h.weight, 0); // 80
  const headerEarned = state.headerResults.reduce((sum, h) => sum + (h.present ? h.weight : 0), 0);
  const headersScore = headerMaxTotal > 0 ? (headerEarned / headerMaxTotal) * HEADER_MAX_POINTS : 0;

  // Cookies: start full, subtract penalty per insecure cookie (capped).
  const cookiePenalty = Math.min(
    state.cookieSummary.insecure * COOKIE_PENALTY_PER_INSECURE,
    COOKIE_PENALTY_CAP
  );
  const cookiesScore = Math.max(0, COOKIE_MAX_POINTS - cookiePenalty);

  // Surface: disclosed sensitive robots.txt paths + fingerprinting headers
  // + exposed sensitive files + HTTPS enforcement + mixed content.
  let surfacePenaltyRaw =
    state.robots.sensitivePaths.length * 2 +
    state.fingerprint.length * 2 +
    state.sensitiveFiles.exposed.length * SENSITIVE_FILE_PENALTY_EACH;

  if (state.httpsEnforcement.checked && state.httpsEnforcement.enforced === false) {
    surfacePenaltyRaw += HTTPS_NOT_ENFORCED_PENALTY;
  }
  if (state.mixedContent.checked && state.mixedContent.resources.length > 0) {
    surfacePenaltyRaw += MIXED_CONTENT_PENALTY;
  }

  const surfacePenalty = Math.min(surfacePenaltyRaw, SURFACE_PENALTY_CAP);
  const surfaceScore = Math.max(0, SURFACE_MAX_POINTS - surfacePenalty);

  const total = Math.round(headersScore + cookiesScore + surfaceScore);
  state.score = Math.min(100, Math.max(0, total));
  return state.score;
}

function scoreLabelFor(score) {
  if (score >= 85) return { text: 'Strong Posture', color: 'var(--accent-emerald)' };
  if (score >= 60) return { text: 'Moderate Risk', color: 'var(--accent-amber)' };
  return { text: 'High Risk', color: 'var(--accent-crimson)' };
}

// ============================================================
// RENDERING (every setter is null-safe - see setText/clearEl/appendChildSafe)
// ============================================================

function renderTargetRow() {
  let label;
  try {
    const u = new URL(state.tab.url);
    label = u.hostname + (u.pathname !== '/' ? u.pathname : '');
  } catch (e) {
    label = state.tab.url || 'Unknown target';
  }
  setText(el.targetDomain, label);
}

function renderScore() {
  const score = state.score;
  const { text, color } = scoreLabelFor(score);

  setText(el.scoreValue, String(score));
  setText(el.scoreLabel, text);
  if (el.scoreLabel) el.scoreLabel.style.color = color;

  const circumference = 264; // 2 * PI * r(42) ≈ 263.9
  const offset = circumference - (score / 100) * circumference;
  if (el.scoreRingFg) {
    el.scoreRingFg.style.strokeDashoffset = String(offset);
    el.scoreRingFg.style.stroke = color;
  }

  if (el.targetDot) {
    el.targetDot.className = 'dot ' + (score >= 85 ? 'ok' : score >= 60 ? 'warn' : 'error');
  }
}

function renderHeaders() {
  clearEl(el.headersList);

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
    appendChildSafe(el.headersList, li);
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
    appendChildSafe(el.headersList, li);
  }
}

function renderCookies() {
  setText(el.cookieTotal, String(state.cookieSummary.total));
  setText(el.cookieInsecure, String(state.cookieSummary.insecure));
  clearEl(el.cookiesList);

  if (!state.cookies.length) {
    const li = document.createElement('li');
    li.className = 'check-item';
    li.innerHTML = `<div class="check-desc">No cookies were found for this origin.</div>`;
    appendChildSafe(el.cookiesList, li);
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
    appendChildSafe(el.cookiesList, li);
  });

  if (sorted.length > MAX_SHOWN) {
    const li = document.createElement('li');
    li.className = 'check-item';
    li.innerHTML = `<div class="check-desc">+ ${sorted.length - MAX_SHOWN} more cookie(s) not shown.</div>`;
    appendChildSafe(el.cookiesList, li);
  }
}

function renderSurface() {
  // robots.txt
  if (!state.robots.checked) {
    setText(el.robotsStatus, 'Checking…');
  } else if (!state.robots.accessible) {
    setText(el.robotsStatus, `Not accessible (${state.robots.error || 'no robots.txt found'}).`);
  } else if (state.robots.sensitivePaths.length === 0) {
    setText(el.robotsStatus, 'Accessible — no high-interest disallowed paths detected.');
  } else {
    setText(el.robotsStatus, `Accessible — ${state.robots.sensitivePaths.length} high-interest path(s) disclosed:`);
  }

  clearEl(el.robotsList);
  state.robots.sensitivePaths.forEach((p) => {
    const li = document.createElement('li');
    li.className = 'chip';
    li.textContent = p;
    appendChildSafe(el.robotsList, li);
  });

  // sitemap.xml
  if (!state.sitemap.checked) {
    setText(el.sitemapStatus, 'Checking…');
  } else if (state.sitemap.accessible) {
    setText(el.sitemapStatus, 'sitemap.xml is publicly accessible.');
  } else {
    setText(el.sitemapStatus, `sitemap.xml not found or inaccessible (${state.sitemap.error || 'n/a'}).`);
  }

  // fingerprinting
  clearEl(el.fingerprintList);
  if (!state.fingerprint.length) {
    const li = document.createElement('li');
    li.className = 'check-item pass';
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">No fingerprinting headers exposed</span>
        <span class="badge pass">Pass</span>
      </div>
    `;
    appendChildSafe(el.fingerprintList, li);
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
      appendChildSafe(el.fingerprintList, li);
    });
  }

  // sensitive files
  if (!state.sensitiveFiles.checked) {
    setText(el.sensitiveFilesStatus, 'Checking…');
  } else if (state.sensitiveFiles.exposed.length === 0) {
    setText(el.sensitiveFilesStatus, 'No exposed source/config files detected among common paths.');
  } else {
    setText(el.sensitiveFilesStatus, `⚠ ${state.sensitiveFiles.exposed.length} sensitive file(s) publicly accessible:`);
  }
  clearEl(el.sensitiveFilesList);
  state.sensitiveFiles.exposed.forEach((f) => {
    const li = document.createElement('li');
    li.className = 'chip';
    li.textContent = `${f.path} (HTTP ${f.status})`;
    appendChildSafe(el.sensitiveFilesList, li);
  });

  // security.txt
  if (!state.securityTxt.checked) {
    setText(el.securityTxtStatus, 'Checking…');
  } else if (state.securityTxt.accessible) {
    setText(
      el.securityTxtStatus,
      state.securityTxt.contact
        ? `Present at ${state.securityTxt.path} — contact: ${state.securityTxt.contact}`
        : `Present at ${state.securityTxt.path}, but no Contact: line found.`
    );
  } else {
    setText(el.securityTxtStatus, 'Not found — this organization has no published responsible disclosure contact.');
  }
}

function renderTechStack() {
  // Detected technologies
  clearEl(el.techList);
  if (!state.techStack.length) {
    setText(el.techStatus, 'No recognizable technology signatures found in headers or cookies.');
  } else {
    setText(el.techStatus, `${state.techStack.length} technology signature(s) detected:`);
    state.techStack.forEach((label) => {
      const li = document.createElement('li');
      li.className = 'chip tech';
      li.textContent = label;
      appendChildSafe(el.techList, li);
    });
  }

  // Third-party scripts
  clearEl(el.thirdPartyList);
  if (!state.thirdPartyScripts.checked) {
    setText(el.thirdPartyStatus, 'Scanning page…');
    return;
  }
  if (state.thirdPartyScripts.error) {
    setText(el.thirdPartyStatus, 'Could not inspect scripts on this page (restricted context).');
    return;
  }
  const list = state.thirdPartyScripts.list;
  if (!list.length) {
    setText(el.thirdPartyStatus, 'No external script hosts detected on this page.');
    return;
  }
  setText(el.thirdPartyStatus, `${list.length} external script host(s) loaded on this page:`);
  const sorted = [...list].sort((a, b) => b.count - a.count);
  sorted.forEach((entry) => {
    const label = labelForScriptDomain(entry.domain);
    const li = document.createElement('li');
    li.className = 'check-item ' + (label ? 'warn' : '');
    li.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">${escapeHtml(entry.domain)}</span>
        <span class="badge ${label ? 'warn' : 'pass'}">${label ? escapeHtml(label) : 'Unknown'}</span>
      </div>
      <div class="check-value">${entry.count} script tag(s)</div>
    `;
    appendChildSafe(el.thirdPartyList, li);
  });
}

function renderNetwork() {
  // HTTPS enforcement
  if (!state.httpsEnforcement.checked) {
    setText(el.httpsEnforcementStatus, 'Checking…');
  } else if (state.httpsEnforcement.enforced === true) {
    setText(el.httpsEnforcementStatus, `✅ Plain-HTTP requests are redirected to HTTPS (final URL: ${state.httpsEnforcement.finalUrl}).`);
  } else if (state.httpsEnforcement.enforced === false) {
    setText(el.httpsEnforcementStatus, `❌ ${state.httpsEnforcement.note || 'The plain-HTTP origin does not redirect to HTTPS.'} Users typing "http://" or clicking old links may stay unencrypted.`);
  } else {
    setText(el.httpsEnforcementStatus, `Inconclusive — could not verify (${state.httpsEnforcement.error || 'network restriction'}).`);
  }

  // Protocol
  if (!state.protocolInfo.checked) {
    setText(el.protocolStatus, 'Checking…');
  } else if (state.protocolInfo.protocol) {
    setText(el.protocolStatus, `Negotiated protocol: ${state.protocolInfo.protocol.toUpperCase()}`);
  } else {
    setText(el.protocolStatus, 'Could not determine the negotiated protocol on this page.');
  }

  // Mixed content
  clearEl(el.mixedContentList);
  if (!state.mixedContent.checked) {
    setText(el.mixedContentStatus, 'Checking…');
  } else if (state.mixedContent.resources.length === 0) {
    setText(el.mixedContentStatus, 'No insecure (http://) resources detected on this HTTPS page.');
  } else {
    setText(el.mixedContentStatus, `⚠ ${state.mixedContent.resources.length} insecure resource(s) loaded over plain HTTP:`);
    state.mixedContent.resources.slice(0, 8).forEach((url) => {
      const li = document.createElement('li');
      li.className = 'chip';
      li.textContent = url.length > 60 ? url.slice(0, 57) + '…' : url;
      appendChildSafe(el.mixedContentList, li);
    });
  }

  // Email security (SPF / DMARC)
  clearEl(el.emailSecurityList);
  if (!state.emailSecurity.checked) {
    setText(el.emailSecurityStatus, 'Looking up DNS records…');
  } else {
    setText(el.emailSecurityStatus, `DNS TXT records checked for ${state.emailSecurity.domain}:`);

    const spfLi = document.createElement('li');
    spfLi.className = 'check-item ' + (state.emailSecurity.spf ? 'pass' : 'warn');
    spfLi.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">SPF Record</span>
        <span class="badge ${state.emailSecurity.spf ? 'pass' : 'warn'}">${state.emailSecurity.spf ? 'Found' : 'Missing'}</span>
      </div>
      ${state.emailSecurity.spf ? `<div class="check-value">${escapeHtml(state.emailSecurity.spf).slice(0, 140)}</div>` : `<div class="check-desc">No SPF record means anyone can send email that appears to come from this domain, aiding phishing.</div>`}
    `;
    appendChildSafe(el.emailSecurityList, spfLi);

    const dmarcLi = document.createElement('li');
    dmarcLi.className = 'check-item ' + (state.emailSecurity.dmarc ? 'pass' : 'warn');
    dmarcLi.innerHTML = `
      <div class="check-item-top">
        <span class="check-name">DMARC Record</span>
        <span class="badge ${state.emailSecurity.dmarc ? 'pass' : 'warn'}">${state.emailSecurity.dmarc ? 'Found' : 'Missing'}</span>
      </div>
      ${state.emailSecurity.dmarc ? `<div class="check-value">${escapeHtml(state.emailSecurity.dmarc).slice(0, 140)}</div>` : `<div class="check-desc">No DMARC policy means spoofed emails from this domain aren't flagged or rejected by receiving mail servers.</div>`}
    `;
    appendChildSafe(el.emailSecurityList, dmarcLi);
  }
}

function renderAll() {
  // Each section renders independently - a DOM mismatch or unexpected
  // state shape in one panel must never prevent the others from showing
  // the data that scanned successfully.
  const sections = [
    ['target row', renderTargetRow],
    ['score', renderScore],
    ['headers', renderHeaders],
    ['cookies', renderCookies],
    ['surface', renderSurface],
    ['tech stack', renderTechStack],
    ['network', renderNetwork],
  ];
  sections.forEach(([name, fn]) => {
    try {
      fn();
    } catch (err) {
      console.error(`[AuditSnap] Render section "${name}" failed:`, err);
    }
  });
}

// ============================================================
// TABS
// ============================================================

function setupTabs() {
  el.tabBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      el.tabBtns.forEach((b) => {
        b.classList.remove('active');
        b.setAttribute('aria-selected', 'false');
      });
      Object.values(el.panels).forEach((p) => p && p.classList.remove('active'));

      btn.classList.add('active');
      btn.setAttribute('aria-selected', 'true');
      const target = btn.getAttribute('data-tab');
      if (el.panels[target]) el.panels[target].classList.add('active');
    });
  });
}

// ============================================================
// EXPORT GENERATORS
// ============================================================

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
  if (state.sensitiveFiles.exposed.length > 0) {
    issues.push(`${state.sensitiveFiles.exposed.length} sensitive source/config file(s) publicly accessible (${state.sensitiveFiles.exposed.map((f) => f.path).join(', ')})`);
  }
  if (state.fingerprint.length > 0) {
    issues.push(`server fingerprinting headers exposing backend technology`);
  }
  if (state.httpsEnforcement.checked && state.httpsEnforcement.enforced === false) {
    issues.push(`plain-HTTP requests are not redirected to HTTPS`);
  }
  if (state.mixedContent.checked && state.mixedContent.resources.length > 0) {
    issues.push(`${state.mixedContent.resources.length} resource(s) loaded over insecure HTTP on an HTTPS page (mixed content)`);
  }
  if (state.emailSecurity.checked && !state.emailSecurity.spf) {
    issues.push(`no SPF record — the domain is more vulnerable to email spoofing/phishing`);
  }
  if (state.emailSecurity.checked && !state.emailSecurity.dmarc) {
    issues.push(`no DMARC policy — spoofed emails from this domain won't be flagged or rejected`);
  }
  if (!state.securityTxt.accessible) {
    issues.push(`no published security.txt / responsible disclosure contact`);
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
  lines.push(`> This is a *passive* assessment based on publicly observable HTTP responses, cookies, DNS records, and disclosure files. It is not a substitute for a full penetration test.`);
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
  lines.push(`**Sensitive file exposure:** ${state.sensitiveFiles.exposed.length ? `⚠ ${state.sensitiveFiles.exposed.length} file(s) publicly accessible` : 'None detected among common paths checked'}`);
  if (state.sensitiveFiles.exposed.length) {
    state.sensitiveFiles.exposed.forEach((f) => lines.push(`- \`${f.path}\` (HTTP ${f.status})`));
  }
  lines.push(``);
  lines.push(`**security.txt (RFC 9116):** ${state.securityTxt.accessible ? `Present at \`${state.securityTxt.path}\`${state.securityTxt.contact ? ` — Contact: ${state.securityTxt.contact}` : ''}` : 'Not published'}`);
  lines.push(``);

  lines.push(`## 4. Technology Fingerprint`);
  lines.push(``);
  if (state.techStack.length) {
    state.techStack.forEach((t) => lines.push(`- ${t}`));
  } else {
    lines.push(`No recognizable technology signatures found in headers or cookies.`);
  }
  lines.push(``);

  lines.push(`## 5. Third-Party Script Inventory`);
  lines.push(``);
  if (state.thirdPartyScripts.list && state.thirdPartyScripts.list.length) {
    lines.push(`| Domain | Script Tags | Category |`);
    lines.push(`|---|---|---|`);
    state.thirdPartyScripts.list.forEach((entry) => {
      const label = labelForScriptDomain(entry.domain) || 'Unknown';
      lines.push(`| ${entry.domain} | ${entry.count} | ${label} |`);
    });
  } else {
    lines.push(`No external script hosts detected on this page.`);
  }
  lines.push(``);

  lines.push(`## 6. Network & Transport`);
  lines.push(``);
  if (state.httpsEnforcement.checked) {
    if (state.httpsEnforcement.enforced === true) {
      lines.push(`**HTTPS Enforcement:** ✅ Plain-HTTP requests redirect to HTTPS (\`${state.httpsEnforcement.finalUrl}\`).`);
    } else if (state.httpsEnforcement.enforced === false) {
      lines.push(`**HTTPS Enforcement:** ❌ ${state.httpsEnforcement.note || 'Plain-HTTP requests are not redirected to HTTPS.'}`);
    } else {
      lines.push(`**HTTPS Enforcement:** Inconclusive (${state.httpsEnforcement.error || 'network restriction'}).`);
    }
  }
  lines.push(`**Negotiated Protocol:** ${state.protocolInfo.protocol ? state.protocolInfo.protocol.toUpperCase() : 'Unknown'}`);
  lines.push(`**Mixed Content:** ${state.mixedContent.resources.length ? `⚠ ${state.mixedContent.resources.length} insecure resource(s) detected` : 'None detected'}`);
  if (state.mixedContent.resources.length) {
    state.mixedContent.resources.slice(0, 10).forEach((url) => lines.push(`- \`${url}\``));
  }
  lines.push(``);

  lines.push(`## 7. Email Security (SPF / DMARC)`);
  lines.push(``);
  if (state.emailSecurity.checked) {
    lines.push(`Domain checked: \`${state.emailSecurity.domain}\``);
    lines.push(``);
    lines.push(`- **SPF:** ${state.emailSecurity.spf ? `\`${state.emailSecurity.spf}\`` : '❌ Not found — domain is more vulnerable to email spoofing.'}`);
    lines.push(`- **DMARC:** ${state.emailSecurity.dmarc ? `\`${state.emailSecurity.dmarc}\`` : '❌ Not found — spoofed emails from this domain will not be flagged or rejected.'}`);
  } else {
    lines.push(`Not checked.`);
  }
  lines.push(``);

  lines.push(`## Summary`);
  lines.push(``);
  lines.push(`This passive scan surfaced ${getFailedHeaderLabels().length} missing security header(s), ${state.cookieSummary.insecure} insecure cookie(s), ${state.robots.sensitivePaths.length} disclosed sensitive path(s), ${state.sensitiveFiles.exposed.length} exposed sensitive file(s), and ${state.mixedContent.resources.length} mixed-content resource(s), resulting in an overall Security Posture Score of **${state.score}/100**.`);
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
    let hostname;
    try {
      const parsed = new URL(tab.url);
      originUrl = parsed.origin;
      hostname = parsed.hostname;
    } catch (e) {
      throw new Error('Could not parse the active tab URL.');
    }
    state.origin = originUrl;

    // Headers and cookies first - later modules (fingerprinting, scoring)
    // depend on their results.
    await resolveHeaders(tab);
    computeHeaderResults();
    await inspectCookies(tab);

    // Run the remaining passive checks concurrently - each has its own
    // internal error handling so one failing module never blocks another.
    await Promise.all([
      scanAttackSurface(originUrl),
      scanSensitiveFiles(originUrl),
      scanSecurityTxt(originUrl),
      scanPageRuntime(tab),
      checkHttpsEnforcement(originUrl),
      checkEmailSecurity(hostname),
    ]);

    state.techStack = detectTechnologies(state.headers, state.cookies);

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
