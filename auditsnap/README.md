# AuditSnap — Client Security & Attack Surface Checker

A Manifest V3 Chrome extension that runs a **1-click passive security assessment** on the active browser tab. Built for penetration testers, security auditors, and freelancers who need to quickly gauge a target's security posture and generate a client-ready outreach snippet or Markdown report.

AuditSnap performs **zero active/intrusive testing** — it only inspects information the target site already exposes publicly (HTTP response headers, cookie flags, `robots.txt`, `sitemap.xml`). It is safe to run against any site you're authorized to view in your browser.

---

## Features

| Module | What it checks |
|---|---|
| **HTTP Security Headers** | Presence/absence of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy` |
| **Cookie Security & Hygiene** | `Secure`, `HttpOnly`, and `SameSite` flags on every cookie set for the current origin |
| **Passive Attack Surface** | `robots.txt` disclosure of sensitive paths (`/admin`, `/login`, `/api`, `/wp-admin`, `/backup`, etc.), `sitemap.xml` accessibility, and server fingerprinting headers (`Server`, `X-Powered-By`) |
| **Security Posture Score** | A single 0–100 score computed from the three modules above (Headers 65%, Cookies 20%, Attack Surface 15%) |
| **Proposal Hook Export** | One-click copy of a persuasive, vulnerability-specific outreach message for cold pitches / freelance proposals |
| **Markdown Report Export** | One-click copy of a full structured Markdown audit report, ready to paste into a doc or ticket |

---

## Project Structure

```
auditsnap/
├── manifest.json     # MV3 manifest — permissions, host_permissions, action, service worker
├── background.js     # Service worker — captures & caches main_frame response headers per tabId
├── popup.html         # Popup UI markup
├── popup.css          # Dark cybersecurity-themed stylesheet
├── popup.js           # All scan logic: headers, cookies, robots.txt, scoring, export generators
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## Installation (Developer Mode)

1. Download and unzip `AuditSnap-extension.zip` (or clone/copy the `auditsnap/` folder) to a local directory.
2. Open Chrome and navigate to `chrome://extensions`.
3. Toggle **Developer mode** on (top-right corner).
4. Click **Load unpacked**.
5. Select the `auditsnap/` folder.
6. The AuditSnap icon will appear in the toolbar. Pin it for quick access.

No build step, no `npm install`, no external dependencies — it's plain HTML/CSS/JS.

---

## How It Works

### 1. Header capture (`background.js`)
The service worker listens on `chrome.webRequest.onHeadersReceived` for `main_frame` navigations only, and caches the normalized (lowercase-keyed) response headers in an in-memory `Map` keyed by `tabId`. The cache entry is cleared automatically via `chrome.tabs.onRemoved` when a tab closes.

### 2. Header retrieval (`popup.js` → `resolveHeaders()`)
When the popup opens:
1. It first asks `background.js` for the cached headers of the active tab (`AUDITSNAP_GET_HEADERS` message).
2. If nothing is cached yet (e.g., the extension was just installed and the tab hasn't reloaded since), it falls back to a live `fetch()` against the page URL and reads headers from the `Response` object.
3. If both fail, the Headers panel is marked **Unavailable** and a warning banner is shown — scoring still proceeds using whatever data is available.

> **Tip:** If headers show as "Unavailable" right after installing the extension, reload the target tab once (`F5`) before opening the popup — this lets the service worker capture the navigation headers.

### 3. Cookie inspection (`popup.js` → `inspectCookies()`)
Uses `chrome.cookies.getAll({ url: tab.url })` and flags any cookie missing `Secure` or `HttpOnly` as insecure. `SameSite` value is reported but does not currently affect the insecure count (browsers default it to `Lax`, which is a reasonable baseline).

### 4. Attack surface scan (`popup.js` → `scanAttackSurface()`)
Fetches `${origin}/robots.txt` and `${origin}/sitemap.xml` directly (both with a 4-second timeout via `AbortController`), parses `Disallow:` lines for high-interest keywords, and cross-references fingerprinting headers already captured in step 2.

### 5. Scoring (`popup.js` → `computeScore()`)
```
Headers score  = (sum of weights of present headers / 80) × 65
Cookies score  = max(0, 20 − insecure_cookie_count × 4)      [capped at 20 penalty]
Surface score  = max(0, 15 − (sensitive_paths + fingerprint_headers) × 2)  [capped at 15 penalty]
Total          = round(Headers + Cookies + Surface), clamped to 0–100
```

### 6. Export generators
- **`buildProposalHook()`** — builds a short, persuasive outreach message referencing the *exact* issues found (missing headers, insecure cookie count, disclosed paths, fingerprinting).
- **`buildMarkdownReport()`** — builds a full Markdown report with header/cookie tables, attack surface findings, and a summary line, ready to paste into a proposal doc, GitHub issue, or Notion page.

Both use `navigator.clipboard.writeText()` with a `document.execCommand('copy')` fallback for environments where the async Clipboard API is blocked.

---

## Permissions Explained

| Permission | Why it's needed |
|---|---|
| `activeTab` | Read the URL/title of the tab the user is currently looking at, only when the popup is invoked |
| `cookies` | Read cookie flags (`Secure`, `HttpOnly`, `SameSite`) for the active origin |
| `webRequest` | Passively observe response headers of the top-level navigation (no request blocking/modification) |
| `storage` | Reserved for future settings persistence (not currently used to store scan data) |
| `clipboardWrite` | Copy the Proposal Hook / Markdown Report to the clipboard |
| `host_permissions: <all_urls>` | Required so `webRequest`, `cookies`, and the `robots.txt`/`sitemap.xml` fetches work on **any** site the user chooses to audit |

AuditSnap does **not** send any data off-device. All scanning, scoring, and report generation happens locally inside the popup — there is no external API call, analytics, or telemetry.

---

## Known Limitations

- **Passive only.** This is not a penetration test. It does not attempt authentication bypass, injection testing, or active exploitation of any kind.
- **Single-page scope.** Headers/cookies are evaluated for the currently active tab's origin only, not the entire site.
- **CORS/network variance.** Some servers block cross-origin reads of `robots.txt`/`sitemap.xml` at the infrastructure level (WAF, bot protection); in that case those checks report "Not accessible" rather than failing silently.
- **Header cache timing.** Right after a fresh install, the background cache may be empty for tabs that haven't reloaded — see the tip in the "How It Works" section.

---

## Troubleshooting

**"Could not retrieve HTTP response headers" banner / `TypeError: Failed to fetch`**
Usually caused by an overly strict `Content-Security-Policy` in `popup.html` blocking `connect-src`, or the tab not having reloaded since install. Confirm `popup.html`'s CSP meta tag includes `connect-src https: http:;` and reload the target tab once, then re-open the popup.

**Score seems low despite the site "looking fine"**
Most sites are missing at least one of the five audited headers (commonly `Content-Security-Policy` or `Referrer-Policy`) — this is normal and exactly the kind of low-effort gap AuditSnap is designed to surface for outreach.

---

## Disclaimer

AuditSnap is intended for use on systems you own or are explicitly authorized to assess. The generated "Proposal Hook" text is a starting point for legitimate freelance/security outreach — always ensure your engagement complies with applicable law and any responsible disclosure policies of the target organization.
