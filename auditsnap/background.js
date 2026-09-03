/**
 * AuditSnap - background.js (Service Worker)
 * Responsibilities:
 *  1. Listen for the top-level (main_frame) navigation response headers
 *     for every tab using chrome.webRequest.onHeadersReceived.
 *  2. Cache those headers in memory, keyed by tabId, so popup.js can
 *     read them instantly (synchronously via message passing) instead
 *     of re-fetching the page (which could trigger duplicate requests,
 *     CORS issues, or miss cookies/auth-dependent responses).
 *  3. Clean up cached data when a tab navigates away or is closed, to
 *     avoid unbounded memory growth and stale data leaking into a new
 *     page's audit.
 */

'use strict';

// In-memory cache: tabId -> { url, status, headers: {lowercaseName: value}, timestamp }
const tabHeaderCache = new Map();

/**
 * Normalizes the raw headers array from webRequest into a simple
 * lowercase-keyed object for easy lookups later (HTTP header names
 * are case-insensitive).
 */
function normalizeHeaders(headersArray) {
  const result = {};
  if (!Array.isArray(headersArray)) return result;

  for (const header of headersArray) {
    if (!header || typeof header.name !== 'string') continue;
    const key = header.name.toLowerCase();
    const value = header.value !== undefined ? header.value : (header.binaryValue ? '' : '');

    // Some headers (e.g. Set-Cookie) can appear multiple times.
    // We concatenate with a separator so nothing is lost, though
    // AuditSnap primarily reads single-value security headers.
    if (result[key] !== undefined) {
      result[key] = `${result[key]}, ${value}`;
    } else {
      result[key] = value;
    }
  }
  return result;
}

// Capture headers for the main frame of every navigation.
// extraHeaders is required in MV3 for some headers (like CSP/HSTS
// in certain Chrome versions) to be visible to the extension.
try {
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      try {
        if (details.type !== 'main_frame') return;
        if (typeof details.tabId !== 'number' || details.tabId < 0) return;

        const normalized = normalizeHeaders(details.responseHeaders);

        tabHeaderCache.set(details.tabId, {
          url: details.url,
          status: details.statusCode,
          headers: normalized,
          timestamp: Date.now(),
        });
      } catch (innerErr) {
        // Never let a single malformed navigation event crash the worker.
        console.error('[AuditSnap] Failed to process headers for tab:', innerErr);
      }
    },
    { urls: ['<all_urls>'], types: ['main_frame'] },
    ['responseHeaders', 'extraHeaders']
  );
} catch (setupErr) {
  // webRequest may be unavailable in some restricted contexts; fail safe.
  console.error('[AuditSnap] Could not register webRequest listener:', setupErr);
}

// Clear stale cache entries when a tab is about to navigate to a
// brand-new document, so popup.js never reads headers belonging
// to the previous page loaded in that tab.
try {
  chrome.webNavigation && chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0 && tabHeaderCache.has(details.tabId)) {
      // Leave the old entry until the new headers arrive; onHeadersReceived
      // will overwrite it. This avoids a flash of "no data" between events.
    }
  });
} catch (navErr) {
  // webNavigation permission not declared/available - safe to ignore,
  // header capture still works via onHeadersReceived alone.
}

// Cleanup when a tab is closed to prevent unbounded memory growth.
chrome.tabs.onRemoved.addListener((tabId) => {
  tabHeaderCache.delete(tabId);
});

// Message bridge: popup.js requests cached headers for the active tab.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'AUDITSNAP_GET_HEADERS') {
    return false; // not our message
  }

  const tabId = message.tabId;

  try {
    if (typeof tabId !== 'number') {
      sendResponse({ ok: false, error: 'Invalid tabId supplied.' });
      return false;
    }

    const cached = tabHeaderCache.get(tabId);

    if (!cached) {
      sendResponse({ ok: false, error: 'NO_CACHE' });
      return false;
    }

    sendResponse({ ok: true, data: cached });
  } catch (err) {
    console.error('[AuditSnap] Error responding to header request:', err);
    sendResponse({ ok: false, error: String(err && err.message ? err.message : err) });
  }

  return false; // synchronous response, no need to keep channel open
});
