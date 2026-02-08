# Instant Data Scraper -- Security Analysis Report

**Extension ID:** `ofaokhiedipichpaobibbnahnkdoiiah`
**Version:** 1.2.1
**Manifest Version:** 3
**Approximate Users:** ~1,000,000
**Developer:** webrobots.io
**Triage Verdict:** SUSPECT (T1=2, V1=3)
**Analysis Date:** 2026-02-06

---

## Executive Summary

**RISK RATING: LOW (CLEAN -- triage flags are all FALSE POSITIVES)**

Instant Data Scraper is a legitimate web scraping tool that extracts tabular data from web pages and exports it locally as CSV or XLSX files. The extension is user-triggered only (requires explicit toolbar click), stores scraped data entirely locally (no upload to remote servers), and contains no malicious behavior such as data exfiltration, XHR/fetch hooking, keylogging, or ad injection.

The two T1 triage flags originate from `eval()` calls in the vendored `js-sha256` v0.9.0 library (a well-known open-source library), which uses `eval("require('crypto')")` for Node.js compatibility -- a standard pattern that never executes in a browser extension context. The three V1 flags are similarly benign: the content script's `document.documentElement.innerHTML` read is only used for data extraction in response to user-initiated actions, and the `$("body *").each()` DOM traversal is the core scraping logic triggered only on message from the popup.

The only external network communication is Google Analytics GA4 Measurement Protocol telemetry sent from the popup page, which transmits usage events (page views, download counts, column renames, errors) to `https://www.google-analytics.com/mp/collect`. This is standard product analytics, not data exfiltration.

---

## Permissions Analysis

### Granted Permissions

| Permission | Purpose | Risk |
|---|---|---|
| `webRequest` | Used in popup.js to monitor page load completion (detect when "next" page has finished loading during crawl) | LOW -- read-only monitoring, no `webRequestBlocking`, no request modification |
| `activeTab` | Grants access to the current tab only when user clicks the extension icon | LOW -- minimal-privilege model |

### Content Scripts

| Match Pattern | Files | Risk |
|---|---|---|
| `*://*/*` (all URLs) | `jquery-3.1.1.min.js`, `sha256.min.js`, `onload.js` | MEDIUM surface, LOW actual risk -- see analysis below |

**Key observation:** The `*://*/*` content script match is inherently broad, but the content script code (`onload.js`) defines only function declarations and a `chrome.runtime.onMessage` listener. No code executes automatically on page load. All scraping functions are invoked only in response to messages from the popup, which is only opened when the user explicitly clicks the extension toolbar icon.

### Missing Permissions (positive signal)

The extension does NOT request:
- `cookies` -- no cookie access
- `history` -- no browsing history access
- `bookmarks` -- no bookmark access
- `management` -- no extension enumeration/management
- `storage` -- does not use chrome.storage (uses localStorage instead)
- `tabs` (host permission) -- no broad tab access
- `<all_urls>` (host permission) -- no background network access
- `webRequestBlocking` -- cannot modify/block requests
- `scripting` -- cannot inject scripts dynamically
- No `externally_connectable` -- not accessible from web pages
- No `web_accessible_resources` -- no resources exposed to web pages

### Content Security Policy

```json
"content_security_policy": {
    "extension_pages": "script-src 'self'; object-src 'self'"
}
```

This is a **strict and proper** CSP. No `unsafe-eval`, no `unsafe-inline`, no remote script sources. Extension pages can only load scripts bundled with the extension.

---

## File Inventory

| File | Type | Size | Purpose |
|---|---|---|---|
| `background.js` | Service Worker | 1 line (minified) | Opens popup window on toolbar click |
| `onload.js` | Content Script | 308 lines | DOM table detection and scraping logic |
| `popup.js` | Popup Script | 551 lines | UI controller, data display, export (CSV/XLSX) |
| `popup.html` | Popup UI | 83 lines | Extension popup interface |
| `js/google-analytics.js` | Analytics | 123 lines | GA4 Measurement Protocol client |
| `js/jquery-3.1.1.min.js` | Library | Standard jQuery 3.1.1 |
| `js/sha256.min.js` | Library | js-sha256 v0.9.0 -- row deduplication hashing |
| `js/papaparse.min.js` | Library | CSV parser/generator |
| `js/xlsx.full.min.js` | Library | XLSX file generation |
| `js/FileSaver.js` | Library | v1.3.5 -- file download trigger |
| `js/bootstrap.min.js` | Library | Bootstrap 3 UI framework |
| `js/handsontable.full.min.js` | Library | Spreadsheet UI component |
| `onload.css` | Stylesheet | Visual highlights for selected tables/rows |
| `popup.css` | Stylesheet | Popup window styling |

---

## Detailed Analysis

### 1. Background Service Worker (`background.js`)

The entire background script is a single line:

```javascript
chrome.action.onClicked.addListener(function(e) {
    chrome.windows.getCurrent(function(e) { parentWindowId = e.id }),
    chrome.windows.create({
        url: chrome.runtime.getURL("popup.html?tabid=" + encodeURIComponent(e.id)
             + "&url=" + encodeURIComponent(e.url)),
        type: "popup", width: 720, height: 650
    })
});
```

**Analysis:** Opens a popup window with the current tab ID and URL passed as query parameters. The URL is constructed using `chrome.runtime.getURL()` (safe, internal-only). No network requests, no data storage, no persistent background activity. The `parentWindowId` global is set but never used elsewhere in the background script.

**Verdict:** CLEAN. Minimal, single-purpose.

### 2. Content Script (`onload.js`)

The content script is 308 lines and implements the core scraping logic. Key functions:

| Function | Purpose |
|---|---|
| `a(e)` (findTables) | Scans `$("body *")` to find elements that look like data tables based on area, child count, and CSS class patterns |
| `n(e)` | Analyzes an element's children to find repeating class patterns (detecting rows) |
| `b(e, t)` (getTableData) | Extracts text, href, and src attributes from detected table rows |
| `x(e)` (getNextButton) | Lets user click to identify a "next page" button |
| `S(e, t, o)` (clickNext) | Simulates click on the next-page button |
| `N(e, t)` (scrollDown) | Scrolls container for infinite scroll detection |
| `w(e)` | Generates a CSS selector path for an element |
| `g(e)` | SHA-256 hash for row deduplication (using the sha256 library) |
| `m(e)` / `v(e)` | Checks/stores visited page hashes in localStorage to detect duplicate pages |
| `I(e)` | Reads `document.documentElement.innerHTML` -- **defined but NOT reachable** via the message listener |

**Critical entry point (line 299-307):**

```javascript
chrome.runtime.onMessage.addListener(function(e, t, o) {
    return "nextTable" == e.action || "findTables" == e.action ? (...)
    : "getTableData" == e.action ? (b(o, e.selector), !0)
    : "getNextButton" == e.action ? (x(o), !0)
    : "clickNext" == e.action ? (S(e.selector, o), !0)
    : "scrollDown" === e.action ? (c(), N(e.selector, o), !0)
    : "markNextButton" == e.action ? (S(e.selector, o, !0), !0)
    : void o({})
});
```

**Analysis:**
- All DOM interaction is gated behind `chrome.runtime.onMessage` -- only the popup (extension page) can send these messages.
- No code runs at page load. The content script only defines functions and registers the listener.
- The message API surface is limited to 6 actions, all related to the scraping workflow.
- Data flows FROM the page TO the popup (via `sendResponse`), never to an external server.
- The `I()` function (which reads full page HTML) is defined but NOT wired into the message listener -- dead code in this version.

**Verdict:** CLEAN. User-triggered only, local data flow, no exfiltration.

### 3. Popup Script (`popup.js`)

The popup script manages the scraping workflow UI. Key behaviors:

**Data storage:** All scraped data is kept in the `s` (state) object in memory. Data is exported locally via:
- CSV download using PapaParse + FileSaver.js
- XLSX download using SheetJS + FileSaver.js
- Clipboard copy

**Configuration storage:** Uses `localStorage` for:
- Column headers configuration (per-hostname)
- Crawl delay / max wait settings
- "Next" button selectors (per-hostname)
- Rate-request tracking stats

**Network communication:** The popup sends analytics events to Google Analytics (see section 4 below). No other outbound network requests.

**LinkedIn blocking (line 104):**
```javascript
null !== i.url.toLowerCase().match(/\/\/[a-z]+\.linkedin\.com/)
    ? ($("#waitHeader").hide(), p("We're unable to collect data from LinkedIn..."))
```
LinkedIn is explicitly blocked, suggesting the developer respects TOS restrictions.

**webRequest usage (lines 1-43, function `e()`):**
```javascript
var f = { urls: ["<all_urls>"], tabId: n,
    types: ["main_frame", "sub_frame", "stylesheet", "script", "font",
            "object", "xmlhttprequest", "other"] };
chrome.webRequest.onBeforeRequest.addListener(p, f);
chrome.webRequest.onCompleted.addListener(h, f);
chrome.webRequest.onErrorOccurred.addListener(h, f);
```
This monitors request completion for a specific tab ID to determine when a page has finished loading after clicking "next". It does NOT use `webRequestBlocking`, cannot modify requests, and the listener is scoped to the current scraping tab via `tabId`. After the page load is detected, the listeners are removed.

**Verdict:** CLEAN. Local-only data handling, standard export mechanisms.

### 4. Google Analytics Telemetry (`js/google-analytics.js`)

**Implementation:** GA4 Measurement Protocol (server-side POST to `https://www.google-analytics.com/mp/collect`)

**Credentials exposed:**
```javascript
const MEASUREMENT_ID = `G-G7PJ1V076F`;
const API_SECRET = `1A9McEv9Sw6ZnLayZs3nJA`;
```

Note: GA4 Measurement Protocol API secrets are not considered sensitive -- they are designed to be included in client-side code. Google's documentation explicitly provides them for this purpose.

**Events sent (from popup.js):**

| Event | Data Sent | Triggered By |
|---|---|---|
| `page_view` | hostname, URL of scraped page | First table detection |
| `AnotherTable` | hostname, URL | Switching to a different table |
| `Download` | hostname, URL, row count | CSV/XLSX download |
| `RenameColumn` | table selectors (last 100 chars), original/new column names | Column rename before download |
| `Error` | URL, error message | Extension errors |
| `Click` | button name ("Rate later" / "Rate now") | Rating prompt interaction |

**Analysis:** This is standard product analytics tracking usage patterns. The data sent is limited to:
- Which websites users scrape (hostname and URL)
- How many rows they collect
- Whether they renamed columns
- Error rates
- Rating prompt engagement

**Privacy concern (LOW):** The extension sends scraped page URLs to Google Analytics. This means the developer can see which websites are being scraped. However, no page content, scraped data, or personally identifiable information is transmitted. This is comparable to standard website analytics.

**Verdict:** Standard analytics, not data exfiltration. LOW privacy concern.

### 5. SHA-256 Library (`js/sha256.min.js`)

**Library:** js-sha256 v0.9.0 by Chen, Yi-Cyuan (MIT license)
**Source:** https://github.com/emn178/js-sha256

**Purpose in extension:** Used in `onload.js` function `g(e)` to hash scraped table content for deduplication (detecting when pagination has reached the end by comparing page hashes).

**The eval() calls (lines 79-80):**
```javascript
var r = eval("require('crypto')"),
    s = eval("require('buffer').Buffer"),
```

These are inside the `b` function (Node.js performance optimization path), which is only reached when running in a Node.js environment where `process.versions.node` is truthy. In a Chrome extension context, this code path is NEVER executed because:
1. Line 44: `n = !s.JS_SHA256_NO_NODE_JS && "object" == typeof process && process.versions && process.versions.node` -- evaluates to `false` in Chrome
2. The `b` function is only assigned to the hash function when `n` is truthy (line 78)

**Verdict:** FALSE POSITIVE. Standard library, Node.js-only code path.

---

## Triage Flag Verdicts

### T1 Flags (2 total)

| # | Flag | Source | Verdict | Explanation |
|---|---|---|---|---|
| 1 | `dynamic_eval` -- eval() with dynamic content | `js/sha256.min.js:79` | **FALSE POSITIVE** | Node.js compatibility `eval("require('crypto')")` in js-sha256 v0.9.0. Never executes in browser. |
| 2 | `dynamic_eval` -- eval() with dynamic content | `js/sha256.min.js:80` | **FALSE POSITIVE** | Node.js compatibility `eval("require('buffer').Buffer")` in js-sha256 v0.9.0. Never executes in browser. |

### V1 Flags (3 total -- reconstructed from pattern analysis)

| # | Flag | Source | Verdict | Explanation |
|---|---|---|---|---|
| 1 | `innerhtml_dynamic` -- innerHTML with dynamic content in content script | `onload.js:278` | **FALSE POSITIVE** | `document.documentElement.innerHTML` is a READ, not a write/assignment. Furthermore, the function `I()` containing this read is dead code -- not wired into the message listener. |
| 2 | `jquery_html_dynamic` or DOM access pattern | `onload.js:65` | **FALSE POSITIVE** | `$("body *").each()` is the core table detection algorithm, only called in response to user-initiated `findTables` message from popup. This is the extension's intended functionality. |
| 3 | Content script on `*://*/*` with jQuery | `onload.js` | **FALSE POSITIVE** | While the content script runs on all URLs, it only declares functions and registers a message listener. No code executes autonomously. All DOM access is gated behind explicit user action (clicking the toolbar icon). |

---

## Vulnerability Assessment

### No Critical Vulnerabilities Found

1. **No XSS vectors:** The extension uses `$(...).text()` for display (not `.html()`), builds HTML via jQuery DOM construction (`$("<div>", {...})`), and the CSP is strict (`script-src 'self'`).

2. **No message origin issues:** The content script uses `chrome.runtime.onMessage` (not `window.addEventListener("message")`), so only the extension itself can send messages. No origin validation is needed.

3. **No remote code execution:** No dynamic script injection, no `importScripts()`, no remote script loading. The CSP blocks `eval()` on extension pages.

4. **No data leakage:** Scraped data stays in memory and is exported locally. The only outbound communication is GA4 analytics with metadata only.

5. **No insecure communication:** All external communication uses HTTPS (Google Analytics endpoint).

### Minor Observations

1. **jQuery 3.1.1 is outdated** (released Sept 2016). It has known CVEs (e.g., CVE-2020-11022/11023 regarding `.html()` XSS). However, the content script does not use `.html()` with untrusted input, so these CVEs are not exploitable here.

2. **Handsontable library** is loaded in the popup (extension page, not content script), so any vulnerabilities in it would be limited to the isolated popup context.

3. **FileSaver.js 1.3.5** is outdated (2018) but only used for triggering downloads of user-generated files.

4. **GA4 API secret is exposed** in source code. This is by design (Measurement Protocol), but could theoretically allow third parties to send fake analytics events to the developer's GA4 property. This is a non-issue for users.

5. **`parentWindowId` leak in background.js:** The variable `parentWindowId` is assigned but never declared with `var/let/const`, making it an implicit global. This is a code quality issue, not a security vulnerability.

---

## Data Flow Summary

```
User clicks toolbar icon
    |
    v
background.js -> opens popup.html with tab ID + URL
    |
    v
popup.js -> sends "findTables" message to content script
    |
    v
onload.js -> scans DOM for table-like structures -> responds with table data
    |
    v
popup.js -> displays data in Handsontable grid
    |
    v
User clicks CSV/XLSX/Copy -> data exported LOCALLY via FileSaver.js
    |
    v (parallel)
popup.js -> sends usage event to Google Analytics (metadata only, no scraped data)
```

**No scraped data ever leaves the browser.** The only outbound requests are GA4 analytics events containing page URLs and usage statistics.

---

## Conclusion

Instant Data Scraper is a **legitimate, well-designed web scraping utility** with a clean security posture. All triage flags (T1=2, V1=3) are false positives attributable to:
- Standard Node.js compatibility patterns in a vendored open-source SHA-256 library
- The inherent nature of the extension (a data scraper necessarily accesses the DOM)
- A read-only `innerHTML` reference in dead code

The extension follows security best practices:
- Minimal permissions (activeTab + webRequest read-only)
- Strict CSP
- User-triggered activation only
- Local-only data storage and export
- No `externally_connectable` or `web_accessible_resources`
- Standard, non-invasive analytics

**Final Risk Rating: LOW / CLEAN**

The extension should be reclassified from SUSPECT to CLEAN.
