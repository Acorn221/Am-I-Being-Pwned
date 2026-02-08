# PDF Viewer (oemmndcbldboiebfnladdacbdfmadadm) - Vulnerability Report

## Extension Metadata
- **ID:** oemmndcbldboiebfnladdacbdfmadadm
- **Version:** 4.6.129
- **Users:** ~1,000,000
- **Manifest Version:** 3
- **Permissions:** alarms, declarativeNetRequestWithHostAccess, webRequest, tabs, webNavigation, storage
- **Host Permissions:** `<all_urls>`
- **Developer:** Mozilla (pdf.js)
- **License:** Apache 2.0

## Executive Summary

PDF Viewer v4.6.129 is the **official Mozilla PDF.js extension**, an open-source PDF renderer that replaces the browser's built-in PDF viewer with the same PDF.js engine used in Firefox. The extension is Apache 2.0 licensed and maintained by the Mozilla PDF.js team.

Despite a broad permission surface (content scripts on all pages, `<all_urls>` host permission, `wasm-unsafe-eval` CSP directive), all permissions are justified by the extension's core functionality: detecting embedded PDFs on any webpage and rendering them locally using a WASM-accelerated PDF engine.

Three independent analysis agents examined the manifest/permissions, background/network layer, and content scripts respectively. **All three rated the extension LOW RISK.** No vulnerabilities, data exfiltration, or malicious behavior was identified.

The only notable finding is a minimal telemetry endpoint (`pdfjs.robwu.nl/logpdfjs`) that sends only extension version and a random deduplication ID, excludes cookies, respects incognito mode, is rate-limited to once per 12 hours, and can be disabled via a user preference.

**Overall Risk Assessment: CLEAN**

---

## Architecture Overview

| Component | File | Purpose |
|---|---|---|
| Service worker | background.js / pdfHandler.js | DNR rules to intercept PDF responses and redirect to viewer |
| Referer preservation | preserve-referer.js | Temporarily stores HTTP Referer header for PDF requests (5-min TTL) |
| Telemetry | telemetry.js | Optional, minimal usage telemetry to Mozilla |
| Content script | contentscript.js | Detects `<object>` and `<embed>` tags containing PDFs via CSS animation |
| PDF viewer | viewer.html / viewer.mjs | Local PDF rendering via PDF.js WASM engine |

### Data Flow Architecture

```
User's Browser
    |
    +-- contentscript.js (on all pages, document_start)
    |       |-- CSS animation listener detects <object>/<embed> with PDF MIME type
    |       |-- Creates isolated iframe in closed shadowRoot
    |       +-- Loads PDF in local viewer (no external requests)
    |
    +-- pdfHandler.js (service worker)
    |       |-- DeclarativeNetRequest rules intercept PDF Content-Type responses
    |       |-- Redirects PDF URLs to local viewer.html?file=<original_url>
    |       +-- preserve-referer.js stores Referer for 5 minutes (memory only)
    |
    +-- viewer.mjs (PDF.js engine)
    |       |-- Fetches PDF bytes from original URL
    |       |-- Parses and renders locally using WASM decoder
    |       +-- No data leaves the extension
    |
    +-- telemetry.js (optional, once per 12 hours)
            |-- POST https://pdfjs.robwu.nl/logpdfjs
            |-- Sends: Extension-Version header + Deduplication-Id (random 40-bit hex)
            |-- credentials: "omit", cache: "no-store"
            |-- Disabled in incognito, only for official extension ID
            +-- Opt-out via disableTelemetry storage preference
```

All PDF processing is performed locally. No PDF content, page content, or user data is transmitted externally.

---

## Vulnerability Analysis

### INFO-01: Telemetry Endpoint
- **Severity:** LOW (Informational)
- **CVSS:** N/A (not a vulnerability)
- **Files:** telemetry.js
- **Analysis:**
  The extension sends a single POST request to `https://pdfjs.robwu.nl/logpdfjs` at most once every 12 hours. The request contains:
  - `Extension-Version` header (e.g., "4.6.129")
  - `Deduplication-Id` header (random 40-bit hex, regenerated per session)
  - No cookies (`credentials: "omit"`)
  - No caching (`cache: "no-store"`)
  - No request body
  - No user-identifiable information

  The telemetry is gated by multiple conditions:
  1. Only fires for the official extension ID (`oemmndcbldboiebfnladdacbdfmadadm`)
  2. Disabled in incognito/private browsing mode
  3. Rate-limited to once per 12 hours via `chrome.storage.local` timestamp
  4. Can be disabled by setting `disableTelemetry` preference to `true`

  This is a textbook example of responsible, transparent telemetry. The endpoint is operated by Rob Wu, a core PDF.js contributor and Mozilla engineer.
- **Verdict:** FALSE POSITIVE -- transparent, opt-outable telemetry by a Mozilla maintainer. No user data or browsing behavior is collected.

---

## False Positive Analysis

| Flag | File | Assessment |
|------|------|------------|
| `<all_urls>` host permission | manifest.json | FP -- required for PDF detection/interception on any website, including file:// URLs |
| `wasm-unsafe-eval` CSP directive | manifest.json | FP -- required for PDF.js WASM-based image decoders (JPEG2000, JBIG2) |
| `webRequest` permission | manifest.json | FP -- used with `declarativeNetRequestWithHostAccess` for PDF response interception |
| Content script on all pages (`http://*/*`, `https://*/*`, `file://*/*`) | manifest.json | FP -- needed to detect `<object>` and `<embed>` tags embedding PDFs on any page |
| Content script at `document_start` | manifest.json | FP -- must run early to catch PDF embeds before they render with built-in viewer |
| `all_frames: true` content script | manifest.json | FP -- PDFs can be embedded in iframes; must detect them in all frames |
| `webRequest.onSendHeaders` / `onHeadersReceived` | preserve-referer.js | FP -- preserves HTTP Referer header for PDF loading (some servers require it); 5-minute TTL, memory only |
| `new Function()` usage | viewer.mjs | FP -- CommonJS `require()` emulation pattern in PDF.js build output |
| `web_accessible_resources` broad exposure | manifest.json | FP -- viewer iframe must be loadable from any page context to replace embedded PDFs |
| External network request | telemetry.js | FP -- minimal, opt-outable telemetry (see INFO-01 above) |

---

## API Endpoints & Domains

| Domain | Protocol | Purpose | Risk |
|--------|----------|---------|------|
| `pdfjs.robwu.nl` | HTTPS POST | Extension telemetry (version + random ID only) | NONE -- no user data, opt-outable |

No other external network calls are made. PDF files are fetched from their original URLs by the viewer, but no data is sent to any third-party analytics, advertising, or data collection service.

---

## Data Flow Summary

**Data collected:** None. The telemetry endpoint receives only the extension version string and a random deduplication ID. No browsing history, page content, PDF content, cookies, or user-identifiable information is transmitted.

**Data stored locally:**
- `chrome.storage.local`: User preferences (viewer settings, telemetry opt-out flag, last telemetry timestamp)
- In-memory: HTTP Referer values for active PDF requests (TTL: 5 minutes, never persisted)

**PDF processing:** All PDF parsing, rendering, and interaction occurs locally within the extension's viewer using PDF.js WASM decoders. PDF content never leaves the user's browser.

**Content script isolation:** The content script creates an isolated iframe within a closed `shadowRoot`, preventing the host page from accessing or manipulating the PDF viewer. Chrome port messaging uses proper origin validation.

---

## Overall Risk Assessment

**Risk Level: CLEAN**

PDF Viewer is a well-engineered, open-source Mozilla extension that does exactly what it claims: render PDFs in the browser using PDF.js. Despite its necessarily broad permissions (required for intercepting and rendering PDFs on any website), the extension demonstrates exemplary security practices:

1. **No data exfiltration** -- zero analytics SDKs, no user tracking, no browsing history collection
2. **Minimal telemetry** -- a single, transparent, opt-outable endpoint that collects no user data
3. **Local-only processing** -- all PDF rendering happens client-side in a WASM sandbox
4. **Proper isolation** -- closed shadowRoot for embedded PDF viewer, origin validation on messaging
5. **No obfuscation** -- fully open-source (Apache 2.0), readable code, no minification tricks
6. **Incognito-aware** -- telemetry automatically disabled in private browsing
7. **No remote code execution** -- CSP restricts to `'self'` and `'wasm-unsafe-eval'` (necessary for WASM decoders)

This extension requires no further investigation. It is a clean, legitimate tool from a trusted developer (Mozilla).
