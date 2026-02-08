# Vulnerability Report: GoFullPage - Full Page Screen Capture

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | GoFullPage - Full Page Screen Capture |
| Extension ID | fdpohaocaechififmbbbbbknoalclacl |
| Version | 8.6 |
| Manifest Version | 3 |
| User Count | ~10,000,000 |
| Author | Peter Coles (screencapture.mrcoles.com) |

## Permissions Summary
| Permission | Type | Notes |
|------------|------|-------|
| `activeTab` | Required | Grants access to current tab on user action |
| `scripting` | Required | Needed to inject page capture script |
| `storage` | Required | For user preferences |
| `unlimitedStorage` | Required | For storing large screenshot images |
| `downloads` | Optional | For saving screenshots to disk |
| `webNavigation` | Optional | For iframe/frameset capture |
| `<all_urls>` | Optional Host | For iframe content access |
| `file://*/*` | Optional Host | For capturing file:// pages |

## Executive Summary

GoFullPage is a well-known, legitimate full-page screenshot extension with ~10 million users. The extension captures entire web pages by scrolling through them and stitching screenshots together. It uses Manifest V3 with a minimal background service worker. The code is bundled with Parcel and is not obfuscated -- it follows standard patterns for a screen capture tool. The only external network communication is Google Analytics 4 (Measurement Protocol) for basic usage telemetry, and postMessage communication with `gofullpage.com` for premium feature management. No malicious behavior, data exfiltration, proxy infrastructure, or suspicious patterns were identified.

## Vulnerability Details

### INFO-01: Google Analytics 4 Measurement Protocol Telemetry
| Field | Value |
|-------|-------|
| Severity | INFO |
| File(s) | `popup.d5240b7c.js`, `popup.a3d47a2a.js` |
| Verdict | **Not malicious** -- standard usage analytics |

**Details:** The extension sends telemetry to Google Analytics 4 via the Measurement Protocol:
- Endpoint: `https://www.google-analytics.com/mp/collect`
- Measurement ID: `G-R8FSS9S0K5`
- Debug endpoint: `http://localhost:3456/debug/mp/collect` (only used in development)
- Events tracked: `page_view`, `download`

This is standard, lightweight usage analytics -- tracking page views within the extension UI and download actions. No page content, URLs visited, or personal data is sent.

### INFO-02: Postmate Library for Premium Feature Communication
| Field | Value |
|-------|-------|
| Severity | INFO |
| File(s) | `p/_api.51ec1949.js`, `p/_api.87464a3e.js` |
| Verdict | **Not malicious** -- premium account management |

**Details:** The `p/` directory contains an API bridge using the Postmate library (dollarshaveclub/postmate) for cross-origin iframe communication. The `web_accessible_resources` section in the manifest restricts access to `p/*` resources to only:
- `*://*.gofullpage.com/*`
- `https://localhost:1234/*`
- `https://dev.d32cgdvim65k7p.amplifyapp.com/*`

This is the mechanism for managing premium subscriptions. The gofullpage.com site embeds the extension's `p/_api.html` page to communicate account/license status. The Postmate library uses `postMessage` with origin validation, which is the correct secure pattern.

### INFO-03: activeTab + scripting Combination
| Field | Value |
|-------|-------|
| Severity | INFO |
| File(s) | `manifest.json`, `popup.3cca83ac.js`, `popup.82f4eb91.js` |
| Verdict | **Not malicious** -- required for core functionality |

**Details:** The extension uses `activeTab` + `scripting` to inject `js/page/index.js` into the active tab when the user triggers a capture. This content script:
- Measures page dimensions and scrollable regions
- Handles scrolling through the page
- Communicates scroll positions back to the background via `chrome.runtime.sendMessage`
- Manages fixed/sticky element repositioning during capture
- Extracts link positions for PDF hyperlink support

This is the core screen capture mechanism. The script runs only on user action (clicking the extension icon or pressing Alt+Shift+P), uses standard DOM measurement APIs, and does not exfiltrate any page content -- it only sends scroll coordinates and layout metadata back to the extension.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `document.cookie` | `capture.9e75074f.js`, `capture.21168ba6.js` | Part of Dexie.js (IndexedDB wrapper) for local file storage, not cookie harvesting |
| `eval()` / `Function()` | Various editor/capture scripts | Part of jsPDF library (PDF generation), Parcel bundler runtime, and Dexie.js -- standard library patterns |
| `postMessage` | `p/_api.*.js`, popup/capture scripts | Postmate library for premium feature communication with origin validation; internal extension messaging |
| `addEventListener("message")` | Multiple files | Internal extension message handling and Postmate communication |
| `keydown`/`keypress` | Editor scripts, welcome scripts | Editor keyboard shortcuts (crop, annotate, undo/redo) -- not keylogging |
| `atob`/`btoa`/`base64` | Editor, popup, capture scripts | jsPDF library for PDF encoding, canvas image data conversion -- standard image processing |
| `chrome.tabs.query` | Options, popup, capture scripts | Used to find the active tab for capture initiation -- standard extension pattern |
| `navigate` | Capture scripts | DOM navigation during page measurement, not URL navigation tracking |
| `innerHTML` | Editor scripts | jsPDF library SVG rendering -- standard library pattern |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://www.google-analytics.com/mp/collect` | GA4 usage telemetry | Anonymous event data (page_view, download) with measurement_id |
| `https://gofullpage.com` | Premium account management (via Postmate iframe) | License/account status |
| `https://screencapture.mrcoles.com/` | Support/issue reporting (link only) | None (user navigates manually) |
| `https://chromewebstore.google.com/detail/.../reviews` | Webstore review prompt (link only) | None (user navigates manually) |
| `https://blog.gofullpage.com/...` | Blog link in welcome page | None (user navigates manually) |

## Data Flow Summary

1. **User triggers capture** (icon click or keyboard shortcut) -> popup opens
2. **Popup injects** `js/page/index.js` into active tab via `chrome.scripting.executeScript`
3. **Content script** measures page dimensions, scrollable elements, fixed elements -> sends layout metadata to background
4. **Background** uses `chrome.tabs.captureVisibleTab` to capture visible viewport screenshots at each scroll position
5. **Popup** stitches screenshots into full-page canvas using CanvasObj class
6. **Result** displayed in `capture.html` with options to download as PNG/PDF, edit/annotate in `editor.html`
7. **Files** stored locally via IndexedDB (Dexie.js) using `unlimitedStorage`
8. **Analytics** sends anonymous `page_view`/`download` events to GA4
9. **Premium features** (editing, annotation, smart PDF splitting) managed via Postmate communication with `gofullpage.com`

No user page content, URLs, browsing history, or personal data leaves the extension except for the anonymous GA4 telemetry.

## Overall Risk Assessment

| Rating | **CLEAN** |
|--------|-----------|

**Rationale:** GoFullPage is a well-architected, legitimate screen capture extension. Key findings:

- **Minimal permissions**: Uses `activeTab` (not `<all_urls>` as required), keeping access to user-initiated captures only
- **No persistent content scripts**: No `content_scripts` in manifest; scripts are injected only on user action
- **Minimal background service worker**: Only opens the welcome page on install -- no persistent listeners, no alarms, no network requests
- **No data exfiltration**: Screenshot data stays entirely local (IndexedDB). Only anonymous analytics events are sent externally
- **No remote code execution**: No dynamic script loading, no eval of remote content, no WebSocket connections
- **No suspicious patterns**: No extension enumeration, no XHR hooking, no proxy infrastructure, no market intelligence SDKs
- **Standard libraries**: Uses jsPDF, Dexie.js, React, Postmate -- all well-known, legitimate open-source libraries
- **Proper origin validation**: Postmate communication restricted to gofullpage.com origins via manifest and library
- **MV3 compliant**: Clean Manifest V3 implementation with service worker
