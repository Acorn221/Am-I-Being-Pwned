# Vulnerability Report: Foxit PDF Creator

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Foxit PDF Creator |
| Extension ID | cifnddnffldieaamihfkhkdgnbhfmaci |
| Version | 12.1.0.0 |
| Manifest Version | 3 |
| User Count | ~8,000,000 |
| Analysis Date | 2026-02-08 |

## Permissions
- `contextMenus` - Creates right-click menu items for PDF conversion
- `tabs` - Reads active tab URL/title to pass to native app for conversion
- `nativeMessaging` - Communicates with local Foxit PhantomPDF desktop application
- `cookies` - Reads cookies for the current page URL (passed to native app for authenticated page conversion)

## Content Script Scope
- Matches: `http://*/*`, `https://*/*`, `file:///*` (all pages)

## Executive Summary

Foxit PDF Creator is a companion extension for the Foxit PhantomPDF desktop application. Its sole purpose is to convert web pages to PDF by communicating with a locally-installed native messaging host (`com.foxit.chromeaddin`). The extension is straightforward, well-scoped, and contains no obfuscation, no remote code loading, no external network calls, and no data exfiltration. All data flows are local (browser to native desktop app). The code is simple, largely unminified, and contains Chinese-language developer comments consistent with Foxit's development team based in China.

The cookie access is the most noteworthy permission -- the extension reads cookies for the page being converted and passes them to the native app. This is a legitimate pattern for PDF conversion of authenticated pages (the native app needs the session cookies to fetch page resources). The cookies are only read when a user explicitly triggers a conversion action, and they are sent exclusively to the local native messaging host, never to any remote endpoint.

The content script is minimal -- it only maintains a keep-alive connection to the background service worker and contains no DOM manipulation, no data extraction, and no injection behavior.

## Vulnerability Details

### LOW-1: Cookie Forwarding to Native Host
| Field | Detail |
|-------|--------|
| Severity | LOW |
| File | `background.js` (lines 147-161) |
| Code | `chrome.cookies.getAll({"url": encodeURI(method.URLs)}, function(cookies) { ... method.cookies = string; sendNativeMessage(method, callback); })` |
| Verdict | **Legitimate functionality.** Cookies for the current page URL are read and forwarded to the local native messaging host (`com.foxit.chromeaddin`) so the desktop app can download authenticated page resources for PDF conversion. Data never leaves the local machine. Only triggered by explicit user action (context menu or popup button click). |

### INFO-1: Deprecated API Usage (executeScript with code string)
| Field | Detail |
|-------|--------|
| Severity | INFO |
| File | `background.js` (line 78) |
| Code | `chrome.tabs.executeScript(null, {code: "switchLight("+ request +");", allFrames: true});` |
| Verdict | **Dead code / legacy artifact.** This uses the MV2 `chrome.tabs.executeScript` API which does not work in MV3 (the manifest declares MV3). The `switchLight` function is never defined anywhere. This is leftover code from an older version. Not exploitable in current form. |

### INFO-2: Commented-Out HTML Content Extraction
| Field | Detail |
|-------|--------|
| Severity | INFO |
| File | `background.js` (lines 434-456) |
| Code | `GetCurrentHtmlContent` function has an early `return` on line 438, making the HTML extraction code unreachable. |
| Verdict | **Dead code.** The function immediately returns empty string. The commented-out code below would have extracted full page HTML for PDF conversion, which is legitimate for the extension's purpose. Currently inactive. |

### INFO-3: background.html NPAPI Embed Tag
| Field | Detail |
|-------|--------|
| Severity | INFO |
| File | `background.html` (line 4) |
| Code | `<embed type="application/npbrowser-plugins" id="pluginId">` |
| Verdict | **Legacy artifact.** NPAPI plugins have been disabled in Chrome since 2015. This embed tag is non-functional. The manifest declares MV3 with a service worker, so `background.html` is not loaded. |

## False Positive Table

| Pattern | Location | Reason Not Flagged |
|---------|----------|--------------------|
| `chrome.cookies.getAll` | background.js:147 | Legitimate: reads cookies for page being converted, sent only to local native host, user-initiated |
| `btoa(encodeURI(value))` | background.js:128 | Legitimate: base64 encoding of method parameters for V2 interface protocol with native host |
| `chrome.tabs.executeScript` | background.js:78 | Dead code: MV2 API in MV3 extension, non-functional |
| Content script on all URLs | content_scripts.js | Benign: only establishes keep-alive port connection, no DOM access or data extraction |
| `BroadcastChannel` | background.js, popup.js | Internal communication between popup and background, standard pattern |

## API Endpoints Table

| Endpoint | Type | Purpose |
|----------|------|---------|
| `com.foxit.chromeaddin` | Native Messaging Host | Local Foxit PhantomPDF desktop application |

**No remote/external API endpoints are contacted by this extension.**

## Data Flow Summary

1. **User initiates PDF conversion** via popup button or context menu
2. **Background script reads active tab** URL and title via `chrome.tabs.query`
3. **Background script reads cookies** for that URL (if interface version >= 8.2.0)
4. **Data sent to local native host** (`com.foxit.chromeaddin`) via `chrome.runtime.connectNative`
5. **Native app returns result** (success/failure status) via the same native messaging port
6. **Result displayed** in popup UI

All data flows are local. No data is sent to any remote server.

## Overall Risk: **CLEAN**

This is a straightforward, legitimate companion extension for the Foxit PhantomPDF desktop PDF editor. It has a small, readable codebase with no obfuscation, no remote code loading, no external network calls, no analytics/tracking SDKs, and no data exfiltration. The permissions (cookies, tabs, nativeMessaging, contextMenus) are all justified by the extension's core functionality of converting web pages to PDF via the locally installed Foxit application. The cookie access is scoped to user-initiated conversion actions and data is sent only to the local native messaging host. The content script is minimal (keep-alive connection only). Multiple pieces of dead/legacy code exist but pose no security risk.
