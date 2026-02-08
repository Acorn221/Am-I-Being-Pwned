# VULN_REPORT: ESET Browser Privacy & Security

## Metadata
| Field | Value |
|---|---|
| Extension Name | ESET Browser Privacy & Security |
| Extension ID | oombnmpbbhbakfpfgdflaajkhicgfaam |
| Version | 1.1.3 |
| Manifest Version | 3 |
| User Count | ~6,000,000 |
| Analysis Date | 2026-02-08 |

## Permissions Summary
| Permission | Justification |
|---|---|
| `tabs` | Monitor tab URLs for content script injection (secure search, website scan) |
| `scripting` | Inject secure search indicators and website scan scripts into pages |
| `storage` | Store extension configuration and user preferences |
| `nativeMessaging` | Communicate with ESET desktop product (`com.eset.browserprivacyandsecurity`) |
| `browsingData` | Browser cleanup feature (history, cookies, cache, etc.) |
| `contentSettings` | Website settings review (notifications, camera, mic, geolocation) |
| `webNavigation` | Get all frames for website scanning |
| `<all_urls>` (host permission) | Inject content scripts on all pages for secure search and website scanning |

## Executive Summary

ESET Browser Privacy & Security is a companion extension for the ESET desktop security suite. It provides: (1) secure search result annotations on Google/Bing, (2) browser data cleanup, (3) website security scanning via the native ESET product, and (4) metadata (EXIF) cleanup notifications. The extension communicates exclusively with a local native messaging host (`com.eset.browserprivacyandsecurity`) and does not make any direct HTTP/fetch/XHR calls to remote servers. All security verdicts are delegated to the ESET desktop product via native messaging.

**The extension is well-structured, uses Manifest V3, has no obfuscation, no remote code execution, no dynamic eval, and no suspicious data exfiltration patterns.** While the website scan feature does capture full page HTML and send it to the native ESET product for analysis, this is clearly part of the extension's intended security scanning functionality and requires explicit user consent via a data collection consent dialog.

## Vulnerability Details

### VULN-001: Full Page HTML Capture for Website Scanning
- **Severity:** LOW (Informational)
- **File:** `websiteScan.js` (lines 18-35)
- **Code:**
```javascript
const sendScannedHTML = (targetWindow, isFrameWithSpecialSrc = false) => {
    const scannedHTML = targetWindow.document.documentElement.outerHTML;
    // ...
    chrome.runtime.sendMessage({
        msg: "website-scan",
        data: {
            html: scannedHTML,
            title: targetWindow.document.title,
            frameUrl: getFrameURL(targetWindow),
            tabUrl: frameId === 0 && !isFrameWithSpecialSrc ? "" : tabUrl
        }
    });
};
```
- **Verdict:** **NOT MALICIOUS.** The full `outerHTML` of every visited page (including iframes with blob:/javascript: sources) is captured and sent via native messaging to the local ESET desktop product for security analysis. This is gated behind: (a) `isWebsiteScanEnabled` and `isWebsiteScanSupported` config flags, (b) explicit `dataCollectionPermissions.browsingActivity` and `dataCollectionPermissions.websiteContent` consent from the user via a consent dialog, and (c) the ESET desktop product must be installed and connected. The data never leaves the local machine via the extension -- it goes to the native host only.

### VULN-002: postMessage with Wildcard Origin
- **Severity:** LOW (Informational)
- **File:** `iframe.js` (line 21)
- **Code:**
```javascript
window.parent.postMessage({ type: "closeIframe" }, "*");
```
- **Verdict:** **FALSE POSITIVE / NEGLIGIBLE.** This sends a simple `{ type: "closeIframe" }` message with wildcard origin. The message contains no sensitive data -- it simply signals the parent frame to remove the notification iframe. The receiving listener in `notifications.js` only checks for `event.data.type === "closeIframe"` and removes the iframe. No data leakage risk.

### VULN-003: chrome.management.uninstallSelf() via Native Message
- **Severity:** LOW (Informational)
- **File:** `nativemsg.js` (lines 56-57)
- **Code:**
```javascript
} else if (msg.cmd === "uninstall") {
    chrome.management.uninstallSelf();
}
```
- **Verdict:** **EXPECTED BEHAVIOR.** The native ESET desktop product can instruct the extension to uninstall itself. This is a standard pattern for security product companion extensions -- when the parent product is uninstalled, the extension should also be removed. `uninstallSelf()` prompts the user for confirmation.

### VULN-004: Search URL Extraction on Google/Bing
- **Severity:** LOW (Informational)
- **Files:** `secure-search/g-search.js`, `secure-search/b-search.js`, `secure-search/common.js`
- **Verdict:** **EXPECTED BEHAVIOR.** The extension extracts URLs from Google and Bing search results and sends them to the native ESET product for safety rating. This is the core "secure search" feature. URLs are extracted from DOM elements only on search result pages, rated by the ESET product, and then safety icons (safe/warning/threat) are displayed inline. No URLs are sent to remote servers -- only to the local native host.

## False Positive Table

| Pattern | File | Reason for FP |
|---|---|---|
| `postMessage("*")` | `iframe.js:21` | Only sends `closeIframe` signal, no sensitive data |
| `document.documentElement.outerHTML` | `websiteScan.js:19` | Intended website security scanning feature, consent-gated |
| `chrome.management.uninstallSelf()` | `nativemsg.js:57` | Standard companion extension self-cleanup |
| `MutationObserver` on `document` | `g-search.js:89-97` | Used to detect new search results for safety annotation |
| `chrome.scripting.executeScript` | `contentScriptInjection.js` | Injects own content scripts for secure search/website scan |
| `getDomElementsFromString` (DOMParser) | `utils.js:33-38` | Used for i18n string formatting, no remote HTML |

## API Endpoints Table

| Endpoint/Target | Purpose | Data Sent |
|---|---|---|
| Native host: `com.eset.browserprivacyandsecurity` | All communication | Config init, search URLs, page HTML (for website scan), trace events, log messages |
| `https://help.eset.com/getHelp` | Help/docs links (opened in browser) | Product code, version, language, topic (via URL params only) |

**Note:** The extension makes zero direct HTTP/fetch/XHR requests. All data goes to the local native messaging host.

## Data Flow Summary

1. **Initialization:** Extension connects to native host on startup, sends `init` command, receives configuration (product type, license status, website scan support).
2. **Secure Search:** On Google/Bing search pages, extracts result URLs from DOM, sends to native host for safety check, receives ratings, displays safety icons.
3. **Website Scan:** On page load (if consent granted + feature enabled), captures page HTML via `outerHTML`, sends to native host for malware/phishing analysis. If the native host returns a "block" verdict, the page is redirected to a blocking page.
4. **Browser Cleanup:** User-initiated browsing data removal (history, cookies, localStorage, etc.) using `chrome.browsingData` API. Supports scheduled auto-cleanup.
5. **EXIF Cleanup:** Notifications about metadata cleanup handled by the ESET desktop product; extension shows notification iframe.
6. **Telemetry/Tracing:** UI interaction events (page opens, button clicks, permission grants) are sent to native host as `trace` commands. These are simple action strings with no browsing content.

## Security Strengths
- **Manifest V3** with service worker (no persistent background page)
- **No remote code loading** -- no eval, no Function constructor, no remote script fetching
- **No obfuscation** -- clean, readable code
- **No direct network requests** -- all communication via native messaging to local ESET product
- **Consent-gated data collection** -- website scanning requires explicit user agreement via `DataCollectionConsentDialog`
- **Shadow DOM** for injected UI elements (prevents style leakage)
- **Chrome Web Store exclusion** in website scan (`websiteScanExcludedList`)

## Overall Risk Assessment

| Risk Level | Justification |
|---|---|
| **CLEAN** | This is a legitimate security companion extension from ESET, a well-known antivirus vendor. While it requests broad permissions (`<all_urls>`, `tabs`, `scripting`) and captures full page HTML for website scanning, all of this is clearly in service of its stated security features. Data flows exclusively to the local native messaging host -- never to remote servers. The website scanning feature requires explicit user consent. There is no obfuscation, no dynamic code execution, no suspicious data exfiltration, no ad injection, no proxy behavior, and no evidence of any malicious intent. The permissions are invasive but justified for a browser security product. |
