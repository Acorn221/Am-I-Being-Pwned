# Vulnerability Report: Video Downloader Professional

## Metadata
| Field | Value |
|-------|-------|
| **Extension Name** | Video Downloader Professional |
| **Extension ID** | elicpjhcidhpjomhibiffojpinpmmpil |
| **Version** | 2.1.6 |
| **Manifest Version** | 3 |
| **User Count** | ~5,000,000 |
| **Developer** | Link64 GmbH (CLink64GmbH namespace) |
| **Analysis Date** | 2026-02-08 |

## Executive Summary

Video Downloader Professional is a straightforward video detection and download utility. The extension monitors HTTP response headers via `chrome.webRequest.onHeadersReceived` to detect video streams (mp4, webm, m3u8, etc.) and also scans page DOM for video elements and links. It provides a popup/side panel UI for users to download detected videos. The codebase is clean, readable, unobfuscated, and contains no evidence of malicious behavior, data exfiltration, remote code execution, or hidden monetization. All network activity is directly related to its stated purpose of detecting and downloading videos.

## Permissions Analysis

| Permission | Justification | Risk |
|-----------|---------------|------|
| `webRequest` | Monitor HTTP response headers to detect video MIME types | LOW - Core functionality |
| `downloads` | Trigger file downloads via `chrome.downloads.download()` | LOW - Core functionality |
| `tabs` | Get current tab info, send messages to content scripts | LOW - Core functionality |
| `storage` | Store user preferences (side panel mode), download counts, video lists | LOW - Standard |
| `sidePanel` | Show video list in Chrome side panel | LOW - UI feature |
| `host_permissions: https://*/*` | Content script injection + webRequest monitoring on all HTTPS sites | MEDIUM - Broad but required |

**CSP**: No custom CSP defined in manifest. Uses default MV3 CSP which is secure (no remote code execution possible).

## Vulnerability Details

### LOW-1: Content Script Polls Every 500ms

**Severity**: LOW (Performance)
**File**: `content.js` (lines 647-649)
**Code**:
```js
setTimeout(function () { sendAllLinks() }, 300);
setInterval(function () { sendAllLinks() }, 500);
```
**Analysis**: The content script continuously polls the page every 500ms to detect new video links. This is a performance concern (not a security vulnerability). The `sendAllLinks()` function only communicates with the extension's own background script via `chrome.runtime.sendMessage`.
**Verdict**: Performance concern, not a security issue.

### LOW-2: Full Page HTML Read via outerHTML

**Severity**: LOW
**File**: `content.js` (lines 86, 398, 407)
**Code**:
```js
var html = document.documentElement.outerHTML;
```
**Analysis**: The content script reads the full page HTML to scan for video URLs. This data is parsed locally within the content script to extract video URLs - it is NOT sent to any external server. The extracted video URLs are only sent to the extension's own background script.
**Verdict**: Expected behavior for video URL detection. No exfiltration.

### LOW-3: XHR to Page URL for Vimeo Detection

**Severity**: LOW
**File**: `content.js` (lines 535-543, 590-594)
**Code**:
```js
var xmlHttpReq = new XMLHttpRequest();
xmlHttpReq.open("GET", document.location.href, true);
// ...
xmlHttpReq.open("GET", url, true); // url = vimeo config URL
```
**Analysis**: Makes XHR requests only to the current page URL or Vimeo player config URLs to extract video metadata. These are same-origin or Vimeo-specific requests for video detection purposes. No data is sent to any third-party server.
**Verdict**: Legitimate video detection for Vimeo. No data exfiltration.

### INFO-1: Cross-promotion to Video Downloader Ultimate

**Severity**: INFO
**File**: `popup.js` (lines 31-39)
**Code**:
```js
chrome.tabs.create({ "url": "https://videodownloaderultimate.com/?p=capture&msg="+fProtected, ... });
chrome.tabs.create({ "url": "https://videodownloaderultimate.com/?p=m3u8", ... });
```
**Analysis**: When users try to download unsupported formats (m3u8, m4s) or from protected sites (YouTube, Netflix), the extension redirects to the developer's premium product page. This is standard upselling behavior, not malicious.
**Verdict**: Standard upsell, not a vulnerability.

### INFO-2: Review Prompt After Download Count

**Severity**: INFO
**File**: `popup.js` (lines 784-795)
**Code**:
```js
if (count == 10 || count == 50) {
    // prompt user to review on Chrome Web Store
    chrome.tabs.create({ "url": "https://chromewebstore.google.com/detail/video-downloader-professi/elicpjhcidhpjomhibiffojpinpmmpil/reviews", ... });
}
```
**Analysis**: After 10 or 50 downloads, prompts the user to leave a review. Standard engagement pattern.
**Verdict**: Standard engagement UX, not a vulnerability.

## False Positive Table

| Pattern | Location | Reason Not a Vulnerability |
|---------|----------|---------------------------|
| `document.documentElement.outerHTML` | content.js:86 | Only parsed locally for video URL extraction, never exfiltrated |
| `XMLHttpRequest` to current page | content.js:535 | Same-origin request to re-fetch page for Vimeo video detection |
| `fetch(url, { referrer: ref })` | content.js:283 | Used only for Content-Length detection of video files |
| `document.createElement` DOM creation | content.js:8, popup.js:201 | UI element creation for download overlays |
| `chrome.webRequest.onHeadersReceived` | background.js:184 | Monitors response headers to detect video MIME types only |
| `setInterval` polling | content.js:649 | Performance concern only, scans for video links |
| `chrome.storage.local` usage | popup.js, L64P.js | Stores video bookmarks and download counts locally |
| `iframe` creation | addonVDP.js:242 | Embeds video player iframe for playback in startpage |

## API Endpoints Table

| URL | Purpose | Data Sent |
|-----|---------|-----------|
| `https://videodownloaderultimate.com/?p=*` | Cross-promotion for premium product | URL parameter with message type only |
| `https://chromewebstore.google.com/detail/.../reviews` | Review prompt | None |
| `https://player.vimeo.com/video/{id}` | Fetch Vimeo video config | None (GET request) |

**Notable absence**: There are ZERO external telemetry, analytics, tracking, or data collection endpoints. The extension does not phone home at all.

## Data Flow Summary

```
[Web Page]
    |
    ├──> [content.js] Scans page DOM for <video> tags, media links, outerHTML
    |       |
    |       ├──> Extracts video URLs locally (no external communication)
    |       └──> Sends video list to background.js via chrome.runtime.sendMessage
    |
    ├──> [background.js] Monitors HTTP response headers via webRequest API
    |       |
    |       ├──> Detects video MIME types (mp4, webm, m3u8, etc.)
    |       └──> Sends detected videos to content.js via chrome.tabs.sendMessage
    |
    └──> [popup.js / sidepanel.html] Displays detected videos
            |
            ├──> Downloads via chrome.downloads.download() (browser native)
            └──> Stores video bookmarks in chrome.storage.local
```

**Key observations:**
- All inter-component communication uses only `chrome.runtime.sendMessage` / `chrome.tabs.sendMessage`
- All messages verify `sender.id == chrome.runtime.id` (lines: background.js:18, content.js:307, popup.js:559)
- No data is sent to any external server
- No dynamic code execution (`eval`, `new Function`, `importScripts`)
- No obfuscation - code is clean and readable
- No hidden iframes, no script injection into pages
- No cookie access, no browsing history access
- No `chrome.management` (no extension enumeration)
- No proxy/VPN/tunnel infrastructure
- No remote config or kill switch mechanism

## Overall Risk Assessment

| Category | Rating |
|----------|--------|
| **Permissions** | Appropriate for functionality |
| **Data Collection** | None detected |
| **External Communication** | None (except user-triggered navigation to developer site) |
| **Code Quality** | Clean, readable, unobfuscated |
| **Dynamic Code Execution** | None |
| **Obfuscation** | None |
| **Remote Config** | None |

## Overall Risk: CLEAN

This extension is a legitimate video downloader that does exactly what it claims. Despite having broad host permissions (`https://*/*`) and running a content script on all pages, all functionality is directly related to detecting and downloading videos. There is no evidence of data exfiltration, hidden monetization, user tracking, or any malicious behavior. The codebase is clean, well-structured, and unobfuscated. The only external URLs are for cross-promotion of the developer's premium product and Chrome Web Store review prompts, both triggered by explicit user actions.
