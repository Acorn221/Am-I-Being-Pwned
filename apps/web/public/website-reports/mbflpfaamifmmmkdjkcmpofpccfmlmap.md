# Vulnerability Report: Video Downloader - MPMux

## Metadata
- **Extension ID**: mbflpfaamifmmmkdjkcmpofpccfmlmap
- **Extension Name**: Video Downloader - MPMux
- **Version**: 1.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Video Downloader - MPMux is a video downloading extension that intercepts media requests across all websites and allows users to download video files. The extension operates as advertised - it monitors HTTP requests for video content (mp4, m3u8, webm, etc.) and provides a download interface through the mpmux.com website. While the extension has broad permissions and intercepts all web traffic, the analysis reveals no malicious behavior, data exfiltration, or privacy violations. The extension's functionality is legitimate and transparent, with all captured video metadata sent only to the user's local browser interface or the legitimate mpmux.com download portal operated by the extension developer.

## Vulnerability Details

### 1. LOW: Overly Broad Permissions for Legitimate Functionality
**Severity**: LOW
**Files**: manifest.json, background.js
**CWE**: N/A (not a vulnerability, but a design consideration)
**Description**: The extension requests host permissions for `http://*/*` and `https://*/*`, as well as webRequest API access. While this appears excessive, it is functionally necessary for a video downloader that needs to intercept media requests across all websites.

**Evidence**:
```json
"host_permissions": ["http://*/*", "https://*/*"],
"permissions": ["tabs", "webRequest", "storage", "declarativeNetRequest"]
```

The background.js monitors all network requests:
```javascript
CHROME.webRequest.onBeforeSendHeaders.addListener((function(t){...}),
  {urls:["<all_urls>"], types:["media","xmlhttprequest","object","other"]},
  ["requestHeaders","extraHeaders"])
```

**Verdict**: NOT MALICIOUS - These permissions are necessary and expected for a video downloader to detect video resources across any website. The extension transparently discloses its purpose as a "professional online video downloader."

### 2. LOW: Content Script Injection on All Pages
**Severity**: LOW
**Files**: manifest.json, js/content-listener.js, js/proxy.js
**CWE**: N/A
**Description**: The extension injects a content script (`content-listener.js`) into all pages at document_start and makes `js/proxy.js` web-accessible. This is used to hook MediaSource API for recording HLS streams.

**Evidence**:
```json
{
  "all_frames": true,
  "matches": ["*://*/*"],
  "exclude_globs": ["*//*.mpmux.com/*", "*//mpmux.com/*"],
  "js": ["js/content-listener.js"],
  "run_at": "document_start"
}
```

The proxy.js hooks MediaSource API:
```javascript
window.MediaSource = new Proxy(o, {
  construct(o, a) {
    const d = new o(...a);
    d.addSourceBuffer = new Proxy(d.addSourceBuffer, {
      apply(o, a, i) {
        // Intercepts appendBuffer to capture HLS segments
      }
    })
  }
})
```

**Verdict**: NOT MALICIOUS - This is standard functionality for capturing streaming video (HLS/DASH). The intercepted data is only sent to the extension's own download interface via BroadcastChannel, not to external servers.

## False Positives Analysis

1. **All URL Monitoring**: While the extension monitors all web requests, this is the core functionality of a video downloader. The extension only stores video-related requests (specific MIME types and file extensions) and excludes its own domain (mpmux.com).

2. **MediaSource API Hooking**: The proxy.js hooks the MediaSource API, which could be flagged as "code injection" or "API hooking." However, this is a legitimate technique for capturing streaming video segments that are not directly downloadable. The data captured stays within the browser and is only sent to the extension's download interface.

3. **External Domain Communication**: The extension communicates with mpmux.com, but this is the developer's legitimate download portal where users are redirected to download videos. No sensitive user data is transmitted - only video metadata (URL, size, format).

4. **Obfuscation Flag**: The static analyzer flagged the code as "obfuscated," but this appears to be minified/bundled code rather than intentional obfuscation for malicious purposes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| mpmux.com | Download portal | Video metadata (URL, filename, size, headers) | LOW - Legitimate functionality |
| v1.mpmux.com | Fallback download portal | Same as above | LOW - Legitimate functionality |
| ../options.json | Extension configuration | None (fetch only) | CLEAN - Local resource |

The extension includes a fallback check:
```javascript
try {
  await fetch("https://mpmux.com/v1.json")
} catch(t) {
  if ("TypeError" === t.name) {
    n.site = "https://v1.mpmux.com"
  }
}
```

This is a simple availability check, not data exfiltration.

## Privacy Analysis

The extension does NOT:
- Send browsing history to external servers
- Track user behavior
- Inject ads or affiliate links
- Modify page content (except for MediaSource hooking on user-initiated recording)
- Access cookies, passwords, or authentication tokens
- Enumerate other extensions

The extension DOES:
- Monitor network requests for video content (disclosed functionality)
- Store video metadata locally in chrome.storage.local
- Send video URLs to mpmux.com when user clicks download (expected behavior)
- Capture video segments during "recording mode" (user-initiated, disclosed feature)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension operates exactly as advertised with no malicious behavior detected. While it has broad permissions and monitors all web traffic, these capabilities are necessary and appropriate for a video downloader. The extension:

1. Has a clear, legitimate purpose (video downloading)
2. Does not collect or exfiltrate user data beyond its stated functionality
3. Only communicates with the developer's legitimate download portal (mpmux.com)
4. Stores captured video data locally and only on user-initiated download actions
5. Excludes certain sites from monitoring (YouTube, Globo) likely due to copyright/legal considerations
6. Provides transparent controls (file size filter, download/record options)

The extension has 200,000 users with a 4.9/5 rating, suggesting a legitimate, well-maintained product. No evidence of malware, tracking, or privacy violations was found. The "obfuscated" flag from static analysis appears to be false - the code is minified but readable after deobfuscation, with clear variable names and logic flow.

All network interception is limited to video-related resources, and the extension appropriately checks content types, file sizes, and response headers to identify downloadable media. The MediaSource hooking in proxy.js is a standard technique for HLS/DASH stream recording and does not indicate malicious intent.
