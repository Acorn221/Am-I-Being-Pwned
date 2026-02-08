# Vulnerability Report: MP3 Converter & Downloader

## Extension Metadata
- **Extension Name**: MP3 Converter & Downloader
- **Extension ID**: ekgllcpppdjkaagfjhdoeacdbihbmban
- **Approximate Users**: ~50,000
- **Manifest Version**: 3
- **Version**: 1.1.2

## Executive Summary

MP3 Converter & Downloader is a legitimate media conversion extension that uses FFmpeg (via WebAssembly) to convert audio/video files to MP3 format. The extension implements privacy-invasive analytics tracking and requests broad permissions that exceed typical media conversion requirements. While the core functionality appears benign, the extension exhibits concerning permission requests and third-party data collection practices.

**Overall Risk Level**: **MEDIUM**

## Vulnerability Details

### 1. Excessive Host Permissions - MEDIUM Severity

**Description**: The extension requests `*://*/*` (all URLs) host permissions, which grants access to all websites the user visits.

**Evidence**:
- **File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/ekgllcpppdjkaagfjhdoeacdbihbmban/deobfuscated/manifest.json`
- **Lines**: 39
```json
"host_permissions": ["*://*/*"]
```

**Analysis**: For a media converter extension, all-URLs access is excessive. The extension only needs to:
1. Intercept YouTube video requests (`https://*.googlevideo.com/videoplayback`)
2. Download user-provided media URLs via explicit permission requests

**Verdict**: CONFIRMED - Overly broad permissions that violate least-privilege principle. The extension should use `activeTab` permission or request specific origins dynamically.

---

### 2. Google Analytics Tracking Without User Consent - MEDIUM Severity

**Description**: The extension sends installation events and pageview tracking to Google Analytics without user consent or disclosure.

**Evidence**:
- **File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/ekgllcpppdjkaagfjhdoeacdbihbmban/deobfuscated/background.js`
- **Lines**: 1876-1883
```javascript
r = "http://www.google-analytics.com/collect",
n = "UA-227235920-1",
i = e,
chrome.runtime.onInstalled.addListener((function(t) {
  fetch(r, {
    method: "POST",
    body: "v=1&tid=".concat(n, "&cid=").concat(i, "&t=event&ec=install&ea=").concat(t.reason)
  })
})),
fetch(r, {
  method: "POST",
  body: "v=1&tid=".concat(n, "&cid=").concat(i, "&t=pageview&dp=bg")
})
```

**Tracking Data Collected**:
- Persistent UUID stored in `chrome.storage.local` (line 1874)
- Installation reason (install/update)
- Background page "pageview" events
- Tracking ID: UA-227235920-1

**Verdict**: CONFIRMED - The extension implements undisclosed analytics tracking. While not directly malicious, this represents a privacy concern and violates user expectations for offline media conversion tools.

---

### 3. YouTube Video URL Interception - LOW Severity

**Description**: The extension monitors YouTube video playback requests to extract audio URLs.

**Evidence**:
- **File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/ekgllcpppdjkaagfjhdoeacdbihbmban/deobfuscated/background.js`
- **Lines**: 1766-1780
```javascript
chrome.webRequest.onBeforeRequest.addListener((function(t) {
  if (t.type, /mime=audio/.test(t.url)) {
    var e = a(t.url.split("?"), 2),
      r = e[0],
      o = e[1],
      n = l().parse(o);
    delete n.range;
    var i = "".concat(r, "?").concat(l().stringify(n));
    v !== n.id && (v = n.id, chrome.tabs.sendMessage(t.tabId, {
      type: "send_audio_mp3",
      url: i
    }).catch((function() {})))
  }
}), {
  urls: ["https://*.googlevideo.com/videoplayback?*"]
})
```

**Analysis**: The extension intercepts YouTube's CDN requests to extract audio stream URLs for conversion. This is legitimate functionality for the extension's stated purpose (YouTube audio downloading). The URL filtering is appropriately scoped to Google's video servers only.

**Verdict**: BENIGN - This is expected functionality for a YouTube audio extractor. No evidence of URL exfiltration beyond local processing.

---

### 4. WebAssembly-Based Audio Processing - LOW Severity

**Description**: The extension uses FFmpeg compiled to WebAssembly for local audio conversion.

**Evidence**:
- **File**: `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/ekgllcpppdjkaagfjhdoeacdbihbmban/deobfuscated/assets/decoder/decoder.wasm`
- **Size**: 9.45 MB
- **Type**: WebAssembly binary module version 0x1 (MVP)
- **Reference**: https://github.com/chandler-stimson/decoder.js/releases/tag/0.1.0

**Analysis**: The WASM module appears to be a legitimate FFmpeg build for browser-based media decoding. The decoder runs in a sandboxed context (`sandbox.pages` in manifest) and processes files entirely client-side. No evidence of remote code execution or data exfiltration through the WASM layer.

**Verdict**: BENIGN - Standard implementation of client-side media processing using well-known FFmpeg library.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `Function("return this")()` | background.js:1625 | Polyfill for detecting global object in webpack bundle |
| `new Function(...)` | background.js:99 | Legitimate bind() polyfill implementation |
| `innerHTML` | convert/convert.js:9 | SVG icon injection (static content, no user input) |
| `document.write` | convert/convert.js:11 | SVG stylesheet injection in controlled context |
| `postMessage` | assets/decoder/api.js:22,38,44,55 | Sandboxed iframe communication for FFmpeg processing |
| `XMLHttpRequest` | content/youtube.js:11 | Content type detection for media URLs |
| `WebAssembly` | assets/decoder/decoder.js:54-55 | FFmpeg WASM module instantiation |

---

## API Endpoints

| Endpoint | Purpose | Data Sent | Method |
|----------|---------|-----------|--------|
| `http://www.google-analytics.com/collect` | Analytics tracking | UUID, install reason, pageviews | POST |
| `https://*.googlevideo.com/videoplayback?*` | YouTube CDN (intercepted) | None (monitored only) | GET |

---

## Data Flow Summary

### Data Collection
1. **Persistent Identifier**: UUID generated and stored in `chrome.storage.local.uuid`
2. **Install Timestamp**: Installation time stored in `chrome.storage.local.installTime`
3. **Analytics Events**: Install reason and background page activity sent to Google Analytics

### Data Processing
1. **Media URLs**: Extracted from YouTube requests, processed locally
2. **Audio/Video Files**: Decoded using FFmpeg WASM, converted to MP3
3. **ID3 Tags**: User-provided metadata embedded in MP3 files using browser-id3-writer library

### Data Transmission
1. **Outbound**: Only Google Analytics tracking (UUID, install events)
2. **No Exfiltration**: Media files, URLs, and user content remain local

---

## Chrome API Usage Analysis

### Legitimate Usage
- `chrome.downloads`: Save converted MP3 files (with shelf management)
- `chrome.contextMenus`: Right-click "Extract media files to MP3" menu
- `chrome.storage.local`: Persist UUID and install timestamp
- `chrome.webRequest`: Monitor YouTube audio stream requests
- `chrome.permissions`: Request origins dynamically for user-provided URLs
- `chrome.tabs.sendMessage`: Communicate with content scripts
- `chrome.windows`: Manage popup converter window
- `chrome.runtime.onInstalled`: Track install/update events

### Concerning Usage
- **Excessive host_permissions**: `*://*/*` grants unnecessary global access
- **Google Analytics**: Third-party tracking without consent

---

## Overall Risk Assessment

**Risk Level**: **MEDIUM**

### Risk Factors
1. **Privacy**: Google Analytics tracking without disclosure (MEDIUM)
2. **Permissions**: Overly broad host permissions (MEDIUM)
3. **Data Exposure**: Minimal - no evidence of content exfiltration (LOW)
4. **Functionality**: Core features are legitimate and work as advertised (CLEAN)

### Mitigating Factors
1. Client-side processing - no media files uploaded to servers
2. Limited network activity (only GA tracking)
3. No evidence of malicious code injection or content manipulation
4. Uses legitimate open-source libraries (FFmpeg, browser-id3-writer)
5. Manifest V3 with appropriate sandboxing for WASM processing

### Recommendations
1. **For Users**: Be aware of analytics tracking; extension functions as advertised but collects usage telemetry
2. **For Developer**:
   - Replace `*://*/*` with `activeTab` permission
   - Implement opt-in analytics with disclosure
   - Disclose Google Analytics tracking in privacy policy
3. **For Chrome Web Store**: Request justification for all-URLs host permission

---

## Conclusion

MP3 Converter & Downloader is a functional media conversion tool that raises moderate privacy concerns due to undisclosed analytics tracking and excessive permissions. The core functionality (FFmpeg-based audio conversion) is implemented cleanly without malicious behavior. However, the broad host permissions and silent analytics collection violate privacy best practices.

**Classification**: Privacy-invasive but not malicious

**Recommended Action**: Monitor for permission abuse; notify users of tracking practices
