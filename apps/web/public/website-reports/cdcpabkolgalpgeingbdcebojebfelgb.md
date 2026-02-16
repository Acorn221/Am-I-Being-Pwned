# Vulnerability Report: Eightify: AI YouTube Summarizer

## Metadata
- **Extension ID**: cdcpabkolgalpgeingbdcebojebfelgb
- **Extension Name**: Eightify: AI YouTube Summarizer
- **Version**: 1.643
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Eightify is a YouTube video summarization extension that uses AI to generate video summaries. The extension collects YouTube video metadata (title, views, transcript, etc.) and sends it to backend servers at eightify.app for processing. While the extension's core functionality appears legitimate for its stated purpose, there are two notable security concerns: a postMessage event listener without origin validation that could allow malicious websites to inject commands, and the collection of YouTube viewing data that is sent to third-party servers.

The extension is assessed as MEDIUM risk due to the postMessage vulnerability and privacy implications of data collection, though there is no evidence of malicious intent.

## Vulnerability Details

### 1. MEDIUM: postMessage Event Listener Without Origin Validation
**Severity**: MEDIUM
**Files**: static/js/content.js:1341
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The content script implements a window.addEventListener("message") handler that processes incoming postMessage events without validating the origin of the sender. This allows any website to send commands to the extension's content script.

**Evidence**:
```javascript
window.addEventListener("message", (function(e) {
  var n = e.data.type,
    r = e.data.startTime,
    o = document.querySelector(".ytp-progress-bar");
  if ("seek" === n && o) // ... handles seek commands
  if ("goto" === n) {
    var v = document.querySelector("video");
    v && (v.currentTime = r, v.play(), window.scrollTo({
      top: 0,
      behavior: "smooth"
    }))
  }
  if ("storage" === n) {
    var p = e.data,
      h = p.key,
      y = p.value;
    chrome.storage.sync.set(u({}, h, y))
  }
  // ... more handlers
}))
```

The handler accepts messages with types: "seek", "goto", "storage", "get-from-storage", "view-port-height", "show-block", "summary-ready", and "height". While most of these commands have limited impact, the "storage" command allows arbitrary writes to chrome.storage.sync, which could be abused.

**Verdict**: This is a legitimate vulnerability. A malicious website could inject a postMessage event to write arbitrary data to the extension's storage, potentially affecting extension behavior. The impact is limited because the storage is isolated to the extension's namespace, but it still represents a security gap.

### 2. LOW: Collection and Transmission of YouTube Viewing Data
**Severity**: LOW
**Files**: static/js/content.js (le function, lines 1283-1340)
**CWE**: CWE-359 (Exposure of Private Personal Information)
**Description**: The extension collects comprehensive YouTube video metadata including video ID, title, view counts, like counts, uploader information, description, tags, and full transcripts, then sends this data to backend.eightify.app.

**Evidence**:
```javascript
var le = function() {
  var e = i(r().mark((function e(t) {
    var n, o, i, a, u, l, c, s, d, f, v, p;
    return r().wrap((function(e) {
      // ... fetches video page, extracts metadata
      return e.next = 21, te((null === (f = c) || void 0 === f || null === (v = f.documentElement) || void 0 === v ? void 0 : v.outerHTML) || "", n);
      // ... sends data including transcript
    }
  // ...
}
```

The static analyzer flagged two exfiltration flows:
- `document.querySelectorAll → fetch(eightify.app)`
- `chrome.storage.sync.get → fetch(eightify.app)`

**Verdict**: This is expected behavior for a video summarization extension - it must send video content to a backend service to generate summaries. The extension's description clearly states it summarizes YouTube videos, which necessarily involves transmitting video metadata. However, users should be aware that their YouTube viewing activity (which videos they summarize) is tracked by the service.

## False Positives Analysis

### Webpack Bundling
The code is minified and appears to use webpack bundling with regenerator-runtime for async/await transpilation. This is standard build tooling, not obfuscation. The static analyzer correctly flagged the code as "obfuscated" but this is webpack minification, not intentional code hiding.

### YouTube API Interaction
The extension fetches YouTube video pages and parses transcript data from YouTube's timedtext API. This is necessary for the core functionality and is not malicious scraping - it's using publicly available YouTube features.

### Iframe Communication
The extension creates an iframe to frontend.eightify.app and communicates with it via postMessage. While this triggers the postMessage handler, the iframe is under the extension's control, so this specific usage is legitimate (though the lack of origin validation remains a vulnerability).

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| backend.eightify.app/event-all | Analytics/telemetry | Extension load events, test configuration | LOW - Basic telemetry |
| backend.eightify.app/onboarding/signin | User onboarding | Opens on install | LOW - User-initiated |
| frontend.eightify.app | Frontend UI | Video ID, language preferences, UI state | MEDIUM - Tracks user activity |
| youtube.com/api/timedtext | Transcript fetching | Video ID | LOW - YouTube's own API |
| youtube.com/watch | Video metadata | Video ID | LOW - Public data |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: The extension performs its stated function (YouTube video summarization) and there is no evidence of malicious behavior. However, it collects and transmits significant amounts of user viewing data to third-party servers, and contains a postMessage vulnerability that could be exploited by malicious websites to manipulate extension storage. The extension would benefit from:

1. Adding origin validation to the postMessage listener (check e.origin)
2. Being more transparent about what data is collected and sent to backend servers
3. Potentially implementing client-side caching to reduce backend requests

The MEDIUM rating reflects the combination of the postMessage vulnerability (which has limited but real exploit potential) and the privacy implications of comprehensive YouTube viewing data collection. For users who are comfortable with cloud-based AI services, this extension operates within expected parameters, but privacy-conscious users should be aware of the data collection scope.
