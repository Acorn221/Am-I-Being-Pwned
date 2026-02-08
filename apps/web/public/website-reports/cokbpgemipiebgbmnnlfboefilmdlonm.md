# Vulnerability Report: Trellix DLP Endpoint Extension

## Metadata
| Field | Value |
|---|---|
| **Extension Name** | Trellix DLP Endpoint Extension |
| **Extension ID** | cokbpgemipiebgbmnnlfboefilmdlonm |
| **Version** | 1.21 |
| **Manifest Version** | 3 |
| **Author** | Trellix LLC |
| **User Count** | ~7,000,000 |
| **Files Analyzed** | manifest.json, background.js, content.js |

## Executive Summary

Trellix DLP Endpoint Extension is a legitimate enterprise Data Loss Prevention (DLP) agent from Trellix (formerly McAfee Enterprise). It is designed to monitor user browsing activity, intercept file uploads, capture page text content, and relay all of this information to a local native messaging host (`com.trellix.dlp_native_messaging_host`) which connects to the corporate DLP infrastructure.

The extension is **extremely invasive by design** -- it monitors every URL visited, intercepts all POST/PUT/PATCH request bodies, captures file upload metadata, can read full page text on demand, and can block web requests based on a remotely-configured blocklist. However, all of this behavior is consistent with its stated purpose as an enterprise DLP endpoint agent. The data flows exclusively to a local native messaging host (not to any remote server directly), and the blocking configuration is received from the same native host.

There is **no evidence of malicious behavior**, no obfuscated code, no remote code execution, no external network calls, no third-party SDK injection, and no credential harvesting beyond what is expected for a DLP product. The code is clean, readable, and well-structured.

## Vulnerability Details

### 1. Full Page Text Exfiltration to Native Host
- **Severity**: INFORMATIONAL (expected DLP behavior)
- **File**: `content.js` (lines 17-22), `background.js` (lines 46-66)
- **Code**:
  ```js
  // content.js - responds with entire page text
  sendResponse({ 'pagetext': { 'window_location': window.location.href, 'id': msg.pagetext.id, 'text': document.body.innerText } });

  // background.js - forwards to native host
  port.postMessage(response);
  ```
- **Verdict**: Expected DLP behavior. The native host requests page text to perform content inspection for sensitive data (PII, classified info, etc.). Data goes only to the local native messaging host, not to any external server.

### 2. Full HTTP POST/PUT/PATCH Body Capture
- **Severity**: INFORMATIONAL (expected DLP behavior)
- **File**: `background.js` (lines 268-332)
- **Code**:
  ```js
  // Captures raw request body bytes from ALL POST/PUT/PATCH requests
  for (var j = 0; j < dv.byteLength; ++j) {
      payload += (String.fromCharCode(dv.getInt8(j)));
  }
  requestsMap.set(details.requestId, payload);

  // Sends captured payloads to native host
  port.postMessage({ 'post': { 'url': decodeURIComponent(details.url), 'payload': payload } });
  ```
- **Verdict**: Expected DLP behavior. Captures outbound data to check for sensitive content before it leaves the corporate network. All data is sent to the local native host only.

### 3. URL Blocking via Remote Configuration
- **Severity**: LOW
- **File**: `background.js` (lines 67-74, 105-186, 298-309)
- **Code**:
  ```js
  // Receives blocklist config from native host
  if (msg.nmConfig) {
      nmConfig = msg.nmConfig;
      chrome.storage.local.set({"nmConfig": msg.nmConfig}, () => { ... });
  }

  // Blocks matching URLs
  return { cancel: urlBlocked };
  ```
- **Verdict**: The native host can push a URL blocklist that the extension enforces via `webRequest.onBeforeRequest`. This is standard DLP/web filtering behavior. The configuration comes from the local native host (controlled by corporate IT), not from an arbitrary remote server. LOW risk because a compromised native host could potentially be used to block arbitrary URLs, but this is an inherent property of native messaging-based DLP.

### 4. Comprehensive URL Monitoring
- **Severity**: INFORMATIONAL (expected DLP behavior)
- **File**: `background.js` (lines 346-432)
- **Code**:
  ```js
  // Monitors every tab activation, focus change, URL update, and navigation
  chrome.tabs.onActivated.addListener(...)
  chrome.windows.onFocusChanged.addListener(...)
  chrome.tabs.onUpdated.addListener(...)
  chrome.webNavigation.onHistoryStateUpdated.addListener(...)
  chrome.webNavigation.onCommitted.addListener(...)
  chrome.webNavigation.onBeforeNavigate.addListener(...)
  chrome.tabs.onRemoved.addListener(...)
  ```
- **Verdict**: All visited URLs are sent to the native host. This is core DLP functionality for monitoring web activity.

### 5. File Upload Monitoring (Input, Drop, Change Events)
- **Severity**: INFORMATIONAL (expected DLP behavior)
- **File**: `content.js` (lines 36-191)
- **Code**:
  ```js
  // Monitors file inputs, drag-and-drop, change events
  // Captures file name, size, and last modified date
  chrome.runtime.sendMessage({ 'inputfile': { name: fName, size: fSize, modification: fModification }, urlFromCS: window.location.href });
  ```
- **Verdict**: Tracks file upload attempts across all pages, including shadow DOM elements. Metadata (name, size, modification date) is relayed to the background script and then to the native host. This is expected behavior for preventing unauthorized file uploads.

### 6. Content Script Injection into All Tabs
- **Severity**: INFORMATIONAL (expected DLP behavior)
- **File**: `background.js` (lines 87-102, 245-264)
- **Code**:
  ```js
  // Injects content script into all existing tabs on startup
  chrome.tabs.query({}).then(forEachTabs);

  // Re-injects on tab activation/navigation if not already present
  function injectCStoTab(tabinfo) { ... }
  ```
- **Verdict**: Ensures the content script is running in every tab for complete DLP coverage. The injection check (`isThere` message) prevents duplicate injection.

### 7. webRequestBlocking Permission in MV3
- **Severity**: INFORMATIONAL
- **File**: `manifest.json` (line 34)
- **Note**: The extension uses `webRequestBlocking` which is deprecated in Manifest V3 for normal extensions. Trellix likely has an enterprise policy exception that allows this permission to function. This is a legitimate enterprise capability.

## False Positive Table

| Pattern | Location | Reason |
|---|---|---|
| `document.body.innerText` capture | content.js:20 | DLP page content inspection - not keylogging or scraping |
| POST body interception | background.js:268-332 | DLP outbound data inspection - not credential theft |
| `<all_urls>` host permission | manifest.json:39 | Required for enterprise-wide DLP monitoring |
| URL monitoring on all events | background.js:346-450 | Standard DLP URL tracking |
| `nativeMessaging` permission | manifest.json:36 | Communication with local DLP agent - not C2 |
| File metadata collection | content.js:36-47 | DLP file upload monitoring - not exfiltration |
| Shadow DOM traversal | content.js:194-286 | Ensures file input monitoring in web components |

## API Endpoints Table

| Endpoint / Channel | Type | Purpose | Data Sent |
|---|---|---|---|
| `com.trellix.dlp_native_messaging_host` | Native Messaging | Local DLP agent communication | URLs, page text, file metadata, POST payloads, navigation events |
| `chrome.storage.local` | Local Storage | Persist nmConfig | URL blocklist configuration |

**Note**: This extension makes **zero external network requests**. All data flows to a local native messaging host only.

## Data Flow Summary

```
[Every Web Page]
    |
    +--> content.js (injected into all frames)
    |       |
    |       +--> Monitors file <input>, drag-drop, change events -> file metadata
    |       +--> Responds to pagetext requests -> full document.body.innerText
    |       +--> Reports current URL on request
    |
    +--> background.js (service worker)
            |
            +--> webRequest.onBeforeRequest -> captures POST/PUT/PATCH bodies
            |                                -> blocks URLs per nmConfig blocklist
            +--> tabs.onActivated/onUpdated  -> reports all URL changes
            +--> webNavigation.*             -> reports all navigation events
            +--> tabs.onRemoved              -> reports tab closures
            |
            +--> ALL DATA --> chrome.runtime.connectNative('com.trellix.dlp_native_messaging_host')
                              (local native messaging host = Trellix DLP endpoint agent)

            <-- nmConfig (blocklist, settings) received FROM native host
            <-- pagetext requests received FROM native host
```

## Overall Risk Assessment

**Risk: CLEAN**

This extension is a legitimate enterprise Data Loss Prevention (DLP) endpoint agent from Trellix (formerly McAfee Enterprise, a major cybersecurity vendor). While it is extremely invasive -- monitoring all URLs, capturing full page text, intercepting all POST/PUT/PATCH request bodies, tracking file uploads, and capable of blocking URLs -- all of this behavior is **precisely what a DLP endpoint extension is designed to do**.

Key factors supporting CLEAN assessment:
1. **No external network calls** -- All data flows to a local native messaging host only, not to any remote server
2. **No obfuscation** -- Code is clean, readable, and well-commented with proper copyright headers
3. **No dynamic code execution** -- No eval(), no Function(), no remote script loading
4. **No credential harvesting** -- No form field monitoring, no password capture, no cookie access
5. **No third-party SDKs** -- No analytics, no market intelligence, no ad injection
6. **Configuration from trusted source** -- Blocklist comes from local native host (corporate IT-controlled)
7. **Legitimate vendor** -- Trellix LLC is a well-known enterprise cybersecurity company (successor to McAfee Enterprise + FireEye)
8. **Enterprise deployment** -- 7M users is consistent with large enterprise rollouts via managed Chrome policies
9. **Minimal codebase** -- Only 2 JS files with clear, purposeful logic; no hidden functionality
