# Vulnerability Report: Push to Kindle

## Metadata
- **Extension ID**: pnaiinchjaonopoejhknmgjingcnaloc
- **Extension Name**: Push to Kindle
- **Version**: 2.6.6
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Push to Kindle is a legitimate Chrome extension that sends web articles to Kindle devices. The extension demonstrates **clean security practices** with minimal permissions, transparent data flow, and no malicious behavior. The extension uses only essential Chrome APIs (`activeTab`, `scripting`) and sends page content to the official Five Filters Push to Kindle service at `pushtokindle.fivefilters.org`.

**Overall Risk Level: CLEAN**

## Vulnerability Analysis

### 1. Permissions Analysis - CLEAN

**Severity**: N/A
**Files**: `manifest.json`

The extension requests only two permissions:
- `activeTab` - Access to the currently active tab (minimal scope)
- `scripting` - Required to inject content scripts

**Code**:
```json
"permissions": [
  "activeTab",
  "scripting"
]
```

**Verdict**: ✅ CLEAN - Minimal permissions appropriate for functionality. No broad permissions like `<all_urls>`, `tabs`, `cookies`, `webRequest`, or storage access.

### 2. Content Security Policy - CLEAN

**Severity**: N/A
**Files**: `manifest.json`

**Verdict**: ✅ CLEAN - No custom CSP defined, using secure Manifest V3 defaults which prohibit inline scripts and `eval()`.

### 3. Data Collection & Transmission - CLEAN

**Severity**: N/A
**Files**: `background.js` (lines 37-57), `inject.js` (lines 34-62)

The extension collects page content and sends it to Five Filters' service:

**Code** (`inject.js`):
```javascript
var bodyCopy = window.document.cloneNode(true);
var loader;
if (loader = bodyCopy.getElementById('ffpushtokindleloader')) loader.parentNode.removeChild(loader);
['script', 'style', 'canvas', 'select', 'textarea'].forEach(function(tagName) {
    var elems = bodyCopy.getElementsByTagName(tagName);
    for (var i = elems.length-1; i >= 0; i--) {
        if (tagName === 'script' && elems[i].getAttribute('type') === 'application/ld+json') {
            // preserve ld+json elements
        } else {
            elems[i].parentNode.removeChild(elems[i]);
        }
    }
});
var sending = browser.runtime.sendMessage({
    "url": window.location.href,
    "content": bodyCopy.documentElement.outerHTML
});
```

**Code** (`background.js`):
```javascript
async function postData(url = '', data = '') {
  url = 'https://pushtokindle.fivefilters.org/send.php?url='+encodeURIComponent(url);
  const response = await fetch(url, {
    method: 'POST',
    mode: 'cors',
    cache: 'no-cache',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    },
    redirect: 'manual',
    referrerPolicy: 'no-referrer',
    body: new URLSearchParams({
      'json': '1',
      'inputhtml': data
    })
  });
  return response.json();
}
```

**Verdict**: ✅ CLEAN - Data transmission is **core to the intended functionality**. The extension:
1. Only activates when user clicks the extension button
2. Strips scripts, styles, canvases, and form elements from the page copy
3. Preserves LD+JSON metadata for article extraction
4. Sends sanitized HTML to the legitimate Five Filters service
5. Uses HTTPS with secure headers (`no-referrer` policy, CORS mode)
6. No evidence of exfiltration to third parties

### 4. Remote Code Execution Risk - CLEAN

**Severity**: N/A
**Files**: All JavaScript files analyzed

**Verdict**: ✅ CLEAN - No use of `eval()`, `Function()`, dynamic script injection, or WebAssembly. The extension uses static code only.

### 5. Chrome API Usage - CLEAN

**Severity**: N/A
**Files**: `background.js`

Chrome APIs used:
- `chrome.action.onClicked` - Responds to extension icon clicks
- `chrome.scripting.executeScript` - Injects content script to extract page content
- `chrome.tabs.update` - Redirects to Push to Kindle service on injection errors
- `browser.runtime.sendMessage/onMessage` - Communication between content and background scripts (via polyfill)

**Verdict**: ✅ CLEAN - All API usage is appropriate for the extension's purpose. No sensitive APIs like `cookies`, `webRequest`, `history`, or `downloads`.

### 6. Third-Party Dependencies - CLEAN

**Severity**: N/A
**Files**: `browser-polyfill.min.js`

The extension includes Mozilla's official WebExtension Polyfill (887 lines) to provide cross-browser compatibility.

**Verdict**: ✅ CLEAN - Standard, well-known library from Mozilla. No suspicious third-party SDKs or tracking libraries detected.

### 7. Obfuscation Analysis - CLEAN

**Severity**: N/A
**Files**: All files

**Verdict**: ✅ CLEAN - Main extension code is clearly written and readable. Only the polyfill is minified (expected for production libraries). No obfuscation detected.

## False Positives

| Pattern | File | Reason |
|---------|------|--------|
| N/A | N/A | No false positives - extension is clean |

## API Endpoints

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://pushtokindle.fivefilters.org/send.php` | POST | Send article to Kindle | URL parameter: current page URL<br>POST body: `json=1&inputhtml=[sanitized HTML]` |

## Data Flow Summary

1. **User Action**: User clicks extension icon while browsing a web page
2. **Content Script Injection**: `background.js` injects `inject.js` into the active tab
3. **Page Extraction**: Content script clones the DOM, removes scripts/styles/forms, preserves article content
4. **Message Passing**: Content script sends sanitized HTML + URL to background script
5. **API Request**: Background script POSTs data to Five Filters service
6. **Redirect**: User is redirected to Push to Kindle web interface to complete sending to Kindle

**Data Collected**:
- Current page URL
- Sanitized page HTML (scripts/styles removed)

**Data Recipients**:
- `pushtokindle.fivefilters.org` (Five Filters service - intended functionality)

**User Control**: Extension only activates on explicit user click - no automatic data collection.

## Attack Surface

1. **Dependency on External Service**: Extension relies on Five Filters' service remaining trustworthy
2. **No Input Validation**: Page content is sent without validation (though this is expected for article conversion)
3. **Error Handling**: On script injection failure, falls back to redirecting user with URL parameter (potential for URL manipulation in edge cases, but low risk)

## Overall Risk Assessment

**Risk Level: CLEAN**

Push to Kindle is a legitimate, well-designed extension that serves its stated purpose without malicious behavior. The extension:

- Uses minimal permissions appropriate for functionality
- Only activates on explicit user interaction
- Sends data exclusively to the legitimate Five Filters Push to Kindle service
- Contains no tracking SDKs, analytics, or third-party integrations
- Uses no obfuscation or dynamic code execution
- Implements secure coding practices (HTTPS, referrer policies, CORS)
- Sanitizes collected data by removing scripts and sensitive elements

The extension's data transmission is **core to its intended functionality** (sending articles to Kindle) and is transparent to users. There are no hidden behaviors, credential harvesting, unauthorized tracking, or security vulnerabilities.

**Recommendation**: This extension is safe for use.
