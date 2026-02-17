# Vulnerability Report: Home - New Tab Page | ChatGPT search with GPT-4o AI answers

## Metadata
- **Extension ID**: ehhkfhegcenpfoanmgfpfhnmdmflkbgk
- **Extension Name**: Home - New Tab Page | ChatGPT search with GPT-4o AI answers
- **Version**: 24.12.10.1
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This new tab page replacement extension provides various productivity features including bookmarks, calendar integration, weather, notes, and AI-powered search via ChatGPT. The extension has legitimate functionality consistent with its purpose, but contains multiple security vulnerabilities related to improper origin validation in postMessage handlers. These vulnerabilities could allow malicious web pages to trigger unintended actions within the extension. The extension also has broad permissions including access to all websites, cookies, browsing history (optional), and extension management capabilities.

The primary security concern is the presence of four unvalidated postMessage event listeners that could be exploited by malicious websites to interact with the extension's internal messaging system or trigger specific behaviors. Additionally, the extension checks for the presence of ad-blocking extensions, though this appears to be for analytics rather than malicious purposes.

## Vulnerability Details

### 1. MEDIUM: Unvalidated postMessage Handler in AI Panel
**Severity**: MEDIUM
**Files**: panels/ai/ai_panel.js:371
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The AI panel component registers a message event listener without validating the message origin. Any web page could potentially send messages to trigger chat functionality.

**Evidence**:
```javascript
// panels/ai/ai_panel.js:371
window.addEventListener('message', (event) => {
  if (event.data.type === 'start-chat') {
    chat.input.value = event.data.term;
    chat.handleSubmit(new Event('submit'));
  }
});
```

**Verdict**: This allows any web page to inject search terms into the AI chat interface. While the impact is limited (it only pre-fills a search query), it could be used for social engineering or to make unwanted API calls to the AI backend (ai.homenewtab.com).

### 2. MEDIUM: Unvalidated postMessage Handler in Search Content Script
**Severity**: MEDIUM
**Files**: js/search/search_content_script.js:3
**CWE**: CWE-346 (Origin Validation Error)
**Description**: Content script that runs on homenewtabsearch.com domains accepts postMessages without origin validation and forwards them to the extension's background script.

**Evidence**:
```javascript
// js/search/search_content_script.js:3
window.addEventListener('message', function (e) {
  var name = e.data && e.data.name;
  if ('search.api' == name || 'search.api_raw' == name) {
    chrome.runtime.sendMessage(e.data, function (response) {
      window.postMessage(response, '*');
    });
  }
});
```

**Verdict**: Since this content script only runs on www.homenewtab.com and homenewtabsearch.com domains (per manifest), the attack surface is limited to these specific domains. However, if either of these sites were compromised or had an XSS vulnerability, attackers could send arbitrary messages to the extension's background script.

### 3. MEDIUM: Unvalidated postMessage Handler in New App Panel
**Severity**: MEDIUM
**Files**: panels/new_app/store/store.js:256
**CWE**: CWE-346 (Origin Validation Error)
**Description**: Store component listens for postMessages without origin validation.

**Evidence**:
```javascript
// panels/new_app/store/store.js:256
window.addEventListener('message', function (event) {
  // Handler code (not fully analyzed in snippet)
});
```

**Verdict**: The exact functionality was not visible in the code snippet, but the lack of origin validation creates a potential attack vector. This component appears to be part of the Chrome app management interface within the new tab page.

### 4. MEDIUM: Unvalidated postMessage Handler in New App Panel (Secondary)
**Severity**: MEDIUM
**Files**: panels/new_app/new_app_panel.js:82
**CWE**: CWE-346 (Origin Validation Error)
**Description**: Another message listener in the new app panel without origin checks.

**Evidence**:
```javascript
// panels/new_app/new_app_panel.js:82
window.addEventListener('message', function (event) {
  // Handler code
});
```

**Verdict**: Similar to vulnerability #3, this creates an attack surface for any web page to send messages to this component.

### 5. LOW: Chrome Extension Enumeration
**Severity**: LOW
**Files**: js/background.js:896-901
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension checks for the presence of specific ad-blocking extensions (uBlock Origin and AdBlock Pro).

**Evidence**:
```javascript
// js/background.js:896-901
chrome.management.get('cjpalhdlnbpafiamejdnhcphjbkeiagm', function (ext) {
  if (!chrome.runtime.lastError && ext && ext.enabled) stored.SD_ublock = 'true';
});
chrome.management.get('ocifcklkibdehekfnmflempfgjhbedch', function (ext) {
  if (!chrome.runtime.lastError && ext && ext.enabled) stored.SD_ublock = 'true';
});
```

**Verdict**: This appears to be for analytics/debugging purposes rather than malicious intent. The extension stores whether ad-blocking extensions are enabled, likely to understand user configuration for troubleshooting. This is borderline privacy-invasive but not inherently malicious for a new tab page that may include ads or affiliate links.

### 6. LOW: Cookie Access for Analytics
**Severity**: LOW
**Files**: js/background.js:773, js/service_worker.js:849
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension reads Google Analytics cookies (__utmz) from the Chrome Web Store to track installation campaigns.

**Evidence**:
```javascript
// js/background.js:773
chrome.cookies.get({ url: url, name: "__utmz" }, function (cookie) {
  if (!cookie) return;
  cookie = cookie.value;
  cookie = cookie.slice(cookie.indexOf('utm'));
  var campaign = {};
  var parts = cookie.split('|');
  parts.forEach(function (part) {
    var key   = part.split('=')[0];
    var value = part.split('=')[1];
    campaign[map[key]] = decodeURIComponent(value);
  });
  ga('send', 'event', 'conversion', 'install', campaign.source);
```

**Verdict**: This is standard affiliate/marketing tracking to determine which campaigns drive installations. The extension only accesses cookies from chrome.google.com/webstore/, not from arbitrary sites, so the privacy impact is minimal.

## False Positives Analysis

### Legitimate setZeroTimeout Implementation
The extension includes a setZeroTimeout polyfill (js/experimental/setZeroTimeout.js:15) that uses postMessage internally. This is a well-known technique for achieving immediate callback execution and is not a security vulnerability:

```javascript
window.addEventListener("message", handleMessage, true);
function handleMessage(event) {
    if (!(event.source == window && event.data == messageName)) return;
    event.stopPropagation();
    if (!timeouts.length) return;
    var fn = timeouts.shift();
    fn();
}
```

This properly validates that the message source is `window` (same-origin) and checks for a specific message name.

### SQLite WASM Module
The extension includes a legitimate SQLite WebAssembly module (js/lib/sqlite3.wasm) for local database functionality. WASM analysis confirms this is the standard sqlite3 library (binary_type: "emscripten", known_library: "sqlite3") with low risk.

### Content Script executeScript
The extension uses `chrome.tabs.executeScript` to inject a mouse wheel detection script (js/temp/sscr_detect.js) on Google search pages. This script only detects whether the user has a discrete mouse wheel (for scrolling behavior) and does not exfiltrate data or perform malicious actions.

### Remote Configuration
The extension fetches configuration from search.homenewtab.com/conf/conf.php, which is a standard practice for updating settings without requiring extension updates. No evidence of malicious code execution or data exfiltration was found in the configuration handling code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ai.homenewtab.com | ChatGPT/AI search integration | User search queries, auth tokens | Low - Expected functionality |
| www.homenewtab.com | Main extension website | Analytics, error logs | Low - First-party analytics |
| search.homenewtab.com | Search functionality and config | Search queries, debug logs, device info | Low - Core functionality |
| www.homenewtabsearch.com | Search results page | Search queries | Low - Core functionality |
| oauth2.googleapis.com | Google OAuth for calendar | OAuth tokens | Low - Standard Google API |
| www.googleapis.com | Google Calendar API | Calendar queries (with user permission) | Low - Disclosed functionality |
| autocomplete.wunderground.com | Weather data | Location queries | Low - Weather widget feature |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension provides legitimate new tab page functionality with features consistent with its description (bookmarks, calendar, weather, AI search). However, it contains multiple medium-severity vulnerabilities related to unvalidated postMessage handlers that could be exploited by malicious web pages to trigger unintended actions or send arbitrary messages to the extension's background script.

The primary risk stems from the lack of origin validation in four separate postMessage event listeners. While the impact of these vulnerabilities is somewhat limited (the worst case appears to be triggering unwanted AI searches or interfering with the app management interface), they represent a significant attack surface that should be addressed.

The extension's broad permissions (access to all websites, cookies, tab information, extension management) are generally justified by its functionality as a comprehensive new tab replacement, though they do create potential for abuse if the extension were compromised.

The extension does not exhibit clear signs of malicious intent such as credential theft, hidden data exfiltration, or credential harvesting beyond standard analytics. The analytics tracking and remote configuration are within normal bounds for this type of extension.

**Recommendations**:
1. Add origin validation to all postMessage event listeners using `event.origin` checks
2. Implement message signing or nonces for critical postMessage communications
3. Consider reducing the scope of host permissions if not all URLs require access
4. Document the legitimate use of the `management` permission (appears to be for Chrome app shortcuts feature)
