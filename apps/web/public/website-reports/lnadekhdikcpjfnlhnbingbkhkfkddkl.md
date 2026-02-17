# Vulnerability Report: Robots Exclusion Checker

## Metadata
- **Extension ID**: lnadekhdikcpjfnlhnbingbkhkfkddkl
- **Extension Name**: Robots Exclusion Checker
- **Version**: 1.2.0.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Robots Exclusion Checker is a legitimate SEO extension designed to check robots.txt rules, meta robots tags, and x-robots-tag headers for web pages. The extension analyzes whether search engines can crawl and index URLs based on these exclusion rules. The code contains development infrastructure (localhost references, debug logging) that is properly gated behind a mode flag hardcoded to "prod", making it inactive in production. The primary security concern is the use of postMessage handlers without origin validation, though these are part of an internal cross-component communication protocol rather than accepting external messages.

The extension's stated purpose aligns with its actual behavior: it monitors page navigation, fetches robots.txt files, parses meta tags, and displays the results in a popup interface. Data is processed locally with no evidence of undisclosed data collection.

## Vulnerability Details

### 1. MEDIUM: postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: extension_content.js, extension_background.js, extension_popup.js
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension implements a custom window messaging protocol for cross-component communication (content script ↔ popup, content script ↔ background). All three components register message listeners using `window.addEventListener("message")` without validating `event.origin`.

**Evidence**:
```javascript
// extension_content.js:168
e.addEventListener("message", (async e => {
  if (e.data) {
    let t = e.data.name,
      r = e.data.meta,
      s = e.data.data;
    "exec_result" === t && r && r.response && a[r.request_id] && a[r.request_id](s.result)
  }
}))

// extension_content.js:192
window.addEventListener("message", (async t => {
  if (t.data) {
    let r = t.data.name,
      s = t.data.meta,
      o = t.data.data;
    if (e[r]) {
      // executes API methods based on message name
    }
  }
}))

// postMessage usage:
t.postMessage({
  name: e,
  meta: n,
  data: r
}, "*")  // wildcard origin
```

The static analyzer flagged 9 cross-component flows involving these handlers. While the messages follow a custom protocol with `name`, `meta`, and `data` fields, the lack of origin checking means a malicious web page could potentially send crafted messages to trigger internal API methods.

**Verdict**: This is a genuine vulnerability, though exploitation risk is limited by the custom protocol structure. The handlers check for specific message structures (`exec_result`, presence of `request_id`, etc.) which provides some protection. However, if the internal API methods (`e[r]`) are not sufficiently defensive, a crafted message could trigger unintended behavior.

## False Positives Analysis

### Development Infrastructure
The static analyzer flagged localhost:2010 and vuejs.org references as potential data exfiltration. These are false positives:

1. **localhost:2010**: Used only in development mode
   ```javascript
   // Line 68
   return "dev" === this.config.mode ? "http://localhost:2010/" : chrome.runtime.getURL("/pages/app/index.html")
   ```
   The config is hardcoded to `"mode":"prod"` (line 3), making localhost references unreachable.

2. **vuejs.org**: Part of Vue.js framework error reporting (line 4358 in popup), not actual data transmission.

3. **Obfuscation flag**: The code is webpack-bundled (minified variable names), not obfuscated. This is standard build tooling.

### Legitimate Functionality
- Content script on `<all_urls>`: Required to analyze any webpage's robots exclusion rules
- Storage permission: Stores user settings (user agent preference, link highlighting colors)
- Host permission for checkrobots.com: Opens activation page on install (line 356-358)
- XHR requests: Fetches robots.txt files from the current page's domain (legitimate SEO analysis)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.checkrobots.com/activation | Activation page on install | None (navigation only) | None |
| (current domain)/robots.txt | SEO analysis | None (GET request) | None |

The extension only communicates with:
1. The activation page (one-time on install)
2. robots.txt files on domains the user visits (for its core functionality)

No user data, browsing history, or sensitive information is transmitted to external servers.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
- The extension performs its stated function (robots.txt checking) without hidden behavior
- No evidence of data exfiltration, tracking, or privacy violations
- Development code is properly gated and inactive in production
- The postMessage vulnerability is real but limited in scope due to the custom protocol structure and the fact that the handlers are part of internal extension communication rather than accepting arbitrary external messages
- Standard permissions appropriate for an SEO analysis tool
- Open-source-style transparent operation (all processing happens locally in user's browser)

**Recommendation**: The postMessage handlers should validate `event.origin` against the extension's own origin (`chrome-extension://${chrome.runtime.id}`) to prevent potential abuse. However, this is a code quality issue rather than active malware, appropriate for a LOW rating rather than MEDIUM or higher.
