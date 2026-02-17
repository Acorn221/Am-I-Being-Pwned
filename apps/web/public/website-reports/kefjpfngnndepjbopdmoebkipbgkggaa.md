# Vulnerability Report: RSSHub Radar

## Metadata
- **Extension ID**: kefjpfngnndepjbopdmoebkipbgkggaa
- **Extension Name**: RSSHub Radar
- **Version**: 2.2.0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

RSSHub Radar is a legitimate browser extension designed to help users discover and subscribe to RSS feeds on websites. The extension integrates with RSSHub (rsshub.app), an open-source RSS feed generator service, to detect available RSS feeds on the current page.

While the extension performs its stated function appropriately, it contains a minor security issue related to postMessage handling without proper origin validation in the background script and sandbox context. However, the overall risk is assessed as LOW because the extension's communication patterns are internal (between extension components), and the data flows to rsshub.app are part of the legitimate RSS discovery functionality.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: background.js (line 54626), chunks/sandbox-DWpXOg1Y.js (line 54419), chunks/offscreen-Bm4fBraZ.js (line 22)
**CWE**: CWE-346 (Origin Validation Error)
**Description**: The extension implements message event listeners without strict origin validation. While the responses do use `t.origin` when posting messages back, the incoming message validation only checks for specific message names rather than validating the source origin.

**Evidence**:
```javascript
// background.js:54626
typeof window < "u" && window.addEventListener("message", t => {
  switch (t.data?.name) {
    case "requestRSSHub": {
      const e = mu({
        html: t.data.body.html,
        url: t.data.body.url,
        rules: t.data.body.rules
      });
      t.source.postMessage({
        name: "responseRSS",
        body: {
          url: "url" in t.data.body && t.data.body.url,
          tabId: "tabId" in t.data.body && t.data.body.tabId,
          rss: e
        }
      }, t.origin);
      break
    }
  }
});
```

**Verdict**: While this pattern is generally discouraged, the actual security impact is limited because:
1. The message handlers only process specific message types (requestRSSHub, requestDisplayedRules)
2. The responses are sent back using the original message's origin (`t.origin`)
3. The extension components (background, offscreen, sandbox) communicate internally
4. No sensitive user data is exposed through these handlers

This is a code quality issue rather than an actively exploitable vulnerability in the current implementation.

## False Positives Analysis

The static analyzer flagged several data exfiltration flows to `rsshub.app` and `icons.duckduckgo.com`. These are NOT malicious:

1. **rsshub.app**: This is the legitimate RSSHub service that the extension is designed to work with. The extension sends page HTML and URLs to RSSHub for RSS feed discovery, which is the extension's core purpose and is clearly disclosed in the extension description.

2. **icons.duckduckgo.com**: Used for fetching favicon/icon images for RSS feeds in the UI, a common and benign practice.

3. **Obfuscation flag**: The code is webpack-bundled with minified variable names, which is standard build tooling output, NOT malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| rsshub.app | RSS feed discovery | Page HTML, URL, internal rules | LOW - Disclosed functionality |
| icons.duckduckgo.com | Fetch feed icons | URLs | LOW - Standard icon fetching |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: RSSHub Radar is a legitimate RSS feed discovery tool that functions as advertised. The postMessage handlers without strict origin validation represent a minor code quality issue, but the actual security impact is minimal given the internal communication pattern and message type filtering. The data flows to rsshub.app are part of the extension's core, disclosed functionality. No credential theft, hidden exfiltration, or malicious behavior was detected. The extension follows standard MV3 patterns and uses appropriate permissions for its functionality.
