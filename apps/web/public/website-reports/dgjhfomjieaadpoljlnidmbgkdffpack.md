# Vulnerability Report: Sourcegraph

## Metadata
- **Extension ID**: dgjhfomjieaadpoljlnidmbgkdffpack
- **Extension Name**: Sourcegraph
- **Version**: 24.3.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Sourcegraph is a legitimate browser extension developed by Sourcegraph Inc. that integrates GitHub with the Sourcegraph code search platform. The extension provides omnibox search functionality (activated via "src" keyword) and adds UI elements to GitHub pages for enhanced code navigation.

The extension communicates with sourcegraph.com (or a user-configurable Sourcegraph instance URL) to perform code searches. The static analyzer flagged one exfiltration flow where chrome.storage.local data is sent to sourcegraph.com, but this is expected and disclosed functionality - the extension retrieves the user's configured Sourcegraph URL from storage and opens search URLs on that domain. No security vulnerabilities or undisclosed data collection were identified.

## Vulnerability Details

### 1. LOW: User Configuration Data Sent to External Domain

**Severity**: LOW
**Files**: static/background/index.js
**CWE**: N/A (Expected behavior)
**Description**: The extension reads user configuration from chrome.storage.local (specifically "useSourcegraphStore" containing the Sourcegraph instance URL) and uses it to construct search URLs opened in new tabs. The static analyzer flagged this as potential exfiltration, but it is the core functionality of the extension.

**Evidence**:
```javascript
// Line 106-119 in static/background/index.js
chrome.omnibox.onInputEntered.addListener(async e => {
  let t = await chrome.storage.local.get("useSourcegraphStore"),
    r = "https://sourcegraph.com";
  try {
    if (t.useSourcegraphStore) {
      let e = "string" == typeof t.useSourcegraphStore ? JSON.parse(t.useSourcegraphStore) : t.useSourcegraphStore;
      e.state?.url && (r = e.state.url.trim()).endsWith("/") && (r = r.slice(0, -1))
    }
  } catch (e) {
    console.error("Failed to parse stored URL:", e)
  }
  let o = `${r}/search?q=context:global+${encodeURIComponent(e)}&patternType=keyword&sm=0`;
  console.log("Opening search URL:", o), chrome.tabs.create({
    url: o
  })
})
```

**Verdict**: This is expected functionality. The extension's purpose is to enable Sourcegraph code search from the browser omnibox. The user's configured Sourcegraph URL is retrieved from storage to construct search queries. This is disclosed in the extension description: "Open repos, compare revisions and search code directly from Chrome's Omnibox".

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" due to Parcel bundler output, but this is standard modern JavaScript bundling, not malicious obfuscation. The code uses Parcel's module loader pattern which appears minified but is not intentionally obfuscated to hide malicious behavior.

The fetch() calls detected in the background script (lines 220, 238) are part of the dynamic content script registration system that looks up script file paths from the extension's own package directory - these are internal extension operations, not external network requests.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| sourcegraph.com | Code search queries | User's omnibox search input, configured via user settings | LOW - Core functionality |
| security.sourcegraph.com | Information page link | None (external link only) | NONE |
| User-configurable Sourcegraph URL | Enterprise/self-hosted instances | Search queries | LOW - User-controlled |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate extension from a reputable company (Sourcegraph Inc.) providing documented functionality. The "exfiltration" detected by the static analyzer is actually the expected behavior of reading user configuration to enable code search. The extension uses standard Chrome extension APIs appropriately and does not collect or transmit any undisclosed user data. The only minor risk is that users should verify they trust the Sourcegraph instance URL they configure, as search queries will be sent to that domain. Overall, this extension poses minimal security risk and operates within expected parameters for its stated purpose.

The extension has appropriate permissions for its functionality:
- `storage` - stores user's Sourcegraph URL preference
- `scripting` - injects UI enhancements into GitHub pages
- `https://github.com/*` - required for GitHub integration

No credential theft, session hijacking, hidden data collection, or malicious code patterns were identified.
