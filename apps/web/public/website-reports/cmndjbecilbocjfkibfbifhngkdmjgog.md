# Vulnerability Report: Swash

## Metadata
- **Extension ID**: cmndjbecilbocjfkibfbifhngkdmjgog
- **Extension Name**: Swash
- **Version**: 3.1.5
- **Users**: Unknown (extension popular on Chrome Web Store)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Swash is a legitimate browser extension that collects browsing activity data from users who consent to share their data in exchange for compensation. The extension's stated purpose is to enable users to monetize their browsing data by selling it on the Streamr Marketplace. Analysis reveals that while the extension's data collection practices are disclosed and consensual, there are minor security concerns related to postMessage handling without proper origin validation.

The extension collects extensive browsing data including page visits, navigation patterns, and interactions with specific e-commerce sites. However, this collection is part of the extension's core functionality and is disclosed in the privacy policy with user controls available to enable/disable collection. The main security vulnerabilities are two instances of postMessage event listeners without origin validation, which could theoretically allow malicious websites to interact with the extension's messaging system.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: core/scripts/sdk.script.js, core/scripts/inpage/sdk.script.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension implements window.addEventListener("message") handlers without proper origin validation checks. This creates a potential attack surface where malicious websites could send crafted messages to the extension's messaging system.

**Evidence**:
```javascript
// core/scripts/sdk.script.js:916
window.addEventListener("message", async i => {
  if (!(i.data && i.data.__fromCS)) try {
    const c = await O(i.data);
    T(i, c)
  } catch (c) {
    T(i, {
```

```javascript
// core/scripts/inpage/sdk.script.js:405
window.addEventListener("message", p), window.postMessage(c, "*")
```

**Verdict**: While this is a security weakness, the risk is mitigated by the fact that the handlers check for specific message formats (`i.data.__fromCS`) and the extension is designed to communicate with swashapp.io domains. However, lack of explicit origin validation is still a vulnerability that could be exploited if message format checks are bypassed.

### 2. MEDIUM: Extensive Browsing Data Collection

**Severity**: MEDIUM
**Files**: core/main.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects comprehensive browsing data including page visits, navigation patterns, and user interactions. This is flagged as a medium-severity issue despite being disclosed because of the broad scope of data collection.

**Evidence**:
```javascript
// core/main.js contains data collection modules
name: "Page Visit",
title: "Visited pages",
description: "This item collects all pages in bathandbodyworks that user has visited",
hook: "webRequest",
target_listener: "inspectVisit"
```

The extension uses webRequest permission with `<all_urls>` to monitor browsing across all websites.

**Verdict**: This is the extension's core functionality and is disclosed in the privacy policy. Users consent to this collection and receive compensation. The data collection is legitimate but warrants medium severity due to the sensitive nature of browsing history data. Users should be fully aware that all browsing activity is monitored when the extension is enabled.

## False Positives Analysis

The ext-analyzer flagged "obfuscated" code and an exfiltration flow from `document.querySelectorAll → fetch`. However:

1. The code is webpack-bundled, not maliciously obfuscated. Standard build tooling creates minified variable names.
2. The fetch operations are part of the extension's legitimate data upload functionality to swashapp.io endpoints.
3. Cloud storage integrations (Dropbox, Google Drive) are legitimate features allowing users to backup their data.

The extension's SDK script injection is also legitimate - it provides a `window.swashSdk` API for the swashapp.io website to interact with the extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| swashapp.io | Main service backend | Collected browsing data | Low - disclosed functionality |
| earn.swashapp.io | Earning portal | User activity, task completion | Low - disclosed functionality |
| callbacks.swashapp.io | OAuth callbacks | Authentication tokens | Low - standard OAuth flow |
| api.dropboxapi.com | Cloud backup | User data backups | Low - optional feature |
| content.dropboxapi.com | File operations | Backup files | Low - optional feature |
| www.googleapis.com | Google Drive integration | User data backups | Low - optional feature |
| api.pinterest.com | Social metrics | URL share counts | Very Low - public API |
| api.tumblr.com | Social metrics | URL share counts | Very Low - public API |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: Swash is a legitimate data collection service with disclosed functionality and user consent mechanisms. The extension operates transparently within its stated purpose of allowing users to monetize their browsing data. The medium risk rating is assigned due to:

1. Two instances of postMessage handlers without explicit origin validation (security vulnerability)
2. The inherently sensitive nature of comprehensive browsing data collection, even when consensual
3. Broad permissions (webRequest, `<all_urls>`, bookmarks, clipboardRead) that extend significant access

The extension is NOT malicious, but users should be fully aware that:
- All browsing activity is monitored when enabled
- Data is sent to third-party services (Swash)
- Users can control collection through in-extension settings
- The privacy policy should be reviewed to understand data usage

Recommendations:
- Add explicit origin validation to postMessage handlers
- Consider reducing permission scope if certain features are unused
- Ensure users fully understand the extent of data collection before installation
