# Vulnerability Report: Local Explorer - Open File Links in Chrome

## Metadata
- **Extension ID**: eokekhgpaakbkfkmjjcbffibkencdfkl
- **Extension Name**: Local Explorer - Open File Links in Chrome
- **Version**: 2023.1.15.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Local Explorer is a utility extension that enables users to open file:// protocol links in Chrome by converting them to custom protocol handlers (LocalExplorer: and LocalExplorerUnicode:). The extension's core functionality is legitimate and serves a valid use case for users needing to access local filesystem paths from web pages.

The extension includes tracking functionality that sends installation and update events to vnprodev.com. While this represents minor telemetry collection, it is limited to basic metadata (browser type, webstore name, version) and does not involve sensitive user data exfiltration. The extension does not collect browsing history, personally identifiable information, or user content. Overall risk is LOW.

## Vulnerability Details

### 1. LOW: Undisclosed Installation Tracking

**Severity**: LOW
**Files**: background.js (lines 22-66)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension sends HTTP requests to vnprodev.com on install and update events without explicit disclosure in a visible privacy policy within the extension interface. The requests include basic telemetry:
- Installation/update type
- Extension version
- Browser type (Chrome/Edge)
- Webstore identifier

**Evidence**:
```javascript
const t = "https://www.vnprodev.com/browser-extensions/local-explorer-install.php";
let o = "chrome";
if (/Edg/.test(navigator.userAgent)) o = "edge";
let n = "chrome";
if (chrome.runtime.id.substr(8, 8) === "ciooajgk") {
  n = "edge"
}

// On install
chrome.tabs.create({
  url: t + "?thanks" + "&ws=" + n + "&br=" + o
})

// On update
chrome.tabs.create({
  url: t + "?update=" + chrome.runtime.getManifest().version + "&ws=" + n + "&br=" + o
})
```

**Verdict**: This is a minor privacy concern. The data collected is limited to non-sensitive metadata. The extension does not harvest user activity, browsing history, or personal information. However, users may not be aware of this tracking behavior.

## False Positives Analysis

### Content Script on All URLs
The extension declares `<all_urls>` in both content_scripts matches and host_permissions. This appears excessive but is necessary for the extension's core functionality - it must detect and transform file:// links on any webpage the user visits. The content script only processes anchor tags with file:// URLs and does not collect page content or user data.

### Base64 Encoding Utility
The content script includes a Base64 encoder/decoder (content.js lines 93-181). This is used legitimately to encode file paths containing Unicode characters into the custom protocol handler format (LocalExplorerUnicode:). It is not used for obfuscation or data exfiltration.

### Dynamic Event Construction
The extension constructs a custom DOM event name using fragments of the extension ID (content.js lines 184-202). This appears to be an obfuscation technique, but analysis shows it's used only to create a unique event name for triggering file link processing when the "optThreads" option is enabled. This prevents conflicts with other extensions.

### External Options Page
The options.js file attempts to fetch and redirect to an external options page at vnprodev.com (options.js lines 30-38). This only occurs during migration from Manifest V2 to V3 and falls back to the local options.html if the remote page is unavailable. The remote options page is not used for data collection but appears to provide a unified configuration interface.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://www.vnprodev.com/browser-extensions/local-explorer-install.php | Installation tracking | Browser type, webstore, version, event type (thanks/update) | LOW |
| https://www.vnprodev.com/browser-extensions/local-explorer-options.html | Remote options page (MV2→MV3 migration) | None (HEAD request only) | MINIMAL |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
The extension performs its advertised function (enabling file:// link access) without collecting sensitive user data. The tracking endpoint receives only basic installation metadata. No browsing history, cookies, authentication tokens, or personally identifiable information is accessed or transmitted. The `<all_urls>` permission is necessary for the file link transformation feature to work on any page.

The main concern is the lack of transparency around the installation tracking, but the data collected is minimal and non-invasive. Users who are privacy-conscious should be aware that install/update events are reported to the developer's server.

**Recommendations**:
1. Add a visible privacy policy link in the extension's options page
2. Disclose the installation tracking behavior in the Chrome Web Store description
3. Consider making the tracking opt-in or providing a disable option

**Comparison to Risk Framework**:
- Not CRITICAL: No credential theft, hidden exfiltration, or command & control
- Not HIGH: No undisclosed user data collection beyond basic telemetry
- Not MEDIUM: Does not collect browsing activity or excessive personal data
- **LOW**: Minor telemetry without explicit disclosure, but limited to non-sensitive metadata
- Not CLEAN: The undisclosed tracking prevents a CLEAN rating
