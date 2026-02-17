# Vulnerability Report: Web Paint Tool - draw online

## Metadata
- **Extension ID**: iklgljbighkgbjoecoddejooldolenbj
- **Extension Name**: Web Paint Tool - draw online
- **Version**: 1.0.7
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Web Paint Tool is a drawing and annotation extension that allows users to draw shapes, text, and freehand sketches on web pages, then take screenshots of the annotated results. The extension uses HTML5 Canvas for all drawing operations and stores user drawings in localStorage for persistence across page reloads. Analysis reveals the extension is a legitimate productivity tool with minimal security concerns. The codebase follows standard Canvas API practices and does not engage in data collection, tracking, or malicious behavior. The extension does include a review prompt mechanism that triggers every 7 uses, which is a common but mildly annoying pattern.

The extension requires `<all_urls>` host permissions and the `scripting` permission to inject its canvas overlay and drawing interface into web pages, which is appropriate for its stated functionality. There are no network requests beyond the optional user-initiated Chrome Web Store review link.

## Vulnerability Details

### 1. LOW: Unsolicited Review Prompts
**Severity**: LOW
**Files**: popup.js (lines 614-638)
**CWE**: None (UX anti-pattern)
**Description**: The extension tracks usage counts in chrome.storage.local and displays a review prompt every 7 uses, asking users to rate the extension on the Chrome Web Store. While not a security vulnerability, this is an unsolicited interruption of user experience.

**Evidence**:
```javascript
chrome.storage.local.get(["openTimes3", "rateClicked3"], (function(e) {
  let {
    openTimes3: i,
    rateClicked3: n
  } = e;
  i ? i += 1 : i = 1,
  chrome.storage.local.set({
    openTimes3: i
  }),
  n || i % 7 != 0 || document.getElementById("xxdialog-rate") ||
  (document.querySelector("body").insertAdjacentHTML("beforeend", t), ...
```

The prompt opens Chrome Web Store in a new tab when users click "yes":
```javascript
window.open("https://chrome.google.com/webstore/detail/" + chrome.runtime.id + "/reviews", "_blank").focus()
```

**Verdict**: This is a legitimate, albeit annoying, user engagement tactic. The counter can be suppressed by clicking "no" which sets `rateClicked3: true`. No privacy or security impact.

## False Positives Analysis

1. **Obfuscated Code Flag**: The ext-analyzer flagged this extension as "obfuscated". However, the code is webpack-bundled, not maliciously obfuscated. The editor.js file contains standard webpack boilerplate (module loaders, chunk management) and the popup.js contains minified but readable Canvas drawing logic. This is normal for production builds.

2. **localStorage Usage**: The extension stores canvas snapshots in localStorage with keys like `WP_CRX_STORAGE_SNAPSHOT_${window.location.pathname}`. This is legitimate functionality to persist user drawings across page reloads and is documented in the extension's description ("draw... then make screenshot").

3. **Dynamic Script Injection**: The background.js uses `chrome.scripting.executeScript` to inject popup.js when the extension icon is clicked. This is the standard MV3 pattern for content script injection and is necessary for the extension's core functionality.

4. **chrome.tabs.captureVisibleTab**: Used in background.js to capture screenshots of the current tab with user drawings overlaid. This is the extension's primary feature and is only triggered when the user clicks the screenshot button.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://chrome.google.com/webstore/detail/{extension_id}/reviews | User review page | None (navigation only) | None |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Web Paint Tool is a legitimate productivity extension with no privacy violations or security vulnerabilities. The extension's behavior aligns with its stated purpose: allowing users to annotate web pages with drawings and capture screenshots. All permissions are appropriately used:

- `<all_urls>` host permission: Required to inject the canvas overlay on any page the user wants to annotate
- `scripting` permission: Required to inject the drawing interface when the user clicks the extension icon
- `storage` permission: Used to persist user preferences (color, tool, line width) and the review prompt counter
- `alarms` permission: Used for retry logic when passing screenshot data to the editor tab

The extension stores all user data locally (localStorage and chrome.storage.local) and does not transmit any data to external servers. The only external link is the optional Chrome Web Store review page, which is user-initiated.

The LOW risk rating is assigned solely due to the review prompt mechanism, which is a minor UX anti-pattern but not a security or privacy concern. Users with privacy concerns should note that the extension has full access to page content due to `<all_urls>`, but there is no evidence of data collection or exfiltration in the codebase.
