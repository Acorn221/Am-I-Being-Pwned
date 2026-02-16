# Vulnerability Report: Padlet Mini

## Metadata
- **Extension ID**: kcljbbiddpoeaknnjaminoceoojdbikp
- **Extension Name**: Padlet Mini
- **Version**: 5.1.6
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Padlet Mini is a legitimate browser extension designed to facilitate adding content to Padlet boards. The extension provides a quick way to save web pages, text, and other content to Padlet.com workspaces. The codebase is built with WXT (a modern web extension framework) and contains minimal security risks.

The extension exhibits one low-severity vulnerability: the content script uses `window.postMessage()` listeners without origin validation, which could theoretically allow malicious pages to inject messages. However, this risk is heavily mitigated by the fact that the content script only runs on Padlet domains (`*://*.padlet.com/add-post*`, `*://*.padlet.org/add-post*`) and the messages are used solely for synchronizing extension state with the Padlet web app. The extension has appropriate permissions (limited to activeTab, contextMenus, storage, and tabs), requests host permissions only for the specific Padlet API endpoint (`https://pepin.padlet.com/*`), and shows no signs of data exfiltration or malicious behavior.

## Vulnerability Details

### 1. LOW: PostMessage Listener Without Origin Validation

**Severity**: LOW
**Files**: content-scripts/addpost.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**:
The content script registers two `window.addEventListener("message")` handlers without validating the origin of received messages. This could theoretically allow a malicious script on the same page to send crafted messages to the extension's content script.

**Evidence**:
```javascript
window.addEventListener("message",r);
// Handler 1: checks for source "add-post-app-extension-body-text-received"
if(((h=l.data)==null?void 0:h.source)==="add-post-app-extension-body-text-received"){
  window.removeEventListener("message",r),clearInterval(d),ue();
  return
}

// Handler 2: checks for source "add-post-app-extension-analytics-received"
((h=l.data)==null?void 0:h.source)==="add-post-app-extension-analytics-received"&&(
  window.removeEventListener("message",r),clearInterval(d),he()
)
```

**Verdict**:
While this is a legitimate security concern, the risk is **LOW** for the following reasons:

1. **Limited Scope**: The content script only runs on Padlet domains (`*.padlet.com/add-post*` and `*.padlet.org/add-post*`), not on arbitrary websites
2. **Benign Functionality**: The messages only control cleanup operations (`ue()` and `he()` which remove stored data from local storage)
3. **No Privilege Escalation**: The message handlers don't execute dangerous operations or grant additional privileges
4. **Expected Communication Pattern**: This is the standard pattern for communication between a web app and its companion extension
5. **Source Filtering**: The handlers do check for specific source identifiers in the message data

**Recommendation**: Add origin validation using `event.origin` to ensure messages only come from trusted Padlet domains:
```javascript
window.addEventListener("message", (event) => {
  if (!event.origin.match(/^https:\/\/([^.]+\.)?padlet\.(com|org)$/)) return;
  // ... rest of handler
});
```

## False Positives Analysis

### Webpack Bundling (Not Obfuscation)
The static analyzer flagged this extension as "obfuscated," but this is a false positive. The code is minified and bundled with Webpack/WXT, which is standard for modern web extensions. The variable names are shortened (e.g., `t`, `r`, `e`), but the code structure is readable and follows predictable patterns.

### WXT Framework Code
Much of the codebase consists of the WXT framework runtime (storage helpers, mutex/semaphore primitives, content script lifecycle management). This is legitimate framework code, not malicious infrastructure.

### Storage Usage
The extension uses `chrome.storage.local` to persist user preferences (`useTenant`, `customDomain`) and temporary data (`bodyText`, `extensionAnalytics`). This is normal for extensions that need to maintain state.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| pepin.padlet.com | Padlet API endpoint for creating posts | User-selected content (text, URLs) | None - legitimate service endpoint |
| padlet.com/add-post* | Padlet web app pages where content script runs | None (only receives messages) | None - extension's own domain |
| padlet.org/add-post* | Padlet web app pages where content script runs | None (only receives messages) | None - extension's own domain |

## Permissions Analysis

### Declared Permissions
- `activeTab`: Used to capture content from the current tab - appropriate for a content-saving extension
- `contextMenus`: Allows adding context menu items (likely "Add to Padlet") - standard for this use case
- `storage`: Used to persist user settings and temporary data - necessary
- `tabs`: Used to access tab information - appropriate for the extension's purpose

### Host Permissions
- `https://pepin.padlet.com/*`: Limited to the specific Padlet API endpoint - appropriately scoped

**Verdict**: Permissions are minimal and appropriate for the extension's stated functionality.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Padlet Mini is a legitimate, well-built browser extension from Padlet (a reputable educational technology company). The extension follows modern development practices using the WXT framework and Manifest V3. The single identified vulnerability (postMessage without origin check) is a minor security issue that poses minimal real-world risk due to the limited scope of the content script and the benign nature of the message handlers.

The extension:
- ✓ Has no data exfiltration
- ✓ Uses minimal, appropriate permissions
- ✓ Communicates only with official Padlet domains
- ✓ Contains no obfuscated malicious code
- ✓ Serves its stated purpose without hidden functionality
- ⚠ Has one low-severity security issue that should be addressed

**Recommendation**: The extension is safe for use. The development team should add origin validation to postMessage listeners in a future update as a security hardening measure.
