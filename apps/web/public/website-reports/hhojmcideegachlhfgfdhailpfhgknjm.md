# Vulnerability Report: Enable right click

## Metadata
- **Extension ID**: hhojmcideegachlhfgfdhailpfhgknjm
- **Extension Name**: Enable right click
- **Version**: 0.0.10
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

"Enable right click" is a utility extension designed to bypass website restrictions that disable right-click context menus. The extension operates by injecting scripts into all web pages that intercept and re-enable contextmenu events that websites attempt to block. While the extension's core functionality is benign and matches its stated purpose, it contains one low-severity security issue: the postMessage communication between the content script and web-accessible resource lacks origin validation. However, this vulnerability has minimal practical impact because the message only controls a boolean flag for enabling/disabling the extension's functionality on specific domains, and no sensitive data is transmitted or exfiltrated.

The extension does not make any network requests, does not collect user data, and does not communicate with external servers. All configuration is stored locally using chrome.storage.sync. The codebase is straightforward with no obfuscation beyond what appears to be standard minification in the Angular library dependency.

## Vulnerability Details

### 1. LOW: postMessage Without Origin Validation

**Severity**: LOW
**Files**: web_accessible_resources/index.js (line 86), src/content_scripts.js (line 5-8)
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension uses window.postMessage() to communicate between the content script and a web-accessible resource script injected into the page context. The web-accessible resource listens for messages on line 86 without validating the origin of the message sender:

```javascript
window.addEventListener('message', function (event) {
    if (!event.data || event.data.type !== 'enable-right-click') {
        return;
    }
    disableRightClick = !!event.data.disableRightClick;
    // ... no origin check
}, true);
```

The content script sends messages using a wildcard origin on line 5-8:

```javascript
function postWebAccessibleResourceMessage (flag) {
    window.postMessage({
        'type': 'enable-right-click',
        'disableRightClick': flag
    }, '*');  // Wildcard origin
}
```

**Evidence**:
This pattern was flagged by ext-analyzer:
```
ATTACK SURFACE:
  [HIGH] window.addEventListener("message") without origin check    web_accessible_resources/index.js:86
```

**Verdict**:
While technically a security anti-pattern, the practical risk is minimal. A malicious script on a webpage could send a fake message to toggle the extension's functionality on/off for that page, but this would only affect whether right-click blocking is bypassed - it wouldn't expose user data, enable code execution, or create any meaningful security impact. The worst case is a webpage could force the extension to remain disabled on that page, which simply returns the user to the default browser behavior. No sensitive data flows through this channel.

## False Positives Analysis

The ext-analyzer flagged the extension as "obfuscated", but this appears to be a false positive. The actual extension code in background.js, content_scripts.js, DisableSettings.js, and web_accessible_resources/index.js is well-formatted and readable with descriptive variable names and clear control flow. The only minified code is the included Angular.js library (src/lib/angular.js), which is a standard third-party dependency and not part of the extension's core logic. This is normal for extensions that use popular frameworks and should not be considered malicious obfuscation.

The extension's functionality exactly matches its description:
- It intercepts contextmenu events to bypass website restrictions
- It provides a browser action to toggle the feature on specific domains
- It stores user preferences locally
- It operates entirely client-side with no external communication

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | N/A |

The extension makes no network requests to external servers. All functionality is local.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This extension performs exactly as advertised - it bypasses website right-click restrictions to restore browser context menus. The single identified vulnerability (postMessage without origin validation) represents a theoretical security issue but has no practical exploitability for meaningful attacks. The extension does not collect user data, does not make network requests, does not use eval() or other dynamic code execution, and stores all configuration locally. The broad permissions (<all_urls>) are necessary for the extension's stated functionality of working on any website. Overall, this is a benign utility with one minor security weakness that poses negligible risk to users.
