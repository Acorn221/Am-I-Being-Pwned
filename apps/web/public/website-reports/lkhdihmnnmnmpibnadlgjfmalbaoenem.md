# Vulnerability Report: Auto refresh page - reload page

## Metadata
- **Extension ID**: lkhdihmnnmnmpibnadlgjfmalbaoenem
- **Extension Name**: Auto refresh page - reload page
- **Version**: 1.0.4
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension provides auto-refresh functionality for web pages, allowing users to automatically reload tabs at configurable intervals. The extension has 500,000 users but carries a concerning 2.0/5 rating. Analysis reveals a medium-severity DOM-based XSS vulnerability in the popup interface where unsanitized message data flows into innerHTML assignments. The extension also exhibits code patterns flagged as "obfuscated" by static analysis, though this appears to be primarily due to minification rather than intentional obfuscation. The extension requests broad host permissions (<all_urls>) but only uses these for content script injection to display timers and manage refresh state, which is appropriate for its stated functionality.

The primary security concern is that the popup UI (scripts/app.js) dynamically sets innerHTML using data from chrome.runtime.sendMessage without proper sanitization, creating a potential cross-site scripting attack surface. While exploitation requires interaction with the extension's internal messaging system, this represents a vulnerability that should be addressed.

## Vulnerability Details

### 1. MEDIUM: DOM-based XSS via innerHTML Injection in Popup UI

**Severity**: MEDIUM
**Files**: scripts/app.js, scripts/serviceWorker.js
**CWE**: CWE-79 (Improper Neutralization of Input During Web Page Generation)

**Description**:
The static analyzer identified a data flow from chrome.runtime message handlers to innerHTML assignments in the popup interface. In scripts/app.js, message data received via chrome.runtime.onMessage is directly used to set innerHTML properties without sanitization:

**Evidence**:
```javascript
// From ext-analyzer output:
ATTACK SURFACE:
  message data → *.innerHTML(chrome.google.com)    from: scripts/serviceWorker.js, scripts/content.js ⇒ scripts/app.js
```

Analysis of scripts/app.js shows multiple instances where data from messages is used to construct HTML:
- The extension builds dynamic HTML strings containing tab URLs, timer values, and extension messages
- While many uses go through the `dij()` function which processes i18n messages, some data flows directly into innerHTML
- The popup constructs UI elements dynamically based on stored data from chrome.storage.local

**Verdict**:
This is a legitimate security concern. While the extension's internal architecture makes exploitation non-trivial (an attacker would need to manipulate the extension's local storage or message bus), the vulnerability exists. The impact is MEDIUM rather than HIGH because:
1. The vulnerable code runs only in the extension popup context (not in web page contexts)
2. Exploitation requires compromising the extension's internal state or message passing
3. The extension does not accept external input that directly flows to these sinks

**Recommendation**: Sanitize all data before innerHTML assignment, or use safer DOM manipulation methods like textContent for user-controlled data.

### 2. LOW: Overly Broad Host Permissions

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**:
The extension requests `<all_urls>` host permissions, granting it access to all websites. While this is technically necessary for the extension's functionality (to inject refresh timers and manage refresh state on any tab), it represents a broad permission surface.

**Evidence**:
```json
"host_permissions": [
    "<all_urls>"
]
```

The content script (scripts/content.js) is injected on all URLs to:
- Display visual countdown timers on pages
- Handle click events to pause refresh
- Communicate with the service worker about refresh state

**Verdict**:
This is appropriate for the extension's stated functionality. Auto-refresh tools inherently need broad access to work on any page the user wants to refresh. The extension does not abuse these permissions for data collection or other malicious purposes. The LOW severity rating reflects that while broad, the permissions are justified and not misused.

## False Positives Analysis

### Obfuscation Flag
The static analyzer flagged this extension as "obfuscated". However, examination of the deobfuscated code shows this is primarily due to:
- Variable name minification (e.g., function names like `foo`, `ryf`, `rox`, `tgy`)
- Standard JavaScript minification practices
- The code is still readable and shows clear functionality

This appears to be standard minification rather than intentional obfuscation to hide malicious behavior. The extension's behavior is transparent and matches its description.

### Content Script on All URLs
While the content script runs on `<all_urls>`, it only:
- Injects a visual timer overlay when requested
- Listens for click events to pause refresh
- Communicates refresh state with the background service worker
- Does not collect page data, intercept network requests, or exfiltrate information

This is standard and expected behavior for an auto-refresh extension.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://fonts.googleapis.com | Google Fonts CDN for UI styling | None (CSS resource load) | None |

The extension only contacts Google Fonts CDN for loading the "Material Icons" font family used in the popup UI. No user data or tracking information is sent to external servers.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The extension is assigned a MEDIUM risk level due to the DOM-based XSS vulnerability in the popup interface. While the extension's core functionality is legitimate and the broad permissions are justified for its purpose, the innerHTML injection vulnerability represents a security weakness that could potentially be exploited if an attacker gains control over the extension's message bus or local storage.

Key factors in the risk assessment:
- **Positive**: No data exfiltration, no remote code loading, no credential harvesting
- **Positive**: Permissions are appropriate for stated functionality
- **Positive**: No hidden tracking or malicious behavior detected
- **Negative**: DOM-based XSS vulnerability via innerHTML injection
- **Negative**: Low user rating (2.0/5) suggests potential quality or trust issues

The extension appears to be a legitimate auto-refresh tool, but the security vulnerability and poor user rating warrant a MEDIUM risk classification. Users should be aware of the security issue, and the developer should address the innerHTML injection vulnerability by implementing proper sanitization or using safer DOM manipulation methods.
