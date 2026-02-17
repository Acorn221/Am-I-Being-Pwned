# Vulnerability Report: UiBot Native Message Plugin

## Metadata
- **Extension ID**: nbacobmbjgnmmdangdadkbjiabhamnco
- **Extension Name**: UiBot Native Message Plugin
- **Version**: 5.1.1
- **Users**: ~90,000
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

UiBot Native Message Plugin is a browser automation tool that enables the UiBot robotic process automation (RPA) software to control Chrome through native messaging. The extension loads its core functionality dynamically via `eval()` from code retrieved from a native messaging host application (`cn.com.uibot.msghost`). While this architecture is legitimate for its stated purpose of browser automation, it creates a code execution risk if the native application is compromised. The extension also uses `unsafe-eval` in its CSP and disables older versions of itself by checking for and disabling extension ID `dcpbjfdnadeepmhmbbdifjnfhgaaiini`.

The extension's behavior is consistent with legitimate RPA tooling, and the dynamic code loading appears to be an intentional design choice for hot-reloading functionality. However, the trust boundary between the extension and the native host creates a moderate security concern.

## Vulnerability Details

### 1. MEDIUM: Dynamic Code Execution via Native Messaging
**Severity**: MEDIUM
**Files**: loader.js (line 303), contentLoader.js (line 36)
**CWE**: CWE-94 (Improper Control of Generation of Code)
**Description**: The extension uses `eval.call(window, g_codeMap["background"])` and `eval.call(window, message.contentCode)` to execute JavaScript code loaded from a native messaging host. The background page requests scripts from the native application `cn.com.uibot.msghost` via the `LoadScripts` function call, and the returned code is executed directly.

**Evidence**:
```javascript
// loader.js, lines 297-304
g_nativeMsgComm.CallFunction("LoadScripts", {}, function (response) {
    console.log("LoadExtensionScripts response.version: " + response["version"]);
    g_codeMap = response;
    // Reload background scripts
    eval.call(window, g_codeMap["background"]);
    delete g_codeMap["background"]; // Not used anymore don't keep it in memory.
    InitializeBackground();
```

```javascript
// contentLoader.js, lines 35-36
try {
    eval.call(window, message.contentCode);
    g_csLoaded = true;
```

**Verdict**: This is a moderate risk. The extension intentionally loads code from a native application to enable hot-reloading and version management. If the native messaging host (`cn.com.uibot.msghost`) is compromised or replaced by malware, arbitrary code could be executed in all browser contexts. However, this is the intended architecture for an RPA tool, and the native host requires separate installation, reducing the attack surface compared to remote code execution.

### 2. MEDIUM: Content Security Policy with unsafe-eval
**Severity**: MEDIUM
**Files**: manifest.json (line 15)
**CWE**: CWE-1335 (Incorrect Bitwise Shift of Integer)
**Description**: The extension's CSP includes `'unsafe-eval'`, which explicitly permits the use of `eval()` and related functions. This weakens the security boundary and could enable code injection if combined with other vulnerabilities.

**Evidence**:
```json
"content_security_policy": "script-src 'self' 'unsafe-eval'; object-src 'self'"
```

**Verdict**: This is necessary for the extension's dynamic code loading architecture but reduces defense-in-depth. The CSP is appropriately restrictive otherwise (no `unsafe-inline`, no remote script sources), limiting the attack surface.

### 3. LOW: Extension Management API to Disable Previous Version
**Severity**: LOW
**Files**: loader.js (lines 8-30)
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension automatically detects and disables an older version of itself (extension ID `dcpbjfdnadeepmhmbbdifjnfhgaaiini`) using `chrome.management.setEnabled()`. While this is standard behavior for extension upgrades, it does use privileged APIs.

**Evidence**:
```javascript
var oldExtensionId = "dcpbjfdnadeepmhmbbdifjnfhgaaiini";
chrome.management.get(oldExtensionId, function (result) {
    if (chrome.runtime.lastError) {
        // failed to find old extension, that's ok
    }
    else if (result && result.enabled) {
        console.log("Found deprecated and enabled UiBot extension");
        chrome.management.setEnabled(oldExtensionId, false, function () {
```

**Verdict**: This is benign. The extension is cleaning up after itself by disabling a deprecated version. The `chrome.management` API requires user permission and the extension ID is hardcoded, so this cannot be used to disable arbitrary extensions.

## False Positives Analysis

1. **Dynamic code loading**: While this pattern is often seen in malicious extensions, it is legitimate for RPA tools that need to update their automation scripts without reinstalling the extension. The code is loaded from a native messaging host, not from a remote server, which limits the attack surface to compromised local applications.

2. **DevTools panel with element inspection**: The `selector.js` script injects helper code into pages to identify and highlight DOM elements. This is standard functionality for browser automation and testing tools (similar to Selenium IDE or Playwright Inspector). The helper code does not exfiltrate data or modify page behavior beyond visual highlighting.

3. **Content script on `<all_urls>`**: The extension needs access to all pages to enable automation across any website. This is expected for an RPA tool and is disclosed in the extension's description.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | No network requests detected | N/A | None |

The extension does not make any external network requests. All communication is via native messaging to a local application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: UiBot Native Message Plugin is a legitimate browser automation extension for the UiBot RPA software. The primary security concern is the use of `eval()` to execute code loaded from a native messaging host. While this is intentional and necessary for the extension's hot-reload architecture, it creates a trust boundary issue: if the native application is compromised, arbitrary code can be executed in the browser context.

The extension does not exhibit malicious behavior, does not exfiltrate data, and does not make network requests. The dynamic code execution risk is mitigated by the requirement that users must install the native messaging host separately, and the extension can only communicate with the registered native application.

For enterprise users, the risk should be evaluated in the context of their RPA deployment and endpoint security controls. The extension's powerful permissions (`<all_urls>`, `tabs`, `webRequest`, `nativeMessaging`) are appropriate for its stated purpose but should be monitored in security-conscious environments.
