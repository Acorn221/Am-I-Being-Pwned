# Vulnerability Report: CORS Unblock

## Metadata
- **Extension ID**: lfhmikememgdcahcdlaciloancbhjino
- **Extension Name**: CORS Unblock
- **Version**: 0.5.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

CORS Unblock is a developer tool extension designed to bypass Cross-Origin Resource Sharing (CORS) restrictions for web development and testing purposes. The extension uses powerful Chrome APIs including `debugger`, `declarativeNetRequest`, and `<all_urls>` permissions to modify HTTP headers and manipulate network requests. While the extension's functionality is inherently security-sensitive, its behavior is transparent, well-documented, and aligns with its stated purpose as a CORS debugging tool.

The extension operates by creating a popup UI where users can configure CORS-related headers (Access-Control-Allow-Origin, Access-Control-Allow-Methods, etc.) and then uses `declarativeNetRequest` session rules and the Chrome Debugger API's Fetch domain to modify responses and requests on a per-tab basis. All modifications are user-initiated and configurable, with clear UI controls. No data exfiltration, tracking, or malicious behavior was detected.

## Vulnerability Details

### 1. MEDIUM: Powerful Security-Sensitive Permissions

**Severity**: MEDIUM
**Files**: manifest.json, worker.js, data/debug/index.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requires highly privileged permissions that could be misused if the extension were compromised:
- `debugger` permission allows attaching to Chrome DevTools Protocol
- `declarativeNetRequest` allows modifying network requests/responses
- `<all_urls>` host permission grants access to all websites

**Evidence**:
```json
"permissions": [
  "storage",
  "declarativeNetRequest",
  "debugger"
],
"host_permissions": [
  "<all_urls>"
]
```

The debugger API is used to intercept and modify HTTP requests/responses:
```javascript
await chrome.debugger.attach({tabId}, '1.3');
await chrome.debugger.sendCommand({tabId}, 'Fetch.enable', {
  patterns
});
```

**Verdict**: While these permissions are excessive for most extensions, they are **legitimately required** for CORS Unblock's core functionality. The extension's purpose is specifically to bypass browser security restrictions for development/testing. The permissions usage is:
- **Transparent**: Users explicitly enable CORS unblocking via UI
- **Scoped**: Applied per-tab, not globally
- **Reversible**: "Terminate" button cleanly removes all modifications
- **Expected**: Standard for developer tools in this category

This is rated MEDIUM rather than HIGH because the functionality is clearly disclosed and expected for a CORS debugging tool. Similar to how browser DevTools have powerful capabilities, this extension provides controlled access to those capabilities.

## False Positives Analysis

The following patterns might appear suspicious but are legitimate for this extension type:

1. **Debugger API Usage**: The `chrome.debugger` API is commonly flagged as dangerous, but it's the only way to implement certain CORS workarounds (like modifying redirected requests or adding custom headers mid-flight). The extension uses it appropriately.

2. **Header Manipulation**: Modifying security headers like `Content-Security-Policy`, `X-Frame-Options`, and CORS headers is the extension's stated purpose. This is not stealth behavior - users explicitly configure and enable these modifications.

3. **Status Code Overwriting**: The option to overwrite 4xx status codes with 200 might seem suspicious, but it's a legitimate development tool feature for testing error handling.

4. **FAQ/Feedback Links**: Opening tabs to the homepage URL on install/update (webextension.org) is standard extension behavior for showing release notes, not tracking.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://webextension.org | Homepage/FAQ/uninstall feedback | Extension name, version, install reason via URL params | Low - Standard extension telemetry |
| https://webbrowsertools.com/test-cors/ | Test page link (user-initiated) | None - just opens URL | None |

No background network requests are made. No analytics or tracking detected. All network activity is user-visible and intentional.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
CORS Unblock is a legitimate developer tool that requires powerful permissions to fulfill its stated purpose. The extension is transparent in its operation, provides clear user controls, and does not engage in any deceptive or malicious behavior. The MEDIUM risk rating reflects that:

1. **Permissions are appropriate for functionality**: Unlike many extensions that request excessive permissions, CORS Unblock actually needs `debugger` and `declarativeNetRequest` to work.

2. **No hidden behavior**: All functionality is user-initiated through a clear UI. No background data collection or exfiltration.

3. **Clean code**: The deobfuscated source code shows straightforward implementation with no obfuscation, hidden payloads, or suspicious patterns.

4. **Inherent security trade-off**: Any tool that bypasses browser security mechanisms carries risk. Users should understand they are intentionally disabling CORS protections when using this extension.

**Recommendation**: MEDIUM risk is appropriate. The extension is safe for its intended audience (web developers who understand CORS and security implications) but should not be enabled permanently or used on sensitive sites. The permissions could be dangerous if the extension were compromised via supply chain attack or malicious update.
