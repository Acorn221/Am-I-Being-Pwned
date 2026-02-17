# Vulnerability Report: Kaspersky Protection 19.0

## Metadata
- **Extension ID**: amkpcclbbgegoafihnpgomddadjhcadd
- **Extension Name**: Kaspersky Protection 19.0
- **Version**: 20.0.543.1521
- **Users**: Unknown (requires CWS lookup)
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

Kaspersky Protection 19.0 is a legitimate security extension developed by Kaspersky Lab. The extension implements web protection features through native messaging integration with the Kaspersky desktop security product. The extension intercepts XMLHttpRequest and WebSocket traffic, communicates with a Kaspersky backend server (scr.kaspersky-labs.com), and provides anti-phishing/anti-malware capabilities.

The extension uses extensive permissions including `<all_urls>`, `webRequest`, `webRequestBlocking`, `management`, and `nativeMessaging`. While these permissions are broad, they are necessary for the extension's stated security functionality. The extension exhibits legitimate enterprise security tool behavior rather than malicious activity.

## Vulnerability Details

### 1. LOW: Extension Management Capabilities
**Severity**: LOW
**Files**: background/background_plugin.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension has the ability to enumerate and uninstall other browser extensions via `chrome.management.get()` and `chrome.management.uninstall()` APIs. These capabilities are exposed through message handlers `getPluginInfo` and `deletePlugin`.

**Evidence**:
```javascript
function handleGetPluginInfo(request, sender, sendResponse) {
    try {
        chrome.management.get(request.id, function (info) {
            // ... returns extension info including icons
        });
    }
    // ...
}

function handleDeletePlugin(request, sender, sendResponse) {
    try {
        chrome.management.uninstall(request.id, function () {
            // ... uninstalls extension
        });
    }
    // ...
}
```

**Verdict**: This is standard behavior for security products that need to detect and remove malicious extensions. The functionality is protected by the content security policy and requires communication with the native Kaspersky product. This is NOT malicious extension enumeration for tracking purposes.

### 2. LOW: XMLHttpRequest and WebSocket Proxying
**Severity**: LOW
**Files**: content/xmlhttprequest_proxy.js, content/websocket_proxy.js, content/api_injection.js
**CWE**: CWE-300 (Channel Accessible by Non-Endpoint)
**Description**: The extension replaces native `XMLHttpRequest` and `WebSocket` implementations with proxy objects that forward all calls to the background page for inspection. This allows the extension to intercept all AJAX and WebSocket traffic on every web page.

**Evidence**:
```javascript
// xmlhttprequest_proxy.js
function replaceNativeXMLHttpRequest() {
    window['XMLHttpRequest'] = XMLHttpRequestProxy;
}

// websocket_proxy.js
function replaceNativeWebSocket() {
    window['WebSocket'] = WebSocketProxy;
}
```

**Verdict**: This is legitimate behavior for a web security extension that needs to scan network traffic for malicious content. The interception is used for anti-phishing and anti-malware scanning, not for data theft. The extension only intercepts HTTPS traffic (`filter: { urls: ["https://*/*"] }`) for security scanning.

## False Positives Analysis

The following patterns appear suspicious but are legitimate for a security extension:

1. **XHR/WebSocket Hooking**: While hooking native web APIs is typically a red flag for malicious extensions, this is standard practice for security tools that need to scan network traffic in real-time for threats.

2. **Management Permission**: The ability to uninstall other extensions could be misused, but in this case it's part of Kaspersky's malware removal capabilities. Security products routinely need to remove malicious browser extensions.

3. **Native Messaging**: Communication with a native application (com.kaspersky.*.host) is required for integration with the desktop Kaspersky security product. This allows the extension to leverage the full threat intelligence database.

4. **Code Injection**: The extension injects scripts into web pages via `executeScriptInDocument()`, but this is limited to injecting a tab ID property and firing ready events, not arbitrary code execution.

5. **All URLs Permission**: While `<all_urls>` is a broad permission, it's necessary for a security product that protects against threats on any website.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| scr.kaspersky-labs.com | Kaspersky cloud security services | XHR/WebSocket traffic for threat scanning | LOW - legitimate security backend |
| gc.kis.v2.scr.kaspersky-labs.com | Kaspersky security gateway | Page protection requests | LOW - official Kaspersky infrastructure |

The extension communicates exclusively with Kaspersky-owned infrastructure. The CSP (`content_security_policy`) explicitly restricts connections to `*.scr.kaspersky-labs.com` domains only.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise security product from Kaspersky Lab. While the extension uses powerful permissions (webRequest blocking, native messaging, extension management, all_urls), these are necessary and appropriate for its security functionality. The extension exhibits all the characteristics of a genuine security tool:

1. **Vendor Legitimacy**: Kaspersky Lab is a well-known security vendor
2. **Purpose Alignment**: All permissions and behaviors align with stated anti-phishing/anti-malware purpose
3. **No Data Exfiltration**: No evidence of user data collection beyond threat scanning
4. **CSP Restrictions**: Content security policy limits communication to official Kaspersky domains only
5. **Native Integration**: Requires desktop Kaspersky product installation (via native messaging)

The extension does NOT exhibit malicious behaviors such as:
- Hidden data exfiltration to third-party domains
- Credential harvesting
- Ad injection or affiliate manipulation
- Cryptocurrency mining
- Keylogging beyond security scanning

**Recommendation**: CLEAN for legitimate Kaspersky users. However, users should be aware that security products necessarily have broad access to browsing activity and network traffic for threat detection purposes. Users who are uncomfortable with this level of access should consider alternative security solutions with less invasive methods.
