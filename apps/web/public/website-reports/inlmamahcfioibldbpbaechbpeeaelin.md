# Vulnerability Report: Помощник диагностики (Diagnostics Helper)

## Metadata
- **Extension ID**: inlmamahcfioibldbpbaechbpeeaelin
- **Extension Name**: Помощник диагностики (Diagnostics Helper)
- **Version**: 3.0.30
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a legitimate native messaging extension developed by Kontur (a Russian business software company) for diagnostic and support purposes. The extension acts as a bridge between Kontur web applications and a native diagnostic client (kd.nc). While the extension is designed for legitimate enterprise support workflows, it contains a **medium-severity security vulnerability** in its content script that accepts postMessage commands from any origin without proper validation before forwarding them to the background script. Although the background script implements origin checking before accessing the native host, the initial postMessage handler in the content script lacks origin validation, creating a potential attack vector.

The extension's primary purpose is to facilitate communication between Kontur's help/support websites and a locally installed diagnostic tool, which is a reasonable use case for enterprise software. However, the implementation contains security weaknesses that should be addressed.

## Vulnerability Details

### 1. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)
**Description**: The content script registers a window message event listener that processes messages without validating the origin of the sender.

**Evidence**:
```javascript
// content.js:74
window.addEventListener("message", handleMessage, false);

function handleMessage(ev) {
    var data = ev.data;
    if (!data) {
        return;
    }

    var type = data.type,
        newType = type === REQUEST_TYPE;
    if (newType || (type === OLD_REQUEST_TYPE)) {
        if (newType) {
            useNewType = true;
        }
        var request = data.request,
            origin = ev.origin || window.location.origin;
        request.origin = origin;
        send(request, origin);  // Forwards to background without validation
    }
}
```

The handler accepts messages with types "white-diag-request" or "diag-helper-request" from any source without checking `ev.origin`. While it does capture and forward the origin to the background script, a malicious page loaded in the same tab could send crafted messages that would be processed by the extension.

**Verdict**: This is a classic postMessage origin validation issue. While the background script has origin checks (`checkAccess()` function), the content script should perform basic origin validation before forwarding messages to avoid unnecessary processing of untrusted data. An attacker could potentially craft messages to probe the extension's behavior or attempt to bypass backend validation through race conditions or timing attacks.

### 2. MEDIUM: Broad Host Permissions with Dynamic Script Injection

**Severity**: MEDIUM
**Files**: background.js, manifest.json
**CWE**: CWE-269 (Improper Privilege Management)
**Description**: The extension requests `<all_urls>` host permissions and dynamically injects content scripts into all tabs during installation/update.

**Evidence**:
```javascript
// background.js:145-173
function reloadContentScripts() {
    var scripts = manifest.content_scripts[0].js;

    chrome.tabs.query({}, function(tabs) {
        tabs.forEach(function(tab) {
            if ((tab.status == "unloaded") || /^chrome:/.test(tab.url)) {
                return;
            }
            chrome.scripting.executeScript({
                target: {
                    tabId: tab.id,
                    allFrames: true,
                },
                files: scripts,
            }, ...);
        });
    });
}

chrome.runtime.onInstalled.addListener(function(details) {
    reloadContentScripts();
    ...
});
```

**Verdict**: While the extension only actively uses the content script on specific Kontur domains (help.kontur.ru, install.kontur.ru, etc.), it requests overly broad `<all_urls>` permissions. The dynamic script injection on all tabs during updates is a common pattern for MV3 extensions to ensure content scripts are active without requiring page refreshes. However, this creates a large attack surface if the extension were compromised. The permissions should ideally be restricted to only the domains where the extension actually operates.

## False Positives Analysis

1. **Native Messaging Usage**: The extension's use of `chrome.runtime.connectNative('kd.nc')` is legitimate for its stated purpose as a diagnostic helper tool. This is standard for enterprise support extensions.

2. **Extension Self-Uninstall**: The command handler includes a self-uninstall feature (cmd == -7) that checks the extension ID before executing. This is a legitimate remote management capability for enterprise deployments.

3. **Web Store Tab Closing**: The `closeWebStorePage()` function that automatically closes Chrome Web Store tabs after installation is a user experience feature, not malicious behavior.

4. **Origin Tracking**: The background script does implement proper origin validation via the `checkAccess()` function, which restricts access to legitimate Kontur domains.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| help.kontur.ru | Support/help website | User requests forwarded to native host | Low - legitimate domain |
| install.kontur.ru | Installation support | Installation diagnostics | Low - legitimate domain |
| tp.kontur.ru | Technical support portal | Diagnostic commands | Low - legitimate domain |
| localhost.testkontur.ru | Local testing | Development/test data | Low - test environment |
| *.testkontur.ru | Test environments | Test data | Low - staging environments |

All endpoints are owned by Kontur and used for legitimate diagnostic purposes. The extension does not communicate with any third-party or external domains beyond Kontur's infrastructure.

## Security Recommendations

1. **Add Origin Validation**: The content script should validate `ev.origin` against an allowlist before processing postMessage events:
   ```javascript
   function handleMessage(ev) {
       // Validate origin first
       if (!checkAllowedOrigin(ev.origin)) {
           return;
       }
       // ... rest of handler
   }
   ```

2. **Restrict Host Permissions**: Change `host_permissions` from `<all_urls>` to only the specific domains where the extension operates (the domains already listed in content_scripts matches).

3. **Add CSP Headers**: Implement Content Security Policy headers to further restrict the extension's capabilities.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: This is a legitimate enterprise diagnostic tool with a clear business purpose, but it contains implementation vulnerabilities that create security risks. The primary concern is the postMessage handler that lacks origin validation in the content script, which could allow malicious pages to interact with the extension's messaging infrastructure. While the background script does implement origin checks before accessing the native messaging host, defense-in-depth principles suggest that validation should occur at the earliest possible point.

The extension has 1 million users and is likely deployed in enterprise environments where Kontur's business software is used. The vulnerabilities identified are concerning but not critical, as they would require a sophisticated attack to exploit (malicious code execution on pages the user visits, combined with precise timing to bypass backend validation). The extension does not appear to collect or exfiltrate user data beyond its diagnostic purpose, and all communication is restricted to Kontur's own domains.

The risk is elevated from LOW to MEDIUM due to the combination of broad permissions (`<all_urls>`), native messaging access (which can interact with the local system), and the postMessage vulnerability. Organizations deploying this extension should ensure they trust Kontur and monitor for updates that address these security concerns.
