# Vulnerability Report: Контур.Плагин

## Metadata
- **Extension ID**: hnhppcgejeffnbnioloohhmndpmclaga
- **Extension Name**: Контур.Плагин
- **Version**: 3.1.7
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Контур.Плагин is a legitimate enterprise browser extension developed by SKB Kontur for performing cryptographic operations in their services. The extension acts as a bridge between web pages and a native messaging host (`kontur.plugin`) that handles cryptographic functions such as digital signatures and certificate operations. The extension restricts most functionality to Kontur domains (`.kontur.ru`, `.kontur-ca.ru`, etc.) and has a legitimate business purpose.

However, the extension contains a medium-severity vulnerability in its postMessage handler that does not properly validate message origins. While the extension does implement some domain checking for critical operations like `extension.uninstall`, the message handler itself accepts messages from any origin, creating a potential attack surface for malicious pages.

## Vulnerability Details

### 1. MEDIUM: PostMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content.js (line 122)
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The content script registers a message event listener on line 122 without properly validating the origin of incoming messages. While the handler does perform some basic checks (comparing `ev.origin === 'null'` and checking `ev.source != window`), it does not enforce that messages come from trusted origins.

**Evidence**:
```javascript
function handleMessage(ev) {
    if (ev.origin === 'null' || ev.source != window || !ev.data) {
        return;
    }

    var data = ev.data;
    if (data.type !== REQUEST_TYPE)
        return;

    var request = data.request;
    if (!request || !request.sessionId)
        return;

    // Special handling for uninstall only checks IS_KONTUR_HOST
    if (request.type === 'extension.uninstall') {
        if (!IS_KONTUR_HOST) {
            // Reject non-Kontur domains
            return;
        }
        // ...
    }

    // All other request types are forwarded without origin check
    request.hostUri = ev.origin;
    send(request);
}

window.addEventListener('message', handleMessage, false);
```

**Verdict**: The vulnerability is somewhat mitigated by several factors:
1. The extension only injects its content script on all pages (match_about_blank and all_frames), but domain checking (`IS_KONTUR_HOST`) restricts critical operations
2. The `extension.uninstall` operation explicitly checks that the current page is on a Kontur domain
3. Most requests are forwarded to the native messaging host, which likely performs its own validation
4. The extension primarily operates as a bridge to the native host rather than performing sensitive operations in the content script itself

However, a malicious page could potentially craft messages that trigger unexpected behavior or probe the extension's capabilities. The risk is elevated because the extension has `*://*/*` host permissions and runs on all pages.

## False Positives Analysis

**Native Messaging for Cryptographic Operations**: The extension's use of `nativeMessaging` permission and connection to `kontur.plugin` is legitimate for an enterprise cryptographic plugin. This is the standard pattern for extensions that need to access system-level cryptographic APIs or smart cards.

**Broad Host Permissions**: The `*://*/*` host permission is necessary because users may access Kontur services from various domains and subdomains. The extension implements domain checking in JavaScript rather than manifest restrictions.

**Extension Self-Uninstall**: The `chrome.management.uninstallSelf()` call (line 84 in background.js) is protected by domain checking and is a legitimate feature for enterprise software that allows remote management/decommissioning.

**Auto-closing Installation Tabs**: The `closeExtensionInstallPages()` function that automatically closes Chrome Web Store tabs is a UX feature to clean up after installation, not malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Messaging Host | Cryptographic operations | User requests including potentially sensitive data | LOW - Standard enterprise crypto bridge pattern |

The extension does not communicate with any web-based API endpoints. All communication is through the browser's native messaging interface to a locally-installed component.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate enterprise tool from SKB Kontur (a major Russian business software provider) serving 1 million users. The extension's core functionality - bridging web pages to a native cryptographic component - is appropriate for its stated purpose of "performing cryptographic operations in SKB Kontur services."

The MEDIUM risk rating is assigned due to:

1. **PostMessage Vulnerability**: The lack of proper origin validation in the message handler creates an attack surface, even though mitigations are in place for critical operations
2. **Broad Permissions**: The combination of `*://*/*` host permissions, `nativeMessaging`, and `scripting` permissions creates a large attack surface if the postMessage handler is exploited
3. **Enterprise Context**: This is a legitimate enterprise tool, not malware, but the vulnerability could potentially be exploited by malicious pages to interact with the native messaging host in unexpected ways

The extension does NOT exhibit:
- Data exfiltration to remote servers
- Credential theft
- Hidden malicious behavior
- Code obfuscation
- Ad injection or affiliate fraud

**Recommendations**:
1. Implement strict origin validation in the postMessage handler to only accept messages from whitelisted Kontur domains
2. Consider using `externally_connectable` manifest key to restrict which domains can send messages
3. Add CSP (Content Security Policy) to prevent potential injection attacks
4. Perform origin checking before forwarding any request to the native messaging host, not just for uninstall operations
