# Vulnerability Report: Hoppscotch Browser Extension

## Metadata
- **Extension ID**: amknoiejhlmhancpahfcfcfhllgkpbld
- **Extension Name**: Hoppscotch Browser Extension
- **Version**: 0.37
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

The Hoppscotch Browser Extension is a legitimate tool designed to provide additional capabilities for the Hoppscotch API testing platform (formerly Postwoman). The extension acts as a bridge to enable cross-origin HTTP requests and handle advanced features like cookie management, form data, and binary content that the web application cannot perform directly due to browser security restrictions.

While the extension's functionality is legitimate and serves its stated purpose, there is a medium-severity vulnerability related to message handling in the hookContent.js script. The script registers a `window.addEventListener("message")` handler without performing proper origin validation before processing messages, which could theoretically allow malicious websites to inject commands. However, this risk is mitigated by the fact that the content script validates the origin list before forwarding requests to the background script, and the hook is only injected on validated origins.

## Vulnerability Details

### 1. MEDIUM: Unsafe postMessage Handler in Injected Hook

**Severity**: MEDIUM
**Files**: hookContent.js:121
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**:
The hookContent.js script, which is injected into the main world of trusted origins (by default https://hoppscotch.io), registers a `window.addEventListener("message")` handler without immediately validating the event origin. The handler processes messages of types `__POSTWOMAN_EXTENSION_RESPONSE__` and `__POSTWOMAN_EXTENSION_ERROR__` that are meant to come from the content script, but the listener itself doesn't explicitly check `ev.origin`.

**Evidence**:
```javascript
function handleMessage(ev) {
    if (ev.source !== window || !ev.data) return;
    if (ev.data.type === "__POSTWOMAN_EXTENSION_RESPONSE__") {
        // Apply transformation from base64 to arraybuffer
        if (ev.data.isBinary) {
            const bytes = ev.data.response.data.length / 4 * 3;
            const ab = new ArrayBuffer(bytes);
            window.__POSTWOMAN_EXTENSION_HOOK__.decodeB64ToArrayBuffer(ev.data.response.data, ab);
            ev.data.response.data = ab;
        }
        resolve(ev.data.response);
        window.removeEventListener("message", handleMessage);
    } else if (ev.data.type === "__POSTWOMAN_EXTENSION_ERROR__") {
        // ... processes error without origin check
    }
}
window.addEventListener("message", handleMessage);
```

The handler only checks `ev.source !== window`, which verifies the message comes from the same window context, but doesn't validate the origin of cross-frame messages.

**Verdict**:
This is a **medium-risk** vulnerability rather than high because:
1. The hookContent.js script is only injected on explicitly trusted origins (stored in chrome.storage.sync and defaulting to https://hoppscotch.io)
2. The content script (contentScript.js) validates the origin before forwarding requests to the background script
3. For an attack to succeed, a malicious actor would need to compromise a trusted origin or trick the user into adding a malicious origin to the allow list
4. The hook operates in the MAIN world, so the `ev.source !== window` check does provide some protection against cross-frame injection

However, if a trusted origin is compromised or contains an XSS vulnerability, a malicious script could potentially inject fake responses or errors that would be processed by the promise handlers.

## False Positives Analysis

**Parcel Bundler Code**: The extension uses Parcel for bundling, which creates wrapper functions like `parcelRequire` and module registration patterns. This is standard build tooling, not obfuscation. While ext-analyzer flagged the extension as "obfuscated," this is actually normal Parcel bundled code with source maps included for debugging.

**Powerful Permissions**: The extension requests `<all_urls>`, `cookies`, `tabs`, and `scripting` permissions. These are necessary for its legitimate function:
- `<all_urls>`: Required to make HTTP requests to any domain the user is testing
- `cookies`: Needed to set/manage cookies for API requests
- `scripting`: Used to inject the hook script into trusted pages
- `tabs`: Required for communication with content scripts

**Message Passing Architecture**: The extension uses a three-layer architecture (page context → content script → background script) which is a secure pattern for browser extensions. The contentScript.js properly validates origins before forwarding requests.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | The extension acts as a proxy and makes requests to user-specified URLs | User-configured request data (headers, body, cookies) | LOW - No hardcoded external endpoints |

The extension does not communicate with any hardcoded external servers. All HTTP requests are initiated by the user through the Hoppscotch web interface and proxied through the extension to bypass CORS restrictions. The extension has no telemetry, analytics, or data exfiltration endpoints.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
The Hoppscotch Browser Extension is a legitimate, open-source tool that performs exactly as advertised - it enables API testing capabilities for the Hoppscotch platform. The extension follows security best practices in most areas:
- Origin validation before processing requests (contentScript.js lines 37-40)
- Separate execution contexts for security isolation
- No hardcoded external endpoints
- Cookie cleanup after requests
- Object URL revocation after use

The medium risk rating is due to the postMessage handler in hookContent.js lacking explicit origin validation. While the overall architecture provides defense in depth (the hook is only injected on trusted origins, and the content script validates origins), adding explicit `event.origin` checks in the message handlers would eliminate a potential attack vector if a trusted origin were compromised.

**Recommendation**: Add explicit origin validation in hookContent.js message handlers to verify messages come from the expected origin before processing responses or errors. This would make the extension fully secure against message injection attacks even if a trusted origin is compromised.
