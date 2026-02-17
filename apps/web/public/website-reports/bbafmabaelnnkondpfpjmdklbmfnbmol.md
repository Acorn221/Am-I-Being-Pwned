# Vulnerability Report: Web Signer

## Metadata
- **Extension ID**: bbafmabaelnnkondpfpjmdklbmfnbmol
- **Extension Name**: Web Signer
- **Version**: 2.17.1
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Web Signer is a legitimate digital signature extension developed by Softplan (Brazil) for document signing using PKI certificates. The extension requires native messaging to communicate with a local native application (br.com.softplan.webpki) for cryptographic operations. While the extension serves a legitimate purpose, it contains a **MEDIUM** severity vulnerability in the form of multiple postMessage listeners without origin validation, which could allow malicious websites to send crafted messages to the extension's content script and potentially trigger unintended behavior.

The extension's core functionality involves bridging web pages with a native PKI application for digital signatures, which is a legitimate use case for enterprise and government applications. However, the implementation exposes an attack surface through unprotected message event listeners.

## Vulnerability Details

### 1. MEDIUM: postMessage Listener Without Origin Validation

**Severity**: MEDIUM
**Files**: scripts/content-script.js (line 32), scripts/forge-cipher.js (lines 169, 3002, 6559)
**CWE**: CWE-346 (Origin Validation Error)

**Description**: The extension registers multiple `window.addEventListener("message")` handlers without validating the origin of incoming messages. This allows any website to send messages to these listeners, potentially triggering extension functionality on behalf of malicious origins.

**Evidence**:

In `scripts/content-script.js`:
```javascript
window.addEventListener('message', function (event) {
    if (event && event.data && event.data.port === requestEventName) {
        onPageMessage(event.data.message);
    }
});
```

The code checks for the presence of `event.data.port` but does not validate `event.origin` to ensure the message comes from a trusted source. This allows any website to craft a message with the expected port name and send it to the content script.

In `scripts/forge-cipher.js`:
```javascript
window.addEventListener('message', handler, true);
```

Multiple instances in the Forge library (used for cryptography) also listen to window messages without origin checks.

**Verdict**: While the extension requires the message to have a specific structure (`event.data.port === requestEventName`), this is insufficient protection. A malicious website could inspect the extension's code and craft appropriately formatted messages. However, exploitation requires understanding the internal message protocol and the extension appears to be designed only for specific trusted domains (websigner.softplan.com.br). The risk is mitigated by the fact that actual cryptographic operations require user interaction through the native application.

### 2. LOW: Content Script Injected on All URLs

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-250 (Execution with Unnecessary Privileges)

**Description**: The content script is injected into all HTTP/HTTPS pages with `all_frames: true`, which increases the attack surface unnecessarily.

**Evidence**:
```json
"content_scripts": [
    {
        "matches": [ "http://*/*", "https://*/*" ],
        "js": [ "scripts/content-script.js" ],
        "all_frames": true
    }
]
```

**Verdict**: While broad content script injection is not ideal, the extension's functionality requires it to be available on any page where digital signing might be needed. This is a design choice for maximum compatibility rather than a direct vulnerability, but it does increase the potential attack surface.

## False Positives Analysis

1. **Native Messaging**: The extension uses the `nativeMessaging` permission and `chrome.runtime.connectNative()` extensively. This is the expected and legitimate behavior for a digital signature extension that needs to interface with local PKI hardware/software.

2. **Webpack Bundled Code**: The extension includes webpack-bundled libraries (forge-cipher.js, main.js). These are standard build artifacts, not obfuscated malware. The ext-analyzer flagged the code as "obfuscated," but this is webpack's module bundling format, which is standard practice.

3. **Third-party Libraries**: The extension includes legitimate cryptography libraries:
   - Forge (forge-cipher.js) - PKI and TLS library
   - SJCL (sjcl.js) - Stanford JavaScript Crypto Library
   - SignalR client - for real-time communication

4. **Remote Domains**: The extension references legitimate Softplan domains:
   - `websigner.softplan.com.br` - official setup site
   - `restpki.lacunasoftware.com` - REST PKI service (Lacuna Software is the vendor)

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| websigner.softplan.com.br | Extension setup/installation page | None (navigation only) | None |
| websignerbeta.softplan.com.br | Beta testing environment | None (navigation only) | None |
| restpki.lacunasoftware.com | REST PKI service endpoints | Certificate/signature data | Low (expected for PKI extension) |
| restpki.com | Alternative REST PKI endpoint | Certificate/signature data | Low (expected for PKI extension) |

**Note**: All network communication appears to go through the native application rather than directly from the extension. The extension primarily acts as a bridge between web pages and the native PKI application.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

Web Signer is a legitimate enterprise digital signature extension with a clear and documented purpose. The extension properly uses native messaging to interface with local PKI infrastructure, which is the correct architectural approach for this use case.

However, the extension contains a **MEDIUM** severity vulnerability in its postMessage event handling. The lack of origin validation on message event listeners creates a potential attack vector where malicious websites could send crafted messages to the extension. While exploitation would require understanding the internal protocol and the native application likely provides additional security controls, this represents a weakness in the extension's security posture.

The risk is elevated to MEDIUM rather than LOW due to:
1. The large user base (1 million+ users)
2. The sensitive nature of the functionality (digital signatures for legal documents)
3. The broad content script injection (all URLs, all frames)

The risk is not elevated to HIGH because:
1. Actual cryptographic operations require user interaction through the native application
2. The extension appears designed for use only on specific trusted domains
3. The native application likely validates requests independently
4. No evidence of data exfiltration or malicious behavior

**Recommendations**:
1. Add origin validation to all `window.addEventListener("message")` handlers
2. Implement a whitelist of allowed origins (e.g., `websigner.softplan.com.br`)
3. Consider restricting content script injection to specific domains where the extension is intended to be used
4. Implement Content Security Policy directives to further restrict message passing
