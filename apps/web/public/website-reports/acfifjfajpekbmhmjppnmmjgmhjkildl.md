# Vulnerability Report: Certisign WebSigner

## Metadata
- **Extension ID**: acfifjfajpekbmhmjppnmmjgmhjkildl
- **Extension Name**: Certisign WebSigner
- **Version**: 2.17.2
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Certisign WebSigner is a legitimate digital signature extension from Certisign (Brazil) that enables cryptographic operations through native messaging integration with a local PKI component. The extension provides digital signing capabilities (PDF/PAdES, CAdES, XML signatures) and interfaces with hardware tokens and smart cards via PKCS#11.

The primary security concern is the presence of multiple postMessage event listeners that accept messages from any origin (using wildcard '*'), creating potential cross-site messaging vulnerabilities. While the extension itself performs legitimate cryptographic functions and does not engage in malicious data collection, the lack of origin validation in message handlers represents a medium-severity security gap that could be exploited by malicious websites.

## Vulnerability Details

### 1. MEDIUM: postMessage Handlers Without Origin Validation

**Severity**: MEDIUM
**Files**: scripts/content-script.js, scripts/forge-cipher.js
**CWE**: CWE-346 (Origin Validation Error)

**Description**:
The extension implements several postMessage event listeners that fail to validate the origin of incoming messages. This creates a security vulnerability where any webpage can send messages to the extension's message handlers.

**Evidence**:

In `scripts/content-script.js` (lines 32-36):
```javascript
window.addEventListener('message', function (event) {
    if (event && event.data && event.data.port === requestEventName) {
        onPageMessage(event.data.message);
    }
});
```

The handler accepts messages from any origin without checking `event.origin`. While it does validate the message structure (`event.data.port === requestEventName`), this is insufficient as malicious sites could craft messages with the correct structure.

In `scripts/forge-cipher.js`, multiple postMessage listeners are present:
- Line 169: `window.addEventListener("message")` without origin check
- Line 3002: `window.addEventListener("message")` without origin check
- Line 6559: `window.addEventListener("message")` without origin check

Additionally, the Firefox fallback path (line 59-62) explicitly sends messages to any origin:
```javascript
window.postMessage({
    port: responseEventName,
    message: message
}, '*');  // wildcard origin
```

**Verdict**:
This is a legitimate security issue. While the extension's architecture uses custom events (`CustomEvent`) for Chrome/Edge which provides some isolation, the Firefox fallback and Web Worker message handlers use wildcard origins. An attacker on a malicious website could potentially inject crafted messages into the extension's message flow, potentially manipulating certificate selection, signature requests, or other cryptographic operations. The impact is reduced by the fact that critical operations still require native component interaction and user authorization.

### 2. LOW: Obfuscated Third-Party Libraries

**Severity**: LOW
**Files**: scripts/forge-cipher.js, scripts/sjcl.js
**CWE**: CWE-656 (Reliance on Security Through Obscurity)

**Description**:
The extension includes bundled/minified cryptographic libraries (Forge.js for RSA/PKI operations, SJCL for symmetric crypto) that have been packed through webpack/bundlers, making code review difficult.

**Evidence**:
The ext-analyzer flagged the extension as "obfuscated". While this appears to be standard webpack bundling rather than intentional obfuscation, the presence of minified crypto code reduces transparency.

**Verdict**:
This is not a security vulnerability per se - the libraries are legitimate open-source cryptographic implementations (Stanford Javascript Crypto Library and Forge). However, for a security-sensitive extension handling PKI operations, shipping minimized crypto code reduces auditability. This is a common practice but not ideal for security-critical extensions.

## False Positives Analysis

1. **Native Messaging for Local PKI Component**: The extension's core functionality requires native messaging to interact with a locally installed component (`br.com.certisign.websigner`) that interfaces with cryptographic hardware. This is the extension's stated purpose and not suspicious.

2. **Tab Permission and URL Access**: The extension requests `tabs` permission and injects content scripts on `<all_urls>`. For a digital signature tool that needs to work across various government/banking/document sites, this is expected behavior.

3. **Downloads Permission**: Used legitimately to download signed documents (PDF, CAdES signatures, etc.) after cryptographic operations complete.

4. **Storage Permission**: Used to cache certificate metadata, user preferences (trace logging), PKCS#11 module configurations, and remote device settings. No sensitive data is exfiltrated.

5. **External Endpoints**: All network requests are to Lacuna Software domains (the company behind WebPKI) for legitimate purposes:
   - `get.websignerplugin.com` - Installation/update site
   - `restpki.lacunasoftware.com` - REST PKI integration for cloud-based signature workflows
   - These are documented endpoints for the product's cloud features

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| get.websignerplugin.com | Extension installer/updater | None (navigation only) | Low |
| restpki.lacunasoftware.com | Cloud PKI signature service | Certificate data, signature tokens | Low (legitimate cloud PKI) |
| getwebpkibeta.lacunasoftware.com | Beta installer | None (navigation only) | Low |

All endpoints are first-party (Lacuna Software/Certisign) and serve legitimate purposes for the extension's digital signature functionality. No third-party analytics, advertising, or tracking endpoints detected.

## Attack Surface Summary

- **postMessage without origin checks**: 4 instances across content scripts and forge library
- **Native messaging**: Required for core functionality (local PKI component)
- **Content scripts on all URLs**: Necessary for signature functionality across diverse websites
- **No CSP violations**: No unsafe-inline or unsafe-eval detected
- **No dynamic code execution**: No eval, Function constructor, or executeScript usage found
- **No data exfiltration**: No flows detected where browsing data, cookies, or credentials are sent externally

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Certisign WebSigner is a legitimate enterprise PKI/digital signature tool with a substantial user base (~1M users, primarily in Brazil). The extension performs its stated function (digital signatures via local cryptographic hardware) without engaging in malicious behavior, data harvesting, or credential theft.

The MEDIUM risk rating is based solely on the postMessage origin validation issue, which represents a genuine security vulnerability that could be exploited by malicious websites to inject messages into the extension's workflow. While the practical exploitability is reduced by the architecture's reliance on native component authorization and the structured message format requirements, this still represents a security gap that should be addressed.

Recommendations for the developer:
1. Implement strict origin validation on all postMessage listeners
2. Use a whitelist of allowed origins based on extension configuration
3. Consider using chrome.runtime.sendMessage for extension-internal communication instead of window.postMessage
4. Avoid wildcard ('*') origins in postMessage calls

For users: This extension is safe to use for its intended purpose (digital signatures with Certisign certificates). The vulnerability requires active exploitation by a malicious website while the extension is in use, and critical operations still require user authorization through the native component.
