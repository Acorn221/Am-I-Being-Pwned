# Vulnerability Report: FlowCrypt: Encrypt Gmail with PGP

## Metadata
- **Extension ID**: bnjglocicdkmhmoohhfkfkbbkejdhdgc
- **Extension Name**: FlowCrypt: Encrypt Gmail with PGP
- **Version**: 8.5.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FlowCrypt is a well-established, legitimate browser extension that provides end-to-end PGP encryption for Gmail. The extension uses OpenPGP.js for cryptographic operations and follows security best practices throughout its codebase. Analysis of the extension revealed no security vulnerabilities or privacy concerns. The extension's stated purpose is to secure email communications through encryption, and the implementation aligns with this purpose without any hidden or malicious functionality.

The static analyzer flagged several postMessage listeners in the forge.js library without explicit origin checks, but these are used for secure Web Worker communication for cryptographic operations and are not exploitable attack vectors. The extension uses chrome.scripting.executeScript only for legitimate content script injection into Gmail and for checking injection status.

## Vulnerability Details

No vulnerabilities were identified in this extension.

## False Positives Analysis

### 1. postMessage Listeners Without Origin Checks (forge.js)
The static analyzer identified six postMessage event listeners in lib/forge.js (and lib/forge.mjs) without explicit origin checks. However, these are part of the forge cryptographic library used for random number generation between Web Workers and the main thread. The message structure is highly specific (`data.forge.prng`) and used only for internal cryptographic operations, not for external communication. This is not an exploitable vulnerability.

**Evidence from lib/forge.js:14177-14198:**
```javascript
ctx.registerWorker = function(worker) {
  if(worker === self) {
    ctx.seedFile = function(needed, callback) {
      function listener(e) {
        var data = e.data;
        if(data.forge && data.forge.prng) {
          self.removeEventListener('message', listener);
          callback(data.forge.prng.err, data.forge.prng.bytes);
        }
      }
      self.addEventListener('message', listener);
      self.postMessage({forge: {prng: {needed: needed}}});
    };
  }
}
```

### 2. chrome.scripting.executeScript Usage
The extension uses `chrome.scripting.executeScript` in two legitimate contexts:
1. **Checking injection status** - to verify if content scripts are already injected into Gmail tabs
2. **Reading window globals** - to retrieve the current Gmail account email for context

Both uses are benign and necessary for the extension's functionality.

### 3. WASM and Obfuscated Flags
The static analyzer flagged WASM and obfuscated code. The WASM is likely part of the cryptographic libraries (OpenPGP.js), which is expected for performance-critical encryption operations. The "obfuscated" code appears to be minified third-party libraries, not intentionally obfuscated malicious code.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| flowcrypt.com | FlowCrypt backend services (message upload, configuration) | Encrypted messages, configuration requests | LOW - Legitimate service for the extension's stated purpose |
| google.com / googleapis.com | Gmail API, OAuth authentication | OAuth tokens, email metadata | LOW - Standard Gmail integration |
| keys.openpgp.org | Public key lookup | Email addresses for key discovery | LOW - Standard PGP keyserver |
| outlook.live.com / outlook.office365.com | Microsoft Outlook integration | OAuth tokens, email metadata | LOW - Optional Outlook support |
| graph.microsoft.com | Microsoft Graph API | API requests for Microsoft services | LOW - Optional Microsoft integration |
| login.microsoftonline.com | Microsoft OAuth | OAuth authentication flows | LOW - Standard Microsoft OAuth |

## Content Security Policy Analysis

The extension implements a strict CSP:
```
script-src 'self';
frame-ancestors https://mail.google.com 'self';
img-src 'self' https://* data: blob:;
frame-src 'self' blob:;
worker-src 'self';
form-action 'none';
media-src 'none';
font-src 'none';
manifest-src 'none';
object-src 'none';
base-uri 'self';
```

This is a strong CSP that prevents inline script execution and limits resource loading to trusted sources.

## Code Quality and Security Practices

1. **Proper error handling** - Comprehensive try-catch blocks with stack trace augmentation
2. **Secure storage** - Uses Chrome storage API with encryption key storage
3. **OAuth implementation** - Standard Google and Microsoft OAuth flows
4. **Message passing security** - Internal message handlers validate message types
5. **No dynamic code execution** - No eval() or Function() calls in core logic (only in libraries)
6. **CORS handling** - Properly routes requests through background page to avoid content script CORS issues

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**: FlowCrypt is a legitimate, well-maintained PGP encryption extension with no security vulnerabilities or privacy concerns. The extension's behavior fully aligns with its stated purpose of providing end-to-end encryption for Gmail. All network requests are to expected endpoints for email service integration and cryptographic key management. The codebase demonstrates security-conscious development practices including proper CSP, secure storage, and no use of dangerous APIs. The static analyzer flags are all false positives related to legitimate cryptographic library usage and standard content script injection patterns.
