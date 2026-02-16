# Vulnerability Report: Lexmark Cloud Print Management for Chrome

## Metadata
- **Extension ID**: ckfgjlakjcboggkbojkdoookoeogpifc
- **Extension Name**: Lexmark Cloud Print Management for Chrome
- **Version**: 2.0.2.179
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Lexmark Cloud Print Management is a legitimate enterprise printing extension developed by Lexmark International. The extension provides cloud-based print management functionality through OAuth2-authenticated communication with Lexmark's identity provider and print management APIs. The extension uses WebAssembly (WASM) for client-side token encryption/decryption using CryptoPP libraries, which is a security-conscious design choice to protect authentication tokens.

The static analyzer flagged one data exfiltration flow (storage.local.get → fetch), but this is an expected false positive for a cloud printing service that must send print jobs and authentication credentials to Lexmark's backend. All network communications are scoped to legitimate Lexmark domains (*.iss.lexmark.com), and the extension follows OAuth2 best practices including PKCE-like flows with encrypted token storage.

## Vulnerability Details

### 1. LOW: CSP with wasm-unsafe-eval

**Severity**: LOW
**Files**: manifest.json
**CWE**: CWE-1188 (Insecure Default Initialization of Resource)
**Description**: The extension's Content Security Policy for extension pages includes 'wasm-unsafe-eval', which is required to instantiate WebAssembly modules but slightly weakens the CSP protection.

**Evidence**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

**Verdict**: This is a necessary configuration for extensions using WASM. The extension properly uses WASM for cryptographic operations (token encryption/decryption), making this directive required rather than a security weakness. No arbitrary code execution risk.

## False Positives Analysis

### Storage.local.get → fetch Flow
The static analyzer correctly identified a flow from `chrome.storage.local.get` to `fetch()` in `lxkAPI.js`. However, this is the expected behavior for a cloud printing service:

1. **Token Management**: The extension retrieves encrypted OAuth tokens from storage and sends them to Lexmark's IDP for validation
2. **Print Job Submission**: Retrieved print configuration is sent to Lexmark's print management API
3. **Scoped Access**: All fetch calls target legitimate Lexmark domains defined in host_permissions

```javascript
// lxkAPI.js lines 123-159: Legitimate token retrieval and validation
chrome.storage.local.get(['UserToken'], (result) => {
    // WASM decryption using CryptoPP
    const getToken = Module.cwrap('getToken', 'string', ['array', 'number'])
    valTok = getToken(parsed, parsed.length);

    // Send to Lexmark IDP for validation
    that.validateToken().then(...)
})
```

### WASM Binary Analysis
The WASM module (TokenManager.wasm, 167KB) contains CryptoPP library signatures for:
- SHA1-HMAC
- PKCS5_PBKDF2 (password-based key derivation)
- AES-CBC encryption (Rijndael)
- AutoSeededRandomPool

These are legitimate cryptographic primitives used to encrypt/decrypt OAuth tokens stored in chrome.storage.local, preventing token theft if storage is compromised.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://idp.eu.iss.lexmark.com/oauth/authorize | OAuth2 authorization | Client ID, redirect URI | CLEAN |
| https://idp.eu.iss.lexmark.com/oauth/token | Token exchange | Auth code, client secret (from WASM), refresh token | CLEAN |
| https://idp.eu.iss.lexmark.com/oauth/token/info | Token validation | Bearer token | CLEAN |
| https://apis.eu.iss.lexmark.com/cpm/print-management-service/v3.0 | Print job submission | PDF document, print options, client metadata | CLEAN |
| https://eu.iss.lexmark.com/cpm | LPM UI | User interaction | CLEAN |

All endpoints are scoped to Lexmark's infrastructure (*.iss.lexmark.com) via host_permissions, preventing misuse.

## Client Metadata Collection

The extension collects minimal client information when submitting print jobs:

```javascript
// lxkAPI.js lines 723-728
request.client = {
  "type": "chrome",
  "version": chrome.runtime.getManifest().version,
  "browserVersion": navigator.appVersion.match(/.*Chrome\/([0-9\.]+)/)[1],
  "browserOsName": that.platformInfo.os
};
```

This metadata is typical for enterprise cloud services to support client debugging and compatibility tracking. No sensitive user data is collected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**: This is a legitimate enterprise extension with proper security practices:

1. **Scoped Permissions**: Host permissions limited to *.iss.lexmark.com
2. **OAuth2 Implementation**: Follows standard authorization code flow with refresh tokens
3. **Token Encryption**: Uses WASM-based CryptoPP encryption to protect stored tokens
4. **No Credential Theft**: Authentication flows use standard browser OAuth2 via chrome.identity API and custom tabs
5. **Transparent Purpose**: All network activity aligns with cloud printing functionality
6. **Enterprise Configuration**: Supports managed_schema for enterprise policy deployment

The only minor concern is the use of 'wasm-unsafe-eval' in CSP, but this is necessary for the WASM cryptographic module and does not introduce exploitable vulnerabilities. The extension is suitable for enterprise deployment.
