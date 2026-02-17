# Vulnerability Report: I.CA PKI Service Component

## Metadata
- **Extension ID**: fdolcjnejgbpoadihncaggiicpkhjchl
- **Extension Name**: I.CA PKI Service Component
- **Version**: 2.2.1.0
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

I.CA PKI Service Component is a legitimate enterprise extension designed to bridge web applications with native PKI libraries for digital signature and authentication operations. The extension is specifically built for Czech banking institutions (CSOB), government services, and business platforms that require smart card or certificate-based authentication.

The extension acts as a secure bridge between web pages and a native host application (`cz.ica.icapkiservice.host`) that handles cryptographic operations. Host permissions are appropriately scoped to specific banking and government domains. The externally_connectable configuration allows these trusted domains to communicate with the extension. While this creates an attack surface, it is necessary for the extension's intended functionality and is limited to legitimate financial and government services.

## Vulnerability Details

### 1. LOW: Broad externally_connectable Configuration

**Severity**: LOW
**Files**: manifest.json, background.js
**CWE**: CWE-923 (Improper Restriction of Communication Channel to Intended Endpoints)
**Description**: The extension defines 19 domains in the `externally_connectable` manifest field, allowing external websites to send messages to the extension. This includes wildcards on multiple domains and localhost connections.

**Evidence**:
```json
"externally_connectable": {
  "matches": [
    "*://localhost/*",
    "*://*.localhost/*",
    "https://*.csob.cz/*",
    "https://*.csob.sk/*",
    "*://*.ica.cz/*",
    "*://*.proebiz.com/*",
    "*://*.digisign.org/*",
    "*://*.digisign.digital.cz/*",
    "*://*.circularo.com/*",
    "*://*.eon.com/*",
    "https://eonos.sharepoint.com/*",
    "https://*.narodni-ca.gov.cz/*",
    "*://*.servis.justice.cz/*",
    "*://pmstest002/*",
    "*://*.sukl.cz/*",
    "*://*.tatra.cz/*",
    "*://*.moneta.cz/*",
    "*://*.tsk-praha.cz/*",
    "*://*.brantner.sk/*"
  ]
}
```

The extension handles external messages through `onMessageFromPage()` which processes directives and forwards requests to the native host:
```javascript
chrome.runtime.onConnectExternal.addListener(connected);

function onMessageFromPage(m, sender) {
  // Process directives like DIR_EXTENSION_CONNECTED, DIR_EXTENSION_VERSION
  // Or forward to native messaging host
  if(m.type == DIR) {
    if(m.content == DIR_EXTENSION_CONNECTED) {
      sendMessageToPage(Directive(DIR_EXTENSION_CONNECTED), tabId);
    }
    // ...
  } else {
    messageRegister[m.id] = tabId;
    sendNativeMessage(m);
  }
}
```

**Verdict**: This is appropriate for a PKI authentication component. The domains listed are legitimate Czech banking institutions (CSOB, Tatra banka, mBank/Moneta), government services (justice.cz, narodni-ca.gov.cz, sukl.cz), and enterprise platforms. The extension validates message types and uses structured communication protocols. Localhost access is needed for development and testing environments.

## False Positives Analysis

1. **Native Messaging Permission**: The extension requires `nativeMessaging` to communicate with the native PKI host application (`cz.ica.icapkiservice.host`). This is the core functionality - it cannot perform cryptographic operations in JavaScript and must delegate to native libraries.

2. **Cookie Permission**: Used legitimately to retrieve session cookies that are then passed to the native host for authentication purposes (line 112-148 in background.js). The cookies are only retrieved for specific URLs and attached to PKI signing requests.

3. **Obfuscation Flag**: The static analyzer flagged the code as "obfuscated," but this appears to be a false positive. The deobfuscated code is clean, readable JavaScript with clear variable names and function purposes. The original code may have been minified but is not maliciously obfuscated.

4. **Localhost in Host Permissions**: Including `*://localhost/*` is necessary for development and testing environments where the banking/government applications may run locally.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| Native Host (cz.ica.icapkiservice.host) | PKI operations via native messaging | Signing requests, certificate operations, cookies for authentication | LOW - Local IPC only |

The extension does not make any external network requests. All communication is either:
- Between the extension and whitelisted web pages (via `chrome.runtime.onConnectExternal`)
- Between the extension and the local native host application (via `chrome.runtime.connectNative`)

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate enterprise PKI authentication extension with appropriate security controls for its intended purpose:

**Strengths**:
- Scoped host permissions limited to specific banking and government domains
- No external network requests or data exfiltration
- Structured message validation with typed directives
- Timeout mechanisms to terminate inactive native host connections
- Clear separation between extension, web pages, and native host
- User-configurable options for timeouts and logging
- Manifest V3 compliance

**Minor Concerns**:
- Broad externally_connectable surface (19 domains) - but all are legitimate financial/government services
- Cookie access - but used appropriately for authentication purposes
- Wildcard subdomain matching - but scoped to specific trusted parent domains

**Recommendation**: This extension is safe for use within its intended enterprise context (Czech banking and government services). The attack surface from externally_connectable is acceptable given the legitimate use case and the restriction to trusted domains. Organizations should verify they need this extension before installing it, as it only provides value when accessing the specific listed services.
