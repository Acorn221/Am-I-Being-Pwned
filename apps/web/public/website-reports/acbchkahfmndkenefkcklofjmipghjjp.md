# Vulnerability Report: Адаптер Рутокен Коннект

## Metadata
- **Extension ID**: acbchkahfmndkenefkcklofjmipghjjp
- **Extension Name**: Адаптер Рутокен Коннект (Rutoken Connect Adapter)
- **Version**: 6.1.1
- **Users**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Адаптер Рутокен Коннект (Rutoken Connect Adapter) is a legitimate enterprise security extension developed by Aktiv Co. for the Russian market. The extension provides secure TLS connections in the browser using GOST cryptographic algorithms via Rutoken hardware security modules (HSMs). It communicates with a companion native application (`ru.rutoken.rtconnect`) to enable two-factor authentication, encryption, and digital signatures compliant with Russian cryptographic standards (GOST R 34.10-2001, GOST R 34.11-94, GOST 28147-89).

While the extension requests broad permissions including `<all_urls>` host access, proxy control, webRequest interception, and native messaging, these are all necessary for its stated purpose of providing GOST-compliant cryptographic operations through browser-based proxy/TLS modification. The static analyzer flagged the code as "obfuscated," but this is webpack bundling, not malicious obfuscation. No exfiltration flows, unauthorized data collection, or malicious behavior was detected.

## Vulnerability Details

### No Security or Privacy Concerns Found

After thorough analysis of the extension's codebase, no security vulnerabilities or privacy issues were identified. The extension operates as a legitimate cryptographic adapter with the following characteristics:

**Files Analyzed**: background.js (205KB), content.js, login.js, error.js, options.js

**Evidence**:
- The extension uses Apache Thrift for structured RPC communication with the native host
- Native messaging is properly scoped to application ID `ru.rutoken.rtconnect`
- Content script is minimal (186 bytes), only sends status via postMessage with fixed UUID
- No external API endpoints contacted (only Chrome Web Store update URL)
- All UI components (login.html, error.html) are local resources
- Proxy and webRequest permissions used exclusively for TLS/certificate operations

**Verdict**: The extension's architecture and implementation are consistent with a legitimate cryptographic hardware token adapter. The permissions align with its documented functionality.

## False Positives Analysis

### 1. Webpack Bundling Misidentified as Obfuscation
The static analyzer flagged the extension as "obfuscated," but examination reveals standard webpack module bundling with Apache Thrift library inclusion. The code structure shows:
- Clear module boundaries (`__webpack_modules__`)
- Readable protocol definitions (Thrift types, exception handling)
- Standard webpack runtime code patterns

This is NOT malicious obfuscation but normal build tooling.

### 2. Broad Permissions Are Contextually Appropriate
For a cryptographic TLS adapter that modifies browser-level secure connections, the following permissions are legitimate:
- `proxy`: Required to intercept and modify TLS handshakes for GOST algorithms
- `webRequest` + `<all_urls>`: Required to identify connections requiring GOST certificates
- `nativeMessaging`: Required to communicate with Rutoken hardware via native app
- `scripting`: Required to inject certificate selection UI when needed

These permissions would be excessive for a typical extension, but are standard for enterprise PKI/HSM adapters.

### 3. Russian Language and Cyrillic Characters
The extension name and all UI text are in Russian (Cyrillic). This is expected as Rutoken is a Russian cryptographic standard (analogous to how FIPS 140-2 is US-specific). The use of Russian GOST standards does not indicate malicious intent.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://clients2.google.com/service/update2/crx` | Chrome Web Store auto-update | Extension version info (Chrome built-in) | None - Standard CWS update mechanism |
| Native Host: `ru.rutoken.rtconnect` | Local IPC with Rutoken Connect native application | Certificate requests, cryptographic operation parameters | None - Local-only communication |

**No external network endpoints detected** beyond the standard Chrome update mechanism.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
This extension is a legitimate enterprise cryptographic adapter with over 1 million users, primarily in Russia and former Soviet states where GOST cryptographic compliance is legally required for government/banking systems. The extension's architecture, permissions, and behavior are entirely consistent with its stated purpose as a hardware security module adapter for GOST-compliant TLS.

The low rating (1.6 stars) likely reflects user experience issues with cryptographic token compatibility or installation complexity, not security concerns. Common complaints for HSM adapters typically involve driver conflicts, certificate enrollment UX, and compatibility across different token models.

**Recommendations**:
- This extension should be considered CLEAN with no security concerns
- Users should verify they download from the official Chrome Web Store to avoid supply chain attacks
- Organizations using this extension should ensure the companion native application (`ru.rutoken.rtconnect`) is obtained from official Aktiv Co. sources
- Regular updates should be monitored as cryptographic standards evolve

**References**:
- Rutoken is a legitimate Russian HSM/smart card manufacturer (Aktiv Co.)
- GOST cryptographic algorithms are Russian federal standards
- Similar to how Western enterprises use Yubikey/smart card extensions with broad permissions
