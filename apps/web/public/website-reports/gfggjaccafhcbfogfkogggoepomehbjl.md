# Vulnerability Report: AdGuard AdBlocker MV2

## Metadata
- **Extension ID**: gfggjaccafhcbfogfkogggoepomehbjl
- **Extension Name**: AdGuard AdBlocker MV2
- **Version**: 5.3.0.8
- **Users**: ~10,000,000+
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

AdGuard AdBlocker MV2 is a legitimate, widely-used ad-blocking browser extension from AdGuard Software Ltd, a reputable security vendor. The extension performs standard ad-blocking and privacy protection functions through content filtering, tracking protection, and malware/phishing site blocking. The static analyzer flagged one benign exfiltration flow and detected WASM usage and some obfuscated vendor code, but these are false positives consistent with legitimate ad-blocking technology.

The extension communicates with AdGuard's own infrastructure for filter updates and safe browsing lookups, which is expected and disclosed behavior. No malicious activity, undisclosed data collection, or privacy violations were identified.

## Vulnerability Details

### 1. LOW: Privacy Permission and Safe Browsing Queries
**Severity**: LOW
**Files**: vendors/tsurlfilter.js, pages/background.js
**CWE**: N/A (Expected Functionality)
**Description**: The extension includes safe browsing functionality that can query AdGuard's servers to check URLs against malware/phishing databases. The static analyzer flagged a `document.getElementById → fetch` flow in the bundled filtering library (tsurlfilter.js).

**Evidence**:
- Manifest requests optional "privacy" permission
- Locale strings reference "safebrowsing_enabled" feature
- Extension communicates with filters.adtidy.org for filter updates
- Extension may contact AdGuard domains for safe browsing lookups

**Verdict**: This is expected functionality for an ad-blocker with malware protection. The feature is disclosed in the extension description ("Phishing and malware protection") and can be disabled by users in settings. This represents standard security functionality, not a vulnerability.

## False Positives Analysis

The static analyzer flagged several patterns that are legitimate for this extension type:

1. **Obfuscated Flag**: The extension uses webpack bundling and includes vendor libraries (React, MobX, tsurlfilter) which produce minified/bundled code. This is standard modern web development practice, not malicious obfuscation.

2. **WASM Flag**: WebAssembly usage is legitimate for performance-critical filtering operations in ad-blockers. AdGuard likely uses WASM for efficient URL matching and filter processing.

3. **Exfiltration Flow**: The single flagged flow (`document.getElementById → fetch`) is part of the legitimate filtering engine that fetches filter updates and performs safe browsing lookups from AdGuard's own servers.

4. **Broad Permissions**: Permissions like `<all_urls>`, `webRequest`, and `webRequestBlocking` are required for ad-blocking functionality to inspect and block network requests across all websites.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| filters.adtidy.org | Filter list updates | Extension version, locale | Low - Standard update mechanism |
| adguard.com | Extension pages, documentation | User navigation data | Low - First-party website |
| adguard.info | Alternative domain for extension pages | User navigation data | Low - First-party website |
| adguard.app | Alternative domain for extension pages | User navigation data | Low - First-party website |

All endpoints are owned and operated by AdGuard Software Ltd, the extension developer. No third-party analytics or tracking services were identified.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
AdGuard AdBlocker MV2 is a legitimate, well-established extension from a reputable vendor with millions of users. The extension performs its stated function (ad-blocking and privacy protection) without undisclosed data collection or malicious behavior. The single low-severity finding relates to expected safe browsing functionality that is disclosed and user-controllable. The permissions requested are appropriate and necessary for ad-blocking technology. The WASM and bundled code are standard for modern, performance-optimized extensions.

The "LOW" risk rating reflects minor privacy considerations around the optional safe browsing feature, which requires communication with AdGuard servers. Users concerned about this can disable the feature in settings. Overall, this extension follows security best practices and poses minimal risk to users.
