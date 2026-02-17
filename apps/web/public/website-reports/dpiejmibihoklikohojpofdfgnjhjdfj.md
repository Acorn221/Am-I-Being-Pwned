# Vulnerability Report: Adblock Ultra

## Metadata
- **Extension ID**: dpiejmibihoklikohojpofdfgnjhjdfj
- **Extension Name**: Adblock Ultra
- **Version**: 4.0.4
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Adblock Ultra is a legitimate ad-blocking browser extension based on the AdGuard open-source codebase. The extension uses Manifest V3's declarativeNetRequest API for content filtering, along with content scripts for cosmetic filtering. Despite the static analyzer flagging the code as "obfuscated," this is simply webpack-bundled production code, not actual obfuscation. The extension contains well-documented AdGuard libraries including Extended CSS, Sizzle selectors, and scriptlet injection utilities for blocking anti-adblock scripts. No external data exfiltration, credential theft, or privacy violations were identified.

The extension operates entirely within its stated purpose of blocking advertisements and trackers. All network requests are for downloading filter lists (declarative JSON rules), and no user data is transmitted to external servers.

## Vulnerability Details

No security vulnerabilities were identified in this extension.

## False Positives Analysis

### 1. Webpack Bundling vs. Obfuscation
The static analyzer flagged this extension as "obfuscated," but examination reveals this is standard webpack bundling with production minification. The code includes:
- Clear copyright headers (AdGuard Team, LGPL-3.0 license)
- Readable variable names and function names
- Standard library code (lodash, Extended CSS, Sizzle)
- Well-documented scriptlet functions

### 2. eval() and Function() Usage
The code contains several uses of `eval()` and `Function()`, but these are legitimate:

**Lines 15641, 19533**: Lodash template compilation uses `Function()` constructor to create compiled templates from strings. This is standard lodash behavior.

**Lines 22946-22961**: The `preventBab` scriptlet wraps `window.eval` to prevent anti-adblock scripts from executing. This is defensive code that *blocks* eval usage by third-party scripts, not a security risk.

**Lines 23021-23044**: The `logEval` scriptlet is a debugging tool that logs eval usage. These are scriptlets injected into pages to defeat anti-adblock measures.

### 3. document.getElementById Pattern
Line 22956 contains `document.getElementById('babasbmsgx')` which was flagged by the static analyzer. However, this is part of the anti-adblock bypass scriptlet that removes elements created by BlockAdBlock detection scripts. This is a protective measure, not an attack.

### 4. Content Scripts on All URLs
The extension injects content scripts on `*://*/*` with `run_at: document_start`. This is required for ad-blocking extensions to:
- Apply cosmetic filters (hiding ad elements via CSS)
- Block scripts before they execute
- Inject scriptlets to bypass anti-adblock measures

This is expected behavior for any ad blocker.

### 5. Web Accessible Resources
The extension exposes `web-accessible-resources/*` which includes:
- Redirect scripts (empty ad replacements, VAST tag replacements)
- Scriptlets for defeating anti-adblock (prevent-bab, prevent-fab)
- Empty JSON responses for blocked ad requests

These are standard ad-blocking resources that replace blocked content with benign substitutes.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | - | - | NONE |

The extension does not contact any external servers. All filter rules are bundled in the extension package as declarative JSON files (`filter_1.json`, `filter_2.json`, `filter_3.json`) and local text files in `web-accessible-resources/filters/`.

## Code Quality Assessment

### Positive Indicators:
1. **Open Source Lineage**: Based on AdGuard Browser Extension (https://github.com/AdguardTeam/AdguardBrowserExtension)
2. **LGPL-3.0 License**: Properly licensed open-source code
3. **Standard Libraries**: Uses well-known libraries (lodash 4.17.21, Extended CSS, Sizzle)
4. **Manifest V3 Compliance**: Uses declarativeNetRequest instead of webRequest blocking
5. **No Remote Code**: All filtering rules are bundled locally
6. **No Telemetry**: No analytics or tracking code found

### Architecture:
- **Background Service Worker**: Manages filter rules, tab state, user settings
- **Content Scripts**: Applies cosmetic filters, injects scriptlets
- **Declarative Net Request**: 3 static rulesets for network-level blocking
- **Popup UI**: React-based settings interface

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

Adblock Ultra is a legitimate, well-implemented ad-blocking extension that adheres to modern security practices and Chrome's Manifest V3 requirements. The extension:

1. **No Privacy Violations**: Does not collect, transmit, or exfiltrate user data
2. **No Malicious Code**: All code serves the stated purpose of ad blocking
3. **Transparent Operation**: Uses standard open-source libraries with proper attribution
4. **No Remote Config**: Filter rules are bundled locally, no remote loading of executable code
5. **Appropriate Permissions**: All requested permissions (declarativeNetRequest, scripting, storage, tabs, webNavigation) are necessary for ad-blocking functionality
6. **No Security Vulnerabilities**: No XSS, CSRF, code injection, or other vulnerabilities identified

The static analyzer's "exfiltration flow" finding (document.getElementById → fetch) is a false positive. The fetch calls in the background script are part of the filter downloading infrastructure from the AdGuard codebase, but no actual external fetching occurs in this compiled version - all filters are pre-bundled.

The extension operates exactly as expected for an ad blocker and poses no security or privacy risk to users.
