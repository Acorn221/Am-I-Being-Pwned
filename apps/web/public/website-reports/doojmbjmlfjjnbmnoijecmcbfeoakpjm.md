# Vulnerability Report: NoScript

## Metadata
- **Extension ID**: doojmbjmlfjjnbmnoijecmcbfeoakpjm
- **Extension Name**: NoScript
- **Version**: 13.5.10
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

NoScript is a well-established, open-source security extension developed by Giorgio Maone since 2005. The extension provides a whitelist-based approach to blocking JavaScript, WebAssembly, Flash, and other executable content on web pages. All code is distributed under the GPL-3.0-or-later license with full source code transparency.

This extension is a legitimate security tool with no malicious functionality. Despite having extensive permissions including `<all_urls>`, `debugger`, `webRequest`, and `scripting`, these are all necessary for its stated security functionality. The extension does not exfiltrate data, inject ads, or perform any undisclosed activities.

## Vulnerability Details

No security vulnerabilities or privacy concerns were identified in this extension.

## False Positives Analysis

While the static analyzer flagged this extension as "obfuscated", this is a false positive. The code uses standard webpack/babel transpilation but is not intentionally obfuscated:

1. **Large Permission Set**: The extension requests `<all_urls>`, `debugger`, `webRequest`, `scripting`, and other broad permissions. These are all necessary for a security extension that:
   - Intercepts and analyzes web requests to block JavaScript
   - Uses Content Security Policy injection to enforce script blocking
   - Hooks into the debugger API to patch Worker constructors
   - Provides XSS filtering and injection detection

2. **Content Script Injection**: The extension injects extensive content scripts into `<all_urls>` with `run_at: document_start` and uses the MAIN world injection feature. This is expected behavior for a script blocker that needs to:
   - Intercept scripts before they execute
   - Hook native APIs like `fetch`, WebAssembly, and WebGL
   - Provide document freezing and CSP enforcement

3. **API Hooking**: The code hooks several browser APIs including Workers, WebAssembly, and WebGL. This is part of the extension's legitimate security functionality to prevent malicious scripts from executing through alternative code paths.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| None | N/A | N/A | CLEAN |

This extension makes no external network requests. All functionality is local, using only browser storage APIs for configuration persistence.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

NoScript is a legitimate, widely-trusted security extension with the following characteristics:

1. **Open Source**: Licensed under GPL-3.0-or-later with full source code availability on GitHub
2. **Established Project**: Maintained since 2005 by Giorgio Maone, originally for Firefox, now supporting Chrome/Chromium
3. **No Data Exfiltration**: No external network requests, no analytics, no tracking
4. **Transparent Functionality**: All behavior matches the stated purpose of blocking JavaScript and active content
5. **Appropriate Permissions**: While extensive, all permissions are necessary for the extension's security features
6. **No Monetization**: No ads, no affiliate injection, no commercial data collection

The extension represents best practices in browser security tooling and poses no security or privacy risk to users. The broad permissions are inherent to its purpose as a comprehensive script blocking solution.
