# Vulnerability Report: I still don't care about cookies

## Metadata
- **Extension ID**: edibdbjcniadpccecjdfdjjppcpchdlm
- **Extension Name**: I still don't care about cookies
- **Version**: 1.1.9
- **Users**: Unknown (not provided in analysis)
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

"I still don't care about cookies" is a community-maintained fork of the original "I don't care about cookies" extension, created after the original was acquired by Avast. The extension serves a single, transparent purpose: automatically removing cookie consent banners and popups from websites to improve browsing experience.

This extension is CLEAN with no security or privacy concerns identified. It operates transparently, uses modern manifest v3 APIs, and has minimal external communication limited to optional user-initiated bug reporting.

## Vulnerability Details

No vulnerabilities identified.

## False Positives Analysis

### Broad Host Permissions (`http://*/*`, `https://*/*`)
**Status**: Expected and Necessary

The extension requires access to all websites because cookie consent banners appear across the entire web. This is the stated and legitimate purpose of the extension.

### Script Injection via chrome.scripting API
**Status**: Expected and Necessary

The extension injects CSS and JavaScript to:
1. Hide cookie consent banners using custom CSS rules
2. Auto-click "reject all" or "accept necessary only" buttons
3. Set cookies to indicate consent preferences have been saved

This behavior is fully transparent and documented in the extension's description.

### External API Communication
**Status**: Benign - Optional User Feature

The extension communicates with `api.istilldontcareaboutcookies.com` only when users manually choose to report a website with cookie banner issues. This is an opt-in feature to help improve the extension's ruleset.

**Evidence from background.js (lines 384-418)**:
```javascript
fetch("https://api.istilldontcareaboutcookies.com/api/report", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    issueType,
    notes,
    url: hostname,
    browser: getBrowserAndVersion(),
    language: navigator.language || Intl.DateTimeFormat().resolvedOptions().locale,
    extensionVersion: chrome.runtime.getManifest().version,
  }),
})
```

Data sent is minimal and user-initiated: hostname being reported, browser version, language, extension version, and user notes.

### declarativeNetRequest Rules Blocking
**Status**: Expected and Necessary

The extension uses 19,901 declarativeNetRequest rules to block known cookie consent management scripts (e.g., OneTrust, Cookiebot, etc.). This is the core functionality of the extension and prevents cookie banner scripts from loading.

Example rules block:
- `/iubenda_cs` (Iubenda cookie consent)
- `/ccm19_` (CCM19 cookie manager)
- `static.clickskeks.at` (Clickskeks)
- OneTrust, Cookiebot, and other consent management platforms

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.istilldontcareaboutcookies.com/api/report | User bug reporting | hostname, browser version, language, extension version, user notes | LOW - User-initiated only |

## Code Quality & Security Practices

### Positive Indicators:
1. **Manifest V3**: Uses modern extension APIs (declarativeNetRequest, scripting)
2. **No obfuscation**: Clean, readable code with comments
3. **Open source**: Community-maintained on GitHub
4. **No tracking**: No analytics, telemetry, or user tracking
5. **No remote code**: All functionality is self-contained
6. **Minimal data collection**: Only collects data when user explicitly reports an issue
7. **Whitelist functionality**: Users can disable the extension on specific domains

### Architecture:
- **Background worker**: Manages tab state, applies rules, handles user actions
- **Content scripts**: Auto-dismiss cookie banners via DOM manipulation
- **CSS injection**: Hides cookie consent UI elements
- **declarativeNetRequest**: Blocks cookie consent management scripts before they load

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:

This extension performs exactly as advertised with complete transparency. It removes cookie consent banners through CSS hiding, script blocking, and auto-clicking consent buttons. The code is clean, well-documented, and open source. There is no data collection, tracking, or malicious behavior.

The broad permissions are necessary for the extension's legitimate purpose. The only external communication is user-initiated bug reporting that sends minimal, non-sensitive information.

This is a legitimate utility extension that enhances user experience by automating the dismissal of cookie consent popups. It represents the community's effort to maintain a trusted tool after the original was acquired by Avast.

**Recommendation**: Safe to use. This is a well-known, legitimate extension serving the privacy-conscious community.
