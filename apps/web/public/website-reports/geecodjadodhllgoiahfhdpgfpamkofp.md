# Vulnerability Report: VPN India - Planet VPN lite Proxy

## Metadata
- **Extension ID**: geecodjadodhllgoiahfhdpgfpamkofp
- **Extension Name**: VPN India - Planet VPN lite Proxy
- **Version**: 1.0.13
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

VPN India - Planet VPN lite Proxy is a legitimate VPN browser extension that provides proxy functionality for Indian server access. The extension uses standard Chrome proxy APIs and WebRequest authentication handlers to route traffic through VPN servers. The static analyzer flagged it as "obfuscated" due to webpack bundling, but the deobfuscated code reveals standard VPN functionality without malicious intent.

The extension communicates with backend servers at vqols.cc and freevpnplanet.com to fetch proxy configurations and check IP geolocation. It sends a browser-specific UUID identifier with API requests for analytics/tracking purposes, but does not exfiltrate browsing history, credentials, or other sensitive user data. The management permission is declared but not used for malicious extension enumeration.

## Vulnerability Details

### 1. LOW: Analytics Tracking via UUID
**Severity**: LOW
**Files**: background.js (lines 1251-1339)
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)
**Description**: The extension sends a hardcoded UUID identifier in the "UUID-APP" HTTP header with all API requests. This UUID is browser and country-specific (e.g., VITE_UUID_APP_CHROME_IN for Chrome/India variant).

**Evidence**:
```javascript
const L0 = (() => {
  const r = "in".toUpperCase();
  switch (w0) {
    case J.FIREFOX:
      return R0[`VITE_UUID_APP_FIREFOX_${r}`] ?? "";
    case J.CHROME:
      return R0[`VITE_UUID_APP_CHROME_${r}`] ?? "";
    // ... other browsers
  }
})(),

Re = async ({ url: r, options: t = {} }) => {
  return await fetch(r, {
    method: t?.method ?? H0.GET,
    headers: {
      "UUID-APP": L0,
      ...t?.headers
    },
    body: t?.method !== H0.GET ? t?.body : null
  })
}
```

**Verdict**: This is a low-risk analytics mechanism. The UUID is extension-specific (not user-specific), and allows the vendor to track installation counts and API usage by browser/country variant. While this enables basic telemetry, it does NOT uniquely identify individual users or expose browsing activity.

## False Positives Analysis

### Obfuscation Flag
The ext-analyzer flagged this extension as "obfuscated", but this is due to webpack/Vite bundling artifacts (minified variable names, IIFE wrappers). After deobfuscation with jsbeautifier, the code is straightforward VPN logic without malicious obfuscation.

### Management Permission
The extension declares `chrome.management` permission but does not use it to enumerate or disable other extensions. This appears to be an unused permission that should be removed, but is not actively malicious.

### WebRequest Listeners
The extension registers `webRequest.onAuthRequired` listeners to inject proxy credentials, which is the standard mechanism for authenticated proxy connections in Chrome. This is expected behavior for VPN/proxy extensions.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| vqols.cc | Proxy config & IP check | UUID-APP header, country code | Low - Analytics only |
| freevpnplanet.com | Marketing pages, support | None (static links) | None |
| cdn.freevpnplanet.com | Static assets (CDN) | None | None |
| s3.amazonaws.com/cdn.freevpnplanet.com | CDN mirror (Russia) | None | None |
| planet-vpn-free.net | Russia-specific marketing | None | None |
| api.telegra.ph/getPage/fvp-11-30 | SSL check via Telegraph | Fetched in offscreen worker | Low - Third-party |

### Key Observations:
1. **No browsing data exfiltration**: The extension does NOT hook fetch/XHR, does NOT access cookies outside proxy authentication, and does NOT send browsing history/URLs to servers.
2. **Proxy-only network access**: WebRequest listeners are scoped to authentication (onAuthRequired) and completion tracking only.
3. **UUID is extension-level, not user-level**: The UUID does not fingerprint individual users; it identifies which variant/country/browser is making requests.
4. **Geolocation data**: The extension fetches the user's IP/country/city from `gapi.vqols.cc/ip` and stores it locally to display current location. This is standard VPN functionality.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

This is a legitimate VPN extension with standard proxy functionality. The "LOW" rating is assigned due to:

1. **Expected VPN behavior**: All proxy/WebRequest/authentication code is standard for VPN extensions
2. **Limited privacy impact**: The UUID tracking is extension-level analytics, not user-level surveillance
3. **No data exfiltration**: The extension does NOT collect browsing history, form data, or credentials beyond what is necessary for VPN operation
4. **Transparent functionality**: The extension's behavior matches its stated purpose (VPN proxy for India)

**Minor concerns**:
- The `management` permission is declared but unused - should be removed
- The UUID tracking could be more transparent in the privacy policy
- The offscreen worker makes a request to api.telegra.ph for "SSL check" which appears unnecessary

**Recommendation**: This extension is safe for general use. Users should be aware that basic analytics (browser type, country variant) are sent to the vendor's servers, but no personal browsing data is collected beyond IP geolocation.
