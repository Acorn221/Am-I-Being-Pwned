# Vulnerability Report: AdGuard VPN: free & secure proxy

## Metadata
- **Extension ID**: hhdobjgopfphlmjbmnpglhfcgppchgje
- **Extension Name**: AdGuard VPN: free & secure proxy
- **Version**: 2.8.9
- **Users**: ~500,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AdGuard VPN is a legitimate VPN extension by Adguard Software Ltd that provides proxy functionality, DNS customization, and privacy features. The extension requests broad permissions typical for VPN services, including `proxy`, `webRequest`, `management`, and `<all_urls>` host permissions.

Analysis reveals standard telemetry collection for user analytics (page views, custom events) sent to `api.agrdvpn-tm.com`. The extension also enumerates installed extensions to disable competing VPN products, which is expected behavior for this product category. No undisclosed data exfiltration, credential theft, or malicious activity was detected.

## Vulnerability Details

### 1. LOW: Extension Enumeration for VPN Conflict Management
**Severity**: LOW
**Files**: background.js
**CWE**: CWE-200 (Information Exposure)
**Description**: The extension uses `chrome.management.getAll()` to enumerate installed extensions and identify those with proxy permissions. It then disables competing VPN extensions to prevent conflicts.

**Evidence**:
```javascript
// Line 76224 in background.js
return _this.browser.management.getAll();

// Line 76227-76232
return extensions.filter(function (extension) {
  var permissions = extension.permissions,
    enabled = extension.enabled,
    id = extension.id;
  return (permissions?.includes(_this.PROXY_PERMISSION))
    && id !== _this.browser.runtime.id && enabled;
});
```

**Verdict**: This is standard behavior for VPN extensions. Multiple VPN extensions cannot operate simultaneously without conflicts, so disabling competitors is legitimate functionality. The `management` permission is declared in the manifest, making this transparent to users.

### 2. INFO: Telemetry Collection
**Severity**: INFO (Not a vulnerability)
**Files**: background.js, export.js, popup.js, options.js, consent.js
**Description**: The extension collects telemetry data including page views, custom events, user interactions, and device information. Data is sent to `api.agrdvpn-tm.com` (TELEMETRY_API_URL).

**Evidence**:
```javascript
// Line 46084 in background.js - Config object
"TELEMETRY_API_URL":"api.agrdvpn-tm.com"

// Line 78772 - Telemetry API initialization
var telemetryApi = new TelemetryApi("".concat(TELEMETRY_API_URL).concat(API_URL_PREFIX));

// Line 78864-78884 - Page view event sending
var sendPageViewEvent = /*#__PURE__*/function () {
  var _ref2 = asyncToGenerator_asyncToGenerator(/*#__PURE__*/regenerator_default().mark(function _callee2(event, baseData) {
    var telemetryData;
    // ... sends to v1/event endpoint
  }));
}();
```

**Telemetry Data Collected**:
- Synthetic ID (anonymous user identifier)
- Screen names and page views (e.g., "auth_screen", "home_screen", "onboarding_screen")
- Custom events with action names, labels, and experiments
- Device information (user agent, browser, OS)
- App version and license status
- Theme preferences

**Verdict**: This is legitimate product analytics for a free VPN service. The telemetry appears to be for usage analytics and product improvement, not data exfiltration. Users are likely informed through the privacy policy. The data collected is minimal and does not include browsing history, personal identifiable information, or sensitive user data.

## False Positives Analysis

1. **Proxy Permission with `<all_urls>`**: While these permissions are extremely broad, they are necessary for VPN functionality. The extension must intercept all network traffic to route it through the proxy.

2. **WebRequest API Usage**: Required for VPN operation, error handling, and detecting non-routable domains. This is not being abused for tracking purposes.

3. **Management Permission**: Used solely for detecting and disabling competing VPN extensions, which is standard practice to prevent proxy configuration conflicts.

4. **Webpack Bundling**: The extension uses Webpack for bundling JavaScript. This is not obfuscation, but standard modern build tooling. The static analyzer flagged "obfuscated" due to bundle complexity, but this is a false positive.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.adguard.io | VPN API - server connections, credentials | Auth tokens, proxy settings, connection status | Low - necessary for VPN |
| auth.adguard.io | Authentication API | User credentials, auth tokens | Low - standard auth |
| api.agrdvpn-tm.com | Telemetry | Anonymous usage analytics, page views, events | Low - disclosed analytics |
| link.adtidy.info | Forwarder domain | Click tracking for external links | Low - URL shortener |
| wss://{{host}}:443/user | WebSocket API | Real-time proxy status updates | Low - VPN coordination |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
AdGuard VPN is a legitimate product from a reputable security vendor. While it requests powerful permissions and collects telemetry, all behaviors align with its stated VPN functionality. The extension enumeration behavior is expected for VPN products to prevent conflicts. Telemetry collection appears to be for legitimate analytics purposes with anonymous identifiers. No evidence of credential theft, undisclosed data exfiltration, or malicious behavior was found.

The LOW risk rating reflects:
1. Extension enumeration via `management` API (standard for VPN category)
2. Telemetry collection (appears disclosed and reasonable)
3. Broad permissions are justified by VPN functionality
4. From reputable vendor (Adguard Software Ltd)
5. No hidden malicious behavior detected
