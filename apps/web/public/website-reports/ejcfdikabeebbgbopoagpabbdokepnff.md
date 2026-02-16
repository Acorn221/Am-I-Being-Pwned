# Vulnerability Report: Rajiko

## Metadata
- **Extension ID**: ejcfdikabeebbgbopoagpabbdokepnff
- **Extension Name**: Rajiko
- **Version**: 3.2026.2
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Rajiko is a legitimate Chrome extension that enables Japanese radio streaming from radiko.jp, including region bypass functionality for accessing content outside Japan. The extension intercepts authentication flows with radiko.jp API and injects custom headers to simulate mobile app requests with different geographic locations. While the static analyzer flagged one postMessage vulnerability and obfuscated code, detailed analysis reveals this is a specialized but legitimate tool for radio streaming enthusiasts.

The extension's core functionality involves authenticating with radiko.jp's API using device spoofing and GPS location manipulation to bypass regional restrictions - this is the extension's stated purpose and expected behavior. All network communications are exclusively with radiko.jp infrastructure (radiko.jp, api.radiko.jp, smartstream.ne.jp, radiko-cf.com) for streaming authentication and content delivery.

## Vulnerability Details

### 1. LOW: PostMessage Handler Without Origin Validation

**Severity**: LOW
**Files**: ui/share_redirect.js
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity)

**Description**: The content script uses `window.addEventListener("message")` without validating the origin of incoming messages. This could theoretically allow malicious scripts on radiko.jp to send arbitrary redirect commands.

**Evidence**:
```javascript
// ui/share_redirect.js
window.addEventListener("message", async function (evt) {
    let param = evt.data["share-redirect"] || {};
    if (param.t && param.station) {
        await chrome.runtime.sendMessage({ "share-redirect": param });
    }
});
```

The background script processes this by redirecting the current tab:
```javascript
// background.js
else if (msg["share-redirect"]) {
    let param = msg["share-redirect"];
    chrome.tabs.update(sender.tab.id, { "url": "https://radiko.jp/#!/ts/" + param.station + "/" + param.t });
}
```

**Verdict**: **LOW RISK** - While the postMessage handler lacks origin validation, the actual impact is minimal:
1. The message handler only runs on pages matching `*://*.radiko.jp/share/?*noreload=1*` (very specific URL pattern)
2. The redirect is hardcoded to `radiko.jp/#!/ts/` URLs (same origin)
3. Parameters are simple strings (station ID and timestamp) with no code execution risk
4. Worst case: a compromised radiko.jp page could trigger unwanted radio stream redirects within the same domain

This is a minor security oversight rather than a critical vulnerability.

## False Positives Analysis

### Obfuscated Code Flag
The static analyzer marked the extension as "obfuscated." However, examination of the deobfuscated code reveals:
- Clean, readable JavaScript with proper function names and comments
- Standard ES6 module imports/exports
- Well-structured authentication flow with detailed inline documentation
- No evidence of intentional obfuscation - any minification is standard build process

### Data Exfiltration Flow
The analyzer flagged: `document.getElementById → fetch(radiko.jp)`

This is **legitimate functionality**:
```javascript
// popup.js retrieves radio stream URLs from the page DOM
let result = {
    tmpUrl: document.getElementById('tmpUrl') && document.getElementById('tmpUrl').value,
    url: document.getElementById('url') && document.getElementById('url').value
}
```

These values are then used in authentication flows to radiko.jp - this is the extension's core purpose (accessing radio streams), not data exfiltration.

### Region Bypass Behavior
The extension deliberately spoofs:
- Device identifiers (`X-Radiko-Device`, `X-Radiko-User`)
- GPS coordinates (`X-Radiko-Location`: `genGPS(area_id)`)
- User agents (mobile app emulation)

This is the **intended functionality** for accessing geographically restricted radio content and is clearly documented in the code comments. Similar to how VPN extensions modify location data, this is expected behavior for a region bypass tool.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| radiko.jp/v2/api/auth1 | Initial authentication | Device fingerprint headers (app version, device ID, user ID) | Low - legitimate auth flow |
| radiko.jp/v2/api/auth2 | Complete authentication | Auth token, partial key, GPS coordinates | Low - expected geo bypass |
| api.radiko.jp/apparea/auth1 | Android app auth flow | Device info JSON (app_id, user_id, device type) | Low - mobile auth emulation |
| radiko.jp/v3/station/stream/pc_html5/* | Stream playlist requests | Token in request context | None - content delivery |
| smartstream.ne.jp/*.aac | Audio stream segments | None | None - content delivery |
| radiko-cf.com/segments/*.aac | Audio stream segments (CDN) | None | None - content delivery |

All endpoints are legitimate radiko.jp infrastructure. No third-party analytics, advertising, or data collection services detected.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:

Rajiko is a specialized tool for accessing Japanese radio streaming with region bypass functionality. The single security issue identified (postMessage without origin check) has minimal real-world impact due to:
1. Restricted execution context (only on specific radiko.jp URLs)
2. Limited attack surface (same-origin redirects only)
3. No sensitive data exposure or credential theft possible

The extension's "suspicious" behaviors (device spoofing, location manipulation, API authentication) are all legitimate features for its stated purpose of bypassing geographic restrictions on radiko.jp. This is analogous to VPN extensions or region unlockers for other streaming services.

**No evidence of**:
- Credential harvesting
- User tracking or analytics
- Third-party data sharing
- Malicious code injection
- Undisclosed data collection

**Recommendation**: The postMessage handler should add origin validation (`if (evt.origin !== 'https://radiko.jp') return;`), but this is a minor hardening measure rather than a critical fix. The extension appears safe for users who understand and consent to using a radio streaming region bypass tool.
