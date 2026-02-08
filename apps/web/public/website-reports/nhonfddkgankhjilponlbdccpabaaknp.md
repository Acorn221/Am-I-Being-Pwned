# Security Analysis Report: Legrooms+ for Google Flights

## Extension Metadata
- **Extension Name**: Legrooms+ for Google Flights
- **Extension ID**: nhonfddkgankhjilponlbdccpabaaknp
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Version**: 11.3.2
- **Analysis Date**: 2026-02-07

## Executive Summary

Legrooms+ for Google Flights is a legitimate travel extension that enhances Google Flights with additional legroom information, seat details, and cashback opportunities. The extension collects significant behavioral data and uses extensive permissions, but operates transparently within its stated functionality. No critical vulnerabilities or malicious behavior was detected. The extension integrates third-party services (Vio.com hotel comparison SDK) with appropriate user visibility.

**Overall Risk Level**: **LOW**

The extension is invasive by design (tracking browsing for cashback deals) but serves its intended purpose without hidden malicious functionality.

## Vulnerability Analysis

### 1. Content Script Injection on All URLs
**Severity**: LOW
**File**: `manifest.json` (lines 19-32)
**Code**:
```json
"content_scripts": [
  {
    "matches": ["http://*/*", "https://*/*", "<all_urls>"],
    "js": ["vio.js"],
    "all_frames": false,
    "run_at": "document_end",
    "world": "ISOLATED"
  },
  {
    "matches": ["http://*/*", "https://*/*", "<all_urls>"],
    "js": ["content.js"],
    "all_frames": true
  }
]
```

**Verdict**: **CLEAN - Justified by Functionality**
The extension requires broad content script access to:
- Detect cashback opportunities across shopping sites
- Inject flight information on Google Flights
- Inject hotel comparison data via Vio SDK

The `vio.js` script is from partners.api.vio.com (Hermes SDK for hotel price comparison) and runs in ISOLATED world. The `content.js` handles flight data parsing and cashback detection. Both are necessary for the extension's core features.

---

### 2. XMLHttpRequest Interception for Flight Data
**Severity**: LOW
**File**: `legroom/load_flight_data.js` (lines 148-160)
**Code**:
```javascript
XMLHttpRequest.prototype.open = function() {
  var n = arguments[1];
  return "POST" == arguments[0] && n.match(/\/GetShoppingResults/) &&
    this.addEventListener("loadend", function() {
      this.status >= 200 && this.status < 300 && t(n, this.__headers, this.responseText)
    }.bind(this)), e.apply(this, arguments)
};
```

**Verdict**: **CLEAN - Required for Core Functionality**
The extension hooks XMLHttpRequest to intercept Google Flights API responses containing flight data. This is necessary to:
- Extract legroom information from flight results
- Parse seat amenities (wifi, power, video)
- Display aircraft type and seat configuration

The interception is scoped only to Google Flights `/GetShoppingResults` endpoints and does not capture sensitive data. The parsed data enhances the user experience by showing legroom measurements directly in search results.

---

### 3. Extensive Tracking and Analytics
**Severity**: LOW
**File**: `sw.js` (lines 219-244), `vio.js` (lines 274-290)
**Code**:
```javascript
async function s(e) {
  const t = await (0, r.getAccount)(),
    o = {
      ...e,
      accountId: t?.id ?? null,
      meta: {
        ...e.meta,
        version: "Legroom:" + chrome.runtime.getManifest().version,
        name: "legroomExtension"
      }
    };
  const i = btoa(JSON.stringify(o));
  if (!(await fetch(`${n.default.api.url}/v3/events`, {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({payload: i}),
      credentials: "omit"
    })).ok) throw new Error("Event creation failed")
}
```

**Verdict**: **CLEAN - Transparent Analytics**
The extension tracks user interactions for legitimate product analytics:
- Extension installation/update events
- Flight search behavior on Google Flights
- Cashback offer interactions
- Seatmap clicks

Events are sent base64-encoded to `api.travelarrow.io/v3/events`. The Vio SDK also tracks hotel comparison interactions to `fe-evas.fih.io/browser-extension/event`. All tracking is related to core functionality and typical for travel/shopping extensions.

---

### 4. Cashback Domain Tracking and Heuristics
**Severity**: LOW
**File**: `sw.js` (lines 1571-1587, 1857-1911)
**Code**:
```javascript
checkHeuristics(e, t = !1) {
  const a = yield this.storageService.getHeuristics();
  const c = e.toLowerCase();
  if (a.ignoreList.some((e => c.includes(e.toLowerCase()))))
    throw new Error("Heruistics: Ignore list match.");
  const l = a.cartKeywords.some((e => c.includes(e.toLowerCase())));
  if (!h) throw new Error("Heruistics | IncludeList did not match.")
}
```

**Verdict**: **CLEAN - Core Feature Implementation**
The extension monitors browsing to detect shopping cart/checkout pages for cashback opportunities. This is the advertised functionality:
- Fetches domain allowlist from `api.travelarrow.io/v3/cashback/domains`
- Uses URL heuristics (cart keywords) to detect purchase intent
- Implements rate limiting to avoid excessive notifications
- Respects "stand down" domains where cashback was dismissed

This is invasive but transparently disclosed as the extension's primary value proposition.

---

### 5. Third-Party SDK Integration (Vio/Hermes)
**Severity**: LOW
**File**: `vio.js` (lines 14-20, 112-136)
**Code**:
```javascript
const r = {
  apiBaseUrl: "https://partners.api.vio.com/v1",
  trackingUrl: "https://fe-evas.fih.io/browser-extension/event",
  remoteConfigUrl: "https://www.vio.com/js/browser-extension/remote-config/v1/config.json",
  trackingKey: String("kk0dwmry7acfeh6af97vw8wroo80texx"),
  version: "1.0.3"
};
```

**Verdict**: **CLEAN - Legitimate Partnership**
The Vio/Hermes SDK provides hotel price comparison on booking sites. It:
- Fetches remote configuration from vio.com
- Compares hotel prices across platforms
- Tracks interactions for analytics (anonymousId stored in chrome.storage.sync)

The SDK is properly sandboxed and the partnership is reflected in the manifest's `externally_connectable` section allowing communication with `travelarrow.io` and `tripchipper.com` domains.

---

### 6. IP Geolocation Tracking
**Severity**: LOW
**File**: `sw.js` (lines 1048-1058)
**Code**:
```javascript
t.getIPGeolocation = function() {
  return o(this, void 0, void 0, (function*() {
    try {
      const e = yield fetch("http://ip-api.com/json/?fields=countryCode");
      if (!e.ok) return null;
      return (yield e.json()).countryCode
    } catch (e) {
      return null
    }
  }))
}
```

**Verdict**: **CLEAN - Legitimate Localization**
Uses IP geolocation API (ip-api.com) to determine user's country code. This is standard for:
- Showing region-appropriate deals
- Currency selection
- Compliance with regional restrictions

Only the country code is fetched, no precise location tracking.

---

### 7. Hardcoded API Endpoint (Potential Concern)
**Severity**: MEDIUM
**File**: `sw.js` (line 513)
**Code**:
```javascript
const t = await fetch("http://137.184.37.30/click", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({url: e.detail.url})
});
```

**Verdict**: **CONCERNING - Hardcoded IP for Hotel Redirect**
This function handles hotel price comparison redirects through a hardcoded IP address (137.184.37.30). While likely a legitimate redirect service, this pattern is problematic:
- IP-based endpoints are harder to audit
- Could be used to change behavior without updating the extension
- No HTTPS (HTTP only)

**Recommendation**: Should use HTTPS and a proper domain name. Users clicking hotel deals are redirected through this endpoint, which could theoretically log/modify URLs.

---

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `innerHTML` usage | content.js, vio.js | Standard DOM manipulation for rendering UI components (flight details, hotel comparison widgets). No user-controlled content. |
| XMLHttpRequest hooking | load_flight_data.js | Necessary to parse Google Flights API responses. Only hooks specific endpoints, doesn't capture credentials. |
| Broad host permissions | manifest.json | Required for cashback feature across shopping sites. Extension transparently discloses this functionality. |
| btoa encoding | sw.js line 231 | Simple base64 encoding of analytics events, not obfuscation. Events contain flight search metadata, not sensitive data. |
| postMessage usage | render_legroom.js line 91-93 | Inter-frame communication for feedback UI. Scoped to extension's own frames. |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `api.travelarrow.io/v3/events` | Analytics tracking | Flight search metadata, user interactions, extension events | LOW - Standard analytics |
| `api.travelarrow.io/accounts/{id}` | Account management | Account ID, token, version | LOW - User identification |
| `api.travelarrow.io/metadata` | Remote configuration | None (GET request) | LOW - Feature flags |
| `api.travelarrow.io/v3/cashback/domains` | Cashback domains | None (GET request) | LOW - Domain allowlist |
| `travelarrow.io/api/s` | Seatmap lookup | Flight details (origin, dest, flight number, date) | LOW - Public flight data |
| `hotels.travelarrow.io/api/prices` | Hotel price comparison | Search parameters (destination, dates, guests) | LOW - Search queries |
| `partners.api.vio.com/v1/search` | Hotel SDK search | Hotel search parameters | LOW - Third-party SDK |
| `fe-evas.fih.io/browser-extension/event` | Vio SDK analytics | Anonymous tracking events | LOW - SDK analytics |
| `ip-api.com/json/` | Geolocation | None (inferred from IP) | LOW - Country code only |
| `http://137.184.37.30/click` | Hotel redirect service | Hotel booking URLs | MEDIUM - Hardcoded IP, HTTP only |

## Data Flow Summary

1. **User Account Creation**: Extension generates anonymous account on first install, stores account ID + token in chrome.storage.local/sync
2. **Flight Search Enhancement**: Hooks Google Flights XHR to extract legroom data, displays aircraft amenities inline
3. **Cashback Detection**: Monitors tab navigation, checks URLs against cached domain list + heuristics, shows notification when shopping cart detected
4. **Hotel Comparison**: Vio SDK injects price comparison widgets on hotel booking sites, communicates with vio.com APIs
5. **Analytics Pipeline**: All user interactions (searches, clicks, installs) sent as base64-encoded events to travelarrow.io
6. **Remote Configuration**: Fetches feature flags, domain allowlists, and deal configurations from API on startup + periodic sync

**Key Storage Items**:
- `account` / `token` - User identification (local + sync)
- `jaideepDeals` - Promotional deals from API
- `cachedDomains` - Rate-limited cashback domains
- `standdownTabs` - Tabs where user dismissed cashback
- `metadata` - Remote feature flags

## Overall Risk Assessment

**Risk Level**: **LOW**

**Justification**:
- Extension operates transparently within stated functionality (flight enhancement + cashback tracking)
- No credential harvesting, clipboard manipulation, or malicious payloads detected
- Third-party SDK (Vio) is properly isolated and from legitimate partner
- Data collection is extensive but expected for cashback/travel extension
- Code is well-structured without obfuscation attempts
- No remote code execution or dynamic script loading

**Concerns**:
1. Very broad permissions (all URLs) enable significant tracking capabilities
2. Hardcoded IP endpoint (137.184.37.30) should use HTTPS and domain name
3. Cashback heuristics monitor all browsing activity (disclosed but invasive)
4. Multiple external API dependencies (travelarrow.io, vio.com, ip-api.com)

**Recommendation**: **CLEAN** - Extension is safe for users who accept trade-off of browsing tracking for cashback rewards. The privacy impact is significant but transparently disclosed in the extension's core value proposition. The hardcoded IP redirect is the only technical concern requiring attention.
