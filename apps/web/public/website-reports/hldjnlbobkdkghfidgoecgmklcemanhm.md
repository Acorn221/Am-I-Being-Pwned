# Security Analysis Report: Web Highlights PDF & Web Highlighter + Notes & AI Summary

## Extension Metadata
- **Extension ID**: hldjnlbobkdkghfidgoecgmklcemanhm
- **Version**: 12.0.2
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Web Highlights is a **MEDIUM RISK** extension that integrates the GiveFreely affiliate marketing platform to monetize through e-commerce redirects. While the extension provides legitimate highlighting and annotation functionality, it includes comprehensive behavioral tracking and affiliate URL generation that modifies user browsing behavior on thousands of merchant sites. The extension monitors all page loads via webRequest API, tracks geolocation, and generates affiliate links for supported merchants.

**Key Concerns:**
1. GiveFreely affiliate SDK tracks user browsing across 2000+ merchant domains
2. Geolocation tracking via MaxMind API with hardcoded credentials
3. Server-controlled configuration allows remote updates to tracked merchant list
4. Backend health monitoring via webRequest API intercepts all HTTP failures
5. Feature only enabled for Chrome extension (not Firefox), suggesting revenue targeting

**No Evidence Found:**
- XHR/fetch prototype hooking
- Extension enumeration or killing
- AI conversation scraping
- Keylogging or form harvesting
- Cookie theft or session hijacking

## Vulnerability Details

### 1. GiveFreely Affiliate Platform Integration (MEDIUM Severity)

**Files**: `background.js:13096-14740`

**Description**: Extension integrates GiveFreely behavioral tracking SDK that monitors browsing activity across thousands of e-commerce sites and generates affiliate URLs for cashback/charity donation purposes.

**Code Evidence**:
```javascript
// background.js:13096
const rs = "https://cdn.givefreely.com/adunit/behavioral/";

// background.js:14735 - Partner API key
const t = new Ys("webhighlightsprod");
yield t.initialize()

// background.js:3021 - Feature flag (Chrome only)
featureIsEnabled: {
  givefreely: !0  // true for Chrome
}

// background.js:3038 - Firefox has it disabled
featureIsEnabled: {
  givefreely: !1  // false for Firefox
}
```

**Functionality**:
- Fetches partner config from `https://cdn.givefreely.com/adunit/behavioral/webhighlightsprod.json`
- Fetches global config from `https://cdn.givefreely.com/adunit/behavioral/global.json`
- Tracks "active domains" (merchant sites)
- Generates affiliate URLs via Wildfire service
- Monitors merchant rates and commissions
- Implements circuit breaker pattern for API failure recovery

**Data Collected**:
- User's country code (via geolocation API)
- Anonymous user ID (stored locally)
- Browsing history on merchant domains
- Domain visit timestamps
- Affiliate activation events
- Health check pings (daily)

**Backend Endpoints**:
```javascript
// background.js:13328
`${this.config.apiConfig.baseUri}/${this.config.apiConfig.getAnonymousUserComissionsPath}`

// background.js:13345
`${this.config.apiConfig.baseUri}/${this.config.apiConfig.createAnonymousUserPath}?adUnitId=${this.adUnitId}`
```

**Verdict**: CONCERN - While GiveFreely markets itself as charity-focused, the extension tracks browsing patterns across thousands of merchant sites and can dynamically update the merchant list via remote config without requiring a CWS update. The feature is only enabled for Chrome users (not Firefox), suggesting revenue optimization.

---

### 2. Geolocation Tracking with Hardcoded Credentials (MEDIUM Severity)

**Files**: `background.js:14192`

**Description**: Extension tracks user's country via MaxMind GeoIP API using hardcoded authorization credentials.

**Code Evidence**:
```javascript
// background.js:14188-14192
const t = {
  method: "GET",
  headers: {
    "Content-Type": "application/json",
    Authorization: "Basic [REDACTED - Base64-encoded MaxMind credentials]"
  }
};
const e = await fetch("https://geoip.maxmind.com/geoip/v2.1/country/me", t);
```

**Data Collection**:
- User's country ISO code
- Stored in extension storage at key `Po`
- Used to configure GiveFreely regional settings

**Verdict**: CONCERN - Hardcoded API credentials in client-side code pose security risk (credential theft, quota exhaustion). Geolocation tracking without explicit user consent may violate privacy regulations in some jurisdictions.

---

### 3. WebRequest API Monitoring (MEDIUM Severity)

**Files**: `background.js:14686-14702`

**Description**: Extension monitors HTTP request failures and completions for backend health monitoring via webRequest API.

**Code Evidence**:
```javascript
// background.js:14689-14695
chrome.webRequest.onErrorOccurred.addListener(function(r) {
  Js(r) && Zs(r) && (t = !1), Xs(r) && Zs(r) && (e = !1), t || e || E.sendMessage({
    id: "allServersAreOffline"
  })
}, {
  urls: Qs  // [BACKEND_URL, BACKEND_URL_FALLBACK].map(t => `${t}/*`)
})

chrome.webRequest.onCompleted.addListener(function(r) {
  let n = !t && !e;
  Js(r) && (t = !0), Xs(r) && (e = !0), n && (t || e) && E.sendMessage({
    id: "serversAreBackOnline"
  })
}, {
  urls: Qs
})
```

**Monitored URLs**:
- `https://api.web-highlights.com/*`
- `https://web-highlights-a56e6dd216b0.herokuapp.com/*`

**Verdict**: LOW RISK - Scoped to extension's own backend domains only. Does not intercept third-party traffic. Used for legitimate health monitoring.

---

### 4. Remote Configuration Updates (MEDIUM Severity)

**Files**: `background.js:13123-13139`

**Description**: Extension fetches remote configuration that can update behavior without CWS review.

**Code Evidence**:
```javascript
// background.js:13125-13129
const t = await fetch(`${rs}${this.partnerApiKey}.json`, {
  cache: "no-store"
});
if (!t.ok) throw new Error(`Failed to fetch partner config: ${t.statusText}`);
return t.json()

// background.js:13136
const t = await fetch(`${rs}global.json`, {
  cache: "no-store"
});
```

**Remote Configs**:
- `https://cdn.givefreely.com/adunit/behavioral/webhighlightsprod.json` (partner-specific)
- `https://cdn.givefreely.com/adunit/behavioral/global.json` (global settings)

**Configurable Parameters**:
- Merchant exclusions (`merchantExclusions`)
- Logging levels (`loggingEnabled`, `backgroundMinLogLevel`)
- Config refresh intervals (`configRefreshInterval`)
- Language purge lists (`purgeLanguages`)
- Affiliate domain filters (via `partnerFilter`)

**Verdict**: CONCERN - Remote config allows extension behavior to change dynamically without CWS update. Could be used to add new tracked merchants, enable more aggressive tracking, or modify affiliate logic.

---

### 5. Comprehensive Analytics Tracking (LOW-MEDIUM Severity)

**Files**: `background.js:13240-13291`

**Description**: Extension tracks user events and sends to remote analytics endpoint with de-duplication.

**Code Evidence**:
```javascript
// background.js:13256-13265
const n = await fetch(t, {
  headers: {
    "Content-Type": "application/json"
  },
  method: "POST",
  body: e,
  cache: "no-store"
});

// background.js:13274-13276
async getEventsUrl() {
  const t = await this._configService.getCachedConfig();
  return t?.eventsUrl
}
```

**Tracked Events** (from code analysis):
- `checkoutPopupHealthCheck` - Daily health ping with UI language
- `checkoutPopupMerchantInResultsFound` - Merchant detection events
- Offer activation events
- Domain standdown events
- User identity events

**Verdict**: LOW-MEDIUM RISK - Standard analytics for affiliate tracking. Events endpoint URL is server-controlled. De-duplication prevents excessive tracking (1-hour window).

---

## False Positives

| Pattern | File | Lines | Reason |
|---------|------|-------|--------|
| `youtube-nocookie.com` regex | background.js | 8127 | Legitimate Quill Delta video embed detection, not tracking |
| `.open = ` assignments | background.js | 1759-1793 | Markdown conversion library (delta-to-markdown), not XHR hooking |
| `cookies: {` object | background.js | 11952 | Notion API configuration object, not cookie theft |

---

## API Endpoints

| Domain | Purpose | Data Sent | Risk |
|--------|---------|-----------|------|
| `api.web-highlights.com` | Extension backend | Highlights, notes, bookmarks, user settings | LOW - Core functionality |
| `cdn.givefreely.com/adunit/behavioral/` | Affiliate config | None (GET requests) | MEDIUM - Remote config updates |
| `geoip.maxmind.com/geoip/v2.1/country/me` | Geolocation | None (uses IP) | MEDIUM - Country tracking |
| `app.web-highlights.com` | Frontend app | User data sync | LOW - Core functionality |
| GiveFreely eventsUrl (dynamic) | Analytics | Event type, event data, anonymous user ID | MEDIUM - Behavioral tracking |

---

## Data Flow Summary

### Outbound Data:
1. **User Highlights/Notes** → `api.web-highlights.com` (legitimate feature)
2. **Geolocation** → MaxMind API → Country code stored locally
3. **Anonymous User Profile** → GiveFreely API (upsert with device info)
4. **Analytics Events** → GiveFreely events endpoint (merchant visits, offers, health checks)
5. **Affiliate Activations** → Wildfire service (generates affiliate URLs)

### Inbound Configuration:
1. **Partner Config** ← `cdn.givefreely.com/adunit/behavioral/webhighlightsprod.json`
2. **Global Config** ← `cdn.givefreely.com/adunit/behavioral/global.json`
3. **Language Content** ← `cdn.givefreely.com/adunit/language/*`
4. **Merchant Domains** ← GiveFreely API (active domains list)

### Data Storage:
- Highlights and notes (IndexedDB - extension functionality)
- Anonymous user ID and token (chrome.storage)
- Country code (chrome.storage)
- Wildfire device ID (chrome.storage)
- Analytics event history (chrome.storage - 1-hour deduplication)
- Circuit breaker state (chrome.storage)

---

## Permissions Analysis

### Declared Permissions:
- `tabs` - Used for badge management and message passing to content scripts
- `contextMenus` - Right-click menu for highlighting
- `storage` - Local data persistence (highlights, settings, tracking state)
- `webRequest` - **Backend health monitoring only** (scoped to own domains)
- `scripting` - Dynamic content script injection
- `<all_urls>` - **Required for highlighting on any page**

### Actual Usage:
- **tabs**: Badge text/color updates, tab query for active tab messaging
- **webRequest**: Monitors only `api.web-highlights.com/*` and fallback domain
- **storage**: Stores highlights, user settings, GiveFreely tracking state
- **scripting**: No dynamic injection observed in background script
- **host_permissions**: Content script runs on `<all_urls>` for highlighting

---

## Overall Risk Assessment: **MEDIUM**

### Risk Score Breakdown:
- **Malicious Intent**: LOW - No evidence of data theft, credential harvesting, or intentionally harmful behavior
- **Privacy Impact**: MEDIUM-HIGH - Tracks browsing on 2000+ merchant sites, geolocation, behavioral analytics
- **Data Exfiltration**: MEDIUM - Sends affiliate tracking events, anonymous user profile to third-party (GiveFreely)
- **User Transparency**: LOW-MEDIUM - GiveFreely integration not prominently disclosed in CWS listing
- **Attack Surface**: MEDIUM - Remote config allows behavior changes without CWS review
- **Credential Security**: MEDIUM - Hardcoded MaxMind API credentials pose security risk

### Comparison to Known Patterns:
- **NOT like Sensor Tower**: No XHR/fetch hooking, no AI conversation scraping, no chatbot monitoring
- **NOT like VPN malware**: No extension killing, no residential proxy infrastructure, no ad injection
- **Similar to**: Honey, Capital One Shopping (affiliate/cashback browser extensions with behavioral tracking)

### Recommendations:
1. **For Users**: Extension provides useful highlighting features but monetizes via affiliate tracking. Review GiveFreely privacy policy and disable if uncomfortable with e-commerce tracking.
2. **For Researchers**: Monitor remote configs at `cdn.givefreely.com/adunit/behavioral/` for scope changes.
3. **For Chrome Web Store**: Require clearer disclosure of GiveFreely affiliate tracking in extension description. Flag hardcoded API credentials as security risk.

---

## Technical Notes

- **Codebase Quality**: Well-structured, uses TypeScript transpiled to JS, includes error handling and logging
- **Obfuscation Level**: Minified but readable variable names, no intentional obfuscation
- **PDF Viewer**: Bundles Mozilla PDF.js library (legitimate, open-source)
- **Frameworks**: Uses Quill Delta for rich text, BSON for data serialization, custom Web Components via `@webhighlights/shared-components`
- **Notable Dependencies**: Notion API client, Delta-to-HTML/Markdown converters, IndexedDB wrapper

---

## Conclusion

Web Highlights is a **legitimate but privacy-concerning** extension. The core highlighting/annotation functionality is useful and well-implemented. However, the GiveFreely affiliate platform integration tracks user browsing behavior across thousands of e-commerce sites with server-controlled configuration updates. While not overtly malicious, this represents significant behavioral tracking that may not be apparent to users from the CWS listing.

The extension falls into the "grey area" of affiliate marketing extensions—providing real value but monetizing through behavioral tracking. Users should be aware of this trade-off when installing.
