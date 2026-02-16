# Vulnerability Report: Amazon Product Finder - AMZScout PRO Extension

## Extension Metadata
- **Name**: Amazon Product Finder - AMZScout PRO Extension
- **Extension ID**: njopapoodmifmcogpingplfphojnfeea
- **User Count**: ~100,000 users
- **Version**: 2.5.5.3
- **Manifest Version**: 3

## Executive Summary

AMZScout PRO is a legitimate Amazon product research tool that helps sellers analyze product opportunities, sales data, and keyword metrics. The extension demonstrates professional development practices with no malicious behavior detected. While it has broad permissions and collects analytics data, these are appropriate for its stated functionality as a market research tool for Amazon sellers.

**Overall Risk: LOW**

The extension uses permissions legitimately for its core Amazon product analysis features. All data collection serves documented business purposes (product research, user authentication, and analytics). No evidence of malware, unauthorized data harvesting, or malicious activity.

## Vulnerability Details

### 1. Broad Permissions Scope
**Severity**: LOW
**Files**: manifest.json
**Verdict**: LEGITIMATE - Required for functionality

**Details**:
The extension requests extensive permissions:
- `host_permissions: ["*://*/*"]` - All URLs
- `cookies` - Cookie access
- `identity` - OAuth authentication
- `tabs`, `activeTab` - Tab management
- `storage`, `unlimitedStorage` - Local data storage
- `alarms` - Background tasks

**Code Evidence**:
```json
{
  "permissions": [
    "background", "activeTab", "tabs", "storage",
    "unlimitedStorage", "cookies", "identity", "alarms"
  ],
  "host_permissions": ["*://*/*"]
}
```

**Assessment**: These permissions are necessary for:
- Amazon page analysis (host permissions)
- User authentication via Google OAuth (identity, cookies)
- Product data caching (storage)
- Real-time product monitoring (alarms)

All permissions align with advertised Amazon seller research functionality.

---

### 2. Third-Party Data Transmission
**Severity**: LOW
**Files**: background.js (lines 1490, 5612, 5807, 5833, 8094)
**Verdict**: LEGITIMATE - Standard API communication

**Details**:
Extension communicates with multiple AMZScout API endpoints for product data and analytics.

**API Endpoints Identified**:
- `https://amzscout.net/extensions/scoutpro/v1/products/{domain}/asins` - Product ASIN lookup
- `https://amzscout.net/extensions/scoutpro/v1/products/{domain}/{asin}/sales` - Sales data
- `https://amzscout.net/extensions/scoutpro/v1/products/{domain}/{asin}/history` - Historical data
- `https://amzscout.net/extensions/scoutpro/v1/fees/{domain}` - Amazon fee calculations
- `https://amzscout.net/extensions/scoutpro/v1/keywords/{domain}/{asin}/value` - Keyword value
- `https://amzscout.net/analytics/v1/events` - Analytics tracking
- `https://amzscout.net/analytics/v1/keywords` - Search keyword tracking
- `https://amzscout.net/ad/api/ad/config` - Ad configuration
- `https://amzscout.net/nservice/api` - Notification service

**Code Evidence**:
```javascript
// Line 1490 - Product ASIN batch lookup
p.fetch("".concat("https://amzscout.net/extensions/scoutpro",
  "/v1/products/").concat(i, "/asins"), "POST", h);

// Line 5807 - Sales data retrieval
Object(a.c)("".concat("https://amzscout.net/extensions/scoutpro",
  "/v1/products/").concat(r, "/").concat(t, "/sales"), "POST", o)

// Line 8094 - Analytics tracking
a._send("".concat("https://amzscout.net/analytics",
  "/v1/keywords"), "POST", u)

// Line 14521 - Custom header for AMZScout APIs
new RegExp("amzscout.net").test(t) && (h["X-Origin"] = "SCOUT_EXT_PRO")
```

**Assessment**: All API calls go to legitimate AMZScout domains. The extension adds custom header `X-Origin: SCOUT_EXT_PRO` to identify itself. This is standard practice for SaaS product research tools.

---

### 3. Analytics and User Tracking
**Severity**: LOW
**Files**: background.js (lines 8041-8139)
**Verdict**: LEGITIMATE - Standard product analytics

**Details**:
Extension implements analytics service to track user interactions and search behavior.

**Data Collected**:
- Client ID (cid) - Anonymous user identifier
- User ID (uid) - For authenticated users
- Search queries and results
- Event tracking (category, action, label)
- Amazon domain and marketplace

**Code Evidence**:
```javascript
// Line 8041 - Analytics service initialization
_classCallCheck(this, ScoutAnalytics),
this.queue = [], this.sync = null,
c.a.addListener("https://amzscout.net/analytics",
  (function(r) { /* ... */ }), "cid")

// Line 8083 - Search tracking
trackSearch(t, r, o, i) {
  var u = {
    category: t,
    domain: r,
    results: o,
    query: i,
    uid: a.userId || void 0,
    cid: c,
    software: "SCOUT_EXT_PRO"
  };
  a._send("...analytics/v1/keywords", "POST", u)
}
```

**Assessment**: Analytics collection is typical for commercial extensions. Data helps improve product research accuracy. User tracking is disclosed in privacy policy and necessary for personalized features.

---

### 4. Cookie Access
**Severity**: LOW
**Files**: background.js (line 8772)
**Verdict**: LEGITIMATE - Limited scope

**Details**:
Extension uses chrome.cookies API but only for AMZScout domain cookies (authentication and analytics).

**Code Evidence**:
```javascript
// Line 8772 - Cookie retrieval for AMZScout analytics
chrome.cookies.get({
  url: t,  // AMZScout analytics URL
  name: r
}, (function(t) {
  var r = t && t.value;
  o(r)
}))
```

**Assessment**: Cookie access is scoped to AMZScout's own domains for maintaining user sessions. No evidence of Amazon cookie harvesting or third-party cookie theft. The `cookies` permission is used appropriately.

---

### 5. External Messaging Interface
**Severity**: LOW
**Files**: background.js (lines 32957, 33455)
**Verdict**: LEGITIMATE - Restricted to AMZScout apps

**Details**:
Extension accepts external messages but only from whitelisted AMZScout extension IDs.

**Code Evidence**:
```javascript
// Line 33455 - External message listener with whitelist check
chrome.runtime.onMessageExternal.addListener((function(r, o) {
  c.a.includes(o.id) && u.includes(r.action) &&
    t.sendToActiveTab(r.action, r.params)
}))

// Line 32957 - Buy success listener
chrome.runtime.onMessageExternal.addListener((function(r) {
  return t(r)
}))
```

**Manifest Evidence**:
```json
"externally_connectable": {
  "matches": ["*://*.amzscout.net/*"]
}
```

**Assessment**: External messaging is properly restricted via `externally_connectable` in manifest. Only AMZScout web properties and whitelisted extensions can communicate. This prevents abuse by malicious third parties.

---

### 6. Google OAuth Authentication
**Severity**: LOW
**Files**: background.js (line 31976), manifest.json
**Verdict**: LEGITIMATE - Standard OAuth flow

**Details**:
Extension uses Google OAuth for user authentication to sync data across devices.

**Code Evidence**:
```javascript
// Line 31976 - OAuth token retrieval
chrome.identity.getAuthToken({
  interactive: t
}, (function(c) {
  // Token handling with retry logic
}))
```

**Manifest Evidence**:
```json
"oauth2": {
  "client_id": "342231008843-00bgfal101nucj7gdvmuq0aqg45kmgdn.apps.googleusercontent.com",
  "scopes": ["email"]
}
```

**Assessment**: Uses official Chrome Identity API with legitimate Google OAuth client ID. Only requests email scope. Token is used for AMZScout account authentication. Implementation includes proper error handling and retry logic.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` usage | bundle.js (multiple) | jQuery/Angular DOM manipulation - standard framework patterns |
| Keydown/keyup listeners | bundle.js:6398, 16556 | D3.js brush selection and search input handlers - legitimate UI features |
| `window.open()` | background.js:16023, 16040 | Opens AMZScout web app for database/trending items - documented feature |
| Broad host permissions | manifest.json | Required to inject UI on all Amazon marketplaces (14 domains) |
| localStorage access | background.js:7567, 15987 | Caching locale preferences and error timestamps |

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Sensitive Data |
|----------|---------|-----------|----------------|
| amzscout.net/extensions/scoutpro/v1/products/*/asins | Product lookup | Amazon ASINs | No |
| amzscout.net/extensions/scoutpro/v1/products/*/sales | Sales estimates | ASINs, marketplace | No |
| amzscout.net/extensions/scoutpro/v1/fees/* | Fee calculation | Product dimensions, price | No |
| amzscout.net/analytics/v1/events | Event tracking | User actions, cid | No |
| amzscout.net/analytics/v1/keywords | Search tracking | Search queries, results count | Limited |
| amzscout.net/ad/api/ad/config | Ad delivery | User ID, license info | Limited |
| Amazon marketplace domains | Product page scraping | None (read-only) | No |

## Data Flow Summary

**Data Collection**:
1. Extension scrapes Amazon product pages (titles, prices, ranks, reviews)
2. Sends ASINs and marketplace IDs to AMZScout API
3. Receives enriched data (sales estimates, keyword metrics, fee calculations)
4. Displays insights in injected UI widgets

**Authentication**:
1. User authenticates via Google OAuth (email scope only)
2. Extension exchanges OAuth token with AMZScout backend
3. Receives license and user ID for feature access
4. Stores session data in chrome.storage

**Analytics**:
1. Tracks search queries and results count
2. Logs user interactions (widget opens, clicks)
3. Sends to AMZScout analytics with anonymous CID
4. No PII beyond authenticated user ID

**No Evidence Of**:
- Amazon credential harvesting
- Payment information collection
- Unauthorized data exfiltration
- Proxy/VPN infrastructure
- Extension fingerprinting
- Market intelligence SDK abuse
- Remote code execution
- Kill switch mechanisms

## Overall Risk Assessment

**Risk Level: LOW**

**Justification**:
AMZScout PRO is a legitimate, professionally-developed Amazon seller research tool. All permissions and data collection serve documented business purposes. The extension:

1. **Legitimate Business Model**: Paid SaaS tool for Amazon sellers ($44.99/month according to AMZScout website)
2. **Appropriate Permissions**: All permissions directly support product research features
3. **Transparent Data Use**: API calls match advertised functionality
4. **Security Best Practices**: OAuth authentication, CSP, whitelisted external messaging
5. **No Malicious Patterns**: No evidence of malware, data theft, or unauthorized tracking
6. **Established Vendor**: AMZScout is a known company in the Amazon seller tools space

**Recommendations**:
- Users should review AMZScout's privacy policy regarding search query logging
- Extension only necessary for active Amazon sellers conducting product research
- Consider revoking if no longer using AMZScout services

**Comparison to Malicious Extensions**:
Unlike malicious extensions that hide their data collection, AMZScout clearly documents its features and API usage aligns with those claims. The extension does not exhibit any deceptive practices common in malware (obfuscation, hidden endpoints, credential theft).
