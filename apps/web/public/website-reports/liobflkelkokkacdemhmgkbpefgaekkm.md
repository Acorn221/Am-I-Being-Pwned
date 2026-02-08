# Security Analysis: AMZScout Stock Stats - Amazon Stock Level Spy

## Metadata
- **Extension ID**: liobflkelkokkacdemhmgkbpefgaekkm
- **Extension Name**: AMZScout Stock Stats - Amazon Stock Level Spy
- **Version**: 1.6.3
- **Users**: ~30,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

AMZScout Stock Stats is a legitimate Amazon seller tool that tracks product availability and stock levels. The extension connects to AMZScout's backend services to provide sales estimates, keyword analysis, and product insights. While the extension requires extensive permissions and handles sensitive Amazon session data, **all network communications are directed to legitimate AMZScout infrastructure** (amzscout.net, iamscout.net domains). The extension serves its intended purpose without exhibiting malicious behavior.

**Overall Risk Level: CLEAN**

The extension is invasive by design (requires access to all Amazon domains and manages cookies), but this is necessary for its core functionality as an Amazon seller intelligence tool. No evidence of malware, residential proxy infrastructure, extension enumeration, or unauthorized data exfiltration was found.

## Vulnerability Analysis

### 1. Broad Host Permissions
**Severity**: LOW
**Status**: EXPECTED FUNCTIONALITY

**Finding**: The extension requests `*://*/*` host permissions and specifically targets all Amazon domains worldwide.

**Evidence**:
```javascript
// manifest.json
"host_permissions": ["*://*/*"],
"content_scripts": [{
  "matches": [
    "*://www.amazon.cn/*", "*://www.amazon.nl/*", "*://www.amazon.ca/*",
    "*://www.amazon.co.uk/*", "*://www.amazon.com/*", "*://www.amazon.com.mx/*",
    "*://www.amazon.de/*", "*://www.amazon.it/*", "*://www.amazon.es/*",
    "*://www.amazon.fr/*", "*://www.amazon.in/*", "*://www.amazon.com.au/*",
    "*://www.amazon.ae/*", "*://www.amazon.sa/*"
  ]
}]
```

**Verdict**: This is expected for an Amazon seller tool that needs to operate across all Amazon marketplaces. The broad permissions are used exclusively for Amazon domain access.

---

### 2. Cookie and Session Handling
**Severity**: LOW
**Status**: NECESSARY FOR FUNCTIONALITY

**Finding**: Extension accesses Amazon cookies to maintain session state and retrieve product data.

**Evidence**:
```javascript
// background.js:44241
chrome.cookies.get({
  "url": domain,
  "name": cookie
}, function (_cookie) {
  var value = _cookie && _cookie.value;
  resolve(value);
});

// Commented code shows planned captcha bypass
// background.js:43137-43156
var FILTERED_OUT_COOKIES = [/x-amz-.*/, /sp-cdn/, /x-main/, /x-wl-uid/];
var CAPTCHA_COOKIE_NAME = 'x-amz-captcha-1';
```

**Verdict**: Cookie access is required to make authenticated requests to Amazon on behalf of the user. The extension filters specific Amazon cookies but does not exfiltrate them to unauthorized domains. All cookie handling is for legitimate Amazon marketplace analysis.

---

### 3. Extensive Data Collection and Analytics
**Severity**: LOW
**Status**: DISCLOSED FUNCTIONALITY

**Finding**: Extension implements comprehensive analytics tracking through `ScoutAnalytics` service.

**Evidence**:
```javascript
// background.js:41198-41320
cookieService.addListener('https://amzscout.net/analytics', function (r) {
  if (_this.cid != r.cid) {
    _this.cid = r.cid;
  }
}, cidKey);

// Analytics endpoints
"https://amzscout.net/analytics/v1/keywords"
"https://amzscout.net/analytics/v1/events"
"https://amzscout.net/analytics/v1/token/update"
```

**Verdict**: Analytics collection is standard for SaaS tools. Data is sent only to AMZScout's legitimate analytics infrastructure. No evidence of selling user browsing data or unauthorized tracking beyond the tool's stated purpose.

---

### 4. WebSocket Connection for Real-Time Tasks
**Severity**: LOW
**Status**: LEGITIMATE FEATURE

**Finding**: Extension maintains WebSocket connection to `wss://ws.amzscout.net/so/` for real-time product parsing tasks.

**Evidence**:
```javascript
// background.js:44644-44762
var WS_HOST = 'wss://ws.amzscout.net/so/';
var MAX_TRY_CONNECT = 3;

this.socket = new WebSocket("".concat(WS_HOST, "?software=").concat('STOCK_STATS_EXT'));
this.socket.onmessage = function (event) { return _this2.onMessage(event); };

// Handles events: 'update', 'task', 'check', 'stop'
switch (eventName) {
  case 'update': this.onUpdate(res.data); break;
  case 'task': this.onTask(res.data); break;
  case 'check': this.onCheck(res.data); break;
  case 'stop': this.onStop(res.data); break;
}
```

**Verdict**: WebSocket is used for distributed product parsing tasks, allowing AMZScout's backend to coordinate data collection across users. This is a legitimate architecture for a market intelligence tool. No evidence of malicious command-and-control.

---

### 5. Authentication via OAuth
**Severity**: LOW
**Status**: STANDARD AUTHENTICATION

**Finding**: Extension uses OAuth for user authentication with AMZScout services.

**Evidence**:
```javascript
// background.js:49132-49141
var IFRAME_SRC = "https://amzscout.net/oauth.html?id=".concat(ID, "&software=STOCK_STATS_EXT");

if (e.origin.indexOf('amzscout.net') >= 0 && e.data.event && e.data.id === ID) {
  // Handle OAuth callback
}

// Auth endpoints
"https://amzscout.net/auth/v1/users/me"
"https://amzscout.net/auth/v1/licences/"
"https://amzscout.net/auth/v1/oauth/"
```

**Verdict**: Standard OAuth implementation. Authentication tokens are scoped to AMZScout services.

---

### 6. Experiment/Feature Flag System
**Severity**: LOW
**Status**: STANDARD A/B TESTING

**Finding**: Extension includes experiment management system for feature rollouts.

**Evidence**:
```javascript
// background.js:44283-44485
function ExperimentService(experiments) {
  this.experiments = experiments;
  // Checks if experiment is enabled, handles date ranges
  if (experiment.fromDate && now <= experiment.fromDate ||
      experiment.toDate && now > experiment.toDate + DAY) {
    return experiment.defaultValue;
  }
}
```

**Verdict**: Standard A/B testing framework. No evidence of remote kill switches or malicious feature flags.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| CryptoJS password functions | main.js:3062-4387 | Standard CryptoJS library for legitimate encryption (password-based key derivation) |
| WebSocket connection | background.js:44644 | Legitimate real-time task coordination, not C2 |
| Cookie access | background.js:44241 | Required for authenticated Amazon API requests |
| Fetch intercept library | background.js:5864-5933 | Standard `fetch-intercept` npm package for request monitoring |
| Cheerio HTML parser | background.js:151-500 | Legitimate HTML parsing library for Amazon product pages |
| Angular framework patterns | main.js:49971-51394 | Standard Angular event handling, not keyloggers |

## API Endpoints and Data Flow

### AMZScout Backend Services

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://amzscout.net/extensions/stockstats/v1/*` | Product data, sales estimates, fees | ASINs, domains, prices, rank history |
| `https://amzscout.net/analytics/v1/*` | Usage analytics | Events, keywords, user actions, CID |
| `https://amzscout.net/auth/v1/*` | User authentication | OAuth tokens, license validation |
| `https://amzscout.net/api/v1/*` | Keyword research | Search queries, domains, parameters |
| `https://amzscout.net/keyword-service/v1/*` | Keyword storage | Keywords by domain |
| `https://amzscout.net/nservice/api` | Config service | N/A (retrieves config) |
| `https://amzscout.net/ad/api/ad` | Advertisement system | Ad impressions, clicks |
| `wss://ws.amzscout.net/so/` | Real-time task queue | Product URLs for parsing, task results |

### Externally Connectable
```javascript
"externally_connectable": {
  "matches": ["*://*.amzscout.net/*"]
}
```
Only AMZScout domains can communicate with the extension.

## Data Flow Summary

1. **Amazon → Extension**: Product pages, search results, seller data
2. **Extension → AMZScout Backend**: Product ASINs, sales ranks, prices, keywords
3. **AMZScout Backend → Extension**: Sales estimates, keyword scores, fees calculations
4. **WebSocket**: Real-time parsing tasks coordinated by backend

All communication is encrypted (HTTPS/WSS) and directed exclusively to AMZScout infrastructure. No third-party analytics SDKs, no residential proxy behavior, no unauthorized data exfiltration.

## Security Concerns (None Critical)

### Information Disclosure
The extension sends Amazon product viewing behavior and search queries to AMZScout servers for analysis. This is disclosed functionality - users install the tool specifically for this purpose.

### Permission Scope
While `host_permissions: ["*://*/*"]` is technically broad, the extension only injects content scripts on Amazon domains and only communicates with AMZScout services.

### Cookie Manipulation (Commented Code)
```javascript
// Commented code in background.js:43133-43229 shows infrastructure for:
// - Amazon captcha bypass
// - User-agent spoofing
// - Cookie injection for different countries
// This code is DISABLED in the current build
```
The presence of disabled anti-detection code suggests the developers considered implementing more aggressive scraping techniques but ultimately did not enable them.

## Recommendations

For AMZScout developers:
1. Consider narrowing `host_permissions` to only Amazon domains (current behavior already scoped)
2. Remove commented-out captcha bypass and user-agent spoofing code
3. Implement certificate pinning for backend API communication
4. Add subresource integrity (SRI) for any external resources

For users:
- This is a legitimate tool that functions as advertised
- Be aware that Amazon browsing behavior is shared with AMZScout for analysis
- Ensure you trust AMZScout with your Amazon marketplace intelligence data

## Overall Risk Assessment

**Risk Level: CLEAN**

AMZScout Stock Stats is a legitimate Amazon seller intelligence tool with no malicious behavior. The extension:
- ✅ Only communicates with official AMZScout infrastructure
- ✅ Uses permissions appropriately for stated functionality
- ✅ Contains no malware, keyloggers, or data theft mechanisms
- ✅ No residential proxy infrastructure
- ✅ No extension enumeration or killing behavior
- ✅ No ad injection or coupon hijacking
- ✅ No obfuscated malicious code
- ✅ No unauthorized third-party tracking

The extension is invasive by design (requires extensive Amazon access), but this is necessary and expected for a professional Amazon seller analytics tool. All data collection serves the tool's legitimate purpose of providing market intelligence to Amazon sellers.
