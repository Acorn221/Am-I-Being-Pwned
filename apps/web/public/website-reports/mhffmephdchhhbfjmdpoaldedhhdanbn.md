# Vulnerability Report: Norton Home Page

## Metadata
- **Extension Name:** Norton Home Page
- **Extension ID:** mhffmephdchhhbfjmdpoaldedhhdanbn
- **Version:** 3.23.0.14
- **Author:** NortonLifeLock Inc
- **Users:** ~4,000,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Executive Summary

Norton Home Page is a legitimate browser extension from NortonLifeLock (Gen Digital) that replaces the new tab page with a Norton-branded homepage featuring safe search, website safety ratings, weather, bookmarks, quick links, and customization features. The extension requests significant permissions (tabs, storage, scripting, alarms, webRequest, <all_urls> content scripts) but these are consistent with its stated functionality as a homepage replacement with website reputation checking.

The extension sends telemetry to Norton/Symantec servers and Google Analytics, which is standard for enterprise security products. The code is minified but not obfuscated in any deceptive way -- it uses standard webpack bundling. No evidence of malicious behavior, data exfiltration beyond expected telemetry, residential proxy infrastructure, keylogging, AI conversation scraping, or market intelligence SDKs was found.

## Vulnerability Details

### V-001: Telemetry Data Collection (Informational)
- **Severity:** LOW (Informational)
- **Files:** `trackingServerSdk.js`, `HeartBeatSDK.js`
- **Description:** The extension sends telemetry events to two endpoints:
  - `https://stats.securebrowser.com/` (production) / `https://stage-stats.securebrowser.com/` (staging)
  - `https://www.google-analytics.com/collect` (Google Analytics)
- **Data sent:** Browser name/version, OS, platform, language, client timestamp, machine ID (GUID), extension version, custom dimensions for feature usage (weather widget enabled, bookmarks enabled, etc.)
- **Code:**
  ```javascript
  // trackingServerSdk.js
  p = this._initParameters.build_type === e
    ? "https://stage-stats.securebrowser.com/"
    : "https://stats.securebrowser.com/"
  ```
- **Verdict:** Expected behavior for a Norton security product. Telemetry is feature-usage analytics, not browsing data exfiltration. Telemetry can be disabled via settings (`isTelemetryEnabled()`). **Not a vulnerability.**

### V-002: Content Script on <all_urls> (Informational)
- **Severity:** LOW (Informational)
- **Files:** `manifest.json`, `content/scripts/SymBfwCS.js`
- **Description:** The extension injects content scripts on `<all_urls>` (first content_scripts entry) including `SymBfwCS.js` which provides the framework for Norton's functionality. Additional content scripts inject on specific Google/Yahoo search pages for annotation (safety ratings).
- **Code (manifest.json):**
  ```json
  {
    "all_frames": false,
    "js": ["content/libs/uri.min.js", "content/scripts/SymBfwCS.js", ...],
    "matches": ["<all_urls>"],
    "run_at": "document_idle"
  }
  ```
- **Verdict:** Required for the extension's Safe Web functionality (displaying website safety ratings). Content scripts communicate with the background via `chrome.runtime.sendMessage` using structured message IDs. **Expected for a security extension.**

### V-003: Cookie Access via chrome.cookies API (Informational)
- **Severity:** LOW (Informational)
- **Files:** `SymBfw.js` (extension adapter layer)
- **Description:** The extension framework includes cookie management helpers (`getAllCookies`, `removeCookie`, `setCookie`, `onCookieChangedForUrl`). These are used for Norton portal authentication and session management, not for harvesting user cookies across domains. Cookie access is scoped to Norton's own domains.
- **Code:**
  ```javascript
  a.getAllCookies = function(e=null) {
    return new Promise(function(t) {
      chrome.cookies.getAll({domain:e}, function(e) { t(e) })
    })
  }
  ```
- **Verdict:** Standard cookie management for Norton portal integration. No evidence of cross-domain cookie harvesting. **Not a vulnerability.**

### V-004: chrome.management.get for Extension Details (Informational)
- **Severity:** LOW (Informational)
- **Files:** `SymBfw.js`
- **Description:** The extension can query details of other extensions by ID using `chrome.management.get()`. This is used to check if the companion Norton Safe Web extension is installed and to coordinate between Norton extensions (HP, DS, SafeWeb share install dates/settings).
- **Code:**
  ```javascript
  a.getExtensionDetails = e => {
    return new Promise((o,n) => {
      chrome.management.get(e, e => {
        var r = a.getLastError();
        if(c(r) || s(e)) return n("Error in getting extension details");
        o(e);
      })
    })
  }
  ```
- **Verdict:** Used for Norton extension coordination only, not for competitive extension enumeration/killing. The extension communicates with known Norton extension IDs only. **Not a vulnerability.**

### V-005: Search Query Redirection (Informational)
- **Severity:** LOW (Informational)
- **Files:** `global.js`, `searchQuery.js`
- **Description:** The extension intercepts omnibox searches and redirects them through Norton Safe Search (nortonsafe.search.ask.com) using `chrome.webRequest.onBeforeRequest`. Search queries include tracking parameters (ocode, install source, campaign code, install date).
- **Code:**
  ```javascript
  chrome.webRequest.onBeforeRequest.addListener(
    l.NSSSHelper.handleOmniSearchMv3,
    {urls: [l.constants.SEARCH_URL + "?omnisearch=yes*"]}
  )
  ```
- **Verdict:** This is the extension's primary advertised functionality (Norton Safe Search). It only intercepts searches when the user has opted into using Norton as their search provider. **Expected behavior.**

### V-006: Affiliate Links in Quick Links (Informational)
- **Severity:** LOW (Informational)
- **Files:** `homePageBG.js`
- **Description:** The homepage displays "quick links" that include affiliate/monetization URLs through services like `ampxdirect.com`, `redirect.viglink.com`, `affinity.net`, and `awin1.com`. Norton monetizes the homepage through these affiliate links.
- **Code:**
  ```javascript
  amazon: {
    associateUrl: "https://nortontiles.ampxdirect.com?partner=nortontiles&sub1=10142&sub2=searchsafe&sub3=74301&source=als_tiles",
    impressionUrl: "https://imp.mt48.net/static?v=2&partner=nortontiles..."
  }
  ```
- **Verdict:** Standard homepage monetization through affiliate links. Links are clearly labeled and go to legitimate retailers. This is a common monetization strategy for homepage extensions. **Not a vulnerability.**

### V-007: SafeWeb URL Reputation Checking (Informational)
- **Severity:** LOW (Informational)
- **Files:** `SafeWeb.js`
- **Description:** The extension sends URLs to Norton's URLITE reputation service (`https://urlite.ff.avast.com/v1/urlinfo`) to check for malware, phishing, and other threats. Requests use protobuf encoding. The `do_not_track` field is available in the query structure.
- **Verdict:** Core security functionality. URL reputation checking is the primary purpose of Norton Safe Web. **Expected behavior.**

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | `multiVariateTestingBG.js` | Webpack polyfill for `globalThis` detection -- standard bundler output |
| `eval` (2 occurrences) | `SymBfw.js` | Not actual `eval()` calls -- partial string matches in identifiers/comments |
| `chrome.cookies.*` | `SymBfw.js` | Extension adapter for Norton portal session management, not cross-domain harvesting |
| `chrome.management.get` | `SymBfw.js` | Norton extension coordination, not competitive enumeration |
| `document.cookie` set/get | `SymBfw.js` | Simple cookie helper for Norton-domain cookies only |
| `postMessage` | `SymBfwCS.js` | In-product messaging iframe communication (Norton notification center) |
| `MutationObserver` (22x) | `annotationCS.js` | DOM observation for inserting safety rating annotations on search results |
| `fetch()` | `SymBfw.js` | Generic fetch wrapper (`safeFetch` with timeout), not data exfiltration |
| `clipboard` access | `SymBfw.js` | `copyToClipboard` helper using `document.execCommand("copy")` |
| `obfuscatePassword` | `SymBfwCS.js` | Utility for obfuscating password strings for Norton portal login, not keylogging |
| `chrome.history` access | `SymBfwCS.js` | History management for Norton homepage features (browsing data cleanup) |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://stats.securebrowser.com/` | Telemetry (production) | Event type, browser info, machine GUID, feature usage |
| `https://stage-stats.securebrowser.com/` | Telemetry (staging) | Same as above |
| `https://www.google-analytics.com/collect` | Google Analytics heartbeat | App name/version, machine ID, custom dimensions |
| `https://urlite.ff.avast.com/v1/urlinfo` | URL reputation (SafeWeb) | URLs for safety rating (protobuf) |
| `https://geolocation.norton.com/api/v2/GeoLocation` | Geo-location for weather | None (IP-based geolocation) |
| `https://static.nortoncdn.com/nortonextensionhomepage/` | Config downloads (AdRules, URL parsing) | None (GET requests) |
| `https://nortontiles.tiles.ampfeed.com/tiles` | Dynamic ad/affiliate tiles | Partner code, region |
| `https://nortontiles.ampxdirect.com` | Affiliate redirects | Click tracking params |
| Norton Safe Search portal | Search queries | User search terms, tracking params |

## Data Flow Summary

1. **Installation:** Extension registers install/update telemetry, sets vendor constants, coordinates with companion Norton extensions via `chrome.runtime.sendMessageExternal`.
2. **New Tab:** Overrides new tab page with Norton homepage. Fetches weather data, location, quick links configs from Norton CDN. Displays safety-rated quick links with affiliate monetization.
3. **Search:** When user searches from homepage, query is sent to Norton Safe Search (ask.com-powered) with tracking parameters (ocode, install source, campaign).
4. **Website Ratings:** On Google/Yahoo/Ask search result pages, `annotationCS.js` injects safety rating annotations. URLs are sent to Norton URLITE service for reputation checking.
5. **Telemetry:** Heartbeat pings sent every 30 minutes to `stats.securebrowser.com` with feature usage data. Google Analytics events for install/update/clicks. Telemetry respects user opt-out settings.
6. **Extension Coordination:** Shares install dates and settings with companion Norton extensions (Safe Web, Safe Search) via cross-extension messaging.

## Overall Risk Assessment

**Risk Level: CLEAN**

Norton Home Page is a legitimate security/homepage extension from NortonLifeLock (Gen Digital). While it requests broad permissions and collects telemetry, all behaviors are consistent with its advertised functionality:
- Homepage replacement with weather, bookmarks, and quick links
- Safe Search integration with URL reputation checking
- Website safety annotations on search results
- Standard telemetry with opt-out capability

The extension monetizes through affiliate links on the homepage and Norton Safe Search, which is standard for homepage extensions. No evidence of malicious behavior, data exfiltration, keylogging, proxy infrastructure, extension killing, or deceptive practices was found. The code is from a reputable security vendor and the permission usage aligns with stated functionality.
