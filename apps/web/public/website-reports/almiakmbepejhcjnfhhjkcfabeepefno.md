# Vulnerability Report: Productor for Merch by Amazon

## Extension Metadata
- **Extension ID**: almiakmbepejhcjnfhhjkcfabeepefno
- **Name**: Productor for Merch by Amazon
- **Version**: 6.135.3
- **User Count**: ~80,000
- **Author**: Thimo Grauerholz
- **Manifest Version**: 3

## Executive Summary

Productor for Merch by Amazon is a productivity toolkit for Amazon Merch sellers. The extension has legitimate business functionality but exhibits several **privacy and security concerns** related to broad permissions, third-party API integrations, and automatic login management. While no critical malware indicators were found, the extension requests extensive permissions and modifies HTTP headers in ways that could be concerning for user privacy.

**Overall Risk Level**: MEDIUM

The extension is functionally legitimate but has privacy implications due to broad permissions, automatic session management, and third-party API dependencies. No malicious code patterns were detected, but the extensive access to Amazon domains and user data warrants scrutiny.

---

## Vulnerability Details

### 1. HTTP Header Modification via declarativeNetRequest
**Severity**: MEDIUM
**Files**: `manifest.json`, `assets/rule1.json`, `background.bundle.js`

**Description**: The extension modifies the User-Agent header for all requests to `merch.amazon.com` domains, setting it to "Productor". This is done via declarativeNetRequest rules.

**Code Evidence**:
```json
// assets/rule1.json
{
  "id": 1,
  "priority": 2,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [
      {
        "header": "user-agent",
        "operation": "set",
        "value": "Productor"
      }
    ]
  },
  "condition": {
    "urlFilter": "https://merch.amazon.com/*",
    "resourceTypes": ["main_frame", "sub_frame", "xmlhttprequest", "websocket", "script", "image", "object"]
  }
}
```

**Background dynamic header modification**:
```javascript
// background.bundle.js:69968
chrome.declarativeNetRequest.updateDynamicRules({
  // ... dynamic rule updates
  type: "modifyHeaders",
  // ...
})
```

**Verdict**: **Medium Risk** - While this is likely used for API identification with Amazon's Merch platform, modifying User-Agent headers can be used to fingerprint users or bypass certain security controls. The functionality appears legitimate for the extension's stated purpose but represents a privacy concern.

---

### 2. Extensive Host Permissions & Data Access
**Severity**: MEDIUM
**Files**: `manifest.json`

**Description**: The extension requests broad host permissions across multiple domains including all Amazon marketplaces, Google services, USPTO trademark search, DeepL translation, and third-party services.

**Permissions Requested**:
- All Amazon domains (14 country-specific domains including .com, .de, .co.uk, etc.)
- `*://*.productor.io/*` (developer's own API servers)
- `*://*.amazonaws.com/*` (AWS services)
- Google Trends and Google Suggest APIs
- `*://translate.googleapis.com/*`
- `*://tmsearch.uspto.gov/*` (US Patent/Trademark Office)
- `*://members.merchinformer.com/*` (third-party market intelligence)
- `*://*.deepl.com/*` (translation service)

**Additional Permissions**:
```json
"permissions": [
  "activeTab",
  "downloads",
  "contextMenus",
  "background",
  "notifications",
  "alarms",
  "storage",
  "unlimitedStorage",
  "declarativeNetRequest",
  "declarativeNetRequestFeedback",
  "offscreen"
]
```

**Verdict**: **Medium Risk** - While the permissions align with the extension's stated functionality (product research, trademark search, translation), the broad access to user browsing data across all Amazon domains creates privacy concerns. The extension can read all user activity on Amazon sites.

---

### 3. Automatic Login & Session Management
**Severity**: MEDIUM
**Files**: `background.bundle.js`, `content-relogin.bundle.js`

**Description**: The extension implements automatic re-login functionality that opens tabs, manages Amazon sessions, and can automatically log users back into Merch by Amazon.

**Code Evidence**:
```javascript
// background.bundle.js:68218
chrome.tabs.create({
  url: "https://www.amazon.com/ap/signin?openid.return_to=https%3A%2F%2Fmerch.amazon.com&...",
  active: !1,
  pinned: !0
}, (function(e) {
  var t = null == e ? void 0 : e.id;
  Object(Yc.J)("productor.merch.reLoginTab", t), setTimeout((function() {
    t ? chrome.tabs.update(e.id, {
      url: "https://merch.amazon.com/dashboard?productor-keep-logged-in=1",
      autoDiscardable: !1
    }, (function() {
      // ... notification logic
      chrome.alarms.create("alarmCloseLoginWindowFallback", {
        delayInMinutes: 2
      });
    }))
  }), 1e3)
}))
```

**Verdict**: **Medium Risk** - Automatic session management and login functionality can be a security risk if the extension is compromised. The extension opens background tabs and manages authentication state, which could be abused. However, the implementation appears to be for user convenience rather than malicious purposes.

---

### 4. Third-Party API Communications
**Severity**: LOW-MEDIUM
**Files**: `background.bundle.js`

**Description**: The extension communicates with multiple third-party API endpoints, some hosted by the developer and others by external services.

**API Endpoints Identified**:
```javascript
// Exchange rates API (developer-controlled)
fetch("https://exchange-rates-api1.productor.io/exchange-rates")

// Product sales rank API (developer-controlled)
fetch("https://products-api-ec2.productor.io/salesranks?asin=...")

// Trademark search APIs (developer-controlled)
fetch("https://dpma-tm-api.productor.io/search-batch?classes=...")
fetch("https://uspto-tm-api.productor.io/search-batch?classes=...")
fetch("https://euipo-tm-api1.productor.io/search-batch?classes=...")

// Amazon Merch API calls
fetch("https://merch.amazon.com/api/ng-amazon/coral/...")
fetch("https://merch.amazon.com/api/productconfiguration/get?id=...")
fetch("https://merch.amazon.com/api/reporting/purchases/records?...")
fetch("https://merch.amazon.com/api/reporting/earnings/records?...")
```

**Verdict**: **Low-Medium Risk** - The extension sends user activity data (ASINs, marketplace data, trademark searches) to developer-controlled servers. While this is expected for the extension's functionality, users should be aware that their product research and earnings data may be transmitted to third parties. No evidence of malicious data exfiltration was found.

---

### 5. Broad Content Script Injection
**Severity**: LOW
**Files**: `manifest.json`

**Description**: Content scripts are injected into all frames (`all_frames: true`) across multiple Amazon domains at `document_start`, giving the extension early access to page content.

**Content Scripts**:
- `content-research.bundle.js` (111,643 lines) - injected on all Amazon marketplace domains
- `content-mba.bundle.js` (265,637 lines) - injected on merch.amazon.com
- `content-menu.bundle.js` (3,269 lines) - injected on merch.amazon.com
- `content-relogin.bundle.js` (104 lines) - injected on merch.amazon.com and www.amazon.com
- `content-tmsearch.bundle.js` (3,254 lines) - injected on tmsearch.uspto.gov
- `content-infringement.bundle.js` (59 lines) - injected on Amazon infringement report pages

**Verdict**: **Low Risk** - The content scripts are very large (especially content-mba.bundle.js at 265k lines) and have access to all page content. However, analysis shows they contain legitimate libraries (ag-Grid, React, moment.js) and no obvious malicious patterns. The size is concerning from a performance perspective but not a security one.

---

### 6. Sentry Error Tracking Integration
**Severity**: LOW
**Files**: `background.bundle.js`, all content scripts

**Description**: The extension includes Sentry SDK for error tracking, which sends telemetry data to external servers.

**Code Evidence**:
```javascript
// SENTRY_RELEASE tracking
_global.SENTRY_RELEASE = {
  id: "31012c75dfed59577a44c9da1a80052e375237ea"
}

// Sentry debug IDs present in all bundle files
e._sentryDebugIds[t] = "3f0502df-d1a5-4afa-8690-4b240b9fc3aa"
```

**Verdict**: **Low Risk** - Error tracking is a standard development practice. The Sentry integration may send error logs and stack traces to Sentry's servers, which could include user data in error contexts. This is disclosed in standard privacy practices but users should be aware.

---

### 7. Chrome Storage Usage (unlimitedStorage)
**Severity**: LOW
**Files**: `background.bundle.js`

**Description**: The extension requests `unlimitedStorage` permission and uses chrome.storage.local extensively.

**Code Evidence**:
```javascript
// background.bundle.js:2401
chrome.storage.local.set(g({}, t, JSON.stringify(n)), (function() {
  e()
}))
```

**Verdict**: **Low Risk** - The extension stores product data, user preferences, and cached API responses locally. No evidence of sensitive credential storage was found. The `unlimitedStorage` permission is appropriate for a data-heavy productivity tool.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `eval` detection | background.bundle.js:53937 | Part of library polyfill code, not used for dynamic code execution |
| `new Function()` | background.bundle.js:26575, 34725, 53810 | Library code for framework functionality (React/moment.js), not malicious |
| `postMessage` usage | content-mba.bundle.js (multiple) | Standard inter-frame communication for UI components (ag-Grid library) |
| `password` field detection | background.bundle.js:12201-12405 | Sentry Replay library masking password fields for privacy (security feature, not vulnerability) |
| `sessionStorage` access | background.bundle.js:16353-16436 | Sentry Replay session management, standard library behavior |
| `localStorage` access | background.bundle.js:29584-29707 | IndexedDB/localForage library polyfill, not malicious data collection |
| `XMLHttpRequest` references | background.bundle.js | Sentry SDK network instrumentation hooks (error tracking) |
| `fetch` instrumentation | background.bundle.js | Sentry SDK breadcrumb collection for debugging |

---

## API Endpoints Table

| Endpoint | Purpose | Developer-Controlled |
|----------|---------|---------------------|
| `https://exchange-rates-api1.productor.io/exchange-rates` | Currency conversion rates | Yes |
| `https://products-api-ec2.productor.io/salesranks` | Amazon sales rank tracking | Yes |
| `https://dpma-tm-api.productor.io/search-batch` | German trademark search | Yes |
| `https://uspto-tm-api.productor.io/search-batch` | US trademark search | Yes |
| `https://euipo-tm-api1.productor.io/search-batch` | EU trademark search | Yes |
| `https://merch.amazon.com/api/*` | Amazon Merch API calls | No (Amazon) |
| `https://trends.google.com/*` | Google Trends data | No (Google) |
| `https://suggestqueries.google.com/*` | Google search suggestions | No (Google) |
| `https://translate.googleapis.com/*` | Translation API | No (Google) |
| `https://tmsearch.uspto.gov/*` | USPTO trademark database | No (USPTO) |
| `https://members.merchinformer.com/*` | Market intelligence data | No (Third-party) |
| `*.deepl.com/*` | Translation service | No (DeepL) |

---

## Data Flow Summary

1. **User Browsing on Amazon**: Content scripts monitor user activity on Amazon marketplace and Merch by Amazon dashboard
2. **Product Research**: Extension extracts ASIN, product data, sales ranks from Amazon pages
3. **Third-Party Enrichment**: Product ASINs sent to `products-api-ec2.productor.io` for sales rank data
4. **Trademark Searches**: Product names sent to developer-controlled trademark API proxies
5. **Amazon API Calls**: Extension makes authenticated API calls to Merch by Amazon for product configuration, earnings, and purchase data
6. **Local Storage**: Product data, research results, user preferences stored in chrome.storage.local
7. **Error Telemetry**: Errors and stack traces sent to Sentry for debugging (includes potential user data in error contexts)

**Data Shared Externally**:
- Product ASINs and research queries (to productor.io APIs)
- Trademark search terms (to productor.io trademark proxies)
- Error logs and stack traces (to Sentry)
- User authentication state (managed via Amazon login flows)

---

## Overall Risk Assessment

**MEDIUM**

### Justification:
The extension is a legitimate productivity tool for Amazon Merch sellers with no evidence of malicious code or active data theft. However, it exhibits several concerning characteristics:

**Security Concerns**:
- Broad permissions across all Amazon domains allow reading all user activity
- HTTP header modification via declarativeNetRequest
- Automatic session management and login functionality
- User data (ASINs, searches, earnings) transmitted to third-party servers
- Very large content scripts injected at document_start

**Mitigating Factors**:
- No credential harvesting detected
- No keylogging or clipboard monitoring
- No evidence of residential proxy infrastructure
- No extension enumeration/killing patterns
- No ad/coupon injection mechanisms
- Sentry integration is standard practice, not malicious
- API calls are legitimate for stated functionality

**Recommendation**: Users should be aware that this extension has extensive access to their Amazon browsing and earnings data, which is transmitted to developer-controlled servers. While the extension appears legitimate, users should review the privacy policy and understand what data is being collected.

---

## Verdict

**MEDIUM RISK** - Legitimate functionality with significant privacy implications due to broad permissions and third-party data sharing. No malicious code detected, but users should be cautious about the extent of data access and external API communications.
