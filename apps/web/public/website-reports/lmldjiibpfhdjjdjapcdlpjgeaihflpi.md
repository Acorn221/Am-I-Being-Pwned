# Security Analysis: 飛比購物幫手:網路購物即時比價工具 (lmldjiibpfhdjjdjapcdlpjgeaihflpi)

## Extension Metadata
- **Name**: 飛比購物幫手:網路購物即時比價工具 (Feebee Shopping Helper)
- **Extension ID**: lmldjiibpfhdjjdjapcdlpjgeaihflpi
- **Version**: 3.46.0
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: Feebee (feebee.com.tw)
- **Analysis Date**: 2026-02-14

## Executive Summary
Feebee Shopping Helper is a Taiwanese price comparison extension that provides legitimate shopping assistance but engages in **extensive tracking and data collection** across all browsing activity. The extension collects search queries, product views, prices, click behavior, and browsing URLs from Google, Yahoo, Bing, YouTube, and all e-commerce sites. All API calls use `credentials: 'include'` to send cookies, enabling user identification. Third-party ads are injected via rd.sitemaji.com. While the core functionality is legitimate, the comprehensive tracking across all HTTP/HTTPS sites without transparent disclosure raises significant privacy concerns.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Extensive Cross-Site Browsing Tracking (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/js/ec.min.js` (lines 2371-2428)
- `/js/google.min.js` (lines 1213-1220)
- `/js/yahoo.min.js` (lines 1213-1220, 1264-1268)
- `/js/bing.min.js` (lines 1290-1294)

**Analysis**:
The extension tracks user behavior across all major search engines and e-commerce sites through content scripts running on `http://*/*` and `https://*/*`.

**Code Evidence** (`ec.min.js`, line 2371):
```javascript
fetch(`https://api.feebee.com.tw/ext/v1/ec-config?url=${encodeURIComponent(document.location.href)}&version=${se()}`, {
  credentials: "include",
  signal: AbortSignal.timeout(3e4),
  headers: {
    bck: encodeURIComponent(window.flybeeBck)
  }
})
```

**Code Evidence** (`yahoo.min.js`, line 1213):
```javascript
return `https://api.feebee.com.tw/ext/v1/x_result_g.php?title=${encodeURIComponent(e.searchKeyword)}&feebeeFlybeeVersion=${se()}&t=${...}&bck=${encodeURIComponent(window.flybeeBck)}`
```

**Data Transmitted**:
1. **Current URL** - Sent on every page load for all HTTP/HTTPS sites
2. **Search keywords** - From Google, Yahoo, Bing searches
3. **Product information** - Title, price, store name, product URL
4. **Click tracking** - Which products users click on search results
5. **Shopping history** - Product view history stored and synced to server
6. **Extension version** - Included in all requests
7. **BCK token** - Tracking identifier sent with credentials

**Privacy Impact**:
The extension builds a comprehensive profile of user shopping behavior, search queries, and general browsing activity across the entire web. The use of `credentials: 'include'` on all fetch requests means user cookies are sent with every API call, enabling persistent user identification.

**Verdict**: **MEDIUM RISK** - Legitimate business model (price comparison requires browsing data) but extensive scope without clear opt-out mechanism raises privacy concerns.

---

### 2. Third-Party Ad Injection (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/js/google.min.js` (lines 1144-1149)
- `/js/yahoo.min.js` (lines 1061-1066)
- `/js/bing.min.js` (lines 1061-1066)
- `/js/ec.min.js` (lines 801-813)

**Analysis**:
The extension injects promotional ads from `rd.sitemaji.com` into search result overlays on Google, Yahoo, Bing, and e-commerce sites.

**Code Evidence** (`ec.min.js`, lines 801-813):
```javascript
t.querySelector(".promo-ad-banner") && fetch("https://rd.sitemaji.com/ask.php?size=25x1&hosthash=870f5303c273", {
  method: "GET"
}).then((e => e.json())).then((o => {
  const i = o.s150x150.ad_list[0],
    n = t.querySelector(".promo-ad-banner"),
    r = document.createElement("a");
  r.classList.add("promo-ad-banner__anchor"), r.target = "_blank", r.href = i.ad_url, r.style.position = "absolute",
  r.innerHTML = `\n    <img style="margin:0 auto;display:block;width:150px;height:150px;" src="${i.ad_img}">\n`,
  r.addEventListener("click", (() => {
    je(_, {unit: "sitemaji_ad", src_page: e.srcPage})
  })), n.appendChild(r)
}))
```

**Security Concerns**:
1. **Third-party content injection** - Ads loaded from external domain (rd.sitemaji.com)
2. **No ad validation** - Extension directly injects ad URLs and images without sanitization
3. **Click tracking** - Ad clicks are tracked and reported back to Feebee API
4. **User confusion** - Ads appear within extension UI overlays on search pages

**Verdict**: **MEDIUM RISK** - While not inherently malicious, third-party ad injection increases attack surface and could be exploited if rd.sitemaji.com is compromised.

---

### 3. Hardcoded Google Analytics Credentials (LOW)
**Severity**: LOW
**Files**: `/js/background.min.js` (lines 97)

**Analysis**:
The extension includes a hardcoded Google Analytics Measurement ID and API secret in the background script.

**Code Evidence** (`background.min.js`, line 97):
```javascript
await fetch(n, {
  method: "POST",
  body: JSON.stringify(o)
})
}("https://www.google-analytics.com/mp/collect?measurement_id=G-0CRHPWXZ8L&api_secret=G99wKtS7Qs6WnJi7OOctQw", n.events);
```

**Security Concerns**:
1. **Exposed API secret** - `G99wKtS7Qs6WnJi7OOctQw` is visible to anyone inspecting the extension
2. **Analytics tracking** - User events are sent to Google Analytics with generated client_id
3. **Credential misuse risk** - Exposed secret could be used by third parties to send false analytics data

**Mitigation**:
Google Analytics Measurement Protocol API secrets are not highly sensitive (they validate but don't authenticate), but best practice is to proxy analytics through a backend service rather than including secrets in client-side code.

**Verdict**: **LOW RISK** - Poor security practice but limited real-world impact.

---

### 4. Broad Content Script Injection (MEDIUM)
**Severity**: MEDIUM
**Files**: `manifest.json` (lines 58-72)

**Analysis**:
The extension injects content scripts on all HTTP and HTTPS sites via the catch-all match pattern.

**Manifest Evidence**:
```json
{
  "run_at": "document_start",
  "matches": [
    "http://*/*",
    "https://*/*"
  ],
  "exclude_matches": [
    "*://*.google.com/*",
    "*://*.google.com.tw/*",
    "*://tw.search.yahoo.com/*",
    "*://www.bing.com/*",
    "*://www.youtube.com/*"
  ],
  "js": [
    "js/ec.min.js",
    "js/traffic.min.js"
  ]
}
```

**Privacy Impact**:
- Scripts run on **every website** the user visits (except excluded search engines)
- Runs at `document_start` before page content loads
- Immediate access to page URL, DOM content, and page context
- Can intercept and modify page behavior before user interaction

**Code Evidence** (`ec.min.js`):
The script immediately fetches configuration from Feebee API on page load:
```javascript
fetch(`https://api.feebee.com.tw/ext/v1/ec-config?url=${encodeURIComponent(document.location.href)}`, {
  credentials: "include"
})
```

This means **every page load on any website** triggers an API call to Feebee servers with the current URL and user cookies.

**Verdict**: **MEDIUM RISK** - Necessary for price comparison functionality but grants extensive access to user browsing.

---

### 5. Cookie Access with Credential Sharing (LOW)
**Severity**: LOW
**Files**: `/js/background.min.js` (lines 17-28)

**Analysis**:
The extension uses the `cookies` permission and sets cookies on feebee.com.tw domains from the background script.

**Code Evidence** (`background.min.js`, lines 17-28):
```javascript
function n(t) {
  const n = ["http://feebee.com.tw/", "http://www.feebee.com.tw/",
              "https://feebee.com.tw/", "https://www.feebee.com.tw/"];
  for (let a = 0; a < n.length; a++) {
    const o = {
      url: n[a],
      name: t.name,
      value: t.value,
      httpOnly: t.httpOnly
    };
    e.g.env.cookies.set(o)
  }
}
```

**Purpose**:
- Synchronizes cookies across HTTP and HTTPS versions of feebee.com.tw
- Maintains user session for price comparison features
- Stores installation tracking data (`firstInstallFlybee` cookie)

**Security Assessment**:
The cookie access is limited to the extension's own domain (feebee.com.tw) and is used for legitimate session management. The use of `credentials: 'include'` in fetch requests sends these cookies to the API, enabling user identification across sessions.

**Verdict**: **LOW RISK** - Standard session management practice for logged-in features.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency | Credentials |
|--------|---------|------------------|-----------|-------------|
| `api.feebee.com.tw/ext/v1/ec-config` | Site configuration | Current URL | Every page load (all sites) | include |
| `api.feebee.com.tw/ext/v1/x_result_g.php` | Price comparison results | Search keyword, extension version | Every search | include |
| `api.feebee.com.tw/ext/v1/x_click.php` | Click tracking | Product title, price, store, URL | Per product click | include |
| `api.feebee.com.tw/ext/v1/flybee_history.php` | Shopping history sync | Product view history array | Periodic sync | include |
| `api.feebee.com.tw/ext/v1/get_user_copon` | Coupon data | None (GET request) | On coupon feature use | include |
| `api.feebee.com.tw/ext/v1/x_enable-google.php` | Ad placement check | Search result URLs | Per search | No credentials |
| `api.feebee.com.tw/ext/v1/collect` | Event tracking | Timestamp | On specific events | No (image beacon) |
| `rd.sitemaji.com/ask.php` | Ad retrieval | Size parameter, hosthash | When ad slots visible | No credentials |
| `www.google-analytics.com/mp/collect` | Analytics | Event data, client_id | On user events | No credentials |

### Data Flow Summary

**Data Collection**: EXTENSIVE
- Search keywords from Google, Yahoo, Bing
- Product titles, prices, store names
- Current URL on all HTTP/HTTPS sites
- Product click behavior
- Shopping history

**User Data Transmitted**: HIGH VOLUME
- All API calls to api.feebee.com.tw use `credentials: 'include'`
- User cookies sent with every request for persistent identification
- Browsing URLs sent on every page load across the web

**Tracking/Analytics**: COMPREHENSIVE
- Google Analytics with hardcoded measurement ID
- Custom event tracking to Feebee API
- Third-party ad click tracking via rd.sitemaji.com
- Shopping history synchronization with backend

**Third-Party Services**:
1. **rd.sitemaji.com** - Ad network for promotional content
2. **Google Analytics** - Usage analytics and event tracking

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `cookies` | Session management for feebee.com.tw | Low (own domain only) |
| `contextMenus` | Right-click search on feebee.com.tw | Low (functional) |
| `storage` | Settings and history storage | Low (local only) |
| `host_permissions: *://*.feebee.com.tw/*` | API access for price data | Low (necessary) |
| **Content scripts: http://*/*, https://*/*** | **Price comparison on all sites** | **High (universal access)** |

**Assessment**: The broad content script injection on all HTTP/HTTPS sites is the primary privacy concern. While necessary for detecting shopping contexts, it grants the extension visibility into all user browsing.

## Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```
**Assessment**: Good - Restricts extension pages to self-hosted scripts only, preventing inline code execution.

## Externally Connectable
```json
"externally_connectable": {
  "matches": ["*://*.feebee.com.tw/*"]
}
```
**Assessment**: Good - Only allows feebee.com.tw domains to communicate with the extension, limiting external attack surface.

---

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`) detected
2. No XHR/fetch prototype hooking or monkey-patching
3. No extension enumeration or killing of competitors
4. No residential proxy infrastructure
5. Clean Content Security Policy for extension pages
6. Externally connectable limited to own domain
7. All data storage uses `chrome.storage.local` (not transmitted elsewhere)

### Security Concerns
1. **Extensive tracking scope** - Content scripts on all HTTP/HTTPS sites
2. **Credentials sent with all API calls** - Enables persistent user identification
3. **Third-party ad injection** - Ads from rd.sitemaji.com without validation
4. **Hardcoded API secrets** - Google Analytics secret exposed in code
5. **No opt-out mechanism** - Tracking appears automatic with no user control
6. **Obfuscated code** - Variable names minified, making auditing difficult

### Obfuscation Level
**Medium** - Code is minified with obfuscated variable names (standard build process). Logic is traceable but requires careful analysis.

---

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception for AI services |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection on third-party sites | ✓ **Yes** | rd.sitemaji.com ads injected in search overlays |
| Remote config loading | ✓ **Yes** | Fetches ec-config from API on every page load |
| Cookie harvesting | ✓ **Limited** | Only accesses own domain cookies (feebee.com.tw) |
| Comprehensive browsing tracking | ✓ **Yes** | URLs sent to API on all HTTP/HTTPS page loads |
| Credential sharing with API | ✓ **Yes** | All fetch requests use `credentials: 'include'` |

---

## Privacy Analysis

### What Data is Collected?
1. **Search queries** - From Google, Yahoo, Bing, YouTube
2. **Product views** - Titles, prices, store names, URLs
3. **Click behavior** - Which products users click on
4. **Browsing URLs** - Current URL sent on every page load (all sites)
5. **Shopping history** - Product view history stored locally and synced to server
6. **User identification** - Cookies sent with all API requests via `credentials: 'include'`
7. **Extension events** - Usage analytics sent to Google Analytics

### How is Data Used?
- **Price comparison** - Core functionality requires product and search data
- **Personalization** - Shopping history enables personalized recommendations
- **Analytics** - Usage tracking for product improvement
- **Advertising** - Third-party ads injected from rd.sitemaji.com
- **Click attribution** - Tracks which products users click for affiliate/referral purposes

### Transparency Concerns
- **No clear opt-out** - Tracking appears to be automatic
- **Broad scope** - Content scripts run on all HTTP/HTTPS sites, not just shopping sites
- **Third-party sharing** - Unclear if data is shared beyond rd.sitemaji.com ads
- **Credential sharing** - All API calls include cookies for persistent tracking

---

## Overall Risk Assessment

### Risk Level: **MEDIUM**

**Justification**:
1. **Legitimate functionality** - Price comparison tools require access to shopping data
2. **Extensive tracking** - Collects search queries, URLs, and product views across all browsing
3. **Third-party ads** - Injects ads from rd.sitemaji.com without validation
4. **Privacy concerns** - Comprehensive data collection with `credentials: 'include'` on all requests
5. **No malicious behavior** - No data theft, credential stealing, or malware detected
6. **Business model transparency** - Likely relies on affiliate commissions and advertising

### Risk Breakdown
- **Critical**: 0 vulnerabilities
- **High**: 0 vulnerabilities
- **Medium**: 3 vulnerabilities
  - Extensive cross-site browsing tracking
  - Third-party ad injection
  - Broad content script injection
- **Low**: 2 vulnerabilities
  - Hardcoded Google Analytics credentials
  - Cookie access with credential sharing

### Recommendations

**For Users**:
1. **Understand the tracking scope** - This extension monitors all browsing activity, not just shopping
2. **Review privacy policy** - Check feebee.com.tw's privacy policy for data retention and sharing practices
3. **Consider alternatives** - If uncomfortable with extensive tracking, consider extensions with narrower scope
4. **Monitor network activity** - Use browser DevTools to see what data is being sent

**For Developers** (Feebee):
1. **Reduce tracking scope** - Consider limiting content scripts to known shopping sites instead of all HTTP/HTTPS
2. **Add opt-out mechanism** - Allow users to disable analytics and non-essential tracking
3. **Proxy analytics** - Remove hardcoded Google Analytics secret, use backend proxy
4. **Validate ad content** - Sanitize and validate third-party ad URLs before injection
5. **Transparency** - Clearly disclose what data is collected and how it's used in extension description
6. **Minimize credential sharing** - Avoid `credentials: 'include'` where possible, use explicit authentication headers

**For Enterprise Administrators**:
- **Medium risk for deployment** - Extensive tracking may violate corporate privacy policies
- **Recommend review** - Evaluate against data loss prevention (DLP) requirements
- **Consider blocking** - If organization has strict data exfiltration policies

---

## Technical Summary

**Lines of Code**: 8,235 (deobfuscated)
**External Dependencies**: None
**Third-Party Libraries**: None (self-contained)
**Remote Code Loading**: None (but fetches remote config)
**Dynamic Code Execution**: None detected

---

## Conclusion

Feebee Shopping Helper is a **legitimate price comparison extension** with a **concerning level of tracking**. While the core functionality (comparing prices across shopping sites) is genuine and useful, the extension collects far more data than necessary by:

1. Running content scripts on **all HTTP/HTTPS sites** (not just shopping sites)
2. Sending **every page URL** to Feebee servers on load
3. Using `credentials: 'include'` on **all API calls** for persistent user identification
4. Injecting **third-party ads** from rd.sitemaji.com

The extension does not exhibit malicious behavior such as credential theft, residential proxying, or extension killing. However, the extensive tracking across all browsing activity raises significant **privacy concerns**, especially for users unaware of the scope.

**Final Verdict: MEDIUM RISK** - Legitimate tool with aggressive data collection practices that may not align with user privacy expectations. Safe for users who accept comprehensive shopping behavior tracking in exchange for price comparison features.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| www.w3.org exfiltration flows | Search result scripts | XML namespace constants | SVG/XML namespace declarations in minified code |
| Dynamic function detection | All scripts | Build process artifacts | Function() in polyfills, not malicious eval |

The ext-analyzer reported 12 exfiltration flows to www.w3.org, which are false positives from XML/SVG namespace constant declarations in the minified code (xmlns="http://www.w3.org/...").
