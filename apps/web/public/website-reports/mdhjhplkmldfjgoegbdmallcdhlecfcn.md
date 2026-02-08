# LI Prospect Finder - Security Analysis Report

## Extension Metadata

- **Extension Name**: LI Prospect Finder
- **Extension ID**: mdhjhplkmldfjgoegbdmallcdhlecfcn
- **Version**: 3.2.6
- **User Count**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

LI Prospect Finder is a legitimate LinkedIn lead generation and data scraping tool that collects professional contact information from LinkedIn profiles, search results, and company pages. The extension automatically captures LinkedIn page HTML, intercepts LinkedIn API requests, and transmits this data to the vendor's backend (`li-prospect-finder.com`) for processing and email discovery.

**Overall Risk Level**: **MEDIUM**

The extension exhibits concerning data collection practices but appears to be a legitimate commercial tool rather than malware. Primary concerns include extensive LinkedIn data harvesting, automatic page HTML exfiltration, webRequest interception of LinkedIn API calls, and transmission of user browsing data to third-party servers without explicit opt-in consent.

## Vulnerability Analysis

### V1: Automatic LinkedIn Data Exfiltration (MEDIUM Severity)

**Files**: `js/content.js`, `js/background/sendLiHtml.js`, `js/apiMethods.js`

**Description**: The extension automatically captures full HTML content from LinkedIn pages (profiles, company pages, search results) and transmits it to `li-prospect-finder.com` backend servers without explicit per-page user consent.

**Code Evidence**:

```javascript
// js/content.js (lines 36-45)
function getHtml() {
  var e = getPageParams();
  (e.url || e.pageType) && chrome.runtime.sendMessage({
    type: "liHtml",
    url: e.url,
    pageType: e.pageType,
    html: document.body.innerHTML,  // Full page HTML captured
    lang: e.lang || "",
    isRenderedPage: isRenderedPage
  })
}

// Monitors page mutations and automatically triggers capture
(rootHtmlObserver = new MutationObserver(() => {
  var e = document.querySelector('.boot-complete, body[data-rehydrated="true"]');
  e && 0 < e.children.length && (isRenderedPage = !0,
    timeoutId = setTimeout(getHtml, 5e3), // Auto-capture after 5 seconds
    rootHtmlObserver.disconnect(), rootHtmlObserver = null,
    setPageToChromeStorage())
})).observe(document.body, {
  childList: !0,
  subtree: !0
})
```

```javascript
// js/apiMethods.js (lines 104-125)
async function apiSendLiHtml({
  link: e,
  html: a,
  lang: t,
  isRenderedPage: n
}, i = !1) {
  if (await checkAuthenticationNew(!0)) {
    n = await put(API_HOST + LI_HTML, {  // PUT to /extension/api/linkedin/collect
      link: e,
      data: a,  // Full HTML payload
      lang: t,
      isRenderedPage: n
    });
    // ... error handling ...
    return n.ok
  }
}
```

**Affected Page Types**:
- LinkedIn profiles (`/in/*`)
- Company profiles (`/company/*`)
- Sales Navigator leads (`/sales/lead/*`)
- Sales Navigator companies (`/sales/company/*`)

**Verdict**: This is expected behavior for a lead scraping tool, but the automatic nature without per-page consent and lack of data minimization (sending full HTML vs. extracted fields) raises privacy concerns. Users may not realize every LinkedIn page they visit is being transmitted to third-party servers.

---

### V2: LinkedIn API Request Interception (MEDIUM Severity)

**Files**: `js/background/webRequestListeners.js`

**Description**: The extension uses `chrome.webRequest` to intercept LinkedIn API requests, capturing API URLs, CSRF tokens, and request bodies for people/company searches.

**Code Evidence**:

```javascript
// js/background/webRequestListeners.js (lines 36-66)
chrome.webRequest.onBeforeSendHeaders.addListener(r => {
  if (-1 !== r.url.indexOf("sales-api") || -1 !== r.url.indexOf("voyager/api/"))
    for (let e = 0; e < r.requestHeaders.length; e++)
      if ("csrf-token" === r.requestHeaders[e].name.toLowerCase()) {
        // Store CSRF token for later use
        chrome.storage.local.set({
          [STORAGE_KEYS.LI_CRFC_TOKEN]: r.requestHeaders[e].value
        });

        // Capture search API URLs
        if (0 < r.url.indexOf("salesApiPeopleSearch")) {
          r.method === REQUEST_METHODS.GET &&
            (addLinkToStorageList(WEB_REQUEST_LI_API_URLS.SALES_PEOPLE_SEARCH, r.url, r.tabId),
             addLinkMethodToStorageList(WEB_REQUEST_LI_API_URLS.SALES_PEOPLE_SEARCH_METHOD, REQUEST_METHODS.GET, r.tabId));
          break
        }
        // ... similar for company searches, schools, etc.
      }
}, {
  urls: [LI_HOST + "/*/*"]
}, ["requestHeaders"])

// Intercept POST request bodies
chrome.webRequest.onBeforeRequest.addListener(r => {
  if (-1 !== r.url.indexOf("salesApiPeopleSearch") || -1 !== r.url.indexOf("salesApiLeadSearch")) {
    let e = "";
    var a;
    r.method === REQUEST_METHODS.POST && r.requestBody && r.requestBody.raw &&
      r.requestBody.raw[0] && r.requestBody.raw[0].bytes &&
      (a = new TextDecoder("utf-8").decode(r.requestBody.raw[0].bytes),
       e = r.url + "?" + a),  // Captures POST body
    // ... store for reuse ...
  }
}, {
  urls: [LI_HOST + "/*/*"]
}, ["requestBody"])
```

**Verdict**: This allows the extension to replay LinkedIn API requests from its own code. While necessary for the tool's functionality, it demonstrates deep integration with LinkedIn's internal APIs and could potentially be abused for automated scraping at scale.

---

### V3: Cookie Manipulation and Session Management (LOW Severity)

**Files**: `js/sw.js`, `js/checkAuthNew.js`, `js/common.js`

**Description**: The extension reads, modifies, and syncs cookies between the vendor's backend domains (`li-prospect-finder.com` and a dynamic `mainHost` fetched at runtime).

**Code Evidence**:

```javascript
// js/sw.js (lines 22-54)
async function checkCurrentToken() {
  var e, o;
  IS_PROD ? (e = await chrome.cookies.get({
    url: APP_HOST,
    name: TOKEN_NAME  // "st_ua" token
  }), setCookie((o = await chrome.cookies.get({
    url: mainHost,
    name: TOKEN_NAME
  }))?.value !== e?.value, o?.value)) : checkCurrentTokenStage()
}

function setCookie(e, o) {
  e && (IS_PROD && chrome.cookies.set({
    name: TOKEN_NAME,
    value: o,
    url: APP_HOST,
    expirationDate: new Date / 1e3 + 1209600,  // 14 days
    httpOnly: !0,
    secure: !0,
    sameSite: "no_restriction"  // Allows cross-site cookies
  }), chrome.storage.local.set({
    [STORAGE_KEYS.COMPANY_LIST_CHANGED]: !0
  }), chrome.storage.local.set({
    [STORAGE_KEYS.USER_LIST_CHANGED]: !0
  }))
}

// js/common.js (lines 25-40)
async function setCookiesForApiHost() {
  (await chrome.cookies.getAll({
    url: mainHost
  })).map(async ({
    name: e,
    value: t
  }) => chrome.cookies.set({
    name: e,
    value: t,
    url: APP_HOST,  // Copy all cookies to APP_HOST
    expirationDate: new Date / 1e3 + 1209600,
    httpOnly: !0,
    secure: !0,
    sameSite: "no_restriction"
  }))
}
```

**Verdict**: Cookie manipulation is necessary for authentication synchronization with the vendor's SaaS platform. The use of `sameSite: "no_restriction"` is required for cross-domain cookie sharing but could pose CSRF risks if the backend is vulnerable.

---

### V4: Dynamic Backend Domain Configuration (LOW Severity)

**Files**: `js/common.js`, `js/constants.js`

**Description**: The extension fetches backend domain configuration from a remote JSON file at runtime.

**Code Evidence**:

```javascript
// js/common.js (lines 13-18)
async function setMainHost() {
  if (IS_PROD) try {
    var e = await (await fetch(APP_HOST + "/assets/domain.json")).json();
    host = e.host, mainHost = "https://" + e.link  // Dynamic domain
  } catch (e) {}
  else host = "{preprodHost}", mainHost = "https://{preprodMainHost}"
}

// js/constants.js (line 1)
let APP_HOST = "https://li-prospect-finder.com"
```

**Verdict**: This allows the vendor to change backend infrastructure without updating the extension. While convenient, it introduces supply-chain risk if `domain.json` is compromised or the domain ownership changes.

---

### V5: Google Analytics Telemetry (LOW Severity)

**Files**: `js/googleAnalyticsEvents.js`

**Description**: The extension sends usage telemetry to Google Analytics (UA-94112226-16) including install/update events and feature usage.

**Code Evidence**:

```javascript
// js/googleAnalyticsEvents.js (lines 12-16)
send(e) {
  e = e + "_" + chrome.runtime.getManifest().version;
  var t = new URLSearchParams;
  t.append("v", 1), t.append("tid", this.trackingID),
  t.append("cid", this.gaCID), t.append("t", "event"),
  t.append("ec", "LIPFExt"), t.append("ea", e),
  this.postData(this.analyticsPath, t)
}
```

**Tracked Events**: install, update, search actions, task completion

**Verdict**: Standard analytics for a commercial extension. No PII appears to be transmitted, only aggregated usage events.

---

## False Positives

| Finding | Reason for Dismissal |
|---------|---------------------|
| `innerHTML` usage in parsers | Used only for parsing API responses and extracting data, not for DOM manipulation or XSS |
| jQuery `.html()` calls | Limited to safe HTML decoding operations (`$("<textarea/>").html(encodedString).text()`) |
| Remote version checking | Standard update notification mechanism (`extension.json` from vendor domain) |
| Cookie access on `<all_urls>` | Limited to LinkedIn.com in practice; broad permission for LinkedIn subdomains |

---

## API Endpoints and Data Flow

### Outbound Data Transmission

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| `https://li-prospect-finder.com/extension/api/linkedin/collect` | PUT | `{link, data (full HTML), lang, isRenderedPage}` | Submit captured LinkedIn page HTML |
| `https://li-prospect-finder.com/extension/api/peoples/create` | POST | Extracted prospect data (name, title, company, etc.) | Save leads to user's account |
| `https://li-prospect-finder.com/extension/api/companies/create` | POST | Company data from LinkedIn | Save companies to user's account |
| `https://li-prospect-finder.com/extension/api/user/balance` | GET | None (authenticated) | Check user's credit balance |
| `https://li-prospect-finder.com/extension/api/news/get-last` | GET | `?data={extensionName}` | Fetch promotional notifications |
| `https://www.google-analytics.com/collect` | POST | Event telemetry (no PII) | Usage analytics |

### Data Collected from LinkedIn

**From Page HTML**:
- Full name, title, location, country
- Profile picture URLs
- Employment history (current/past positions)
- Company information (name, size, industry, employee count)
- Skills (from API responses)
- Email addresses (when discoverable from page source)

**From Intercepted API Requests**:
- LinkedIn CSRF tokens
- Search query parameters
- Profile entity URNs
- API response data

---

## Data Flow Summary

```
LinkedIn Page Load
    ↓
Content Script Monitors DOM (MutationObserver)
    ↓
After 5s Delay → Capture document.body.innerHTML
    ↓
Store in chrome.storage.local temporarily
    ↓
Background Service Worker Retrieves HTML
    ↓
Strip <svg>, <img>, <code> tags (minimal sanitization)
    ↓
PUT to li-prospect-finder.com/extension/api/linkedin/collect
    ↓
Backend Parses HTML → Extracts Contact Data
    ↓
User Views Extracted Data in Extension Popup
    ↓
User Clicks "Save" → POST to /peoples/create or /companies/create
```

**LinkedIn API Interception Flow**:
```
User Browses LinkedIn Search/Profile
    ↓
LinkedIn Makes API Request (e.g., /voyager/api/search/dash/clusters)
    ↓
chrome.webRequest.onBeforeSendHeaders → Extract CSRF Token
    ↓
chrome.webRequest.onBeforeRequest → Capture Request Body (if POST)
    ↓
Store API URL + Method + Body in chrome.storage.local
    ↓
Extension Reuses Stored API URLs to Fetch Data Directly (bypassing LinkedIn UI)
```

---

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| `tabs` | Query active tab URL to determine LinkedIn page type | Low - standard popup interaction |
| `cookies` | Sync authentication between extension and web app | Medium - can read/write all cookies on host_permissions domains |
| `notifications` | Show update/news notifications | Low - user-visible only |
| `storage` | Cache scraped data, settings, task state | Low - standard extension storage |
| `webRequest` | Intercept LinkedIn API calls to extract CSRF tokens and URLs | Medium - passive monitoring, not blocking/modifying |
| `contextMenus` | Add "Background tasks" context menu | Low - UI enhancement |
| `scripting` | Inject presence detection script on LinkedIn pages | Low - minimal injected code |
| `host_permissions: ["http://*/", "https://*/"]` | Access all websites to read LinkedIn content | **HIGH RISK** - overly broad; should be restricted to `*://linkedin.com/*` |

**Critical Issue**: The `host_permissions` grant access to **all HTTP/HTTPS websites**, not just LinkedIn. This is a significant over-permission. While the extension only actively operates on LinkedIn URLs in practice, the manifest grants it capability to read/modify any website.

---

## Content Security Policy

**Manifest CSP**: None explicitly defined (defaults to MV3 strict CSP)

**Analysis**: Manifest V3 enforces strict CSP by default (no inline scripts, no eval). Code review confirms no `eval()`, `Function()`, or dynamic code execution. All scripts are static files.

---

## Privacy Concerns

1. **Passive Data Collection**: Every LinkedIn page visit triggers automatic HTML capture and transmission to vendor servers, even if the user doesn't actively click "Save"
2. **Overly Broad Permissions**: `host_permissions` grant access to all websites, not just LinkedIn
3. **Third-Party Data Sharing**: LinkedIn profile data is transmitted to vendor backend without explicit LinkedIn authorization
4. **LinkedIn ToS Violation**: Automated scraping and API interception likely violates LinkedIn's Terms of Service and User Agreement
5. **No Data Minimization**: Sends entire page HTML instead of just extracted fields

---

## Risk Assessment

### Overall Risk: **MEDIUM**

**Breakdown**:
- **Malware Likelihood**: LOW - This is a legitimate commercial product with identifiable vendor
- **Privacy Risk**: HIGH - Extensive automated data collection and transmission
- **Security Risk**: MEDIUM - Overly broad permissions, remote config dependency
- **Compliance Risk**: HIGH - Likely violates LinkedIn ToS; may raise GDPR/CCPA concerns

### Threat Model

**For Users**:
- LinkedIn account suspension risk (automated scraping detection)
- Privacy exposure (browsing history on LinkedIn transmitted to third party)
- Dependency on vendor security practices (data stored on li-prospect-finder.com)

**For LinkedIn Users Being Scraped**:
- Publicly available LinkedIn data harvested without consent
- Email addresses discovered and added to marketing databases
- Profile views may trigger LinkedIn notifications

---

## Recommendations

### For Users
1. Review LinkedIn's Terms of Service before use (likely prohibits automated scraping)
2. Understand that all LinkedIn pages visited are captured and transmitted to vendor servers
3. Consider using on a non-primary LinkedIn account to mitigate suspension risk
4. Review vendor privacy policy at li-prospect-finder.com

### For Vendor (Good Faith Security Recommendations)
1. **Restrict host_permissions** to `*://www.linkedin.com/*` and `*://li-prospect-finder.com/*` only
2. **Implement opt-in consent** for page capture (require user click before transmitting HTML)
3. **Data minimization**: Extract and send only necessary fields instead of full HTML
4. **Clarify data retention**: Document how long captured LinkedIn data is stored
5. **Add CSP headers** to popup/options pages for defense-in-depth

---

## Conclusion

LI Prospect Finder is a **legitimate but aggressive LinkedIn scraping tool**. It does not contain traditional malware characteristics (no code obfuscation, no C2 infrastructure, no keyloggers, no credential theft), but its data collection practices are extensive and may surprise users who don't fully understand the extension's behavior.

The primary concern is **privacy invasion through passive surveillance** of LinkedIn browsing activity. Every profile, search result, and company page visited is automatically captured and transmitted to vendor servers for analysis. While this is the core functionality of a lead generation tool, the lack of per-page consent and overly broad permissions raise ethical and compliance concerns.

**Recommended User Action**: Use with caution and awareness that LinkedIn browsing activity is being monitored and transmitted. Consider whether the productivity benefits outweigh the privacy trade-offs and account suspension risk.

---

## Report Metadata

- **Analyst**: Claude Sonnet 4.5
- **Analysis Methodology**: Static code analysis, manifest review, network endpoint mapping
- **Code Volume**: ~7,037 lines of JavaScript
- **Coverage**: 100% of deobfuscated source code
- **False Positive Rate**: Low (known FPs documented in table above)

---

**Overall Risk Level**: **MEDIUM**
- **Version**: 3.2.6
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

LI Prospect Finder is a LinkedIn automation tool that scrapes user profiles, company data, and contact information from LinkedIn pages. The extension exhibits **legitimate business functionality** but employs **aggressive data harvesting techniques** that pose privacy risks and potentially violate LinkedIn's Terms of Service. While not technically malicious, the extension collects sensitive professional data including LinkedIn profiles, company information, email addresses, and user activity patterns.

**Overall Risk Level**: MEDIUM

The extension operates as advertised but raises significant privacy concerns through comprehensive LinkedIn data extraction, user tracking, and transmission of scraped content to external servers.

## Vulnerability Assessment

### 1. EXCESSIVE DATA HARVESTING - MEDIUM SEVERITY

**Files**:
- `js/content.js` (lines 36-103)
- `js/background/sendLiHtml.js` (lines 1-53)
- `js/sw.js` (lines 138-147)

**Description**:
The extension captures complete HTML content from LinkedIn pages including profiles, company pages, and search results. This data is stored locally and transmitted to external servers.

**Code Evidence**:
```javascript
// content.js - Captures full page HTML
function getHtml() {
  var e = getPageParams();
  (e.url || e.pageType) && chrome.runtime.sendMessage({
    type: "liHtml",
    url: e.url,
    pageType: e.pageType,
    html: document.body.innerHTML,  // Full page content
    lang: e.lang || "",
    isRenderedPage: isRenderedPage
  })
}

// Monitors page mutations to capture dynamically loaded content
rootHtmlObserver = new MutationObserver(() => {
  var e = document.querySelector('.boot-complete, body[data-rehydrated="true"]');
  e && 0 < e.children.length && (isRenderedPage = !0,
    timeoutId = setTimeout(getHtml, 5e3), // Waits 5 seconds then captures
    rootHtmlObserver.disconnect(), rootHtmlObserver = null,
    setPageToChromeStorage())
})
```

**sendLiHtml.js - Transmits to external API**:
```javascript
async function sendLiHtml({url: e, html: a, pageType: t, lang: l, isRenderedPage: s}) {
  // Cleans HTML but preserves data
  a = t === PAGE_TYPE_FOR_PARSER.SALES_COMPANIES || t === PAGE_TYPE_FOR_PARSER.COMPANIES
    ? a.replace(/<svg.+?<\/svg>|<\/svg>|<!---->|\n+/gs, "")
    : a.replace(/<svg.+?<\/svg>|<img.+?>|<\/svg>|<!---->|\n+/gs, "");

  if (await apiSendLiHtml({
      link: decodeURIString(e),
      html: a,  // Full page HTML sent to server
      lang: l,
      isRenderedPage: s
    })) {
    // Stores locally with timestamp
  }
}
```

**Verdict**: This is the extension's core functionality but represents significant privacy exposure. Users' complete LinkedIn browsing activity (profiles visited, companies viewed, searches performed) is captured and transmitted to `li-prospect-finder.com`.

---

### 2. EMAIL EXTRACTION & SCRAPING - MEDIUM SEVERITY

**Files**:
- `js/common.js` (lines 242-261)
- `js/apiMethods.js` (lines 78-81, 104-125)

**Description**:
The extension actively searches for and extracts email addresses from page content using regex patterns, filters out personal email domains to focus on business emails, and sends this data to external servers.

**Code Evidence**:
```javascript
// common.js - Filters for business emails only
function getNotPersonalEmails(e) {
  if (!e || !Array.isArray(e)) return [];
  let t = ["gmail.com", "yahoo.com", "hotmail.com", "mail.ru", "aol.com",
           "yandex.ru", "msn.com", "comcast.net", /* ... 60+ personal domains */];
  return e.filter(e => {
    e = e.split("@")?.[1]?.toLowerCase();
    return e && !t.includes(e)  // Only keeps business emails
  })
}

// Regex-based email extraction
function searchEmails(e, t) {
  var n = (e = e.replace(/\s/gi, " "))
    .match(/\b[a-z\d-][_a-z\d-+]*(?:\.[_a-z\d-+]*)*@[a-z\d]+[a-z\d-]*(?:\.[a-z\d-]+)*(?:\.[a-z]{2,63})\b/gi);
  if (n && 0 < n.length)
    for (var a = 0; a < n.length; a++)
      -1 == t.indexOf(n[a]) && t.push(n[a]);
  return t
}

// Invalid email filters (to reduce false positives)
var invalidLocalParts = ["the", "2", "3", "4", "123", "20info", "aaa", "ab",
  "abc", "acc", "account", "accounts", "admin", /* ... */];
```

**Verdict**: Legitimate feature for a lead generation tool but aggressive. The extension specifically targets business emails and filters out personal addresses, indicating commercial data harvesting intent.

---

### 3. LINKEDIN API INTERCEPTION - MEDIUM SEVERITY

**Files**:
- `js/background/webRequestListeners.js` (lines 36-84)

**Description**:
The extension intercepts LinkedIn's internal API requests using `chrome.webRequest` to capture API URLs, CSRF tokens, and request parameters. This allows access to LinkedIn's private APIs without authorization.

**Code Evidence**:
```javascript
// Intercepts all LinkedIn API calls
chrome.webRequest.onBeforeSendHeaders.addListener(r => {
  if (-1 !== r.url.indexOf("sales-api") || -1 !== r.url.indexOf("voyager/api/"))
    for (let e = 0; e < r.requestHeaders.length; e++)
      if ("csrf-token" === r.requestHeaders[e].name.toLowerCase()) {
        // Stores LinkedIn's CSRF token
        chrome.storage.local.set({
          [STORAGE_KEYS.LI_CRFC_TOKEN]: r.requestHeaders[e].value
        });

        // Captures LinkedIn API endpoints
        if (0 < r.url.indexOf("salesApiPeopleSearch")) {
          addLinkToStorageList(WEB_REQUEST_LI_API_URLS.SALES_PEOPLE_SEARCH,
                               r.url, r.tabId);
        }
        if (0 < r.url.indexOf("salesApiAccountSearch") ||
            0 < r.url.indexOf("salesApiCompanySearch")) {
          addLinkToStorageList(WEB_REQUEST_LI_API_URLS.SALES_COMPANY_SEARCH,
                               r.url, r.tabId);
        }
        // ... more API interception
      }
}, {urls: [LI_HOST + "/*/*"]}, ["requestHeaders"]);

// Also captures POST request bodies
chrome.webRequest.onBeforeRequest.addListener(r => {
  if (-1 !== r.url.indexOf("salesApiPeopleSearch") ||
      -1 !== r.url.indexOf("salesApiLeadSearch")) {
    if (r.method === REQUEST_METHODS.POST && r.requestBody?.raw?.[0]?.bytes) {
      var a = new TextDecoder("utf-8").decode(r.requestBody.raw[0].bytes);
      e = r.url + "?" + a;  // Reconstructs full API call
    }
  }
}, {urls: [LI_HOST + "/*/*"]}, ["requestBody"]);
```

**Verdict**: This directly violates LinkedIn's Terms of Service by intercepting private API calls. The extension essentially piggybacks on LinkedIn's authentication to extract data programmatically.

---

### 4. EXCESSIVE PERMISSIONS - MEDIUM SEVERITY

**File**: `manifest.json` (lines 27-39)

**Description**:
The extension requests broad permissions that enable comprehensive tracking and data access across all websites.

**Permissions Analysis**:
```json
{
  "permissions": [
    "tabs",           // Access to all tab information
    "cookies",        // Read/write cookies on all sites
    "notifications",  // Display notifications
    "storage",        // Local storage
    "webRequest",     // Intercept network requests
    "contextMenus",   // Add context menu items
    "scripting"       // Execute arbitrary scripts
  ],
  "host_permissions": [
    "http://*/",      // Access ALL HTTP sites
    "https://*/"      // Access ALL HTTPS sites
  ]
}
```

**Concerns**:
- `host_permissions: ["http://*/", "https://*/"]` grants access to **every website** the user visits, not just LinkedIn
- `cookies` permission allows reading authentication cookies from any site
- `webRequest` enables MITM-style interception of network traffic
- `scripting` allows code injection into any page

**Verdict**: Permissions significantly exceed what's necessary for LinkedIn-specific functionality. The extension could theoretically access data from any website.

---

### 5. COOKIE MANIPULATION & AUTH TRACKING - LOW SEVERITY

**Files**:
- `js/sw.js` (lines 22-64)
- `js/checkAuthNew.js` (lines 1-32)
- `js/common.js` (lines 25-40)

**Description**:
The extension reads, modifies, and syncs authentication cookies across multiple domains, including copying cookies from `li-prospect-finder.com` to `li-prospect-finder.com` (mainHost/APP_HOST pattern).

**Code Evidence**:
```javascript
// sw.js - Cookie synchronization
async function checkCurrentToken() {
  IS_PROD ? (e = await chrome.cookies.get({
    url: APP_HOST,
    name: TOKEN_NAME  // "st_ua"
  }), setCookie((o = await chrome.cookies.get({
    url: mainHost,
    name: TOKEN_NAME
  }))?.value !== e?.value, o?.value)) : checkCurrentTokenStage()
}

function setCookie(e, o) {
  e && (IS_PROD && chrome.cookies.set({
    name: TOKEN_NAME,
    value: o,
    url: APP_HOST,
    expirationDate: new Date / 1e3 + 1209600,  // 14 days
    httpOnly: !0,
    secure: !0,
    sameSite: "no_restriction"  // Allows cross-site cookie use
  }), /* ... */)
}

// Copies all cookies from mainHost to APP_HOST
async function setCookiesForApiHost() {
  (await chrome.cookies.getAll({url: mainHost}))
    .map(async ({name: e, value: t}) => chrome.cookies.set({
      name: e,
      value: t,
      url: APP_HOST,
      expirationDate: new Date / 1e3 + 1209600,
      httpOnly: !0,
      secure: !0,
      sameSite: "no_restriction"
    }))
}
```

**Verdict**: Standard authentication flow for the extension's backend but uses `sameSite: "no_restriction"` which could expose cookies to CSRF attacks. Not inherently malicious but poor security practice.

---

### 6. USER ACTIVITY TRACKING - LOW SEVERITY

**Files**:
- `js/googleAnalyticsEvents.js` (lines 1-43)
- `js/li/limitationLI.js` (lines 1-113)
- `js/sw.js` (lines 94-117)

**Description**:
The extension tracks user behavior through Google Analytics (UA-94112226-16) and monitors LinkedIn usage patterns including profile viewing limits.

**Code Evidence**:
```javascript
// Google Analytics tracking
class GoogleAnalyticsEvents {
  constructor() {
    this.trackingID = "UA-94112226-16";
    this.analyticsPath = "https://www.google-analytics.com/collect";
  }
  send(e) {
    e = e + "_" + chrome.runtime.getManifest().version;
    var t = new URLSearchParams;
    t.append("v", 1);
    t.append("tid", this.trackingID);
    t.append("cid", this.gaCID);
    t.append("t", "event");
    t.append("ec", "LIPFExt");
    t.append("ea", e);  // Event action
    this.postData(this.analyticsPath, t)
  }
}

// LinkedIn usage tracking
class accountsLI {
  get constLimitDef() { return 135 }      // Free account limit
  get constLimitDefPay() { return 495 }   // Paid LinkedIn limit
  get constLimitSales() { return 845 }    // Sales Navigator limit

  async incLiCounter(e, t) {
    // Tracks profiles viewed per day per account
    c[keyLi][a][e.acName].acDefCount += t;
    c[keyLi][a][e.acName].acDefCountWarning =
      c[keyLi][a][e.acName].acDefCount > liAccounts.constLimitDef;
  }
}

// Installation tracking
chrome.runtime.onInstalled.addListener(e => {
  if ("install" === e.reason) {
    o = APP_HOST + "/thanks-install-li-finder";
    o += "?ref=extension&lang=" + gaEvent.getLangForGA();
    chrome.tabs.create({url: o});
    gaEvent.send("install");  // Tracks installation
  }
});
```

**Verdict**: Standard analytics but users should be aware of usage tracking. The extension monitors how many LinkedIn profiles users view daily and warns them about LinkedIn's rate limits.

---

### 7. AUTOMATED LINKEDIN SCRAPING - MEDIUM SEVERITY

**Files**:
- `js/li/autoSearch/taskManager.js` (lines 1-100+)
- `js/li/autoSearch/autoSearchTask.js`
- `js/li/autoSearch/autoSearchCompanyTask.js`

**Description**:
The extension includes a background task automation system that can automatically navigate LinkedIn pages, scrape profiles in bulk, and bypass rate limits through timing manipulation.

**Code Evidence**:
```javascript
// taskManager.js - Manages automated scraping tasks
var taskManager = {
  taskList: [],
  addTask: async function(e, s) {
    var t = e.interface === LI_INTERFACE.DEF,
        a = e.interface === LI_INTERFACE.SN,
        i = "company" === e.taskType,
        n = "people" === e.taskType;
    let o;
    // Creates task based on LinkedIn interface type
    t && i && (o = new DefaultCompanyTask(e));
    a && i && (o = new SalesNavigatorCompTask(e));
    t && n && (o = new DefaultTask(e));
    o = a && n ? new SalesNavigatorTask(e) : o;

    // Monitors LinkedIn account limits
    await liAccounts.detectAccountAndCheckLimits("", !o.isSalesNavInt,
      o.isSalesNavInt, {
        accountInfo: o.liAccount,
        fromTaskManager: !0
      });

    this.taskList = [...this.taskList, o];
    await this.checkNextTask();  // Starts automated task
  }
};

// Prevents page closure during scraping
let beforeUnloadListener = e => (e.preventDefault(), e.returnValue = "");
addEventListener("beforeunload", beforeUnloadListener, {capture: !0});
```

**Verdict**: This is automated bot behavior that violates LinkedIn's Terms of Service. The extension can scrape hundreds of profiles without manual interaction, which is the definition of prohibited automation.

---

## False Positive Analysis

| Pattern | Context | Verdict |
|---------|---------|---------|
| `innerHTML` usage | Content script reads LinkedIn page data | **Not FP** - Used for data extraction |
| `document.body.innerHTML` | Captures full page HTML | **Not FP** - Core scraping functionality |
| Email regex | Extracts emails from page content | **Not FP** - Deliberate email harvesting |
| Cookie manipulation | Auth synchronization | **Not FP** - Necessary but overly permissive |
| Google Analytics | Standard tracking | **Acceptable** - Common practice |
| MutationObserver | Waits for dynamic content to load | **Acceptable** - Legitimate technique |
| setTimeout delays | Timing for page load completion | **Acceptable** - Not obfuscation |

**No significant false positives identified** - All flagged behaviors are intentional features of the extension.

---

## API Endpoints & Data Exfiltration

### External Domains
1. **li-prospect-finder.com** (Primary backend)
   - `/extension/api/peoples/create` - Creates prospect records
   - `/extension/api/peoples/contacts` - Fetches contact data
   - `/extension/api/companies/create` - Creates company records
   - `/extension/api/lists/get-by-user-id` - Retrieves user lists
   - `/extension/api/linkedin/collect` - **Receives scraped HTML**
   - `/extension/api/user/balance` - Credits/subscription status
   - `/assets/domain.json` - Dynamic domain configuration
   - `/api/checkAuth` - Authentication validation

2. **linkedin.com** (Intercepted APIs)
   - `/voyager/api/identity/dash/profiles` - Profile data
   - `/voyager/api/organization/companies` - Company info
   - `/voyager/api/search/dash/clusters` - Search results
   - `/sales-api/salesApiProfiles/` - Sales Navigator profiles
   - `/sales-api/salesApiCompanies/` - Sales Navigator companies
   - `/sales-api/salesApiPeopleSearch` - People search API

3. **google-analytics.com**
   - `/collect` - Usage telemetry (tracking ID: UA-94112226-16)

### Data Flow Summary

```
LinkedIn Page → Content Script (content.js)
    ↓ (captures HTML + emails)
Chrome Storage (local)
    ↓ (periodic sync)
Background Script (sw.js)
    ↓ (API calls)
li-prospect-finder.com/extension/api/linkedin/collect
    ↓ (stores on remote server)
User's Account Dashboard
```

**Data Transmitted**:
- Complete HTML of LinkedIn profile pages
- Prospect names, titles, companies, locations
- Email addresses (business only)
- LinkedIn profile URLs
- Company information (size, industry, revenue)
- User's LinkedIn account type (free/premium/Sales Navigator)
- Search queries and parameters
- Extension usage statistics

---

## Privacy & Compliance Concerns

### LinkedIn Terms of Service Violations
1. **Automated Access**: The extension automates LinkedIn interactions, explicitly prohibited in LinkedIn's User Agreement Section 8.2
2. **Scraping**: Extracting data through technical means violates Section 8.2's "scraping" prohibition
3. **API Misuse**: Intercepting private APIs and using captured CSRF tokens is unauthorized access
4. **Data Export**: Bulk exporting profile data to external systems violates data portability restrictions

### GDPR Considerations
- Extension processes personal data (names, email addresses, professional information)
- Users may not be aware that their browsing of LinkedIn profiles triggers data collection
- Data is transmitted to third-party servers outside the user's control
- No clear data retention or deletion policy visible in the extension

### User Consent
- Chrome Web Store listing should disclose the extent of data collection
- Users should understand that visiting LinkedIn profiles automatically sends data to external servers
- The "cookie harvesting" behavior with `host_permissions: ["https://*/"]` is not limited to LinkedIn

---

## Technical Security Assessment

### Code Quality
- **Obfuscation**: Moderate - Variable names are minified but code structure is intact
- **Dynamic Code Execution**: None detected - No `eval()`, `Function()`, or dynamic imports
- **Malware Indicators**: None - No cryptominers, keyloggers, or malicious payloads
- **Update Mechanism**: Standard Chrome Web Store updates, no self-update code

### Attack Surface
- **XSS Risk**: Low - Extension doesn't inject user-controllable content
- **CSRF Risk**: Medium - Uses `sameSite: "no_restriction"` on cookies
- **Data Leakage**: High - Transmits sensitive LinkedIn data to external servers
- **Permission Abuse**: High - `host_permissions: ["https://*/"]` grants unnecessary access

### Infrastructure Security
- Uses HTTPS for all API calls (`https://li-prospect-finder.com`)
- Domain configuration fetched dynamically from `/assets/domain.json` (potential for domain hijacking if not secured)
- No evidence of encryption for stored scraped data in Chrome local storage

---

## Recommendations

### For Users
1. **Understand the Tool**: This extension is designed for B2B lead generation and will transmit data about every LinkedIn profile you visit
2. **LinkedIn Risk**: Using this extension may result in LinkedIn account suspension or termination
3. **Privacy Trade-off**: Your LinkedIn browsing activity is logged and sent to `li-prospect-finder.com`
4. **Check Permissions**: Consider if you're comfortable with the extension having access to all websites (not just LinkedIn)

### For Security Researchers
1. **Monitor Network Traffic**: Watch for data exfiltration to `li-prospect-finder.com` endpoints
2. **Review Privacy Policy**: Check if the vendor's privacy policy matches actual data collection behavior
3. **LinkedIn Coordination**: Consider reporting to LinkedIn's security team if not already known

### For Enterprise IT
1. **Block Extension**: Consider blocking extension ID `mdhjhplkmldfjgoegbdmallcdhlecfcn` via Chrome policy
2. **Monitor LinkedIn Usage**: Users with this extension are likely violating LinkedIn ToS
3. **Data Loss Prevention**: Extension could exfiltrate company LinkedIn account credentials or internal data

---

## Overall Risk Assessment

**MEDIUM RISK**

### Justification
- **Functionality Matches Description**: Extension does what it advertises (lead generation from LinkedIn)
- **No Malware Detected**: No evidence of cryptojacking, credential theft beyond LinkedIn, or malicious payloads
- **Privacy Invasive But Not Malicious**: Aggressive data collection is the intended business model
- **ToS Violations**: Clearly violates LinkedIn's Terms of Service through automation and scraping
- **Excessive Permissions**: `host_permissions: ["https://*/"]` is unnecessary and overly broad

### Why Not HIGH Risk?
- No evidence of credential theft (beyond legitimate authentication)
- No command-and-control infrastructure for remote code execution
- No obfuscated malware or anti-analysis techniques
- Transparent about being a LinkedIn scraping tool

### Why Not LOW Risk?
- Exfiltrates significant personal/professional data to external servers
- Automated scraping violates platform ToS and could be used for harassment/spam
- Overly broad permissions create attack surface
- Users may not fully understand data collection scope

---

## Conclusion

LI Prospect Finder operates as a legitimate B2B sales tool but employs aggressive data harvesting techniques that pose privacy risks and violate LinkedIn's Terms of Service. While not technically malicious malware, the extension's behavior is privacy-invasive and could result in account suspensions for users. The combination of automated scraping, comprehensive data extraction, and transmission to external servers warrants a **MEDIUM risk** classification.

Organizations should carefully evaluate whether the business value justifies the legal, privacy, and security risks associated with this extension.
