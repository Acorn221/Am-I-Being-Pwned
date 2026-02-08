# BigSeller Product Scraper - Security Analysis Report

**Extension ID:** `kkfocohhekldeddhkllgofalggnlhhae`
**Version:** 3.44.2
**Package Name:** `bs-crawl`
**Manifest Version:** 3
**Developer:** BigSeller / Meiyunji (meiyunji.net)
**Analysis Date:** 2026-02-06

---

## Executive Summary

BigSeller is a **legitimate commercial e-commerce product scraping tool** designed to help sellers copy product listings from competitor marketplaces into their BigSeller multi-store management platform. It targets 20+ Southeast Asian and Chinese e-commerce platforms including Shopee, Lazada, TikTok Shop, Tokopedia, Taobao, 1688, AliExpress, and Facebook Marketplace.

The extension is **not malware**. However, it employs several aggressive techniques that raise privacy and security concerns for users who install it:

1. **XHR/Fetch monkey-patching** to intercept all API responses on marketplace pages
2. **Shopee anti-fraud header interception** via `webRequest.onBeforeSendHeaders`
3. **Full window object enumeration** on every page navigation
4. **Overly broad host_permissions** (`http://*/*`, `https://*/*`)
5. **Hardcoded Amplitude API key** and analytics endpoint exposed
6. **Internal development IPs** left in production manifest
7. **Bulk product data exfiltration** to BigSeller servers with user session binding

The high triage flag count (45 T1, 22 T2, 67 V1, 13 V2) is primarily due to the extension's legitimate-but-aggressive scraping architecture being replicated across 20+ platform modules, each containing copies of the same XHR hooking, innerHTML rendering, cookie access, and script injection patterns.

**Overall Risk Assessment: MEDIUM**

The extension is a legitimate commercial tool, not covert malware. However, its broad permissions, aggressive API hooking, and data collection practices present real privacy risks, particularly for sellers who may not understand the scope of data being captured and forwarded.

---

## Targeted Platforms

| Platform | Region | Content Script |
|----------|--------|----------------|
| Shopee (seller.shopee.*) | MY, PH, SG, VN, ID, TH, CN, TW | `platform/shopee/index.js`, `flashSale/index.js` |
| Lazada (*.lazada.*) | MY, SG, VN, ID, TH, PH | `platform/lazada/index.js` |
| TikTok Shop | SG, VN, TH, PH, MY, UK | `platform/tiktok/index.js` |
| Tokopedia | ID | `platform/tokopedia/index.js` |
| Taobao | CN | `platform/taobao/index.js` |
| Tmall | CN, HK | `platform/tmall/index.js` |
| 1688 | CN | `platform/ali1688/index.js` |
| AliExpress | Global | `platform/aliexpress/index.js` |
| JD Thailand | TH | `platform/jdth/index.js` |
| JD Indonesia | ID | `platform/jdid/index.js` |
| Pinduoduo | CN | `platform/pinduoduo/index.js` |
| Facebook Marketplace | Global | `platform/facebook/index.js` |
| Line Shop | TH, TW | `platform/lineshop/index.js` |
| Bukalapak | ID | `platform/bukalapak/index.js` |
| Blibli | ID | `platform/blibli/index.js` |
| Tiki | VN | `platform/tiki/index.js` |
| Sendo | VN | `platform/sendo/index.js` |
| Jakmall | ID | `platform/jakmall/index.js` |
| Evermos | ID | `platform/evermos/index.js` |
| Ocistok | ID | `platform/ocistok/index.js` |
| Sabomall | ID | `platform/sabomall/index.js` |
| JakartaNotebook | ID | `platform/jakartanotebook/index.js` |
| Tuyou B2B | CN | `platform/tuyoub2b/index.js` |

---

## Vulnerability Analysis

### VULN-01: XHR/Fetch Monkey-Patching (Response Interception)

**Severity:** MEDIUM (CVSS 5.3 - AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
**File:** `platform/_inject/requestHooks.js:2234-2366`
**Also in:** `platform/intercept/index.js:1849-1873`

**Description:** The extension replaces `window.XMLHttpRequest` with a proxy class that intercepts all XHR responses on targeted marketplace pages. It also wraps `window.fetch` to intercept Shopee API responses. Intercepted data is stored in `localStorage` and `sessionStorage` keyed by platform name.

**Intercepted API endpoints:**
- Shopee: `api/v4/item/get`, `api/v4/pdp/get_pc`, `api/v4/pdp/get_rw`, `cart_panel/select_variation_pc`
- Lazada: `acs-m.lazada.*/h5/mtop.global.detail.web.getdetailinfo/1.0/`
- Facebook: `/api/graphql` (MarketplaceMiniShopProductDetailsPage)
- Pinduoduo: `oak/integration/render`
- JD Thailand: `api.jd.co.th/client.action` (wareIntroView, wareGuigView)
- JD Indonesia: `color.jd.id/soa_h5/id_wareBusiness.style`
- 1688: `h5api.m.1688.com/h5/mtop.alibaba.alisite.cbu.server.moduleasyncservice`
- Line Shop: `sc-oms-api.line-apps.com/api/v1/shopend`, `ect-mall-api.line-apps.com/graph`, `promotion-api.line-apps.com/graph`
- AliExpress: `mtop.aliexpress.pdp.pc.query`

**PoC Scenario:** A user browsing any targeted marketplace will have ALL XHR/fetch responses passing through the extension's interceptor, even when not actively scraping. The intercepted product detail responses are gzip-compressed and stored in localStorage, then forwarded to BigSeller servers when a scrape action is triggered.

**Evidence:**
```javascript
// requestHooks.js:2234 - XHR prototype replacement
var n = (e = e || window).XMLHttpRequest,
  ...
return (a.prototype = n.prototype).constructor = a, e.XMLHttpRequest = a

// intercept/index.js:1849 - Fetch wrapper for Shopee
var t = fetch;
window.fetch = e(a().mark(function e() {
  // intercepts api/v4/pdp/get_pc and api/v4/pdp/get_rw responses
}))
```

---

### VULN-02: Shopee Anti-Fraud Header Interception

**Severity:** MEDIUM (CVSS 5.0 - AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
**File:** `background.js:198-214`

**Description:** The background service worker uses `chrome.webRequest.onBeforeSendHeaders` to intercept the `af-ac-enc-dat` header from Shopee API requests (`api/v4/item/get`, `api/v4/search/search_items`). This header is Shopee's anti-fraud/anti-bot encryption token. The extension captures it and forwards it to content scripts via `chrome.tabs.sendMessage`.

**Impact:** This bypasses Shopee's bot detection mechanism, allowing the extension to make authenticated API calls that would otherwise be blocked. This could facilitate unauthorized bulk scraping of product data at scale.

**Evidence:**
```javascript
// background.js:198-214
chrome.webRequest.onBeforeSendHeaders.addListener(function(e) {
  if ((-1 !== e.url.indexOf("shopee") || -1 !== e.url.indexOf("xiapibuy")) && ...)
    for (var t = 0; t < e.requestHeaders.length; t++) {
      if ("af-ac-enc-dat" === a) {
        chrome.tabs.sendMessage(e.tabId, {
          platform: "shopee",
          shopeeHeaders: !0,
          "af-ac-enc-dat": r
        });
```

---

### VULN-03: Window Object Global Enumeration

**Severity:** LOW (CVSS 3.1 - AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `platform/_inject/onPageChange.js:11-25`

**Description:** On every page load across all targeted platforms, the extension enumerates ALL keys on the `window` object, serializes every plain object found, and includes this data in `postMessage` events sent on URL changes (polled every 500ms).

**Impact:** This captures any global state the marketplace application stores on `window`, which could include user session data, authentication tokens, CSRF tokens, cart contents, or internal application state. The data is sent via `window.postMessage("*")` which any frame or injected script could intercept.

**Evidence:**
```javascript
// onPageChange.js:11-25
var o = Object.keys(window),
    i = {};
o.forEach(function(t) {
  if (e = window[t], "[object Object]" === n.call(e)) try {
    i[t] = JSON.parse(JSON.stringify(window[t]))
  } catch (n) { i[t] = null }
}), e = setInterval(function() {
  t !== location.href && (t = location.href) && window.postMessage({
    from: "onPageChange",
    pageChange: !0,
    url: t,
    topWindow: i  // <-- all window globals serialized
  }, "*")
}, 500)
```

---

### VULN-04: Product Data Exfiltration to BigSeller Servers

**Severity:** MEDIUM (CVSS 4.3 - AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
**File:** `platform/shopee/index.js:6369-6389` (representative example, pattern repeats in all 20+ platform scripts)

**Description:** When the user clicks "Scrape to BigSeller", the extension sends the full intercepted product JSON data (prices, descriptions, images, stock levels, seller info, variation details) to `https://www.bigseller.com/api/v1/product/crawl/{platform}/clientCrawl.json`. The request includes:
- `uid` - BigSeller user PUID (obtained from login check)
- `url` - source product URL
- `platform` - marketplace identifier
- `jsonData` - full JSON-stringified product data including stock information
- `isOpenSkip` - user preference stored in chrome.storage

The request uses `credentials: "include"` which attaches the user's BigSeller session cookies, and falls back between `bigseller.com` and `bigseller.pro` domains.

**Evidence:**
```javascript
// shopee/index.js:6369-6389
xi(r = {
  uid: o,         // BigSeller user ID
  url: a,         // Source product URL
  type: 1,
  isOpenSkip: s,
  platform: c,    // "shopee"
  jsonData: l     // Full product JSON including stockInfoData
}, { tryStartTimes: 0, timeOut: 6e4 })
```

---

### VULN-05: Overly Broad Host Permissions

**Severity:** LOW-MEDIUM (CVSS 3.7 - AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `manifest.json:465-468`

**Description:** The extension requests `http://*/*` and `https://*/*` host permissions, granting it access to make cross-origin requests to ANY website. While the content scripts are limited to specific marketplace URLs, the background service worker's `proxyRequest` action can make arbitrary HTTP requests to any URL on behalf of content scripts.

**Evidence:**
```json
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

The background script's proxy handler:
```javascript
// background.js:180-185
else if ("proxyRequest" === e.action) {
  var o = e.type, i = e.data;
  t[o](i).then(function(e) { r(e) })
}
```

This allows content scripts to make arbitrary GET/POST/FormData requests to any URL, bypassing CORS restrictions, with the extension's full credential context.

---

### VULN-06: Hardcoded Amplitude API Key

**Severity:** LOW (CVSS 2.4 - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**File:** `platform/shopee/index.js:6126-6128` (and all other platform scripts)

**Description:** The extension embeds an Amplitude analytics API key in plaintext across all platform content scripts, sending telemetry to a custom endpoint.

**Exposed Credentials:**
- **Amplitude API Key:** `yosu7anwociqipifcb7at9cy8nxze9ct`
- **Events Server:** `https://events.sellfox.com/events`
- **Plugin Namespace:** `@meiyunji/plugin-default-page-view-event-enrichment-browser`

**Evidence:**
```javascript
// shopee/index.js:6126-6128
(0, qo.init)("yosu7anwociqipifcb7at9cy8nxze9ct", "", "", {
  serverUrl: "https://events.sellfox.com/events"
});
```

**Impact:** The API key is a write-only analytics key (standard for client-side Amplitude), so direct exploitation is limited. However, it reveals the analytics infrastructure and could be used to inject false telemetry events. The `sellfox.com` domain is a related BigSeller/Meiyunji property.

---

### VULN-07: Internal Development IPs in Production Manifest

**Severity:** INFORMATIONAL (CVSS 0.0)
**File:** `manifest.json:117-118`

**Description:** The manifest contains content script match patterns for internal development servers:
```json
"http://192.168.0.119:8000/*",
"http://192.168.0.119:9000/*"
```

**Impact:** No direct security impact, but indicates the extension is deployed without stripping development artifacts. If a user happened to be on the same network segment, the extension's content scripts would run on the development server.

---

### VULN-08: Tmall/Taobao Anti-Bot Bypass

**Severity:** LOW (CVSS 2.6 - AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N)
**File:** `background.js:220-226`

**Description:** The extension monitors Tmall/Taobao anti-bot challenge URLs (`_____tmd_____/punish`, `slide`, `newslidevalidate`) via `webRequest.onResponseStarted` and sends messages to hide the verification modal, effectively attempting to suppress bot-detection CAPTCHAs.

**Evidence:**
```javascript
// background.js:220-226
chrome.webRequest.onResponseStarted.addListener(function(e) {
  -1 === e.url.indexOf("slide?") && -1 === e.url.indexOf("newslidevalidate?") ||
    chrome.tabs.sendMessage(e.tabId, { tmallHideModal: !0 }, function(e) {})
}, {
  urls: ["https://item.taobao.com:443//item.htm/_____tmd_____/punish*", ...]
})
```

---

### VULN-09: postMessage to Wildcard Origin

**Severity:** LOW (CVSS 2.4 - AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
**File:** `platform/_inject/onPageChange.js:21-26`, `platform/_inject/requestHooks.js:2456-2474`

**Description:** Multiple injected scripts use `window.postMessage(data, "*")` to communicate between the page-world injected scripts and the content scripts. Using `"*"` as the target origin means any other extension or injected script on the same page can intercept this data.

**Data exposed via postMessage:**
- Full serialized window globals (`topWindow` object)
- Lazada product detail API responses
- JD Thailand/Indonesia product descriptions
- Shopee variation stock data

---

## False Positive Analysis

| Triage Flag | Count | Verdict | Explanation |
|-------------|-------|---------|-------------|
| `beacon_exfil` | ~6 | **FALSE POSITIVE** | `navigator.sendBeacon` references are inside the bundled **Amplitude analytics SDK** (v2.10.0) used for product usage telemetry. The sendBeacon is a standard transport option for the analytics library, not custom data exfiltration. Found in ali1688, jdid, and other platform scripts at identical code patterns. |
| `cookie_access` | ~30 | **MOSTLY FALSE POSITIVE** | The majority of `document.cookie` access is inside the bundled **Amplitude SDK** cookie storage layer for maintaining analytics session state (`AMP_*` cookies). A small number are legitimate platform-specific cookie reads (e.g., reading JD Indonesia session cookies for API calls). No evidence of wholesale cookie theft or exfiltration to third parties. |
| `fetch_hook` | ~8 | **TRUE POSITIVE** | The extension genuinely replaces `window.fetch` on Shopee pages (`platform/intercept/index.js:1849-1873`) to intercept product detail API responses (`api/v4/pdp/get_pc`, `api/v4/pdp/get_rw`). This is core scraping functionality, not a library artifact. |
| `script_injection` | ~8 | **TRUE POSITIVE (benign intent)** | Content scripts inject page-world scripts via `document.createElement("script")` with `chrome.runtime.getURL()` sources: `platform/intercept/index.js`, `platform/_inject/onPageChange.js`, `platform/_inject/requestHooks.js`. These are first-party extension resources, not remote scripts. Purpose is to run XHR hooks in the page context. |
| `innerhtml_dynamic` | ~67 | **FALSE POSITIVE** | The vast majority are the extension's own UI rendering: notification popups, scrape buttons, modal dialogs, status indicators. All use template literals with sanitized i18n strings. The jQuery `$.html()` calls in platform scripts render the "Scrape to BigSeller" button overlay. No user-controlled input flows into innerHTML. |
| `jquery_html_dynamic` | ~20 | **FALSE POSITIVE** | jQuery `.html()` calls for rendering the extension's in-page UI (scrape buttons, notification modals). Content comes from i18n translation strings and static templates, not from external or user input. |
| `webRequest` | 2 | **TRUE POSITIVE** | `chrome.webRequest.onBeforeSendHeaders` intercepts Shopee `af-ac-enc-dat` headers (VULN-02). `chrome.webRequest.onResponseStarted` monitors Taobao/Tmall anti-bot challenges (VULN-08). Both are genuine and documented above. |

---

## Data Flow Summary

```
User visits marketplace page (e.g., Shopee product page)
    |
    v
Content script injects page-world scripts:
  - requestHooks.js (XHR/fetch interception)
  - onPageChange.js (URL monitoring + window enumeration)
  - intercept/index.js or intercept/aliexpress.js (platform-specific fetch hooks)
    |
    v
Intercepted API responses stored in:
  - localStorage: "{platform}-api-data" (gzip-compressed, base64-encoded)
  - sessionStorage: platform-specific keys
  - IndexedDB: "BS_DB" (Facebook product cache)
    |
    v
User clicks "Scrape to BigSeller" button (injected into page)
    |
    v
Content script checks BigSeller login status:
  POST https://www.bigseller.com/api/v1/user/getUserAccount.json
  (falls back to bigseller.pro)
    |
    v
Product data sent to BigSeller:
  POST https://www.bigseller.com/api/v1/product/crawl/{platform}/clientCrawl.json
  Body: { uid, url, platform, jsonData, type, isOpenSkip }
    |
    v
Analytics event sent:
  POST https://events.sellfox.com/events
  (Amplitude SDK with key yosu7anwociqipifcb7at9cy8nxze9ct)
```

---

## Key Observations

### What This Extension IS:
- A legitimate commercial product scraping tool for the BigSeller e-commerce management platform
- Designed for cross-border sellers managing stores on multiple SE Asian marketplaces
- User-initiated scraping (requires clicking a button, plus BigSeller login)
- Data flows to the user's own BigSeller account
- Chinese company (Meiyunji/BigSeller) targeting SEA market

### What This Extension IS NOT:
- NOT covert malware or spyware
- NOT stealing session tokens to take over accounts
- NOT scraping without user action (background passive collection is limited to API response caching)
- NOT sending data to unknown C2 servers (only bigseller.com/bigseller.pro)
- NOT enumerating or disabling other extensions
- NOT injecting ads or modifying page content beyond its own UI

### Privacy Concerns:
1. The XHR/fetch hooks run continuously on marketplace pages even when the user is not actively scraping, silently caching all product API responses
2. The `onPageChange.js` window enumeration captures ALL global JavaScript objects, which could include sensitive application state
3. The `host_permissions: ["http://*/*", "https://*/*"]` is far broader than necessary
4. The `proxyRequest` background handler can make arbitrary cross-origin requests
5. The Shopee `af-ac-enc-dat` header capture could be used for automated scraping beyond what the user explicitly initiates

---

## Overall Risk Assessment

**MEDIUM**

BigSeller is a legitimate commercial tool, not malware. The SUSPECT classification from the triage was triggered by genuinely aggressive techniques (XHR hooking, fetch patching, webRequest header interception) that are core to its product scraping functionality. However, the overly broad permissions, continuous background API interception, window global enumeration, and anti-bot bypass capabilities present real privacy and security concerns that users should be aware of.

The high flag count (147 total) is primarily explained by the same code patterns being duplicated across 20+ platform-specific content scripts, each containing copies of the shared scraping infrastructure (Amplitude analytics, notification UI, clientCrawl submission, i18n rendering).

---

## Recommendations

1. **Reduce host_permissions** to only the specific marketplace domains actually targeted
2. **Remove internal development IPs** from the production manifest
3. **Restrict XHR/fetch hooks** to only activate when the user initiates a scrape action, rather than running continuously
4. **Use specific targetOrigin** in `postMessage` calls instead of `"*"`
5. **Remove window global enumeration** from `onPageChange.js` or restrict to known-safe keys
6. **Scope the proxyRequest handler** to validate destination URLs against an allowlist
