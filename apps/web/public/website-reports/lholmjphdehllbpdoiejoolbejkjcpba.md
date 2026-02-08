# Vulnerability Report: Shopee Fans - Shopee Seller Assistant

## Extension Metadata
- **Extension ID**: lholmjphdehllbpdoiejoolbejkjcpba
- **Extension Name**: Shopee Fans - Shopee Seller Assistant
- **Version**: 8.7.5
- **User Count**: ~40,000
- **Developer**: shopeefans.com / keyouyun.com
- **Manifest Version**: 3

## Executive Summary

Shopee Fans is a seller assistant tool for Shopee marketplace that implements **HTTP request/response interception** on e-commerce platforms including Shopee, Amazon, AliExpress, 1688, Taobao, Tmall, Lazada, Pinduoduo, and TikTok Shop. The extension intercepts all XMLHttpRequest and Fetch API calls on these platforms and forwards the intercepted data via `window.postMessage`, which could potentially expose sensitive seller/buyer data including authentication tokens, product information, pricing data, and order details.

While the extension appears to serve its stated purpose of providing seller analytics and automation, the aggressive request interception combined with extremely broad permissions creates a **HIGH security risk** - not due to clear malicious intent, but due to the significant attack surface and potential for misuse.

## Risk Assessment: **HIGH**

### Key Risk Factors:
1. **XHR/Fetch hooking** intercepts ALL network traffic on major e-commerce platforms
2. **All URLs** host permission enables interception across entire web
3. **Cookies permission** combined with traffic interception could expose session tokens
4. **Intercepted data** includes API responses that may contain sensitive business/customer data
5. **Multiple third-party domains** (keyouyun.com services) receive extension data
6. **CSP removal** on Pinduoduo weakens security boundaries

---

## Vulnerability Details

### 1. XHR/Fetch Request Interception
**Severity**: HIGH
**Files**:
- `/js/hookRequest.js` (2700 lines)
- `/js/content-pre.js` (injected at document_start)

**Details**:

The extension injects `hookRequest.js` into Shopee and other e-commerce pages at `document_start`, which hooks both `XMLHttpRequest` and `fetch()` APIs before page scripts execute:

```javascript
// content-pre.js - Injection logic
/shopee|xiapibuy/.test(window.location.hostname) && u("js/hookRequest.js")

// hookRequest.js - Hooking implementation
window.XMLHttpRequest = function(e) {
  var n = new OriginalXMLHttpRequest(e);
  // ... intercepts open(), send(), and load events
  n.addEventListener("load", (function() {
    // Captures response data
    var e = n.response;
    if ("string" === typeof e && "{" === e[0]) {
      e = JSON.parse(e);
    }
    onResponseSeen({
      api: "XMLHttpRequest",
      method: method,
      url: url,
      body: requestBody,
      status: n.status,
      response: e  // ← Response data captured
    })
  }))
}

// Fetch hooking
e.fetch = function(t, u) {
  // ... intercepts and clones response
  .then((function(t) {
    return t.json().catch((function() {
      return t.text()
    })).then((function(t) {
      onResponseSeen({
        api: "fetch",
        method: method,
        url: url,
        body: requestBody,
        response: t  // ← Response data captured
      })
    }))
  }))
}
```

**Intercepted Data Transmission**:
```javascript
// hookRequest.js - Data forwarded via postMessage
r((function(t) {
  window.postMessage({
    type: "ORIGINAL_PAGE",
    data: t,
    instruct: "onRequest"
  })
}))

n((function(t) {
  window.postMessage({
    type: "ORIGINAL_PAGE",
    data: t,
    instruct: "onResponse"  // ← ALL responses forwarded
  })
}))
```

**Risk**: This interception captures ALL network traffic on Shopee, Amazon, AliExpress, 1688, Taobao, Tmall, Lazada, Pinduoduo, TikTok Shop, and other e-commerce platforms. This includes:
- Authentication tokens and session IDs
- Product pricing and inventory data
- Customer order information
- Seller business metrics
- API keys and access tokens
- Payment-related data (if transmitted via XHR/fetch)

**Verdict**: The interception itself is not inherently malicious (likely needed for the extension's analytics features), but the scope is extremely broad and creates significant privacy/security exposure.

---

### 2. Overly Broad Permissions
**Severity**: HIGH
**File**: `/manifest.json`

**Permissions Granted**:
```json
{
  "permissions": [
    "declarativeNetRequest",
    "downloads",
    "notifications",
    "storage",
    "cookies",           // ← Can read all cookies
    "webNavigation",
    "contextMenus",
    "alarms"
  ],
  "host_permissions": [
    "<all_urls>"         // ← Access to ALL websites
  ]
}
```

**Risk**: The combination of:
- `<all_urls>` host permission
- `cookies` permission
- XHR/fetch interception

Creates a scenario where the extension could theoretically:
1. Intercept authentication requests/responses on any site
2. Extract session cookies via `chrome.cookies` API
3. Correlate traffic across different e-commerce platforms
4. Build comprehensive user browsing/shopping profiles

**Verdict**: While the extension only injects content scripts into specific e-commerce platforms (not all URLs), the `<all_urls>` permission is excessive for its stated purpose.

---

### 3. Content Security Policy Manipulation
**Severity**: MEDIUM
**File**: `/rules.json`

**Details**:

The extension uses `declarativeNetRequest` to remove CSP headers on Pinduoduo:

```json
{
  "id": 9,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {
        "header": "content-security-policy",
        "operation": "remove"
      },
      {
        "header": "content-security-policy-report-only",
        "operation": "remove"
      }
    ]
  },
  "condition": {
    "regexFilter": "pinduoduo.com"
  }
}
```

Additionally removes `x-frame-options` on Amazon domains:
```json
{
  "id": 8,
  "action": {
    "type": "modifyHeaders",
    "responseHeaders": [
      {
        "header": "x-frame-options",
        "operation": "remove"
      }
    ]
  },
  "condition": {
    "regexFilter": "www.amazon"
  }
}
```

**Risk**: Removing CSP weakens the security boundary between extension code and page scripts, potentially enabling:
- Extension scripts to execute code that would normally be blocked
- Easier injection of third-party content
- Reduced protection against malicious code execution

**Verdict**: Likely done to enable extension functionality (e.g., embedding Pinduoduo pages in iframes), but weakens overall security posture.

---

### 4. Multiple Third-Party Backend Services
**Severity**: MEDIUM
**Files**: `/js/background.js`, `/js/content-script.js`

**External Domains Contacted**:

```
https://wapi.shopeefans.com                    (Main API endpoint)
https://www.shopeefans.com                     (Website)
https://shopeefans.tikotu.com                  (Unknown subdomain)
https://api.keyouyun.com                       (Partner service)
https://erp.keyouyun.com                       (ERP system)
https://erp2.keyouyun.com                      (ERP system v2)
https://cdn1.keyouyun.com                      (CDN)
https://test.api.keyouyun.com                  (Test API)
https://pre.api.keyouyun.com                   (Pre-prod API)
```

**API Endpoints Used**:
```
/data-analysis/bussinessman/categoryDetail/
/data-analysis/bussinessman/goodsDetail/
/data-analysis/bussinessman/goods/hot
/data-analysis/bussinessman/shopDetail/
/data-analysis/bussinessman/shop/hot
/data-analysis/ciba/flowWord/searchFlowWord
/data-analysis/ciba/searchWord/recommend
/data-analysis/recharge/order/fansAt
/data-analysis/recharge/order/ratingsAt
/data-api/auth/login
```

**Risk**: The extension sends user/seller data to multiple backend services operated by shopeefans.com and keyouyun.com. Given the broad interception capabilities, this data could include:
- Shopee seller account information
- Product analytics and competitive intelligence
- User behavior patterns
- Potentially intercepted API responses from Shopee/Amazon/etc.

**Verdict**: The extension appears to be a legitimate SaaS tool that requires backend analytics, but users should understand their seller data is being transmitted to third-party servers.

---

### 5. Header Manipulation for API Access
**Severity**: LOW
**File**: `/rules.json`

**Details**:

The extension modifies `Referer` and `Origin` headers to bypass CORS restrictions on various Chinese e-commerce APIs:

```json
{
  "id": 2,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [
      {
        "header": "Referer",
        "operation": "set",
        "value": "https://s.1688.com/"
      },
      {
        "header": "Origin",
        "operation": "set",
        "value": "https://s.1688.com/"
      }
    ]
  },
  "condition": {
    "urlFilter": "h5api.m.1688.com/h5/mtop.1688.shop.data.get/1.0/^*pluginReq=true|"
  }
}
```

Similar rules exist for:
- Baidu Translate API
- 1688.com shop data API
- Pinduoduo API
- Taobao product/video APIs
- Tmall product APIs

**Risk**: While this enables the extension to fetch product data from these platforms, it bypasses CORS protections designed to prevent unauthorized API access. This could potentially:
- Violate terms of service of these platforms
- Enable scraping of data not intended for third-party use
- Expose extension to liability if platforms detect header spoofing

**Verdict**: Common practice for browser extensions, but users should be aware the extension is accessing APIs in ways not intended by platform operators.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `new Function()` | `/js/background.js` (8 instances) | Webpack/build tool artifacts, not dynamic code execution |
| Large compiled bundles | All JS files | Vue.js SPA with webpack bundling - creates very long lines but not obfuscation |
| `localStorage`, `sessionStorage` access | `/js/content-script.js` | Legitimate extension storage for user preferences and cached data |
| `document.cookie` access | `/js/content-script.js` | Likely reading Shopee session cookies to make authenticated API calls on user's behalf |
| `chrome.storage` calls | Multiple files | Standard extension storage API usage |

---

## API Endpoints Table

| Domain | Endpoint | Purpose | Data Sent |
|--------|----------|---------|-----------|
| wapi.shopeefans.com | (Various) | Main API backend | Seller analytics data |
| www.shopeefans.com | /data-api/auth/login | User authentication | Login credentials |
| www.shopeefans.com | /data-analysis/bussinessman/* | Business analytics | Product/shop metrics |
| www.shopeefans.com | /data-analysis/ciba/* | Keyword research | Search term data |
| www.shopeefans.com | /data-analysis/recharge/order/* | Subscription/billing | Payment-related data |
| erp.keyouyun.com | /recharge/order | ERP integration | Order management data |
| api.keyouyun.com | (Various) | Partner API | Unknown |
| Shopee APIs | (Intercepted) | Via XHR hooks | ALL Shopee API traffic |
| Amazon APIs | (Intercepted) | Via XHR hooks | ALL Amazon API traffic |
| 1688/Taobao/Tmall APIs | (Intercepted) | Via XHR hooks | ALL API traffic on these platforms |

---

## Data Flow Summary

1. **User browses Shopee/Amazon/other e-commerce sites**
2. **content-pre.js** injected at `document_start`
3. **hookRequest.js** loaded into page context, hooks `XMLHttpRequest` and `fetch()`
4. **All network requests/responses** intercepted and forwarded via `window.postMessage`
5. **content-script.js** receives postMessage data
6. **Processed data sent** to shopeefans.com/keyouyun.com backends via `chrome.runtime.sendMessage` → background.js
7. **Backend services** store/analyze seller data for analytics dashboard

**Critical Flow**:
```
Page XHR/Fetch → hookRequest.js intercept → window.postMessage
  → content-script.js → chrome.runtime.sendMessage
  → background.js → POST to wapi.shopeefans.com
```

---

## Overall Risk Assessment: **HIGH**

### Reasoning:

This extension is **NOT clearly malicious** - it appears to be a legitimate SaaS tool for Shopee sellers providing:
- Product analytics
- Competitor monitoring
- Keyword research
- Automated follow/rating features
- Multi-currency conversion
- Bulk messaging

**However, it warrants a HIGH risk rating because:**

1. **Aggressive Traffic Interception**: The XHR/fetch hooking captures ALL network traffic on 10+ major e-commerce platforms, including potentially sensitive data like auth tokens, customer info, and business metrics.

2. **Broad Permission Scope**: `<all_urls>` + `cookies` + traffic interception creates an extremely powerful data collection capability that goes beyond what most users would expect from a "seller assistant" tool.

3. **Third-Party Data Transmission**: Intercepted data flows to external services (shopeefans.com, keyouyun.com) with unclear data retention/usage policies.

4. **Security Weakening**: CSP removal on Pinduoduo and X-Frame-Options removal on Amazon reduce security protections.

5. **Lack of Transparency**: The extension description doesn't clearly inform users about the extent of traffic interception or data transmission to third-party servers.

### Not Marked as CRITICAL Because:

- No evidence of credential theft/exfiltration
- No keylogging or clipboard monitoring
- No extension enumeration/killing behavior
- No residential proxy infrastructure
- No remote code execution or kill switches
- The functionality appears aligned with stated purpose (seller tools)
- Uses standard Vue.js framework without heavy obfuscation

### Recommendation:

**Users should be aware** that installing this extension grants it access to:
- ALL their browsing traffic on major e-commerce platforms
- Their Shopee/Amazon/etc. cookies and session tokens
- All API requests/responses including business-sensitive data
- The ability to send this data to shopeefans.com/keyouyun.com servers

For sellers who trust shopeefans.com and need the analytics features, this may be acceptable. However, the extension creates significant privacy/security exposure and users should evaluate whether the benefits outweigh the risks.

---

## Mitigation Recommendations

For the extension developer:
1. Reduce `host_permissions` from `<all_urls>` to specific domains where features are needed
2. Add clear privacy policy explaining what data is intercepted and transmitted
3. Implement client-side data filtering to only capture necessary API responses
4. Consider using less invasive methods (e.g., content script scraping vs. XHR interception)
5. Remove CSP modification rules or clearly document why they're required

For users:
1. Only install if you trust shopeefans.com with your seller data
2. Understand ALL your e-commerce traffic is being monitored
3. Consider using in a separate browser profile for Shopee selling only
4. Review extension's network activity periodically
5. Be aware session tokens could theoretically be accessed by the extension
