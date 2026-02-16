# Vulnerability Report: Adminer - Capturar anúncios e produtos grátis

## Metadata
- **Extension ID**: amolhiihcpdbkjimhlffamgieibhfapi
- **Extension Name**: Adminer - Capturar anúncios e produtos grátis
- **Version**: 10.5
- **Users**: ~60,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Adminer is a Portuguese-language extension marketed as a tool to "capture ads and free products" on Facebook. While the extension's stated purpose is to help users identify and save Facebook advertisements (likely for dropshipping/e-commerce research), it employs aggressive techniques that raise significant privacy concerns.

The extension hooks into XMLHttpRequest to intercept all Facebook GraphQL API responses, parses out sponsored content data, and exfiltrates detailed ad information (ad IDs, creative content, targeting parameters, page names, destination URLs) to the developer's backend at ads.adminer.pro. It also integrates Mixpanel analytics to track user behavior. While the core functionality (capturing Facebook ads) may be disclosed in the extension's description, the extent of data collection and the use of third-party analytics appears excessive and potentially undisclosed.

## Vulnerability Details

### 1. HIGH: XMLHttpRequest Hooking for Ad Data Interception

**Severity**: HIGH
**Files**: libs.js, content.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**:
The extension replaces the native `XMLHttpRequest.prototype.send` function to intercept all XHR responses on Facebook pages. It specifically targets Facebook GraphQL API calls containing the base64-encoded string `L2FwaS9ncmFwaHFsLw==` (which decodes to `/api/graphql/`) and filters for sponsored content (base64: `U1BPTlNPUkVE` = `SPONSORED`).

**Evidence**:
```javascript
// libs.js lines 50-101
var e = atob("TDJGd2FTOW5jbUZ3YUhGc0x3PT0="),  // /api/graphql/
    t = atob("U1BPTlNPUkVE");                  // SPONSORED

function r(r, n, o) {
  if ((r = r ? r.toLowerCase() : r) && r.indexOf(e) > -1 && "blob" != n && o) try {
    var s = o.split("\n");
    window.postMessage({
      type: "apiCall"
    }, "*"), s.forEach((e, r) => {
      // Parse JSON responses and extract ad data
      if (e.indexOf("ad_id") > -1 || e.indexOf("brs_filter_setting") > -1) {
        let t = JSON.parse(e);
        window.postMessage({
          type: "adDonR",
          payload: t.data
        }, "*")
      }
      // Filter for SPONSORED content
      e.data.viewer.news_feed.edges.forEach((e, r) => {
        e.category === t && window.postMessage({
          type: "adDonR",
          payload: e
        }, "*")
      })
    })
  } catch (e) {
    window.postMessage({
      type: "error",
      payload: this.responseText
    }, "*")
  }
}

var n = XMLHttpRequest.prototype,
    o = n.send;
if (o) n.send = function() {
  return this.addEventListener("load", (function() {
    "blob" != this.responseType && "arraybuffer" != this.responseType &&
    this.responseText && r(this.responseURL, this.responseType, this.responseText)
  })), o.apply(this, arguments)
}
```

**Verdict**: This is a legitimate XHR hooking technique for the extension's stated purpose (capturing Facebook ads), but it operates at a very low level and intercepts all Facebook API traffic. The extent of data captured and transmitted is significant.

### 2. HIGH: Exfiltration of Facebook Ad Data to Third-Party Server

**Severity**: HIGH
**Files**: content.js, background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
When the content script detects ad data (via the postMessage mechanism from the XHR hook), it parses the ad details and sends them to `https://ads.adminer.pro/save` via the background script. The data includes:
- Ad ID
- Ad creative content (images, video, text)
- Page name of advertiser
- Destination URL
- User's session token
- User ID

**Evidence**:
```javascript
// content.js lines 6435-6443
chrome.runtime.sendMessage({
  name: "saveAd",
  data: a  // Parsed ad object
}, (async function(t) {
  t && 1 == t.save && (/* update local storage counters */)
}))

// background.js lines 322-367 (saveAd handler)
case "saveAd":
  return async function(t) {
    const n = await a();  // Get user from IndexedDB
    if (!n || !n.userId) return e({error: "no user logged in"});
    t.data.userId = n.userId;
    const s = await fetch(o + "/save", {  // o = "https://ads.adminer.pro"
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify(t.data)
    })
  }
```

**Verdict**: While this functionality aligns with the extension's purpose (saving Facebook ads for user analysis), the data is sent to a third-party server controlled by the developer. Users may not fully understand that all ads they encounter on Facebook are being logged and transmitted externally. The privacy policy and disclosure around this data collection should be carefully reviewed.

### 3. MEDIUM: Undisclosed Third-Party Analytics (Mixpanel)

**Severity**: MEDIUM
**Files**: content.js
**CWE**: CWE-359 (Exposure of Private Personal Information)

**Description**:
The extension loads the Mixpanel analytics library (`https://api-js.mixpanel.com`) and tracks user events without prominent disclosure. While analytics are common, the integration of a third-party tracking service in an extension that already collects Facebook ad data increases the privacy surface area.

**Evidence**:
```javascript
// content.js line 4947
api_host: "https://api-js.mixpanel.com"

// Mixpanel tracking calls throughout content.js
mixpanel.track(eventName, properties)
```

**Verdict**: Using third-party analytics libraries in extensions should be clearly disclosed in the privacy policy. Combined with the ad data collection, this creates a comprehensive tracking profile of user behavior on Facebook.

## False Positives Analysis

- **XHR Hooking**: While XHR hooking is often a red flag for malicious extensions, in this case it's the core mechanism for the extension's advertised functionality (capturing Facebook ads). The technique itself is not malicious, but the extent of data collected warrants scrutiny.

- **Webpack Bundling**: The jQuery code and standard webpack boilerplate are not indicators of malicious intent, just standard build tooling.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| ads.adminer.pro/save | Save captured ad data | Ad IDs, creative content, user ID, page names, destination URLs | HIGH - Comprehensive ad data exfiltration |
| ads.adminer.pro/users/auth | User authentication | Email, password, token | MEDIUM - Standard auth, but credentials pass through extension |
| ads.adminer.pro/users/session | Session validation | Email, token | LOW - Standard session check |
| ads.adminer.pro/users/notification/* | Notification system | User email, token | LOW - Feature notification |
| api-js.mixpanel.com | Third-party analytics | User events, behavioral data | MEDIUM - Undisclosed analytics |
| forms.gle/* | Google Forms (feedback/uninstall) | User feedback | LOW - Standard feedback mechanism |
| app.adminer.pro | User signup redirect | None (navigation only) | LOW |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
While the extension provides a legitimate service for users interested in analyzing Facebook advertising (common for dropshipping/e-commerce research), it employs invasive techniques that collect and exfiltrate significant amounts of data:

1. **XHR hooking** intercepts all Facebook GraphQL API traffic on targeted domains
2. **Comprehensive ad data** (IDs, creatives, targeting info, advertiser pages) is sent to a third-party server
3. **User behavioral tracking** via Mixpanel creates an additional privacy concern
4. **Disclosure concerns**: The extent of data collection may not be fully transparent to users

The extension is **not malware** in the traditional sense — it performs its advertised function of capturing Facebook ads. However, the privacy implications are substantial. Users should be fully informed that:
- Every Facebook ad they see is logged and sent to adminer.pro
- Their interaction patterns are tracked via Mixpanel
- Ad creative content and targeting data is collected in detail

**Recommendation**: Users concerned about privacy should carefully review the extension's privacy policy and terms of service. The developer should ensure transparent disclosure of all data collection practices, third-party services, and data retention policies.
