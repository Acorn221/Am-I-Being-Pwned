# Vulnerability Report: AliMedia | AliExpress image/video download

## Metadata
- **Extension ID**: mecmjepeibkhgpmohknknmfggoimnaam
- **Extension Name**: AliMedia | AliExpress image/video download
- **Version**: 3.1.14
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AliMedia is a browser extension designed to download product images and videos from AliExpress and AliBaba. The extension performs its stated function legitimately but collects and transmits usage analytics data to multiple third-party endpoints. The data collection includes user browsing behavior on AliExpress (visited product URLs), extension usage patterns, installation/update timestamps, and a persistent unique user identifier. While the core functionality appears benign, the extent of telemetry collection and transmission to third-party analytics services raises moderate privacy concerns, particularly given the lack of transparent disclosure in the extension's privacy practices.

The extension also implements affiliate link injection through purpleshades.xyz when users interact with certain features, which is a monetization strategy but may not be clearly disclosed to users.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Analytics and Telemetry Collection
**Severity**: MEDIUM
**Files**: background.js (line 3719), contentScript.js (line 20425)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects detailed usage analytics including user behavior, visited URLs on AliExpress, extension install/update timestamps, and a persistent unique identifier. This data is sent to multiple endpoints:
- `api.alibill.net/service/analytics/ga` - Receives event tracking with clientId and custom parameters
- `extension-monitor.toriox.dev/api/v1/diagnostics` - Receives comprehensive diagnostic data including URLs, feature usage, timestamps

**Evidence**:
```javascript
// background.js line 3710-3726
function b(e) {
  return y(this, arguments, void 0, (function*(e, t = {}) {
    const r = yield v(p.UNIQUE_ID), n = "string" == typeof r ? r.trim() : "";
    if (0 === n.length) return !0;
    const i = {
      eventName: e,
      clientId: n,
      params: t
    };
    return yield fetch("https://api.alibill.net/service/analytics/ga?extension=alimedia", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(i)
    }), !0
  }))
}
```

```javascript
// contentScript.js line 20415-20432
yield fetch("https://extension-monitor.toriox.dev/api/v1/diagnostics", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "x-api-key": "wzrAFVISvtVPexatTYVC4Hy6ZAnWxLqgfjm7JYeEChkRyZz0XBNtueN5DBS3KHKwmtJbLH6m87WbaYCteiLzUeq"
  },
  body: JSON.stringify({
    // Contains URL, installedAt, updatedAt, uniqueRandomId, feature usage
    url: window.location.href,
    installedAt: e[ps.INSTALLED_AT],
    updatedAt: e[ps.UPDATED_AT],
    extensionName: "AliMedia",
    extensionVersion: chrome.runtime.getManifest().version,
    uniqueRandomId: e[ps.UNIQUE_ID]
  })
})
```

**Verdict**: While analytics collection is common in extensions, the combination of persistent user tracking, URL monitoring, and transmission to multiple third-party services without prominent privacy disclosure constitutes a medium-severity privacy concern. The data could potentially be used to build browsing profiles of AliExpress shoppers.

### 2. MEDIUM: Affiliate Link Injection
**Severity**: MEDIUM
**Files**: background.js (line 5519)
**CWE**: CWE-441 (Unintended Proxy or Intermediary)

**Description**: The extension injects affiliate tracking through purpleshades.xyz CPA network when creating tabs, appending the user's unique ID as a subid parameter.

**Evidence**:
```javascript
// background.js line 5517-5522
const i = yield v(), s = (null == i ? void 0 : i[p.UNIQUE_ID]) || "",
  a = (null == e ? void 0 : e.url) ? e.url : "https://aliexpress.com",
  o = `https://purpleshades.xyz/cpa?subid=r9785&link=${encodeURIComponent(a)}&subid1=${s}`;
chrome.tabs.create({
  active: !1,
  index: ...
```

**Verdict**: Affiliate monetization is legitimate but should be transparently disclosed. The use of a user's unique ID in affiliate links enables cross-site tracking of purchase behavior.

### 3. LOW: Legitimate API Access to AliExpress Reviews
**Severity**: LOW
**Files**: contentScript.js (line 18944)
**CWE**: N/A

**Description**: The extension fetches product reviews from `feedback.aliexpress.com` to enable image downloading from reviews. This is legitimate functionality aligned with the extension's purpose.

**Evidence**:
```javascript
// contentScript.js line 18942-18946
const r = yield fetch(`https://feedback.aliexpress.com/pc/searchEvaluation.do?productId=${e}&page=1&pageSize=200&filter=all&sort=complex_default`),
  o = yield r.json();
return (null === (n = null === (t = null == o ? void 0 : o.data) || void 0 === t ? void 0 : t.evaViewList) || void 0 === n ? void 0 : n.flatMap(...
```

**Verdict**: This is expected behavior for downloading review images and does not pose a security risk.

## False Positives Analysis

The static analyzer flagged 7 exfiltration flows, but several are false positives or low-risk:

1. **DOM queries → fetch(feedback.aliexpress.com)**: Legitimate - fetching public review data to enable the extension's core download feature
2. **chrome.storage → analytics endpoints**: While privacy-concerning, this is standard telemetry rather than credential theft
3. **chrome.tabs.query → analytics**: Event tracking, not sensitive data exfiltration
4. **Document queries for download functionality**: Required for identifying media elements on AliExpress pages

The "obfuscated" flag is also a false positive - the code uses webpack bundling, which is standard practice, not malicious obfuscation.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.alibill.net | Analytics tracking | Event names, unique client ID, custom parameters | Medium - enables user profiling |
| extension-monitor.toriox.dev | Diagnostic reporting | URLs, install/update times, feature usage, unique ID | Medium - comprehensive usage tracking |
| feedback.aliexpress.com | Fetch product reviews | Product IDs | Low - public data access |
| purpleshades.xyz | Affiliate tracking | AliExpress URLs, unique user ID | Medium - enables purchase tracking |
| alimedia.io | Welcome page on install | Unique user ID | Low - standard onboarding |
| tally.so | Uninstall survey & feedback | N/A | Low - standard user feedback |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
AliMedia functions as advertised - it successfully downloads images and videos from AliExpress. However, it collects more user data than necessary for its core functionality. The combination of:
- Persistent unique user tracking across sessions
- URL monitoring on AliExpress (revealing shopping interests)
- Transmission to multiple third-party analytics endpoints
- Affiliate injection with user tracking
- Lack of prominent privacy disclosure

elevates this beyond a LOW risk, but it does not constitute HIGH risk because:
- No credential harvesting or sensitive data theft
- No malicious code execution or XSS vulnerabilities
- Scoped to AliExpress domains only (not `<all_urls>`)
- Core functionality is legitimate and works as described
- No evidence of data selling or misuse (though tracking enables it)

The primary concern is **privacy**, not security. Users installing this extension should be aware they are being tracked across their AliExpress browsing sessions and that their shopping behavior may be monetized through affiliate programs.
