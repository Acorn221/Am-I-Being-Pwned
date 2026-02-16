# Vulnerability Report: 广告终结者 (Ad Terminator)

## Metadata
- **Extension ID**: fpdnjdlbdmifoocedhkighhlbchbiikl
- **Extension Name**: 广告终结者 (Ad Terminator)
- **Version**: 3.4.2
- **Users**: Unknown (Chinese market extension)
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

This extension is a Chinese ad blocker ("Ad Terminator") that provides legitimate ad-blocking functionality but contains undisclosed data exfiltration capabilities. The extension collects and transmits browsing data including tab URLs to remote servers (sub.adtchrome.com, stat.adtchrome.com) without clear user consent. The static analyzer flagged one HIGH-severity exfiltration flow where chrome.tabs.query data reaches sub.adtchrome.com. Additionally, the extension injects shopping coupon functionality for JD.com and Taobao that harvests product browsing data and enables remote content injection via message handlers.

While the core ad-blocking features appear legitimate (based on Adblock Plus), the hidden data collection, combined with broad permissions (webRequest, webRequestBlocking, all URLs) and remote configuration capabilities, presents significant privacy risks.

## Vulnerability Details

### 1. HIGH: Undisclosed Tab URL Exfiltration
**Severity**: HIGH
**Files**: background.js (lines 533-620)
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension collects user browsing data via chrome.tabs.query and transmits it to remote servers without user consent. The background script contains code that sends tracking data to stat.adtchrome.com and sub.adtchrome.com, including:
- Installation timestamp
- Total blocked ads count
- Tab URLs when shopping on JD.com/Taobao
- Product IDs and seller information

**Evidence**:
```javascript
// background.js line 533-548
let u = o.d.am || "",
  d = o.d.debugUrl || "https://stat.adtchrome.com",
  l = !!o.d.debugUrl;
! function e() {
  let t = JSON.parse(o.d.stats_total || '{"blocked":0}').blocked,
    n = function(e) {
      // Browser fingerprinting code
    }() ? "2" : "3";
  i({
    type: "GET",
    url: d + "/state/v2?s=" + n + "&am=" + u + "&bc=" + t + "&it=" + o.d.installTime + "&tfl=" + (o.d.tfl || "") + "&tflTimeCd=" + (o.d.tflTimeCd ? o.d.tflTimeCd : 0)
  }).then(e => {
    // Remote config updates
  })
}()
```

The ext-analyzer output confirms this:
```
EXFILTRATION (1 flow):
  [HIGH] chrome.tabs.query → *.src(sub.adtchrome.com)    background.js
```

**Verdict**: This is a clear privacy violation. While ad blockers need to track blocked ads for statistics, sending tab URLs and browsing data to external servers without explicit disclosure violates user privacy expectations.

### 2. HIGH: Shopping Data Harvesting via Coupon Features
**Severity**: HIGH
**Files**: background.js (lines 556-659), include.postload.js
**CWE**: CWE-359 (Exposure of Private Information)

**Description**: The extension includes undisclosed "coupon helper" functionality for Chinese e-commerce sites (JD.com, Taobao) that:
1. Intercepts product page visits
2. Extracts product IDs, seller IDs, and shopping cart data
3. Transmits this data to stat.adtchrome.com to fetch "coupon" data
4. Injects HTML templates with QR codes and promotional content

**Evidence**:
```javascript
// background.js lines 567-620
if ("getQuan" == e.cmd) {
  let n = {
    am: "false" == o.d.tfl ? "" : u,
    itemId: s("id", e.url),
    iss: o.d.iss,
    quan: [],
    ws: !!o.d.ws,
    status: 1,
    pageSellerId: e.pageSellerId,
    ps: o.d.ps
  };
  // Sends shopping data to stat.adtchrome.com
  await i({
    type: "GET",
    url: d + "/query/v2?itemId=" + e.itemId + "&amid=" + o.d.am
  })
}
```

The extension also reads shopping cart data from JD.com:
```javascript
// lines 590-610
await i({
  type: "GET",
  url: "https://cart." + o.e + ".com/json/GetPriceVolume.do?sellerId=" + e.sellerId
})
```

**Verdict**: This shopping assistant feature was not disclosed in the extension's primary description ("ad blocker"). It harvests detailed shopping behavior including products viewed, cart contents, and seller interactions, then transmits this data to third-party servers.

### 3. MEDIUM: Message Handler with Unsafe innerHTML Injection
**Severity**: MEDIUM
**Files**: include.postload.js, register.js, popup.js
**CWE**: CWE-79 (Cross-Site Scripting)

**Description**: The ext-analyzer identified an attack surface where message data from background/popup scripts flows to innerHTML on www.adtchrome.com domains:

```
ATTACK SURFACE:
  message data → *.innerHTML(www.adtchrome.com)    from: register.js, popup.js +2 more ⇒ include.postload.js
```

While the innerHTML injection is limited to first-party domains (www.adtchrome.com), this pattern indicates the extension injects dynamic content received via messaging. The content includes HTML templates for coupon displays (from include.postload.js lines 1-300) with embedded JavaScript for WeChat/Taobao QR code displays.

**Evidence**:
```javascript
// include.postload.js - HTML injection via templates
// Templates include SVG, event handlers, and dynamic content
```

**Verdict**: While limited to specific domains, this creates a potential XSS vector if the remote server (stat.adtchrome.com) is compromised or serves malicious content. The extension effectively gives the remote server the ability to inject arbitrary HTML on shopping sites.

## False Positives Analysis

The following patterns are legitimate for an ad blocker:
- **webRequest/webRequestBlocking permissions**: Required for ad blocking functionality
- **Element hiding via CSS injection**: Standard ad-blocking technique (include.preload.js)
- **AdBlock Plus library usage**: The extension appears to be based on legitimate open-source ad blocking code (lib/adblockplus.js)
- **Google Analytics**: Used for extension usage analytics (ssl.google-analytics.com)

The obfuscated flag is justified - while some code is webpack-bundled, portions use string obfuscation like:
```javascript
let o = "uoy,qhy,_lft,rqt,mt,oat,iuh,edoc,nc,moc,xob,oab,da,lla".split("").reverse().join("").split(",");
```
This decodes to domain/URL strings, a technique used to evade static detection.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| sub.adtchrome.com | Ad filter list subscriptions + tab URL exfiltration | Tab URLs, installation time, blocked ad counts | HIGH - Privacy violation |
| stat.adtchrome.com | Shopping data collection & coupon API | Product IDs, seller IDs, cart data, user browsing | HIGH - Undisclosed tracking |
| ssl.google-analytics.com | Extension usage analytics | Standard GA metrics | LOW - Standard analytics |
| cart.jd.com | Shopping cart data retrieval | Seller ID queries | MEDIUM - Legitimate API but privacy concern |
| www.adtchrome.com | Official website (HTML injection target) | N/A (receives injected content) | MEDIUM - Content injection risk |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:
While this extension provides legitimate ad-blocking functionality, it contains multiple undisclosed data collection mechanisms that violate user privacy expectations:

1. **Hidden data exfiltration**: Browsing data (tab URLs, timestamps, ad counts) is sent to remote servers without clear disclosure
2. **Shopping surveillance**: The coupon feature harvests detailed e-commerce browsing behavior (products viewed, cart contents, seller interactions) and transmits to third-party servers
3. **Remote control capability**: The extension receives configuration updates from stat.adtchrome.com that can enable/disable features and modify behavior
4. **Broad permissions**: Combined with webRequest/webRequestBlocking and all_urls access, the hidden tracking creates significant privacy risks
5. **Obfuscation**: Partial code obfuscation suggests intent to hide functionality from review

The extension description focuses solely on ad blocking ("清除网页上的所有广告" - "Remove all ads from web pages") but does not disclose the shopping assistant features or data collection practices. This lack of transparency, combined with active data exfiltration to external servers, warrants a HIGH risk rating.

**Recommendation**: Users should be warned about undisclosed data collection. Extension should be flagged for privacy policy review and potential removal unless developer provides clear disclosure and opt-in consent for data collection features.
