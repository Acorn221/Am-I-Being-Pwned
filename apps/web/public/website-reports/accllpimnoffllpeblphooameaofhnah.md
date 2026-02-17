# Vulnerability Report: 楽天リーベイツ ポイントアシスト

## Metadata
- **Extension ID**: accllpimnoffllpeblphooameaofhnah
- **Extension Name**: 楽天リーベイツ ポイントアシスト (Rakuten Rebates Point Assist)
- **Version**: 0.1.20
- **Users**: Unknown
- **Manifest Version**: 3
- **Author**: Rakuten, Inc.
- **Analysis Date**: 2026-02-15

## Executive Summary

Rakuten Rebates Point Assist is a legitimate shopping cashback/rewards extension from Rakuten that notifies users when they visit partner stores offering cashback opportunities. The extension collects browsing activity data and sends analytics/telemetry to multiple third-party services including Datadog, Google Analytics, Segment, and internal Rakuten tracking endpoints. While the data collection is likely disclosed in the privacy policy and necessary for the cashback functionality, the extension has broad access permissions (`<all_urls>`, cookies, webRequest) and actively monitors user navigation across all websites.

The extension is webpack-bundled (not obfuscated) and appears to be a standard affiliate/cashback tool. The primary privacy concern is the breadth of browsing data collection sent to third parties, though this is typical for shopping extensions in this category.

## Vulnerability Details

### 1. MEDIUM: Extensive Third-Party Analytics and Telemetry

**Severity**: MEDIUM
**Files**: bg/bundle.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends browsing activity and user agent data to multiple third-party analytics services:

1. **Datadog Logging** (lines 13989-14007): Sends logs to `logs.browser-intake-datadoghq.com` with user agent and browsing context
2. **Google Analytics** (lines 14039-14079): Tracks events and pageviews to `www.google-analytics.com`
3. **Segment Analytics** (line 13742): Sends data to `api.segment.io`
4. **Internal Analytics** (line 13660): `bl.ecbsn.com/index.php` and `events.engager.ecbsn.com`

**Evidence**:
```javascript
// Datadog integration
const t = `https://logs.browser-intake-datadoghq.com/api/v2/logs?${new URLSearchParams({
  ddsource:"browser",
  "dd-api-key":this._clientToken,
  "dd-evp-origin":"browser",
  "dd-request":$n()
})}`,

// Google Analytics
url: "https://www.google-analytics.com/collect",
defaults: {
  v: 1,
  tid: null,
  cid: null,
  an: rr.TENANT,
  ul: navigator.language,
  dl: "/background.html",
  z: null
}
```

**Verdict**: This is standard practice for shopping/affiliate extensions but represents a privacy concern due to the volume of third parties receiving user data. The extension likely discloses this in its privacy policy.

### 2. MEDIUM: Broad Navigation Monitoring with webRequest

**Severity**: MEDIUM
**Files**: bg/bundle.js (lines 11703-11714)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension uses `webRequest.onBeforeRequest` to monitor all main frame navigations across all URLs. This allows the extension to track every website the user visits.

**Evidence**:
```javascript
t().webRequest.onBeforeRequest.addListener((e => this.onBeforeRequestHandler(e)), {
  urls: ["<all_urls>"],
  types: ["main_frame"]
})

onBeforeRequestHandler(e) {
  (0 === e.frameId || this.isSafariWebext && 0 === e.parentFrameId) &&
  e.url && this.fireEvent(s.BEFORENAVIGATE, {
    name: s.BEFORENAVIGATE,
    tabId: e.tabId,
    url: e.url
  })
}
```

**Verdict**: This is necessary functionality for detecting when users visit partner stores to trigger cashback notifications. However, it provides comprehensive visibility into user browsing history.

### 3. LOW: Confirmation Page Detection for Purchase Tracking

**Severity**: LOW
**Files**: content/bundle.js (lines 6-18)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension uses regex patterns to detect order confirmation pages across e-commerce sites, which could reveal purchase behavior.

**Evidence**:
```javascript
{
  type: "url",
  match: "confirm|thank|complete|success|receipt|submit|place_?order|complete|accepted|confpm|ocp|order(id)?=|ordernumber=",
  score: .5
}, {
  type: "text",
  match: "(a|your) confirmation email has been sent|You( will| should|'ll) (be receiving|receive)",
  score: .5
}
```

**Verdict**: This functionality is core to the extension's purpose (tracking cashback eligibility on completed purchases) and is expected behavior for a shopping rewards extension.

## False Positives Analysis

1. **Webpack Polyfills**: The extension includes standard browser API polyfills (webextension-polyfill) which define API structures for cookies, webRequest, etc. These are not actual usage, just API definitions (lines 196-216, 648-651).

2. **jQuery/Moment.js**: Contains bundled libraries (jQuery, Moment.js) which include standard AJAX/fetch functionality. The actual network requests are to legitimate Rakuten domains and analytics providers.

3. **Content Script Cookie Reading**: The extension reads `document.cookie` for the `express_locale` cookie (line 2860), which is used for localization purposes and is benign.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.rebates.jp | Primary Rakuten Rebates domain | User tokens, browsing context, store IDs | LOW - First party |
| static.rebates.jp | CDN for static assets | None (resources only) | LOW |
| logs.browser-intake-datadoghq.com | Error/event logging | Logs, user agent, extension events | MEDIUM - Third party telemetry |
| www.google-analytics.com | Analytics tracking | Navigation events, user actions | MEDIUM - Third party analytics |
| api.segment.io | Analytics platform | User behavior data | MEDIUM - Third party analytics |
| events.engager.ecbsn.com | Internal event tracking | User engagement metrics | MEDIUM - Third party tracking |
| bl.ecbsn.com | Internal logging | Extension logs | MEDIUM - Third party tracking |
| point.rakuten.co.jp | Rakuten points system | User rewards balance | LOW - First party |
| forms.office.com | Uninstall feedback form | Feedback responses | LOW - Standard practice |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

This is a legitimate shopping extension from Rakuten, a major e-commerce company. The extension's core functionality (detecting partner stores and tracking cashback opportunities) requires broad permissions and browsing monitoring. However, the extension exhibits several privacy-concerning behaviors:

1. **Extensive third-party data sharing**: User browsing data is sent to at least 4 different analytics/logging services (Datadog, Google Analytics, Segment, and internal Rakuten tracking)
2. **Comprehensive navigation monitoring**: Uses webRequest to track all website visits
3. **Broad permissions**: Has access to cookies, all URLs, and web request data

The risk is classified as MEDIUM rather than HIGH because:
- The extension is from a reputable, established company (Rakuten)
- The functionality appears necessary for the stated purpose (cashback notifications)
- Data collection is likely disclosed in privacy policies
- No evidence of credential theft, hidden exfiltration, or malicious behavior
- The extension uses standard analytics services common in legitimate extensions

**Recommendation**: Users should be aware that this extension tracks their browsing activity across all websites and shares data with multiple third parties. Those concerned about privacy should review Rakuten's privacy policy and consider whether the cashback benefits outweigh the privacy trade-offs.
