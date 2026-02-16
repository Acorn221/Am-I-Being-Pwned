# Vulnerability Report: セゾンツールバー (Saison Toolbar)

## Metadata
- **Extension ID**: odepgchmjhknppjoihgmfdmlgkihmghp
- **Extension Name**: セゾンツールバー (Saison Toolbar)
- **Version**: 2.0.7.0
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

This is a shopping toolbar extension for Saison Card members (a Japanese credit card company). The extension tracks browsing activity and communicates with both production and development servers. Two security concerns were identified:

1. **HIGH**: Tab data exfiltration to development server - The extension sends browsing data (including tab information) to a development/testing domain (`dev-toolbar.stylez-dev.work`) that should not be present in production code.

2. **MEDIUM**: Unsafe postMessage listener - The content script registers a `window.addEventListener("message")` handler without validating the message origin, allowing any website to inject messages.

The extension appears to be a legitimate shopping toolbar that has accidentally shipped with development/debug configuration enabled, resulting in user data being sent to testing infrastructure.

## Vulnerability Details

### 1. HIGH: Tab Data Exfiltration to Development Server

**Severity**: HIGH
**Files**: background.js, content-script.js, content-script-connect.js, dbgSetting.js, scripts/shopnotif.js, scripts/favornotif.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**:
The extension contains hardcoded configuration pointing to a development server domain (`dev-toolbar.stylez-dev.work`) across all major script files. The static analyzer flagged a data flow where `chrome.tabs.query` results are sent via `fetch()` to this development domain.

**Evidence**:
```javascript
// From background.js line 8792 (and similar in other files)
Lg = {
  aqfDomain: "debug2.a-q-f.com",
  token: "https://dev-toolbar.stylez-dev.work",  // Development server!
  connect: "apit.saisoncard.co.jp",
  isDebug: !0,
  xml_site_path: "https://debug.a-q-f.com/saison/tb/v3_site.xml",
  // ...
}

// Static analyzer finding: EXFILTRATION flow
// chrome.tabs.query → fetch(dev-toolbar.stylez-dev.work)
// at background.js (line detected by analyzer)
```

The extension queries tab information using `chrome.tabs.query()` throughout the codebase:
```javascript
// Line 13259
chrome.tabs.query({...})

// Line 13272
chrome.tabs.create({...})

// Multiple references to tabId tracking:
// Lines 13283-13340 show extensive tab tracking
await Xe(t.tabId, "strReferrer")
await Xe(t.tabId, "strLastVistedUrl")
await at(t.tabId, "strCurrUrl", t.url)
```

**Verdict**:
This appears to be a configuration error rather than malicious intent - the developers forgot to remove debug/testing configuration before publishing. However, the impact is real: user browsing data is being sent to a development server that likely has weaker security controls than production infrastructure. The `dev-toolbar.stylez-dev.work` domain could be logging all user activity for debugging purposes.

### 2. MEDIUM: postMessage Handler Without Origin Validation

**Severity**: MEDIUM
**Files**: content-script.js:4447
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)

**Description**:
The content script registers a message event listener that only performs minimal validation, checking if `J.source == window` and a type field, but does not validate the origin of the message sender.

**Evidence**:
```javascript
// Line 4447 in content-script.js
window.addEventListener("message", function(J) {
  J.source == window && J.data.type && J.data.type == "sr" && xr(document.URL) && ut.runtime.sendMessage({
    message: "onGoogleAjax",
    url: document.URL,
    referrer: document.referrer
  })
})
```

**Verdict**:
While the handler does check `J.source == window` (meaning the message must come from the same window, not an iframe), it does not validate `event.origin`. Any script running on the page (including third-party scripts or injected malicious code) could potentially trigger this handler by posting messages with `type: "sr"`. The actual risk depends on what `xr(document.URL)` does and what the background script does with the `onGoogleAjax` message - if it only triggers analytics, impact is low; if it triggers privileged operations, impact could be higher.

## False Positives Analysis

**Obfuscation Flag**: The static analyzer marked this extension as "obfuscated". However, after examining the deobfuscated code, this appears to be webpack/bundler minification rather than intentional obfuscation. The code uses standard patterns (webextension-polyfill, jQuery 3.6.1) and follows typical extension architecture. This is NOT malicious obfuscation.

**Legitimate Shopping Toolbar Features**:
- Tracking referrer chains for affiliate attribution is expected for shopping toolbars
- Monitoring navigation to shopping sites (a-q-f.com, saisoncard.co.jp) is the core functionality
- User authentication flows via ID tokens are normal for card member services
- Content scripts on `<all_urls>` are necessary to detect shopping opportunities across all sites

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| dev-toolbar.stylez-dev.work | Development/testing server | Tab data, browsing history, user activity | **HIGH** - Should not be in production |
| tb.a-q-f.com | Production toolbar API | Shopping data, user preferences | Low - Expected |
| tb-dev.a-q-f.com | Development toolbar API | Same as above | Medium - Dev endpoint in production |
| debug.a-q-f.com | Debug configuration server | Fetches XML config | Low - Read-only config |
| debug2.a-q-f.com | Debug domain | Unknown | Medium - Debug infrastructure |
| apit.saisoncard.co.jp | Saison Card Connect API | User profile, authentication | Low - Legitimate auth endpoint |

The primary concern is `dev-toolbar.stylez-dev.work` - this is clearly a development/testing domain (using "stylez-dev.work" subdomain) that should not receive production user data.

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
While the tab data exfiltration to a development server is concerning and warrants a HIGH severity vulnerability rating, the overall extension risk is MEDIUM because:

1. **Likely Unintentional**: This appears to be a configuration management error rather than deliberate malicious data collection. The presence of multiple debug/development endpoints across the codebase suggests inadequate build processes.

2. **Legitimate Purpose**: The extension serves a legitimate function as a shopping toolbar for Saison Card members in Japan.

3. **Limited Sensitive Data Exposure**: The data being sent (browsing history, tab URLs) is limited to shopping-related activity tracking, which users would reasonably expect from a shopping toolbar. No evidence of credential theft or financial data exfiltration.

4. **Established Entity**: Saison Card (Credit Saison) is a major Japanese credit card company - this is not an anonymous threat actor.

**Recommendations**:
- The vendor should immediately update the extension to remove all references to development/debug servers
- Implement proper build configurations to prevent debug code from reaching production
- Add origin validation to the postMessage handler
- Consider using environment variables or build flags to manage dev vs. prod endpoints
