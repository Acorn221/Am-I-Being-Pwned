# Vulnerability Report: MATH Keys - Equation & Formula Editor

## Metadata
- **Extension ID**: imcaiokpoocfeplmgemffhmdokiaallo
- **Extension Name**: MATH Keys - Equation & Formula Editor
- **Version**: 4.0.9
- **Users**: Unknown
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

MATH Keys is a legitimate mathematical equation editor that allows users to create LaTeX formulas through a visual keyboard interface. The extension uses Google Analytics to track usage metrics and includes the ExtPay payment library for optional monetization. The extension has minimal permissions (only `storage` and host permission for its own backend) and does not access sensitive user data beyond basic analytics.

The ext-analyzer flagged two exfiltration flows involving chrome.storage data being sent to Google Analytics. However, upon manual code review, these flows only transmit non-sensitive metadata (user count ranges, UI language, and event names) for legitimate analytics purposes. The extension does not harvest browsing history, cookies, or other private user data.

## Vulnerability Details

### 1. LOW: Basic Analytics Tracking Without Explicit User Consent
**Severity**: LOW
**Files**: math_extention_main.js (lines 585-617)
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension sends basic usage analytics to Google Analytics (GA4) including a persistent user_id (randomly generated UUID), session_id, UI language, and usage frequency buckets. While the data transmitted is minimal and non-sensitive, users are not explicitly informed about this tracking in a privacy policy accessible within the extension.

**Evidence**:
```javascript
function ga4(name, eventName) {
    fetch(`https://www.google-analytics.com/mp/collect?measurement_id=G-BXWWE6WN4H&api_secret=w-ns_TQPQCGsuuclyyZPog`, {
      method: "POST",
      body: JSON.stringify({
        client_id: user_id,
        events: [{
          name: eventName,
          params: {
            "engagement_time_msec": "100",
            "session_id": session_id,
            "language": chrome.i18n.getUILanguage(),
            "user_id": user_id,
            "link_id": name
         },
        }]
      })
    });
}
```

The user_id is generated once and persisted in chrome.storage.sync:
```javascript
chrome.storage.sync.get({user_id: 0}, function(result) {
  if(result.user_id == 0){
    let uuid = self.crypto.randomUUID();
    chrome.storage.sync.set({user_id: uuid});
    user_id = uuid;
    first_time = true;
  }
  else {
    user_id = result.user_id;
  }
});
```

**Verdict**: This is common practice for extension developers to understand usage patterns and improve their product. The data collected is minimal and does not include browsing history, personal information, or page content. However, it would be best practice to disclose this in the extension's privacy policy.

## False Positives Analysis

The ext-analyzer flagged two HIGH-severity exfiltration flows:
1. `chrome.storage.sync.get → fetch(www.google-analytics.com)`
2. `chrome.storage.local.get → fetch(www.google-analytics.com)`

These are **false positives** in the context of malicious behavior. The extension reads from chrome.storage to:
- Retrieve the user_id (a random UUID, not linked to any real identity)
- Get usage count to determine when to show review dialogs
- Load saved formulas and settings

The only data sent to Google Analytics is:
- Event names (e.g., "keyboard_click", "copy_image", "open_extention")
- Usage frequency bucket (e.g., "10-20", "50-100")
- UI language
- Platform OS (only on first use)

No browsing history, personal data, or formula content is transmitted.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| www.google-analytics.com | Usage analytics (GA4) | user_id (UUID), session_id, event names, UI language, usage count bucket | Low - standard analytics |
| mathkeyboards-347222.web.app | Extension's own backend | None observed in code | Low - developer-controlled domain |
| nodejs-latex-to-image-fjdegnkwea-uc.a.run.app | LaTeX to image conversion service | LaTeX formula string, font size, color | Low - legitimate functionality |
| extpay.com | Payment processing (ExtPay library) | User payment status, API key | Low - legitimate payment processor |

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
This is a legitimate, functional mathematical equation editor with no malicious intent. The extension:
- Uses minimal permissions (storage only, plus host_permissions for its own backend)
- Does not access browsing history, cookies, or sensitive user data
- Sends only basic, non-identifying analytics data to Google Analytics
- Uses a legitimate payment processor (ExtPay) for optional monetization
- Provides genuine utility as a LaTeX formula editor

The only concern is the lack of transparent disclosure about analytics tracking within the extension UI or description. The data collected is minimal and consistent with standard extension telemetry practices.

**Recommendation**: The extension is safe for general use. Power users concerned about analytics tracking may wish to review the Chrome Web Store listing for privacy policy information or contact the developer for clarification on data practices.
