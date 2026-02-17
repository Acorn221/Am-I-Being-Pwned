# Vulnerability Report: T-Сashback — кэшбэк-сервис

## Metadata
- **Extension ID**: odbmjgikedenicicookngdckhkjbebpd
- **Extension Name**: T-Сashback — кэшбэк-сервис
- **Version**: 1.0.0.2
- **Users**: Unknown
- **Manifest Version**: 2
- **Analysis Date**: 2026-02-15

## Executive Summary

T-Cashback is a Russian cashback/affiliate extension that intercepts user navigation to partner e-commerce sites and redirects them through affiliate tracking URLs. The extension uses `webRequest.onBeforeSendHeaders` with blocking permissions to monitor all HTTP requests and inject affiliate links when users visit supported merchants. While this behavior is typical for cashback extensions and aligns with its stated purpose, the extension relies on remote configuration files fetched from `t-cashback.xyz` to determine which sites to intercept and where to redirect users, creating a dependency on external infrastructure that could be modified without user consent.

The extension's core functionality is transparent to its purpose as a cashback service, but the use of broad permissions (`<all_urls>`, `webRequestBlocking`) combined with remote configuration represents a moderate privacy concern due to the potential for scope changes or malicious updates to the remote configuration.

## Vulnerability Details

### 1. MEDIUM: Remote Configuration Control Over Affiliate Injection

**Severity**: MEDIUM
**Files**: scripts/bg.js
**CWE**: CWE-912 (Hidden Functionality)
**Description**: The extension fetches its merchant list and redirect rules from a remote server (`https://t-cashback.xyz/t_cash/1.0.0.2/list.json`) on startup and periodically thereafter. This configuration determines which websites trigger affiliate redirects and where users are redirected. Changes to this remote configuration can alter the extension's behavior without requiring an extension update or user notification.

**Evidence**:
```javascript
function updateList() {
    superagent
        .get('https://t-cashback.xyz/' + self.campaignId + '/' + chrome.runtime.getManifest().version + '/list.json')
        .set('X-Requested-With', 'XMLHttpRequest')
        .set('Accept', 'application/json')
        .then(res => {
            tc_list = res.body;
            updateFeautured();
        });
}

updateList(); // Called on extension startup
```

The remote configuration contains affiliate URLs that users are redirected to:
```json
{
  "links": {
    "alcomarket.ru": {
      "durl": "https://hskwq.com/click-EQRLUF4B-ECAQCOC7?bt=25&tl=1",
      "cback": {"val": 2.5, "cur": 0, "rng": " до "}
    }
  }
}
```

**Verdict**: This is standard behavior for cashback extensions that need to maintain updated merchant partnerships, but represents a moderate risk because the remote configuration could be modified to redirect users to unexpected domains or inject tracking on additional sites beyond the initial scope.

### 2. LOW: Broad Permission Scope for Affiliate Functionality

**Severity**: LOW
**Files**: manifest.json, scripts/utils.js
**CWE**: CWE-250 (Execution with Unnecessary Privileges)
**Description**: The extension requests `webRequestBlocking` and `webRequest` permissions on `<all_urls>`, allowing it to intercept and potentially modify all HTTP requests across all websites. While this is necessary for the cashback redirect functionality, it grants more access than is minimally required for a limited set of partner merchants.

**Evidence**:
```json
"permissions": [
    "webRequestBlocking",
    "webRequest",
    "cookies",
    "storage",
    "tabs",
    "http://*/*",
    "https://*/*"
]
```

```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(function (details) {
    // ... processes all requests to determine if redirect is needed
}, {urls: ["<all_urls>"]}, ["blocking"]);
```

**Verdict**: This is a common pattern for cashback/coupon extensions that don't know in advance which sites users will visit. While overly broad, the implementation limits actual interception to sites in the remote configuration's merchant list. The extension does not modify requests to non-partner sites.

## False Positives Analysis

The following patterns were identified but are legitimate for a cashback extension:

1. **Cookie Manipulation**: The extension sets cookies (`tc_last_usage`) to track when cashback was last activated for a merchant. This is necessary to prevent duplicate redirects and improve user experience.

2. **Content Script on All URLs**: The extension injects a content script on `<all_urls>` at `document_start`, but this script only displays notification frames when visiting partner merchants. It does not collect browsing data from non-partner sites.

3. **Request Interception**: The use of `webRequestBlocking` to intercept navigation is the core mechanism for affiliate insertion and is disclosed in the extension's functionality as a cashback service.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| t-cashback.xyz | Fetch merchant list and featured links | Extension version, campaign ID | LOW - Standard config endpoint |
| hskwq.com | Affiliate redirect domain | User's destination URL (in redirect) | LOW - Third-party affiliate network |
| ssl.google-analytics.com | Analytics (CSP allowlist) | Unknown (not directly called in code) | LOW - Standard analytics |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:

T-Cashback is a legitimate cashback/affiliate extension that performs exactly the behavior advertised in its description: it identifies when users visit partner e-commerce sites and redirects them through affiliate tracking URLs to earn cashback. The extension's core functionality is transparent and expected for this category of extension.

The MEDIUM risk rating is assigned due to:

1. **Remote Configuration Dependency**: The extension's behavior is controlled by remotely-fetched configuration files, which could be modified to expand the scope of interception or change redirect destinations without user notification.

2. **Broad Permission Scope**: While standard for cashback extensions, the `<all_urls>` webRequest permissions grant significant access that exceeds the minimal set needed if the merchant list were fixed and known in advance.

3. **Limited User Base/Provenance**: As a Russian-language extension with unknown user count and limited web presence, there is less community oversight to detect potential malicious updates.

However, the extension does NOT:
- Exfiltrate browsing history beyond partner site visits
- Inject advertisements or modify page content
- Access credentials or sensitive user data
- Use obfuscated code to hide functionality
- Exhibit malicious behavior patterns

For users who understand and consent to cashback/affiliate tracking, this extension operates as expected. The primary concern is the reliance on remote configuration that could theoretically be weaponized, though no evidence of malicious intent was observed in the current implementation.
