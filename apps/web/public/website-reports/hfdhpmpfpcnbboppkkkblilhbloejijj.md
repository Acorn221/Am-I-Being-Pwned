# Vulnerability Report: Backit Plugin

## Metadata
- **Extension ID**: hfdhpmpfpcnbboppkkkblilhbloejijj
- **Extension Name**: Backit Plugin
- **Version**: 4.1.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Backit Plugin is a legitimate cashback and shopping extension that provides users with affiliate rewards when making purchases on e-commerce sites. The extension modifies shopping links to include affiliate tracking parameters (affiliate injection), communicates with multiple backend services (app.backit.me, oauth2.backit.me, pltrack.bz), and uses a PAC script proxy to route traffic to its own domain through access.backit.me:8888. The extension is properly disclosed as a cashback service, and the privacy policy indicates that page URLs are sent to backit.me to check for cashback opportunities.

The static analyzer flagged one exfiltration flow (chrome.storage.local.get → fetch), which is expected behavior for a cashback extension communicating user preferences and session data to its backend. The extension implements OAuth2 authentication, tracks installation and daily active usage via pltrack.bz, and injects content scripts on all URLs to display cashback offers. All observed behaviors align with the stated functionality of a shopping rewards extension.

## Vulnerability Details

### 1. LOW: Proxy Configuration for Backend Communication
**Severity**: LOW
**Files**: core/modern/proxy.js, background.js
**CWE**: CWE-441 (Unintended Proxy or Intermediary)
**Description**: The extension configures a PAC (Proxy Auto-Config) script that routes all traffic to backit.me and its subdomains through a proxy server at access.backit.me:8888.

**Evidence**:
```javascript
// core/modern/proxy.js
class Proxy {
    constructor() {
        this.config = {
            mode: 'pac_script',
            pacScript: {
                data: `
                    function FindProxyForURL(url, host) {
                        if (host == "backit.me" || dnsDomainIs(host, ".backit.me")) return 'PROXY access.backit.me:8888';
                        return 'DIRECT';
                    }
                `,
            },
        };
    }
    setProxy() {
        apiObj.proxy.settings.set({
            value: this.config,
            scope: 'regular',
        });
    }
}
```

**Verdict**: This is a legitimate configuration pattern used to route the extension's own backend traffic through a specific proxy, likely for load balancing, CDN, or infrastructure purposes. Only traffic to backit.me domains is proxied; all other traffic is sent DIRECT. This does not intercept or redirect user browsing traffic. The extension properly requests the "proxy" permission in manifest.json. This is standard practice for SaaS extensions managing their own infrastructure.

## False Positives Analysis

The static analyzer flagged the extension as "obfuscated" and detected one exfiltration flow (chrome.storage.local.get → fetch). These findings require context:

1. **Obfuscation flag**: The background.js and popup chunk files show typical build tool minification (Vite/Rollup) with shortened variable names and bundled dependencies (webextension-polyfill, axios, lodash, Vue). The deobfuscated source code in core/modern/ shows clean, well-structured JavaScript modules with proper class definitions, JSDoc comments, and readable variable names. This is webpack/vite bundling, not malicious obfuscation.

2. **Exfiltration flow (storage → fetch)**: The extension stores user authentication tokens (access_token, refresh_token), cashback activation timestamps, user preferences, and tracking parameters in chrome.storage.local, then sends this data to app.backit.me when activating cashback, checking link eligibility, or refreshing session tokens. This is expected behavior for a cashback service that requires user authentication and needs to communicate active offers to the backend.

Example of legitimate data flow:
```javascript
// core/modern/affiliate.js - activating cashback
async activateCashback(redirectUrl, offerId) {
    const tabId = await getTabId({ active: true, currentWindow: true });
    const trackParams = await getSettingFromLocalStorage(TRACK_PARAMS);
    const affId = `${offerId}_affiliate`;
    let url = redirectUrl;
    if (trackParams) url += `&${trackParams}`;
    const newTab = await browser.tabs.update(tabId, { url, active: true });
    return browser.storage.local.set({ [affId]: Date.now() + AFF_TIME });
}
```

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| app.backit.me:443 | Main API for cashback offers, user data, similar goods | User tokens, current page URL, offer IDs, language, browser type | Low - expected for cashback service |
| oauth2.backit.me:443 | OAuth2 authentication flow | OAuth parameters, client_id, redirect_uri, user credentials (via OAuth flow) | Low - standard OAuth2 implementation |
| pltrack.bz | Installation and daily usage tracking ("ping") | Extension version, browser type, language | Low - basic analytics for install/active user tracking |
| access.backit.me:8888 | Proxy server for routing backit.me traffic | All requests to *.backit.me domains | Low - internal infrastructure proxy |

All endpoints are owned by the Backit service. The extension only sends data to its own first-party servers.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
Backit Plugin is a legitimate cashback/shopping rewards extension with standard functionality for its category. The extension appropriately discloses its purpose (cashback rewards), requests relevant permissions (proxy, tabs, storage, webNavigation), and limits host_permissions to its own backend domains. The affiliate link injection behavior is the core feature of the extension, not a hidden malicious function. The proxy configuration only affects traffic to the extension's own domains, not user browsing. The extension uses OAuth2 for authentication, stores tokens locally, and communicates with first-party servers to activate cashback offers and check link eligibility.

The privacy policy (visible in _locales/en/messages.json) states: "When you click on the 'Go to Site' button while you visiting AliExpress site, we send the URL of the current page to backit.me. We use the current domain name of the site where you are located: this data is needed to inform you about the possibility of receiving cashback."

The one LOW-severity finding (proxy configuration) is a standard infrastructure pattern and does not pose a security risk to users. All observed behaviors align with disclosed functionality.

**Recommendation**: This extension is safe for users who understand and consent to affiliate link modification and cashback tracking. No security or privacy issues beyond normal cashback extension behavior were identified.
