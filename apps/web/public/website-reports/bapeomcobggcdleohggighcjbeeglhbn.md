# Vulnerability Report: BP Proxy Switcher

## Metadata
- **Extension ID**: bapeomcobggcdleohggighcjbeeglhbn
- **Extension Name**: BP Proxy Switcher
- **Version**: 6.0
- **Users**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

BP Proxy Switcher is a legitimate proxy management extension that allows users to switch between HTTP and SOCKS5 proxies, manage user agents, delete browsing data, and block URLs. The extension's core functionality is appropriate for its stated purpose as a proxy switcher. It makes one external API call to testmyproxies.com to fetch geographic locations for proxy IPs, which is a reasonable feature for a proxy management tool.

The main security concern is the presence of advertising functionality that creates browser tabs to a proxy sales website (buyproxies.org/secret.html) based on usage patterns. While this is not malicious, it represents undisclosed commercial behavior that triggers after a certain number of proxy switches. The extension also requests powerful permissions including `<all_urls>`, `cookies`, `browsingData`, and `webRequest` which are appropriate for its proxy management functionality but create a large attack surface.

## Vulnerability Details

### 1. MEDIUM: Undisclosed Advertising Functionality

**Severity**: MEDIUM
**Files**: popup.js (lines 790-889)
**CWE**: CWE-506 (Embedded Malicious Code)
**Description**: The extension contains functionality that displays a "special offer" and can automatically open tabs to a commercial proxy sales website. This behavior is triggered after the user has set a proxy more than 10 times, is not using specific restricted ports (12345 or 4444), and within a 24-hour window from when the counter first triggers.

**Evidence**:
```javascript
function initSpecialOffer() {
    chrome.storage.local.get(
        {
            setProxyCount: 0,
            specialOfferDismissed: false,
            specialOfferStartTime: null,
            lastPort: null
        },
        function (res) {
            // dismissed permanently
            if (res.specialOfferDismissed) return;

            // not enough usage
            if (res.setProxyCount <= 10) return;

            // restricted ports
            if (res.lastPort === 12345 || res.lastPort === 4444) {
                return;
            }

            const now = Date.now();
            let startTime = res.specialOfferStartTime;
            // ... shows special offer UI
        }
    );
}

// Lines 834-839
const buyEl = document.getElementById("specialOfferBuy");
if (buyEl) {
    buyEl.onclick = function () {
        // Replace the URL with whatever landing page you want
        chrome.tabs.create({ url: "https://buyproxies.org/secret.html" });
    };
}
```

**Verdict**: This is not malicious code, but it represents monetization behavior that should be disclosed to users. The functionality only displays an offer UI after reasonable usage (10+ proxy switches) and does not automatically navigate without user interaction. However, users may not expect their proxy management extension to display proxy sales offers. This is rated MEDIUM because it represents undisclosed commercial behavior rather than a security vulnerability.

## False Positives Analysis

### Proxy Credential Handling
The extension extracts proxy credentials from proxy strings in the format `host:port:username:password` and uses them for proxy authentication (background.js lines 584-602). This is standard behavior for a proxy switcher and not credential theft.

### WebRTC IP Leak Protection
The extension can disable WebRTC to prevent IP leaks when using proxies (popup.js lines 363-369). This is a legitimate privacy protection feature.

### Browsing Data Deletion
The extension deletes cookies, cache, history, and other browsing data based on user configuration (background.js lines 536-579). This is core functionality for a proxy switcher to maintain anonymity and is clearly exposed in the UI.

### User-Agent Modification
The extension uses declarativeNetRequest to modify the User-Agent header (popup.js lines 371-403). This is expected behavior for a proxy/anonymity tool.

### External API Call
The single external fetch to `testmyproxies.com/_scripts/showLocations.php` (popup.js line 740) is legitimate - it fetches country/location data for the user's proxy IPs to display flags in the UI. The extension only sends IP addresses (which the user already provided) and receives location data.

### Content Script Injection
The extension does not inject any content scripts despite having `<all_urls>` permission. The permission is used for proxy authentication interception via webRequest.onAuthRequired.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| testmyproxies.com/_scripts/showLocations.php | Fetch geographic locations for proxy IPs | Proxy IP addresses (user-provided, joined with hyphens) | LOW - Legitimate feature to display country flags for proxies |
| buyproxies.org/secret.html | Commercial landing page | None (tab creation only, user-initiated) | LOW - Advertising destination, user must click to visit |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**: BP Proxy Switcher is a legitimate proxy management extension with appropriate functionality for its stated purpose. The code is clean, well-structured, and contains no credential theft, data exfiltration, or malicious behavior. The extension properly implements proxy switching, user-agent modification, browsing data deletion, and URL blocking features.

The MEDIUM risk rating is assigned due to:
1. **Undisclosed advertising functionality** - The extension displays proxy sales offers and can create tabs to a commercial website after usage thresholds, which is not clearly disclosed in the extension description
2. **Powerful permissions** - The extension requests `<all_urls>`, `cookies`, `browsingData`, and `webRequest` permissions which create a large attack surface, though these are appropriate for proxy management functionality
3. **Remote configuration potential** - While currently benign, the external API call to testmyproxies.com could theoretically be used for remote configuration

The extension does not engage in hidden data collection, credential theft, session hijacking, or other high-severity threats. Users who understand they are installing a proxy switcher and accept that it may contain commercial offers can use this extension safely. The advertising behavior, while not ideal from a transparency perspective, is relatively unintrusive (requires 10+ uses to trigger, shows a dismissible UI, requires user click to navigate).

For enterprise or high-security environments, the advertising functionality and powerful permissions may be unacceptable. For general users seeking proxy switching capabilities, this extension provides legitimate value with minor privacy/transparency concerns.
