# Vulnerability Report: PureVPN Proxy - Best VPN for Chrome

## Metadata
- **Extension ID**: bfidboloedlamgdmenmlbipfnccokknp
- **Extension Name**: PureVPN Proxy - Best VPN for Chrome
- **Version**: 4.37.5
- **Users**: ~300,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

PureVPN Proxy is a legitimate VPN extension by GZ Systems Ltd. The extension provides standard VPN functionality including proxy configuration, country/city server selection, WebRTC leak protection, and GPS location spoofing. The code is well-structured and clearly documented with copyright headers identifying GZ Systems Ltd. as the developer.

The extension uses chrome.management.getAll() to enumerate installed extensions, which is standard behavior for VPN extensions that need to detect conflicting proxy extensions. All network communication is directed to legitimate PureVPN infrastructure domains. The extension fetches remote configuration for server lists, streaming channel configurations, and campaign banners, which is expected behavior for a commercial VPN service.

## Vulnerability Details

### 1. LOW: Remote Configuration Fetching
**Severity**: LOW
**Files**: library/proxy.js, library/popup_campaign.js, library/banner_campaign.js, config/constant.js
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
**Description**: The extension fetches configuration data from remote endpoints including country lists, city lists, channel lists, tooltip configurations, and campaign popup/banner data. This is standard practice for commercial VPN services that need to update server lists and UI elements without requiring extension updates.

**Evidence**:
```javascript
// config/constant.js
const API_COUNTRIES_LIST = 'https://purevpn-extension.servermild.com/ext_countries.json';
const API_CITIES_LIST = 'https://purevpn-extension.servermild.com/ext_cities.json';
const API_CHANNELS_LIST = 'https://purevpn-extension.servermild.com/ext_channels.json';
const API_TOOLTIP = SCHEME_SSL + PROXY_API_ENDPOINT + '/v3/proxy/premium/meta';
const API_CAMPAIGN = SCHEME_SSL + PROXY_API_ENDPOINT + '/v3/proxy/premium/popup';
const API_BANNER = SCHEME_SSL + PROXY_API_ENDPOINT + '/v3/proxy/premium/banner';

// library/proxy.js - Country list fetching
pVn.uri.request(API_COUNTRIES_LIST, onCountriesList);

// library/proxy.js - Tooltip fetching
pVn.uri.request(API_TOOLTIP, onToolTipDetails);
```

**Verdict**: This is expected behavior for a commercial VPN service. The remote configuration allows PureVPN to update server locations and promotional content without requiring users to update the extension. All endpoints are HTTPS and belong to PureVPN's infrastructure.

## False Positives Analysis

### Extension Enumeration (chrome.management)
The extension uses `chrome.management.getAll()` to enumerate installed extensions:

```javascript
// library/proxy.js:741
chrome.management.getAll(getExtensionsList);

// library/messenger.js:565-572
chrome.management.onEnabled.addListener(function(oExtensionInfo) {
  pVn.getExtensionDetails(oExtensionInfo, false);
});
chrome.management.onDisabled.addListener(function(oExtensionInfo) {
  pVn.getExtensionDetails(oExtensionInfo, true);
});
```

This behavior is NOT malicious for the following reasons:
1. **Legitimate use case**: VPN extensions need to detect other proxy/VPN extensions to prevent conflicts and inform users about control issues
2. **User experience**: The extension shows warnings when another extension controls the proxy settings (levelOfControl)
3. **Standard practice**: This is documented behavior in VPN extensions to ensure only one proxy is active at a time
4. **Context**: The code checks for proxy control conflicts, not harvesting extension lists for fingerprinting

The extension displays messages like "Please disable the proxy service listed below to use PureVPN Extension" when conflicts are detected, which is helpful user guidance.

### GPS Location Spoofing
The extension includes GPS location spoofing functionality:

```javascript
// assets/js/content_location.js
chrome.storage.local.get(["latitude", "longitude", "locationSpoofing"],
  function(storage) {
    if (storage.locationSpoofing &&
      storage.latitude && storage.longitude
    ) {
      var script = document.createElement("script");
      script.src = chrome.runtime.getURL('assets/js/script.js?') +
        new URLSearchParams({longitude: storage.longitude, latitude: storage.latitude});
      (document.head || document.documentElement).appendChild(script);
    }
  });

// assets/js/script.js
navigator.geolocation.getCurrentPosition = (fn) => {
  setTimeout(() => {
    fn({
      coords: {
        accuracy: 10,
        latitude: latitude,
        longitude: longitude,
      },
      timestamp: Date.now(),
    })
  }, 2912)
};
```

This is NOT malicious because:
1. **Opt-in feature**: Only active when user explicitly enables "locationSpoofing" setting
2. **Privacy enhancement**: Designed to protect user privacy by faking GPS location to match VPN server location
3. **Transparent**: Listed in UI as "Spoof GPS Location" with description "Fake your GPS location to manipulate hackers and phishers while connected to VPN"
4. **Standard VPN feature**: Many VPN services offer location spoofing to prevent GPS-based tracking

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| auth.purevpn.com | OAuth authentication (FusionAuth) | User credentials, OAuth tokens | Low - Standard auth flow |
| api.proxy.purevpn.com | Main API endpoint | Access tokens, user preferences, connection logs | Low - Legitimate service |
| d2s1wxofuvqhy8.cloudfront.net | CloudFront domain fronting | Same as api.proxy.purevpn.com | Low - CDN for censorship circumvention |
| api.purevpn.com | Gateway API | Subscription verification, IP release | Low - Account management |
| purevpn-extension.servermild.com | Configuration CDN | None (GET only) | Low - Server list updates |
| auth.puresquare.com | Primary SSO endpoint | OAuth flows | Low - Corporate SSO |
| connecttossowin.com | Secondary SSO endpoint | OAuth flows | Low - Fallback SSO |
| my.purevpn.com | Member area | Auto-login tokens | Low - Account portal |

**Domain Fronting Note**: The extension uses CloudFront domain fronting (`d2s1wxofuvqhy8.cloudfront.net`) as an alternative to `api.proxy.purevpn.com` when `use_cloudfront_domain` is enabled. This is a legitimate censorship circumvention technique used by VPN services in restricted regions.

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification**:
PureVPN is a legitimate commercial VPN extension by GZ Systems Ltd. with ~300,000 users. The extension's use of chrome.management API is standard practice for VPN extensions to detect and warn about proxy conflicts. The remote configuration fetching is expected behavior for maintaining up-to-date server lists and promotional content. All network communication occurs over HTTPS to legitimate PureVPN infrastructure. The GPS location spoofing is an opt-in privacy feature clearly disclosed to users. The code is well-documented with copyright notices and follows standard VPN extension patterns. No evidence of malicious data exfiltration, credential theft, or undisclosed tracking was found.

The only minor concern is the remote configuration mechanism, which could theoretically be used to inject malicious content if PureVPN's servers were compromised. However, this is a standard trade-off for commercial VPN services that need to update server lists dynamically, and PureVPN is an established commercial entity with reputation incentives to maintain security.
