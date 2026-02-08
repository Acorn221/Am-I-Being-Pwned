# Security Analysis Report: Ishaan VPN

## Extension Metadata

- **Extension Name**: Ishaan VPN
- **Extension ID**: ooocanibackdgkbjkoedhljnjkpfaafe
- **Version**: 0.0.1
- **Author**: Ishaan Garg
- **User Count**: ~0 users
- **Permissions**: proxy, storage, alarms
- **Host Permissions**: `<all_urls>`

## Executive Summary

Ishaan VPN is a basic free VPN Chrome extension that proxies traffic through servers provided by `api.nucleusvpn.com`. The extension includes analytics tracking via Google Analytics and fetches remote configuration from `api1.extinsight.com` that controls install/update/uninstall URLs. While the core VPN functionality appears legitimate, the extension's remote configuration capability presents a low-risk concern as it could be used to inject arbitrary URLs into user tabs. The extension has zero users and appears to be a white-label implementation of a VPN service.

**Overall Risk Level**: LOW

## Vulnerability Analysis

### LOW-001: Remote Configuration URL Injection

**Severity**: LOW
**Files**: `/deobfuscated/js/background.js` (lines 786-826)
**Category**: remote_config

**Description**:
The extension fetches remote configuration from `https://api1.extinsight.com/api/urls/${chrome.runtime.id}` that controls which URLs are opened when the extension is installed, updated, or uninstalled. This configuration is cached in storage but is fetched remotely on each startup.

**Code Evidence**:
```javascript
// Line 786-805: Remote config fetch
const Hq = `https://api1.extinsight.com/api/urls/${chrome.runtime.id}`;
try {
  const rO = await fetch(Hq);
  if (404 === rO.status)
    return (
      chrome.storage &&
        chrome.storage.local.set({ [cJ]: {}, [ld]: +new Date() }),
      {}
    );
  if (rO.ok) {
    const fx = await rO.json();
    return (
      chrome.storage &&
        chrome.storage.local.set({ [cJ]: fx, [ld]: +new Date() }),
      fx
    );
  }
} catch (rO) {}

// Line 810-825: Tab creation based on remote config
chrome.runtime.onInstalled.addListener(async (fO) => {
  const cJ = await rO();
  "install" === fO.reason
    ? (null == cJ ? void 0 : cJ.installURL) &&
      (await chrome.tabs.create({ url: fx(cJ.installURL) }))
    : "update" === fO.reason
    ? (null == cJ ? void 0 : cJ.updateURL) &&
      (await chrome.tabs.create({ url: fx(cJ.updateURL) }))
    : "chrome_update" === fO.reason &&
      (null == cJ ? void 0 : cJ.browserUpdateURL) &&
      (await chrome.tabs.create({ url: fx(cJ.browserUpdateURL) }));
});

// Uninstall URL
const fO = await rO();
(null == fO ? void 0 : fO.uninstallURL) &&
  chrome.runtime.setUninstallURL(fx(fO.uninstallURL));
```

**Impact**:
If the remote server is compromised or the developer becomes malicious, arbitrary URLs could be injected and opened in user tabs during install/update events. URL templates support `{crx_id}` and `{crx_version}` substitution. However, the risk is limited since:
- The extension has 0 users
- Opening tabs is visible to users
- No sensitive data is exfiltrated via these URLs

**Verdict**: LOW - Standard monetization mechanism for free extensions, but does create dependency on third-party remote configuration.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| webextension-polyfill | content.js, background.js, popup.js | Standard Mozilla WebExtension polyfill library for cross-browser compatibility |
| UUID library | background.js | Standard uuid.js library for generating unique identifiers for analytics |
| MD5/SHA1 hashing | background.js | Part of uuid.js library for v3/v5 UUID generation |
| Proxy objects | content.js, background.js | WebExtension polyfill uses Proxy for API wrapping |
| Google Analytics | background.js (line 69) | Standard Google Analytics (GA3) tracking - sends pageview to `www.google-analytics.com/collect` |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://api.nucleusvpn.com/api/proxy` | Fetch VPN proxy server list | None | Low - Core VPN functionality |
| `https://ifconfig.me/ip` | Check public IP address | None | None - Public IP check service |
| `https://api1.extinsight.com/api/urls/{extension_id}` | Fetch install/update/uninstall URLs | Extension ID (in URL path) | Low - Remote config capability |
| `https://www.google-analytics.com/collect` | Analytics tracking | Client ID (UUID), pageview data, extension ID | Low - Standard analytics |

## Data Flow Analysis

### VPN Connection Flow
1. Extension fetches proxy server list from `api.nucleusvpn.com/api/proxy`
2. Servers are filtered by country and sorted by quality
3. Each proxy is tested by setting PAC script for `ifconfig.me` domain only
4. If proxy responds successfully to `ifconfig.me/ip`, it's set as the active proxy
5. Active proxy is configured with bypass list for `*api.nucleusvpn.com*`

### Analytics Flow
1. On background script initialization, Google Analytics tracking fires
2. Generates or retrieves client ID (UUID) from storage
3. Sends pageview to Google Analytics with extension ID in domain header
4. Alarm is set to ping GA every 24 hours

### Remote Configuration Flow
1. On startup, fetch configuration from `api1.extinsight.com/api/urls/{id}`
2. If 404, store empty config; if success, cache JSON response
3. On install/update events, open tabs to URLs specified in config
4. On init, set uninstall URL from config

## Content Script Analysis

**File**: `/deobfuscated/js/content.js` (626 lines)

**Injection Scope**:
- Matches: `http://*/*`, `https://*/*`
- All frames: Yes
- Match about:blank: Yes
- Run at: `document_start`

**Behavior**:
The content script is minimal and only injects a VPN status indicator image:
- Injects a status image (`/web_accessible_resources/status_on.png`) into the page DOM
- Listens for messages from background script to toggle indicator visibility via CSS class
- Image is inserted at `beforeBegin` position relative to document.body
- Uses extension ID to ensure unique element ID

**Security Notes**:
- No DOM manipulation beyond inserting a single image element
- No data collection from pages
- No message passing to external domains
- No XSS risk - image URL is from chrome.runtime.getURL()

## Permissions Analysis

| Permission | Justification | Risk |
|------------|---------------|------|
| proxy | Required for VPN functionality - sets proxy configuration | Justified |
| storage | Used to cache analytics CID and remote config | Justified |
| alarms | Used for 24-hour GA ping interval | Justified |
| `<all_urls>` | Required for content script status indicator injection | Overly broad - could use activeTab instead |

## Manifest Security

**Content Security Policy**: Not defined (uses MV3 defaults)
**Web Accessible Resources**: `web_accessible_resources/status_on.png` - Low risk

## Known Security Issues

None detected.

## Suspicious Patterns Not Found

- No extension enumeration/killing
- No XHR/fetch hooking
- No residential proxy infrastructure indicators (beyond being a VPN service)
- No market intelligence SDKs
- No AI conversation scraping
- No ad/coupon injection
- No keylogging
- No cookie harvesting beyond standard storage API usage
- No SDK injection
- No dynamic eval() or Function() calls
- No obfuscation beyond standard minification

## Third-Party Dependencies

- **NucleusVPN Service** (`api.nucleusvpn.com`) - VPN proxy provider
- **ExtInsight** (`api1.extinsight.com`) - Remote configuration service
- **Google Analytics** (`www.google-analytics.com`) - Usage analytics
- **uuid.js** - UUID generation library (bundled)
- **webextension-polyfill** - Browser API polyfill (bundled)

## Recommendations

1. **Reduce Host Permissions**: Replace `<all_urls>` with `activeTab` if possible, since content script only shows status indicator
2. **Local Configuration**: Consider bundling install/update URLs in manifest rather than fetching remotely
3. **CSP Header**: Add explicit Content-Security-Policy to manifest
4. **Privacy Policy**: Disclose data collection (analytics, IP checks) to users

## Overall Risk Assessment

**RISK LEVEL: LOW**

This extension is a basic, white-label VPN implementation with minimal security concerns. The remote configuration capability is the primary risk vector, but given the extension has 0 users and the functionality is limited to opening tabs (which is user-visible), the risk remains low. The core VPN functionality appears legitimate and uses standard proxy APIs. No malicious behavior detected.

The extension would be classified as **CLEAN** if:
- Remote configuration was removed or hardcoded
- Host permissions were reduced to activeTab
- The extension had actual users and legitimate use

As currently configured, it's a **LOW** risk due to the remote config dependency and overly broad permissions, despite having no clear malicious intent.
