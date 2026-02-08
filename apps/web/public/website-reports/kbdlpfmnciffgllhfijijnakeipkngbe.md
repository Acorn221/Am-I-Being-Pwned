# Vulnerability Report: Safum free VPN

## Extension Metadata
- **Extension ID**: kbdlpfmnciffgllhfijijnakeipkngbe
- **Name**: Safum free VPN
- **Version**: 1.2.5
- **Users**: ~30,000
- **Rating**: 3.3/5
- **Manifest Version**: 3

## Executive Summary

Safum free VPN is a straightforward Chrome extension that provides free VPN proxy functionality through the "Nucleus VPN" backend service (api.nucleusvpn.com). The extension operates as a legitimate free VPN service with standard proxy configuration capabilities. After comprehensive analysis, no malicious behavior, data exfiltration, or critical security vulnerabilities were identified.

The extension uses Google Analytics for telemetry, fetches proxy server lists from a remote API, and configures Chrome's proxy settings. All permissions are used appropriately for its stated VPN functionality. The extension injects a visual indicator on web pages to show VPN connection status.

## Permissions Analysis

### Declared Permissions
- `alarms` - Used for periodic analytics events (hourly)
- `scripting` - Used to inject content script on install
- `storage` - Used to store client ID for analytics and session data
- `proxy` - **Core functionality** - Required to configure VPN proxy settings
- `<all_urls>` - Required for content script injection and proxy functionality

### Permission Usage Assessment
All permissions are used appropriately for VPN functionality:
- **proxy**: Core feature - sets/clears proxy configuration
- **scripting**: Only used on install to inject content script into existing tabs
- **storage**: Minimal usage - only stores analytics identifiers
- **alarms**: Benign usage for analytics heartbeat

## Vulnerability Analysis

### No Critical or High Vulnerabilities Found

After thorough analysis of all scripts, no exploitable vulnerabilities, malicious code, or concerning data collection patterns were identified.

## Security Findings

### 1. Google Analytics Integration
**Severity**: INFO
**File**: `background.js` (lines 32-97)
**Code**:
```javascript
const E = "https://www.google-analytics.com/mp/collect"
this.measurement_id = L, this.api_secret = C
analytics("G-GBEHT0VY4P", "YQowCvA-RGWJRTD7WXC14Q");
```

**Analysis**: Standard Google Analytics 4 implementation with measurement protocol. Sends:
- Client ID (UUID stored in `chrome.storage.local`)
- Session ID (stored in `chrome.storage.session`)
- Event name and basic engagement metrics

**Verdict**: BENIGN - Standard telemetry for extension usage tracking. No PII collected.

---

### 2. Remote Proxy Configuration
**Severity**: INFO
**File**: `background.js` (lines 2422-2430, 1489)
**Code**:
```javascript
this.serverUrl = "https://api.nucleusvpn.com/api/proxy"
const C = await fetch(this.serverUrl);
L = (await C.json()).proxy_list;
```

**Analysis**: Fetches proxy server list from `api.nucleusvpn.com`. Response structure:
```json
{
  "proxy_list": [
    {"host": "20.210.113.32:8123", "country": "US", "quality": 4},
    {"host": "128.199.202.122:3128", "country": "SG", "quality": 3}
  ]
}
```

The extension:
1. Fetches list of proxy servers with country codes
2. Filters by selected country
3. Tests proxy connectivity via `ifconfig.me/ip`
4. Sets `chrome.proxy.settings` to route traffic through selected proxy

**Verdict**: BENIGN - Standard VPN operation. Servers are hosted by legitimate cloud providers.

---

### 3. IP Address Checking
**Severity**: INFO
**File**: `background.js` (lines 2474-2485, 1489)
**Code**:
```javascript
this.ipUrl = "https://ifconfig.me/ip"
const S = await fetch(this.ipUrl, { signal: C.signal });
L = await S.text();
```

**Analysis**: Uses `ifconfig.me/ip` to:
- Verify proxy connectivity during connection tests
- Display current external IP to user

**Verdict**: BENIGN - Standard practice for VPN extensions. ifconfig.me is a well-known public IP lookup service.

---

### 4. Content Script Visual Indicator
**Severity**: INFO
**File**: `content.js` (lines 901-918)
**Code**:
```javascript
document.addEventListener("DOMContentLoaded", (() => {
    const L = document.getElementById(`${t.browser.runtime.id}-img`);
    if (!L) {
        const C = `<img class='safum-vpn-status'
                    id='${t.browser.runtime.id}-img'
                    src='${chrome.runtime.getURL("/web_accessible_resources/status_on.png")}'
                    alt='status'>`;
        document.body.insertAdjacentHTML("beforeBegin", `${C}`);
    }
}))
```

**Analysis**:
- Injects PNG image indicator at top of every page
- Image is dynamically shown/hidden based on VPN connection status
- Uses runtime message passing to update visibility
- No DOM manipulation beyond indicator injection

**Verdict**: BENIGN - Simple visual feedback mechanism. No data access or exfiltration.

---

### 5. Proxy Configuration via PAC Script
**Severity**: INFO
**File**: `background.js` (lines 2436-2445)
**Code**:
```javascript
const S = {
    mode: "pac_script",
    pacScript: {
        data: `function FindProxyForURL(url, host) {
          if (dnsDomainIs(host,'${this.ipDomain}'))
            return 'PROXY ${L}';
          return 'DIRECT';
        }`
    }
}
```

**Analysis**: During proxy testing, uses PAC script to only route `ifconfig.me` traffic through proxy. This prevents test failures if proxy doesn't support general browsing. Actual VPN connection uses `fixed_servers` mode (lines 2459-2472).

**Verdict**: BENIGN - Smart implementation to test proxy connectivity before full activation.

---

### 6. Content Script Injection on Install
**Severity**: INFO
**File**: `background.js` (lines 1517-1527)
**Code**:
```javascript
chrome.runtime.onInstalled.addListener((async L => {
    if (L.reason === "install") {
        const L = await chrome.tabs.query({});
        for (const C of L) try {
            if (C.id) await chrome.scripting.executeScript({
                target: { tabId: C.id },
                files: [ "js/content.js" ]
            });
        } catch (L) {}
    }
}))
```

**Analysis**: On first install, injects content script into all existing tabs so VPN indicator appears immediately. This is a one-time operation.

**Verdict**: BENIGN - Standard practice for extensions with content scripts. Only injects the VPN status indicator.

## False Positive Analysis

| Pattern | Context | Reason for FP |
|---------|---------|---------------|
| `eval` (background.js:832, 1761) | webextension-polyfill library | Part of browser API polyfill, not dynamic code execution |
| `eval` (content.js:255) | webextension-polyfill library | Part of browser API polyfill, not dynamic code execution |
| `eval` (popup.js:2567, 3791, 4345, 5389) | jQuery library | Part of bundled jQuery 3.x, not exploitable in extension context |
| `removePasswords` (multiple files) | webextension-polyfill metadata | API definition for `chrome.browsingData`, not actual usage |
| `password` (popup.js:1393, 3858) | jQuery form handling | Standard HTML form type handling, not password collection |

## API Endpoints

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://api.nucleusvpn.com/api/proxy` | Fetch proxy server list | None (GET request) | LOW - Public endpoint |
| `https://ifconfig.me/ip` | Check external IP | None (GET request) | LOW - Public IP lookup service |
| `https://www.google-analytics.com/mp/collect` | Analytics telemetry | Client ID, session ID, event names | LOW - Standard GA4 telemetry |

## Data Flow Analysis

### Data Collection
- **Analytics Client ID**: UUID v4 generated and stored locally
- **Session ID**: Timestamp-based, stored in session storage
- **No browsing data**: Extension does NOT monitor, log, or transmit user browsing activity
- **No credentials**: Extension does NOT access passwords, cookies, or authentication tokens

### Data Transmission
1. **To api.nucleusvpn.com**: None (only receives proxy list)
2. **To ifconfig.me**: None (only receives IP address)
3. **To Google Analytics**: Anonymous usage events (install, run every 60 min)

### Data Storage
- **chrome.storage.local**: Analytics client ID only
- **chrome.storage.session**: Session timestamp for analytics
- **No user data persistence**: Extension does not store browsing history, credentials, or personal information

## Code Quality Notes

### Positive Aspects
- Uses Manifest V3 (modern, secure)
- Implements proper proxy bypass for API server domain
- Includes connectivity testing before activating proxy
- Uses AbortController for fetch timeout handling
- Error handling wraps proxy operations

### Neutral Aspects
- Bundled libraries (jQuery, webextension-polyfill, uuid, i18n-iso-countries)
- Minified/browserified code structure
- Uses Google Analytics (common for freeware)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification
Safum free VPN is a legitimate, functional VPN extension that:

1. **Serves its stated purpose**: Provides free proxy-based VPN functionality
2. **Minimal data collection**: Only anonymous analytics, no user data harvesting
3. **Transparent operation**: All network calls are to known, legitimate services
4. **Appropriate permissions**: All declared permissions are necessary and properly used
5. **No malicious indicators**:
   - No obfuscation beyond standard bundling
   - No credential harvesting
   - No ad injection
   - No extension enumeration/killing
   - No residential proxy infrastructure patterns
   - No remote code execution capabilities
   - No cookie/token theft
   - No keylogging or form interception

### Limitations of Free VPN Model
While technically clean, users should be aware:
- Free VPN services route all traffic through third-party proxies
- Proxy servers could theoretically inspect unencrypted traffic
- Connection quality depends on free proxy server reliability
- No independent audit of backend infrastructure

### Recommendation
**CLEAN** - Extension may be used, but users should understand inherent risks of routing traffic through free proxy servers. For sensitive activities, commercial VPN services with end-to-end encryption and audited infrastructure are recommended.

## Technical Notes

### Proxy Implementation
- Uses `chrome.proxy.settings` API with `fixed_servers` mode
- Configures single proxy for all protocols (HTTP/HTTPS)
- Implements bypass list for API server domain
- Tests connectivity before full activation

### Content Security Policy
- No CSP explicitly defined (defaults to Manifest V3 secure baseline)
- No remote script loading
- All code is bundled within extension package

### Build System
- Uses Browserify for module bundling
- Includes polyfills for cross-browser compatibility
- Bundles third-party libraries (jQuery 3.x, uuid 9.x)

---

**Analysis Date**: 2026-02-08
**Analyst**: Claude Opus 4.6 (Automated Security Analysis)
