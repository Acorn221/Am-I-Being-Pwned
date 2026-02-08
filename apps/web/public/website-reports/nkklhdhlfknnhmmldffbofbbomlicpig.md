# Vulnerability Report: Snap VPN

## Extension Metadata
- **Extension ID**: nkklhdhlfknnhmmldffbofbbomlicpig
- **Name**: Snap VPN
- **Version**: 0.3.13
- **Users**: ~50,000
- **Rating**: 3.7/5
- **Manifest Version**: 3

## Executive Summary

Snap VPN is a basic VPN extension that routes user traffic through HTTP proxies obtained from a third-party API (api.nucleusvpn.com). The extension demonstrates standard VPN functionality with proxy configuration capabilities. Analysis reveals **no critical security vulnerabilities or malicious behavior**. The extension operates transparently as a proxy service with Google Analytics telemetry. All flagged code patterns (innerHTML, eval) are contained within legitimate third-party libraries (jQuery, webextension-polyfill) and pose no security risk.

**Overall Risk Assessment: LOW**

The extension functions as advertised without evidence of data exfiltration, malicious injection, or privacy violations beyond standard VPN proxy functionality.

## Permissions Analysis

### Declared Permissions
- `alarms` - Used for Google Analytics periodic events (hourly heartbeat)
- `scripting` - Used to inject content script on install
- `storage` - Used for storing client ID, session data, and user preferences (indicator setting)
- `proxy` - **Core functionality** - Required for VPN proxy configuration
- `host_permissions: <all_urls>` - Required for proxy to route all traffic

### Permission Risk Assessment
All permissions are **justified and necessary** for VPN functionality. The `<all_urls>` permission is required for the proxy to intercept and route traffic through VPN servers.

## Vulnerability Findings

### CLEAN - No Security Vulnerabilities Detected

After comprehensive analysis of background.js, content.js, and popup.js, **no exploitable vulnerabilities were identified**.

## Code Analysis

### Background Script Analysis (`js/background.js`)

**Key Functionality:**
1. **Proxy Management** (lines 2503-2656):
   - Fetches proxy list from `https://api.nucleusvpn.com/api/proxy`
   - Tests proxy connectivity via PAC script to `ifconfig.me`
   - Configures `chrome.proxy.settings` with fixed_servers mode
   - Bypasses proxy for `*api.nucleusvpn.com*` (reasonable for API access)

2. **Connection State Management**:
   - Tracks connection status (NotConnected, Connecting, Cancelling, Connected, Unknown)
   - Implements connection retry logic with quality-based proxy selection
   - No kill switch or remote config detected

3. **Analytics Integration** (lines 32-106):
   - Google Analytics (G-TCJ03YV7TR) via `https://www.google-analytics.com/mp/collect`
   - Tracks: extension run events (hourly), page views, errors
   - Stores UUID client ID in chrome.storage.local
   - **Privacy Impact**: Standard analytics, no PII collection detected

4. **Content Script Injection** (lines 1600-1611):
   - On install, injects `js/content.js` into existing tabs
   - Standard practice to enable indicator on existing tabs

**Security Assessment**: Clean. Standard VPN proxy implementation.

### Content Script Analysis (`js/content.js`)

**Functionality:**
- Inserts visual indicator image (`web_accessible_resources/status_on.png`) into page DOM
- Uses `insertAdjacentHTML("beforeBegin")` to inject `<img>` element with extension runtime ID
- Listens for `updateIndicator` messages to toggle visibility via CSS class
- **No data extraction, no page content manipulation beyond indicator**

**Security Assessment**: Benign. Only visual indicator injection.

### Popup Script Analysis (`js/popup.js`)

**Functionality:**
- jQuery 3.x library (detected innerHTML usage is jQuery DOM manipulation - **false positive**)
- UI for country selection, connect/disconnect actions
- Fetches user IP via `ifconfig.me/ip` for display
- Manages indicator checkbox preference in storage

**Security Assessment**: Clean. Standard UI code with bundled jQuery.

### Network Endpoints

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://api.nucleusvpn.com/api/proxy` | Fetch VPN proxy list | LOW - Third-party dependency |
| `https://ifconfig.me/ip` | Display user's current IP | LOW - Public IP check service |
| `https://www.google-analytics.com/mp/collect` | Analytics telemetry | LOW - Standard analytics |
| `https://clients2.google.com/service/update2/crx` | Chrome update URL (manifest) | NONE - Standard CWS |

### Data Flow Summary

**Data Collected:**
- Google Analytics: UUID client ID, session ID, extension events (no PII)
- Local Storage: indicator preference (boolean)

**Data Transmitted:**
- To Google Analytics: Anonymous usage events
- To ifconfig.me: HTTP GET request (receives IP)
- To api.nucleusvpn.com: HTTP GET request (receives proxy list)

**Proxy Traffic:**
- All user HTTP/HTTPS traffic routed through selected proxy server
- Standard VPN behavior - expected and disclosed

**No evidence of**:
- Cookie harvesting
- Form data interception
- Credential theft
- Browser history exfiltration
- Cross-site tracking beyond GA

## False Positive Analysis

| Pattern | Location | Verdict |
|---------|----------|---------|
| `innerHTML` | popup.js (multiple) | **FALSE POSITIVE** - jQuery 3.x DOM manipulation library code |
| `innerHTML` | content.js line 942 | **FALSE POSITIVE** - Static SVG injection for indicator, no user data |
| `eval` | background.js, popup.js, content.js | **FALSE POSITIVE** - Part of webextension-polyfill devtools API metadata, never executed |
| `insertAdjacentHTML` | content.js line 942 | **FALSE POSITIVE** - Injects static `<img>` tag with hardcoded source |
| Host permission `<all_urls>` | manifest.json | **JUSTIFIED** - Required for proxy to intercept all traffic |

## Content Security Policy

**Manifest CSP**: None specified (defaults to MV3 strict CSP)

**Analysis**: MV3 default CSP prevents:
- Inline scripts
- `eval()` and `new Function()`
- Remote script loading

The bundled code complies with MV3 CSP requirements.

## Third-Party Dependencies

1. **webextension-polyfill** - Mozilla's official Chrome API wrapper
2. **UUID library** - Standard RFC4122 UUID generation
3. **jQuery 3.x** - Bundled in popup.js for UI
4. **Google Analytics** - Official GA4 Measurement Protocol

All dependencies are legitimate and widely used.

## Privacy Considerations

1. **VPN Traffic Routing**: User traffic is routed through third-party proxies from nucleusvpn.com
   - This is **expected VPN behavior** and disclosed in the extension's purpose
   - Proxy servers can see plaintext HTTP and SNI of HTTPS traffic
   - Standard risk for any VPN/proxy service

2. **Analytics**: Minimal telemetry to Google Analytics (extension usage only, no browsing data)

3. **No Excessive Data Collection**: Extension does not harvest cookies, credentials, or browsing history

## Recommendations

**For Users:**
- Understand that proxy operators can potentially monitor traffic (standard VPN limitation)
- Review privacy policy of nucleusvpn.com for proxy data handling practices

**For Developers:**
- Consider adding explicit privacy policy link in extension
- Consider adding kill switch to prevent traffic leaks on proxy disconnect

## Overall Risk Assessment

**RISK LEVEL: LOW**

**Justification:**
- Functions as advertised (VPN proxy service)
- No malicious code detected
- No data exfiltration beyond expected VPN functionality
- Standard analytics implementation
- All permissions justified
- No evidence of tracking, injection, or credential theft

**Verdict: CLEAN**

This extension is a legitimate VPN service with standard proxy functionality. While users should understand the inherent privacy implications of routing traffic through third-party proxies (true for ALL VPN services), there is no evidence of malicious behavior or security vulnerabilities in the extension code itself.
