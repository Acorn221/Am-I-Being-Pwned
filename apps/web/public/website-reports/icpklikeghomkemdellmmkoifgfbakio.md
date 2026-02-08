# Security Analysis Report: anonymoX

## Extension Metadata

- **Extension ID**: icpklikeghomkemdellmmkoifgfbakio
- **Name**: anonymoX
- **Version**: 1.7.8
- **Users**: ~300,000
- **Developer**: anonymox.net (German company)
- **Manifest Version**: 3

## Executive Summary

anonymoX is a VPN/proxy browser extension that provides legitimate proxy routing functionality through servers operated by anonymox.net. The extension communicates with backend services using Apache Thrift over HTTPS and manages proxy configurations via Chrome's proxy API. While the core functionality appears legitimate, there are several security concerns including disabled ad injection infrastructure, hardcoded API endpoints for third-party services, and use of innerHTML in UI rendering.

**Overall Risk Level**: **LOW**

The extension serves its intended purpose as a VPN/proxy service. The most concerning finding is dormant ad injection code that is currently disabled but could be activated remotely. The extension does not exhibit clear malicious behavior in its current state.

## Vulnerability Details

### 1. Dormant Ad Injection Infrastructure (MEDIUM Severity)

**Category**: ad_injection
**Severity**: MEDIUM
**Files**:
- `js/listener.js` (lines 17-53, 74-79, 158-183)
- `js/content_script.js`
- `js/ad_cache.js`

**Description**:
The extension contains infrastructure for ad injection that is currently disabled via the `ADS_ENABLED = false` flag. When enabled, this code would:
1. Inject content scripts into all web pages on navigation
2. Load ads from backend or cache
3. Communicate ad data to content scripts via message ports

**Evidence**:
```javascript
// js/listener.js:17-20
const ADS_ENABLED = false;
const AGL_CREATE_ARTICLE_ENDPOINT = "https://agentlemanslifestyle.com/wp-json/api/data";
const AGL_API_KEY = "safe-9e7h3845rc-shop";

// js/listener.js:74-79
if (ADS_ENABLED) {
  chrome.webRequest.onCompleted.addListener(webRequestListener, {
    urls: ["*://*/*"],
    types: ["main_frame"],
  });
}
```

**Verdict**: **CONFIRMED ISSUE** - While currently disabled, this infrastructure could be activated without code changes by flipping a configuration flag retrieved from the backend's `getInfo` response. The hardcoded endpoint to `agentlemanslifestyle.com` suggests planned commercial partnerships.

---

### 2. Hardcoded Third-Party API Credentials (LOW Severity)

**Category**: credential_exposure
**Severity**: LOW
**Files**: `js/listener.js` (line 20)

**Description**:
The extension contains a hardcoded API key for a third-party service (A Gentleman's Lifestyle website).

**Evidence**:
```javascript
const AGL_API_KEY = "safe-9e7h3845rc-shop";
```

**Verdict**: **CONFIRMED ISSUE** - Hardcoded credentials are a security risk as they're visible in the extension code. However, this appears to be a low-privilege API key for a currently unused feature.

---

### 3. innerHTML Usage Without Sanitization (LOW Severity)

**Category**: xss
**Severity**: LOW
**Files**:
- `js/ui/popup.js` (line 74)
- `js/ui/country_list.js` (line 20)
- `js/ui/gateway_list.js` (line 98)

**Description**:
The extension uses `innerHTML` to render UI elements, including i18n messages and dynamic content.

**Evidence**:
```javascript
// js/ui/popup.js:74
el.innerHTML = text;

// js/ui/country_list.js:20
this.countrySelectItems.innerHTML = "";

// js/ui/gateway_list.js:98
this.idList.innerHTML = "";
```

**Verdict**: **FALSE POSITIVE** - Analysis shows:
1. Most innerHTML usage is for clearing containers (`innerHTML = ""`)
2. i18n message injection uses Chrome's built-in `chrome.i18n.getMessage()` which is safe
3. Dynamic UI elements are constructed using `createElement()` and DOM manipulation, not string concatenation
4. No user-controlled input is directly inserted via innerHTML

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `innerHTML` | `js/ui/popup.js:74` | Uses Chrome's i18n API which is safe - content comes from manifest locales, not user input |
| `innerHTML = ""` | `js/ui/*.js` | Clearing containers only, no injection risk |
| jQuery library | `js/libs/jquery-3.7.1.min.js` | Standard library, not a vulnerability |
| `postMessage` | Multiple files | Legitimate extension messaging between background/popup/content scripts |
| `chrome.storage` | Multiple files | Standard extension storage API for credentials/settings |

## API Endpoints & Network Communication

| Domain/Endpoint | Purpose | Protocol | Risk |
|----------------|---------|----------|------|
| `master.anonymox.net/chrome` | Main backend API (Thrift RPC) | HTTPS | Low |
| `sc.nwi.anonymox.net` | Self-check/auth ping | HTTP/HTTPS | Low |
| `nwi.anonymox.net` | Network info service | HTTP | Low |
| `anonymox.net/*` | Website integration (premium activation) | HTTPS | Low |
| `agentlemanslifestyle.com/wp-json/api/data` | Dormant ad API (unused) | HTTPS | Medium |

**Communication Patterns**:
- Uses Apache Thrift over HTTPS for RPC communication
- Sends user credentials (username/password) to backend for authentication
- Receives gateway list, premium status, and configuration
- No evidence of unauthorized data exfiltration
- Periodic 15-minute check-in for updated gateway list

## Data Flow Summary

### Data Collection
- **User Credentials**: Username/password stored in `chrome.storage.local`, sent to backend for authentication
- **Extension State**: VPN on/off status, selected gateway, country filter
- **User Metadata**: Browser version, OS type, locale sent during API calls
- **Safelist**: Domains user whitelists for direct connection (stored locally)

### Data Storage
- **Local Storage**: Credentials, premium status, external IP info, safelist
- **Session Storage**: Active gateway, VPN enabled status, country filter, gateway list

### Data Transmission
- All network requests to `master.anonymox.net` use Thrift binary protocol over HTTPS
- Credentials transmitted on every API call for authentication
- No third-party analytics or tracking detected
- No cookie harvesting or browsing history collection

## Permissions Analysis

### Declared Permissions
- `scripting` - Used for premium activation content script on anonymox.net
- `storage` - Legitimate credential/settings storage
- `proxy` - Core VPN functionality via PAC script
- `webRequest` + `webRequestAuthProvider` - Proxy authentication
- `declarativeNetRequest` - Adds capability header for anonymox.net requests
- `alarms` - 15-minute periodic gateway refresh
- `activeTab`, `offscreen` - Standard UI permissions
- `unlimitedStorage` - For gateway lists and cache
- `host_permissions: <all_urls>` - Required for proxy to work on all sites

### Permission Justification
All permissions are appropriate for a VPN/proxy extension except for the dormant ad injection infrastructure which would misuse the `scripting` and `host_permissions`.

## Notable Behaviors

### Legitimate VPN Functionality
1. **Proxy Configuration**: Uses PAC (Proxy Auto-Config) scripts to route traffic
2. **Selective Routing**: Bypasses local networks, anonymox.net, and private IPs
3. **Gateway Selection**: Allows country/server selection with quality scoring
4. **Premium Support**: Activation code system for premium gateways
5. **Self-Check**: Pings proxy servers to verify connectivity before activation

### Concerning Patterns
1. **Remote Configuration**: Backend could theoretically enable ad injection by returning different config
2. **Uninstall Tracking**: Sets uninstall URL to `anonymox.net/[locale]/safeshop/uninstall/`
3. **Commented Code**: References to "SafeShop" feature suggest additional monetization plans

## Security Recommendations

### For Users
1. Extension appears safe for use as a basic VPN/proxy service
2. Be aware that ad injection infrastructure exists but is currently disabled
3. Monitor extension updates for changes to ad injection flag
4. Credentials are sent to anonymox.net servers - trust in the provider required

### For Developers
1. Remove dormant ad injection code entirely if not intended for use
2. Implement proper Content Security Policy
3. Replace innerHTML with safer alternatives (textContent, createElement)
4. Remove hardcoded API credentials
5. Implement certificate pinning for master.anonymox.net
6. Add code signing/integrity checks to prevent tampering

## Overall Risk Assessment

**Risk Level**: **LOW**

### Justification
- Core functionality is legitimate VPN/proxy service
- No active malicious behavior detected
- No unauthorized data collection or exfiltration
- Dormant ad injection is concerning but not currently active
- Extension serves its stated purpose transparently
- Developed by established German company (anonymox.net)

### Key Concerns
1. **Ad Injection Infrastructure**: Could be activated remotely without user consent
2. **Credential Transmission**: Username/password sent to backend servers (inherent to service model)
3. **Broad Permissions**: `host_permissions: <all_urls>` required for VPN but could be abused

### Mitigating Factors
- MV3 implementation limits abuse potential
- Ad injection currently disabled and would require explicit activation
- No evidence of privacy violations or data theft
- Transparent about being a proxy service
- German privacy law compliance likely (EU-based developer)

## Conclusion

anonymoX is a functional VPN/proxy extension with legitimate use cases. The primary security concern is the presence of disabled ad injection infrastructure that references third-party commercial partnerships. In its current state (v1.7.8), the extension does not exhibit malicious behavior and appears to operate as advertised. However, users should be aware that the codebase contains dormant advertising features that could potentially be activated in future updates.

The extension is **CLEAN** with **LOW** risk based on current behavior, but warrants monitoring for future changes to the `ADS_ENABLED` flag or activation of the SafeShop/ad injection features.
