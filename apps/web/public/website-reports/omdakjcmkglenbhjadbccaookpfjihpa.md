# TunnelBear VPN - Security Analysis Report

## Metadata
- **Extension Name**: TunnelBear VPN
- **Extension ID**: omdakjcmkglenbhjadbccaookpfjihpa
- **Version**: 4.1.0
- **User Count**: ~1,000,000
- **Manifest Version**: 3
- **Publisher**: TunnelBear Inc.
- **Analysis Date**: 2026-02-08

## Executive Summary

TunnelBear VPN is a legitimate commercial VPN browser extension from a well-established privacy company (acquired by McAfee in 2018). The extension provides comprehensive VPN functionality with appropriate security implementations including kill switches, proxy authentication, and privacy-enhancing features (GhostBear, VigilantBear, Split tunneling).

**Overall Risk Level: CLEAN**

While the extension requires extensive permissions typical for a VPN service, all functionality aligns with its stated purpose. The code demonstrates professional security practices including proper authentication flows, error handling, server rotation on failures, and legitimate data handling. No malicious behavior, data exfiltration, or exploitation attempts were identified.

## Permissions Analysis

### Granted Permissions
- `proxy` - Required for VPN functionality
- `storage` - Legitimate user settings/state management
- `declarativeNetRequest` - Used for kill switch implementation
- `webRequest` - Proxy authentication handling
- `privacy` - WebRTC leak prevention, network prediction control
- `management` - Conflict detection with other proxy extensions
- `webRequestAuthProvider` - Proxy server authentication
- `<all_urls>` - Required for routing all traffic through VPN

### Justification
All permissions are essential for VPN operation. The `<all_urls>` permission is necessary to route user traffic through the VPN proxy servers. The privacy and webRequest permissions are used for security enhancements like WebRTC leak protection.

## Vulnerability Analysis

### No Critical or High Severity Issues Found

After comprehensive analysis of the codebase, no critical vulnerabilities, malicious code, or security exploits were identified.

## Security Features (Positive Findings)

### 1. Kill Switch Implementation
**Files**: `src/service-worker.js` (lines 303-377)
- **Chrome Implementation**: Uses `declarativeNetRequest` API to block all traffic except whitelisted domains when VPN disconnects unexpectedly
- **Firefox Implementation**: Sets invalid proxy configuration to prevent traffic leakage
- **Whitelisted Domains**: `localhost`, `127.0.0.1`, `*.lazerpenguin.com`, `*.tunnelbear.com`, `*.polargrizzly.com`, `*.googleapis.com`
- **Verdict**: Properly implemented kill switch to prevent IP leaks on VPN disconnection

```javascript
async activateChromeKillSwitch() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    addRules: [this.createBlockAllRule()],
    removeRuleIds: [this.KILL_SWITCH_RULE_ID]
  });
}

createBlockAllRule() {
  return {
    id: this.KILL_SWITCH_RULE_ID,
    priority: 1,
    action: { type: chrome.declarativeNetRequest.RuleActionType.BLOCK },
    condition: {
      urlFilter: "*",
      resourceTypes: Object.values(chrome.declarativeNetRequest.ResourceType),
      excludedDomains: this.ALLOWED_DOMAINS,
      excludedRequestMethods: [chrome.declarativeNetRequest.RequestMethod.OPTIONS]
    }
  };
}
```

### 2. WebRTC Leak Prevention
**Files**: `src/service-worker.js` (lines 277-292)
- Configures `webRTCIPHandlingPolicy` to prevent IP leaks
- Firefox: Sets to `proxy_only`
- Chrome/Edge: Sets to `disable_non_proxied_udp`
- Disables network prediction to prevent DNS leaks

```javascript
privacySettingEnable() {
  y.network.webRTCIPHandlingPolicy.set({
    value: "disable_non_proxied_udp"  // Chrome
  });
  y.network.networkPredictionEnabled.set({ value: !1 });
}
```

### 3. Proxy Authentication with Retry Logic
**Files**: `src/service-worker.js` (lines 391-434)
- Implements auth retry mechanism with max 5 attempts
- Uses VPN token from backend for proxy server authentication
- Properly handles auth failures and triggers server rotation

```javascript
setProxyAuthListener() {
  chrome.webRequest.onAuthRequired.addListener(async (e, t) => {
    let i = e.challenger.host;
    if (!i.endsWith(".lazerpenguin.com")) return { cancel: !0 };

    if (this.authAttempts >= this.MAX_AUTH_ATTEMPTS) {
      await this.onProxyError();
      return { cancel: !0 };
    }

    const vpn_token = (await o.getItem(g.PB_USER_INFO))?.vpn_token;
    return vpn_token ? {
      authCredentials: { username: vpn_token, password: vpn_token }
    } : { cancel: !0 };
  });
}
```

### 4. Server Rotation on Failure
**Files**: `src/service-worker.js` (lines 490-503, 587-600)
- Automatically rotates to next available VPN server on connection failures
- Implements retry logic (5 attempts per server) before rotating
- Prevents service disruption from individual server failures

### 5. Split Tunneling (SplitBear)
**Files**: `src/service-worker.js` (lines 294-302, 458-474)
- Allows users to bypass VPN for specific domains
- Implements PAC script with domain whitelist
- Properly validates and manages bypass rules

### 6. GhostBear Feature
**Files**: `src/service-worker.js` (lines 208-214)
- Obfuscation mode that routes through AWS Lambda endpoint
- Changes API endpoint: `api.polargrizzly.com` → `w6wgmwa4bd.execute-api.us-east-1.amazonaws.com/prod/polarbear`
- Designed to bypass VPN blocking in restrictive networks

## Authentication Flow

### TunnelBear Backend Authentication
1. Retrieves CSRF token from `/core/csrf`
2. Exchanges cookie token for JWT via `/v2/cookieToken`
3. Stores JWT in `chrome.storage.local` as `TB_AUTH_TOKEN`
4. Uses Bearer token authentication for all subsequent API calls
5. Auto-refreshes on 401 responses (retry up to 5 times)

### PolarBear (VPN Infrastructure) Authentication
1. TunnelBear JWT is exchanged for PolarBear token via `/auth` endpoint
2. PolarBear token used to authenticate with proxy servers (*.lazerpenguin.com)
3. Token serves as both username and password for proxy authentication

**Files**: `src/service-worker.js` (lines 44-154, 225-264)

## API Endpoints

| Domain | Purpose | Data Transmitted |
|--------|---------|------------------|
| `api.tunnelbear.com` | Primary TunnelBear API | Authentication, account info, usage data, logs |
| `8tiodxhk8a.execute-api.us-east-1.amazonaws.com` | GhostBear mode endpoint | Same as primary API (alternate route) |
| `api.polargrizzly.com` | VPN infrastructure API | VPN server lists, region data, authentication |
| `w6wgmwa4bd.execute-api.us-east-1.amazonaws.com` | PolarBear GhostBear endpoint | VPN infrastructure (obfuscated) |
| `*.lazerpenguin.com` | VPN proxy servers | User traffic (encrypted via HTTPS proxy) |
| `tunnelbear.com` | Website communication | Login status, account management |

## Content Scripts

**File**: `src/content-script.js`

The content script is restricted to `https://*.tunnelbear.com/*` only and serves legitimate purposes:
- Detects when user logs in/signs up on TunnelBear website
- Notifies extension to refresh authentication state
- Receives logout messages from extension to sync with website

```javascript
function n() {
  window.location.pathname.endsWith("/signed-up") ||
  window.location.pathname.endsWith("/logged-in")
    ? chrome.runtime.sendMessage({ action: "LOGGED_IN" })
    : chrome.runtime.sendMessage({ action: "CHECK_AUTH" });
}
```

**Verdict**: Clean - No DOM manipulation, no data harvesting, limited scope

## Data Flow Summary

### Data Collection
1. **Account Information**: Email, subscription status, bandwidth usage
2. **Usage Statistics**: Data transferred (up/down bytes), device ID
3. **Connection Metadata**: Selected region/country, connection timestamps
4. **Logs**: Extension activity logs (for debugging)
5. **User Preferences**: Split tunneling rules, feature toggles (GhostBear, VigilantBear)

### Data Storage
- All data stored in `chrome.storage.local` (encrypted by browser)
- Device ID generated once using UUID v4 format
- No localStorage or IndexedDB usage
- No cookies set by extension

### Data Transmission
- All API calls use HTTPS with Bearer token authentication
- Logs only transmitted when user explicitly submits bug report
- No third-party analytics or tracking SDKs detected
- No data sent to domains outside TunnelBear infrastructure

**Files**: `src/service-worker.js` (lines 1119-1167 - bug report/logs submission)

## Conflict Detection

**Files**: `src/service-worker.js` (lines 518-537)

The extension detects conflicting proxy extensions using `chrome.management.getAll()`:
- Searches for other extensions with `proxy` permission
- Displays warning to user with conflicting extension details
- Prevents simultaneous proxy control conflicts

**Verdict**: Legitimate feature to prevent service issues from multiple VPN extensions

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `fromCharCode` | `index.js:6131,8864` | Legitimate base64 encoding/decoding (part of JSZip library) |
| `atob` | `index.js:8868` | Standard base64 decoding for URL parameters |
| `chrome.management` | `service-worker.js:525` | Conflict detection, not extension enumeration attack |
| `<all_urls>` | `manifest.json:33` | Required for VPN to route all traffic |
| `postMessage` | `content-script.js:14` | Communication between content script and website (TunnelBear domain only) |
| Bearer tokens | Throughout | Standard OAuth2 authentication pattern |
| Cookie token endpoint | `service-worker.js:39` | Cookie-to-JWT exchange for authentication |

## Code Quality Observations

### Positive
- Professional error handling with try-catch blocks throughout
- Detailed logging system for debugging (not sent unless user requests)
- Proper cleanup of listeners and resources
- No dynamic code execution (eval, Function constructor)
- No obfuscation beyond standard minification
- Clear separation of concerns (API service, proxy manager, kill switch)

### Architecture
- Manifest V3 compliant (uses service worker, not background page)
- Modular design with separate managers for proxy, kill switch, API communication
- Vue.js frontend framework for popup UI (index.js)
- JSZip library for log compression before submission

## Comparison to VPN Industry Standards

TunnelBear's implementation meets or exceeds VPN browser extension best practices:
- ✅ Kill switch to prevent IP leaks
- ✅ WebRTC leak protection
- ✅ DNS leak prevention (network prediction disabled)
- ✅ Split tunneling support
- ✅ Server failover/rotation
- ✅ Obfuscation mode (GhostBear) for censorship circumvention
- ✅ No logging policy (only local logs for debugging)
- ✅ Conflict detection with other VPNs

## Overall Risk Assessment

**Risk Level: CLEAN**

### Justification
TunnelBear VPN is a legitimate, well-implemented VPN service with no malicious indicators:

1. **Established Company**: TunnelBear (owned by McAfee) is a reputable VPN provider with 10+ years of operation
2. **Appropriate Permissions**: All permissions justified for VPN functionality
3. **Security Features**: Implements industry-standard protections (kill switch, WebRTC protection)
4. **No Malicious Code**: No data exfiltration, no keyloggers, no ad injection
5. **Transparent Communication**: All network requests to legitimate TunnelBear infrastructure
6. **Professional Implementation**: Clean code, proper error handling, no obfuscation
7. **User Control**: Features like split tunneling give users granular control

### Privacy Considerations (Not Vulnerabilities)
While not malicious, users should be aware:
- VPN provider can see all routed traffic (industry standard limitation)
- Extension collects bandwidth usage data (for quota enforcement)
- Requires account with TunnelBear (email address)

These are inherent to how VPN services operate and are disclosed in TunnelBear's privacy policy.

## Recommendations

None. The extension is secure and operates as intended for a commercial VPN service.

## Conclusion

TunnelBear VPN represents a best-in-class implementation of a browser VPN extension. The code demonstrates sophisticated security engineering with proper kill switch implementation, leak prevention mechanisms, and robust error handling. No vulnerabilities or malicious behavior were identified. The extension serves its stated purpose without hidden functionality or deceptive practices.

Users requiring VPN privacy should understand that the VPN provider necessarily has access to routed traffic, which is an inherent characteristic of VPN architecture, not a security flaw specific to TunnelBear.

---

**Analyst Notes**: This is one of the cleanest VPN extension implementations analyzed. The security features (kill switch, WebRTC protection, server rotation) demonstrate that the developers prioritized user privacy and connection security. The lack of third-party SDKs, analytics, or tracking code is notable and consistent with a privacy-focused service.
