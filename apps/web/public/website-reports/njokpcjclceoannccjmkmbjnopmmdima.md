# Security Analysis Report: Norton VPN - Fast & Secure

## Extension Metadata

- **Extension ID**: njokpcjclceoannccjmkmbjnopmmdima
- **Extension Name**: Norton VPN - Fast & Secure
- **Version**: 2.1.0.766
- **User Count**: ~0 users
- **Developer**: NortonLifeLock (Gen Digital)
- **Manifest Version**: 3

## Executive Summary

Norton VPN is a legitimate browser extension published by NortonLifeLock (Gen Digital Inc.), a well-established cybersecurity company. The extension serves as a companion UI for the Norton VPN desktop application, providing browser-based controls for VPN connectivity through native messaging. The extension bundles the eyeo Web Extension SDK (AdblockPlus technology) to provide content filtering capabilities alongside VPN functionality.

**Key Findings:**
- Extension communicates with the native Norton VPN application via `chrome.nativeMessaging`
- Includes legitimate eyeo/AdblockPlus SDK for ad/tracker blocking
- Implements telemetry through eyeo's infrastructure (first-ping only)
- No malicious code, data theft, or security vulnerabilities identified
- Appropriate CSP prevents inline script execution
- All network endpoints are legitimate (Norton, eyeo/AdblockPlus domains)

**Overall Risk Level**: **CLEAN**

## Vulnerability Analysis

### No Critical or High-Severity Issues Found

After comprehensive analysis of the extension's background scripts, content scripts, manifest permissions, and network behavior, **no security vulnerabilities or malicious functionality were identified**.

## Architecture Overview

### 1. Native Messaging Integration

The extension acts as a browser-based UI controller for the native Norton VPN application:

**Connection Mechanism** (background.js:318):
```javascript
connect() {
  this.disconnect(!1),
  this.port = chrome.runtime.connectNative(Lv.nmhAppName), // "com.norton.vpn"
  this.port.onMessage.addListener(this.onMessageReceived.bind(this)),
  this.port.onDisconnect.addListener(this.onDisconnect.bind(this))
}
```

**Commands Supported**:
- `Connect` - Connect to specified VPN gateway
- `ConnectToOptimal` - Connect to optimal location
- `Disconnect` - Disconnect VPN
- `Pause` / `Resume` - Pause/resume VPN connection
- `GetState` - Retrieve VPN status, license info, gateway list
- `GetProductInfo` - Get native app version
- `OpenApp` - Launch native VPN application

**Verdict**: This is standard native messaging architecture for companion browser extensions. The native host name `com.norton.vpn` is properly scoped to Norton's namespace.

### 2. Eyeo Web Extension SDK Integration

The extension bundles the eyeo Web Extension SDK v0.13.2, which is the open-source technology behind AdblockPlus:

**Evidence** (background.js:16972):
```javascript
addon_name: "eyeo-webext-sdk",
addon_version: "0.13.2",
extension_name: T.addonName,
extension_version: T.addonVersion,
aa_active: await (0, Q.hasAcceptableAdsEnabled)()
```

**Functionality Provided**:
- Content filtering via declarativeNetRequest API (MV3 compliant)
- Ad/tracker blocking using EasyList subscriptions
- Anti-circumvention snippets for sites that detect ad blockers
- Acceptable Ads program support (user-configurable)

**Filter Lists** (bundled rulesets):
- `8C13E995-8F06-4927-BEA7-6C845FB7EEBF` - EasyList (9.5MB, disabled by default)
- `0798B6A2-94A4-4ADF-89ED-BEC112FC4C7F` - Additional ruleset (3.7MB, disabled by default)

**Subscription Sources** (background.js:16581-16585):
```javascript
p = "https://easylist-downloads.adblockplus.org/exceptionrules.txt",
u = "https://easylist-downloads.adblockplus.org/v3/full/exceptionrules.txt",
y = "https://easylist-downloads.adblockplus.org/exceptionrules-privacy-friendly.txt",
B = "https://easylist-downloads.adblockplus.org/v3/full/exceptionrules-privacy-friendly.txt"
```

**Verdict**: Legitimate integration of eyeo's open-source ad-blocking technology. This is commonly bundled by security vendors (Norton, Avast, AVG) to provide additional privacy protection alongside VPN functionality.

### 3. Telemetry Implementation

The extension implements minimal telemetry through eyeo's infrastructure:

**Telemetry Function** (background.js:16923-16960):
```javascript
function L(M) {
  if (!M.url) throw new Error("No telemetry `url` provided");
  if (!M.bearer) throw new Error("No telemetry `bearer` provided");
  X || (X = !0, m(M).catch(P => console.error(P.toString())))
}

async function m(M) {
  const C = (await d.storage.local.get([R]))[R];
  if (C && C.firstPing) return; // Only sends ONCE
  const E = await z(M.url, M.bearer, {
    payload: await h()
  });
  await d.storage.local.set({
    [R]: {
      firstPing: E
    }
  })
}
```

**Telemetry Payload** (background.js:16961-16978):
```javascript
async function h() {
  return {
    platform: M,
    platform_version: P,
    application: T.application,
    application_version: T.applicationVersion,
    addon_name: "eyeo-webext-sdk",
    addon_version: "0.13.2",
    extension_name: T.addonName,
    extension_version: T.addonVersion,
    aa_active: await (0, Q.hasAcceptableAdsEnabled)()
  }
}
```

**Behavior**:
- Sends a single "first ping" after initialization
- Contains only platform/version metadata (no user data)
- Storage flag prevents repeat transmission
- Endpoint controlled by eyeo SDK configuration

**Verdict**: This is standard opt-in telemetry for eyeo's SDK, used to understand SDK adoption. The first-ping-only design minimizes data collection. No PII or browsing data is transmitted.

### 4. Content Script Functionality

**Content Script**: `ewe-content.js` (4k lines)

**Purpose**: Implements eyeo SDK content filtering:
- DOM traversal for filter rule application
- Element hiding for ad/tracker removal
- Snippet injection for anti-circumvention (standard AdblockPlus technique)
- Communication with background script via runtime messaging

**Key Operations** (ewe-content.js:1380-1497):
```javascript
this.document.addEventListener("DOMContentLoaded", onLoad, true);
this.document.addEventListener("load", onLoad, true);

for (let element of this.document.querySelectorAll(selector)) {
  // Apply hiding/removal based on filter rules
}
```

**Snippet Injection** (background.js:11870-11873):
```javascript
function injectSnippetsInMainContext(exec)
{
  // injecting phase
  let script = document.createElement("script");
```

**Verdict**: Standard eyeo SDK content filtering. The snippets are from the open-source `@eyeo/snippets` library (background.js:17191-17204) used to counter ad-blocker detection. This is not obfuscation or malicious injection—it's the core functionality of ad-blocking extensions.

### 5. Permissions Analysis

**Requested Permissions**:
```json
"permissions": [
  "tabs",               // VPN status per-tab, UI updates
  "webNavigation",      // Filter application timing
  "storage",            // Settings, filter cache, VPN state
  "unlimitedStorage",   // Large filter lists (13MB+)
  "nativeMessaging",    // Required for VPN app communication
  "declarativeNetRequest", // MV3 content filtering
  "scripting",          // Snippet injection for anti-circumvention
  "alarms",             // Periodic VPN status polling
  "activeTab",          // Current tab info for UI
  "webRequest"          // Filter metadata (read-only in MV3)
],
"host_permissions": [
  "<all_urls>"          // Required for content filtering on all sites
]
```

**Justification**:
- **nativeMessaging**: Core functionality—extension is useless without native app communication
- **declarativeNetRequest + scripting + `<all_urls>`**: Required for ad/tracker blocking across all websites
- **unlimitedStorage**: Filter lists exceed standard quota (EasyList = 9.5MB)
- **tabs + webNavigation + alarms**: Standard for VPN status display and periodic polling
- **webRequest**: Read-only in MV3, used for filter metadata

**Content Security Policy** (manifest.json:25-27):
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Verdict**: All permissions are appropriate and necessary for stated functionality (VPN control + ad blocking). The CSP properly prevents inline script execution and remote code loading.

## Network Endpoints

| Endpoint | Purpose | Verdict |
|----------|---------|---------|
| `sitedirector.norton.com` | Norton services directory/support | Legitimate |
| `easylist-downloads.adblockplus.org` | Filter list updates (eyeo CDN) | Legitimate |
| `notification.adblockplus.org` | eyeo SDK notifications | Legitimate |
| `adblockplus.org` | Subscription fallback URLs | Legitimate |

**Native Host**: `com.norton.vpn` (local IPC, not a network endpoint)

## False Positive Analysis

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| Script injection | background.js:11870 | eyeo SDK snippet injection for anti-ad-blocker-blocker functionality | **False Positive** - Standard AdblockPlus technique |
| `Proxy` usage | background.js:13292, 17207 | JavaScript Proxy objects for eyeo SDK API wrapping (not network proxy) | **False Positive** - Language feature |
| `crypto.subtle` | background.js:11404, 13498 | Extension signature verification (validates eyeo SDK content) | **False Positive** - Security feature |
| `document.createElement("script")` | background.js:11873 | Snippet injection (AdblockPlus anti-circumvention) | **False Positive** - Expected for ad-blocking |
| Analytics/telemetry | background.js:8362-8430 | eyeo SDK first-ping telemetry (version info only) | **False Positive** - Minimal, non-invasive |

## Data Flow Summary

```
User Action (popup)
  → Runtime Message (background.js)
    → Native Messaging (chrome.runtime.connectNative)
      → Norton VPN Desktop App (com.norton.vpn)
        → VPN Gateway Connection

Web Page Load
  → Content Script (ewe-content.js)
    → Filter Rule Evaluation (declarativeNetRequest)
      → Element Hiding / Script Blocking
        → Anti-Circumvention Snippets (if needed)
```

**Data Retention**:
- VPN state (connection status, active gateway) → `chrome.storage.local`
- Filter subscriptions (EasyList rules) → `chrome.storage.local` + static rulesets
- User preferences (license info cache) → `chrome.storage.local`
- Telemetry flag (first ping sent) → `chrome.storage.local` (`ewe:telemetry`)

**No Data Exfiltration**: All data stays local except for:
1. VPN connection requests to Norton infrastructure (via native app)
2. Filter list updates from eyeo CDN (standard HTTP requests)
3. Single telemetry ping to eyeo (platform/version metadata only)

## Security Strengths

1. **Proper Native Messaging Architecture**: Extension correctly implements the Chrome native messaging protocol with connection lifecycle management and error handling.

2. **Manifest V3 Compliance**: Uses declarativeNetRequest instead of webRequest blocking, aligning with Chrome's latest security model.

3. **Content Security Policy**: Enforces `script-src 'self'`, preventing remote code execution and inline scripts.

4. **Signature Verification**: Implements cryptographic verification of filter list content using `crypto.subtle.verify()`.

5. **No Sensitive Data Collection**: No access to passwords, form data, cookies (beyond what's necessary for filtering), or keyboard input.

6. **Transparent Licensing**: Bundles open-source eyeo SDK with proper GPL licensing attribution.

7. **Minimal Telemetry**: First-ping-only design limits data transmission to initial SDK adoption metrics.

## Recommendations

While no security issues were identified, the following observations are noted:

1. **Transparency**: The extension description should explicitly mention the bundled AdblockPlus/eyeo SDK functionality, as users may not expect ad-blocking from a VPN extension.

2. **Ruleset Management**: Both bundled rulesets are disabled by default (`enabled: false` in manifest.json:60,64). Users should be informed if/when these are enabled.

3. **Native App Dependency**: Extension is non-functional without the Norton VPN desktop application installed. This should be clearly communicated in the web store listing.

## Conclusion

Norton VPN (njokpcjclceoannccjmkmbjnopmmdima) is a **legitimate, secure browser extension** published by NortonLifeLock/Gen Digital. It functions as designed—providing browser-based UI controls for the Norton VPN desktop application while bundling eyeo's open-source ad-blocking technology for additional privacy protection.

**No malicious behavior, data theft, or security vulnerabilities were identified.**

The extension demonstrates industry-standard practices for:
- Native messaging integration
- Manifest V3 content filtering
- Cryptographic signature verification
- Minimal telemetry implementation

All network communications are with legitimate Norton and eyeo infrastructure. Permissions are appropriate for stated functionality. Code follows secure development practices with proper CSP and API usage.

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Rationale**:
- Legitimate developer (NortonLifeLock/Gen Digital, publicly traded cybersecurity company)
- All functionality serves stated purpose (VPN control + privacy protection)
- No code obfuscation beyond standard production minification
- No malicious network activity, data exfiltration, or user tracking
- Open-source eyeo SDK integration is transparent and properly licensed
- Appropriate permission usage with strong CSP

**Recommendation**: Safe for use. Extension performs as advertised with no security concerns.
