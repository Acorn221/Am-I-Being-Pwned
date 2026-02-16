# Security Analysis: SmartProxy (jogcnplbkgkfdakgdenhlpcfhjioidoj)

## Extension Metadata
- **Name**: SmartProxy
- **Extension ID**: jogcnplbkgkfdakgdenhlpcfhjioidoj
- **Version**: 2.0
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: Salar Khalilzadeh (github.com/salarcode)
- **Open Source**: Yes (GPL-3.0 License)
- **Repository**: https://github.com/salarcode/SmartProxy
- **Analysis Date**: 2026-02-14

## Executive Summary
SmartProxy is a **legitimate, open-source proxy management extension** with **CLEAN** status. The extension allows users to define domain-based proxy rules for automatic proxy switching, similar to AutoProxy/AutoProxy-ng but built with modern WebExtensions. Analysis revealed no malicious behavior, data exfiltration, or tracking mechanisms. The ext-analyzer flagged three "exfiltration" flows from `document.querySelectorAll → fetch(*)`, but all are **false positives** involving legitimate operations: loading bundled IP geolocation data, fetching user-configured proxy rule subscriptions, and checking for updates from the official GitHub repository.

**Overall Risk Assessment: CLEAN**

## Vulnerability Assessment

### 1. Ext-Analyzer "Exfiltration" Flows (FALSE POSITIVES)
**Severity**: N/A (Not Vulnerabilities)
**Files**:
- `/ui/code/settingsPage.js` (lines 2324-2330, 2721-2724, 2854, 10572)
- `/ui/code/proxyable.js` (lines 2324-2330, 2721-2724, 2854)
- `/ui/code/popup.js` (lines 2324-2330, 2721-2724, 2854)
- `/core.js` (lines 2606-2609, 3461-3464, 3849-3852)

**Analysis**:
The ext-analyzer detected `document.querySelectorAll → fetch(*)` flows and classified them as "exfiltration." Detailed code review reveals all are legitimate:

#### Flow 1: IP Geolocation Database Loading (Local Resource)
**Code Evidence** (popup.js, line 2327):
```javascript
const e = n.api.runtime.getURL("assets/IPCountryDB/IP2LOCATION-LITE-DB1.CSV"),
  t = await fetch(e),
  r = (await t.text()).split("\n");
```

**Purpose**: Loads a bundled IP-to-country CSV database from the extension's local assets to display country flags for proxy servers. This is a **local resource fetch** using `chrome.runtime.getURL()`, not external data exfiltration.

**Data Flow**: No DOM data accessed → Fetch internal asset → Parse CSV locally → No network transmission

**Verdict**: **FALSE POSITIVE** - Internal asset loading, not exfiltration.

---

#### Flow 2: Proxy Rule Subscription Fetching (User-Configured)
**Code Evidence** (popup.js, lines 2721-2724):
```javascript
readFromServer(e, t, r) {
  if (e && e.url) {
    if (!t) throw "onSuccess callback is mandatory";
    null !== e.applyProxy && l.ProxyEngineSpecialRequests.setSpecialUrl(e.url, e.applyProxy),
    fetch(e.url, {
      method: "GET",
      cache: "no-store",
      headers: {
        "User-Agent": navigator.userAgent
      }
    })
```

**Purpose**: Fetches proxy rule lists from user-configured subscription URLs. This is a **core feature** allowing users to subscribe to public proxy rule lists (similar to ad-blocker filter subscriptions).

**User Control**:
- URLs are explicitly configured by the user in settings
- Supports standard proxy rule formats and private WebDAV servers
- Optional Basic Authentication for private subscriptions
- Downloaded text is parsed as proxy rules, not transmitted elsewhere

**Data Transmitted**: None (GET request only, no query parameters or POST data)

**Verdict**: **FALSE POSITIVE** - User-initiated subscription feature, expected behavior.

---

#### Flow 3: Update Check from GitHub (Developer Repository)
**Code Evidence** (core.js, lines 2606-2609):
```javascript
let e = "https://raw.githubusercontent.com/salarcode/SmartProxy/master/updateinfo.json";
n.Debug.isEnabled() && (e = "http://localhost:5500/updateinfo.json"),
fetch(e, {
  method: "GET"
}).then((e => e.json())).then((e => {
  n.DiagDebug?.trace("Checking for update result", e),
```

**Purpose**: Checks the official SmartProxy GitHub repository for version updates. The JSON file contains only version numbers and release notes.

**Data Transmitted**: None (GET request, no user data or identifiers sent)

**Endpoint**: `raw.githubusercontent.com/salarcode/SmartProxy/master/updateinfo.json` (official repository)

**Verdict**: **FALSE POSITIVE** - Standard update check mechanism for open-source extension.

---

#### Flow 4: Localized "About" Page Loading (Local Resource)
**Code Evidence** (settingsPage.js, line 10572):
```javascript
let o = `${n||i.api.i18n.getMessage("languageCode")}/settings-about.html`,
  a = s.PolyFill.extensionGetURL(`_locales/${o}`);
fetch(a).then((e => e.text())).then((e => {
  t(e)
}))
```

**Purpose**: Loads localized "About" page HTML from extension's bundled `_locales` directory.

**Verdict**: **FALSE POSITIVE** - Internal localization file loading.

---

### 2. WebDAV Backup/Restore Feature
**Severity**: N/A (Expected Behavior)
**Files**: `/ui/code/settingsPage.js` (lines 2844-2860)

**Analysis**:
The extension includes optional WebDAV backup/restore functionality for storing extension settings on private servers.

**Code Evidence** (settingsPage.js, line 2854):
```javascript
fetch(e.url, n).then((e => e.text())).then((n => {
  var s;
  (s = n) ? l.importRulesBatch(e, s, null, !1, null, (e => {
    e.success ? t && t(e) : r && r(e)
  })) : r && r(null)
}))
```

**User Control**:
- Completely optional (user must configure server URL, username, password)
- Supports Basic Authentication
- Only fetches/uploads extension settings (proxy rules, not browsing data)
- Implements WebDAV client library (`webdav-client`)

**Privacy Impact**: None - User-controlled private server feature

**Verdict**: **NOT MALICIOUS** - Optional backup feature with full user control.

---

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `proxy` | Required for PAC script-based proxy configuration | Low (core feature) |
| `tabs` | Required for per-tab proxy status tracking | Low (functional) |
| `webRequest` | Required for monitoring proxy-applied requests | Low (functional) |
| `webRequestAuthProvider` | Required for proxy authentication credentials | Low (functional) |
| `storage` | Settings and proxy server configurations | Low (local only) |
| `unlimitedStorage` | Large proxy rule subscription lists | Low (functional) |
| `notifications` | Update notifications and proxy status alerts | Low (local only) |
| `activeTab` | Current tab domain detection for rule matching | Low (functional) |
| `host_permissions: <all_urls>` | Required for PAC script to proxy any URL | Medium (broad but necessary) |

**Assessment**: All permissions are justified and properly used for declared proxy management functionality.

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `raw.githubusercontent.com/salarcode/SmartProxy/master/updateinfo.json` | Update check | None (GET only) | Periodic (user-configured) |
| User-configured subscription URLs | Proxy rule lists | None (GET only) | On-demand (user-initiated) |
| User-configured WebDAV servers | Settings backup/restore | Extension settings (user data only if enabled) | On-demand (user-initiated) |

### Data Flow Summary

**Data Collection**: NONE
**User Data Transmitted**: NONE (except optional WebDAV backup if user configures it)
**Tracking/Analytics**: NONE
**Third-Party Services**: NONE

All network calls are:
1. Update checks to official repository (no data sent)
2. User-configured proxy rule subscriptions (GET requests only)
3. Optional WebDAV backup (user must explicitly configure private server)

**No browsing data, cookies, tab URLs (beyond current tab for rule matching), or user identifiers are transmitted to external servers.**

## Code Quality Observations

### Positive Indicators
1. **Open-Source Transparency**: GPL-3.0 licensed on GitHub with 26 open issues
2. **No Dynamic Code Execution**: No `eval()`, `Function()`, or remote script loading
3. **No XHR/Fetch Hooking**: No prototype modifications or monkey-patching
4. **No Extension Enumeration**: No `chrome.management` API usage
5. **No Residential Proxy Infrastructure**: No proxy credentials harvesting
6. **No Market Intelligence SDKs**: No Sensor Tower, Pathmatics, etc.
7. **No Ad/Coupon Injection**: No DOM manipulation for ads
8. **No Cookie Harvesting**: No `cookies` permission or cookie access
9. **Clean Separation of Concerns**: Well-structured TypeScript modules (background, content, popup)
10. **Minimal Network Activity**: Only update checks and user-configured subscriptions
11. **Local Data Storage**: All settings stored in `chrome.storage.local`

### Obfuscation Level
**Medium** - The code is bundled/minified by Webpack (standard build process), but the TypeScript source structure is preserved with clear module names like `ProxyEngine`, `SettingsOperation`, `TabManager`, etc. This is **standard production build obfuscation**, not deliberate security evasion.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | Legitimate user-configured proxy feature |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✗ No | No cookie access |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ✗ No | All network calls are transparent and user-controlled |
| Credential theft | ✗ No | Proxy auth stored locally, not exfiltrated |

## False Positive Explanation: Ext-Analyzer Limitations

The ext-analyzer detected `document.querySelectorAll → fetch(*)` flows because:

1. **Context-Insensitive Analysis**: The analyzer cannot distinguish between:
   - Fetching local resources (`chrome.runtime.getURL()`)
   - User-initiated network requests
   - Actual data exfiltration

2. **No Semantic Understanding**: The tool flags any path from DOM API to `fetch()`, but doesn't analyze:
   - Whether the fetch URL is internal vs. external
   - Whether DOM data is actually transmitted
   - Whether network calls are user-controlled

3. **Legitimate Use Cases Flagged**:
   - Loading bundled CSV files (IP geolocation database)
   - Fetching user-configured subscriptions (expected proxy extension behavior)
   - Update checks to official repository (standard practice)

**Recommendation**: Ext-analyzer should differentiate between `fetch(chrome.runtime.getURL(...))` (internal) and `fetch(external_url)` (potentially concerning), and consider whether DOM data is actually included in the request body/URL.

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
1. **Open-Source Transparency**: Fully auditable on GitHub with active development
2. **No Malicious Behavior**: No data exfiltration, tracking, or surveillance mechanisms
3. **Minimal Network Activity**: Only update checks and user-configured subscriptions
4. **No Data Collection**: Extension doesn't collect or transmit user data
5. **Legitimate Functionality**: All features match expected proxy management behavior
6. **Proper Permission Use**: All permissions justified and used appropriately
7. **No Hidden Backdoors**: No remote code loading or kill switches

### Recommendations
- **No action required** - Extension operates as advertised
- Users concerned about update checks can inspect `updateinfo.json` content (publicly visible on GitHub)
- WebDAV backup feature requires explicit user configuration (opt-in, not default)
- Proxy rule subscriptions are user-controlled and transparent

### User Privacy Impact
**MINIMAL** - The extension only accesses:
- Current tab URL (for proxy rule matching)
- User-configured proxy servers and rules (stored locally)
- Optional user-configured subscription URLs (GET requests only)
- No cross-site tracking or data aggregation
- No third-party analytics or advertising networks

## Technical Summary

**Lines of Code**: ~555KB minified JavaScript (standard Webpack production build)
**External Dependencies**: jQuery, DataTables, Bootstrap, Pako (compression), Noty (notifications), webdav-client
**Third-Party Libraries**: All bundled from CDN-hosted versions (npm packages)
**Remote Code Loading**: None
**Dynamic Code Execution**: None
**Proxy Implementation**: PAC script generation for Chrome, `proxy.onRequest` listener for Firefox

## Conclusion

SmartProxy is a **clean, legitimate, open-source browser extension** that provides rule-based proxy management. The ext-analyzer's "exfiltration" flags are **false positives** caused by context-insensitive analysis of legitimate operations:
- Loading bundled IP geolocation databases
- Fetching user-configured proxy rule subscriptions
- Checking for updates from the official GitHub repository

All network calls are transparent, user-controlled, and properly justified. No user data is collected or transmitted. The extension follows browser extension best practices and maintains an active open-source presence with GPL-3.0 licensing.

**Final Verdict: CLEAN** - Safe for use with ~100K users. Recommended for users who need automatic proxy switching based on domain rules.
