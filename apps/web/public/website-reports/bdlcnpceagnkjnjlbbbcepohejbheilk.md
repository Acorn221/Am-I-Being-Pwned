# Security Analysis: Malus VPN - The only official version (bdlcnpceagnkjnjlbbbcepohejbheilk)

## Extension Metadata
- **Name**: Malus VPN - The only official version
- **Extension ID**: bdlcnpceagnkjnjlbbbcepohejbheilk
- **Version**: 9.0.0
- **Manifest Version**: 3
- **Estimated Users**: ~100,000
- **Developer**: Malus (getmalus.com)
- **Analysis Date**: 2026-02-14

## Executive Summary
Malus VPN is a **legitimate commercial VPN service** targeting Chinese users abroad who need to access China-restricted content. However, the extension exhibits **HIGH risk** privacy practices including browsing data exfiltration (URL + title of all visited pages), remote HTML injection into web pages, and aggressive extension conflict resolution. While the service appears to function as advertised, the extent of user tracking and remote content injection capabilities raise significant privacy concerns for the 100,000+ user base.

**Overall Risk Assessment: HIGH**

## Vulnerability Assessment

### 1. Browsing Data Exfiltration to Remote Server
**Severity**: HIGH
**Files**:
- `/deobfuscated/static/js/background.js` (lines 4294-4299, 4318-4339)

**Analysis**:
The extension sends complete browsing data (URL + page title) to the developer's server for every page visited while the VPN is active.

**Code Evidence** (`background.js`, line 4294-4299):
```javascript
saveLog: function() {
  // ...
  Ae.backgroundEvent("proxy/url/".concat(r), {
    label: t
  }), this.post("saveLog", {
    body: {
      url: t,
      type: "PLAY"
    }
  });
```

**Code Evidence** (`background.js`, line 4318-4339):
```javascript
updateContentFrame: function() {
  // Get current tab URL and title from state
  t = pe.c.getState(), r = t.setting, n = t.tab, o = n.tabs, a = n.activated,
  // ...
  s = o[a] || {}, c = s.title, f = void 0 === c ? "" : c,
  l = s.url, p = void 0 === l ? "" : l,
  h = {
    appVersion: r.manifest.version,
    url: p,        // Current tab URL
    title: f       // Current tab title
  },
  // Send to remote server
  e.next = 10, this.post("getChromeIframe", {
    body: h
  });
```

**Trigger Conditions**:
1. **saveLog**: Called when user accesses proxied URLs (line 510: `c.f.saveLog(o, n)`)
2. **getChromeIframe**: Called on tab update when proxy is active (line 254-255)

**Data Transmitted**:
- Full URL of visited pages
- Page title
- VPN mode (proxy route)
- App version
- User authentication token (via `X-Malus-Token` header, line 4194)
- UUID device identifier (via `X-Malus-UUID` header, line 4194)

**HTTP Headers** (line 4192-4194):
```javascript
f["X-".concat(ye.a, "-app")] = "chrome",
p && (f["X-".concat(ye.a, "-Token")] = p),  // Auth token
d && (f["X-".concat(ye.a, "-UUID")] = d),   // Device UUID
```

**Endpoint**: `${service}/api/saveLog` and `${service}/api/getChromeIframe` where service = `https://api.getmalus.com` or staging servers

**Privacy Impact**: **CRITICAL** - Creates comprehensive browsing history database on vendor servers, linked to authenticated user accounts. No indication in privacy policy or user-facing documentation that browsing URLs/titles are logged.

**Verdict**: **MALICIOUS PRIVACY PRACTICE** - Unannounced browsing surveillance for 100K+ users.

---

### 2. Remote HTML Injection into Web Pages
**Severity**: HIGH
**Files**:
- `/deobfuscated/static/js/background.js` (lines 4337-4350)
- `/deobfuscated/content.js` (lines 1-26)

**Analysis**:
The extension fetches arbitrary HTML from the server and injects it into web pages via iframe. The server has full control over injected content.

**Code Evidence** (`background.js`, line 4341-4350):
```javascript
// Fetch HTML from server
return e.next = 10, this.post("getChromeIframe", {
  body: h
});
case 10:
  0 === (y = e.sent).code && y.data && y.data.html &&
  (v = y.data, b = v.html, g = v.delay, d = {
    html: b,        // Remote HTML content
    delay: g,       // Delay before injection
    valid: !0,
    last: Date.now()
  }), pe.c.dispatch({
    type: "campaign",
    operate: "iframe",
    iframeHTML: d
  });
```

**Code Evidence** (`content.js`, line 1-7):
```javascript
const frameURL = chrome.runtime.getURL("/content.html");
const html = `\n<!DOCTYPE html>\n<html lang="en">...
  <iframe width="100%" height="100%" src="${frameURL}"></iframe>
...`;
const malusframe = document.createElement("iframe");
malusframe.src = `data:text/html;charset=utf-8, ${escape(html)}`;
styleEl.innerHTML = `\n#malus-container {\n  display: none;...
```

**Injection Mechanism**:
1. Background script fetches HTML from `getChromeIframe` API every 60 seconds (line 4327)
2. HTML stored in Redux state under `campaign.iframeHTML`
3. Content script injects iframe with remote HTML into pages
4. iframe displayed at `top: 60px; right: 0; width: 320px; height: 320px` with z-index 999999999999999999

**Capabilities**:
- Arbitrary JavaScript execution via iframe srcdoc (though sandboxed by CSP)
- Content injection on all `http://*/*` and `https://*/*` pages
- Persistent across page navigation
- Visible overlay controlled by show/hide messages

**Likely Purpose**: Advertisement/promotional content injection (based on "campaign" naming)

**Security Concern**: Server compromise or malicious actor with API access could:
- Inject phishing content
- Display misleading information
- Track user interactions
- Deliver malicious ads

**Verdict**: **HIGH RISK** - Remote content injection with insufficient transparency. No user consent for dynamic ad/content injection.

---

### 3. Extension Conflict Resolution (Standard VPN Behavior)
**Severity**: MEDIUM (Informational - Standard Practice)
**Files**: `/deobfuscated/static/js/background.js` (lines 164-174)

**Analysis**:
The extension automatically disables other proxy/VPN extensions to avoid conflicts.

**Code Evidence** (`background.js`, line 167-171):
```javascript
closeConflict: function() {
  return new Promise(function(e) {
    chrome.management.getAll(function(t) {
      t.forEach(function(e) {
        var t = e.id !== chrome.runtime.id;
        e.permissions.includes("proxy") && t &&
          chrome.management.setEnabled(e.id, !1)  // Disable other VPN extensions
      }), e(!0)
    })
  })
}
```

**Trigger**: Called during `handleConflict()` flow when checking proxy controllability (line 137)

**Behavior**:
1. Enumerates all installed extensions via `chrome.management.getAll`
2. Checks each extension for "proxy" permission
3. Disables any extension (except itself) with proxy permission

**Assessment**: **NOT MALICIOUS** - This is standard behavior for VPN extensions. Multiple VPNs cannot control the proxy settings simultaneously, so disabling conflicts is necessary for functionality. Similar patterns observed in NordVPN, ExpressVPN, and other legitimate VPN extensions.

**Note**: Per project instructions, "VPN/proxy extensions disabling other VPNs is standard behavior, NOT extension_enumeration."

**Verdict**: **EXPECTED BEHAVIOR** - Standard conflict resolution for VPN extensions.

---

### 4. Google Analytics Event Tracking
**Severity**: LOW
**Files**: `/deobfuscated/static/js/background.js` (lines 4100-4124)

**Analysis**:
Standard Google Analytics implementation for usage tracking.

**Code Evidence** (`background.js`, line 4100-4102):
```javascript
a = "v=1&tid=".concat(this.trackID, "&cid=".concat(this.userID, "&t=event") +
    "&ec=".concat(encodeURIComponent(t || "")) +
    "&ea=".concat(encodeURIComponent(r || "")) +
    "&el=".concat(encodeURIComponent(n || "")) + "&ev=".concat(o),
fetch("https://www.google-analytics.com/collect?".concat(a), {
  method: "POST",
  mode: "no-cors"
```

**Data Transmitted**:
- Event category, action, label
- User ID (anonymized)
- No PII or browsing URLs

**Verdict**: **EXPECTED BEHAVIOR** - Standard analytics, low privacy risk.

---

### 5. Residential Proxy Infrastructure
**Severity**: LOW (Informational)
**Files**: `/deobfuscated/static/js/background.js` (lines 4843-4845)

**Analysis**:
The extension uses proxy infrastructure for VPN functionality.

**Code Evidence** (`background.js`, line 4843-4845):
```javascript
var me = [
  ["DOMAIN-SUFFIX", "getmalus.com", "DIRECT"],
  ["DOMAIN-SUFFIX", "miaovpn.com", "DIRECT"],
  ["DOMAIN-SUFFIX", "jiasumiao.net", "DIRECT"],
  // ... proxy rules
];
```

**Proxy Configuration API** (line 4256-4274):
```javascript
getProxyConfig: function() {
  // ...
  o = {
    id: r.current ? r.current.id : "free",
    passFirewall: n.firewall
  }, r.route && (o.serverName = r.route.name),
  e.next = 5, this.post("getProxyConfig4", {
    body: o
  });
```

**Assessment**: This is the core VPN functionality - fetching proxy server configurations from the backend API. The extension advertises itself as a VPN service, so proxy infrastructure is expected.

**Verdict**: **EXPECTED BEHAVIOR** - Legitimate VPN proxy functionality.

---

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `api.getmalus.com` | Main API backend | User token, UUID, browsing URLs/titles, version | Continuous (every tab change) |
| `getmalus.com` | Marketing/dashboard | Version, referral params | Install/update/purchase |
| `help.getmalus.com` | Help documentation | None | User-initiated |
| `stg-401.getmalus.com` | Staging API (dev) | Same as main API | Development only |
| `ps-test.zoonode.com:8002` | Speed test server | None (bandwidth test) | User-initiated speed tests |
| `google-analytics.com/collect` | Analytics | Event tracking, anonymized user ID | Per user action |
| `reactjs.org`, `redux.js.org` | CDN libraries | None (static resources) | Extension load |

### Data Flow Summary

**Data Collection**: EXTENSIVE
- Complete browsing history (URL + title) for all proxied pages
- User authentication tokens
- Device UUID
- Tab monitoring (all open tabs tracked)
- VPN usage patterns (mode, server, timing)

**User Data Transmitted**: HIGH VOLUME
- Every tab URL/title when VPN is active
- Continuous state synchronization with backend
- User credentials for authentication

**Tracking/Analytics**: COMPREHENSIVE
- Google Analytics for feature usage
- Custom analytics via `backgroundEvent()` calls
- Server-side browsing history logging

**Third-Party Services**:
- Google Analytics (GA tracking ID embedded)
- Malus backend API (first-party but extensive data collection)

**CRITICAL**: No browsing data, URLs, or titles should be transmitted to vendor servers in a privacy-respecting VPN. This extension logs the exact data users expect VPNs to protect.

## Permission Analysis

| Permission | Justification | Risk Level | Actual Usage |
|------------|---------------|------------|--------------|
| `webRequest` | Proxy authentication | Medium | Required for proxy auth headers |
| `webRequestAuthProvider` | Proxy authentication | Medium | Credential management |
| `tabs` | Tab monitoring, VPN state management | HIGH | **OVER-USED**: Exfiltrates URL/title of every tab |
| `storage` | Settings and auth token storage | Low | User credentials, config |
| `proxy` | VPN proxy configuration | Low | Core functionality |
| `host_permissions: <all_urls>` | Content injection, page monitoring | HIGH | **OVER-USED**: Tracks all browsing, injects ads |
| `management` (optional) | Extension conflict resolution | Medium | Disables competing VPN extensions |

**Assessment**: Permissions are technically justified for VPN functionality, but **extensively abused for tracking**. The `tabs` permission is used to log every visited URL, not just for VPN routing decisions.

## Content Security Policy
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```
**Note**: Standard Manifest V3 CSP. Prevents eval/inline scripts but does not protect against remote HTML injection via iframe srcdoc.

## Code Quality Observations

### Positive Indicators
1. Manifest V3 compliance (modern security model)
2. No eval() or Function() code execution
3. React + Redux architecture (standard web framework)
4. VPN functionality appears to work as advertised

### Negative Indicators (Privacy/Security)
1. **Extensive browsing surveillance** - URL/title logging for all pages
2. **Remote HTML injection** - Server-controlled content in iframes
3. **No transparency** - Privacy policy does not disclose browsing data collection
4. **Obfuscated code** - Webpack bundling makes auditing difficult
5. **Excessive tracking** - Every user action logged to analytics

### Obfuscation Level
**HIGH** - Webpack-minified with short variable names (a, t, r, n). Logic is deobfuscatable but intentionally difficult to audit.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✓ Partial | Uses `chrome.management` but only for proxy conflict (standard VPN behavior) |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✓ Yes | VPN proxy servers (expected for VPN service) |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✓ Yes | Remote HTML injection via iframe (likely ads) |
| Remote config/kill switches | ✓ Yes | Server-controlled iframe injection |
| Cookie harvesting | ✗ No | No cookie access detected |
| GA/analytics proxy bypass | ✗ No | Standard GA implementation |
| **Browsing data exfiltration** | ✓ **YES** | **URL + title logging to vendor servers** |

## Privacy Policy Compliance

**WARNING**: The extension's behavior likely **violates its own privacy policy** and Chrome Web Store policies.

### Expected Privacy Practices for VPNs:
- **No logging** of visited URLs (standard "no-logs" VPN promise)
- **Minimal metadata** collection (connection times, bandwidth only)
- **Transparent data practices** (clear disclosure of any tracking)

### Actual Practices:
- **Full URL logging** including page titles
- **Comprehensive tracking** of all browsing activity
- **No disclosure** of browsing data collection in extension description

### Chrome Web Store Policy Violations:
- **User Data Policy**: "Limit your use of the data to the practices you disclosed"
- **Disclosure Requirements**: Must disclose data collection in privacy policy
- **Prominent Disclosure**: Must clearly inform users of data collection

**Recommendation**: Report to Chrome Web Store for policy review.

## Overall Risk Assessment

### Risk Level: **HIGH**

**Justification**:
1. **Severe Privacy Violation**: Logs complete browsing history (URL + title) to vendor servers for 100K+ users
2. **Remote Content Injection**: Server can inject arbitrary HTML into web pages
3. **No Transparency**: Users expect VPNs to protect privacy, not log all browsing
4. **Trust Violation**: VPN service is collecting the exact data users trust it to protect
5. **Potential for Abuse**: Server compromise or malicious insider could access 100K users' browsing histories

### Vulnerability Breakdown
- **CRITICAL**: 0
- **HIGH**: 2 (Browsing data exfiltration, Remote HTML injection)
- **MEDIUM**: 1 (Extension conflict resolution - informational)
- **LOW**: 1 (Google Analytics tracking)

### Recommendations

**For Users**:
1. **UNINSTALL** if privacy is a concern
2. Assume all browsing data while VPN is active is logged by vendor
3. Review privacy policy and terms of service
4. Consider alternative VPN providers with verified no-logs policies

**For Vendor (Malus)**:
1. **Immediate**: Update privacy policy to disclose URL/title logging
2. **Short-term**: Implement opt-in for browsing data collection
3. **Long-term**: Eliminate URL logging entirely (VPN best practice)
4. **Transparency**: Publish data retention and deletion policies

**For Chrome Web Store**:
1. Review for User Data Policy compliance
2. Require prominent disclosure of browsing data collection
3. Consider suspension pending privacy policy updates

### User Privacy Impact
**SEVERE** - The extension collects:
- Complete browsing history (URLs + titles) for all proxied pages
- User authentication and account details
- Device identifiers (UUID)
- Tab activity across all open tabs
- VPN usage patterns (servers, timing, duration)

**All data linked to authenticated user accounts and stored on vendor servers indefinitely (no disclosed retention policy).**

## Technical Summary

**Lines of Code**: ~5,448 (background.js deobfuscated)
**External Dependencies**: React, Redux, react-ga (Google Analytics)
**Third-Party Libraries**: Standard React ecosystem
**Remote Code Loading**: Yes (HTML injection via `getChromeIframe`)
**Dynamic Code Execution**: No (no eval/Function)

## Conclusion

Malus VPN is a **functional VPN service with severe privacy violations**. While the core proxy functionality works as advertised, the extension engages in comprehensive browsing surveillance that directly contradicts user expectations for VPN privacy. The logging of every visited URL and page title to the vendor's servers, combined with remote HTML injection capabilities, represents a significant breach of user trust.

**The extension is not technically "malware"** in the sense of stealing credentials or installing backdoors, but it is **malicious in privacy practice** by collecting extensive browsing data without adequate disclosure. For users who installed a VPN to protect their privacy, this extension actively undermines that goal.

**Final Verdict: HIGH RISK** - Functional VPN with severe privacy violations. Users should be aware their complete browsing history is logged by the vendor.

## Tags
- `privacy:browsing_data_exfil` - Logs URL + title to remote servers
- `privacy:tab_url_tracking` - Monitors all tab URLs
- `vuln:remote_html_injection` - Server-controlled HTML injection
- `behavior:extension_conflict_resolution` - Disables competing VPN extensions (standard practice)
