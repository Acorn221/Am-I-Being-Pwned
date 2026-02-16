# Security Analysis: Unblock Bilibili (jpegpdbkhceiipenjmaglmphmfjjpbmp)

## Extension Metadata
- **Name**: Unblock Bilibili
- **Extension ID**: jpegpdbkhceiipenjmaglmphmfjjpbmp
- **Version**: 3.0.1
- **Manifest Version**: 2
- **Estimated Users**: ~40,000
- **Developer**: Malus (getmalus.com)
- **Analysis Date**: 2026-02-15

## Executive Summary
Unblock Bilibili is a proxy extension designed to bypass geo-restrictions on Chinese streaming platforms. The extension transmits browsing activity (current tab URLs and page titles) to the developer's remote API and injects dynamic advertising content into visited pages. While the proxy functionality is legitimate, the extension exhibits **MEDIUM** risk due to unnecessary collection of browsing metadata and injection of remotely-controlled content.

**Overall Risk Assessment: MEDIUM**

The extension routes traffic through Malus proxy servers to unblock region-restricted content, which is its stated purpose. However, it also sends browsing context to remote servers for ad targeting and periodically injects promotional iframes. These practices raise privacy concerns for users who may not expect their browsing activity to be tracked.

## Vulnerability Assessment

### 1. Browsing Activity Tracking
**Severity**: MEDIUM
**Files**: `/static/js/background.js` (lines 3548-3555)

**Analysis**:
The extension sends the current tab's URL and page title to the Malus API endpoint `getUnblockIframe` to fetch advertising content. This creates a log of user browsing activity on the remote server.

**Code Evidence** (`background.js`):
```javascript
t = Ge.getState(), r = t.setting, n = t.tab, o = n.tabs, a = n.activated,
s = o[a] || {}, u = s.title, c = void 0 === u ? "" : u,
f = s.url, l = void 0 === f ? "" : f,
p = {
  app: ze.f.app,
  appVersion: r.manifest.version,
  url: l,        // Current tab URL sent to API
  title: c       // Current tab title sent to API
},
e.next = 5, this.post("getUnblockIframe", {
  body: p
});
```

**Network Flow**:
```
chrome.tabs.query() → tab.url + tab.title → POST api.getmalus.com/api/getUnblockIframe
```

**Data Transmitted**:
- Current tab URL
- Current tab page title
- Extension version
- App identifier ("chrome-bilibili")
- User token (if authenticated)
- Device UUID
- Browser language

**Privacy Impact**:
- Creates server-side logs of which pages users visit
- Allows behavioral profiling for ad targeting
- No explicit user consent mechanism for tracking
- Data sent even when proxy is not actively being used

**Mitigation**: The extension should only transmit browsing data when the proxy is active for specific whitelisted domains (Bilibili, etc.), not for all browsing activity.

**Verdict**: **MEDIUM RISK** - Unnecessary collection of browsing metadata beyond functional requirements.

---

### 2. Dynamic Content Injection
**Severity**: MEDIUM
**Files**:
- `/content.js` (lines 1-25)
- `/static/js/background.js` (lines 3553-3569)

**Analysis**:
The extension injects iframes into visited pages containing remotely-controlled HTML content. This creates a potential attack surface if the API is compromised or serves malicious content.

**Code Evidence** (`content.js`):
```javascript
const malusframe = document.createElement("iframe");
malusframe.src = `data:text/html;charset=utf-8, ${escape(html)}`;
malusframe.id = "malus-container";
const styleEl = document.createElement("style");
styleEl.innerHTML = `
#malus-container {
  display: none;
  position: fixed;
  top: 60px;
  right: 0;
  width: 320px;
  height: 320px;
  border: none;
  overflow: hidden;
  z-index:999999999999999999;
}`;
```

**Injection Trigger** (`background.js`):
```javascript
case 5:
  h = e.sent, d = {
    html: "",
    delay: 0,
    valid: !1
  },
  0 === h.code && h.data && (y = h.data, v = y.html, b = y.delay,
  d = {
    html: v,      // Remotely-controlled HTML
    delay: b,
    valid: !0
  }),
  Ge.dispatch({
    type: "campaign",
    operate: "iframe",
    iframeHTML: d  // Injected into page
  });
```

**Attack Surface**:
- Remote API controls iframe HTML content
- iframe injected into all pages matching content script patterns
- High z-index (999999999999999999) overlays page content
- No validation of HTML content before injection

**CSP Protection**:
The extension's CSP allows connections to Malus domains:
```json
"content_security_policy": "default-src 'self' https://api.getmalus.com https://getmalus.com https://ps-test.zoonode.com:8002 https://www.google-analytics.com; script-src 'self' https://www.google-analytics.com; ..."
```

**Potential Risks**:
- If `api.getmalus.com` is compromised, arbitrary content can be injected
- Phishing overlays could be displayed on legitimate sites
- Click-jacking attacks via high z-index iframes
- User tracking via iframe content

**Mitigation**: Content injection should use CSP-restricted templates or require explicit user interaction.

**Verdict**: **MEDIUM RISK** - Dynamic content injection from remote API without validation.

---

### 3. Externally Connectable to Localhost
**Severity**: LOW
**Files**: `/manifest.json` (line 22)

**Analysis**:
The extension allows external connections from localhost, which could enable local applications to communicate with the extension.

**Code Evidence** (`manifest.json`):
```json
"externally_connectable": {
  "matches": ["*://localhost/*"]
}
```

**Risk Assessment**:
- Allows localhost webpages/apps to send messages to extension
- Could be used by local malware to interact with proxy
- Limited attack surface (requires local access)

**Legitimate Use Case**:
This may be intended for developer debugging or integration with local Malus client software.

**Verdict**: **LOW RISK** - Minimal attack surface, requires local system access.

---

## Network Analysis

### API Endpoints
The extension communicates with multiple Malus backend services:

**Primary APIs**:
- `api.getmalus.com` - Main API server
- `api.getmalus.net` - Backup API server
- `a.getmalus.cn` - China-based API server

**API Calls Observed**:
1. **getProxyConfig4** - Retrieves proxy server configuration
   - Request: `{ id, bypassMedia, passFirewall }`
   - Response: `{ auth, rules, servers, version, groups }`

2. **getUnblockIframe** - Fetches advertising content
   - Request: `{ app, appVersion, url, title }`
   - Response: `{ html, delay, valid }`

3. **getOperationConfig** - Unknown operational configuration
   - Request: `{ app }`

**Network Headers**:
```javascript
{
  "Content-Type": "application/json",
  "x-malus-app": "chrome-bilibili",
  "X-Malus-Token": "<user_token>",
  "X-Malus-UUID": "<device_uuid>",
  "X-Malus-Version": "3.0.1",
  "X-Malus-Lang": "<browser_language>"
}
```

**Third-Party Services**:
- `www.google-analytics.com` - Analytics tracking (GA ID: UA-92398359-8)
- `ps-test.zoonode.com:8002` - Speed test endpoint (fetches `/10MB.bin`)
- `malusfile.com` - CDN for static assets

**Proxy Routing**:
The extension only proxies traffic for whitelisted domains:
```javascript
proxyUrls: [
  "*://bilibili.com/*",
  "*://*.bilibili.com/*",
  "*://bilibili.cn/*",
  "*://*.bilibili.cn/*",
  "*://*.acgvideo.com/*",
  "*://*.ksyungslb.com/*",
  "*://*.szbdyd.com/*",
  "*://*.bilivideo.com/*"
]
```

**Direct Routing** (bypasses proxy):
```javascript
["DOMAIN-SUFFIX", "getmalus.com", "DIRECT"],
["DOMAIN-SUFFIX", "google-analytics.com", "DIRECT"],
["DOMAIN-SUFFIX", "malusfile.com", "DIRECT"],
["DOMAIN-SUFFIX", "localhost", "DIRECT"]
```

---

## Permission Analysis

### High-Risk Permissions

**webRequest + webRequestBlocking**:
- Intercepts and modifies network requests
- Used for proxy injection on whitelisted domains
- Legitimate for proxy functionality

**proxy**:
- Controls browser proxy settings
- Routes specific domains through Malus servers
- Standard for VPN/proxy extensions

**tabs**:
- Reads tab URLs and titles
- **CONCERNING**: Used to send browsing data to API
- Excessive for proxy-only functionality

### Medium-Risk Permissions

**storage**:
- Stores user settings and tokens
- Stores UUID for device tracking
- Standard for user authentication

**management** (optional):
- Not granted by default
- Could enumerate installed extensions
- Not observed being used in code

---

## Code Quality & Obfuscation

The extension uses React and is minified/bundled with Webpack. While this is standard for modern web applications, it makes code analysis more difficult. The deobfuscated code reveals:

**React Error URLs**:
The "exfiltration" flows detected by ext-analyzer pointing to `reactjs.org` are **false positives**. These are React's error handling URLs:
```javascript
for (var t = arguments.length - 1,
     r = "https://reactjs.org/docs/error-decoder.html?invariant=" + e,
     n = 0; n < t; n++)
  r += "&args[]=" + encodeURIComponent(arguments[n + 1]);
```
This is standard React development code for error messages and does not represent data exfiltration.

---

## Data Flow Summary

### Sensitive Data Sources
1. **chrome.tabs.query()** - Gets all tab URLs and titles
2. **chrome.storage.local** - User tokens, UUID, settings
3. **chrome.i18n.getUILanguage()** - Browser language

### Network Sinks
1. **fetch(api.getmalus.com/api/getUnblockIframe)** - Receives browsing activity
2. **fetch(api.getmalus.com/api/getProxyConfig4)** - Receives proxy preferences
3. **Google Analytics** - Receives usage telemetry

### Data Flow Traces
```
Source: chrome.tabs.query() → tab.url, tab.title
  ↓
Processing: Store in Redux state (Ge.getState())
  ↓
Transmission: POST to api.getmalus.com/api/getUnblockIframe
  ↓
Result: Returns HTML for iframe injection
```

---

## Behavioral Observations

### Installation Flow
1. Opens `getmalus.com/r/chrome-bilibili-installed` on first install
2. Opens `getmalus.com/r/chrome-bilibili-updated` on version update
3. Sets uninstall URL to `getmalus.com/r/chrome-bilibili-uninstalled`

**Tracking Purpose**: Measures install/uninstall metrics via UTM parameters.

### Speed Testing
The extension includes a bandwidth speed test:
```javascript
return t = Date.now(), this.controller = new AbortController,
e.next = 4, fetch("https://ps-test.zoonode.com:8002/10MB.bin?r=" + Math.random(), {
  signal: this.controller.signal
}).then(function(e) {
  // Calculates download speed
})
```

**Purpose**: Likely used to optimize proxy server selection based on user connection speed.

---

## Risk Verdict

### Risk Level: MEDIUM

**Justification**:
The extension performs its advertised proxy functionality legitimately by routing whitelisted domains through Malus servers to bypass geo-restrictions. However, it exhibits concerning privacy practices:

**Concerning Behaviors**:
1. **Unnecessary browsing tracking** - Sends tab URLs/titles even when proxy is inactive
2. **Remote content injection** - Injects API-controlled HTML without validation
3. **Lack of transparency** - No clear disclosure of tracking in store listing

**Mitigating Factors**:
1. Proxy only affects whitelisted streaming domains
2. No observed credential theft or keylogging
3. React error URLs are false positives, not exfiltration
4. Developer (Malus) is an established VPN service provider

**Recommendations for Users**:
- Be aware that browsing activity on Chinese streaming sites is logged
- Expect advertising content to be injected periodically
- Consider if geo-unblocking benefit outweighs privacy trade-off
- Review Malus privacy policy at getmalus.com

**Recommendations for Developer**:
- Only collect browsing data when proxy is active
- Implement CSP validation for injected iframe content
- Add clear privacy disclosures in extension description
- Provide opt-out for advertising content injection

---

## Conclusion

Unblock Bilibili is a **functional geo-restriction bypass tool with privacy concerns**. The proxy mechanism is legitimate and properly scoped to Chinese streaming platforms. However, the extension tracks browsing activity beyond what's necessary for proxy operation and injects remotely-controlled advertising content.

**Final Risk Rating: MEDIUM** - Privacy-invasive tracking and dynamic content injection justify caution, but no critical malware behavior observed.
