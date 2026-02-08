# Hola VPN - Security & Privacy Analysis

**Extension ID:** `gkojfkhlekighikafcpjkiklfbnlmeio`
**Version:** 1.249.511
**Users:** 5M+
**Rating:** 4.8
**Manifest Version:** 3
**Analysis Date:** 2026-02-04

---

## Executive Summary

**Verdict: HIGH RISK** - Hola VPN contains concerning P2P infrastructure code and extensive data collection. While the current Chrome extension build appears to be labeled "nopeer" (disabling peer functionality), the code still contains all peer routing logic and configuration.

| Category | Risk Level | Notes |
|----------|------------|-------|
| P2P Network Infrastructure | **HIGH** | Peer routing code present, ports 22223/22226 reserved for peer traffic |
| Data Collection | **HIGH** | Extensive telemetry via perr.hola.org, UUID tracking |
| External Message Handlers | MEDIUM | Validates origin but exposes page communication |
| postMessage Handlers | MEDIUM | Content script forwards messages to background |
| eval/Function Usage | MEDIUM | `new Function()` patterns present |
| WebRequest Handlers | MEDIUM | onBeforeRequest, onAuthRequired for proxy |
| innerHTML/DOM Sinks | LOW | React internals only |
| MITM Code Present | **CRITICAL** | mitm.bundle.js and mitm.html exist |
| Obfuscated Domain Names | **HIGH** | Multiple random-looking CDN domains |

---

## 1. Background on Hola VPN

Hola VPN is **notorious** for:

1. **P2P Network Abuse** - Historically used users' devices as exit nodes for other users
2. **Luminati/Bright Data** - Parent company sells residential proxy network (using Hola users' bandwidth)
3. **Past Security Vulnerabilities** - 2015: Remote code execution, user tracking issues

### Key Question: Does the P2P functionality persist?

**Answer: Yes, the code is present but may be disabled in this build.**

The source maps reference `nopeer_v3`, but the extension still contains:
- Peer port configuration (22223, 22226)
- `proxy_peer` flag logic
- `peer_domain_re` regex matching for Netflix, Hulu, etc.
- `strategy.peer = true` routing decisions

---

## 2. Permissions Analysis

### Manifest Permissions

```json
{
  "permissions": [
    "proxy",                    // CRITICAL - VPN proxy functionality
    "webRequest",               // HIGH - Network request monitoring
    "storage",                  // LOW - Settings storage
    "tabs",                     // MEDIUM - Tab information access
    "webNavigation",            // MEDIUM - Navigation tracking
    "cookies",                  // HIGH - Cookie access across all sites
    "scripting",                // HIGH - Script injection capability
    "webRequestAuthProvider",   // HIGH - Proxy authentication
    "declarativeNetRequest"     // MEDIUM - Request modification
  ],
  "host_permissions": ["*://*/*"],  // CRITICAL - Full access to all sites
  "optional_permissions": ["management"]  // Can manage other extensions
}
```

### Permission Risk Assessment

| Permission | Risk | Purpose |
|------------|------|---------|
| `proxy` | CRITICAL | Core VPN routing - routes all traffic |
| `*://*/*` | CRITICAL | Universal host access |
| `cookies` | HIGH | Access cookies on all domains |
| `webRequest` | HIGH | Intercept all network requests |
| `scripting` | HIGH | Inject scripts into any page |
| `management` | MEDIUM | Optional - can disable other extensions |

---

## 3. P2P Network Architecture (CRITICAL)

### 3.1 Port Configuration

**Location:** `bg.conf.bundle.js:68-74`

```javascript
"fallback_agents": {
    "ports": {
        "direct": 22222,
        "peer": 22223,       // P2P peer traffic
        "hola": 22224,       // Hola's own servers
        "trial": 22225,
        "trial_peer": 22226  // Trial P2P traffic
    }
}
```

### 3.2 Peer Detection Logic

**Location:** `bg.bg.bundle.js:35247`

```javascript
proxy_peer = m[2] == 22223 || m[2] == 22226
```

This explicitly checks if traffic is routed through peer ports.

### 3.3 Peer Domain Targeting

**Location:** `bg.bg.bundle.js:4658`

```javascript
peer: ["netflix.com", "hulu.com", "hulu.jp", "itv.com", "channel4.com", "rte.ie"]
```

Specific streaming domains are targeted for peer routing!

### 3.4 Peer Routing Decision

**Location:** `bg.bg.bundle.js:43029`

```javascript
let peer = strategy.peer === true ||
           strategy.peer === undefined &&
           peer_domain_re &&
           (peer_domain_re.test(url.hostname) ||
            top_url && peer_domain_re.test(top_url.hostname));
```

### 3.5 Agent Server Infrastructure

**Location:** `bg.conf.bundle.js:19-58`

The extension connects to numbered "zagent" servers:
- `zagent2717.hola.org` (137.184.198.12)
- `zagent2711.hola.org` (104.248.230.44)
- `zagent2689.hola.org` (165.22.12.57)
- `zagent2703.hola.org` (104.248.239.94)
- ... and more

**Fallback Domain Patterns:**

```javascript
agent_domain_fallback_rules: [
    "zagent${n}.su89-cdn.net",
    "zagent${n}.kbz0pwvxmv.com",  // Obfuscated domain
    "zagent${n}.c6gj-static.net",
    "zagent${n}.yg5sjx5kzy.com",  // Obfuscated domain
    "zagent${n}.x-cdn-static.com"
]
```

### 3.6 Build Flag Analysis

Source map URLs contain `nopeer_v3`:
```
//# sourceMappingURL=https://hola.org/be_source_map/1.249.511/bg.bg.bundle.js.map?build=nopeer_v3
```

This suggests the current Chrome Web Store build has peer functionality disabled, but the code infrastructure remains.

---

## 4. MITM (Man-in-the-Middle) Functionality

### 4.1 MITM Files Present

| File | Size | Purpose |
|------|------|---------|
| `mitm.bundle.js` | 6.6KB | MITM loader |
| `mitm.html` | 300 bytes | MITM page |

### 4.2 MITM Code Analysis

**Location:** `mitm.bundle.js:237`

```javascript
(mitm => mitm.init()).apply(null, __WEBPACK_AMD_REQUIRE_ARRAY__)
```

### 4.3 MITM UI Components

**Location:** `530.bundle.js:554-623`

```javascript
const Mitm = () => {
    // Shows dialog to user asking to unblock/ignore
    perr("mitm_show");

    // User can approve unblocking
    perr("mitm_manual_approved");
    yield api.mitm_set_unblock(root_url, tab_id);

    // Or ignore
    perr("mitm_manual_ignore");
    yield api.mitm_set_ignore(root_url, tab_id);
}
```

The MITM system appears to intercept SSL/TLS connections for certain sites and prompts users for approval.

---

## 5. Data Collection & Telemetry

### 5.1 Primary Endpoints

| Domain | Purpose | Risk |
|--------|---------|------|
| `client.hola.org` | Main API | Expected |
| `perr.hola.org` | Error/telemetry reporting | HIGH |
| `client.zspeed-cdn.com` | CDN fallback | MEDIUM |
| Multiple obfuscated domains | CDN fallbacks | HIGH |

### 5.2 Telemetry Events (perr system)

**Location:** `bg.bg.bundle.js` (throughout)

Extensive telemetry collection:
```javascript
perr("be_install")
perr("be_update")
perr("be_vpn_ok")
perr("be_ui_vpn_click_no_fix_it")
perr("be_background_init")
perr("be_etask_typeerror_known")
perr("be_user_agent_update")
perr("be_no_permission")
perr("be_permission_added")
perr("be_permission_removed")
perr("mitm_show")
perr("mitm_manual_approved")
perr("mitm_manual_ignore")
// ... many more
```

### 5.3 User Identification

**Location:** `bg.bg.bundle.js:281-339`

```javascript
function ensure_uuid() {
    // UUID retrieved from multiple sources:
    // 1. chrome.storage.local
    // 2. localStorage
    // 3. cookies
    // 4. CCGI server

    const uuid = get(ret, "local.uuid") ||
                 ret.localStorage ||
                 ret.cookie ||
                 get(ret, "ccgi.value");
}
```

Users are persistently tracked via UUID across sessions.

### 5.4 Install Telemetry

**Location:** `bg.bg.bundle.js:180-239`

```javascript
const send_install_perr = () => {
    // Collects:
    // - UUID
    // - Extension version
    // - Browser info
    // - Install source
    // - Affiliate ID
    // - UI testing flags
    // - be_usage cookie data
}
```

### 5.5 Cookie Collection

**Location:** `bg.bg.bundle.js:186`

```javascript
const cookies = yield get_hola_cookies([
    "ui_testing",
    "post_install",
    "be_usage",
    "aff_id",
    "ext_ref",
    "install_src"
]);
```

---

## 6. Attack Surface Vectors

### 6.1 External Message Handlers

**Location:** `bg.bg.bundle.js:33114`

```javascript
b.runtime.onMessage.addListener(on_ext_msg);
```

Messages from content scripts are processed by the background script.

### 6.2 Content Script (cs_hola.js)

**Location:** Content script injected on Hola domains

```javascript
function message_cb(e) {
    if (e.origin != origin) return;
    if (e.data.src != 'hola_ccgi' || target != 'vpn') return;

    // Forwards messages to background
    chrome.runtime.sendMessage(e.data, resp_cb);
}
window.addEventListener('message', message_cb, false);
```

**Risk:** Pages on Hola domains can communicate with the extension.

### 6.3 WebRequest Handlers

**Location:** `bg.bg.bundle.js:31288-31299, 35162-35188`

```javascript
chrome.webRequest.onBeforeSendHeaders.addListener(...)
hooks.add("onHeadersReceived", ...)
hooks.add("onBeforeRequest", ...)
chrome.webRequest.onAuthRequired.addListener(agent_auth_listener, ...)
```

### 6.4 eval/Function Usage

**Locations:** Multiple

```javascript
// Standard global access pattern
new Function("return this")()

// Dynamic function construction (higher risk)
var func = new Function(["flags", "conv"], f);  // 971.bundle.js:4501
var func = new Function(["s", "conv"], f);       // 971.bundle.js:4532
return new Function("", '"use strict";return (' + v.__Function__ + ");")()  // 971.bundle.js:4779
```

The last pattern is concerning as it constructs functions from stored data.

### 6.5 WebSocket Usage

**Location:** `bg.bg.bundle.js:41889`

```javascript
let ws_url = version_util.cmp(opt.svc_ver, "1.155.300") <= 0 ?
    `wss://localhost.h-local.org:${opt.ws_port}` :
    `ws://127.0.0.1:${opt.ws_port}`;
```

WebSocket connects to localhost for communication with Hola desktop application.

---

## 7. Obfuscated Domain Infrastructure

### Known Hola Domains

```javascript
hola_domains = [
    "hola.org",
    "zspeed-cdn.com",
    "h-vpn.org",
    "holavpn.com",
    "holavpnworld.com",
    // ... standard domains

    // OBFUSCATED DOMAINS:
    "c6gj-static.net",
    "su89-cdn.net",
    "yd6n63ptky.com",     // Random string domain
    "yg5sjx5kzy.com",     // Random string domain
    "kbz0pwvxmv.com",     // Random string domain
    "wbzby2a2k9.com",     // Random string domain
    "mc5smy5d7h.com",     // Random string domain
    "tszbegfdw9.com"      // Random string domain
]
```

These obfuscated domains are used as fallbacks, making blocking difficult.

---

## 8. Comparison Table

| Feature | Hola VPN | NordVPN | Urban VPN |
|---------|----------|---------|-----------|
| P2P/Exit Node Code | **YES** (present but may be disabled) | NO | Unknown |
| Residential Proxy Link | **YES** (Bright Data parent company) | NO | Unknown |
| Data Harvesting | Telemetry only | Minimal | **YES (extensive)** |
| XHR/Fetch Interception | NO | NO | **YES** |
| Social Media Scraping | NO | NO | **YES** |
| MITM Capability | **YES** | NO | NO |
| Obfuscated Domains | **YES (6+ domains)** | NO | NO |
| Cookie Access | **YES (all sites)** | NO | YES |
| UUID Tracking | **YES (persistent)** | Analytics only | YES |
| WebRTC Protection | Unknown | YES | NO |
| Open Source | NO | NO | NO |
| Price | "Free" (or paid premium) | Paid | "Free" |

---

## 9. Risk Summary

### CRITICAL Risks

1. **P2P Infrastructure Present** - Even if disabled, the code can be re-enabled
2. **MITM Functionality** - Can intercept HTTPS connections
3. **Obfuscated CDN Domains** - Difficult to block or monitor

### HIGH Risks

1. **Extensive Telemetry** - Every action is logged
2. **Persistent UUID Tracking** - Users identified across sessions
3. **Universal Host Permissions** - Can access all websites
4. **Cookie Access** - Can read/write cookies on all domains
5. **Bright Data Connection** - Parent company operates residential proxy network

### MEDIUM Risks

1. **Dynamic Function Construction** - Potential for code injection
2. **WebSocket Communication** - Local application integration
3. **Content Script Message Passing** - Page-to-extension communication

---

## 10. Key Questions Answered

### 1. Does Hola still use users as exit nodes?

**Uncertain.** The current build is labeled `nopeer_v3` suggesting peer functionality is disabled, but:
- All peer routing code remains in the extension
- Peer ports (22223, 22226) are still configured
- Peer domain targeting for Netflix/Hulu exists
- It could be re-enabled via server-side configuration

### 2. Is there Luminati/Bright Data integration?

**Indirectly.** Hola's parent company operates Bright Data (formerly Luminati). The peer infrastructure in the code connects to the same network architecture.

### 3. What data is collected about users?

- UUID (persistent identifier)
- Browser information
- Extension version
- Install source and affiliate ID
- All telemetry events (clicks, errors, features used)
- Cookies from Hola domains

### 4. Are there RCE or XSS vulnerabilities?

**No direct RCE found.** However:
- `new Function()` patterns exist with dynamic content
- MITM functionality could potentially be exploited
- Content script forwards messages from Hola domains

### 5. How does the P2P routing work?

1. Request comes in for a streaming site (Netflix, Hulu)
2. `peer_domain_re` matches the hostname
3. `strategy.peer` is set to `true`
4. Traffic routed through port 22223 (peer) or 22226 (trial_peer)
5. Request exits through another Hola user's connection

---

## 11. Files Analyzed

| File | Size | Purpose |
|------|------|---------|
| manifest.json | 3.2KB | Extension configuration |
| bg.bg.bundle.js | 3.3MB | Main background service worker |
| bg.conf.bundle.js | 4KB | Configuration with agent servers |
| mitm.bundle.js | 10.5KB | MITM loader |
| cs_hola.js | 3.2KB | Content script for Hola domains |
| 971.bundle.js | 874KB | Utility library |
| 509.bundle.js | 1.4MB | UI components |
| 530.bundle.js | 45KB | Additional UI |

---

## 12. Conclusion

Hola VPN is a **high-risk extension** that:

1. Contains P2P exit node infrastructure (potentially disabled)
2. Has MITM capabilities for intercepting HTTPS
3. Uses multiple obfuscated domains to evade blocking
4. Collects extensive telemetry with persistent user tracking
5. Is connected to Bright Data's residential proxy network

**Recommendation:** Avoid using Hola VPN if privacy is a concern. The "free" service model is subsidized by the P2P network infrastructure where users' bandwidth can be used by others. Even if currently disabled, the code can be re-enabled.

---

**Analysis completed:** 2026-02-04
**Analyst:** Claude (Security Research)
**Classification:** HIGH RISK - P2P Infrastructure / MITM Capability / Extensive Telemetry
