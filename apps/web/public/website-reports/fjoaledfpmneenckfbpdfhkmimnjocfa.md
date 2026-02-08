# NordVPN Extension - Attack Surface Analysis

**Extension ID:** `fjoaledfpmneenckfbpdfhkmimnjocfa`
**Version:** 5.3.1
**Users:** 12M+
**Manifest Version:** 3

---

## Executive Summary

**Verdict: CLEAN** - No exploitable vulnerabilities found. Well-designed extension with proper security controls.

| Category | Risk Level | Notes |
|----------|------------|-------|
| External Message Handlers | LOW | Proper sender ID validation |
| postMessage Handlers | LOW | Message type filtering |
| innerHTML/DOM Sinks | LOW | React internals only |
| eval/Function Usage | SAFE | Only `Function("return this")()` for global |
| WebRequest Handlers | SAFE | Proxy auth only, no content interception |
| Tab Creation | SAFE | Hardcoded URLs only |
| WebSocket | SAFE | localhost only, whitelisted |
| Native Messaging | N/A | Not used |
| Cookie/History Access | N/A | Not used |

---

## 1. Permissions Analysis

### Manifest Permissions
```json
{
  "permissions": [
    "alarms",           // Timer functionality
    "scripting",        // Script injection (for proxy detection)
    "proxy",            // VPN proxy functionality
    "webRequest",       // Proxy auth handling
    "webNavigation",    // Tab state tracking
    "privacy",          // WebRTC leak protection
    "storage",          // Settings storage
    "notifications",    // User alerts
    "tabs",             // Tab management
    "contextMenus",     // Right-click menu
    "activeTab",        // Current tab access
    "unlimitedStorage", // Large cache
    "downloads",        // Log file downloads
    "declarativeNetRequestWithHostAccess",  // Ad/tracker blocking
    "webRequestAuthProvider",  // Proxy authentication
    "offscreen"         // Background processing
  ],
  "host_permissions": ["<all_urls>"]  // Required for VPN
}
```

### Permission Risk Assessment

| Permission | Purpose | Risk |
|------------|---------|------|
| `proxy` | Core VPN functionality | Expected |
| `webRequest` | Proxy authentication | Expected - NOT used for traffic inspection |
| `<all_urls>` | Route all traffic through VPN | Expected |
| `privacy` | WebRTC leak protection | Security feature |
| `declarativeNetRequest` | Threat Protection (ad/tracker blocking) | Bonus feature |
| `scripting` | Proxy detection on YouTube | Limited use - ISOLATED world |

---

## 2. External Communication

### Endpoints

| Domain | Purpose | Risk |
|--------|---------|------|
| `nordvpn.com` | Main API | Expected |
| `my.nordaccount.com` | User account | Expected |
| `applytics.nordvpn.com` | First-party analytics | LOW - consent-based |
| `mqtt.nordvpn.com` | Real-time VPN status | Expected |
| `nordvpn.zendesk.com` | Support tickets | Expected |
| `sentry.io` (docs only) | Error tracking | LOW - opt-in |
| `ws://localhost:{port}` | Desktop app communication | SAFE - local only |

### NOT Present (Good)
- No third-party analytics (Google Analytics, Mixpanel, etc.)
- No advertising networks
- No data brokers
- No social media trackers

---

## 3. Attack Vector Evaluation

### 3.1 External Message Handlers

**Location:** `background.js:69513`

**Finding:** The extension registers listeners for `onMessageExternal` and `onConnectExternal` but ONLY for logging/debugging purposes:

```javascript
e("runtime.onMessageExternal", r7.runtime?.onMessageExternal)
// Where e() just logs events, doesn't process them
```

**Actual message validation** (`background.js:69066`):
```javascript
$P = (e, t) => {
    if (e?.id !== r7.runtime.id) return !1;  // ✓ Validates sender extension ID
    if (t) {
        let t = $N();  // Gets extension origin
        return "origin" in e ? e?.origin === t : e?.url?.startsWith(t) === !0
    }
    // ...
}
```

**Verdict:** SAFE - External messages are rejected. Only messages from the extension itself are processed.

---

### 3.2 postMessage Handlers

**Location:** `background.js:45902`

```javascript
globalThis.addEventListener("message", function(e) {
    e.data?.name === "cs-proxy-detection" && chrome.runtime.sendMessage(e.data)
})
```

**Analysis:**
- Only forwards messages with exact name `"cs-proxy-detection"`
- Injected in `ISOLATED` world (sandboxed from page)
- Used for YouTube proxy detection feature

**Verdict:** SAFE - Strict message type filtering, isolated execution context.

---

### 3.3 innerHTML/DOM Sinks

**Locations:** `uiMain.js`, `csNotification.js`

**Finding:** All innerHTML references are React internal code:
```javascript
"children dangerouslySetInnerHTML defaultValue defaultChecked innerHTML..."
```

This is React's DOM property handling, not actual innerHTML assignments from user data.

**Verdict:** SAFE - No user-controlled innerHTML.

---

### 3.4 eval/Function Usage

**Pattern found:**
```javascript
Function("return this")()
```

**Analysis:** This is a standard pattern to get the global object (`globalThis`). Used by:
- Polyfills
- Library code (Redux, etc.)
- No user input passed to Function()

**Verdict:** SAFE - No code execution from external data.

---

### 3.5 WebRequest Handlers

**Locations:**
- `background.js:69472` - `onAuthRequired` (proxy authentication)
- `background.js:69482` - `onCompleted` (connection tracking)
- `background.js:32884` - `onErrorOccurred` (error detection)

**Analysis:**
```javascript
r9.chrome.webRequest.onAuthRequired.addListener((e, n) => {
    // Returns proxy credentials
}, rC, ["asyncBlocking", "responseHeaders"])
```

**NOT PRESENT:**
- No `onBeforeRequest` with blocking (no request interception)
- No response body reading
- No URL logging

**Verdict:** SAFE - Only used for legitimate proxy authentication.

---

### 3.6 Tab Creation

**Locations:** `background.js:16678`, `background.js:68163`

**URLs used:**
```javascript
t4 = {
    chrome: "https://chromewebstore.google.com/detail/nordvpn.../reviews",
    firefox: "https://addons.mozilla.org/.../nordvpn-proxy-extension/",
    edge: "https://microsoftedge.microsoft.com/..."
}
```

**Verdict:** SAFE - All URLs are hardcoded constants (store review pages).

---

### 3.7 WebSocket Connection

**Location:** `background.js:53543-53626`

```javascript
allowedConnectionStrings = this.ports.map(e => `ws://localhost:${e}`);
// ...
let t = `ws://localhost:${e}${this.version?`/nordvpn/v${this.version}`:""}`;
if (!this.isWhiteListedDomain(t)) throw Error("websocket url is invalid");
```

**Analysis:**
- Only connects to `ws://localhost:{port}`
- Whitelist validation before connection
- Used for communication with NordVPN desktop application
- Messages are validated with `sanitizeEventData()`

**Verdict:** SAFE - Local only, whitelisted, validated.

---

### 3.8 Script Injection

**Location:** `background.js:45898`

```javascript
await Ep({
    injection: {
        injectImmediately: !0,
        world: "ISOLATED",  // ✓ Sandboxed
        func: () => {
            globalThis.addEventListener("message", function(e) {
                e.data?.name === "cs-proxy-detection" &&
                chrome.runtime.sendMessage(e.data)
            })
        },
        target: { tabId: e, frameIds: [0], allFrames: !1 }
    }
})
```

**Analysis:**
- Injected in ISOLATED world (can't access page JS)
- Only listens for specific message type
- Only targets main frame
- Used for YouTube proxy detection

**Verdict:** SAFE - Minimal, sandboxed injection.

---

## 4. Data Collection Analysis

### Analytics System (Applytics)

**Consent levels:**
- `Essential` - Required for app function
- `NonEssential` - Opt-in analytics
- `Disabled` - No analytics

**Data collected (with consent):**
```javascript
device: {
    cpu: { architecture },
    os, model, resolution, timeZone, type,
    isDataAbuser,  // Abuse detection
    location: { city, country, region }  // VPN server location, NOT user
},
user: {
    nordvpnapp: {
        subscription: { planType, isActive, ... }
    }
}
```

**NOT collected:**
- Browsing history
- Page content
- Form data
- Passwords
- Cookies

**Verdict:** CLEAN - First-party analytics with proper consent, no invasive tracking.

---

## 5. Comparison with Urban VPN

| Feature | NordVPN | Urban VPN |
|---------|---------|-----------|
| Social media scraping | NO | YES (8 platforms) |
| XHR/Fetch interception | NO | YES (monkey-patches APIs) |
| Video/ad data collection | NO | YES |
| Third-party data sharing | NO | YES |
| Consent bypass | NO | YES (install tracking) |
| WebRTC protection | YES | NO |
| DNS leak protection | YES | API traffic leaks |
| Price | Paid | "Free" (you are the product) |

---

## 6. Files Analyzed

| File | Size | Purpose |
|------|------|---------|
| background.js | 3.8MB | Service worker - main logic |
| app.js | 4.5MB | Popup application |
| csNotification.js | 2.1MB | Content script notifications |
| uiMain.js | 831KB | UI components |
| pageKillSwitch.js | 2.0MB | Kill switch page |
| pagePin.js | 1.2MB | PIN entry page |
| offscreenChromium.js | 233KB | Offscreen document |

---

## 7. Conclusion

NordVPN's Chrome extension is a legitimate, well-secured VPN proxy. No exploitable vulnerabilities were found.

**Security Positives:**
- Proper sender validation for all messages
- Isolated script injection
- Whitelist-only WebSocket connections
- Consent-based analytics
- No traffic content inspection
- WebRTC leak protection

**Minor Notes:**
- Uses Sentry for error tracking (opt-in)
- First-party analytics (applytics.nordvpn.com) with consent
- MQTT connection to nordvpn.com for real-time status

**Recommendation:** Safe to use. This is what a VPN extension should look like.
