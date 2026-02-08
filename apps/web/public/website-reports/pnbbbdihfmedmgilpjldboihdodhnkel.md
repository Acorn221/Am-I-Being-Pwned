# QuickVPN Proxy - VPN for Browsing
## Security Analysis Report

**Extension ID:** pnbbbdihfmedmgilpjldboihdodhnkel
**Version:** 1.0.4
**User Count:** ~0 users
**Analysis Date:** 2026-02-08
**Overall Risk:** LOW

---

## Executive Summary

QuickVPN Proxy is a freemium VPN extension that provides browser-level proxy services through datacenter proxies from Webshare.io. The extension includes a 3-day trial period and offers paid licensing through Gumroad. While the extension's core VPN functionality appears legitimate and serves its intended purpose, it exhibits several **architectural security concerns** that prevent it from being classified as CLEAN:

1. **Exposed API Key Retrieval**: Hardcoded Cloudflare Workers endpoint serves Webshare API keys to all users
2. **Insecure Credential Handling**: API keys stored in local storage without encryption
3. **Third-Party Infrastructure Dependencies**: Reliance on external API key service creates availability and security risks
4. **Datacenter Proxy Infrastructure**: Uses commercial proxy service (not residential proxy fraud)

Despite these concerns, the extension does not exhibit malicious behavior, data exfiltration, or deceptive practices. The VPN functionality works as advertised.

---

## Metadata

| Field | Value |
|-------|-------|
| Extension Name | QuickVPN Proxy – VPN for Browsing |
| Extension ID | pnbbbdihfmedmgilpjldboihdodhnkel |
| Version | 1.0.4 |
| Manifest Version | 3 |
| User Count | ~0 users |
| Category | VPN/Proxy |
| Publisher | Unknown (hritikkumarkota on Gumroad) |

---

## Permissions Analysis

### Declared Permissions

```json
{
  "permissions": [
    "proxy",
    "storage",
    "activeTab",
    "webRequest",
    "webRequestAuthProvider",
    "notifications"
  ],
  "host_permissions": [
    "<all_urls>"
  ]
}
```

### Permission Risk Assessment

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `proxy` | Core functionality - required to configure browser proxy settings | ✅ Required |
| `storage` | Stores connection state, API keys, license info, trial data | ✅ Required |
| `activeTab` | Limited use, VPN status display | ⚠️ Low Risk |
| `webRequest` | Monitors proxy connection status | ⚠️ Low Risk |
| `webRequestAuthProvider` | Injects proxy credentials for authentication | ✅ Required |
| `notifications` | Trial expiration and license alerts | ✅ Benign |
| `<all_urls>` | Required for proxy to work across all domains | ✅ Required |

**Verdict:** Permissions are **appropriate** for a VPN extension. No excessive or suspicious permissions detected.

---

## Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Assessment:** Strong CSP - no `unsafe-eval`, no external script sources, no inline scripts allowed. ✅

---

## Vulnerability Analysis

### 1. Exposed API Key Retrieval via Cloudflare Workers

**Severity:** MEDIUM (architectural design flaw, not exploitable for malicious purposes)
**Files:** `background.js:15-36`
**CVSSv3:** 5.3 (MEDIUM) - AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N

**Description:**

The extension retrieves the Webshare API key from a public Cloudflare Workers endpoint:

```javascript
const A = "https://vpn-proxy-api.rovelin.workers.dev";

async function h() {
  try {
    const a = "webshareApiKey_cache",
      e = "webshareApiKey_cacheTime",
      r = Date.now(),
      t = await chrome.storage.local.get([a, e]);
    if (t[a] && t[e] && r - t[e] < 5 * 60 * 1e3) return t[a];

    const s = await fetch(`${A}/webshare-api-key`);  // ⚠️ Public endpoint
    if (!s.ok) throw new Error(`Failed to fetch API key: ${s.status} ${s.statusText}`);

    const o = await s.json();
    if (!o.success || !o.apiKey) throw new Error("Invalid API key response from server");

    return await chrome.storage.local.set({
      [a]: o.apiKey,
      [e]: r
    }), o.apiKey
  } catch (a) {
    console.error("Error getting Webshare API key from server:", a);
    // Falls back to local storage
  }
}
```

**Security Implications:**

1. **API Key Exposure**: Any user can call this endpoint and obtain the Webshare API key
2. **Quota Abuse**: Malicious actors could consume the developer's Webshare proxy quota
3. **Rate Limiting**: No evidence of rate limiting or authentication on the Workers endpoint
4. **Single Point of Failure**: If the Workers endpoint goes down, new users cannot use the extension

**Proof of Concept:**

```bash
curl https://vpn-proxy-api.rovelin.workers.dev/webshare-api-key
# Expected response: {"success": true, "apiKey": "..."}
```

**Recommended Remediation:**

- Use per-user API key generation with license verification
- Implement server-side rate limiting
- Add authentication/authorization to the Workers endpoint
- Consider a backend proxy service instead of exposing API keys

**Exploitation Likelihood:** HIGH (easy to exploit)
**Impact:** MEDIUM (quota abuse, but no user data exposure)
**Verdict:** Design flaw, but not malicious behavior. Affects developer's infrastructure, not end users.

---

### 2. Insecure Credential Storage

**Severity:** LOW
**Files:** `background.js:26-29, 704-713`
**CVSSv3:** 3.3 (LOW) - AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N

**Description:**

The extension stores proxy authentication credentials in unencrypted local storage:

```javascript
// Webshare API key stored in plain text
await chrome.storage.local.set({
  webshareApiKey: o.apiKey,
  webshareApiKey_cacheTime: r
}), o.apiKey

// Proxy credentials stored in plain text
await chrome.storage.local.set({
  proxyAuth: {
    username: t.username,
    password: t.password,  // ⚠️ Plain text password
    serverId: e,
    host: t.ip,
    port: t.port,
    protocol: "http"
  }
})
```

**Security Implications:**

1. Local attackers with filesystem access can read stored credentials
2. Malicious extensions with `storage` permission could access credentials
3. Browser profile theft exposes proxy credentials

**Mitigation Factors:**

- Chrome extension storage is sandboxed per-extension
- Requires local system access or malicious extension to exploit
- Credentials are for datacenter proxies, not user's personal accounts

**Recommended Remediation:**

- Use ephemeral credentials that expire after disconnect
- Store credentials in memory only during active sessions
- Encrypt sensitive data in local storage

**Exploitation Likelihood:** LOW (requires local access or malicious extension)
**Impact:** LOW (datacenter proxy credentials, not user credentials)
**Verdict:** Minor issue, acceptable for VPN extensions with datacenter proxies.

---

### 3. Lack of TLS Certificate Pinning / MITM Risk

**Severity:** LOW
**Files:** `background.js:203-231, 641-649`
**CVSSv3:** 4.2 (MEDIUM) - AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N

**Description:**

API calls to Webshare.io and Gumroad lack TLS certificate pinning:

```javascript
// Webshare API calls (no certificate pinning)
const t = await fetch(r, {
  method: "GET",
  headers: {
    Authorization: `Token ${a}`,
    "Content-Type": "application/json"
  }
});

// Gumroad license verification (no certificate pinning)
const n = await (await fetch(t, {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json"
  },
  body: s.toString()
})).json();
```

**Security Implications:**

1. Man-in-the-Middle attacks could intercept API keys or license keys
2. Corporate proxies/TLS inspection could capture credentials
3. No verification of server certificates beyond browser defaults

**Mitigation Factors:**

- HTTPS is enforced by browser
- Chrome's built-in certificate validation provides baseline protection
- MitM requires network-level access

**Recommended Remediation:**

- Implement certificate pinning for sensitive API endpoints
- Add additional integrity checks for API responses

**Exploitation Likelihood:** LOW (requires network-level MitM position)
**Impact:** MEDIUM (API key/license key exposure)
**Verdict:** Acceptable risk for consumer VPN extensions.

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `fetch()` to external APIs | `background.js:22, 206, 641, 888` | Legitimate API calls to Webshare.io (proxy provider) and Gumroad (licensing) | ✅ False Positive |
| `chrome.storage.local` usage | Throughout codebase | Standard extension storage for settings, connection state, license data | ✅ False Positive |
| `chrome.proxy.settings.set()` | `background.js:713, 821` | Core VPN functionality - expected for proxy extensions | ✅ False Positive |
| `<all_urls>` permission | `manifest.json:28` | Required for proxy to intercept all traffic | ✅ False Positive |
| `webRequestAuthProvider` | `manifest.json:23` | Required to inject proxy auth credentials | ✅ False Positive |
| Hardcoded IP addresses | Server list (fallback) | Static proxy server addresses (not C2 infrastructure) | ✅ False Positive |
| Base64-like string | `background.js:883` | Gumroad product ID (`ZZ2OUzE4OlyB2EqPMrAPsQ==`) - not obfuscation | ✅ False Positive |

---

## API Endpoints & External Communication

### 1. Webshare API (Proxy Provider)

**Endpoint:** `https://proxy.webshare.io/api/v2/proxy/list/`
**Purpose:** Fetch list of available datacenter proxies
**Method:** GET
**Authentication:** Bearer token (from Workers endpoint)
**Data Sent:** None (query params: `mode=direct`, `page`, `page_size`)
**Data Received:** Proxy list with IPs, ports, credentials, geolocation
**Frequency:** On server list refresh (5-minute cache)
**Privacy Impact:** None (no user data sent)

```javascript
const r = `${d.API_BASE_URL}${d.ENDPOINTS.PROXY_LIST}?mode=direct&page=${e}&page_size=${d.DEFAULT_PAGE_SIZE}`;
const t = await fetch(r, {
  method: "GET",
  headers: {
    Authorization: `Token ${a}`,
    "Content-Type": "application/json"
  }
});
```

---

### 2. Cloudflare Workers Endpoint (API Key Service)

**Endpoint:** `https://vpn-proxy-api.rovelin.workers.dev/webshare-api-key`
**Purpose:** Retrieve shared Webshare API key
**Method:** GET
**Authentication:** None ⚠️
**Data Sent:** None
**Data Received:** Webshare API key
**Frequency:** Every 5 minutes (or on first load)
**Privacy Impact:** None (but security risk as noted in Vulnerability #1)

---

### 3. Gumroad License Verification

**Endpoint:** `https://api.gumroad.com/v2/licenses/verify`
**Purpose:** Validate license keys for Pro upgrade
**Method:** POST
**Authentication:** Product ID embedded
**Data Sent:**
- `product_id`: `ZZ2OUzE4OlyB2EqPMrAPsQ==`
- `license_key`: User-provided license key

**Data Received:**
- License validity status
- Purchase details (email, date, uses)

**Frequency:** On user license verification, daily revalidation
**Privacy Impact:** Minimal (Gumroad already has purchase data)

```javascript
const t = "https://api.gumroad.com/v2/licenses/verify";
const s = new URLSearchParams;
s.append("product_id", r), s.append("license_key", e);

const n = await (await fetch(t, {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
    Accept: "application/json"
  },
  body: s.toString()
})).json();
```

---

### 4. Gumroad Purchase Page

**Endpoint:** `https://hritikkumarkota.gumroad.com/l/quickvpn_proxy`
**Purpose:** License purchase link
**Method:** Browser navigation
**Privacy Impact:** None (user-initiated)

---

### 5. Flag CDN

**Endpoint:** `https://flagcdn.com/24x18/{country_code}.png`
**Purpose:** Display country flags in server list
**Method:** GET (image resource)
**Privacy Impact:** Minimal (CDN logs IP addresses, but standard practice)

---

## Data Flow Summary

### Data Collection

**What data is collected:**
- Connection state (current server, connection status)
- Trial start time and remaining time
- License key and verification status
- Webshare API key (cached locally)
- Server list and connection details

**Where data is stored:**
- `chrome.storage.local` (all data stored locally, not synced)

**Data transmission:**
- **To Webshare API**: API key only (no user data)
- **To Gumroad**: License key only (during verification)
- **To Cloudflare Workers**: None (receives API key)

### No Evidence Of:
- ❌ User browsing history collection
- ❌ Cookie harvesting
- ❌ Form data interception
- ❌ Keylogging
- ❌ Ad injection
- ❌ Tracker injection
- ❌ Analytics SDKs
- ❌ Fingerprinting
- ❌ Data exfiltration to unknown servers

---

## Content Script Analysis

**File:** `content.js`
**Injection Scope:** `<all_urls>` at `document_start`
**Functionality:**

1. Displays VPN connection status indicator on pages (optional visual feedback)
2. Listens for proxy status updates from background script
3. Minimal DOM manipulation (adds single overlay div)

```javascript
updatePageProxyStatus(e=null){
  // Creates or updates a small overlay indicator
  let t=document.getElementById("vpn-proxy-indicator");
  if(!t) {
    t=document.createElement("div");
    t.id="vpn-proxy-indicator";
    t.style.cssText=`
      position: fixed;
      top: 10px;
      right: 10px;
      background: rgba(0, 0, 0, 0.8);
      color: white;
      padding: 8px 12px;
      border-radius: 4px;
      z-index: 10000;
      display: none;
    `;
    document.body.appendChild(t);
  }

  if(e&&e.connected) {
    t.innerHTML=`🔒 VPN: ${e.server.name}`;
    t.style.display="block";
  } else {
    t.style.display="none";
  }
}
```

**Security Assessment:**

- ✅ No sensitive DOM access (no form fields, passwords, cookies accessed)
- ✅ No event listeners on user input elements
- ✅ No data exfiltration
- ✅ No script injection
- ✅ Minimal footprint (single div overlay)

**Verdict:** Content script is benign - provides optional VPN status indicator.

---

## Background Script Analysis

**File:** `background.js`
**Primary Functions:**

1. **VPN Service Worker** (`class b`): Manages proxy connections
2. **API Key Management** (`function h`): Retrieves Webshare API key
3. **Server Management** (`function m, T, E`): Fetches and caches proxy servers
4. **License Verification** (`verifyLicense`, `getLicenseStatus`): Gumroad integration
5. **Trial Management** (`initializeTrial`, `checkTrialExpiration`): 3-day trial logic

### Key Security Observations:

**✅ Positive Indicators:**
- No `eval()` or `Function()` constructor usage
- No dynamic code execution
- No obfuscated code (readable variable names after deobfuscation)
- No WebSocket connections to unknown servers
- No cryptocurrency mining
- No extension enumeration/killing behavior
- No hooking of `fetch()` or `XMLHttpRequest`
- No clipboard access
- No geolocation tracking beyond IP-based country detection

**⚠️ Concerns (non-malicious but noteworthy):**
- API key retrieved from public endpoint (see Vulnerability #1)
- Trial enforcement relies on client-side timestamp (easily bypassed)
- No server-side session management
- Fallback to hardcoded server list if API fails

---

## Monetization Model

**Trial:** 3-day free trial (client-side enforcement)
**Licensing:** Gumroad-based license keys
**Payment Link:** `https://hritikkumarkota.gumroad.com/l/quickvpn_proxy`
**Pro Features:** Unlimited server access after trial expiration

**Trial Enforcement:**

```javascript
this.TRIAL_DURATION = 3 * 24 * 60 * 60 * 1e3; // 3 days

async initializeTrial() {
  const r = "2.0";
  if (!e.trialInitialized || e.trialVersion !== r) {
    const t = Date.now();
    await chrome.storage.local.set({
      trialStartTime: t,
      trialInitialized: !0,
      trialVersion: r
    });
  }
}
```

**Security Note:** Trial can be easily bypassed by clearing `chrome.storage.local` data. However, this is a **business logic issue**, not a security vulnerability affecting end users.

---

## Proxy Infrastructure Analysis

### Type: **Datacenter Proxies** (Not Residential Proxies)

**Provider:** Webshare.io
**Protocol:** HTTP proxy
**Authentication:** Username/password per proxy
**Proxy Mode:** `fixed_servers` (routes all traffic through selected proxy)

### Residential Proxy Assessment

**Is this a residential proxy vendor?** ❌ NO

**Rationale:**
1. Webshare.io provides **datacenter proxies**, not residential IPs
2. No evidence of user traffic being sold/shared
3. No P2P proxy network behavior
4. No traffic relay through user machines
5. Proxies are legitimate Webshare infrastructure

**Verdict:** This is a standard VPN/proxy extension using commercial datacenter proxies. NOT a residential proxy fraud scheme like Hola VPN.

---

## Dynamic Code Analysis

### No Dynamic Code Execution Detected

- ❌ No `eval()`
- ❌ No `Function()` constructor
- ❌ No `setTimeout()` / `setInterval()` with string arguments
- ❌ No `document.write()` with external content
- ❌ No WebAssembly modules
- ❌ No remote script loading

**Verdict:** Static codebase with no dynamic code execution risks.

---

## Comparison with Malicious VPN Extensions

| Behavior | QuickVPN Proxy | Typical Malicious VPN |
|----------|----------------|----------------------|
| Residential proxy resale | ❌ No | ✅ Yes (e.g., Hola VPN) |
| User traffic sold | ❌ No evidence | ✅ Yes |
| Ad injection | ❌ No | ✅ Common |
| Cookie harvesting | ❌ No | ✅ Common |
| Credential theft | ❌ No | ✅ Common |
| Tracker injection | ❌ No | ✅ Common |
| Obfuscated code | ❌ No | ✅ Common |
| Hidden C2 servers | ❌ No | ✅ Common |
| Extension enumeration | ❌ No | ✅ Common |
| Data exfiltration | ❌ No | ✅ Common |

**Verdict:** QuickVPN Proxy does **not** exhibit malicious VPN behaviors.

---

## Responsible Disclosure Items

### For Developer (hritikkumarkota):

1. **Exposed API Key Endpoint**: Secure your Cloudflare Workers endpoint with authentication
2. **Trial Bypass**: Implement server-side trial validation
3. **Credential Encryption**: Encrypt sensitive data in local storage
4. **Rate Limiting**: Add rate limiting to prevent quota abuse
5. **TLS Pinning**: Consider certificate pinning for API calls

### For Users:

- Extension functions as advertised
- No malicious behavior detected
- Be aware that datacenter proxies may not provide anonymity
- License verification sends license key to Gumroad (expected behavior)

---

## Overall Risk Assessment

### Risk Level: **LOW**

**Justification:**

1. **No malicious intent detected**: Extension provides legitimate VPN service
2. **No user data collection**: No browsing history, cookies, or credentials harvested
3. **Transparent monetization**: Clear trial and licensing model via Gumroad
4. **Datacenter proxies**: Not a residential proxy fraud scheme
5. **Appropriate permissions**: All permissions justified for VPN functionality
6. **No obfuscation**: Code is readable and analyzable

**Why not CLEAN?**

The extension exhibits architectural security flaws (exposed API key endpoint, insecure credential storage) that prevent a CLEAN rating. However, these issues primarily affect the **developer's infrastructure** and are not exploitable to harm end users directly.

**Recommendation:**

- ✅ Safe for personal use with awareness of datacenter proxy limitations
- ⚠️ Developer should address security architecture issues
- ✅ No evidence of malware, spyware, or data theft
- ⚠️ Trial enforcement is client-side and easily bypassed (business issue, not security issue)

---

## Verdict Summary

| Category | Rating | Details |
|----------|--------|---------|
| Malware | ✅ CLEAN | No malicious code detected |
| Data Privacy | ✅ GOOD | No user data collection or exfiltration |
| Permissions | ✅ APPROPRIATE | All permissions justified |
| Code Quality | ⚠️ FAIR | Architectural security flaws but not malicious |
| Monetization | ✅ TRANSPARENT | Clear licensing model |
| Overall Risk | ⚠️ LOW | Legitimate VPN with minor security concerns |

**Final Recommendation:** **LOW RISK** - Extension is functional and non-malicious but should improve API key security architecture.

---

## Technical Details

**Analysis Methodology:**
- Manual code review of all JavaScript files
- Manifest permission analysis
- Network endpoint documentation
- API call flow analysis
- Content script behavior assessment
- Comparison with known malicious VPN patterns

**Deobfuscation Notes:**
- Code appears to be minified/uglified by standard build tools (likely Webpack/Vite)
- Variable names are short but code logic is clear
- No intentional obfuscation beyond standard minification

**Extension Architecture:**
- Manifest V3 service worker model
- Modern Chrome extension APIs
- Freemium licensing via Gumroad
- Datacenter proxy infrastructure via Webshare.io

---

## References

- Webshare API Documentation: https://proxy.webshare.io/api/v2/docs/
- Gumroad License API: https://help.gumroad.com/article/76-license-keys
- Chrome Extension Manifest V3: https://developer.chrome.com/docs/extensions/mv3/intro/

---

**Report Generated:** 2026-02-08
**Analyst:** Claude Sonnet 4.5
**Analysis Duration:** Comprehensive review
**Confidence Level:** HIGH
