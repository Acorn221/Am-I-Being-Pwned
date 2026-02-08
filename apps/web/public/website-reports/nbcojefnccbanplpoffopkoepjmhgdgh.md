# Vulnerability Report: Hoxx VPN Proxy

## Extension Metadata
- **Extension ID**: nbcojefnccbanplpoffopkoepjmhgdgh
- **Extension Name**: Hoxx VPN Proxy
- **Version**: 3.50.6
- **Users**: ~700,000
- **Analysis Date**: 2026-02-08

## Executive Summary

Hoxx VPN Proxy is a VPN/proxy extension with ~700,000 users. The extension implements standard VPN functionality with proxy configuration, authentication, and remote configuration updates. Analysis reveals **MEDIUM** risk due to broad permissions, XOR-encrypted communications with remote servers, hardcoded remote configuration domains, and extensive use of `chrome.management.getAll()` API (which is standard for VPN extensions to detect conflicting extensions).

The extension uses legitimate VPN infrastructure patterns including proxy API usage, WASM for cryptographic operations, and remote configuration updates. While the extension has invasive permissions, the behavior aligns with expected VPN functionality.

## Vulnerability Details

### 1. Remote Configuration with Hardcoded Domains
**Severity**: MEDIUM
**Category**: Remote Configuration / Kill Switch
**Files**:
- `js/service-worker.js` (lines 2651, 11548-11553)

**Description**:
The extension fetches remote configuration from multiple hardcoded domains with fallback mirrors:

**Hardcoded Configuration Domains** (embedded JSON at line 2651):
```javascript
"mainbase": [
    "https://nvne.spoken.fun",
    "https://nytw.chester.run",
    "https://bwxm.chester.run",
    "https://eggx.sciences.run",
    "https://pkcw.chester.run",
    "https://vsxm.chester.run",
    "https://3rd2j.severity.uk",
    // ... more domains
],
"tierbase": [
    "https://okog.chester.run",
    "https://fhhb.spoken.fun",
    "https://api.doneverdrop.com",
    "https://solarsie.com",
    "https://scandiums.org",
    "https://vanadiums.org",
    // ... more domains
],
"mirrors": [
    "https://tierbase3.fra1.cdn.digitaloceanspaces.com/tiershx.json",
    "https://tierbase4.s3.amazonaws.com/tiershx.json",
    "https://pub-8029ed10cf4e4db0b3757e6b82ef7a40.r2.dev/tiershx.json",
    // ... CDN mirrors
]
```

**API Endpoints** (lines 9450-9650):
```javascript
CAPS: { endpoint: "/api3/caps" },
GUEST: { endpoint: "/api3/r/guest" },
REGISTER: { endpoint: "/api3/r/email" },
CONFIG: { endpoint: "/api3/c/4" },
LOGIN: { endpoint: "/api3/u/login" },
SESSION: { endpoint: "/api3/c/4/[params]" },
// ... 20+ API endpoints
```

**Verdict**: EXPECTED for VPN services. Configuration includes server lists, timeouts, and update intervals. The multi-tier fallback system (mainbase → tierbase → CDN mirrors) is a resilience pattern for VPN services to ensure availability.

---

### 2. XOR Encryption for Server Communications
**Severity**: MEDIUM
**Category**: Custom Encryption / Obfuscation
**Files**:
- `js/service-worker.js` (lines 4665-4693)

**Description**:
The extension uses XOR encryption to protect API communications:

```javascript
function So(t) {
  return {
    "Content-Type": "text/plain",
    Authorization: "Basic " + btoa(t + ":" + Oo(Math.round(3 + 5 * Math.random())))
  }
}

function Lo(t, e) {
  return btoa(To(function(t) {
    var e = [];
    for (var r in t)
      t.hasOwnProperty(r) && e.push(encodeURIComponent(r) + "=" + encodeURIComponent(t[r]));
    return e.join("&")
  }(t), e))
}

function To(t, e) {
  t = t.split(""), e = e.split("");
  for (var r = t.length, n = e.length, o = String.fromCharCode, i = 0; i < r; i++)
    t[i] = o(t[i].charCodeAt(0) ^ e[i % n].charCodeAt(0));
  return t.join("")
}

function _o(t, e) {
  return To(decodeURIComponent(escape(atob(t))), e)
}
```

**Analysis**:
- Request bodies are URL-encoded, XOR-encrypted with a key, then base64-encoded
- Authorization header uses Basic auth with username + random password
- Responses are decrypted using the same XOR key via `_o()`

**Verdict**: MEDIUM RISK. XOR encryption is weak cryptography, but appears to be an obfuscation layer on top of HTTPS (all domains use https://). This pattern is sometimes used to prevent trivial API reverse engineering.

---

### 3. WASM Binary for Cryptographic Operations
**Severity**: LOW
**Category**: WebAssembly Binary
**Files**:
- `js/service-worker.js` (line 9015)

**Description**:
The extension loads a WASM binary for cryptographic operations:

```javascript
const oa = (0, na.A)(fetch("/js/main.wasm").then((t => t.arrayBuffer())));
```

Later instantiated with:
```javascript
return i = r.sent, r.next = 6, WebAssembly.instantiate(i, n.importObject);
```

**Verdict**: EXPECTED for VPN extensions. WASM is commonly used for high-performance cryptographic operations (encryption, tunnel protocol implementation). Without decompiling the WASM binary, cannot determine if malicious, but usage pattern is legitimate.

---

### 4. Extension Enumeration via chrome.management.getAll()
**Severity**: LOW (False Positive)
**Category**: Extension Enumeration
**Files**:
- `js/service-worker.js` (line 3564)
- `js/popup.js` (line 12293)
- `js/mainlink.js` (line 11690)

**Description**:
The extension calls `chrome.management.getAll()` in multiple contexts:

```javascript
management: {
  getAll: async function() {
    return await chrome.management.getAll();
  }
}
```

**Verdict**: FALSE POSITIVE. VPN/proxy extensions MUST detect other proxy/VPN extensions to warn users about conflicts (only one proxy can be active at a time). This is standard behavior per the instructions: "VPN/proxy extensions disabling other VPN/proxy extensions is standard behavior."

---

### 5. Declarative Net Request - Origin Header Removal
**Severity**: LOW
**Category**: Header Manipulation
**Files**:
- `assets/rule.json`

**Description**:
The extension removes the Origin header from its own requests:

```json
[{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [{
      "header": "Origin",
      "operation": "remove"
    }]
  },
  "condition": {
    "initiatorDomains": ["nbcojefnccbanplpoffopkoepjmhgdgh"],
    "requestMethods": ["post"],
    "resourceTypes": ["xmlhttprequest"]
  }
}]
```

**Verdict**: LOW RISK. The extension only removes the Origin header from its own POST requests (initiated from extension ID). This is likely to bypass CORS restrictions when communicating with API servers, a common pattern for extensions that need to work with non-CORS-enabled backends.

---

### 6. Broad Permissions
**Severity**: MEDIUM
**Category**: Permission Scope
**Files**:
- `manifest.json`

**Description**:
The extension requests extensive permissions:

```json
"permissions": [
  "declarativeNetRequest",
  "alarms",
  "proxy",
  "storage",
  "webRequest",
  "webRequestAuthProvider",
  "notifications",
  "tabs",
  "management"
],
"host_permissions": ["<all_urls>"]
```

**Analysis**:
- `proxy` - Required for VPN functionality
- `webRequest` + `webRequestAuthProvider` - Used for proxy authentication
- `<all_urls>` - Needed to proxy all traffic
- `management` - Used to detect conflicting extensions
- `declarativeNetRequest` - Used for Origin header removal

**Verdict**: EXPECTED for VPN extensions. All permissions align with documented VPN functionality.

---

### 7. Dynamic Code Execution via eval/Function
**Severity**: LOW
**Category**: Dynamic Code
**Files**:
- Multiple JS files contain `Function()` constructor usage

**Description**:
Standard JavaScript bundling artifacts (regenerator-runtime, React) that use `new Function()` for polyfills and framework internals. No evidence of arbitrary remote code execution.

**Verdict**: FALSE POSITIVE. This is bundler-generated code, not malicious dynamic evaluation.

---

## False Positive Analysis

| Pattern | Files | Explanation |
|---------|-------|-------------|
| `chrome.management.getAll()` | service-worker.js, popup.js, mainlink.js | Standard for VPN extensions to detect conflicting proxy extensions |
| `charCodeAt`, `fromCharCode` | All JS files | Standard string manipulation, hashing (MurmurHash), and React framework code |
| `addEventListener('keydown')` | popup.js, mainlink.js | Standard React UI event handling, not keylogging |
| `eval`/`Function` constructor | All JS files | Bundler artifacts (regenerator-runtime), not malicious |
| WASM binary | service-worker.js | Legitimate cryptographic operations for VPN tunnel |

---

## API Endpoint Summary

| Endpoint | Purpose | Risk |
|----------|---------|------|
| `/api3/caps` | Capabilities check | Low |
| `/api3/r/guest` | Guest registration | Low |
| `/api3/r/email` | Email registration | Low |
| `/api3/u/login` | User login | Low |
| `/api3/c/4` | Configuration fetch | Medium |
| `/api3/c/4/[server]/[port]/[protocol]` | Session creation | Low |
| `/api3/u/ca` | Close account | Low |
| `/api3/captcha/solve` | CAPTCHA solving | Low |

All endpoints use HTTPS. Communications are XOR-encrypted (weak but supplementary to TLS).

---

## Data Flow Summary

1. **Extension Install**:
   - Fetches remote configuration from hardcoded domains
   - Updates server list, API endpoints, and timeouts

2. **User Authentication**:
   - User credentials sent via XOR-encrypted POST to `/api3/u/login`
   - Session tokens stored in `chrome.storage.local`

3. **VPN Connection**:
   - User selects server from fetched server list
   - Extension configures `chrome.proxy` API with server details
   - Proxy authentication via `chrome.webRequestAuthProvider`

4. **Ongoing Operation**:
   - Periodic configuration updates (every 6 hours per hardcoded config)
   - Proxy connection testing via random subdomain requests
   - Session validation

**Data Collected**:
- User credentials (email, password) - expected for VPN service
- Extension version, platform, OS - standard telemetry
- Proxy connection status - required for service operation

---

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

### Justification:
Hoxx VPN Proxy exhibits behavior consistent with a legitimate VPN service. The extension:
- ✅ Uses appropriate permissions for VPN functionality
- ✅ Implements standard proxy configuration via `chrome.proxy` API
- ✅ Detects conflicting extensions (standard VPN behavior)
- ✅ Uses HTTPS for all remote communications
- ⚠️ Uses weak XOR encryption (supplementary to TLS)
- ⚠️ Relies on hardcoded remote configuration domains
- ⚠️ Loads WASM binary (common for crypto, but opaque)
- ⚠️ Communicates with 15+ backend domains

### Medium Rating Rationale:
1. **Custom Encryption**: XOR encryption is weak cryptography, though all communications occur over HTTPS
2. **Remote Configuration Trust**: Extension behavior can be modified via remote config updates
3. **WASM Opacity**: Cannot analyze WASM binary contents without specialized tools
4. **Broad Access**: `<all_urls>` + `webRequest` provides full traffic visibility (expected for VPN but high risk if compromised)

### NOT Flagged:
- ❌ No evidence of ad injection
- ❌ No keylogging behavior (React event handlers are standard)
- ❌ No cookie theft
- ❌ No extension killing (only enumeration for conflict detection)
- ❌ No obvious malware patterns

### Recommendations:
1. **For Users**: Standard VPN privacy considerations apply - extension can see all traffic
2. **For Researchers**: Decompile WASM binary to verify cryptographic operations
3. **For Developers**: Replace XOR encryption with standard TLS client certificates
4. **For Store Review**: Acceptable risk level for a VPN extension with legitimate functionality

---

## Conclusion

Hoxx VPN Proxy is a **MEDIUM** risk extension that implements standard VPN functionality with some concerning but not inherently malicious patterns. The extension's behavior aligns with expectations for a commercial VPN service, including remote configuration, server selection, and proxy setup. The primary concerns are weak custom encryption and reliance on remote configuration, both of which are supplementary to the extension's core legitimate functionality.

**Triage Verdict**: MEDIUM - Legitimate VPN with typical privacy trade-offs and some weak security practices (XOR encryption), but no clear malicious intent detected.
