# Vulnerability Report: SetupVPN - Lifetime Free VPN

## Metadata

| Field | Value |
|-------|-------|
| Extension Name | SetupVPN - Lifetime Free VPN |
| Extension ID | oofgbpoabipfcfjapgnbbjjaenockbdp |
| Version | 4.0.9 |
| Manifest Version | 3 |
| User Count | ~9,000,000 |
| Analysis Date | 2026-02-08 |

## Executive Summary

SetupVPN is a free VPN browser extension with approximately 9 million users. The extension functions as a proxy-based VPN using Chrome's `chrome.proxy` API to route traffic through remote servers. The extension employs a **Go-compiled WebAssembly (WASM) binary** for critical operations including API request encryption/decryption, browser fingerprinting, anti-bot detection, and authentication challenge resolution. The WASM module is opaque and cannot be fully audited, representing a significant trust boundary.

Key concerns include:

1. **`externally_connectable` set to `<all_urls>`** -- any website can send messages to the extension's background service worker, though an origin validation guard limits accepted origins.
2. **Extensive browser fingerprinting in WASM** -- the WASM binary collects screen dimensions, mouse movements, timezone, incognito status, DevTools state, Selenium/webdriver detection, memory heap size, and storage quota.
3. **Opaque WASM binary with custom AES encryption** -- all API communications are encrypted/decrypted through the WASM module using a custom `vc/vwasm/aes` package with a hardcoded key, making traffic inspection impossible.
4. **Dynamic server infrastructure with remote config updates** -- the extension fetches server lists from 7+ mirror locations (DigitalOcean Spaces, AWS S3, Cloudflare R2, Vultr, Linode, GitHub, Bitbucket) and can dynamically update its API endpoints.
5. **Suspicious domain patterns** -- API servers use randomized-looking subdomain names on disposable TLDs (e.g., `lllm.scanners.fun`, `uabh.talked.run`, `xcxx.pointed.cc`, `1.6912044.cc`).
6. **XOR-based request body obfuscation** in addition to the WASM AES layer.

## Vulnerability Details

### 1. CRITICAL: Opaque WASM Binary with Fingerprinting and Custom Encryption

**Severity:** HIGH
**Files:** `deobfuscated/main.wasm` (534,666 bytes), `deobfuscated/background.bundle.js`
**Evidence (WASM strings):**
```
detectSelenium
webdriverObjectkeyscdc_toStringFirebugchromeisInitializeduserAgentDataarchitecture
widthheightwidthThresholdheightThresholdconfigdataconfigswitch5entropy
browserinfoisSeleniumtimezoneMismatchdevToolsOpenisIncognitomouseMovement
screenfpABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
queryUsageAndQuotawindowouterWidthinnerWidthouterHeightinnerHeight
navigatorwebkitTemporaryStorage
performancememoryjsHeapSizeLimitwindow
(*vc/vwasm/aes.AES).addRoundKey
(*vc/vwasm/aes.AES).shiftRow
(*vc/vwasm/aes.AES).subBytes
vc/vwasm/aes.Xor
JHn7tK7OjOWMHHPm2wEgeS3E8Gbq3PPgZx3dnj3Xx?q!!
```

**Analysis:** The WASM module (compiled from Go, package `vc/vwasm`) performs:
- **Browser fingerprinting**: Collects screen dimensions, window size thresholds, mouse movements, storage quota, JS heap size, timezone, and generates a `screenfp` (screen fingerprint).
- **Anti-bot/anti-analysis detection**: Detects Selenium WebDriver, ChromeDriver (`cdc_`), Firebug, DevTools, incognito mode.
- **Custom AES encryption**: Implements its own AES cipher (`vc/vwasm/aes`) for encrypting all API requests via `doRequest` (26 calls) and `challengeAnswer` (1 call).
- **Hardcoded encryption key**: Contains the string `JHn7tK7OjOWMHHPm2wEgeS3E8Gbq3PPgZx3dnj3Xx?q!!` which appears to be an encryption key or seed.
- **Remote kill switch capability**: The `configswitch5` string suggests a server-controlled feature toggle.

The fingerprint data is bundled into every API request via the WASM `doRequest` function, which handles all server communication. This data collection goes significantly beyond what is needed for VPN functionality.

**Verdict:** HIGH -- Extensive opaque fingerprinting sent to servers on every API call. The WASM binary cannot be fully audited and performs browser environment profiling (Selenium detection, incognito detection, DevTools detection, mouse tracking, screen fingerprinting) that is not necessary for VPN operation. The `configswitch` field suggests remote behavior modification capability.

---

### 2. HIGH: externally_connectable with `<all_urls>` and Message-Based Control

**Severity:** HIGH
**Files:** `deobfuscated/manifest.json`, `deobfuscated/background.bundle.js`
**Evidence (manifest.json):**
```json
"externally_connectable": {
    "matches": ["<all_urls>"]
}
```
**Evidence (background.bundle.js):**
```javascript
chrome.runtime.onMessageExternal.addListener(Bu.listener())

Bu.on("SET_PROXYSETTING", function(t) { ... })
Bu.on("GET_PROXYSETTING", function(t) { ... })
Bu.on("SYNC_DISPATCH", function(t) {
    var e = t.type, r = t.payload;
    return Pi.dispatch({type: e, payload: r}), true
})
Bu.on("IS_READY", function(t) { return true })
Bu.on("OPEN_URL", function(t) {
    var e = t.url;
    return chrome.tabs.create({url: e}), true
})
```

**Analysis:** The extension declares `externally_connectable` with `<all_urls>`, meaning any website can send messages to the extension via `chrome.runtime.sendMessage()`. The message router exposes handlers for:
- `SET_PROXYSETTING` -- Change proxy configuration
- `GET_PROXYSETTING` -- Read proxy settings
- `SYNC_DISPATCH` -- Dispatch arbitrary Redux actions to the extension's store
- `OPEN_URL` -- Open arbitrary URLs in new tabs
- `IS_READY` -- Check if extension is active

A guard function `qu()` validates that the sender's origin matches the extension's own origin or the current "baselink" server. However, the baselink servers are dynamically updated from remote mirrors and use suspicious domains. If an attacker controls or compromises any of these servers, they could send commands to modify proxy settings, dispatch state changes, or open arbitrary URLs for all 9 million users.

**Verdict:** HIGH -- The `externally_connectable: <all_urls>` combined with powerful message handlers (proxy control, arbitrary state dispatch, URL opening) creates a significant attack surface. While origin validation exists, it trusts dynamically-updated remote server domains.

---

### 3. MEDIUM: Dynamic Remote Configuration Infrastructure

**Severity:** MEDIUM
**Files:** `deobfuscated/servers.json`, `deobfuscated/background.bundle.js`
**Evidence:**
```json
"mainbase": [
    "https://lllm.scanners.fun",
    "https://uabh.talked.run",
    "https://mjgu.figure.run",
    "https://xcxx.pointed.cc",
    "https://uaia.scanners.fun",
    "https://icax.figure.run",
    "https://1.foreground.work",
    "https://1.awakened.work",
    "https://1.6912044.cc",
    "https://1.default2024.uk",
    "https://1.sahi.uk",
    "https://1.area9.uk"
],
"mirrors": [
    "https://tierbase3.fra1.cdn.digitaloceanspaces.com/tierssv.json",
    "https://tierbase4.s3.amazonaws.com/tierssv.json",
    "https://pub-8029ed10cf4e4db0b3757e6b82ef7a40.r2.dev/tierssv.json",
    "https://ams1.vultrobjects.com/tierupdate2/tierssv.json",
    "https://mirror4.es-mad-1.linodeobjects.com/tierssv.json",
    "https://raw.githubusercontent.com/the7c/update/master/master/ui/data.json",
    "https://bitbucket.org/the7c/update/raw/master/edge/pub/data.json"
]
```

**Analysis:** The extension maintains a multi-tier server infrastructure:
- **uibase**: 14 servers on `setupvpn.com` subdomains for the user-facing UI
- **mainbase**: 12 servers on randomized domains for API communication
- **tierbase**: 5 servers for fallback API endpoints
- **mirrors**: 7 locations across DigitalOcean, AWS, Cloudflare R2, Vultr, Linode, GitHub, and Bitbucket for configuration updates

The extension fetches updated server lists from these mirrors every 6 hours. New server endpoints received from mirrors are validated (must have `retcode: 200`, arrays with >2 entries for mainbase and tierbase) and then dispatched to the Redux store via `UPDATE_SERVERSJSON`. This means the extension's entire API infrastructure can be silently rotated to new domains.

The domain naming pattern is characteristic of domain generation algorithms (DGA) or disposable infrastructure designed to evade blocking.

**Verdict:** MEDIUM -- While infrastructure redundancy is common for VPN services, the use of suspicious disposable domains combined with the ability to remotely rotate the entire server infrastructure creates potential for abuse.

---

### 4. MEDIUM: XOR Obfuscation of API Communications

**Severity:** MEDIUM
**Files:** `deobfuscated/background.bundle.js`
**Evidence:**
```javascript
// bo - encode request body
function bo(t, e) {
    return btoa(Eo(url_encode(params), random_key))
}

// wo - decode response
function wo(t, e) {
    return Eo(decodeURIComponent(escape(atob(t))), e)
}

// Eo - XOR cipher
function Eo(t, e) {
    t = t.split(""), e = e.split("");
    for (var r = t.length, n = e.length, o = String.fromCharCode, i = 0; i < r; i++)
        t[i] = o(t[i].charCodeAt(0) ^ e[i % n].charCodeAt(0));
    return t.join("")
}

// mo - Authorization header with random key
function mo(t) {
    return {
        "Content-Type": "text/plain",
        "Authorization": "Basic " + btoa(t + ":" + go(Math.round(3 + 5 * Math.random())))
    }
}
```

**Analysis:** All API requests use a dual-layer obfuscation:
1. **JavaScript layer**: Request parameters are URL-encoded, XOR'd with a random key, and base64-encoded. The random key is sent in the Authorization header as Basic auth (base64). Responses are decoded via the reverse process.
2. **WASM layer**: The WASM `doRequest` function wraps the JavaScript fetch with additional AES encryption from the `vc/vwasm/aes` package.

This makes it extremely difficult for researchers, network monitoring tools, or enterprise security solutions to inspect what data is being sent to the extension's servers.

**Verdict:** MEDIUM -- While some obfuscation is expected for VPN authentication, the dual-layer approach (XOR + AES in WASM) combined with opaque WASM code suggests an intent to prevent traffic analysis beyond normal security requirements.

---

### 5. MEDIUM: Extension Enumeration via management.getAll

**Severity:** LOW
**Files:** `deobfuscated/background.bundle.js`
**Evidence:**
```javascript
io.management.getAll()
// Filters for extensions with proxy permission
r.filter(function(t) {
    return e.hasExtensionProxyPermission(t) &&
        chrome.runtime.id !== t.id &&
        true === t.enabled
})

hasExtensionProxyPermission: function(t) {
    return (t.permissions?.includes("proxy")) || false
}
```

**Analysis:** The extension calls `chrome.management.getAll()` to enumerate all installed extensions, specifically filtering for those with the "proxy" permission. This list is stored in the Redux state under `UPDATE_PROXYEXTENSIONS`. This is used to detect competing proxy/VPN extensions. There is no evidence of disabling or uninstalling competing extensions -- the data appears to be used for displaying a warning to the user about proxy conflicts.

**Verdict:** LOW -- Extension enumeration is used for a legitimate purpose (proxy conflict detection). No evidence of disabling or reporting competing extensions to the server.

---

### 6. LOW: Origin Header Removal via Declarative Net Request

**Severity:** LOW
**Files:** `deobfuscated/rules.json`
**Evidence:**
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
        "initiatorDomains": ["oofgbpoabipfcfjapgnbbjjaenockbdp"],
        "requestMethods": ["post"],
        "resourceTypes": ["xmlhttprequest"]
    }
}]
```

**Analysis:** The extension strips the `Origin` header from POST XHR requests initiated by the extension itself. This is used to prevent CORS issues when communicating with its rotating API servers. The rule is scoped only to the extension's own domain.

**Verdict:** LOW -- Limited to the extension's own requests; standard practice for extensions communicating with multiple backend servers.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")` | background.bundle.js | Standard regenerator-runtime globalThis polyfill |
| Multiple `Function()` calls | background.bundle.js (17 occurrences) | All are regenerator-runtime async/generator polyfills |
| `redux-saga` action types | background.bundle.js | Standard Redux state management library |
| `react-redux`, `react-router-dom` | vendors-manifest.json | Standard React UI framework |
| `antd` | vendors-manifest.json | Ant Design UI component library |
| `redux-persist` | vendors-manifest.json | Standard Redux persistence library |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/api3/caps` | POST | Server capabilities check | `{}` + platform defaults (os, cv, platform, brand) |
| `/api3/r/guest` | POST | Guest registration | `{}` + platform defaults |
| `/api3/r/email` | POST | Email registration | `{email, hpassword}` (SHA-512 hashed) |
| `/api3/r/email2` | POST | Email registration v2 | `{email, hpassword}` |
| `/api3/u/login` | POST | User login | `{login, hpassword}` |
| `/api3/c/4` | POST | Config fetch | `{login, hpassword}` |
| `/api3/c/4/{country}/{server}/{protocol}` | POST | VPN session request | `{login, hpassword}` |
| `/api3/c/4/2/{country}/{server}/{protocol}` | POST | VPN session v2 | `{login, hpassword}` |
| `/api3/c/4/refresh/{token}` | POST | Token refresh | `{login, hpassword}` |
| `/api3/u/ca` | POST | Close account/session | `{login, hpassword}` |
| `/api3/apps` | POST | App listing | Auth required |
| `/api3/captcha/solve` | POST | CAPTCHA solving | Captcha data |
| `/api2/i/p` | POST | Products listing | `{}` |
| `/api2` | POST | Payment link | Unknown |
| `/api2/support/ticket/new` | POST | Support ticket | Unknown |
| `/api2/t/u` | POST | Tier info | `{}` |
| `/api2/cu` | POST | Version status | `{}` |
| `/api2/user/forgotpassword` | POST | Password reset | Unknown |
| `/api2/p` | POST | Generic proxy endpoint | Various (via WASM doRequest) |
| Mirror URLs (7 locations) | GET | Config update (tierssv.json) | None |

All POST requests are encrypted via XOR + WASM AES. Authorization uses Basic auth with random per-request keys for the XOR cipher exchange.

## Data Flow Summary

```
User Action (Connect to VPN)
    |
    v
Popup UI (React/Ant Design) --> chrome.runtime.sendMessage
    |
    v
Background Service Worker (Redux + Redux-Saga)
    |
    v
WASM Module (Go-compiled)
    |-- Browser Fingerprinting (screen, mouse, timezone, incognito, Selenium, DevTools)
    |-- AES Encryption of API payload
    |-- challengeAnswer() for proxy auth
    |
    v
JavaScript XOR Encoding Layer (bo/wo/Eo functions)
    |
    v
fetch() POST to dynamically-selected server
    |-- mainbase servers (12 domains, DGA-like naming)
    |-- tierbase fallback (5 domains)
    |-- Mirror config updates (7 CDN locations)
    |
    v
Server Response (XOR + AES encrypted)
    |
    v
chrome.proxy.settings.set() with proxy config
    |
    v
All user traffic routed through SetupVPN proxy
```

**Data collected and sent to servers on every API call:**
- OS type (via `chrome.runtime.getPlatformInfo`)
- Extension version (`cv: "4.0.9"`)
- Platform (`chrome`)
- Brand (`sv`)
- Browser fingerprint data (via WASM): screen dimensions, mouse movements, timezone mismatch, incognito status, DevTools state, Selenium/WebDriver detection, JS heap size, storage quota

## Overall Risk Assessment

**Risk Level: HIGH**

**Justification:**

While SetupVPN does function as a VPN extension and its core proxy functionality is legitimate, the extension exhibits several high-risk behaviors that go beyond what is necessary for VPN operation:

1. **Opaque WASM binary with extensive fingerprinting**: The Go-compiled WASM module collects detailed browser environment data (screen fingerprint, mouse movements, incognito detection, Selenium/WebDriver detection, DevTools detection, timezone analysis, memory/storage analysis) and sends it to the server on every API call. This fingerprinting is disproportionate for VPN functionality and could be used for user tracking or fraud detection beyond the VPN service.

2. **Dual-layer encryption preventing inspection**: The combination of XOR encoding in JavaScript and AES encryption in WASM makes it impossible to determine exactly what data is being sent to servers without full WASM reverse engineering.

3. **externally_connectable with `<all_urls>`**: Any website can attempt to communicate with the extension. While origin validation exists, it trusts dynamically-updated remote servers, creating a potential for abuse if any server in the chain is compromised.

4. **Suspicious infrastructure pattern**: The use of randomized/DGA-like domain names across disposable TLDs, combined with 7 mirror locations for configuration updates, suggests infrastructure designed for rapid rotation to evade detection or blocking. The `configswitch5` capability in WASM suggests remote behavior modification.

5. **9 million users at risk**: The scale of the user base amplifies the impact of any potential abuse.

The extension is **not classified as malware** -- it does provide functional VPN service and there is no evidence of direct data theft, keylogging, ad injection, or residential proxy abuse. However, the opaque WASM fingerprinting, dual-layer encryption preventing traffic analysis, and the remote configuration update infrastructure with suspicious domains represent a level of opacity and control that is concerning for an extension with 9 million users.
