# Red Shield VPN -- Security Analysis

**Extension ID:** `fmhbdohlogekfmknbhfpbeiphcldcfji`
**Users:** ~20,000
**Manifest Version:** 3
**Framework:** Parcel bundler + Vue 3 (popup), vanilla JS (background service worker)
**Author:** Red Shield VPN

---

## Executive Summary

Red Shield VPN is a paid subscription VPN extension built with Vue 3 and Parcel. It uses a sophisticated **DNS-over-HTTPS (DoH) domain resolution system** to dynamically discover its API server, with the real API domain encrypted via AES-256 in a DNS TXT record (`pl.metgo4u5yhre.org`). The extension **actively disables competing proxy extensions** via `browser.management.setEnabled()`. It also uses `externally_connectable` with `<all_urls>` to receive subscription payment confirmations from external websites.

While the extension has an aggressive anti-competition mechanism and obscured infrastructure, it does **not** exhibit the hallmarks of spyware (no data harvesting, no cookie theft, no keylogging, no ad injection, no remote code execution). The code is a legitimate VPN client with questionable competitive practices and unnecessarily opaque infrastructure.

**Risk Level: MEDIUM**

---

## Flag Verdicts Table

| Flag | Verdict | Evidence |
|------|---------|----------|
| Extension Enumeration/Killing | **CONFIRMED** | `management.getAll()` filters for `proxy` permission, disables all enabled proxy extensions except itself (popup.588cc70c.js:13210-13226) |
| Credential Harvesting | **NOT FOUND** | No DOM scraping of login forms, no content scripts in manifest |
| Keylogging | **NOT FOUND** | `keydown`/`keypress` only in Vue framework code (Tab focus trapping) |
| DOM Scraping | **NOT FOUND** | No content scripts registered; `rsvcontent.js` is empty (comment only) |
| XHR/Fetch Monkey-Patching | **NOT FOUND** | Native `fetch()` used directly; no prototype overrides |
| eval / Dynamic Code | **NOT FOUND** | No `eval()`, no `new Function()`, no `importScripts` (matches are Vue/promise polyfill) |
| Encrypted Comms | **CONFIRMED** | AES-256 decryption of DNS TXT record to resolve API domain, hardcoded key in source (bg:12076-12078) |
| Cookie Theft | **NOT FOUND** | No cookie API usage anywhere |
| Ad Injection | **NOT FOUND** | No ad-related code, no script injection into pages |
| Fingerprinting | **NOT FOUND** | `navigator.userAgent` used only for browser name/version headers (`X-RSV-Browser-Name`, `X-RSV-Browser-Ver`) -- standard API client identification |
| Remote Code Loading | **NOT FOUND** | No `scripting.executeScript`, no dynamic script loading |
| C2 / Server-Controlled Behavior | **PARTIAL** | API domain is resolved dynamically via encrypted DNS; behavior itself is standard VPN config (endpoints, credentials, subscription status) |
| WebRTC Leak Prevention | **LEGITIMATE** | `privacy.network.webRTCIPHandlingPolicy` set to `disable_non_proxied_udp` when connected (bg:24798-24800) |

---

## Detailed Findings

### 1. Proxy Extension Killing (CONFIRMED -- Anti-Competitive)

**Location:** `popup.588cc70c.js` (beautified lines 13207-13228)

```javascript
async function l() {
    let e = await browser.management.getAll();
    e = e.filter(e => {
        let { permissions: t, enabled: r, id: o } = e;
        return t?.includes("proxy") && o !== browser.runtime.id && r
    });
    let t = e.map(async e => {
        try {
            await browser.management.setEnabled(e.id, !1)
        } catch (e) {
            console.log(e)
        }
    });
    await Promise.all(t)
}
```

**Behavior:** Enumerates all installed extensions, filters those with the `proxy` permission that are not itself and are enabled, then forcibly disables them. This is exposed as a UI button labeled "Disable" when the extension detects it does not have control over proxy settings (`error_control_other` error state).

**Trigger:** Called from popup when `isControl` is false (another extension controls proxy settings). The user sees: *"Other extensions have control over the required browser settings. You can disable them."* and clicks a "Disable" button.

**Assessment:** This is user-initiated (requires clicking the button), but it is an aggressive anti-competitive tactic that disables ALL proxy extensions, not just the one blocking control. The `management` permission enables this.

### 2. DNS-over-HTTPS Domain Resolution with AES Encryption (CONFIRMED -- Evasive Infrastructure)

**Location:** `static/background/index.js` (beautified lines 11936-12118)

The extension resolves its API domain by:

1. Querying `pl.metgo4u5yhre.org` TXT record via 10 different DNS-over-HTTPS resolvers in a race condition (first to respond wins)
2. The TXT record content is AES-256 encrypted
3. Decryption uses a **hardcoded key**: `eiS5iuFai1ahngeexeiWaew2Ophoh9ahz5ooph4zoong7baek5Eph5aiyai2Thai0Aep5Dujopi7phie3Nugie7ooqueexe5ahzo4rohyiesaceangai8Dopaagieyah`
4. The decrypted value is validated as a domain name, then used as the API base URL

**DNS Resolvers used (in parallel):**
- `8.8.8.8` (Google DNS JSON)
- `149.112.112.11` (Quad9 binary DoH)
- `9.9.9.11` (Quad9 binary DoH)
- `8.8.4.4` (Google DNS JSON)
- `doh.pub` (Tencent DNS JSON)
- `dns.google` (Google DNS JSON)
- `<random>.kmntc3ty8boq.online:8000` (custom resolver, binary DoH)
- `<random>.kmntc3ty8boq.online` (custom resolver, binary DoH)
- `<random>.kmntc3ty8boq.online:8443` (custom resolver, binary DoH)
- `dns11.quad9.net` (Quad9 binary DoH)

**Fallback domain:** `r872qg487g8.49032ur98u3892h84h8h243t.online`

**Random subdomain generation** for `kmntc3ty8boq.online`:
```javascript
function f() {
    let e = "0123456789abcdefghijklmnopqrstuvwxyz", t = "";
    for (let r = 0; r < 10; r++) {
        let r = Math.floor(Math.random() * e.length);
        t += e[r]
    }
    return t
}
```

**Assessment:** This is a domain fronting/resilience technique. The encrypted DNS TXT record means the actual API domain can be rotated without updating the extension. The random subdomains for `kmntc3ty8boq.online` suggest wildcard DNS. While this is not inherently malicious (VPN services operating in hostile jurisdictions use this to survive domain blocking), it does create an opaque infrastructure where the API domain is unknowable without performing the DNS resolution and decryption at runtime.

### 3. Externally Connectable with `<all_urls>` (ELEVATED RISK)

**Location:** `manifest.json`

```json
"externally_connectable": {
    "matches": ["<all_urls>"]
}
```

**Usage:** `browser.runtime.onMessageExternal` listener accepts `RSV_SUBSCRIPTION_PAID` messages from any website:

```javascript
browser.runtime.onMessageExternal.addListener((e, t, r) => {
    "RSV_SUBSCRIPTION_PAID" === e.type && (
        console.log("RSV_SUBSCRIPTION_PAID received", e.payload),
        f.dispatch("onRsvSubscriptionPaid"),
        r({ status: "Message received" })
    )
})
```

**Assessment:** The handler only responds to `RSV_SUBSCRIPTION_PAID` and triggers a reload of general info and endpoints. The `<all_urls>` scope is overly broad -- should be restricted to `redshieldvpn.com` -- but the actual handler is narrowly scoped and does not expose sensitive data.

### 4. Proxy Authentication via webRequest (LEGITIMATE)

**Location:** `static/background/index.js` (beautified lines 26884-26905)

```javascript
chrome.webRequest.onAuthRequired.addListener(
    this.boundCallbackAuth,
    { urls: ["<all_urls>"] },
    ["blocking"]
);
```

**Assessment:** Standard HTTPS proxy authentication. The `webRequestAuthProvider` permission is specifically for this. The callback provides `{ authCredentials: { username, password } }` from the stored proxy credentials. This is the correct way to implement proxy auth in Manifest V3.

### 5. PAC Script Generation (LEGITIMATE)

**Location:** `static/background/index.js` (beautified lines 26757-26822)

The extension generates PAC (Proxy Auto-Configuration) scripts with the marker comment `/* RedShieldVPN */` for three tunnel modes:
- **All traffic:** Route everything through proxy
- **Exclude domains:** Route everything except specified domains through proxy
- **Custom domains:** Route only specified domains through proxy

**Assessment:** Standard VPN split-tunneling implementation. The domain list handling includes proper parsing, subdomain matching with wildcards, and bogon IP filtering.

---

## Network Map

### Domains

| Domain | Purpose | Type |
|--------|---------|------|
| `pl.metgo4u5yhre.org` | DNS TXT record holding encrypted API domain | DoH lookup target |
| `r872qg487g8.49032ur98u3892h84h8h243t.online` | Fallback API domain | HTTPS API |
| `<random>.kmntc3ty8boq.online` (ports 443, 8000, 8443) | Custom DoH resolver | DNS resolution |
| `redshieldvpn.com` | Company website (ToS, Privacy Policy links) | Static |
| `<dynamic from DNS>` | Actual API server (resolved at runtime) | HTTPS API |
| Various VPN endpoint hosts (from `/api/v2/endpoints`) | Proxy servers | HTTPS proxy |

### API Endpoints (all relative to dynamic API domain)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/login` | POST | User authentication |
| `/api/v2/register-password` | POST | Account registration |
| `/api/v2/recover` | POST | Password recovery |
| `/api/v2/logout` | POST | Session termination |
| `/api/v2/general` | GET | Subscription info, payment domain, refcode |
| `/api/v2/endpoints` | GET | VPN server list, credentials, ports |
| `/api/v2/feedback` | POST | User rating/feedback |
| `/api/v2/captcha/altcha/challenge` | GET | CAPTCHA challenge (Altcha) |
| `check_url` (from endpoints response) | GET | Connection verification |

### Headers Sent with API Requests

| Header | Value |
|--------|-------|
| `X-RSV-Platform` | `plugin` |
| `X-RSV-Lang` | `ru` or `en` |
| `X-RSV-Build` | Extension build number |
| `X-RSV-Browser-Name` | Chrome/Firefox/Safari/etc. |
| `X-RSV-Browser-Ver` | Browser version number |
| `X-RSV-Token` | Auth token (when logged in) |

---

## What It Does NOT Do

- **No content scripts** -- manifest.json declares no `content_scripts`. `rsvcontent.js` is web-accessible but completely empty (just `//`).
- **No cookie access** -- No use of `chrome.cookies` or `document.cookie` anywhere.
- **No browsing history access** -- No `chrome.history`, `chrome.bookmarks`, or `chrome.topSites`.
- **No download interception** -- No `chrome.downloads` usage.
- **No tab content access** -- `tabs` permission used only for `tabs.query` (check active tab on startup), `tabs.create` (open payment page), and `tabs.reload` (reload active tab after reconnect).
- **No analytics/tracking** -- No Google Analytics, no Amplitude, no third-party tracking.
- **No ad injection** -- No DOM manipulation on web pages, no script injection.
- **No fingerprinting** -- UA string parsed only for browser identification headers.
- **No data exfiltration** -- API calls are strictly VPN operations (auth, endpoint list, connection check).
- **No remote code execution** -- No `eval()`, `new Function()`, `scripting.executeScript()`.

---

## Permissions vs. Usage Assessment

| Permission | Declared | Used | Justified |
|------------|----------|------|-----------|
| `storage` | Yes | Yes | State persistence (token, settings, connection state) |
| `unlimitedStorage` | Yes | Yes | Logs, tunnel domain lists |
| `proxy` | Yes | Yes | Core VPN functionality (PAC script / proxy.settings) |
| `management` | Yes | Yes | **Anti-competitive extension disabling** -- overprivileged |
| `tabs` | Yes | Yes | Active tab query, create, reload -- could use `activeTab` instead |
| `webRequest` | Yes | Yes | Proxy authentication (`onAuthRequired`) |
| `webRequestAuthProvider` | Yes | Yes | Required for `onAuthRequired` blocking in MV3 |
| `privacy` | Yes | Yes | WebRTC leak prevention |
| `<all_urls>` (host) | Yes | Yes | Proxy applies to all URLs |
| `externally_connectable: <all_urls>` | Yes | Partially | Subscription payment messages -- should be scoped to `redshieldvpn.com` |

---

## Final Verdict

**Risk Level: MEDIUM**

Red Shield VPN is a functional, subscription-based VPN extension with two notable security/ethical concerns:

1. **Anti-competitive extension killing (MEDIUM):** The extension will disable all other proxy extensions when a user clicks the "Disable" button. While user-initiated, it is aggressive and unnecessary -- the correct approach is to inform users which specific extension conflicts and how to resolve it manually.

2. **Evasive infrastructure (MEDIUM):** The API domain is hidden behind encrypted DNS TXT records resolved via 10 different DoH providers, with a custom DoH resolver on a suspicious domain (`kmntc3ty8boq.online`) using random subdomains. The AES decryption key is hardcoded. This makes the actual API infrastructure deliberately opaque to static analysis and network monitoring. While this could be a legitimate anti-censorship measure (the extension appears to target Russian-speaking users based on the default locale and i18n), it also means the extension operator could redirect all API traffic to a new domain without any extension update.

**What keeps this from HIGH risk:**
- No data harvesting, no content scripts, no DOM access
- No cookie/history/credential theft
- No ad injection or search manipulation
- No remote code execution
- The extension killing is user-triggered, not automatic
- The encrypted DNS is for infrastructure discovery, not for hiding malicious payloads
- Standard VPN operations (proxy settings, WebRTC protection, split tunneling)

**Recommendation:** Downgrade to REVIEW. The extension is aggressive but not malicious. The `management` permission abuse is the primary concern, but it is user-initiated. Monitor the encrypted API domain resolution for any changes in behavior.
