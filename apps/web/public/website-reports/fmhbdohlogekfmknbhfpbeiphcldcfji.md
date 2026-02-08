# Red Shield VPN - Security Vulnerability Report

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension Name** | Red Shield VPN |
| **Extension ID** | `fmhbdohlogekfmknbhfpbeiphcldcfji` |
| **Version** | 1.0.315 |
| **User Count** | ~20,000 |
| **Manifest Version** | 3 |
| **Author** | Red Shield VPN |
| **Framework** | Parcel bundler + Vue 3 (popup), vanilla JS (background) |

---

## Executive Summary

Red Shield VPN is a subscription-based VPN extension that employs sophisticated infrastructure obfuscation techniques. The extension uses DNS-over-HTTPS (DoH) with AES-256 encryption to dynamically discover its API server domain, making the actual backend infrastructure opaque to static analysis. It also implements user-initiated anti-competitive functionality by disabling all other proxy extensions when activated.

**Key Concerns:**
1. **Anti-competitive extension killing** via `chrome.management` API (user-initiated)
2. **Encrypted DNS infrastructure** with hardcoded AES key for API domain resolution
3. **Overly broad `externally_connectable` scope** (`<all_urls>` instead of specific domains)

**Positive Security Indicators:**
- No data harvesting, credential theft, or cookie access
- No content scripts or DOM manipulation
- No keylogging, ad injection, or remote code execution
- Standard VPN functionality with proper proxy authentication
- No third-party analytics or tracking SDKs

**Overall Risk Level: MEDIUM**

---

## Vulnerability Details

### VULN-001: Anti-Competitive Extension Disabling

**Severity:** MEDIUM
**Category:** Anti-competitive behavior
**Status:** CONFIRMED

**Description:**
The extension enumerates all installed browser extensions and disables any that have the `proxy` permission (excluding itself). This behavior is triggered when a user clicks a "Disable" button in the popup UI when the extension detects it doesn't have control over proxy settings.

**Location:**
- File: `popup.588cc70c.js` (minified line 13207-13228)

**Code Evidence:**
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

**Impact:**
- Disables ALL proxy extensions, not just the conflicting one
- Creates poor user experience for users with multiple proxy tools
- Anti-competitive behavior that may violate Chrome Web Store policies

**Mitigation:**
User-initiated (requires clicking button), not automatic. However, the broad scope of disabling ALL proxy extensions rather than identifying the specific conflicting extension is problematic.

**Verdict:** MEDIUM risk - Anti-competitive but user-initiated and transparent to the user.

---

### VULN-002: Encrypted DNS Infrastructure with Hardcoded Key

**Severity:** MEDIUM
**Category:** Infrastructure obfuscation
**Status:** CONFIRMED

**Description:**
The extension uses an encrypted DNS TXT record to resolve its API domain. The TXT record at `pl.metgo4u5yhre.org` contains AES-256 encrypted data, decrypted using a hardcoded 128-character key embedded in the source code. This allows the backend operator to change the API domain without updating the extension.

**Location:**
- File: `static/background/index.js` (minified, ~lines 11936-12118)

**Technical Details:**

1. **DNS Resolution Strategy:**
   Queries 10 different DoH providers in parallel (race condition - first response wins):
   - Google DNS: `8.8.8.8`, `8.8.4.4`, `dns.google`
   - Quad9: `149.112.112.11`, `9.9.9.11`, `dns11.quad9.net`
   - Tencent: `doh.pub`
   - Custom: `<random>.kmntc3ty8boq.online` (ports 443, 8000, 8443)

2. **Random Subdomain Generation:**
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

3. **Hardcoded AES Key:**
   ```
   eiS5iuFai1ahngeexeiWaew2Ophoh9ahz5ooph4zoong7baek5Eph5aiyai2Thai0Aep5Dujopi7phie3Nugie7ooqueexe5ahzo4rohyiesaceangai8Dopaagieyah
   ```

4. **Fallback Domain:**
   `r872qg487g8.49032ur98u3892h84h8h243t.online`

**Impact:**
- API domain can be changed without extension update
- Makes infrastructure tracking and analysis difficult
- Potential for redirection to malicious infrastructure (though no current evidence)
- Hardcoded key is visible in source code (AES provides no real protection)

**Verdict:** MEDIUM risk - While this technique is used by legitimate VPN services in hostile jurisdictions for censorship resistance, it creates an opaque infrastructure that could be abused for malicious purposes. No current evidence of abuse.

---

### VULN-003: Overly Broad External Messaging Scope

**Severity:** LOW
**Category:** Permission scope
**Status:** CONFIRMED

**Description:**
The extension uses `externally_connectable` with `<all_urls>`, allowing any website to send messages to the extension. While the message handler only responds to `RSV_SUBSCRIPTION_PAID` messages (for payment confirmation), the scope is unnecessarily broad.

**Location:**
- File: `manifest.json`

**Code Evidence:**
```json
"externally_connectable": {
    "matches": ["<all_urls>"]
}
```

Message handler:
```javascript
browser.runtime.onMessageExternal.addListener((e, t, r) => {
    "RSV_SUBSCRIPTION_PAID" === e.type && (
        console.log("RSV_SUBSCRIPTION_PAID received", e.payload),
        f.dispatch("onRsvSubscriptionPaid"),
        r({ status: "Message received" })
    )
})
```

**Impact:**
- Any website can attempt to communicate with the extension
- Handler is narrowly scoped to one message type (good)
- No sensitive data exposed through handler (good)
- Best practice would be to scope to `redshieldvpn.com` only

**Verdict:** LOW risk - Handler is safely implemented, but scope should be restricted.

---

## False Positive Analysis

| Pattern | Source | Verdict | Reason |
|---------|--------|---------|--------|
| `setTimeout`, `setInterval` | Vue 3 framework, Parcel runtime | **FALSE POSITIVE** | Standard framework timers, not dynamic code execution |
| `navigator.userAgent` | API request headers | **FALSE POSITIVE** | Used only for browser identification headers (`X-RSV-Browser-Name`, `X-RSV-Browser-Ver`) |
| `chrome.tabs.query` | Background script | **FALSE POSITIVE** | Used only to check active tab on startup, standard VPN behavior |
| `chrome.webRequest.onAuthRequired` | Background script | **FALSE POSITIVE** | Standard proxy authentication implementation |
| `privacy.network.webRTCIPHandlingPolicy` | Background script | **FALSE POSITIVE** | Legitimate WebRTC leak prevention (`disable_non_proxied_udp`) |
| `localStorage` | Background script | **FALSE POSITIVE** | Standard state persistence for extension settings |

---

## API Endpoints and Data Flow

### Domains

| Domain | Purpose | Protocol |
|--------|---------|----------|
| `pl.metgo4u5yhre.org` | DNS TXT record (encrypted API domain) | DoH (DNS-over-HTTPS) |
| `<random>.kmntc3ty8boq.online` | Custom DoH resolver | HTTPS (ports 443, 8000, 8443) |
| `r872qg487g8.49032ur98u3892h84h8h243t.online` | Fallback API domain | HTTPS |
| `redshieldvpn.com` | Company website (ToS, Privacy Policy) | HTTPS |
| `<dynamic_from_dns>` | Actual API server (resolved at runtime) | HTTPS |

### API Endpoints

All endpoints relative to dynamically resolved API domain:

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `/api/v2/login` | POST | User authentication | Username, password |
| `/api/v2/register-password` | POST | Account registration | Email, password |
| `/api/v2/recover` | POST | Password recovery | Email |
| `/api/v2/logout` | POST | Session termination | Token |
| `/api/v2/general` | GET | Subscription info | Token |
| `/api/v2/endpoints` | GET | VPN server list | Token |
| `/api/v2/feedback` | POST | User rating/feedback | Token, rating, comment |
| `/api/v2/captcha/altcha/challenge` | GET | CAPTCHA challenge (Altcha) | None |

### Request Headers

| Header | Value | Purpose |
|--------|-------|---------|
| `X-RSV-Platform` | `plugin` | Platform identification |
| `X-RSV-Lang` | `ru` or `en` | User language preference |
| `X-RSV-Build` | Extension build number | Version tracking |
| `X-RSV-Browser-Name` | Chrome/Firefox/Safari/etc. | Browser identification |
| `X-RSV-Browser-Ver` | Browser version | Compatibility tracking |
| `X-RSV-Token` | Auth token | User authentication |

### Data Flow Summary

1. **Extension Installation:** Resolves API domain via encrypted DNS
2. **User Registration/Login:** Sends credentials to `/api/v2/login`, receives token
3. **VPN Connection:** Fetches server list from `/api/v2/endpoints`, configures proxy with PAC script
4. **Proxy Authentication:** Uses `chrome.webRequest.onAuthRequired` to inject credentials
5. **WebRTC Protection:** Sets `privacy.network.webRTCIPHandlingPolicy` to prevent IP leaks
6. **Payment Confirmation:** Receives `RSV_SUBSCRIPTION_PAID` message from `redshieldvpn.com` payment page

**No data exfiltration detected:**
- No cookie access
- No browsing history access
- No download monitoring
- No tab content scraping
- No keylogging
- No analytics/tracking SDKs

---

## Permissions Analysis

| Permission | Declared | Used | Justified | Risk |
|------------|----------|------|-----------|------|
| `storage` | ✓ | ✓ | Token, settings, connection state | LOW |
| `unlimitedStorage` | ✓ | ✓ | Logs, tunnel domain lists | LOW |
| `proxy` | ✓ | ✓ | Core VPN functionality | LOW |
| `management` | ✓ | ✓ | **Extension disabling (anti-competitive)** | MEDIUM |
| `tabs` | ✓ | ✓ | Active tab query, create, reload | LOW |
| `webRequest` | ✓ | ✓ | Proxy authentication | LOW |
| `webRequestAuthProvider` | ✓ | ✓ | Required for `onAuthRequired` in MV3 | LOW |
| `privacy` | ✓ | ✓ | WebRTC leak prevention | LOW |
| `<all_urls>` (host) | ✓ | ✓ | Proxy applies to all traffic | LOW |

---

## What the Extension Does NOT Do

✓ **No content scripts** - `rsvcontent.js` is empty (only contains `//`)
✓ **No cookie harvesting** - No use of `chrome.cookies` or `document.cookie`
✓ **No credential theft** - No form scraping, no login interception
✓ **No keylogging** - No `keydown`/`keypress` listeners on web pages
✓ **No browsing history access** - No `chrome.history` API usage
✓ **No download monitoring** - No `chrome.downloads` API usage
✓ **No DOM manipulation** - No script injection into web pages
✓ **No ad injection** - No advertising code or ad network connections
✓ **No XHR/fetch hooking** - No prototype patching or monkey-patching
✓ **No eval or dynamic code** - No `eval()`, `new Function()`, or dynamic imports
✓ **No remote code loading** - No `scripting.executeScript()` or external script fetching
✓ **No fingerprinting** - UA string used only for API headers
✓ **No analytics/tracking** - No Google Analytics, Amplitude, Sentry, or other tracking SDKs
✓ **No market intelligence SDKs** - No Sensor Tower, Pathmatics, or similar

---

## Overall Risk Assessment

### Risk Level: MEDIUM

**Rationale:**

**Concerning Behaviors:**
1. **Anti-competitive extension disabling** - Disables all proxy extensions, not just conflicting ones
2. **Encrypted infrastructure** - API domain hidden behind AES-encrypted DNS with hardcoded key
3. **Custom DoH resolver** - Uses suspicious domain (`kmntc3ty8boq.online`) with random subdomains
4. **Overly broad external messaging** - `<all_urls>` scope when specific domain would suffice

**Mitigating Factors:**
1. **Extension disabling is user-initiated** - Not automatic, requires user action
2. **No data harvesting** - No access to cookies, history, credentials, or page content
3. **No malicious functionality** - Standard VPN operations, no hidden payload
4. **No remote code execution** - No dynamic code loading or eval
5. **Encrypted DNS is single-purpose** - Only for API domain resolution, not for C2
6. **Message handler is safe** - Only responds to subscription payment confirmation

**Comparison to Malicious Extensions:**
- Unlike malicious VPN extensions, Red Shield VPN does NOT:
  - Harvest browsing data or cookies
  - Inject ads or scripts into web pages
  - Function as a residential proxy network
  - Use the device for market intelligence or web scraping
  - Contain hidden cryptocurrency miners or clickbots

**Verdict:**
Red Shield VPN is a **functional VPN extension with questionable infrastructure practices and anti-competitive behavior**. The encrypted DNS system and extension disabling functionality are concerning from a policy perspective but do not represent active malware or data theft. The extension serves its stated purpose (VPN service) without additional hidden functionality.

**Recommended Action:**
- Monitor for changes in behavior or backend infrastructure
- Consider warning users about anti-competitive extension disabling
- Request scoping of `externally_connectable` to specific domain
- Flag for potential Chrome Web Store policy review regarding `management` permission abuse

---

## Revision History

| Date | Version | Changes |
|------|---------|---------|
| 2026-02-08 | 1.0 | Initial security analysis |
