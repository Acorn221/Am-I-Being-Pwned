# Analysis: Free VPN for Chrome: Secure VPN Proxy in One Click

**Extension ID:** `hklhhkchffegjfojbofhfkckjidfbjhe`
**Version:** 1.0.1
**Manifest Version:** 3
**Users:** ~6,000
**Locale:** Spanish-origin developer (console logs, variable names, file naming all in Spanish)

---

## Executive Summary

This extension is a rudimentary HTTPS proxy that routes **all user traffic** through 9 hardcoded domains on suspicious TLDs (`.space`, `.club`, `.site`, `.website`). It uses a PAC script to redirect traffic to `HTTPS <domain>:443` endpoints. While it lacks the sophisticated malicious payloads seen in Urban VPN or VeePN (no credential harvesting, no extension enumeration, no keylogging), it presents **significant privacy and security risks**:

1. **Unencrypted proxy architecture** -- Traffic is sent to unknown HTTPS proxy servers with no authentication, no VPN tunnel (WireGuard/OpenVPN/IPsec), and no verifiable encryption. The "AES-256" claim in the UI is false.
2. **Analytics/telemetry blocking via declarativeNetRequest** -- Blocks Google Analytics, Amplitude, PostHog, Mixpanel, and `clients*.google.com` (Chrome update/SafeBrowsing infrastructure), which could prevent security warnings from reaching the user.
3. **Suspicious proxy domains** -- All 9 proxy domains use cheap/disposable TLDs and have names unrelated to VPN services, suggesting either fly-by-night infrastructure or potential residential proxy relay nodes.
4. **Content script injection on all URLs** -- Injects SweetAlert2 library on every page with no apparent usage, which is unnecessary resource waste and could be a placeholder for future injection payloads.

**Risk Level: MEDIUM-HIGH** -- Not actively malicious in terms of data harvesting, but the proxy architecture allows the operator to perform full MITM on user traffic, and the blocking of Chrome's update/safety infrastructure is a red flag.

---

## Flag Verdicts Table

| Flag | Verdict | Evidence |
|------|---------|----------|
| Extension Enumeration/Killing | CLEAN | No `chrome.management` usage |
| Credential Harvesting | CLEAN | No password/login/form monitoring |
| Keylogging | FALSE POSITIVE | keydown/keyup in popup.js = React event system; sweetalert2 keyboard handling |
| DOM Scraping | CLEAN | No content script DOM reading (sweetalert2 only injects its own UI elements) |
| XHR/Fetch Monkey-Patching | CLEAN | No prototype tampering of XMLHttpRequest or fetch |
| eval / Dynamic Code Execution | FALSE POSITIVE | `new Function("return this")()` in webpack runtime (global `this` fallback); `Function("return " + n)()` in SweetAlert2 v11.14.5 `<swal-function-param>` parser |
| Encrypted/Obfuscated Comms | CLEAN | No encrypted payloads; proxy config is plaintext PAC script |
| Cookie Theft | CLEAN | No `chrome.cookies` or `document.cookie` access |
| Ad Injection | CLEAN | No ad-related code, affiliate links, or DOM manipulation on user pages |
| Browser Fingerprinting | FALSE POSITIVE | `navigator.userAgent` in popup.js = React Adobe Spectrum UI toolkit platform detection; framer-motion browser sniffing |
| Remote Code Loading | CLEAN | No dynamic script loading from remote URLs |
| C2 / Command and Control | SUSPECT | Hardcoded proxy server list; no dynamic config fetching, but operator controls the proxy servers |
| Analytics Blocking | CONFIRMED | `rules.json` blocks GA, Amplitude, PostHog, Mixpanel, crash.google.com, clients*.google.com |
| Unverified Proxy Infrastructure | CONFIRMED | 9 hardcoded domains on disposable TLDs; PAC script routes ALL traffic through them |
| Unnecessary Content Script Injection | CONFIRMED | SweetAlert2 + CSS injected on `<all_urls>` at `document_start` with no code that uses it |
| Misleading Security Claims | CONFIRMED | UI claims "Encrypted AES-256", "Hidden IP", "Kill Switch Active" -- none are implemented |

---

## Detailed Findings

### 1. Proxy Infrastructure (CRITICAL)

**File:** `/deobfuscated/js/background.js`, lines 176-227

The extension hardcodes 9 proxy server domains:

```javascript
["goldenearsvccc.space", "pagecloud.space", "projectorpoint.website",
 "precisiontruck.space", "maureenesther.website", "marjifx.club",
 "jjs-bbq.space", "haringinsuranc.website", "bst2200.site"]
```

When connecting, it randomly selects up to 10 (all 9) hosts and generates a PAC script:

```javascript
function FindProxyForURL(url, host) {
  if (host === 'localhost' || shExpMatch(host, '127.0.0.1')) {
    return 'DIRECT';
  }
  return 'HTTPS goldenearsvccc.space:443; HTTPS pagecloud.space:443; ...';
}
```

**Impact:** ALL browser traffic (except localhost) is routed through these servers. The operator can:
- Log all visited URLs
- Perform MITM on non-HSTS sites
- Inject content into HTTP responses
- Correlate browsing activity with user identity
- Sell bandwidth as residential proxy (similar to Troywell pattern)

The domains are all on cheap/disposable TLDs with names that bear no relation to VPN services (`jjs-bbq.space`, `precisiontruck.space`, `haringinsuranc.website`), suggesting throwaway infrastructure.

### 2. Analytics & Safety Infrastructure Blocking (HIGH)

**File:** `/deobfuscated/rules.json`

Two declarativeNetRequest rules block:

**Rule 1:** All requests matching `^https?://clients[0-9]+\.google\.com/.*` -- This blocks Chrome's:
- Extension update checks (`clients2.google.com/service/update2/crx`)
- Safe Browsing API lookups
- Chrome component updates
- CRLSet (certificate revocation) updates

**Rule 2:** Blocks domains: `analytics.google.com`, `google-analytics.com`, `api.amplitude.com`, `api.posthog.com`, `api.mixpanel.com`, `googleapis.com`, `crash.google.com`

Blocking `googleapis.com` is extremely aggressive -- it affects Google Sign-In, Fonts, Maps, YouTube APIs, and many other legitimate services.

**Impact:** Users cannot receive Chrome safety updates, Safe Browsing protections are degraded, and Google services may break. This appears designed to prevent detection/telemetry that could flag the extension as malicious.

### 3. Unnecessary Content Script Injection (MODERATE)

**File:** `/deobfuscated/manifest.json`, lines 36-48

SweetAlert2 v11.14.5 (library + CSS) is injected as a content script on `<all_urls>` at `document_start`. However, no code in the extension actually invokes SweetAlert2 on user pages. The worker.js uses `chrome.scripting.executeScript` for simple notification divs, not SweetAlert2.

**Possible explanations:**
- Leftover from development
- Placeholder for future popup/modal injection on user pages
- Preparing infrastructure for social engineering prompts (e.g., fake login dialogs)

### 4. Misleading Security Claims (MODERATE)

**File:** `/deobfuscated/popup.js`, lines 16996-17029

The popup UI claims:
- "Encrypted AES-256" -- **False.** The extension uses a PAC script that routes traffic to HTTPS proxy servers. There is no AES-256 encryption layer; the only encryption is the standard TLS from the browser-to-proxy HTTPS connection.
- "Hidden IP" -- **Partially true** for the destination server, but the proxy operator sees the real IP.
- "Kill Switch Active" -- **False.** There is no kill switch implementation. If the proxy goes down, traffic flows directly (DIRECT).

### 5. Worker.js Tab Tracking (LOW)

**File:** `/deobfuscated/worker.js`, lines 91-101

The worker tracks tabs through storage keys `abouts`, `tab`, and `visited_load`:

```javascript
chrome.tabs.onRemoved.addListener(function(e, t) {
  chrome.storage.local.get(["tab"]).then(t => {
    t.tab == e && chrome.storage.local.set({ abouts: "visited_close" })
  })
})
```

```javascript
chrome.tabs.onUpdated.addListener((e, t, o) => {
  "complete" === t.status && /^http/.test(o.url) && chrome.storage.local.get(["abouts"]).then(e => {
    "visited_close" == e.abouts && Local.setItem("visited_load", !0)
  })
})
```

This appears to track whether a user visited a specific tab (likely opened on install) and closed it, then later loaded another page. This is a minor tracking mechanism, likely for onboarding flow state management, but uses the vague variable name `abouts`.

---

## Network Map

### Proxy Endpoints (All traffic routed here when "connected")
| Domain | Port | TLD |
|--------|------|-----|
| goldenearsvccc.space | 443 | .space |
| pagecloud.space | 443 | .space |
| projectorpoint.website | 443 | .website |
| precisiontruck.space | 443 | .space |
| maureenesther.website | 443 | .website |
| marjifx.club | 443 | .club |
| jjs-bbq.space | 443 | .space |
| haringinsuranc.website | 443 | .website |
| bst2200.site | 443 | .site |

### Blocked Endpoints (via declarativeNetRequest)
| Domain/Pattern | Impact |
|----------------|--------|
| `clients[0-9]+.google.com` | Chrome updates, Safe Browsing, CRLSets |
| `analytics.google.com` | Google Analytics |
| `google-analytics.com` | Google Analytics |
| `api.amplitude.com` | Amplitude analytics |
| `api.posthog.com` | PostHog analytics |
| `api.mixpanel.com` | Mixpanel analytics |
| `googleapis.com` | Google APIs (Sign-In, Fonts, Maps, YouTube, etc.) |
| `crash.google.com` | Chrome crash reporting |

### Outbound from extension code
None. The extension makes zero outbound HTTP/fetch requests itself. All network activity occurs through the browser's proxy subsystem.

---

## What It Does NOT Do

- **No extension enumeration or killing** -- Does not use `chrome.management` API
- **No credential harvesting** -- Does not monitor form inputs, passwords, or login pages
- **No keylogging** -- All keyboard event handling is from React and SweetAlert2 libraries
- **No DOM scraping** -- Does not read page content, URLs, or user data from visited pages
- **No XHR/fetch hooking** -- Does not monkey-patch network APIs
- **No cookie theft** -- Does not access `chrome.cookies` or `document.cookie`
- **No ad injection** -- Does not modify page content or inject advertisements
- **No remote code loading** -- Does not fetch and execute remote JavaScript
- **No data exfiltration** -- Does not POST/send user data to any server
- **No browser fingerprinting** -- navigator/UA access is from standard library platform detection

---

## Permissions vs. Usage Assessment

| Permission | Used? | Justified? |
|-----------|-------|------------|
| `tabs` | Yes | For notification display on active tab |
| `activeTab` | Yes | For `chrome.scripting.executeScript` notifications |
| `background` | N/A | MV3 service worker (deprecated permission, ignored) |
| `scripting` | Yes | For injecting notification divs |
| `webRequest` | Yes | For HTTP/2 error detection |
| `declarativeNetRequest` | Yes | **ABUSE** -- Blocks Chrome safety infrastructure |
| `storage` | Yes | Connection state persistence |
| `proxy` | Yes | Core functionality -- PAC script proxy |
| `<all_urls>` (host) | Yes | Required for proxy to work on all sites |
| `web_accessible_resources` | Marginal | Exposes CSS/PNG to all pages -- low risk |

**Over-permissioned:** The `tabs`, `activeTab`, and `scripting` permissions are used only for showing simple toast notifications, which could be done via the `notifications` API instead. The `webRequest` permission is used only for error detection.

---

## Final Verdict

**Risk Level: MEDIUM-HIGH**

This extension is not actively malicious in the traditional sense (no data harvesting, no keylogging, no ad injection). However, it is **dangerous** for the following reasons:

1. **Full traffic interception capability** -- The operator of the 9 proxy servers has full visibility into users' browsing activity and can MITM non-HSTS traffic. This is the same architecture used by residential proxy services that sell user bandwidth.

2. **Active sabotage of Chrome safety features** -- Blocking `clients*.google.com` prevents Safe Browsing updates, extension update checks, and CRLSet updates. Blocking `googleapis.com` breaks legitimate Google services. This pattern is consistent with extensions trying to avoid detection or removal.

3. **Deceptive security claims** -- The UI falsely claims AES-256 encryption and kill switch functionality that do not exist. This misleads users into a false sense of security.

4. **Suspicious infrastructure** -- The proxy domains are on cheap/disposable TLDs with names completely unrelated to VPN services, suggesting temporary or fraudulent infrastructure.

5. **Unused content script injection** -- SweetAlert2 injected on all pages with no current use suggests potential for future payload delivery.

**Classification: SUSPECT -- Likely residential proxy / traffic monetization scheme with deceptive VPN facade. Not a traditional VPN. Users' traffic is routed through unverified third-party proxy servers with no real encryption beyond standard TLS.**
