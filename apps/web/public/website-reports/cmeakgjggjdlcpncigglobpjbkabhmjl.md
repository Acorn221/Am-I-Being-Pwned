# Steam Inventory Helper (SIH) v2.9.10 -- Vulnerability & Security Report

**Extension ID:** `cmeakgjggjdlcpncigglobpjbkabhmjl`
**Manifest Version:** 3
**Analyzed Version:** 2.9.10
**Analysis Date:** 2026-02-06
**Analyst:** Automated static analysis pipeline + manual deep dive

---

## Executive Summary

Steam Inventory Helper (SIH) is a large, feature-rich extension (~113K lines in background.js alone) for managing Steam inventories, market listings, trade offers, and item pricing across ~20 third-party skin marketplaces. The triage flagged it as SUSPECT with 67 T1 flags across 21 categories including `residential_proxy_vendor`, `xhr_hook`, `fetch_hook`, `cookie_access`, `ext_enumeration`, `bulk_cookies`, `dynamic_eval`, `script_injection`, `management_permission`, and `externally_connectable_many`.

After thorough analysis, **the vast majority of flags are FALSE POSITIVES** arising from:
1. Sentry SDK error monitoring (XHR/fetch hooks in background.js)
2. Legitimate Steam session management (cookie access for authenticated API calls)
3. Feature-appropriate use of declarativeNetRequest for cookie-to-header injection
4. Third-party marketplace price overlay functionality (XHR hooks on external market sites)
5. Steam's own eval-based hover system (copied verbatim from Steam's market page JS)

However, several **genuine security and privacy concerns** exist, primarily around the wide externally_connectable surface, extension ID exposure to web pages, and the overly broad permissions model.

**Overall Risk Assessment: MEDIUM**

The extension is NOT malware. It does not contain residential proxy SDK code, does not exfiltrate cookies to unauthorized servers, does not disable competing extensions, and does not inject ads. The flagged patterns are functional requirements of a Steam trading tool. However, the broad attack surface created by `externally_connectable` and exposed extension ID creates meaningful risk.

---

## Vulnerability Analysis

### VULN-01: Extension ID Exposed to Web Pages via DOM Injection
**Severity:** Medium | **CVSS 3.1:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Files:**
- `/js/sih-rep-inject/sih-rep-inject.js:1-5`
- `/js/sih_global_header.js:165`
- `/js/market.js:113`

**Description:**
The extension injects its runtime ID (`chrome.runtime.id`) into every Steam page via DOM attribute manipulation:

```javascript
// sih-rep-inject.js
const actualCode = [`window.SIHID = '${chrome.runtime.id}'`].join('\r\n');
document.documentElement.setAttribute('onreset', actualCode);
document.documentElement.dispatchEvent(new CustomEvent('reset'));
document.documentElement.removeAttribute('onreset');
```

This also runs on `sih.app` and `sihrep.com` pages. Additionally, `sih_global_header.js` and `market.js` set `window.SIHID` on Steam pages.

**Impact:**
Any script running on Steam pages (including XSS payloads) can read `window.SIHID` and use it to send messages to the extension via `chrome.runtime.sendMessage(SIHID, ...)`. Combined with the `externally_connectable` configuration that allows `*.steampowered.com` and `steamcommunity.com`, this enables web-to-extension messaging from any script context on those domains.

**PoC Scenario:**
An XSS on steamcommunity.com could read `window.SIHID` and invoke background message handlers that return user data, trade information, or trigger extension actions.

---

### VULN-02: Wide externally_connectable Surface with Sensitive Message Handlers
**Severity:** Medium | **CVSS 3.1:** 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N)

**File:** `manifest.json:462-475`

**Description:**
The `externally_connectable` configuration allows messages from:
- `https://api.steaminventoryhelper.com/*`
- `https://stats.steaminventoryhelper.com/*`
- `https://wss-api.steaminventoryhelper.com/*`
- `*://*.steampowered.com/*`
- `*://steamcommunity.com/*`
- `*://store.epicgames.com/*`
- `*://sih.app/*`, `*://*.sih.app/*`
- `*://sihrep.com/*`, `*://*.sihrep.com/*`

Multiple `onMessageExternal` listeners are registered in the background:

1. **backgroundAngular.js:252** -- Handles `TS_GET_KEY_OFFERS`, `TS_GET_KEY_OFFERS_METADATA` (game key store queries)
2. **background.js:48609** -- Handles `BACKGROUND_EDIT_PROJECTS_PERMISSION`, `BACKGROUND_DELETE_PROJECTS_PERMISSION` (permission management)
3. **background.js:48993** -- Handles `BACKGROUND_GET_PROJECTS_PERMISSION`
4. **background.js (multiple locations)** -- Trade offer, inventory, market, and subscription handlers

**Impact:**
Any JavaScript executing on Steam domains can invoke these handlers. While the extension does validate `installType === "normal"` for some sensitive operations, the permission edit/delete handlers and key offer handlers do not perform origin validation beyond what Chrome's externally_connectable provides. A compromised or XSS'd Steam page could potentially manipulate extension permissions state.

**PoC Scenario:**
An XSS on `steamcommunity.com` sends `chrome.runtime.sendMessage(SIHID, {type: 'BACKGROUND_EDIT_PROJECTS_PERMISSION', data: {permission: 'trading', project: 'attacker', action: 'accept'}})` to modify the extension's internal permission grants.

---

### VULN-03: Cookie-to-Header Injection via declarativeNetRequest
**Severity:** Low-Medium | **CVSS 3.1:** 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)

**Files:**
- `/bundle/js/background.js:24869-24908` (function `um`)
- `/bundle/js/background.js:72145-72192` (Steam mobile auth simulation)

**Description:**
The extension reads Steam session cookies (`sessionid`, `steamLoginSecure`, `steamCountry`, `webTradeEligibility`, etc.) and injects them as request headers via `chrome.declarativeNetRequest.updateDynamicRules`. This is used for:

1. **Trade notification polling** (line 25057-25069): Reads cookies, constructs cookie string, sets DNR rules for Steam community URLs
2. **Mobile API simulation** (line 72145-72192): Constructs `steamLoginSecure` token and sets Cookie + User-Agent headers to mimic Android Steam client (`okhttp/3.12.12`, `mobileClient=android`)

```javascript
// Line 72157
value: "sessionid=".concat(SC.generateSessionID(),
  "; steamLoginSecure=").concat(SC.getSteamLoginSecure(e, r),
  "; mobileClient=android; mobileClientVersion=777777 3.6.1;")
```

**Impact:**
While this is used for legitimate functionality (confirming trade offers, checking market listings), it means the extension constructs authenticated requests that bypass CSRF protections and impersonate the Steam mobile app. The `steamLoginSecure` cookie value is the user's full session credential. If the extension's background script were compromised (e.g., via a supply chain attack on one of its API endpoints), these credentials could be exfiltrated.

The cookies are NOT sent to third-party servers -- they are injected into requests to Steam's own domains. However, the pattern of reading `steamLoginSecure` and constructing auth tokens programmatically is a high-value target.

---

### VULN-04: Russian Payment Gateway Integration (foreignpay.ru)
**Severity:** Low | **CVSS 3.1:** 3.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)

**Files:**
- `/bundle/js/background.js:37119` (serviceURL definition)
- `/bundle/js/background.js:37030-37054` (payment flow)

**Description:**
The extension integrates with `https://foreign.foreignpay.ru` as a payment service for Steam wallet refills. The `Qw` class (line 36855) connects to `https://core.steaminventoryhelper.com` and also references `foreignpay.ru`. The payment flow:

1. Gets SIH app user token
2. POSTs to `/sih/steam/pay` with `steamUsername`, `amount`, `currency` (default `RUB`), and `transactionId`
3. Checks Ukraine country code from Steam cookies and blocks the service for Ukrainian users

```javascript
// Line 37072
if ("ua" === r.toLowerCase()) { ... return { success: !0 }; }
```

**Impact:**
This is a legitimate monetization feature (Steam wallet top-up service), not a malicious pattern. However, the integration with a Russian payment processor (`foreignpay.ru`) and country-specific blocking may raise compliance concerns. The extension sends the user's Steam username to this endpoint.

---

### VULN-05: eval() of Steam API Response Data
**Severity:** Low | **CVSS 3.1:** 3.7 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N)

**File:** `/js/market.script.js:267,1058,1097,1132,1201,1216`

**Description:**
The market page script calls `eval(response.hovers)` on data returned from Steam's own AJAX endpoints:

```javascript
eval(res.hovers);   // Line 267
eval(response.hovers);  // Lines 1058, 1097, 1132, 1201, 1216
```

**Impact:**
This is a **verbatim copy of Steam's own market page JavaScript**. Steam's `CAjaxPagingControls` returns hover tooltip initialization code as a string in the `hovers` field, which is intended to be eval'd. The data comes from `steamcommunity.com` AJAX responses, not from any third-party server.

While eval of server responses is always a risk, this is Steam's own pattern and the data source is the same origin. If Steam's servers were compromised, this would be exploitable, but that is outside the extension's threat model.

---

## False Positive Analysis

| Triage Flag | Category | Verdict | Explanation |
|---|---|---|---|
| `residential_proxy_vendor` | T1 | **FALSE POSITIVE** | No Bright Data, Luminati, Hola SDK, or any proxy/bandwidth-sharing code found. The word "proxy" appears only in Angular framework code (`_createContextForwardProxy`) and JavaScript `Proxy` objects for Sentry instrumentation. |
| `xhr_hook` | T1 | **FALSE POSITIVE** | Three distinct sources: (1) **Sentry SDK** (background.js:17177-17229) hooks `XMLHttpRequest.prototype.open/send` for error telemetry -- this is the standard `@sentry/browser` instrumentation, identifiable by `__sentry_xhr_v3__` marker. (2) **Third-party market overlays** (skinport, shadowpay, haloskins, csfloat, waxpeer bundles) hook XHR to detect item page loads on those marketplaces and inject SIH price comparison buttons. (3) **Market listing page** (marketListing.bundle.js:45989) hooks XHR to detect Steam pagination responses for error display. All are benign. |
| `fetch_hook` | T1 | **FALSE POSITIVE** | Three sources: (1) **Sentry SDK** (background.js:19186) hooks `self.fetch` for error telemetry. (2) **CS.Money/DMarket overlays** (csmoney.bundle.js:23-24, dmarket.bundle.js:12-13) hook `window.fetch` to detect item detail API calls. (3) **Inventory page** (profilesInventory.bundle.js:53329-53330) hooks `window.fetch` to intercept `priceoverview` calls for cached price display. All serve legitimate feature purposes. |
| `cookie_access` | T1 | **TRUE POSITIVE (benign)** | The extension reads cookies from `steamcommunity.com`, `.steampowered.com`, and `store.steampowered.com` using `chrome.cookies.getAll()`. Cookies read: `sessionid`, `steamLoginSecure`, `steamCountry`, `timezoneOffset`, `Steam_Language`, `webTradeEligibility`, `browserid`. These are used exclusively for authenticated requests to Steam's own servers (trade notifications, market operations, game key store). No cookies are sent to third-party domains. See VULN-03 for security implications. |
| `bulk_cookies` | T1 | **TRUE POSITIVE (benign)** | Multiple `chrome.cookies.getAll({domain: "steamcommunity.com"})` calls (lines 25057, 25606, 33454, 37086, 63159, 73711, 87939, 91661, 91956). Each call retrieves all cookies for a domain, then filters to specific known cookie names. This is an over-broad pattern (should use `name` filter) but the data stays within the extension. |
| `ext_enumeration` | T1 | **TRUE POSITIVE (benign)** | One `chrome.management.getAll()` call at line 97595 checks for extension `pbeheebcldakpkohnellphloljkaanfa` (SIH's own companion "Market App" extension). When found and enabled, it sets a badge notification "!" to inform the user. It does NOT disable, uninstall, or interfere with any extensions. |
| `management_permission` | T1 | **TRUE POSITIVE (benign)** | Three uses: (1) `management.getAll` -- checks for companion extension (see above). (2) `management.getSelf` (lines 66058, 77074) -- checks `installType === "normal"` to verify the extension was installed from the Chrome Web Store (anti-sideloading check for premium features). This is a standard anti-piracy pattern. |
| `dynamic_eval` | T1 | **TRUE POSITIVE (benign)** | `eval(response.hovers)` in market.script.js is a copy of Steam's own market page JS pattern. See VULN-05. |
| `script_injection` | T1 | **TRUE POSITIVE (benign)** | Extensive use of `document.createElement('script')` + `appendChild` in content scripts (tradeofferrev.js, listing.js, profile.js, cart.js, gamePage.js, etc.). All inject the extension's own bundled scripts (from `chrome.runtime.getURL()`) into the page context to access Steam's JavaScript globals (`g_rgAssets`, `g_oMyHistory`, `g_strInventoryLoadURL`, etc.). This is the standard pattern for MV3 extensions that need world=MAIN access. No external scripts are injected. |
| `externally_connectable_many` | T1 | **TRUE POSITIVE** | 10 match patterns covering Steam, Epic Games, SIH's own domains, and sihrep.com. See VULN-02. This is overly broad but functionally motivated. |
| `webRequest` | V1 | **TRUE POSITIVE (benign)** | `webRequest.onCompleted` monitors Steam profile/market URLs and login flow. `webRequest.onBeforeSendHeaders` monitors market buy listings. Used for: detecting login completion, tracking page loads for UI updates, monitoring trade offer completions. No request blocking or modification via webRequest (modification is done via declarativeNetRequest). |
| `declarativeNetRequest` | V1 | **TRUE POSITIVE (notable)** | Dynamic rules inject Cookie headers into Steam requests (authenticated API calls). Also injects Referer headers for YouTube embeds. See VULN-03. |
| `<all_urls>` host permission | V2 | **TRUE POSITIVE (overly broad)** | Required because the extension operates on ~20 different third-party marketplace domains plus Steam and Epic Games. Could theoretically be narrowed to an explicit list. |
| `unlimitedStorage` | V2 | **TRUE POSITIVE (benign)** | Used for caching item prices, market data, inventory data. Standard for data-heavy extensions. |
| `WebSocket connection` | V2 | **TRUE POSITIVE (benign)** | Connects to `wss://wss.steaminventoryhelper.com` for real-time market agent features (live trading). Authenticated with SIH app tokens. |

---

## External Server Communication

| Domain | Purpose | Data Sent |
|---|---|---|
| `api.steaminventoryhelper.com` | Item pricing, free rewards, classId prices | SIH token, item IDs, market selections |
| `core.sih.app` | User authentication, token exchange | `sih.login` cookie, SIH token |
| `gamestats.steaminventoryhelper.com` | Game key offers, order management | Search/filter parameters, currency |
| `wss.steaminventoryhelper.com` | WebSocket for live market agent | SIH token, trade events, permission events |
| `foreign.foreignpay.ru` | Steam wallet refill (RUB payments) | Steam username, amount, currency, transaction ID |
| `sentry.io` (via SDK) | Error telemetry | Stack traces, XHR/fetch metadata, extension version |

**Critical finding: Steam session cookies (`steamLoginSecure`, `sessionid`) are NEVER sent to SIH's own servers.** They are only injected as headers on requests to Steam's own domains (`steamcommunity.com`, `steampowered.com`).

---

## Monetization Patterns

### Affiliate Links (Disclosed)
The extension generates affiliate/tracking links for third-party skin marketplaces using `subid1`/`subid2` parameters:

```javascript
// Pattern found across all siteExt bundles
a = "".concat(i, "?subid1=").concat(z, "&subid2=sih.app")
```

Markets with affiliate integration: Skinport, ShadowPay, BitSkins, SkinBaron, CS.Money, DMarket, Waxpeer, White Market, LisSkins, Mannco, IGXE, Gamerpay, Gameboost, Skinplace, Halo Skins, CSFloat, Avan Market, TradIt.

This is standard disclosed monetization for a free extension. No hidden ad injection or search result manipulation.

### Premium Subscription
The extension has a paid "ad-free" subscription verified via `management.getSelf` + SIH app user profile check. This is a legitimate freemium model.

---

## Architecture Summary

- **Background:** `service-worker.js` imports `bundle/js/common.js` (~23K lines), `bundle/js/background.js` (~113K lines), `bundleAngular/backgroundAngular.js` (~700 lines)
- **Content Scripts:** 40+ content script entries targeting Steam, Epic Games, and ~20 third-party skin marketplaces
- **Libraries:** Sentry SDK (error monitoring), Cheerio (HTML parsing server-side in SW), jQuery 1.10.2, Angular (for options page), Chart.js
- **API Backend:** `steaminventoryhelper.com` (pricing, auth), `sih.app` (core services), `foreignpay.ru` (payments)

---

## Overall Risk Assessment

**MEDIUM**

### Rationale

**Not malware.** The extension does not:
- Contain residential proxy/bandwidth-sharing code
- Exfiltrate session cookies to unauthorized servers
- Disable or interfere with other extensions
- Inject advertisements or modify search results
- Contain obfuscated command-and-control logic
- Dynamically load remote code

**Genuine concerns:**
1. The `externally_connectable` surface combined with extension ID exposure creates a meaningful attack vector if any Steam domain is XSS'd
2. The `steamLoginSecure` cookie is programmatically assembled into auth tokens and injected via DNR rules -- while this stays within Steam's domains, it represents a high-value target for supply chain attacks against SIH's API infrastructure
3. The `<all_urls>` host permission + `cookies` permission is overly broad for the actual functionality
4. The `eval()` of Steam response data, while mimicking Steam's own pattern, is unnecessary in an extension context
5. The `foreignpay.ru` integration sends Steam usernames to a Russian payment processor

**Mitigating factors:**
- The codebase is large but readable (standard webpack bundles, not obfuscated)
- Sentry integration provides legitimate error monitoring
- Cookie access is narrowly scoped to Steam domains only
- Extension enumeration is limited to checking for its own companion extension
- No dynamic code loading from remote servers
- `management.getSelf` is used for anti-piracy, not enumeration
