# Vulnerability Report: Avast SafePrice

## Metadata
| Field | Value |
|-------|-------|
| Extension Name | Avast SafePrice |
| Extension ID | eofcbnmajmjmplflapaojjnihcjkigck |
| Version | 24.18.2.825 |
| Manifest Version | 3 |
| Users | ~5,000,000 |
| Analyzed Files | manifest.json, background.js, contentScript.js, siteScript.js |

## Executive Summary

Avast SafePrice is a coupon finder and price comparison extension built on the **CouponFollow/Cently CATC SDK** (version 1.340.0-453). The extension auto-applies coupon codes on e-commerce checkout pages, provides cashback offers, and includes a "SafeSite" phishing/malware URL checker. It uses Snowplow analytics for telemetry and Optimizely for A/B testing.

The extension requires broad permissions (`<all_urls>` host permissions, `webRequest`, content scripts on all pages) which is invasive but consistent with its stated purpose of finding coupons across all shopping sites. The code is minified but not obfuscated -- it deobfuscates cleanly with standard beautification. No evidence of malicious behavior, data harvesting beyond functional requirements, residential proxy infrastructure, market intelligence SDK injection, or extension-killing was found.

## Vulnerability Details

### 1. Broad Data Collection via Snowplow Analytics (MEDIUM)
- **Severity:** MEDIUM
- **Files:** `background.js` (lines 31624-31693, 32060-32122)
- **Description:** The extension sends telemetry to Snowplow analytics (via `com.snowplowanalytics.snowplow/tp2` POST endpoint) including: current page URL, domain, color depth, viewport size, screen resolution, language, document charset, cookie status, user ID, and member ID. Data is sent with `iglu:com.couponfollow/` schemas.
- **Code:**
  ```js
  // Snowplow collector POST endpoint
  i = t + "://" + e + ":443" + (r === ac.GET ? "/i" : "/com.snowplowanalytics.snowplow/tp2");
  // Attached properties
  e && this.tracker.setColorDepth(e), t && this.tracker.addPayloadPair("cookie", t),
  i && this.tracker.setLang(i), l && u && this.tracker.setViewport(l, u),
  a && this.tracker.addPayloadPair("url", a)
  ```
- **Verdict:** Expected for a coupon/shopping extension. Snowplow collector URL is fetched from remote SDK config. The extension has throttling, sampling, and analytics-blocking mechanisms. Data collected is standard for product analytics -- no passwords, form data, or browsing history exfiltration. **Not malicious, but privacy-invasive.**

### 2. Affiliate Monetization via Redirect (LOW)
- **Severity:** LOW
- **Files:** `background.js` (lines 33080-33096)
- **Description:** The extension monetizes via affiliate redirects when users visit supported e-commerce sites. It constructs a redirect URL with partner website key (PWK), domain, hostname, member ID, device ID, and cashback eligibility.
- **Code:**
  ```js
  u.searchParams.append("pwk", s), u.searchParams.append("dn", e),
  u.searchParams.append("hn", t), u.searchParams.append("r", n),
  u.searchParams.append("mid", n), u.searchParams.append("did", r),
  u.searchParams.append("c", l)
  ```
- **Verdict:** Standard affiliate monetization for a coupon extension. Configuration-driven (can be disabled), with clear logging. **Expected behavior.**

### 3. Extension Handshake / Discovery (LOW)
- **Severity:** LOW
- **Files:** `background.js` (lines 36734-36778, 35403-35412)
- **Description:** The extension uses `chrome.runtime.sendMessage()` with other extension IDs and `chrome.runtime.onMessageExternal` to perform "handshake" communication with other Avast/Avira extensions. This is used for onboarding coordination (e.g., detecting if Avast browser extension is already installed) via `extensionOnboarding: "discover"` checks.
- **Code:**
  ```js
  handle() { return { installed: !0 } }
  shouldHandle(e) { ... return "discover" === e.extensionOnboarding && !!n; }
  ```
- **Verdict:** Limited to responding `{installed: true}` to specific handshake messages from known Avast/Avira extension IDs. Feature-flag gated. **Not extension enumeration/killing.**

### 4. Native Dialog Override in siteScript.js (LOW)
- **Severity:** LOW
- **Files:** `siteScript.js` (lines 8706-8713)
- **Description:** The site script can temporarily override browser `alert()`, `prompt()`, and `confirm()` dialogs to prevent them from interfering with the auto-apply coupon flow, then restores them afterward.
- **Code:**
  ```js
  overrideNativeDialogsOnce() {
    return 0 === this.nativeDialogsOverrides.length && (
      this.nativeDialogsOverrides = this.nativeDialogsToOverrideNames.map(e => {
        const t = new I(window).create(e);
        return t.override(), t
      }), !0)
  }
  restoreNativeDialogs() {
    this.nativeDialogsOverrides.forEach(e => e.restore()), this.nativeDialogsOverrides = []
  }
  ```
- **Verdict:** Functional requirement for coupon auto-apply (sites may show alerts during code testing). Dialogs are restored after use. **Expected behavior.**

### 5. Remote SDK Configuration (LOW)
- **Severity:** LOW
- **Files:** `background.js` (line 58657)
- **Description:** The extension fetches its SDK configuration from Azure Blob Storage at `https://stwleprodwus.blob.core.windows.net/web/configuration/gen_dig/ava/{browser}/sdkConfig-prod.json`. This includes feature flags, Snowplow collector URL, monetization settings, and various toggle switches.
- **Code:**
  ```js
  return "https://stwleprodwus.blob.core.windows.net/web/configuration/gen_dig/ava/{browser}/sdkConfig-prod.json"
    .replace("{browser}", e)
  ```
- **Verdict:** Standard remote configuration pattern. Config is fetched from Avast's Azure infrastructure and validated against Zod schemas. Feature flags control analytics, monetization, safe site checks, etc. **No remote code execution capability observed.**

### 6. Keyboard Event Simulation for Coupon Entry (LOW)
- **Severity:** LOW
- **Files:** `contentScript.js` (lines 44550-44610), `siteScript.js` (lines 8695-8704)
- **Description:** The extension simulates keyboard events (keydown, keypress, keyup) and mouse clicks to enter coupon codes into form fields during the auto-apply process.
- **Verdict:** Required for programmatic coupon code entry on e-commerce sites. Only triggered during user-initiated coupon application flows. **Standard coupon extension behavior.**

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | background.js:8722, contentScript.js:59946, siteScript.js:8318 | Standard Webpack/bundler global scope detection |
| `innerHTML` | contentScript.js (multiple) | React/jQuery DOM rendering for popup UI |
| `credentials: "include"` | background.js:63,233 | Ky HTTP library default configuration |
| `password: !0` | contentScript.js:5319, siteScript.js:3917 | jQuery input type detection (form field type identification for selectors) |
| `Proxy` references | Multiple files | JavaScript `Proxy` built-in object usage (MobX, lodash type checking) |
| `eval`-like patterns | None found | No eval() usage detected |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `stwleprodwus.blob.core.windows.net/web/configuration/gen_dig/ava/{browser}/sdkConfig-prod.json` | SDK configuration fetch | GET |
| Snowplow collector (URL from config) `/com.snowplowanalytics.snowplow/tp2` | Analytics telemetry | POST |
| Feature flags URL (from sdkConfig) | Feature flag fetching | GET |
| InitData endpoint (from sdkConfig) | Init data / domain mappings | GET |
| Monetization redirector URL (from config) | Affiliate redirect | GET |
| SafeSite remote API (from config) | URL safety check | GET |
| Experiment tracking URLs (from config) | A/B test evaluation tracking | POST |

## Data Flow Summary

1. **Startup:** Background service worker loads, fetches SDK config from Azure Blob Storage, initializes feature flags, Snowplow tracker, and Safe Site module.
2. **Page Visit:** Content script injects on all pages at `document_start`. It communicates with background via `chrome.runtime.sendMessage`. The background script checks domain mappings to determine if the site is a supported shopping site.
3. **Shopping Site Detection:** When a supported e-commerce cart/checkout page is detected (via URL keyword matching for "cart", "checkout", "basket", etc.), the extension activates coupon features.
4. **Coupon Auto-Apply:** The content script fetches coupon codes from the backend (CATC DAPI), injects them into form fields via simulated keyboard events, clicks apply buttons, and monitors order totals to determine savings.
5. **Monetization:** If the domain is monetizable, the extension may redirect through an affiliate URL (PWK-based) before landing on the merchant site.
6. **Telemetry:** User interactions (impressions, clicks, auto-apply results, page views on supported sites) are tracked via Snowplow analytics with anonymization options and throttling.
7. **SafeSite:** URLs are checked against whitelists/blacklists and a remote API for phishing/malware detection.
8. **Extension Handshake:** The extension responds to handshake messages from other Avast/Avira extensions to coordinate onboarding.

## Overall Risk: **CLEAN**

Avast SafePrice is a legitimate coupon-finding and price comparison extension built on the well-known CouponFollow/Cently SDK. While it requires broad permissions (`<all_urls>`, `webRequest`, content scripts on all pages) and collects telemetry data (page URLs, viewport info, user IDs) via Snowplow analytics, all observed behavior is consistent with its stated purpose. The extension does not:

- Exfiltrate browsing history, passwords, or form data
- Hook XHR/fetch for surveillance purposes
- Inject market intelligence SDKs
- Operate residential proxy infrastructure
- Execute remote code
- Enumerate or kill other extensions

The monetization model (affiliate redirects) and analytics collection (Snowplow) are standard practices for coupon browser extensions. Feature flags and remote configuration are fetched from Avast's Azure infrastructure and validated with Zod schemas, with no evidence of dynamic code execution capabilities. The extension is privacy-invasive by nature (it needs to know what site you're on to offer coupons), but serves its intended purpose without malicious behavior.
