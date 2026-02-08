# Vulnerability Report: Avira Safe Shopping

## Metadata
- **Extension Name:** Avira Safe Shopping
- **Extension ID:** ccbpbkebodcjkknkfkpmfeciinhidaeh
- **Version:** 7.34.2.825
- **Manifest Version:** 3
- **Users:** ~7,000,000
- **SDK Version:** Cently SDK 1.340.0-453, CATC 7.5.2.0

## Executive Summary

Avira Safe Shopping is a coupon/deal-finding and website safety-checking extension published by Gen Digital (parent company of Avira, Norton, Avast). It uses the CouponFollow/Cently SDK to provide automated coupon application at checkout, deal comparisons, and cashback offers. The extension also integrates Avira's URL safety checking (threat detection API) to warn users about malicious sites.

The extension requests broad permissions (`<all_urls>`, `webRequest`, `scripting`, `storage`, `alarms`) and runs a content script on all pages. While these permissions are invasive, they are justified by its core functionality: detecting supported shopping sites, injecting coupon UI, monitoring cart/checkout flows, and checking URL safety.

The extension embeds Snowplow analytics (via CouponFollow's SDK) for tracking user engagement with coupons. It accesses cookies only for site-specific coupon/cart detection (reading e-commerce session data). It has affiliate link detection logic to "stand down" when existing affiliate cookies are present, indicating a commission-based revenue model. No evidence of malicious data exfiltration, keylogging, credential harvesting, residential proxy infrastructure, or market intelligence SDKs was found.

## Vulnerability Details

### 1. Broad Content Script Injection
- **Severity:** LOW (Informational)
- **Files:** `manifest.json`, `contentScript.js`
- **Details:** Content script runs on `<all_urls>` at `document_start`. The script injects UI overlays for coupon/deal notifications on shopping sites. It communicates with the background via `chrome.runtime.sendMessage`.
- **Code:** `"matches": ["<all_urls>"], "run_at": "document_start"`
- **Verdict:** Expected for a shopping assistant extension that needs to detect any supported e-commerce site.

### 2. Snowplow Analytics Tracking
- **Severity:** LOW
- **Files:** `background.js`, `contentScript.js`
- **Details:** Integrates CouponFollow's Snowplow analytics (18 references in background, 9 in content script). Tracks coupon-related events (coupon list loads, auto-apply results, popup interactions). Snowplow collector URL is configured remotely via feature flags. Tracking can be toggled off via `SnowplowToggle` flag.
- **Code:** `"Won't create a tracker because snowplow is disabled"` / `collectorUrl, namespace` from config
- **Verdict:** Standard analytics for a coupon SDK. Tracks extension UI interactions, not general browsing activity.

### 3. Remote Configuration System
- **Severity:** LOW
- **Files:** `background.js`
- **Details:** Fetches SDK configuration from Azure blob storage: `https://stwleprodwus.blob.core.windows.net/web/configuration/gen_dig/avi/{browser}/sdkConfig-prod.json`. Feature flags control many behaviors (coupon list, auto-apply, snowplow, affiliate configs, supported sites, recommended offers, etc.).
- **Verdict:** Standard remote configuration pattern. Config endpoint is first-party Gen Digital infrastructure. No evidence of remote code execution or dynamic script loading from config.

### 4. Cookie Access for Cart/Coupon Detection
- **Severity:** LOW
- **Files:** `contentScript.js`
- **Details:** `getCookieValue()` reads `document.cookie` to extract site-specific cart/session data used by the coupon application engine (DAPI - Data API). Reads cookies defined in per-site configurations to detect cart values, login state, etc.
- **Code:** `getCookieValue(e){const t=\`${e}=\`,n=decodeURIComponent(document.cookie).split(";")`
- **Verdict:** Scoped to specific cookie names defined in site configs. Used for coupon/cart functionality, not general cookie harvesting.

### 5. Simulated Text Input for Coupon Application
- **Severity:** LOW
- **Files:** `contentScript.js`
- **Details:** `simulateTextInput()` and `simulateReturnKeyPress()` dispatch keyboard and input events to programmatically enter coupon codes into form fields. This is the core auto-apply functionality.
- **Code:** `simulateTextInput(e,t){e.focus(),e.setValue(t),this.dispatchKeyboardEvent(e,"keydown"...`
- **Verdict:** Expected behavior for an auto-apply coupon extension. Events are dispatched to specific form elements, not used for general input monitoring.

### 6. Affiliate Link Detection & Revenue Model
- **Severity:** LOW (Informational)
- **Files:** `background.js`
- **Details:** Comprehensive affiliate detection system with "stand down" logic. Detects existing affiliate cookies/redirects from networks (commission-junction, apmebf.com, anrdoezrs.net, etc.) and defers to them. Extension earns commission via affiliate links when applying coupons. Disclosed in UI: "When you use our coupons, we may earn a commission."
- **Verdict:** Transparent affiliate revenue model with stand-down logic for existing affiliates. Standard for coupon extensions.

### 7. Log Posting to Remote Server
- **Severity:** LOW
- **Files:** `background.js`
- **Details:** Sends logs to a remote endpoint when enabled via config: `fetch(i.logPosting.url, {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify([{type, hostname, timestamp, args, method}])})`. Controlled by feature flag (`logPosting.enabled`).
- **Verdict:** Debug/telemetry logging. Sends extension operation logs, not user data. Gated behind feature flag.

### 8. WebRequest Monitoring (Main Frame Only)
- **Severity:** LOW
- **Files:** `background.js`
- **Details:** Listens to `webRequest.onBeforeRequest`, `onBeforeRedirect`, `onCompleted` for `main_frame` requests on `<all_urls>`. Used to track redirect chains for affiliate detection and URL safety checking.
- **Code:** `const e={urls:["<all_urls>"],types:["main_frame"]}`
- **Verdict:** Scoped to main frame only (not subresources). Used for legitimate redirect tracking and safety features.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")()` | background.js (x3) | Webpack globalThis polyfill |
| `innerHTML` (x23) | contentScript.js | React DOM rendering for coupon UI overlays |
| `keydown/keyup/keypress` (x55) | contentScript.js | jQuery event binding + coupon input simulation + React synthetic events |
| `password` (x9) | contentScript.js | HTML input type detection (jQuery/React form handling) |
| `creditcard` (x3) | contentScript.js | TLD/public suffix list entries |
| `.cookie` (x7) | contentScript.js | Site-specific cart/coupon cookie reading |
| `Proxy.revocable` | background.js | Immer.js immutable state library |
| `XMLHttpRequest` (x2) | siteScript.js | jQuery AJAX implementation |
| `onMessageExternal` | background.js | Safari onboarding ping/keepalive |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `stwleprodwus.blob.core.windows.net/web/configuration/gen_dig/avi/{browser}/sdkConfig-prod.json` | SDK configuration | GET |
| Snowplow collector (dynamic from config) | Analytics events | POST |
| Feature flag service (dynamic from config) | Feature toggles | GET |
| Codes API (dynamic from config) | Coupon codes for domains | GET |
| Supported sites API (dynamic from config) | List of supported shopping sites | GET |
| Recommended offers API (dynamic from config) | Deal/offer data | GET |
| Safety/Threats API (dynamic from config) | URL safety checking | GET |
| Log posting URL (dynamic from config) | Debug telemetry | POST |
| `accounts.nike.com` | Site-specific coupon integration | - |
| `www.bedbathandbeyond.com/cartajax` | Site-specific cart detection | - |
| `www.klook.com/v*/couponapisrv/...` | Site-specific coupon redemption | - |

## Data Flow Summary

1. **Page Load:** Content script injected on all pages at `document_start`
2. **Site Detection:** Background checks if current URL matches supported shopping sites list (fetched from remote config)
3. **Safety Check:** Background queries threat API with URL to determine site safety status
4. **Cart/Coupon Detection:** On supported sites, content script reads site-specific cookies and DOM elements to detect cart pages and coupon fields
5. **Coupon Application:** When user triggers auto-apply, extension fetches coupon codes from API, simulates text input in coupon fields, monitors cart value changes
6. **Affiliate Handling:** Background monitors redirect chains via webRequest to detect existing affiliate cookies; stands down if affiliate already present
7. **Analytics:** Snowplow tracks extension UI interactions (popup opens, coupon applies, etc.) - not general browsing
8. **Telemetry:** Optional log posting sends extension operation logs to remote endpoint (gated by feature flag)

## Overall Risk: **CLEAN**

Avira Safe Shopping is a legitimate coupon/deal-finding extension from Gen Digital (Avira's parent company) that integrates the CouponFollow/Cently SDK. While it requests broad permissions and runs on all pages, this is justified by its functionality: detecting shopping sites, applying coupons, checking URL safety, and tracking affiliate redirects. The extension uses standard analytics (Snowplow), has transparent affiliate revenue disclosure, and scopes its data access to shopping-related functionality. No evidence of malicious behavior, data exfiltration, keylogging, residential proxy usage, or market intelligence SDK integration was found. The `chrome.avast.safeprice` API references indicate shared infrastructure with the Norton/Avast Safe Shopping variants from the same parent company.
