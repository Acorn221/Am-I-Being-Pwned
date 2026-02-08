# Vulnerability Report: Browsec VPN - Free VPN for Chrome

## Metadata
- **Extension Name:** Browsec VPN - Free VPN for Chrome
- **Extension ID:** omghfjlpggmjjaagoclmmobgdodcjboh
- **Version:** 3.92.12
- **Manifest Version:** 3
- **User Count:** ~8,000,000
- **Homepage:** https://browsec.com/
- **Analysis Date:** 2026-02-08

## Executive Summary

Browsec VPN is a legitimate free/freemium VPN proxy extension that routes browser traffic through its proxy servers. The extension uses the `chrome.proxy` API to configure PAC scripts, manages WebRTC leak protection via `chrome.privacy`, and provides timezone spoofing to match the selected VPN country. It includes a promotional notification system that injects in-page banners to upsell premium subscriptions.

The extension requires broad permissions (`<all_urls>`, `proxy`, `webRequest`, `scripting`) which are appropriate for a VPN extension's core functionality. The most notable finding is a **massive CSP connect-src whitelist containing 86+ suspicious-looking domain names** (e.g., `cacheflow.cloud`, `edgecache.xyz`, `rapidcdn.click`). These are Browsec's own VPN proxy server domains used for tunneling traffic. While the domain naming pattern is suspicious, they are demonstrably used as proxy endpoints in the embedded server configuration. There is a remote configuration mechanism via GitHub Gist that can push `forceProxyRules` to route specific domains through specific countries, which is a mild concern but consistent with VPN functionality.

No evidence of: residential proxy abuse, data exfiltration, keylogging, cookie harvesting, ad/coupon injection, AI conversation scraping, extension enumeration/killing, or market intelligence SDK integration.

## Vulnerability Details

### MEDIUM-1: Remote Dynamic Configuration via GitHub Gist

- **Severity:** MEDIUM
- **Files:** `background.js` (module 6300, 5735, 6365)
- **Code:**
  ```javascript
  dynamicConfigUrl: "https://gist.githubusercontent.com/brwinfo/ef7f684e524d01137b84313a60e1ed01/raw/"
  rootUrl: "https://gist.githubusercontent.com/brwinfo/0d4c6d2ebbe6fd716a43f0ac9d37ce22/raw"
  ```
  The `dynamicConfig` is fetched every 240 minutes and can update:
  - `metricsDomain` (telemetry endpoint)
  - `forceProxyRules` (force specific domains through proxy)
  - `browsecCountry` (default proxy country for browsec.com)
  - Feature flags (`jitsuStatsEarlyEnabled`, `jitsuStatsUpdateEnabled`)
  - `browcheck` groups (connectivity monitoring config)
- **Verdict:** Standard remote configuration pattern for VPN services. The `forceProxyRules` capability could theoretically be abused to route specific domains through attacker-controlled servers, but this is managed via a public GitHub Gist (auditable). The config is validated and only accepts specific known properties. LOW actual risk.

### MEDIUM-2: Massive CSP connect-src Whitelist with Opaque Domain Names

- **Severity:** MEDIUM
- **Files:** `manifest.json` (line 25)
- **Code:** 86+ domains whitelisted in CSP connect-src including:
  ```
  prmsrvs.com, trafcfy.com, prmdom.com, frmdom.com, static-fn.com, fn-cdn.com,
  bd-assets.com, cdnflow.net, promptmesh.net, contentnode.net, swiftcdn.org,
  cacheflow.cloud, edgecache.xyz, rapidcdn.click, speedycdn.fun, tiktokcdn.org, ...
  ```
- **Verdict:** These are Browsec's VPN proxy server hostnames. The embedded server list in the code confirms these domains host proxy endpoints (e.g., `bg24.cacheflow.live:16694`, `no3.edgecache.fun:5969`). While the domain naming convention mimics CDN services (likely to evade network-level VPN blocking), they are used for their intended VPN purpose. The use of HTTP (not HTTPS) for these connections in the CSP is notable but may be required for proxy protocol compatibility. INFORMATIONAL for the domain opacity; the functionality is legitimate.

### LOW-1: In-Page Notification Banner Injection

- **Severity:** LOW
- **Files:** `notification.js`, `background.js`
- **Code:**
  ```javascript
  // background.js injects notification.js into tabs matching browsec promo domains
  inject({tabId, url}, "/notification.js")

  // notification.js creates a floating banner DOM element for premium upsell
  showNotificationBanner({html, promotionId, size, css, modifier})
  ```
- **Verdict:** The extension injects promotional banners into web pages to upsell Browsec Premium. The HTML for these banners is fetched from Browsec's promotion API (not arbitrary remote code). The CSS class names are randomized to avoid ad-blocker detection. This is a common monetization pattern for freemium VPN extensions and not malicious.

### LOW-2: Timezone Spoofing via Content Script Injection

- **Severity:** LOW
- **Files:** `timezoneChange.js`
- **Code:**
  ```javascript
  // Injects a <script> tag that overrides Date constructor to match proxy country timezone
  Date = dateCodeChange(Date, offsetDifference, proxyTimeZoneOffset);
  script.innerText = code.replace(/\n/gm, "");
  document.documentElement.insertBefore(script, document.documentElement.firstChild);
  ```
- **Verdict:** This is a privacy-enhancing feature that aligns the browser's timezone with the VPN exit node country to prevent timezone-based de-anonymization. This is legitimate VPN functionality. The `innerText` assignment (not `innerHTML`) prevents XSS.

### LOW-3: Telemetry/Analytics Data Collection

- **Severity:** LOW
- **Files:** `background.js`
- **Code:**
  ```javascript
  // GA4 digest analytics
  fallbackMetricsDomain: "data-e5.brmtr.org"
  GA4DigestAdapter.API_ENDPOINT = "https://www.google-analytics.com/g/collect"

  // Jitsu analytics for connection quality monitoring
  jitsu.A.track("connection")
  jitsu.A.track("traffic_in", {value: mbValue})
  jitsu.A.track("smartSettingsEdit")
  jitsu.A.track("vpnOff", {source: "onAuthRequired error"})
  ```
  Telemetry endpoint: `https://${metricsDomain}/api/st/event`
- **Verdict:** Standard analytics for VPN quality monitoring and usage statistics. The extension tracks connection events, errors, traffic volume, and feature usage. Firefox users have a `dontSendTelemetry` opt-out. The data collected is operational metrics, not browsing history or PII. GA tracking is disabled by default (`ga.enabled: false`), with only GA4 Digest active.

### INFO-1: User Identity Tracking via extintid

- **Severity:** INFO
- **Files:** `background.js`
- **Code:**
  ```javascript
  fetch(production_default().baseUrl + "/api/v1/attributes/extintid", {
    credentials: "include", method: "GET"
  })
  // Then stores and reports back:
  fetch(production_default().baseUrl + "/api/v1/attributes", {
    body: JSON.stringify({data: {extintid: id}}),
    credentials: "include", method: "POST"
  })
  ```
- **Verdict:** Creates a unique installation identifier for analytics correlation. This is standard practice for extension analytics and not a privacy concern beyond normal telemetry.

### INFO-2: `new Function("return this")` Usage

- **Severity:** INFO
- **Files:** `background.js`
- **Code:** `new Function("return this")` - used to get global `this` reference
- **Verdict:** Common webpack/bundler pattern for getting the global scope. Not dynamic code execution.

## False Positive Table

| Pattern | Location | Reason for FP |
|---------|----------|---------------|
| `new Function("return this")` | background.js | Webpack global scope detection pattern |
| `chrome.management.getAll` | common.js (API wrapper) | Part of cross-browser API compatibility layer (`webextension-polyfill`-like), only used if `management` permission is granted (optional) |
| `browsingData.remove` | background.js | Used to clear cache for specific domains on proxy tunnel errors (cache busting for connectivity), not data wiping |
| `innerHTML` | notification.js | Used for constructing in-page promo banner elements from Browsec's own promotion API, not arbitrary injection |
| `chrome.scripting.executeScript` | background.js | Injects only Browsec's own bundled content scripts (`promoPageExecutor.js`, `notification.js`) by file path, not arbitrary code |
| `postMessage` listener | browsecSiteContentScript.js | Listens for `auth` type messages from browsec.com page to relay login credentials to background - site-to-extension auth flow |
| Domain names (bard, gemini, coupon, etc.) | background.js | Part of public suffix / domain categorization database for smart proxy routing, not scraping targets |
| `p2p`, `peer` references | background.js | Domain names in public suffix list (e.g., `starp2p.com`, `servep2p.com`), not residential proxy infrastructure |

## API Endpoints Table

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `https://browsec.com/api/v1/test` | GET | Server connectivity test |
| `https://browsec.com/api/v1/attributes/extintid` | GET | Fetch/create installation ID |
| `https://browsec.com/api/v1/attributes` | POST | Store installation ID |
| `https://d3i5gqankjg0sg.cloudfront.net/` | GET | Primary API server |
| `https://a703.l461.r761.fastcloudcdn.net/api/` | GET | Fallback API server |
| `https://ca901.l503.r843.fastcloudcdn.net/` | GET | Fallback API server |
| `{apiServer}/v1/test` | GET | Server availability test |
| `{apiServer}/servers` | GET | Fetch proxy server list |
| `{apiServer}/properties` | GET/PUT | User settings sync (smart settings, favorites, timezone, webrtc) |
| `{apiServer}/properties/smart_settings` | PUT | Update smart proxy routing rules |
| `{apiServer}/properties/timezoneChange` | PUT | Update timezone spoofing preference |
| `{apiServer}/properties/webrtcBlock` | PUT | Update WebRTC blocking preference |
| `{apiServer}/properties/favorites` | PUT | Update favorite countries |
| `{apiServer}/properties/promotionsBlock` | PUT | Update promotion blocking preference |
| `https://gist.githubusercontent.com/brwinfo/.../raw` | GET | Fetch available server list (rootUrl) |
| `https://gist.githubusercontent.com/brwinfo/.../raw/` | GET | Fetch dynamic configuration |
| `https://www.google-analytics.com/mp/collect` | POST | GA4 Measurement Protocol |
| `https://www.google-analytics.com/g/collect` | POST | GA4 digest analytics |
| `https://{metricsDomain}/api/st/event` | POST | Jitsu telemetry events |
| `https://data-e5.brmtr.org/...` | POST | Fallback metrics domain |
| Various `*.cacheflow.cloud`, `*.edgecache.xyz`, etc. | PROXY | VPN proxy server endpoints (86+ domains) |

## Data Flow Summary

1. **Installation:** Extension generates/fetches unique `extintid` from browsec.com, stores locally and reports to server.
2. **Server Discovery:** Fetches available VPN server list from GitHub Gist (rootUrl) and CloudFront/fastcloudcdn API servers. Server list includes proxy hostnames across 86+ domains.
3. **Proxy Configuration:** Uses `chrome.proxy.settings` to set PAC script that routes traffic through selected country's proxy servers. Smart Settings allows per-domain country selection.
4. **Dynamic Config:** Every 4 hours, fetches dynamic configuration from GitHub Gist that can update metrics domain, force proxy rules, and feature flags.
5. **Authentication:** For premium users, proxy authentication via `webRequestAuthProvider`. Credentials (access_token, ipsec_password, xray_uuid) stored locally. Authorization header injected via `declarativeNetRequest` for Browsec domains.
6. **Privacy Features:** WebRTC leak protection via `chrome.privacy.network.webRTCIPHandlingPolicy`, timezone spoofing via content script Date prototype override.
7. **Telemetry:** Connection quality metrics (success rate, failure count, latency) sent via GA4 Measurement Protocol to google-analytics.com and custom metrics domain (brmtr.org). Tracks VPN on/off, connection errors, feature usage, traffic volume.
8. **Promotions:** In-page notification banners injected on web pages to promote Browsec Premium. Promo page executor runs on Browsec-opened tabs to append tracking parameters.
9. **Cache Removal:** On proxy tunnel errors, clears browser cache for the failing domain using `browsingData.remove`.

## Overall Risk Assessment

**Risk Level: CLEAN**

Browsec VPN is a legitimate freemium VPN extension that functions as advertised. While it requests broad permissions (`<all_urls>`, `proxy`, `webRequest`, `scripting`, `browsingData`, `declarativeNetRequest`), all of these are justified for a VPN extension that needs to:
- Route all traffic through proxy servers (proxy, `<all_urls>`)
- Monitor connection quality and handle auth challenges (webRequest, webRequestAuthProvider)
- Inject timezone spoofing and notification scripts (scripting)
- Clear cache on tunnel failures (browsingData)
- Set authorization headers for API calls (declarativeNetRequest)

The 86+ opaque domain names in the CSP are VPN proxy server endpoints, not C2 infrastructure. The remote configuration via GitHub Gist is auditable and constrained to known configuration properties. The telemetry collected is standard operational metrics without browsing history or PII exfiltration. The in-page notification banners are a standard freemium upsell mechanism.

No evidence of malicious behavior, residential proxy abuse, data harvesting, or security vulnerabilities beyond the inherent trust model of routing traffic through a third-party VPN provider.
