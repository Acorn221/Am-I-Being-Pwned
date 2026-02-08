# Vulnerability Report: Norton Safe Web

## Metadata
- **Extension Name:** Norton Safe Web
- **Extension ID:** fnpbeacklnhmkkilekogeiekaglbmmka
- **Version:** 3.24.0.19
- **Author:** NortonLifeLock Inc (Gen Digital Inc.)
- **Manifest Version:** 3
- **User Count:** ~5,000,000
- **Analyzed Date:** 2026-02-08

## Executive Summary

Norton Safe Web is a legitimate website safety rating extension from Gen Digital (formerly NortonLifeLock). It checks URLs against Norton's SafeWeb reputation database and the Avast URLITE service (following Gen Digital's acquisition of Avast). The extension uses broad permissions (`<all_urls>`, `tabs`, `webNavigation`, `webRequest`, `downloads`, `scripting`, `storage`, `declarativeNetRequest`) which are invasive but consistent with its stated purpose of providing real-time website safety ratings, search result annotations, phishing/malware blocking, download scanning, and link guard protection.

The extension sends visited URLs to Norton/Avast backend servers for reputation lookup, sends telemetry to Google Analytics (`google-analytics.com/collect`) and Norton's tracking server (`stats.securebrowser.com`), and threat data to `analytics.avcdn.net`. It includes search engine redirection infrastructure (Norton Safe Search via `nortonsafe.search.ask.com`, `searchsafe.norton.com`, Yahoo, and Bing), multi-variate A/B testing from remote CDN config, and checks for the existence of other Norton extensions. All of this is consistent with a security product's intended functionality. No malicious behavior, data exfiltration beyond stated purpose, residential proxy infrastructure, market intelligence SDKs, or obfuscated payloads were found.

## Vulnerability Details

### 1. Broad URL Data Collection to Multiple Backends
- **Severity:** LOW (Privacy concern, not a vulnerability)
- **Files:** `NSSS.js` (background), `content/scripts/beforeLoad.js`, `content/scripts/annotationCS.js`
- **Description:** Every page visited is sent to Norton's backend for URL reputation checking via the SafeWeb SDK and Avast's URLITE service (`https://urlite.ff.avast.com/v1/urlinfo`). This is the core functionality of the extension.
- **Verdict:** Expected behavior for a web safety extension. Users opt in by installing it.

### 2. Telemetry to Multiple Analytics Endpoints
- **Severity:** LOW (Privacy concern)
- **Files:** `NSSS.js` - telemetry modules (`BfwTelemetry.js`, `BfwTelemetryScd.js`, `BfwTelemetrySettings.js`)
- **Endpoints:**
  - `https://www.google-analytics.com/collect` (Google Analytics)
  - `https://stats.securebrowser.com/` (Norton tracking server)
  - `https://analytics.avcdn.net/v4/receive/json` (Avast threat telemetry)
- **Data sent:** Client ID, application name/version, data source, tracking ID, user agent, user language, product telemetry events.
- **Code:** `this.GOOGLE_ANALYTICS_URL="https://www.google-analytics.com/collect",this.REQUEST_TYPE="POST",this.COLLECTION_STATE=!0`
- **Verdict:** Standard product telemetry. Extension provides a telemetry opt-out mechanism (`TELEMETRY_ENABLED`, `TELEMETRY_OPT_OUT_SHOWN`).

### 3. Search Engine Redirection Infrastructure
- **Severity:** LOW (PUP-like behavior)
- **Files:** `NSSS.js`
- **Description:** The extension contains infrastructure to redirect searches through Norton Safe Search endpoints (`nortonsafe.search.ask.com`, `searchsafe.norton.com`, Yahoo partner search). This appears to be an opt-in "Safe Search" feature integrated into the extension.
- **Code:** `s.SEARCH_URL="https://nortonsafe.search.ask.com/web"`, `searchUrl:{"en-us":"https://search.yahoo.com/yhs/search?"}`
- **Verdict:** Search partner integration is opt-in (controlled by `defaultSearchEnabled` setting). While historically controversial, this is a disclosed Norton feature, not covert hijacking.

### 4. Remote Configuration via CDN
- **Severity:** LOW
- **Files:** `NSSS.js`
- **Endpoints:**
  - `https://static.nortoncdn.com/nortonextensionhomepage/multi-variate-testing-rules.json`
  - `https://static.nortoncdn.com/nortonextensionhomepage/URLParsingRules.json`
- **Description:** Extension fetches remote A/B testing rules and URL parsing rules from Norton's CDN. These are verified with a pinned root CA certificate.
- **Verdict:** Remote config with certificate pinning is a reasonable approach. The rules control UI experiments and URL parsing, not code execution.

### 5. `wasm-unsafe-eval` in CSP
- **Severity:** LOW
- **Files:** `manifest.json`
- **Code:** `"extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"`
- **Verdict:** Required for WebAssembly execution, likely for cryptographic operations (forge.js, jsrsasign). Not exploitable without another vulnerability.

### 6. XHR Proxy Wrapper (BfwXhr/BfwXhrProxy)
- **Severity:** INFO
- **Files:** `NSSS.js` (source modules `xhr_proxy/BfwXhr.js`, `xhr_proxy/BfwXhrProxy.js`)
- **Description:** The extension wraps XMLHttpRequest in a proxy class for its own internal use (logging, monitoring). This does NOT inject into page context or hook page-level XHR.
- **Verdict:** Internal utility pattern, not XHR hijacking.

### 7. `new Function()` Usage
- **Severity:** INFO (False Positive)
- **Files:** `NSSS.js`
- **Code:** `return this||new Function("return this")()`
- **Verdict:** Standard JavaScript globalThis polyfill pattern from Closure Compiler / webpack. Not dynamic code execution.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")` | NSSS.js, NSSS_CS.js, BfwCS.js | Standard globalThis polyfill (Closure Compiler) |
| `fromCharCode` (192 instances) | NSSS.js | forge.js / jsrsasign crypto library character processing |
| `privateKey` (128+ instances) | NSSS.js | forge.js / jsrsasign RSA/Ed25519 cryptographic operations |
| `chrome.proxy.settings` | NSSS.js | BFW adapter reads/monitors proxy settings for security purposes |
| `chrome.history.onVisited` | NSSS.js | BFW adapter wrapper; declared but not necessarily used for data collection |
| `innerHTML` | Not found | N/A |
| `createElement`/`appendChild` | beforeLoad.js | Standard DOM element creation (7/5 instances) for UI elements |
| JavaScript Proxy objects | NSSS.js | ES6 Proxy polyfill from Closure Compiler |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://urlite.ff.avast.com/v1/urlinfo` | URL reputation lookup (Avast URLITE) | URL being visited |
| `https://safeweb.norton.com/report/show` | User-initiated site report | URL, user report |
| `https://www.google-analytics.com/collect` | Product telemetry | Client ID, UA, events |
| `https://stats.securebrowser.com/` | Norton tracking server | Telemetry events, product metrics |
| `https://analytics.avcdn.net/v4/receive/json` | Threat data telemetry | Threat detection events |
| `https://cloudconnect2.norton.com/v1/geolocationapi/location/countryembargoinformation/` | Geolocation/embargo check | IP-based geolocation |
| `https://static.nortoncdn.com/nortonextensionhomepage/multi-variate-testing-rules.json` | A/B test config | None (download only) |
| `https://static.nortoncdn.com/nortonextensionhomepage/URLParsingRules.json` | URL parsing rules | None (download only) |
| `https://nortonsafe.search.ask.com/web` | Norton Safe Search (Ask partner) | Search queries |
| `https://searchsafe.norton.com/search` | Norton Safe Search | Search queries |
| `https://search.yahoo.com/yhs/search` | Yahoo partner search | Search queries |
| `https://gendigital.qualtrics.com/jfe/form/SV_eM0Jz36NWeBBkeG` | User feedback survey | User-initiated |
| `https://sitedirector.norton.com/932743328` | Norton site director / marketing | Redirect parameters |

## Data Flow Summary

1. **Page Visit Flow:** User navigates to a page -> content script (`beforeLoad.js`) injects at `document_start` on `<all_urls>` -> sends URL to background service worker via chrome.runtime message -> background (`NSSS.js`) queries Avast URLITE (`urlite.ff.avast.com/v1/urlinfo`) for URL reputation -> result (CLEAN/MALWARE/PHISHING) returned to content script -> UI updated (icon, annotation on search results, block page if malicious).

2. **Search Annotation Flow:** User searches on Google -> content script (`annotationCS.js`) extracts search result URLs -> sends to background for batch URL rating -> annotations (safe/warning icons) displayed next to search results.

3. **Download Protection:** Downloads monitored via `chrome.downloads.onCreated` -> download URL analyzed -> malicious downloads cancelled via `chrome.downloads.cancel()`.

4. **Telemetry Flow:** Product usage events collected -> sent to Google Analytics and `stats.securebrowser.com` (configurable, with opt-out). Threat detections sent to `analytics.avcdn.net`.

5. **Search Engine Integration:** Optional Norton Safe Search redirects searches through partner engines (Ask.com, Yahoo) with safety annotations. Controlled by `defaultSearchEnabled` setting.

6. **Extension Coordination:** Checks for existence of other Norton extensions (Home Page, Safe Search, Password Manager) via `chrome.runtime.sendMessage` to known Norton extension IDs only.

7. **Remote Config:** Fetches A/B test rules and URL parsing rules from `static.nortoncdn.com` with certificate pinning validation.

## Overall Risk: **CLEAN**

Norton Safe Web is a legitimate security product from Gen Digital (Norton/Avast parent company). While it collects URLs for reputation checking and sends telemetry data, this is the core intended functionality of a web safety extension. The broad permissions (`<all_urls>`, `webRequest`, `tabs`, `downloads`, `scripting`) are justified by the feature set: real-time URL reputation checking, search result annotation, download protection, phishing/malware blocking, and link guard. The search engine partnership infrastructure (Ask.com, Yahoo) is an opt-in feature. No evidence of malicious behavior, covert data exfiltration, residential proxy usage, market intelligence SDK injection, keylogging, or obfuscated payloads was found. The extension uses standard Gen Digital/NortonLifeLock infrastructure exclusively.
