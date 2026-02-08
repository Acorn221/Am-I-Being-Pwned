# Vulnerability Report: Norton Safe Search

## Metadata
- **Extension Name:** Norton Safe Search
- **Extension ID:** mpnlkmlkncncpgnnkmkgoobfpnjmblnk
- **Version:** 3.24.0.5
- **Author:** NortonLifeLock Inc (Gen Digital)
- **Users:** ~5,000,000
- **Manifest Version:** 3
- **Analysis Date:** 2026-02-08

## Permissions
- `tabs` - Access to tab URLs and info
- `storage` - Local/sync storage
- `scripting` - Programmatic script injection
- `alarms` - Scheduling background tasks
- `declarativeNetRequest` - URL redirect/rewrite rules
- `webRequest` - Observe network requests
- **Host permissions:** `https://*.norton.com/*`
- **Content scripts:** `<all_urls>` (main injection), plus targeted Norton domains, nortonsafe.search.ask.com, Google/Yahoo search results

## Executive Summary

Norton Safe Search is a **legitimate search hijacking extension** from Gen Digital (NortonLifeLock). It overrides the default search engine to `searchsafe.norton.com`, annotates search results on Google/Yahoo/Ask with Norton SafeWeb safety ratings (clean/malware/phishing), and sends browsing URLs to Avast/Norton reputation servers for real-time safety checking. It also includes telemetry to Google Analytics and Norton's own stats server (`stats.securebrowser.com`), heartbeat pinging for install/active user tracking, and A/B testing configuration fetched from Norton's CDN.

The extension is invasive by design -- it intercepts search queries, rewrites URLs via declarativeNetRequest, sends visited URLs to backend servers for safety rating, and injects content scripts on all pages. However, all of this behavior is **consistent with its stated purpose** as a safe search / safe browsing tool from a major security vendor. There are no signs of malicious data exfiltration, residential proxy infrastructure, market intelligence SDKs, keylogging, or ad/coupon injection beyond its core search redirect functionality.

## Vulnerability Details

### 1. URL Exfiltration to Avast/Norton Reputation Servers (LOW)
- **Severity:** LOW (privacy concern, not a vulnerability)
- **Files:** `SafeWeb.js`, `annotationBG.js`
- **Details:** Every URL the user visits is sent to `https://urlite.ff.avast.com/v1/urlinfo` via protobuf-encoded POST requests for reputation checking (malware/phishing/clean/regional_block ratings). This is the core SafeWeb functionality. URLs are also sent for annotation of search results on Google/Yahoo.
- **Code:** `URL:"https://urlite.ff.avast.com/v1/urlinfo",RATINGS:{MALWARE:"MALWARE",PHISHING:"PHISHING",CLEAN:"CLEAN",REGIONAL_BLOCK:"REGIONAL_BLOCK"}`
- **Verdict:** Expected behavior for a safe browsing extension. The URL submission is standard for Norton/Avast URL reputation services. Privacy-sensitive but not malicious.

### 2. Search Query Interception & Redirect (LOW)
- **Severity:** LOW (by design)
- **Files:** `global.js`, `content/scripts/NSSS.js`
- **Details:** The extension sets itself as the default search provider (`searchsafe.norton.com`), intercepts omnibox searches via `webRequest.onBeforeRequest` and `declarativeNetRequest` dynamic rules, and redirects search queries through Norton's search partner (Ask.com / Yahoo). Search suggestions come from `ss-sym.search.ask.com`.
- **Code:** `chrome.webRequest.onBeforeRequest.addListener(l.NSSSHelper.handleOmniSearchMv3,{urls:[l.constants.SEARCH_URL+"?omnisearch=yes*"]})`
- **Verdict:** This is the extension's primary function. The search redirect monetizes through Ask.com/Yahoo partnerships. Standard for search-focused browser extensions.

### 3. Telemetry to Multiple Endpoints (LOW)
- **Severity:** LOW
- **Files:** `trackingServerSdk.js`, `HeartBeatSDK.js`
- **Details:** Sends telemetry events to two endpoints:
  - Google Analytics: `https://www.google-analytics.com/collect` (install pings, heartbeat, active user tracking)
  - Norton Stats: `https://stats.securebrowser.com/` (prod) / `https://stage-stats.securebrowser.com/` (debug)
  - Heartbeat pings every 30 minutes (`HB_POLLING_TIME_IN_MINUTES:30`)
- **Data sent:** Application name, version, client ID (machine ID), browser name/version, OS, platform, user language, custom events
- **Verdict:** Standard product telemetry. The telemetry can be disabled via settings (`isTelemetryEnabled()`). No unusual data collection observed.

### 4. Chrome Management API Usage (INFO)
- **Severity:** INFO
- **Files:** `SymBfw.js`, `content/scripts/NSSS.js`
- **Details:** Uses `chrome.management.get()` to check status of sibling Norton extensions (Norton Safe Web, Norton Homepage, etc.). Only uses `chrome.management.uninstallSelf()` -- does NOT uninstall other extensions. Extension IDs checked are all Norton/Symantec IDs:
  - `aajahhgggmjeoanmebkebnikpnfkbejb` (Norton Anti-Tracker)
  - Various Norton extension IDs for HP, SW, DS variants
  - Firefox: `nortonhomepage@symantec.com`, `nortonsafeweb@symantec.com`
- **Verdict:** Legitimate sibling extension coordination, not extension enumeration/killing.

### 5. Cookie API Access (INFO)
- **Severity:** INFO
- **Files:** `SymBfw.js`, `content/scripts/SymBfwCS.js`
- **Details:** Framework includes helper functions for `chrome.cookies.getAll()`, `chrome.cookies.remove()`, `chrome.cookies.set()`, and cookie change listeners. These are used for Norton portal session management on `*.norton.com` domains.
- **Verdict:** Cookie access is scoped to Norton domains via host_permissions. Standard for product portal integration.

### 6. Remote Configuration via CDN (INFO)
- **Severity:** INFO
- **Files:** `content/scripts/NSSS.js`, `annotationBG.js`
- **Details:** Fetches configuration from Norton CDN:
  - `https://static.nortoncdn.com/nortonextensionhomepage/URLParsingRules.json` (search result annotation rules)
  - `https://static.nortoncdn.com/nortonextensionhomepage/multi-variate-testing-rules.json` (A/B testing)
  - Uses certificate pinning with DigiCert root CA for CDN validation
- **Verdict:** Standard remote configuration pattern. Certificate pinning is a positive security measure. Rules appear to control UI behavior (annotations, homepage layout), not code execution.

### 7. Content Script on All URLs (INFO)
- **Severity:** INFO
- **Files:** `content/scripts/SymBfwCS.js`, `content/scripts/BfwNotificationCenterProxy.js`, `content/scripts/NSSSDarkModeCS.js`
- **Details:** Injects content scripts on `<all_urls>` for SafeWeb notification display and dark mode detection. The BfwNotificationCenterProxy creates iframes for Norton notification overlays.
- **Verdict:** Required for SafeWeb safety warnings to display on any page the user visits. Standard for safe browsing tools.

## False Positive Table

| Finding | File | Reason for FP |
|---------|------|--------------|
| `innerHTML` in React DOM | `content/libs/react-dom-latest.min.js` | React library internal DOM manipulation |
| `innerHTML` in jQuery | `content/libs/jquery.min.js` | jQuery DOM manipulation |
| `eval` in forge.min.js | `content/libs/forge.min.js` | Forge crypto library internals |
| `Function()` in multiVariateTestingBG.js | `multiVariateTestingBG.js` | JSON Schema validation library (Ajv) |
| `fetch` in multiple files | Various | Legitimate API calls to Norton/Avast services |
| `chrome.cookies` access | `SymBfw.js` | Scoped to Norton domains for portal integration |

## API Endpoints Table

| Endpoint | Purpose | Method |
|----------|---------|--------|
| `https://urlite.ff.avast.com/v1/urlinfo` | URL reputation checking (SafeWeb) | POST (protobuf) |
| `https://searchsafe.norton.com/search` | Safe search queries | GET |
| `https://ss-sym.search.ask.com/ss` | Search suggestions | GET |
| `https://static.nortoncdn.com/nortonextensionhomepage/URLParsingRules.json` | Search result annotation rules | GET |
| `https://static.nortoncdn.com/nortonextensionhomepage/multi-variate-testing-rules.json` | A/B testing config | GET |
| `https://www.google-analytics.com/collect` | Telemetry (GA) | POST |
| `https://stats.securebrowser.com/` | Norton telemetry | POST |
| `https://cloudconnect2.norton.com/v1/geolocationapi/location/countryembargoinformation/` | Geo/embargo check | GET |
| `https://safeweb.norton.com/report/show` | SafeWeb report page | GET |
| `https://search.norton.com/client` | Norton search client page | GET |
| `https://hp.norton.myway.com/norton/` | Norton homepage | GET |

## Data Flow Summary

1. **Search Interception:** User types in omnibox -> `declarativeNetRequest` rule or `webRequest.onBeforeRequest` listener intercepts -> redirects to `searchsafe.norton.com/search` with Norton tracking parameters (OCode, vendor ID, etc.)
2. **URL Reputation:** User navigates to any URL -> background SafeWeb module sends URL to `urlite.ff.avast.com/v1/urlinfo` via protobuf -> receives malware/phishing/clean rating -> displays warning if unsafe
3. **Search Annotations:** User views Google/Yahoo results -> content script (`annotationCS.js`) extracts result URLs -> sends to SafeWeb for batch rating -> renders safety icons (green checkmark / red warning) next to each result
4. **Telemetry:** Install events, heartbeat (30-min interval), and feature usage events -> sent to Google Analytics and Norton stats server with device/browser metadata
5. **Sibling Extension Coordination:** Checks for Norton Safe Web, Norton Homepage, Norton Anti-Tracker extensions via `chrome.management.get()` -> coordinates features (dark mode, association date, etc.)
6. **Norton Portal Communication:** On `*.norton.com` pages, content script sends extension metadata (vendor, extension type, product ID) via CustomEvent for portal integration

## Overall Risk Assessment: **CLEAN**

Norton Safe Search is a legitimate browser extension from Gen Digital (NortonLifeLock) that functions as advertised. While it is invasive by nature (search hijacking, URL reputation checking on all visited pages, telemetry), all observed behaviors are consistent with its stated purpose as a safe search and safe browsing tool. Key points:

- **No malicious data exfiltration** beyond its documented URL reputation checking
- **No residential proxy infrastructure** or traffic tunneling
- **No market intelligence SDKs** (Sensor Tower, Pathmatics, etc.)
- **No keylogging or credential harvesting**
- **No ad/coupon injection** beyond search result redirection
- **No extension enumeration/killing** of competitor extensions (only checks its own Norton siblings)
- **No dynamic code execution** from remote sources (CDN configs control UI behavior only, with cert pinning)
- **No obfuscation** beyond standard minification/bundling
- Certificate pinning on CDN requests is a positive security practice
- Telemetry has an opt-out mechanism

The extension monetizes through search partnerships (Ask.com/Yahoo) which is standard for free security tools. All network endpoints belong to Norton/Gen Digital, Avast (owned by Gen Digital), Google Analytics, and Ask.com -- all expected partners.
