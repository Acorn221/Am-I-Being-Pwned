# Avira Browser Safety (v4.3.1.57) -- Vulnerability & Static Analysis Report

**Extension ID:** `flliilndjeohchalpbbcdekjklbdgfkk`
**Publisher:** Avira Operations GmbH & Co. KG
**Manifest Version:** 3
**Users:** ~8M
**Triage Result:** SUSPECT (16 T1, 2 T2, 3 V1, 15 V2)

---

## Executive Summary

Avira Browser Safety is a legitimate security extension from a major antivirus vendor. It provides URL classification (phishing/malware blocking), tracker blocking (via embedded AdGuard), search result safety annotations, Do-Not-Track header enforcement, and a **shopping/coupon comparison feature ("Offers")** powered by Ciuvo.

**Overall Risk: LOW-MEDIUM** -- This is not malware. However, there are several privacy/security concerns that users should be aware of:

1. **Shopping/price comparison module** scrapes product data from pages and sends it to Avira's offers API -- this is a monetization feature hidden inside a "security" extension
2. **Extension enumeration** collects IDs, names, permissions, versions of all installed extensions and sends to Mixpanel
3. **Tracker blocker is temporarily disabled** when users visit coupon/affiliate pages (DNT bypass for offers)
4. **CSP includes `http://localhost:4000`** -- a leftover development debugging backdoor
5. **8 hardcoded API keys** are exposed in the bundle (low severity but poor practice)

---

## Architecture Overview

### Manifest Permissions
```
permissions: tabs, storage, webRequest, cookies, unlimitedStorage, scripting,
             declarativeNetRequest, alarms, webNavigation
host_permissions: <all_urls>
optional_permissions: management
```

### Key Components
| File | Purpose |
|------|---------|
| `js/background/ServiceWorker.js` | Service worker entry, imports background.js + webRequestListenerWrapper.js |
| `js/background/background.js` | 1.2MB monolithic bundle -- ALL background logic |
| `js/webRequestListenerWrapper.js` | Deduplicates redirect loops in webRequest |
| `js/content/content.js` | Content script bootstrapper -- creates ABS messenger |
| `js/content/content-safety.js` | Injected per-tab: search engine scan, phishing detection, tracker notifications |
| `js/content/content-offers.js` | Injected per-tab when offers enabled: Ciuvo shopping comparison UI |
| `adguard/adguard-api.js` | Embedded AdGuard content blocker library |
| `adguard/adguard-content.js` | AdGuard cosmetic filtering + element hiding |
| `offers_js/cms_ao2.js`, `cms_aon.js`, `cms_ass.js`, `cms_ss2.js` | Shopping offer template renderers (price comparison, coupons, hotels) |
| `offers_js/external-splashoffer.js` | Firefox link fix for external offer iframes |

---

## Triage Flag Analysis

### 1. `dynamic_function` (11 files) -- FALSE POSITIVE

All 11 instances of `new Function()` are from **Underscore.js's `_.template()` engine** bundled into multiple files. The pattern is always:

```javascript
// Underscore.js template compilation
s = "var __t,__p='',__j=Array.prototype.join,...";
o = new Function(a, "_", s)  // a = "obj", compiles template string
```

**Files affected:** popup.js, blockedIFrame.js, blocked.js, content-offers.js, landingPage.js, content-safety.js, background.js, verticalApp.js, about.js, app.js, ExtPermNotification.js, trackerNotification.js

**Verdict: FALSE POSITIVE** -- Standard Underscore.js template compilation. No dynamic code execution from external sources.

### 2. `dynamic_eval` -- FALSE POSITIVE (AdGuard)

The single `eval()` call is in `adguard/adguard-content.js:5105`:
```javascript
contentWindow.eval(`(${injectedToString()})(${args});`);
```

This is AdGuard's standard mechanism for injecting content scripts into iframes to apply cosmetic filters. The `injectedToString()` is a local function reference, not remote code. AdGuard also contains `noeval` and `log-eval` scriptlets which intercept/block eval calls on pages -- these are security features, not vulnerabilities.

**Verdict: FALSE POSITIVE** -- Standard AdGuard content blocker behavior.

### 3. `script_injection` -- TRUE POSITIVE (Expected for extension type)

The extension uses `chrome.scripting.executeScript()` in several places:

1. **content-safety.js injection** (line ~754): Injects safety classification UI on every tab
2. **content-offers.js injection** (line ~484): Injects shopping comparison module when offers are enabled
3. **Extension onboarding classname injection** (line ~41198): Adds CSS class `{ext}-installed` to Avira pages
4. **Extension onboarding "don't show again" injection** (line ~41281): Adds click handler for onboarding dismissal

All injection targets are the extension's own bundled scripts. No remote code is injected.

**Verdict: TRUE POSITIVE but expected behavior** -- Security extension injecting its own analysis scripts.

### 4. `ext_enumeration` -- TRUE POSITIVE (Privacy Concern)

**Location:** background.js lines ~40970-41000

The extension requests `management` permission at runtime and calls `chrome.management.getAll()`:

```javascript
get(e) {
  return !e && !a.get("extension_scan") || null == chrome.management.getAll
    ? Promise.resolve(null)
    : new Promise((e => {
        chrome.management.getAll((t => {
          const r = {
            ExtensionIds: [],
            ExtensionNames: [],
            ExtensionInstallTypes: [],
            ExtensionPermissions: [],
            ExtensionVersions: []
          };
          t.filter(this._extensionFilter).forEach((e => {
            r.ExtensionIds.push(e.id),
            r.ExtensionNames.push(e.name),
            r.ExtensionInstallTypes.push(e.installType),
            r.ExtensionPermissions.push(e.permissions),
            r.ExtensionVersions.push(e.version)
          })), e(r)
        }))
      }))
}
```

The filter excludes self and a hardcoded list of Avira extensions. The collected data is sent to Mixpanel:

```javascript
n.publish("Mixpanel:track", {
  event: "Extension scan initialised",
  properties: e  // contains all extension IDs, names, permissions, versions
})
```

**Mitigating factors:**
- Gated behind `extension_scan` setting (user can disable)
- Uses `optional_permissions: ["management"]` (requires user consent prompt)
- The filter excludes Avira's own extensions

**Verdict: TRUE POSITIVE -- Privacy concern.** Full extension inventory (IDs, names, permissions, versions) is sent to Mixpanel analytics. While framed as a "security scan," this is fingerprinting telemetry.

### 5. `hardcoded_secret` (8 instances) -- TRUE POSITIVE (Low severity)

All 8 secrets are in the config block (duplicated in background.js and content-offers.js):

| Secret | Service | Value | Risk |
|--------|---------|-------|------|
| `auc.api_key` | Avira URL Classification API | `2216cc6964aa79fa09205dd4b08fb808` | Low -- server-side API key for URL lookups |
| `ao.api_key` | Avira Offers API | `DhwrO06Igpulf142CT6NcUDrKlh4OG4L` | Low -- shopping comparison API |
| `ao.api_key_promo` | Avira Offers Promo API | `FaE1BFxmrh9zK5KOF27UiRLAdWoPCZY7` | Low -- promo variant of offers API |
| `mixpanel.token` | Mixpanel Analytics | `c34a8016e04ab4b4b232b1e71cc12d66` | Low -- analytics token |
| `sentry_dsn` | Sentry Error Reporting | `https://de51468527964eda8ca3e52ac844db69@sentry.avira.net/20` | Low -- error reporting DSN |
| `beta.gc_id` | Beta Extension ID | `biegckbcmgljgabmpjcpmkbheikknfch` | Info -- not a secret |
| `nightly.gc_id` | Nightly Extension ID | `enhedicmkidpahjffkbmhgiacbodpcbo` | Info -- not a secret |
| `chrome.id` | Production Extension ID | `flliilndjeohchalpbbcdekjklbdgfkk` | Info -- not a secret |

**Verdict: TRUE POSITIVE but low severity.** These are standard client-side API keys, not server secrets. Mixpanel token and Sentry DSN could be abused to inject fake analytics events, but this is a minor concern. The Offers API keys could be used to query Avira's shopping comparison backend.

### 6. `webrequest_all_urls` -- TRUE POSITIVE (Expected for extension type)

The extension registers multiple `chrome.webRequest.onBeforeRequest` listeners with `<all_urls>`:

1. **URL classification** (AUC Classifier, line ~2368): Inspects all main_frame, sub_frame, script, xmlhttprequest, image, object, other requests to classify URLs as safe/unsafe/malware/phishing
2. **Tracker blocking** (AdGuard DNT, line ~43047): Monitors main_frame requests for tracker blocking
3. **Affiliate detection** (Ciuvo ASDetector, line ~40376): Monitors HTTP(S) main_frame requests to detect affiliate redirects
4. **DNT header** (line ~60): Adds `DNT: 1` header to all requests via declarativeNetRequest

**What it does NOT do:**
- Does NOT modify response bodies
- Does NOT inject scripts via webRequest (uses scripting API instead)
- Does NOT redirect to monetized URLs (affiliate detection is passive)

**Verdict: TRUE POSITIVE but expected** -- Security extension monitoring traffic for threat detection.

---

## Detailed Security & Privacy Findings

### FINDING 1: Shopping Comparison / Price Comparison Module (MEDIUM)

**The core privacy concern with this extension is that it is not just a security tool -- it is also a shopping comparison and coupon platform.**

When the "Offers" setting is enabled (default: ON per config):

1. **Page scraping:** The extension sends the current page URL to `https://offers.avira.com/aviraoffers/api/v2/analyze` to get scraping instructions
2. **Data extraction:** Scraped product data (price, name, availability) is sent to `https://offers.avira.com/aviraoffers/api/v2/offers`
3. **UI injection:** Price comparison results, coupons, and affiliate offers are injected into the page via an iframe (top bar or side card)
4. **Coupon auto-apply:** When users visit coupon pages from `offers.avira.com`, the extension:
   - Shows a loading page
   - **Temporarily whitelists affiliate tracking domains** by adding AdGuard exception rules (`@@||domain^$important`)
   - Disables DNT (tracker blocking) for the tab with a timeout of `dnt_disable_timeout: 72e5` (7,200,000ms = 2 hours)
   - Redirects back to the coupon page

**This means the "Browser Safety" extension actively disables its own security features (tracker blocking) to enable affiliate tracking on shopping sites.**

The offers module is powered by **Ciuvo** (a shopping comparison provider). The `ciuvo/ASDetector` module detects when traffic originates from affiliate sources and suppresses offers to avoid affiliate conflicts.

### FINDING 2: Telemetry / Data Collection (LOW-MEDIUM)

The extension sends data to multiple endpoints:

| Endpoint | Data Sent | Method |
|----------|-----------|--------|
| `https://api.mixpanel.com/track/` | User actions, popup opens, detections, errors, extension inventory, settings, browser/OS info, distinct_id | GET (base64-encoded JSON) |
| `https://analytics.avcdn.net/v4/receive/json/167` | Threat detections (URL, category, browser, OS, GUID, user agent) | POST via tracking SDK |
| `https://v2.auc.avira.com/api` | URL hashes for classification queries | GET |
| `https://offers.avira.com/aviraoffers/api/v2` | Current page URL, scraped product data, extension version, dark mode pref | GET |
| `https://sentry.avira.net` | Error reports with stack traces | POST |
| `https://dispatch.avira-update.com/` | Update checks with product_id | GET |

**Mixpanel events tracked include:**
- "Popup open" (with tab URL)
- "AUC - Detection" (with category, domain, URL, extension inventory)
- "Extension scan initialised" (with full extension inventory)
- "SpoofedAddressBar - Detection" (with URL)
- "DNT - Settings change"
- "iFrame removed by website" (with category, URL, domain)
- Install/active/error events

### FINDING 3: CSP Localhost Exception (LOW -- Development Leftover)

```json
"content_security_policy": {
  "extension_pages": "script-src 'self' http://localhost:4000; object-src 'self';"
}
```

This allows extension pages to load and execute scripts from `http://localhost:4000`. This is clearly a development debugging remnant. In practice:

- Requires local code running on port 4000 to exploit
- Only affects extension pages (popup, blocked page, etc.), not content scripts
- MV3 CSP is more restrictive than MV2, limiting the blast radius

**Verdict: Low severity** but poor security hygiene. Should be removed in production builds.

### FINDING 4: Extension Discovery / Cross-Extension Communication (LOW)

The extension discovers other Avira extensions via `chrome.runtime.sendMessage()` to hardcoded extension IDs:

```javascript
extensionOnboarding: {
  extensions: {
    abs: ["flliilndjeohchalpbbcdekjklbdgfkk", "abs@avira.com", "cgaagkgjdadbihdpanmdkgdphlloacnj"],
    pwm: ["caljgklbbfbcjjanaijlacgncafpegll", "pedpfpedmgmbfnplmhbkodnfbfelgdbc", ...],
    sse: ["ccbpbkebodcjkknkfkpmfeciinhidaeh", "caiblelclndcckfafdaggpephhgfpoip", ...]
  }
}
```

This is used for:
- Checking if Avira Safe Shopping (SSE) is installed (to avoid duplicate offers)
- Cross-extension onboarding coordination
- Reporting `PWM installed`, `SSE installed` etc. to Mixpanel

The `onMessageExternalHandler` responds to `extensionOnboarding: "discover"` messages from these IDs only.

**Does NOT enumerate arbitrary extensions** -- only checks Avira's own extension IDs.

### FINDING 5: Search Result Annotations (LOW -- Expected)

The `content/searchEngineScan` module and `content/search/search` annotate search engine results with safety icons:
- `serp_info_safe.svg` (green)
- `serp_info_unsafe.svg` (red)
- `serp_info_warning.svg` (yellow)

Safety annotations are based on AUC (Avira URL Classification) database lookups. The icons are inserted next to search results via `insertBefore`. This modifies the visual appearance of search pages but does not modify links, URLs, or search rankings.

**Verdict: Expected behavior for a web safety extension.** Not manipulating results, only annotating them.

### FINDING 6: AdGuard Content Blocker Integration (LOW)

The embedded AdGuard library (`adguard/adguard-api.js`, ~9000 lines) includes:
- `new Function()` calls for CSS selector/filter rule parsing (standard AdGuard behavior)
- Scriptlet injection (noeval, log-eval, etc.) for blocking page-side tracking
- `eval()` for injecting content scripts into iframes

Filter lists are downloaded from `https://download.avira.com/update/adguard/` with Avira whitelisting of `*.avira.com`, `*.avira.org`, `*.avira.net`.

**Notable:** Avira whitelists its own domains from tracker blocking by default.

### FINDING 7: webRequestListenerWrapper.js (INFO)

```javascript
(function(e) {
  let r = -1;
  const t = e.addListener.bind(e);
  e.addListener = (e, ...n) => {
    t((t => {
      const n = e(t);
      return t.requestId === r ? null : (n && null != n.redirectUrl && (r = t.requestId), n)
    }), ...n)
  }
})(chrome.webRequest.onBeforeRequest)
```

This monkey-patches `chrome.webRequest.onBeforeRequest.addListener` to prevent redirect loops by suppressing duplicate redirects for the same requestId. This is a defensive wrapper, not malicious.

---

## What This Extension Does NOT Do

- Does NOT disable or uninstall other extensions (uses management.getAll only for telemetry)
- Does NOT inject affiliate links into pages
- Does NOT modify search results (only adds safety annotations)
- Does NOT proxy traffic or act as a VPN
- Does NOT contain obfuscated C2 communication
- Does NOT execute remotely-fetched code (all scripts are bundled)
- Does NOT capture passwords or form data

---

## Risk Assessment

| Category | Rating | Notes |
|----------|--------|-------|
| Malware/Trojan | NONE | Legitimate vendor, no malicious payload |
| Privacy | MEDIUM | Shopping data scraping, extension inventory to Mixpanel, user activity tracking |
| Security | LOW | CSP localhost exception, hardcoded API keys |
| Monetization | MEDIUM | Hidden shopping comparison module, DNT bypass for affiliates |
| Transparency | LOW-MEDIUM | "Browser Safety" name does not indicate shopping comparison features |

**Overall: LOW-MEDIUM risk. Not malware. The main concerns are:**
1. The shopping/coupon comparison module is a monetization feature that actively disables the extension's own tracker blocking to enable affiliate tracking
2. Extension inventory telemetry to Mixpanel is a fingerprinting concern
3. The CSP localhost exception is a development leftover that should be removed

---

## Recommendations for Users

1. **Disable the "Offers" setting** in the extension popup to prevent shopping data scraping and affiliate tracking
2. **Decline the "Extensions Analysis" permission** prompt when asked -- this sends your full extension list to Mixpanel
3. Be aware that this is not purely a security tool -- it contains a price comparison/coupon monetization engine
4. Consider whether the URL classification and tracker blocking features are worth the telemetry tradeoff vs. alternatives like uBlock Origin

---

## File Inventory

```
deobfuscated/
  manifest.json                          -- MV3, permissions as documented above
  js/background/ServiceWorker.js         -- Service worker entry (9 lines)
  js/background/background.js            -- 1.2MB monolithic bundle (44107+ lines)
  js/webRequestListenerWrapper.js        -- Redirect loop prevention wrapper
  js/content/common.js                   -- Shared utilities
  js/content/content.js                  -- Content script bootstrapper (ABS messenger)
  js/content/content-safety.js           -- Safety UI, search annotations, phishing analysis
  js/content/content-offers.js           -- Shopping comparison UI (Ciuvo-powered)
  js/content/landingPage.js              -- Avira landing page integration
  js/content/about.js                    -- About page
  js/content/app.js                      -- App page
  js/content/verticalApp.js              -- Vertical app page
  js/content/ExtPermNotification.js      -- Extension permission notification
  js/content/trackerNotification.js      -- Tracker count notification
  js/popup/popup.js                      -- Popup UI
  js/blocked.js                          -- Blocked page UI
  js/blockedIFrame.js                    -- Blocked iframe UI
  js/absLog.js                           -- Logging
  js/modules/offers/content/iframe/external.js -- External offers iframe
  adguard/adguard-api.js                 -- AdGuard content blocker engine
  adguard/adguard-content.js             -- AdGuard content script
  adguard/adguard-assistant.js           -- AdGuard assistant
  offers_js/cms_ao2.js                   -- Offers template set AO2
  offers_js/cms_aon.js                   -- Offers template set AON
  offers_js/cms_ass.js                   -- Offers template set ASS (hotels, coupons)
  offers_js/cms_ss2.js                   -- Offers template set SS2
  offers_js/external-splashoffer.js      -- Firefox link fix for external offers
  rules/rules_1.json                     -- DeclarativeNetRequest blocking rules
```
