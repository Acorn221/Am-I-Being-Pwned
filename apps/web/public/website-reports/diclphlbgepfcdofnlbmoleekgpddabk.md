# AVG Secure VPN (diclphlbgepfcdofnlbmoleekgpddabk) - Security Analysis

## Executive Summary

AVG Secure VPN is a **legitimate** browser extension published by AVG (Gen Digital / NortonLifeLock). It serves as a companion extension for the AVG Secure VPN desktop application, communicating with the native VPN client via Chrome Native Messaging Host (NMH). The extension also bundles an ad blocker powered by the eyeo Web Extensions (EWE) engine -- the same core used by Adblock Plus. The codebase is large (~63K lines across 3 JS files) but consists almost entirely of well-known, attributable open-source components: React 19, Adblock Plus EWE, webextension-polyfill, i18next, and a standard VPN control layer.

All triage flags that triggered the SUSPECT classification are **false positives** attributable to the bundled Adblock Plus/EWE library and standard React/i18next patterns.

**Risk Level: CLEAN**

---

## Flag Verdicts Table

| Flag | Verdict | Explanation |
|------|---------|-------------|
| Extension enumeration/killing | NOT PRESENT | No use of `chrome.management` API. The `management.setEnabled`/`uninstallSelf` references are part of the webextension-polyfill API metadata object (lines 12931-12935), not actual code calls. |
| Credential harvesting | NOT PRESENT | No form interception, no password field monitoring. |
| Keylogging | NOT PRESENT | No keydown/keyup/keypress listeners anywhere. |
| DOM scraping | FALSE POSITIVE | `querySelector`/`querySelectorAll` usage is entirely within EWE's element hiding emulation engine (Adblock Plus cosmetic filtering). |
| XHR/fetch monkey-patching | FALSE POSITIVE | `window.XMLHttpRequest = class extends qt { ... }` at line 38665 is EWE's `replace-xhr-response` ad-blocking snippet. This is a well-documented Adblock Plus scriptlet. Similarly, the `replace-fetch-response` and `strip-fetch-query-parameter` snippets are standard ABP tools. |
| eval / dynamic code execution | FALSE POSITIVE | `new Function("exports", "environment", isolatedLib)` at line 11827 is EWE's snippet isolation mechanism for loading ad-blocking scriptlets. The `injectSnippetsInMainContext` function (line 11870) creates script elements for ABP snippets -- standard ABP architecture. |
| Encrypted comms | NOT PRESENT | `crypto.subtle.verify` at line 11404 is used for ABP subscription signature verification, not C2 communication. |
| Cookie theft | FALSE POSITIVE | `cookie-remover` at line 37925 is an ABP content-blocking snippet for removing tracking cookies, not exfiltration. |
| Ad injection | NOT PRESENT | The extension **blocks** ads via EWE/ABP, it does not inject them. |
| Fingerprinting | NOT PRESENT | `navigator.userAgent` usage (lines 26-46, 144) is solely for browser detection to set icon paths and format user-agent strings for NMH communication. |
| Remote code loading | NOT PRESENT | No `importScripts`, no remote script fetching. ABP filter lists are downloaded from `easylist-downloads.adblockplus.org` but these are declarative text rules, not executable code. |
| C2 patterns | NOT PRESENT | The only external communication is: (1) NMH to local AVG VPN desktop app, (2) Google Analytics telemetry, (3) ABP filter list downloads, (4) Site Director URL for AVG. |
| innerHTML / DOM manipulation | FALSE POSITIVE | All `innerHTML`/`outerHTML`/`insertAdjacentHTML` references are within EWE's snippet engine and XPath error messages. Line 37429 shows ABP's DOM mutation monitoring for ad-blocking. |

---

## Detailed Findings

### 1. Architecture Overview

The extension has three JS files:

- **`background.js`** (39,294 lines): Service worker containing:
  - VPN control layer (NMH client, data provider, UI handlers)
  - eyeo Web Extensions (EWE) / Adblock Plus engine
  - Google Analytics telemetry
  - Popup event relay

- **`ewe-content.js`** (3,986 lines): Content script -- purely the EWE element hiding emulation engine from Adblock Plus (GPL-licensed, eyeo GmbH copyright headers throughout).

- **`assets/popup-JYFdlAoV.js`** (20,482 lines): React 19 popup UI with:
  - VPN connection controls (connect, disconnect, pause, resume, server selection)
  - Ad blocker toggle
  - i18next for localization
  - zustand-style state management

### 2. Native Messaging Host (NMH) Communication

The extension communicates with the local AVG VPN desktop application via `chrome.runtime.connectNative("com.avg.vpn")` (line 318). Messages use a structured protocol:

```javascript
// Line 335-344
const message = {
  header: {
    apiVersion: this.apiVersion,  // "1", "2", or "3"
    id: messageId,
    type: "request",
    action: actionName,
    userAgent: "Chrome/xxx/AVG Secure VPN/2.3.0.852"
  },
  data: payload
};
```

Commands sent to the native app (enum `za`, line 230):
- Connect, ConnectToOptimal, Disconnect, Pause, Resume
- GetState, GetProductInfo, GetPublicIp, GetRecentGateways
- GetApiVersion, GetOptimalGateway, OpenApp, SetLanguage, ShowNag

This is standard companion-extension architecture -- the extension is a thin UI layer for the desktop VPN app.

### 3. Google Analytics Telemetry

The extension sends telemetry to Google Analytics Measurement Protocol (lines 38906-38953):

```
Endpoint: https://www.google-analytics.com/mp/collect
measurement_id: G-6ETLM81MB0
api_key: _1GC-DNnS5SOOrDt2vI6eQ
```

Data collected (lines 39004-39012):
- `brandName`: "AVG"
- `browserName`: Browser type (Chrome, Firefox, etc.)
- `extensionVersion`: Manifest version string
- `extensionId`: Chrome extension ID
- `os`: Operating system
- `productVersion`: Native VPN app version

Telemetry events:
- `browser_ext_cta`: CTA button interactions in the popup
- `heartbeat`: Every 24 hours, sends license status, ad blocker state, and acceptable ads state
- `connect_failed` / `disconnect_failed`: VPN connection errors

The telemetry is opt-in via a disclaimer toggle (`Rl.telemetry = "disclaimer"`, line 220). A `declarativeNetRequest` rule (ID 100001) is created to allow GA requests from the extension origin (line 38929) -- this is necessary because the bundled ad blocker would otherwise block the extension's own analytics calls.

### 4. Adblock Plus / EWE Engine

The bulk of the background.js (roughly lines 8300-38775) is the eyeo Web Extensions (EWE) engine -- the commercial SDK version of Adblock Plus. Key indicators:

- Copyright headers: "Copyright (C) 2006-present eyeo GmbH" (visible in ewe-content.js)
- Filter subscriptions: EasyList, ABP filters, EasyPrivacy, etc. (line 17152)
- Snippet names match known ABP scriptlets: `abort-on-property-read`, `json-prune`, `replace-xhr-response`, `cookie-remover`, `hide-if-shadow-contains`, etc. (lines 38753-38774)
- Subscription URLs all point to `easylist-downloads.adblockplus.org`

The ad blocker is toggled via NMH notifications and license status (lines 38839-38903).

### 5. Script Injection (ABP Snippets)

The `injectSnippetsInMainContext` function (line 11870) and `chrome.scripting.executeScript` calls (lines 13655-13731) are part of ABP's snippet injection mechanism. Snippets are cosmetic/behavioral filters that run in the page context to counter ad-reinsertion scripts. This is standard ABP functionality, not malicious code injection.

### 6. Permissions Assessment

| Permission | Usage | Justified? |
|------------|-------|------------|
| `tabs` | Icon updates based on VPN state | Yes |
| `webNavigation` | ABP: frame tracking for ad blocking | Yes |
| `storage` | VPN state caching, ABP filter storage | Yes |
| `unlimitedStorage` | ABP filter lists can be large | Yes |
| `nativeMessaging` | Communication with AVG VPN desktop app | Yes |
| `declarativeNetRequest` | ABP: network-level ad blocking rules | Yes |
| `scripting` | ABP: snippet injection for cosmetic filtering | Yes |
| `alarms` | NMH polling (1 min), telemetry batching (1 min), heartbeat (24 hrs) | Yes |
| `activeTab` | Not actively used in code, likely for future features | Marginal |
| `webRequest` | ABP: monitoring request headers for ad blocking | Yes |
| `<all_urls>` (host) | ABP: ad blocking works on all websites | Yes |

All permissions are justified by the combination of VPN companion + ad blocker functionality.

---

## Network Map

| Endpoint | Purpose | Triggered By |
|----------|---------|-------------|
| `chrome.runtime.connectNative("com.avg.vpn")` | Local NMH to AVG VPN desktop app | Extension startup, polling every 1 min |
| `https://www.google-analytics.com/mp/collect` | Telemetry (GA4 Measurement Protocol) | CTA clicks, heartbeat (24h), errors |
| `https://easylist-downloads.adblockplus.org/v3/full/*.txt` | ABP filter list downloads | Ad blocker startup, periodic updates |
| `https://sitedirector.avg.com/932743328` | AVG site director (likely update/config) | Referenced in config but not actively called in analyzed code |

---

## What It Does NOT Do

- Does NOT enumerate or disable other extensions
- Does NOT harvest credentials, passwords, or form data
- Does NOT log keystrokes
- Does NOT scrape page content or DOM data for exfiltration
- Does NOT inject advertisements
- Does NOT modify search results
- Does NOT intercept or exfiltrate browsing history
- Does NOT steal cookies (the `cookie-remover` is an ABP snippet that *removes* tracking cookies)
- Does NOT use eval() for dynamic remote code execution
- Does NOT establish C2 channels
- Does NOT fingerprint users beyond basic browser/OS identification for telemetry
- Does NOT proxy user traffic through third-party servers (VPN tunneling is handled by the native desktop app)
- Does NOT bypass its own VPN for analytics (GA telemetry is sent directly but only collects non-PII metadata)

---

## Final Verdict

**CLEAN** -- Reclassify from SUSPECT to CLEAN.

This is a legitimate companion extension for AVG Secure VPN (Gen Digital / NortonLifeLock). The extension consists of:

1. A thin VPN control UI (React 19) that communicates with the local desktop VPN client via Native Messaging
2. A bundled ad blocker powered by eyeo Web Extensions (Adblock Plus SDK)
3. Standard Google Analytics telemetry with opt-in consent

All triage flags are false positives caused by:
- **EWE/ABP scriptlets**: XHR proxying (`replace-xhr-response`), cookie manipulation (`cookie-remover`), DOM element hiding, script injection -- all standard ad-blocking techniques
- **React 19 runtime**: innerHTML usage for component rendering
- **webextension-polyfill**: API metadata listing `management.setEnabled`, `management.uninstallSelf` etc. as method signatures, not actual invocations
- **i18next**: fetch/XHR polyfill for loading localization files

The codebase is well-structured, uses standard open-source libraries, and shows no evidence of malicious behavior. The low user count (~521) is likely because this is a companion extension that requires the paid AVG VPN desktop application to function.
