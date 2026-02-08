# AVG Secure VPN - Security Analysis

**Extension ID:** diclphlbgepfcdofnlbmoleekgpddabk
**Extension Name:** AVG Secure VPN
**Version:** 2.3.0.852
**User Count:** ~0
**Analysis Date:** 2026-02-08
**Overall Risk Level:** CLEAN

---

## Executive Summary

AVG Secure VPN is a **legitimate** browser extension published by AVG (Gen Digital / NortonLifeLock). It serves as a companion extension for the AVG Secure VPN desktop application, communicating with the native VPN client via Chrome Native Messaging Host (NMH). The extension also bundles an ad blocker powered by the eyeo Web Extensions (EWE) engine -- the same core used by Adblock Plus.

The codebase is large (~43K lines across main files) but consists almost entirely of well-known, attributable open-source components:
- React 19 (popup UI)
- Adblock Plus / eyeo Web Extensions (ad blocker)
- webextension-polyfill (cross-browser compatibility)
- i18next (localization)
- Standard VPN control layer

**All triage flags are false positives** attributable to the bundled Adblock Plus/EWE library and standard React patterns. The extension shows no evidence of malicious behavior, data exfiltration, or security vulnerabilities.

**Final Verdict: CLEAN**

---

## Metadata

| Field | Value |
|-------|-------|
| Extension ID | diclphlbgepfcdofnlbmoleekgpddabk |
| Name | AVG Secure VPN |
| Version | 2.3.0.852 |
| Manifest Version | 3 |
| Publisher | AVG Technologies (Gen Digital Inc.) |
| User Count | ~0 (likely requires paid desktop VPN app) |
| Code Size | background.js: 39,294 lines<br>ewe-content.js: 3,986 lines<br>popup.js: 20,482 lines |

---

## Permissions Analysis

### Declared Permissions

| Permission | Usage | Justified? | Notes |
|------------|-------|------------|-------|
| `tabs` | Icon updates based on VPN connection state | ✅ Yes | Line 532-553: `chrome.action.setIcon` calls to update extension icon when VPN connects/disconnects |
| `webNavigation` | ABP frame tracking for ad blocking | ✅ Yes | Used by eyeo Web Extensions for monitoring navigation events to apply filters |
| `storage` | VPN state caching, ABP filter storage | ✅ Yes | Lines 250, 459: `chrome.storage.local` for caching NMH responses and ABP preferences |
| `unlimitedStorage` | ABP filter lists (large datasets) | ✅ Yes | EasyList subscriptions can exceed 5MB quota |
| `nativeMessaging` | Communication with AVG VPN desktop app | ✅ Yes | Line 318: `chrome.runtime.connectNative("com.avg.vpn")` |
| `declarativeNetRequest` | Network-level ad blocking rules | ✅ Yes | Lines 14196-14577: ABP uses DNR for efficient network filtering |
| `scripting` | ABP snippet injection for cosmetic filtering | ✅ Yes | Lines 13655-13731: `chrome.scripting.executeScript` for ABP scriptlets |
| `alarms` | NMH polling, telemetry batching, heartbeat | ✅ Yes | 1-minute polling for VPN state, 24-hour telemetry heartbeat |
| `activeTab` | Not actively used | ⚠️ Marginal | No evidence of usage in code |
| `webRequest` | Monitor request headers for ABP | ✅ Yes | ABP: Header analysis for ad detection |
| `<all_urls>` | Ad blocking on all websites | ✅ Yes | ABP requires broad host permissions to inject filters |

### Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Assessment:** ✅ Secure - No unsafe-eval, no remote script loading, self-only sources.

---

## Vulnerability Details

### VERDICT: No Critical, High, or Medium Vulnerabilities Found

All initially flagged patterns are **false positives** from legitimate functionality:

---

## False Positive Analysis

| Flag | Location | Verdict | Explanation |
|------|----------|---------|-------------|
| **Extension enumeration/killing** | N/A | ❌ NOT PRESENT | No use of `chrome.management` API. References to `management.setEnabled`/`uninstallSelf` at lines 12931-12935 are webextension-polyfill API metadata, not actual calls. |
| **Credential harvesting** | N/A | ❌ NOT PRESENT | No form interception, no password field monitoring anywhere in codebase. |
| **Keylogging** | popup.js:18273, 19499 | ✅ FALSE POSITIVE | `addEventListener("keydown")` is for escape key handling in modal dialogs (Floating UI library). No keystroke logging or data collection. |
| **DOM scraping** | ewe-content.js:3568 | ✅ FALSE POSITIVE | `document.querySelector(selector)` is EWE's element hiding emulation engine (Adblock Plus cosmetic filtering). Lines 3563-3591 show ABP tracing hidden elements, not data exfiltration. |
| **XHR/fetch monkey-patching** | background.js:38665 | ✅ FALSE POSITIVE | `window.XMLHttpRequest = class extends qt` is EWE's `replace-xhr-response` ABP snippet. Well-documented ad-blocking scriptlet for intercepting ad network responses. Similarly, `replace-fetch-response` and `strip-fetch-query-parameter` are standard ABP tools. |
| **eval() / dynamic code execution** | background.js:11827, 17173 | ✅ FALSE POSITIVE | Line 11827: `new Function("exports", "environment", isolatedLib)` is EWE's snippet isolation mechanism for loading ABP scriptlets in sandboxed contexts. Line 17173: Fallback for detecting global scope (`this \|\| new Function("return this")()`). Standard ABP architecture. |
| **Encrypted comms** | background.js:11404 | ✅ FALSE POSITIVE | `crypto.subtle.verify` is used for ABP subscription signature verification (RSA public key validation), not C2 communication. Public key at line 283: `MIIBIjANBgkqhkiG9w0BA...` (AVG's manifest key). |
| **Cookie theft** | background.js:37925 | ✅ FALSE POSITIVE | `cookie-remover` at line 37925 is an ABP content-blocking snippet for removing tracking cookies, not exfiltration. |
| **Ad injection** | N/A | ❌ NOT PRESENT | Extension **blocks** ads via EWE/ABP. No ad insertion, no coupon injection, no search hijacking. |
| **Fingerprinting** | background.js:26-46, 144 | ✅ FALSE POSITIVE | `navigator.userAgent` is solely for browser detection to set icon paths and format user-agent strings for NMH communication (line 341). No canvas fingerprinting, no WebGL probing. |
| **Remote code loading** | N/A | ❌ NOT PRESENT | No `importScripts`, no remote script fetching. ABP filter lists (EasyList) are downloaded from `easylist-downloads.adblockplus.org` but these are declarative text rules (lines 16581-16585), not executable code. |
| **C2 patterns** | N/A | ❌ NOT PRESENT | Only external communication: (1) Local NMH to desktop app, (2) Google Analytics telemetry, (3) ABP filter downloads, (4) AVG site director URL (config only). |
| **innerHTML / DOM manipulation** | ewe-content.js:various | ✅ FALSE POSITIVE | All DOM manipulation is within EWE's snippet engine for cosmetic filtering. No malicious script injection. |

---

## Architecture Overview

### 1. Native Messaging Host (NMH) Communication

The extension is a **thin UI layer** for the AVG VPN desktop application. Communication via:

```javascript
// Line 318
chrome.runtime.connectNative("com.avg.vpn")
```

**Message Protocol** (lines 335-344):
```javascript
{
  header: {
    apiVersion: "3",  // Versions: 1, 2, 3
    id: messageId,
    type: "request",
    action: "Connect",
    userAgent: "Chrome/xxx/AVG Secure VPN/2.3.0.852"
  },
  data: { gatewayId: "us-nyc" }
}
```

**Commands** (enum `za`, line 230):
- `Connect`, `ConnectToOptimal`, `Disconnect`, `Pause`, `Resume`
- `GetState`, `GetProductInfo`, `GetPublicIp`, `GetRecentGateways`
- `GetApiVersion`, `GetOptimalGateway`, `OpenApp`, `SetLanguage`, `ShowNag`

**Assessment:** Standard companion extension architecture. No evidence of tampering with native app communication.

---

### 2. Adblock Plus / eyeo Web Extensions (EWE)

Lines 8300-38775 of background.js contain the EWE engine:

**Evidence:**
- Copyright headers: "Copyright (C) 2006-present eyeo GmbH" (ewe-content.js)
- Filter subscriptions: EasyList, ABP filters (line 17152)
- Snippet names: `abort-on-property-read`, `json-prune`, `replace-xhr-response`, `cookie-remover` (lines 38753-38774)
- Subscription URLs: `https://easylist-downloads.adblockplus.org/`

**Acceptable Ads:** Lines 16828-16835 define URLs for AA lists:
- Standard AA: `exceptionrules.txt`
- Privacy-friendly AA: `exceptionrules-privacy-friendly.txt`

**Verdict:** Legitimate ABP integration. No ad injection, no filter tampering.

---

### 3. Google Analytics Telemetry

Lines 38906-38953 implement GA4 Measurement Protocol telemetry:

**Endpoint:** `https://www.google-analytics.com/mp/collect`
**Measurement ID:** `G-6ETLM81MB0`
**API Key:** `_1GC-DNnS5SOOrDt2vI6eQ`

**Data Collected** (lines 39004-39012):
- `brandName`: "AVG"
- `browserName`: Browser type (Chrome, Firefox, etc.)
- `extensionVersion`: "2.3.0.852"
- `extensionId`: Chrome extension ID
- `os`: Operating system
- `productVersion`: Native VPN app version

**Events:**
- `browser_ext_cta`: CTA button clicks
- `heartbeat`: Every 24 hours, sends license status + ad blocker state
- `connect_failed` / `disconnect_failed`: VPN errors

**Privacy Assessment:**
- Telemetry is **opt-in** via disclaimer toggle (`Rl.telemetry = "disclaimer"`, line 220)
- No PII, no browsing history, no page content
- Standard GA4 non-invasive telemetry

**Verdict:** ✅ Acceptable telemetry. No privacy violations.

---

### 4. Script Injection (ABP Snippets)

Lines 11870, 13655-13731: `chrome.scripting.executeScript` for ABP snippet injection.

**Example Snippets:**
- `abort-on-property-read`: Prevents ad scripts from detecting ad blockers
- `json-prune`: Removes tracking fields from JSON responses
- `replace-xhr-response`: Modifies XHR responses to remove ads
- `cookie-remover`: Deletes tracking cookies

**Verdict:** Standard ABP functionality. All snippets are documented ABP scriptlets, not malicious code injection.

---

## Network Communication Map

| Endpoint | Purpose | Triggered By | Data Sent | Assessment |
|----------|---------|-------------|-----------|------------|
| `chrome.runtime.connectNative("com.avg.vpn")` | Local NMH to AVG VPN desktop app | Extension startup, 1-min polling | VPN commands, state queries | ✅ Local only |
| `https://www.google-analytics.com/mp/collect` | GA4 telemetry | CTA clicks, 24h heartbeat, errors | Browser version, OS, extension version, license status | ✅ Opt-in, non-PII |
| `https://easylist-downloads.adblockplus.org/v3/full/*.txt` | ABP filter list downloads | Ad blocker startup, periodic updates | None (GET requests) | ✅ Standard ABP |
| `https://sitedirector.avg.com/932743328` | AVG site director (config/update endpoint) | Referenced in config (line 279) | Not actively called in analyzed code | ✅ Config only |

**Verdict:** No suspicious endpoints, no data exfiltration, no C2 channels.

---

## Data Flow Summary

### Data Collected:
1. **VPN state** (local desktop app → extension): Connection status, gateway list, license info, public IP
2. **Telemetry** (extension → Google Analytics): Browser version, OS, extension version, usage stats (opt-in)
3. **ABP preferences** (local storage): Ad blocker on/off, acceptable ads on/off

### Data Transmission:
- **Local NMH:** VPN state queries/commands to `com.avg.vpn` (local desktop app)
- **Google Analytics:** Non-PII telemetry (opt-in)
- **ABP filter updates:** EasyList downloads (read-only)

### Data Stored:
- `chrome.storage.local`: VPN state cache, ABP preferences, telemetry disclaimer acceptance
- No IndexedDB usage
- No cookies set by extension

**Verdict:** No sensitive data collection, no exfiltration, no persistent tracking beyond opt-in telemetry.

---

## What It Does NOT Do

✅ Does NOT enumerate or disable other extensions
✅ Does NOT harvest credentials, passwords, or form data
✅ Does NOT log keystrokes
✅ Does NOT scrape page content or DOM data for exfiltration
✅ Does NOT inject advertisements
✅ Does NOT modify search results
✅ Does NOT intercept or exfiltrate browsing history
✅ Does NOT steal cookies (cookie-remover is for blocking trackers)
✅ Does NOT use eval() for dynamic remote code execution
✅ Does NOT establish C2 channels
✅ Does NOT fingerprint users beyond basic browser/OS identification
✅ Does NOT proxy user traffic through third-party servers (VPN handled by native app)
✅ Does NOT bypass its own VPN for analytics

---

## API Endpoints Summary

| Endpoint | Type | Purpose |
|----------|------|---------|
| `chrome.runtime.connectNative` | Local NMH | AVG VPN desktop app communication |
| `https://www.google-analytics.com/mp/collect` | Telemetry | GA4 Measurement Protocol (opt-in) |
| `https://easylist-downloads.adblockplus.org/` | ABP Filters | Filter list downloads |
| `https://sitedirector.avg.com/932743328` | Config | AVG site director (not actively called) |

---

## Overall Risk Assessment

### Risk Level: **CLEAN**

### Rationale:

1. **Legitimate Publisher:** AVG Technologies (Gen Digital Inc.), a well-known security vendor
2. **Standard Architecture:** Companion extension for desktop VPN app using Native Messaging Host
3. **Attributable Code:** 95%+ of codebase is identifiable open-source (React 19, ABP/EWE, webextension-polyfill, i18next)
4. **No Malicious Patterns:** Zero evidence of data exfiltration, credential harvesting, ad injection, or C2 communication
5. **All Flags are False Positives:** Every triage flag is attributable to legitimate ABP ad-blocking techniques or standard React UI patterns
6. **Privacy-Respecting:** Telemetry is opt-in, non-invasive, and collects only non-PII metadata
7. **Secure CSP:** No unsafe-eval, no remote script loading

### Justification for Low User Count:

~0 users is consistent with a companion extension that requires the **paid AVG VPN desktop application** to function. Users would install this extension only after purchasing AVG VPN.

### Recommendation:

**Reclassify from SUSPECT to CLEAN.** This is a legitimate, well-engineered companion extension from a reputable security vendor. No security concerns, no privacy violations, no malicious behavior.

---

## Changelog

- **2026-02-08:** Initial comprehensive security analysis completed. Verdict: CLEAN.
