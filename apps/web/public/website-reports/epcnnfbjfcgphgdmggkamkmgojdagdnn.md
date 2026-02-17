# Security Analysis Report: uBlock

## Extension Metadata
- **Extension ID**: epcnnfbjfcgphgdmggkamkmgojdagdnn
- **Name**: uBlock (NOT uBlock Origin)
- **Version**: 25.5.0
- **Users**: ~2,000,000
- **Manifest Version**: 3
- **Last Updated**: 2026-02-14

## Executive Summary

This security analysis examines uBlock (the controversial fork sold by the original developer), not to be confused with the reputable uBlock Origin. The extension is maintained by eyeo GmbH (makers of Adblock Plus) and includes integrated telemetry that collects user statistics and sends them to eyeo's servers.

**Risk Level**: **LOW**

While the extension implements telemetry and analytics systems, the data collection appears limited to non-invasive aggregate statistics (browser version, OS, extension install type) and does not exfiltrate browsing history, URLs, or personally identifiable information. The keylogging flag is a false positive related to user activity detection for CDP (Chrome DevTools Protocol) session management. The extension functions as a legitimate ad blocker using eyeo's Ad Filtering Engine (EWE).

## Vulnerability Details

### 1. Privacy Telemetry Collection
**Severity**: LOW
**Files**:
- `assets/worker/service-jJz2UCeQ.js` (compiled from `src/background/telemetry.js`)
- `assets/worker/service-jJz2UCeQ.js` (compiled from `src/background/utils/utils.js`)

**CWE**: CWE-359 (Exposure of Private Information)

**Description**:
The extension implements two separate telemetry systems that send usage data to remote servers:

1. **uBlock Stats Endpoint** (`https://ping.ublock.org/api/stats`):
   - Sends daily pings with extension version, browser info, OS details
   - Initial ping after 10 minutes, then every 24 hours
   - Generates and stores a unique user ID

2. **Eyeo Telemetry** (`https://ublock.telemetry.eyeo.com/topic/webextension_activeping/version/3`):
   - Part of eyeo's Ad Filtering Engine (EWE) SDK
   - Collects ML model performance metrics
   - Authenticated with bearer token: `p_N9gr9UbaNJ2GsJEsz16BWC3asXGCFz1H`

**Evidence from source code** (extracted from source maps):

```javascript
// From src/background/telemetry.js
export class Telemetry {
  constructor(name, version) {
    this.name = name;
    this.version = version;
    // ... browser fingerprinting ...
  }

  getStats(userId) {
    return {
      n: this.name,           // Extension name
      v: this.version,        // Version
      u: userId,              // Unique user ID
      f: this.browserFlavor,  // "F" (Firefox) or "E" (Chrome)
      o: this.operatingSystem,
      bv: this.browserVersion,
      ov: this.operatingSystemVersion,
      l: this.browserLanguage,
    };
  }

  async sendPing(userId) {
    const data = this.getStats(userId);
    if (this.browserName === "Chrome") {
      const info = await getManagementInfo();
      if (info && typeof info.installType === "string") {
        data["it"] = info.installType.charAt(0);  // Install type
      }
    }
    ping(data).then(response => {
      // ... handle survey actions ...
    });
  }

  async scheduleStatsEvent() {
    browser.alarms.create(STATS_ALARM, {
      delayInMinutes: 10,        // First ping after 10 minutes
      periodInMinutes: 60 * 24,  // Daily pings
    });
  }
}

// From src/background/utils/utils.js
export async function ping(data) {
  const url = "https://ping.ublock.org/api/stats";
  return fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json;charset=UTF-8",
    },
    body: JSON.stringify(data),
  });
}
```

**Eyeo EWE Telemetry Configuration**:
```javascript
const V4="https://ublock.telemetry.eyeo.com/topic/webextension_activeping/version/3";
const H4="p_N9gr9UbaNJ2GsJEsz16BWC3asXGCFz1H";  // Bearer token
let Kx = {url: V4, bearer: H4};

const W4 = Ea.start({
  name: K1,
  version: pf,
  bundledSubscriptions: $4.subscriptions,
  bundledSubscriptionsPath: "rules",
  telemetry: Kx
});

Ea.telemetry.setOptOut(!1);  // Telemetry opt-out set to FALSE
```

**Impact**: The telemetry collects device fingerprinting data (browser version, OS, language, install type) and associates it with a persistent user ID. While not as invasive as browsing history collection, this creates a tracking mechanism that users may not be aware of.

**Recommendation**: Users should be informed about telemetry collection. The extension should provide a clear opt-out mechanism in settings.

---

### 2. CDP Session Activity Monitoring
**Severity**: LOW
**Files**: `ewe-content.js` (compiled from `src/content/cdp-session.js`)

**CWE**: CWE-200 (Exposure of Sensitive Information)

**Description**:
The content script monitors user activity (scroll, click, keypress events) to detect if the browser tab is "active" for Chrome DevTools Protocol (CDP) session management. This triggers the `keylogging` flag but is **NOT actual keylogging**.

**Evidence**:
```javascript
// From ewe-content.js lines 3460-3470
let isActive = false;

function markActive() {
  isActive = true;
}

function notifyActive() {
  if (isActive) {
    ignoreNoConnectionError(
      browser.runtime.sendMessage({
        type: "ewe:cdp-session-active"
      })
    );
    isActive = false;
  }
  setTimeout(notifyActive, 1000);
}

function startNotifyActive() {
  scheduleCheckActive();
  document.addEventListener("scroll", markActive, true);
  document.addEventListener("click", markActive);
  document.addEventListener("keypress", markActive, true);  // ← Flag trigger
}
```

**Impact**: This is a **false positive**. The keypress listener only sets a boolean flag to indicate user activity; it does not capture key values, log keystrokes, or exfiltrate typed data. The message `"ewe:cdp-session-active"` is sent internally to the background script, not to external servers.

**Recommendation**: No action needed. This is legitimate functionality for managing browser debugging sessions.

---

### 3. Acceptable Ads Program Integration
**Severity**: LOW
**Files**: `subscriptions.json`, filter rule files

**CWE**: N/A (Business Practice, not a vulnerability)

**Description**:
The extension includes two filter subscriptions for "acceptable ads" by default:
- Subscription ID `0798B6A2-94A4-4ADF-89ED-BEC112FC4C7F`: "Allow nonintrusive advertising"
- Subscription ID `F12E0801-A00B-49DE-B1E3-52C9C4F90C8C`: "Allow nonintrusive advertising without third-party tracking"

These are downloaded from `https://easylist-downloads.adblockplus.org/exceptionrules.txt` and allow certain ads that meet eyeo's criteria. This is part of eyeo's business model where advertisers can pay to be whitelisted.

**Evidence from subscriptions.json**:
```json
{
  "id": "0798B6A2-94A4-4ADF-89ED-BEC112FC4C7F",
  "type": "allowing",
  "title": "Allow nonintrusive advertising",
  "homepage": "https://acceptableads.com/",
  "url": "https://easylist-downloads.adblockplus.org/v3/full/exceptionrules.txt"
}
```

**Impact**: Users install uBlock expecting full ad blocking but may unknowingly allow certain ads. This is a transparency issue rather than a security vulnerability.

**Recommendation**: Users who want complete ad blocking without acceptable ads should use uBlock Origin instead.

---

## False Positives

### 1. Keylogging (flagCategories: keylogging)
**Status**: FALSE POSITIVE

The `addEventListener("keypress", markActive, true)` listener in the CDP session manager only tracks **whether** a key was pressed (boolean flag), not **which** key or the typed content. No keystroke data is logged or transmitted.

### 2. Fetch Hooking (flagCategories: fetch_hooking)
**Status**: FALSE POSITIVE

The extension uses standard `fetch()` calls to download filter lists and send telemetry. There is no hooking/monkey-patching of the global `window.fetch` function to intercept other extensions' or websites' network requests.

### 3. Dynamic Function (flagCategories: dynamic_function)
**Status**: EXPECTED BEHAVIOR

The extension includes TensorFlow.js for ML-based ad detection (referenced in source: `github.com/tensorflow/tfjs`). WASM and dynamic code generation are part of TensorFlow.js's normal operation for running machine learning models in the browser.

### 4. Exfiltration Flows (ext-analyzer findings)
**Status**: LEGITIMATE FUNCTIONALITY

The two flagged exfiltration flows are:
1. `chrome.tabs.get → fetch(ping.ublock.org)` — Sending extension stats (legitimate telemetry)
2. `document.getElementById → fetch(www.w3.org)` — Likely false positive from parsing W3C namespace references in XML/SVG parsing code

---

## API Endpoints

The extension communicates with the following external endpoints:

### Telemetry & Analytics
- `https://ping.ublock.org/api/stats` — uBlock usage statistics (POST JSON)
- `https://ublock.telemetry.eyeo.com/topic/webextension_activeping/version/3` — eyeo EWE telemetry
- `https://notification.adblockplus.org/notification.json` — eyeo notifications system

### Filter List Updates
- `https://easylist-downloads.adblockplus.org/` — Base URL for all filter subscriptions
  - EasyList (ads)
  - EasyPrivacy (tracking)
  - Acceptable Ads exception rules
  - Regional filter lists (30+ languages)
  - Anti-circumvention filters

### Documentation & Support
- `https://ublock.org/` — Official uBlock website
- `https://support.ublock.org/` — Support site
- `https://github.com/` — GitHub repositories for filter lists
- `https://easylist.to/` — EasyList homepage

All filter downloads use HTTPS with v3 diff-based updates for bandwidth efficiency.

---

## Data Flow Summary

**User Activity Monitoring** (Content Script):
```
User interaction (scroll/click/keypress)
  ↓
markActive() sets isActive = true
  ↓
notifyActive() sends internal message
  ↓
runtime.sendMessage({type: "ewe:cdp-session-active"})
  ↓
Background script (local, not exfiltrated)
```

**Telemetry Flow**:
```
Extension installation
  ↓
10 minutes delay → First stats ping
  ↓
Generate unique userId (stored locally)
  ↓
Collect: browser version, OS, extension version, install type
  ↓
POST JSON to https://ping.ublock.org/api/stats
  ↓
Repeat every 24 hours
```

**Filter Updates**:
```
Extension startup
  ↓
Load bundled filter rulesets (30+ lists)
  ↓
Check for updates from easylist-downloads.adblockplus.org
  ↓
Download diffs (incremental updates)
  ↓
Apply declarativeNetRequest rules
  ↓
Block ads/trackers on web pages
```

---

## Manifest Analysis

**Key Permissions**:
- `declarativeNetRequest` / `declarativeNetRequestFeedback` — MV3 ad blocking via DNR rules
- `webRequest` / `webNavigation` — Monitoring network requests (read-only in MV3)
- `tabs` — Tab information access (for stats on install type, not URLs)
- `storage` / `unlimitedStorage` — Storing filter lists and user preferences
- `scripting` — Content script injection for element hiding
- `alarms` — Scheduling telemetry pings

**Host Permissions**: `*://*/*` (all URLs) — Required for ad blocking on all websites

**Content Scripts**:
- `ewe-content.js` injected at `document_start` on all HTTP/HTTPS pages
- Purpose: Element hiding, CDP session management, snippet injection

**Service Worker**: `assets/worker/service-jJz2UCeQ.js` (module type)
- Manages filter subscriptions, declarativeNetRequest rules, telemetry

**declarativeNetRequest**: 30 rulesets (regional filter lists, all disabled by default except user selections)

---

## Overall Risk Assessment

**Risk Level**: **LOW**

### Summary
uBlock (eyeo GmbH fork) is a functional ad blocker that implements privacy-invasive telemetry but does not engage in malicious data exfiltration. The key concerns are:

1. **Non-consensual telemetry**: Collects device fingerprinting data without prominent disclosure
2. **Acceptable ads business model**: Allows certain ads by default (transparency issue)
3. **eyeo ecosystem lock-in**: Uses eyeo's proprietary EWE engine and filter infrastructure

### Comparison to uBlock Origin
Users seeking privacy-focused ad blocking should use **uBlock Origin** (extension ID: `cjpalhdlnbpafiamejdnhcphjbkeiagm`), which:
- Has no telemetry
- Does not allow acceptable ads
- Is fully open-source and community-maintained
- Has a larger user base (10M+ vs 2M)

### Positive Findings
- No credential theft, malware, or malicious code injection
- No browsing history or URL collection
- TensorFlow.js ML models used for legitimate ad detection
- Telemetry is limited in scope (no PII beyond browser fingerprint)
- Uses standard MV3 declarativeNetRequest for blocking (not invasive webRequest)

### Recommendations
1. **For users**: Switch to uBlock Origin for privacy-first ad blocking
2. **For this extension**: Add clear telemetry opt-out in settings UI, disclose data collection in listing
3. **For Chrome Web Store**: Require disclosure of telemetry and acceptable ads program

---

## Tags
- `privacy:telemetry` — Sends device fingerprinting data to ublock.org and eyeo.com
- `privacy:user_tracking` — Persistent user ID for analytics
- `behavior:acceptable_ads` — Whitelist-based business model

## Vulnerability Count
- **Critical**: 0
- **High**: 0
- **Medium**: 0
- **Low**: 1 (Privacy telemetry without clear user consent)

---

**Analysis Date**: 2026-02-14
**Analyzed By**: Claude Opus 4.6 Security Analyst
**Deobfuscation**: jsbeautifier + source map extraction
**Static Analysis**: ext-analyzer (risk_score: 70), Python regex scanner
