# Vulnerability Report: FasterWeb

## Metadata
- **Extension ID**: nmgpnfccjfjhdenioncabecepjcmdnjg
- **Extension Name**: FasterWeb
- **Version**: 26.1.31
- **Users**: ~0
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

FasterWeb is a browser performance extension that claims to "Browse the web faster" through link prefetching functionality. However, static analysis reveals the extension collects and transmits extensive user data to remote servers (api.browsecraft.com) including tab information, chrome.storage data, account identifiers, email addresses, browser metadata, and behavioral analytics. The extension implements a sophisticated event batching system that aggregates user activity and sends it to external servers every 5 minutes. While the extension provides legitimate instant page loading functionality via the instantpage.js content script, the extensive data collection goes far beyond what is necessary for this stated purpose and lacks transparency.

The extension has broad host permissions (`*://*/*`) and runs on all websites, giving it access to all browsing activity. The static analyzer detected 4 high-severity exfiltration flows where sensitive Chrome APIs (chrome.storage.local.get, chrome.storage.sync.get, chrome.tabs.query, chrome.tabs.get) feed data into network calls to api.browsecraft.com.

## Vulnerability Details

### 1. HIGH: Extensive User Data Exfiltration Without Clear Disclosure

**Severity**: HIGH
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension implements a comprehensive telemetry system that collects and transmits extensive user data to api.browsecraft.com, including:

- Tab information (URLs, titles, active tabs via chrome.tabs.query and chrome.tabs.get)
- Chrome storage data (both local and sync storage via chrome.storage.local.get and chrome.storage.sync.get)
- User account information (accountId, email addresses from identity storage)
- Installation tracking (installId, installTime, installVersion, updateTime)
- Browser metadata (browser type, version, OS, platform, language, display size)
- UTM parameters and install type
- Extension theme preferences
- Event batching with timestamps

**Evidence**:

```javascript
// Lines 1225-1234: Event payload construction with user ID
const O = async (e, t = {}) => {
  const r = await (0, n.ip)("identity"),
    o = f().get(r, ["account", "accountId"]);
  return {
    eventName: e,
    extraParams: t,
    time: Date.now(),
    eventId: ++w,
    userId: o
  }
}
```

```javascript
// Lines 1235-1263: Batch event transmission to api.browsecraft.com
const M = async () => {
  const e = await (0, n.ip)("settings", ["theme"]),
    t = await (0, n.ip)("extension"),
    r = f().get(t, ["installId"]);
  if (!r) return !1;
  let o = (await (0, n.ip)("events", ["batch"]) || []).splice(0, 1e3);
  if (0 === o.length) return !1;
  const a = await (0, n.ip)("identity"),
    i = f().get(a, ["account", "accountId"]),
    s = f().get(t, ["utm"], {}),
    l = await chrome.management.getSelf();
  o = o.map((n => y(y(y({}, n), {}, {
    installId: r
  }, s), {}, {
    browser: f().get(t, ["browser"]),
    platform: f().get(t, ["platform"]),
    displaySize: f().get(t, ["displaySize"]),
    browserLang: f().get(t, ["browserLang"]),
    currentVersion: f().get(t, ["currentVersion"]),
    browserVersion: f().get(t, ["browserVersion"]),
    email: f().get(a, ["userInfo", i, "email"]),
    theme: e || void 0,
    extId: f().get(l, ["id"], null) || u.A.getId(),
    installType: f().get(l, ["installType"])
  })));
  const g = await c("/api/v1/events/batch", {
    batch: o,
    isProd: d.O_
  });
```

```javascript
// Lines 867-869: API endpoint configuration
const d = {
  api: {
    url: r(78).O_ ? "https://api.browsecraft.com" : "https://ai-dev.manganum.app"
  },
```

**Verdict**:
This represents HIGH severity data collection that extends far beyond the extension's stated purpose of faster browsing. The collection of email addresses, account IDs, tab data, and storage contents constitutes significant privacy exposure. While event batching is currently disabled (`const b = !1` on line 1216), the infrastructure is fully implemented and could be enabled via remote configuration.

### 2. HIGH: Chrome Storage Data Access and Transmission

**Severity**: HIGH
**Files**: background.js
**CWE**: CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor)

**Description**:
The extension reads both chrome.storage.local and chrome.storage.sync data and includes it in network requests to api.browsecraft.com. The static analyzer identified exfiltration flows from chrome.storage.local.get and chrome.storage.sync.get feeding into fetch() calls to the remote API.

**Evidence**:

From ext-analyzer output:
```
EXFILTRATION (4 flows):
  [HIGH] chrome.storage.local.get → fetch(api.browsecraft.com)    background.js
  [HIGH] chrome.storage.sync.get → fetch(api.browsecraft.com)    background.js
  [HIGH] chrome.tabs.query → fetch(api.browsecraft.com)    background.js
  [HIGH] chrome.tabs.get → fetch(api.browsecraft.com)    background.js
```

Storage access code (lines 263-342):
```javascript
chrome.storage.local.get((r => { /* ... */ }))
chrome.storage.local.get([e], (n => { /* ... */ }))
chrome.storage.sync.get((r => { /* ... */ }))
chrome.storage.sync.get([e], (n => { /* ... */ }))
```

**Verdict**:
Chrome storage can contain sensitive user data from this or other extensions. Transmitting this data to remote servers represents a significant privacy concern, especially given the lack of clear disclosure about what specific data is being collected and transmitted.

### 3. MEDIUM: Tab Data Collection and Transmission

**Severity**: MEDIUM
**Files**: background.js
**CWE**: CWE-359 (Exposure of Private Personal Information to an Unauthorized Actor)

**Description**:
The extension monitors and collects tab information including active tabs, tab URLs, and tab metadata through chrome.tabs.query and chrome.tabs.get APIs. This data is incorporated into the event tracking system and transmitted to external servers.

**Evidence**:

```javascript
// Lines 408-442: Tab API wrappers
static async getActiveTabs() {
  return new Promise((e => {
    chrome.tabs ? chrome.tabs.query({
      active: !0
    }, e) : n.A.sendBackgroundMessage("api-tabs-active", {}, e)
  }))
}

static async getActive(e = !0) {
  return new Promise((t => {
    chrome.tabs ? chrome.tabs.query({
      active: !0,
      currentWindow: e
    }, (e => {
      t(e.length ? e[0] : null)
    })) : n.A.sendBackgroundMessage("api-tab-active", {}, t)
  }))
}

static async getTab(e) {
  return new Promise((t => {
    if (!e) return t(null);
    chrome.tabs ? chrome.tabs.get(e, (e => {
      if (chrome.runtime.lastError) return t(null);
      t(e)
    })) : g.sendBackgroundMessage("api-tab", {
      tabId: e
    }, t)
  }))
}
```

**Verdict**:
While tab monitoring can be legitimate for browser performance tools, the combination with the extensive data collection system raises privacy concerns. Users' browsing patterns and active tabs could be tracked and transmitted without clear consent.

## False Positives Analysis

1. **Instant Page Prefetching**: The instantpage.js content script (line prefetching on hover/touch) is legitimate functionality that matches the extension's stated purpose of faster browsing. This is not suspicious.

2. **Webpack Bundling**: The code shows typical webpack module loading patterns. While the code is minified, it's not obfuscated in a malicious sense - it's standard build tooling.

3. **Message Passing**: The extension uses chrome.runtime message passing for internal communication between content scripts and background service worker, which is standard practice.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| api.browsecraft.com | Primary telemetry endpoint | User events, account IDs, email, tabs, storage data, browser metadata, install tracking | HIGH |
| ai-dev.manganum.app | Development/testing endpoint | Same as production endpoint | HIGH |
| /api/v1/events/batch | Event batching endpoint | Batches of up to 1000 events with full user context | HIGH |

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While FasterWeb provides legitimate instant page loading functionality through link prefetching, the extension implements extensive data collection infrastructure that goes far beyond what is necessary for its stated purpose. The extension collects and is prepared to transmit:

1. User account identifiers and email addresses
2. Chrome storage contents (both local and sync)
3. Tab information and browsing activity
4. Detailed browser fingerprinting data
5. Installation tracking and analytics

The static analyzer detected 4 high-severity exfiltration flows showing direct paths from sensitive Chrome APIs to network calls. Although the event batching system appears to be currently disabled (`const b = !1`), the complete infrastructure exists and could be activated remotely or in future versions.

The primary concerns are:
- Lack of transparency about the extent of data collection
- Collection of personally identifiable information (email, account IDs)
- Access to storage data that may contain sensitive information
- Broad host permissions allowing monitoring on all websites
- Event batching system ready for deployment despite being currently disabled

This extension exhibits patterns typical of undisclosed analytics/telemetry collection, warranting a HIGH risk classification. Users installing this extension for faster page loading would not reasonably expect the level of data collection implemented in the codebase.

**Recommendation**: Users should be aware that this extension contains infrastructure for extensive telemetry collection beyond typical performance monitoring. The extension should clearly disclose all data collection practices in its privacy policy and store listing.
