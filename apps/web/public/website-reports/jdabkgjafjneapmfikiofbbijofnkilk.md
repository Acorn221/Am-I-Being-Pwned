# Vulnerability Report: Adblock Fortress

## Metadata
- **Extension ID**: jdabkgjafjneapmfikiofbbijofnkilk
- **Extension Name**: Adblock Fortress
- **Version**: 2.0.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Adblock Fortress is an ad-blocking extension that claims to "strip away promotional content across multiple sources." While the extension does perform legitimate ad-blocking functionality using declarativeNetRequest rules, it exhibits concerning privacy practices that are not adequately disclosed to users. The extension implements a remote configuration system that fetches dynamic blocking rules from addefenderplus.com while transmitting persistent user identifiers with every request. This behavior constitutes undisclosed data collection, as the Chrome Web Store listing does not mention this remote communication or user tracking. The extension generates and stores a unique user ID (UID) that is sent as a URL parameter ("rpsps") to the remote server on installation and with all subsequent configuration update requests.

The extension's behavior is particularly concerning because: (1) it installs silently without user consent for remote tracking, (2) it generates persistent identifiers that can track users across sessions, (3) it beacons to the remote server on installation, hourly updates, and uninstallation, and (4) these practices are not disclosed in the extension's privacy policy or listing description. While the ad-blocking functionality itself appears legitimate, the undisclosed user tracking elevates this to a HIGH risk classification.

## Vulnerability Details

### 1. HIGH: Undisclosed User Tracking with Persistent Identifiers

**Severity**: HIGH
**Files**: service_worker.js, updater.js, net_updater.js
**CWE**: CWE-359 (Exposure of Private Information), CWE-201 (Information Exposure Through Sent Data)

**Description**: The extension generates a persistent unique user identifier on installation and transmits this ID to addefenderplus.com with every network request. This tracking occurs without adequate user disclosure or consent.

**Evidence**:

In `service_worker.js`, on installation the extension fetches a UID from the remote server:
```javascript
const domain = "https://addefenderplus.com",
  consts = {
    UIDURL: domain + "/set/",
    configURL: domain + "/configs/",
    netURL: domain + "/net/",
    netUpdateURL: domain + "/net/",
    updateURL: domain + "/configs/",
    installFinishedURL: domain + "/installed/",
    uninstalledURL: domain + "/ciao/"
  };

// On installation:
let t = await fetchJson(consts.UIDURL);
chrome.storage.sync.get(["uid"], (function(a) {
  a.uid && (t.rpsps = a.uid)
})), await chrome.storage.sync.set({
  uid: t.rpsps,
  delay: t.vmqwo
});
```

The UID is then appended to all remote requests via the `addParams` function:
```javascript
async function addParams(t) {
  return t += "?rpsps=" + (await chrome.storage.sync.get(["uid"])).uid
}
```

This UID is sent to:
- `/set/` - Initial UID generation
- `/configs/` - Hourly configuration updates
- `/net/` - Network rule updates
- `/installed/` - Installation completion beacon (delayed)
- `/ciao/` - Uninstall tracking URL

The extension also implements Chrome Web Store tab auto-closing functionality to prevent users from reading reviews:
```javascript
async function closeCWS() {
  const t = chrome.runtime.id,
    a = await chrome.tabs.query({});
  for (const e of a) e.url && -1 !== e.url.indexOf("chrome.google.com/webstore") &&
    -1 !== e.url.indexOf(t) && chrome.tabs.remove(e.id)
}
```

**Verdict**: This constitutes HIGH severity undisclosed data collection. The extension tracks users with persistent identifiers across sessions and sends this data to a remote server without adequate disclosure in the Chrome Web Store listing.

### 2. HIGH: Remote Configuration Without Transparency

**Severity**: HIGH
**Files**: updater.js, net_updater.js
**CWE**: CWE-912 (Hidden Functionality)

**Description**: The extension fetches its ad-blocking rules dynamically from a remote server controlled by addefenderplus.com, allowing the operator to update blocking behavior without user knowledge or review.

**Evidence**:

The extension updates both CSS-based blocking rules and declarativeNetRequest rules hourly:

```javascript
async function updateData() {
  const {
    AKimr: a
  } = await chrome.storage.local.get({
    AKimr: 0
  });
  if (a && Date.now() - a < 864e5) return;  // 86400000ms = 24 hours
  const t = await addParams(consts.configURL),
    e = await fetch(t),
    s = await e.json(),
    n = [];
  for (const a of s) n.push(UpdateItem(a));
  await Promise.all(n), await chrome.storage.local.set({
    AKimr: Date.now()
  })
}

// Network rules update
async function updateNetData() {
  const {
    KptDeQsKG: a
  } = await chrome.storage.local.get({
    KptDeQsKG: 0
  });
  if (a && Date.now() - a < 864e5) return;
  const t = await addNetParams(consts.netURL),
    e = await fetch(t),
    s = await e.json();
  await UpdateNetItem(s), await chrome.storage.local.set({
    KptDeQsKG: Date.now()
  })
}
```

The dynamic network rules completely replace existing rules:
```javascript
const i = await chrome.declarativeNetRequest.getDynamicRules();
for (const a of i) n.push(a.id);
await chrome.declarativeNetRequest.updateDynamicRules({
  removeRuleIds: n,
  addRules: o
}, (() => {}));
```

**Verdict**: While remote filter lists are common in ad blockers, this implementation sends user identifiers with update requests and does not disclose this remote configuration mechanism adequately. The operator can change blocking behavior at will without extension updates.

## False Positives Analysis

The extension includes legitimate ad-blocking libraries and functionality:
- **ExtendedCSS library** (from AdGuard, LGPL-3.0 licensed) - This is a legitimate open-source CSS selector library used by ad blockers
- **Static blocking rules** - The extension ships with ~15MB of static declarativeNetRequest rules in JSON files
- **Content script injection** - The extension injects CSS and scriptlets to hide ads, which is standard ad-blocker behavior
- **Per-site toggles** - The popup allows users to enable/disable blocking per site, which is legitimate UX

However, these legitimate features do not excuse the undisclosed user tracking.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| addefenderplus.com/set/ | UID generation | None initially, returns UID | HIGH - Tracking infrastructure |
| addefenderplus.com/configs/ | CSS/scriptlet rules | UID parameter (?rpsps=...) | HIGH - User tracking on updates |
| addefenderplus.com/net/ | Network blocking rules | UID parameter (?rpsps=...) | HIGH - User tracking on updates |
| addefenderplus.com/installed/ | Installation beacon | UID parameter (?rpsps=...) | HIGH - Installation tracking |
| addefenderplus.com/ciao/ | Uninstall tracking | UID parameter (?rpsps=...) | MEDIUM - Uninstall tracking |

All endpoints receive the user's unique identifier, enabling cross-session tracking. The hourly update mechanism creates a persistent connection pattern that could be used to monitor user activity over time.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**:

While Adblock Fortress provides legitimate ad-blocking functionality, it implements undisclosed user tracking mechanisms that violate user privacy expectations. The key concerns are:

1. **Persistent User Tracking**: The extension generates and transmits unique user identifiers to addefenderplus.com with every configuration request, enabling cross-session user tracking without disclosure.

2. **Installation/Uninstall Tracking**: The extension beacons to the remote server on installation and sets an uninstall tracking URL, behaviors that are not disclosed to users.

3. **Chrome Web Store Interference**: The automatic closing of Chrome Web Store tabs containing the extension's listing could be intended to prevent users from reading reviews or warnings.

4. **Remote Control**: The hourly update mechanism allows the operator to change blocking behavior dynamically without extension updates or user awareness.

5. **Lack of Disclosure**: Review of the extension's Chrome Web Store listing reveals no mention of remote configuration, user tracking, or data collection practices.

The extension does not appear to be outright malware - it performs real ad-blocking functions. However, the undisclosed data collection and user tracking represent significant privacy violations. This behavior is particularly concerning given the 100,000+ user base.

**Recommendation**: The extension should be flagged for privacy policy review. Users should be notified that the extension tracks them with persistent identifiers and communicates with remote servers. The developer should either remove the tracking mechanisms or provide clear, prominent disclosure of these practices in the Chrome Web Store listing and within the extension itself.
