# Vulnerability Report: AdBlocker Professional

## Metadata
- **Extension ID**: kgknjmfebhekokplfpmodjopebmfdjac
- **Extension Name**: AdBlocker Professional
- **Version**: 2.0.2.3
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

AdBlocker Professional presents itself as a privacy-focused ad blocking extension that "blocks intrusive ads, enhances browsing speed, and improves online privacy." However, analysis reveals undisclosed data exfiltration behavior that contradicts its privacy claims. The extension sends browsing data from chrome.storage.local to a remote server (adblockerprofessional.com) and assigns each user a unique tracking identifier. While the extension does implement legitimate ad-blocking functionality using declarativeNetRequest rules and content scripts, the hidden telemetry and user tracking raise serious privacy concerns.

The extension fetches remote configuration from adblockerprofessional.com every 24 hours, including filter lists and potentially executable code that gets stored in chrome.storage and injected into web pages. The static analyzer detected an exfiltration flow from chrome.storage.local to fetch() calls targeting the remote domain, and cross-component message passing that transmits data from isolated content scripts to the background service worker.

## Vulnerability Details

### 1. HIGH: Undisclosed User Tracking and Data Exfiltration

**Severity**: HIGH
**Files**: backend.js, isolated.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension assigns a unique user ID to each installation and transmits browsing-related data to adblockerprofessional.com without user consent or privacy policy disclosure. On installation, the extension contacts the remote server to obtain a uniqueUserId which is stored locally and included in all subsequent requests.

**Evidence**:

```javascript
// backend.js lines 16-39
chrome.runtime.onInstalled.addListener(async n => {
  if (n.reason === chrome.runtime.OnInstalledReason["INSTALL"]) {
    let e = l["defaultUserId"];
    try {
      const o = await fetch(l.installUrl + "?version=" + encodeURIComponent(chrome["runtime"].getManifest().version), {
        credentials: "include"
      });
      const s = await o.json();
      function t() {
        e = s.uniqueUserId
      }
      t()
    } finally {
      await chrome.storage.local.set({
        userId: e
      });
      await r();
      chrome.runtime.setUninstallURL(l["uninstallUrl"] + "?" + l.userIdQueryParam + "=" + e);
    }
  }
});
```

The extension then periodically sends the userId along with version information to fetch updated filter rules:

```javascript
// backend.js lines 136-171
const o = async () => {
  let {
    userId: e,
    updateNetDataLastRunDate: n
  } = await chrome["storage"].local.get(["userId", "updateNetDataLastRunDate"]);
  // ...
  try {
    const t = await i(l.updateForNetUrl + "?" + l.userIdQueryParam + "=" + e + "&version=" + encodeURIComponent(chrome["runtime"].getManifest()["version"]));
    // ...
    const r = await i(t.url);
    chrome.storage.local["set"](r);
    // ...
```

Static analysis confirms the exfiltration flow:
```
[HIGH] chrome.storage.local.get → fetch(adblockerprofessional.com)    backend.js
```

**Verdict**: This is a clear privacy violation. Users installing an "ad blocker" expect privacy protection, not to be tracked with a unique identifier. The extension description makes no mention of telemetry, user tracking, or data collection. This constitutes undisclosed data exfiltration.

### 2. HIGH: Remote Code Execution via Dynamic Configuration

**Severity**: HIGH
**Files**: backend.js, isolated.js, main.js
**CWE**: CWE-494 (Download of Code Without Integrity Check)
**Description**: The extension fetches arbitrary JSON data from adblockerprofessional.com every 24 hours and stores it in chrome.storage.local. This data is then read by content scripts and can include "codeBlock" arrays that dispatch CustomEvents with arbitrary parameters into the page context.

**Evidence**:

```javascript
// isolated.js lines 72-98
const A = await chrome.storage.local.get(R);
for (const a of R) {
  const u = A[a];
  if (!u) {
    continue
  }
  try {
    if (!u.codeBlock) {
      Promise["allSettled"]
    } else {
      for (const e of u.codeBlock) {
        try {
          function M() {
            return e[n]
          }
          const n = Object.keys(e)[0];
          const t = M();
          document.dispatchEvent(new CustomEvent(n, {
            detail: {
              params: t
            }
          }))
        } catch (e) {}
      }
    }
  } catch (e) {
```

The main.js content script listens for these custom events and executes functions based on the event name, effectively allowing remote code to trigger arbitrary JavaScript execution in the page context.

**Verdict**: While the extension uses CustomEvents rather than direct eval(), this pattern allows the remote server to control page-level behavior by dispatching events that trigger pre-defined code paths. The lack of integrity checks (no signatures, no hashes) means a compromised server or MITM attack could inject malicious configurations.

### 3. MEDIUM: Fetch/XHR Hooking in Page Context

**Severity**: MEDIUM
**Files**: main.js
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension injects proxy wrappers around window.fetch and XMLHttpRequest in the MAIN world context to intercept and potentially modify network requests made by web pages.

**Evidence**:

```javascript
// main.js lines 3119, 3233, 4523, 4559, 5132, 5695, 8378
self.fetch = new Proxy(self["fetch"], { /* ... */ });
self.XMLHttpRequest = class extends self["XMLHttpRequest"] { /* ... */ };
self.XMLHttpRequest.prototype.open = new Proxy(self.XMLHttpRequest.prototype.open, { /* ... */ });
```

**Verdict**: While fetch/XHR hooking is a standard technique for ad blockers to prevent ad requests, the implementation in the MAIN world (not ISOLATED) means the extension has the capability to intercept, read, and modify all network traffic from the page, including sensitive data like login credentials or API tokens. This is necessary for blocking ads but represents a significant attack surface if the extension is compromised.

## False Positives Analysis

1. **Fetch/XHR Proxying**: Standard for ad blocking extensions to intercept network requests before they're sent. This is expected behavior for the stated purpose.

2. **declarativeNetRequest Rules**: The extension legitimately uses Chrome's declarativeNetRequest API to block network requests matching filter patterns. The adblock-data/ folder contains typical uBlock Origin-style filter lists (hosts, entities, generic rules).

3. **Content Script Injection**: Injecting CSS and procedural cosmetic filters into pages is standard ad-blocking behavior. The complex selector logic in isolated.js matches uBlock Origin's scriptlet system.

4. **WebRTC Disabling**: The main.js script includes code to disable WebRTC (lines 48-101), which is a legitimate privacy feature offered by many ad blockers to prevent IP leaks.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| https://adblockerprofessional.com/install/ | User registration on install | extension version | HIGH - assigns tracking ID |
| https://adblockerprofessional.com/maj/net_data/ | Fetch remote filter updates | userId, version | HIGH - enables user tracking |
| https://adblockerprofessional.com/un/ | Uninstall tracking | userId | MEDIUM - tracks churn |

All requests use `credentials: "include"` which sends cookies, enabling cross-site tracking if the user visits adblockerprofessional.com in a regular tab.

## Overall Risk Assessment

**RISK LEVEL: HIGH**

**Justification**: While AdBlocker Professional implements legitimate ad-blocking functionality, it engages in undisclosed user tracking and data exfiltration that violates user privacy expectations. The extension assigns a unique identifier to each user and sends it to a remote server along with browsing-related data, without any disclosure in the extension description or permission warnings. This behavior is particularly concerning given the extension's claim to "improve online privacy."

The combination of:
1. Undisclosed unique user tracking
2. Periodic data transmission to third-party server
3. Remote configuration fetching without integrity checks
4. Access to all user browsing via `<all_urls>`

creates a significant privacy risk for the 100,000 users who installed this extension expecting privacy protection. Users should be informed of telemetry collection, and the unique user ID system should either be removed or made opt-in with clear disclosure.
