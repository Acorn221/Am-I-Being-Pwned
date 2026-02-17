# Vulnerability Report: Netpanel

## Metadata
- **Extension ID**: kbidbgoheiddfilfipcobicemncfogno
- **Extension Name**: Netpanel
- **Version**: 1.92.0
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-15

## Executive Summary

Netpanel is a legitimate market research browser extension operated by Gemius, a web analytics company. The extension tracks browsing behavior, page views, ad impressions, video content viewing, and user engagement metrics across all websites. While the extension's purpose is disclosed as being "necessary for carrying out Netpanel" (a market research panel), it collects extensive browsing data including URLs visited, page content, screen dimensions, active time on pages, search queries, and potentially canvas fingerprinting data.

The extension operates on all websites via content scripts injected at document_start, collects detailed viewing metrics, and transmits data to Gemius servers at hit.gemius.pl. The optional "management" permission allows enumeration of installed extensions when granted. While this is a disclosed market research tool and not malicious, the breadth of data collection and tracking capabilities across the entire web warrant a MEDIUM risk classification.

## Vulnerability Details

### 1. MEDIUM: Comprehensive Browsing Data Collection
**Severity**: MEDIUM
**Files**: lib/backgrounds/sw_modules/adhcclient.js, lib/backgrounds/hit.js, lib/backgrounds/sw_modules/adlogger.js
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension collects extensive browsing behavior data across all websites including URLs visited, referrer information, page titles, authors, search keywords, screen/window dimensions, active time periods, click tracking, and video viewing behavior. Data is sent to gemius.pl servers with a unique panelist identifier (x_gemius_netpanel).

**Evidence**:
```javascript
// lib/backgrounds/sw_modules/adhcclient.js:66-83
sendRequest(url) {
  if (typeof fetch === "function") {
    try {
      fetch(url, {
        method: "GET",
        credentials: "include",
        keepalive: true,
      }).catch(() => {
        this.sendHitFallback(url);
      });
    } catch (e) {
      this.sendHitFallback(url);
    }
  } else {
    this.sendHitFallback(url);
  }
}

// lib/backgrounds/sw_modules/adhcclient.js:124-142
params.push("href=" + this.encode_param(page.url ? page.url : "", AdHCClientModule.MAX_URL_LENGTH));
params.push("ref=" + this.encode_param(page.referrer ? page.referrer : "", AdHCClientModule.MAX_URL_LENGTH));
params.push("extra=" + encodeURIComponent(extra));
params.push("npid=" + this.x_gemius_netpanel);
```

**Verdict**: While this data collection is consistent with disclosed market research activities, the extensive scope of tracking across all websites represents significant privacy exposure for users who may not fully understand the breadth of monitoring.

### 2. MEDIUM: Optional Extension Enumeration (Management Permission)
**Severity**: MEDIUM
**Files**: lib/backgrounds/sw_modules/adreal.js (lines 124-140), popup.js (lines 56-66, 84-95)
**CWE**: CWE-200 (Exposure of Sensitive Information)
**Description**: The extension requests optional "management" permission that allows enumeration of all installed extensions and plugins. When granted, it logs all installed extensions/plugins to the tracking servers.

**Evidence**:
```javascript
// lib/backgrounds/sw_modules/adreal.js:124-140
var logAddons = function () {
  if (
    typeof chrome !== "undefined" &&
    chrome.management &&
    chrome.management.getAll
  ) {
    // management permission is granted, so log addons
    chrome.management.getAll(function (addons) {
      for (var i = 0; i < addons.length; i++) {
        var addon = addons[i];
        if (addon.type && ["extension", "plugin"].includes(addon.type)) {
          AdLogger.addon(addon);
        }
      }
    });
  }
};
```

**Verdict**: Extension enumeration can be used for browser fingerprinting and profiling. However, this is an optional permission that users must explicitly grant, and the popup UI clearly allows toggling this permission on/off.

### 3. MEDIUM: Postmessage Listeners Without Origin Validation
**Severity**: MEDIUM
**Files**: lib/contents/utils/adutil.js (lines 248, 255, 258)
**CWE**: CWE-940 (Improper Verification of Source of a Communication Channel)
**Description**: The extension registers multiple window.addEventListener("message") handlers without proper origin validation, potentially allowing malicious websites to send crafted messages to the extension's content scripts.

**Evidence**:
```javascript
// lib/contents/utils/adutil.js:246-261
var addMessageListener = function (callback) {
  try {
    window.addEventListener("message", callback, false);
  } catch (e) {
    // ignore
  }
  if (!isFirefox()) {
    // workaround for chrome
    NativeProtector.setTimeout(function () {
      window.addEventListener("message", callback, false);
    }, 2000);
    NativeProtector.setTimeout(function () {
      window.addEventListener("message", callback, false);
    }, 5000);
  }
};
```

**Verdict**: While this creates an attack surface, the actual message handlers appear to be used for internal communication between injected scripts rather than processing external commands, limiting exploitability.

### 4. LOW: Cookie Collection Across All Domains
**Severity**: LOW
**Files**: background.js (line 60), manifest.json
**CWE**: CWE-359 (Exposure of Private Information)
**Description**: The extension has the "cookies" permission and reads cookies named "nplight" across all domains during initialization to synchronize panel configuration.

**Evidence**:
```javascript
// background.js:60
let cookies = await ChromeCookies.getAll({name: "nplight"});
```

**Verdict**: Cookie access is limited to specific named cookies ("nplight") used for panel configuration synchronization. While the permission is broad, the actual usage is constrained and necessary for the extension's legitimate functionality.

## False Positives Analysis

### Canvas Detection (Not Actually Canvas Fingerprinting)
The extension includes files named "canvas.js" and "canvas_interceptor.js" and has code for collecting "canvas data". However, examination reveals this is for detecting and measuring canvas-based advertisements and video players, not for browser fingerprinting. The data collection appears focused on ad viewability metrics rather than extracting canvas-based fingerprints for user tracking.

### Obfuscation Flag
The ext-analyzer flagged this extension as "obfuscated". However, the code is standard minified/compiled JavaScript typical of production extensions. After deobfuscation, the code is readable and does not show signs of deliberate anti-analysis obfuscation.

### Window.open Interception
Files like "windowopen_interceptor.js" exist to track pop-up ads and new window advertisements for viewability measurement, which is a standard market research activity, not malicious behavior.

## API Endpoints Analysis

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| netpanel.gemius.com/light-rpc/ | RPC configuration endpoint | Panelist ID, ticket for authentication | Low - encrypted HTTPS, limited to config |
| {prefix}.hit.gemius.pl/redot.js | Tracking hit collector | Page URLs, referrers, view events, ad impressions, video views, panelist ID, browser info, screen dimensions | Medium - comprehensive behavioral data |
| ls.hit.gemius.pl/* | Tracking endpoint (excluded from content scripts) | Various tracking beacons | Medium - data collection |
| gemius.com | Homepage URL | None (just listed in manifest) | None |

## Overall Risk Assessment

**RISK LEVEL: MEDIUM**

**Justification**:
Netpanel is a legitimate market research browser extension that collects extensive browsing behavior and web content consumption data across all websites. The extension is transparent about its purpose ("carrying out Netpanel"), and the data collection aligns with typical market research panel activities operated by Gemius, a known web analytics company.

However, the breadth of data collection warrants a MEDIUM risk classification:
- Tracks all browsing activity across the entire web (*:///*/*)
- Collects URLs, page titles, content, search queries, and viewing behavior
- Gathers detailed engagement metrics (active time, scroll depth, video playback)
- Optional extension enumeration for fingerprinting when management permission granted
- Content scripts run on all pages at document_start with all_frames:true
- Sends unique panelist identifier with all tracking data

While not malicious, users should be aware that installing this extension means comprehensive monitoring of their web browsing for market research purposes. The extension operates as disclosed, but the privacy impact is significant. Users participating in the Netpanel research program are presumably consenting to this level of tracking, but the extension would be inappropriate for users seeking privacy.

**Recommendations**:
- Users should only install if participating in the Gemius Netpanel market research program
- Users concerned about privacy should avoid granting the optional "management" permission
- The extension description could be more explicit about the scope of data collection
- Origin validation should be added to postMessage event listeners
