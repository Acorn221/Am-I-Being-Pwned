# Vulnerability Report: Adblock for Youtube™

## Metadata
- **Extension Name:** Adblock for Youtube™
- **Extension ID:** cmedhionkhpnakcndndgjdbohmhepckk
- **Version:** 7.0.8
- **Manifest Version:** 3
- **User Count:** ~11,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

Adblock for Youtube™ is a YouTube ad-blocking extension that operates using a combination of declarativeNetRequest rules, CSS cosmetic filtering, and scriptlet injection (via `chrome.scripting.executeScript` in MAIN world). The extension fetches updated blocking rules from a remote server (`api.adblock-for-youtube.com`) and includes a bundled scriptlets library (version 2.1.4) that closely mirrors the AdGuard/uBlock Origin scriptlets ecosystem.

The extension's permissions are broad (`<all_urls>`, `tabs`, `webRequest`, `scripting`, `webNavigation`) but are consistent with what a YouTube ad blocker requires. The remote config mechanism is a notable attack surface, as the server can push arbitrary CSS rules, network rules, scriptlet configurations, and popup configurations. However, no evidence of data exfiltration, user tracking beyond DAU, keylogging, cookie harvesting, proxy infrastructure, or SDK injection was found.

**Overall Assessment:** The extension functions as advertised. Its permissions and behaviors align with its stated purpose as a YouTube ad blocker. The remote config fetch is the primary concern but is narrowly scoped to blocking rule updates.

## Vulnerability Details

### MEDIUM - Remote Configuration Fetching (Potential for Remote Code Execution via Scriptlets)

- **Severity:** MEDIUM
- **Files:** `background.js` (lines 2379-2397, 2442-2473)
- **Code:**
```javascript
var fetchServerData = function () {
    return fetch("https://api.adblock-for-youtube.com/api/v2/rules?version=" + EXTENSION_VERSION);
};

var updateSettingsFromServer = function () {
    var response = await fetchServerData();
    var { networkRules, cssRules, popupConfig, scripletsRules, updatePageConfig } = response;
    // These are stored and used to inject scripts and CSS
    await setMultiplyToStorageAndSettings(data);
};
```
- **Verdict:** The server can push new `scripletsRules` which are resolved against the bundled scriptlets library and executed in the MAIN world of YouTube pages. While the scriptlet names must match the bundled library (limiting arbitrary code execution), the `args` arrays for scriptlets like `set-constant`, `json-prune`, `trusted-replace-outbound-text`, etc. are controlled by the server. The `trusted-replace-outbound-text` scriptlet in particular allows server-controlled string replacements in `JSON.stringify` output. If the server were compromised, this could be leveraged for targeted manipulation. However, the scriptlets library is bundled locally and names must match -- the server cannot push arbitrary JavaScript, only configure known scriptlet functions with new arguments.

### LOW - Script Injection in MAIN World

- **Severity:** LOW
- **Files:** `background.js` (lines 2172-2214)
- **Code:**
```javascript
function injectedFunction(script, scriptId) {
    var policy = window.trustedTypes.createPolicy('default', {
        createScript: function (input) { return input; },
    });
    var safeScriptContent = policy.createScript(script);
    var scriptTag = document.createElement('script');
    scriptTag.textContent = safeScriptContent;
    var parent = document.head || document.documentElement;
    parent.appendChild(scriptTag);
}
// Executed via chrome.scripting.executeScript with world: 'MAIN'
```
- **Verdict:** The extension injects scripts into the MAIN world of YouTube pages using Trusted Types bypass. This is standard practice for ad blockers that need to intercept page-level APIs (JSON.parse, JSON.stringify, Array.push, Promise.then, XMLHttpRequest.send, TextEncoder.encode, Request constructor, Node.appendChild). The inline scripts (lines 2122-2128) are hardcoded in the extension and focus exclusively on YouTube ad-skipping/blocking behavior. This is expected functionality for an ad blocker.

### LOW - Broad Content Script Match Pattern with all_frames

- **Severity:** LOW
- **Files:** `manifest.json` (lines 16-23)
- **Code:**
```json
"content_scripts": [{
    "matches": ["http://*/*", "https://*/*"],
    "js": ["contentscript.js"],
    "all_frames": true,
    "run_at": "document_start"
}]
```
- **Verdict:** The content script runs on all URLs in all frames, though its actual behavior is gated by `isAdBlockWorksOnPage()` which checks for `youtube.com`. The broad match pattern is used primarily for the popup display system (rate-us, anti-adblock, configurable popup) and the keep-alive ping mechanism. No data collection or manipulation occurs on non-YouTube pages.

### INFO - Service Worker Keep-Alive Mechanism

- **Severity:** INFO
- **Files:** `background.js` (lines 41-48, 1121-1144)
- **Code:**
```javascript
var calculateDau = function () {
    setTimeout(function () {
        chrome.runtime.reload();
    }, 86400 * 1000);  // 24 hours
};

var mainScheduler = function () {
    setInterval(function () {
        chrome.runtime.getPlatformInfo();
    }, 25000);  // 25 seconds
    chrome.alarms.create(ActionsEnum.Ping, { periodInMinutes: 1 });
};
```
- **Verdict:** The extension uses `chrome.runtime.getPlatformInfo()` calls every 25 seconds and a 1-minute alarm to keep the MV3 service worker alive. It also schedules a full `chrome.runtime.reload()` every 24 hours. These are common patterns for MV3 ad blockers that need persistent background processing. The naming "calculateDau" is misleading -- it does not actually calculate or report DAU metrics.

### INFO - Install/Uninstall/Update Page Opening

- **Severity:** INFO
- **Files:** `background.js` (lines 495-497, 836-862)
- **Code:**
```javascript
var INSTALL_URL = "https://get.adblock-for-youtube.com/install?v=" + EXTENSION_VERSION + "&xtid=" + EXTENSION_ID;
var UNINSTALL_URL = "https://get.adblock-for-youtube.com/uninstall?v=" + EXTENSION_VERSION + "&xtid=" + EXTENSION_ID;
var UPDATE_URL = "https://get.adblock-for-youtube.com/update?v=" + EXTENSION_VERSION + "&xtid=" + EXTENSION_ID;
```
- **Verdict:** Standard practice for extensions. The only data sent is extension version and extension ID (not user-specific). The uninstall URL is set via `chrome.runtime.setUninstallURL()`. The update page is only shown when the server enables it for a specific version AND the user has "Inform about updates" enabled.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `innerHTML` assignment | `contentscript.js:526` | i18n translation via `chrome.i18n.getMessage()` -- safe, localized strings |
| `innerHTML` assignment | `contentscript.js:802` | Popup HTML injection -- hardcoded HTML templates for rate-us/anti-adblock popups |
| Trusted Types `createScript` bypass | `background.js:2175` | Standard ad blocker pattern to inject scriptlets past CSP |
| `JSON.parse` / `JSON.stringify` proxy | `background.js:2126` (inline scripts) | Ad-blocking technique to prune ad placement data from YouTube API responses |
| `XMLHttpRequest.prototype.send` proxy | `background.js:2127` (inline scripts) | Ad-blocking technique to modify outbound YouTube API requests |
| `Array.prototype.push` proxy | `background.js:2122` (inline scripts) | Ad-skipping technique using SSAP entity tracking |
| `Promise.prototype.then` proxy | `background.js:2125` (inline scripts) | Blocks YouTube's `onAbnormalityDetected` anti-adblock callback |
| `Node.prototype.appendChild` proxy | `background.js:2124` (inline scripts) | Ensures about:blank iframes use the same fetch/Request as main page |
| `TextEncoder.prototype.encode` proxy | `background.js:2126` (inline scripts) | Modifies YouTube playback context to bypass ad serving |
| `Request` constructor proxy | `background.js:2126` (inline scripts) | Modifies YouTube API request bodies for ad bypass |
| AdGuard-style scriptlets library | `background.js:1420-2010` | Bundled library (v2.1.4) for standard ad-blocking scriptlets |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent |
|----------|--------|---------|-----------|
| `https://api.adblock-for-youtube.com/api/v2/rules?version={VERSION}` | GET | Fetch updated blocking rules | Extension version only |
| `https://get.adblock-for-youtube.com/install` | Page open | Post-install page | Extension version + ID (via URL params) |
| `https://get.adblock-for-youtube.com/uninstall` | Page open | Post-uninstall page | Extension version + ID (via URL params) |
| `https://get.adblock-for-youtube.com/update` | Page open | Post-update page | Extension version + ID (via URL params) |
| `https://get.adblock-for-youtube.com/windows` | Link | Promotional link in popup | None (user clicks) |
| `https://fonts.googleapis.com/css2` | CSS import | Google Fonts for popup UI | None |
| `https://chromewebstore.google.com/detail/{ID}/reviews` | Link | Rate button in popup | None (user clicks) |

## Data Flow Summary

1. **On Install:** Sets default settings in `chrome.storage.local` (ads=true, annotations=false, informAboutUpdates=true). Opens install page.
2. **On Startup:** Fetches updated rules from `api.adblock-for-youtube.com`. Stores updated `networkRules`, `cssRules`, `scripletsRules`, and `popupConfig` locally. Updates `declarativeNetRequest` dynamic rules.
3. **On YouTube Navigation:** Background script detects YouTube pages via `webNavigation.onCommitted` and `webRequest.onResponseStarted`. Injects CSS (hiding ad elements) and scripts (scriptlets + inline scripts for API interception) into the tab.
4. **Content Script:** Runs on all pages but gates YouTube-specific behavior behind `isAdBlockWorksOnPage()`. Sends `PAGE_READY` message to background, receives settings. May show promotional popups (windows app, anti-adblock, rate-us) based on server-pushed config. Sends periodic `PING` messages for keep-alive.
5. **No user data is collected or transmitted.** The only outbound request is the rules fetch which sends only the extension version.

## Overall Risk Assessment

**CLEAN**

This extension is a legitimate YouTube ad blocker. While it requires broad permissions (`<all_urls>`, `scripting`, `webRequest`, `webNavigation`, `tabs`) and fetches remote configuration, all of these are necessary for and consistent with its ad-blocking functionality. The remote config is narrowly scoped to blocking rules (CSS selectors, network filter rules, scriptlet configurations, popup display settings). No evidence of data exfiltration, user tracking, malicious behavior, extension enumeration, residential proxy infrastructure, market intelligence SDKs, or obfuscated code was found. The codebase is cleanly structured TypeScript compiled with webpack, with clear module boundaries and named source files.
