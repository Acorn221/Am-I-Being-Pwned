# Vulnerability Report: Microsoft Bing Homepage & Search for Chrome

## Metadata
- **Extension Name:** Microsoft Bing Homepage & Search for Chrome
- **Extension ID:** ddojnmkongaimkdddgmcccldlfhokcfb
- **Version:** 1.0.0.27
- **Users:** ~4,000,000
- **Manifest Version:** 3
- **Publisher:** Microsoft Corporation (implied by code and endpoints)

## Permissions Analysis
- **cookies** - Used to set Bing tracking cookies (_DPC, _NTPC, SRCHS, _SS, BCEX)
- **declarativeNetRequest** - Used to redirect Bing search/homepage URLs to append partner codes
- **tabs** - Used to open welcome pages and navigate to Bing
- **alarms** - Used for daily ping telemetry and periodic cookie refreshes
- **storage** - Used extensively to persist partner codes, machine IDs, channels
- **contextMenus** - Quick search / visual search context menu integration
- **notifications** - Displays Bing extension notifications
- **scripting** - Injects content.bundle.js for quick search overlay on pages
- **host_permissions:** `https://*/*`, `http://*/*` - Broad host access for content script injection

**CSP:** `script-src 'self'; object-src 'self'` - Properly restrictive.

**externally_connectable:** `https://www.bing.com/*`, `https://browserdefaults.microsoft.com/*` - Only Microsoft domains.

## Executive Summary

This is an official Microsoft extension that sets Bing as the default search engine and homepage, and adds a quick-search overlay feature. The extension has broad permissions (all URLs host access, cookies, scripting) but uses them for legitimate purposes: redirecting search queries through Bing with partner tracking codes, injecting a quick-search UI overlay, and sending telemetry to Microsoft's Aria analytics pipeline. No malicious behavior, data exfiltration, residential proxy infrastructure, or unauthorized surveillance was identified. The code is consistent with a first-party Microsoft browser extension.

## Vulnerability Details

### 1. Broad Host Permissions with Content Script Injection
- **Severity:** LOW (informational)
- **Files:** `scripts/ping.js` (background), `content.bundle.js` (content script)
- **Code:** `chrome.scripting.executeScript({target:{tabId:n},files:["content.bundle.js"]})`
- **Details:** The extension injects content.bundle.js into pages to provide a Bing quick-search overlay. While the broad `https://*/*` and `http://*/*` host permissions grant access to all websites, the injected content script is limited to displaying a search overlay widget and does not harvest page content or user data beyond what is needed for the search feature.
- **Verdict:** Expected behavior for a search overlay feature. No exploitation vector identified.

### 2. Machine ID Generation and Tracking
- **Severity:** LOW (informational)
- **Files:** `scripts/ping.js`
- **Code:** `function guid(){...var t=e()+e()+e()+e()+e()+e()+e()+e();...chrome.storage.local.set({[MACHINE_ID]:t}),t}`
- **Details:** The extension generates a random machine ID (GUID) on install and persists it in chrome.storage.local. This ID is sent with all telemetry pings and set as a cookie on browserdefaults.microsoft.com. This enables Microsoft to track individual installations across sessions.
- **Verdict:** Standard for Microsoft products. The machine ID is randomly generated (not fingerprint-based) and used for install attribution/analytics only.

### 3. Partner Code URL Rewriting via declarativeNetRequest
- **Severity:** LOW (informational)
- **Files:** `scripts/ping.js`
- **Code:** `chrome.declarativeNetRequest.updateDynamicRules({addRules:a,removeRuleIds:[e]})` - rewrites `pc=BG00` params and `form=BGGCDF` on Bing search URLs
- **Details:** All Bing search and homepage navigations have partner tracking parameters injected/replaced (pc, form codes). This is the core monetization mechanism - Microsoft tracks that searches came from this extension.
- **Verdict:** Expected behavior. This is the extension's stated purpose.

### 4. Telemetry to Microsoft Aria Pipeline
- **Severity:** LOW (informational)
- **Files:** `background.bundle.js` (extracted)
- **Endpoints:** `https://{region}.pipe.aria.microsoft.com/Collector/3.0/`
- **Details:** The extension uses Microsoft's Aria Web Telemetry SDK (AWT) to send usage analytics. Data includes partner code, market, browser version, OS version, channel, extension ID, machine ID, and event type. This is Microsoft's standard telemetry infrastructure used across all their products.
- **Verdict:** Standard Microsoft telemetry. No PII beyond machine ID is collected.

### 5. Cookie Manipulation on Bing Domains
- **Severity:** LOW (informational)
- **Files:** `scripts/ping.js`
- **Code:** Sets cookies `_DPC`, `_NTPC`, `SRCHS`, `_SS` (BCEX param), `MachineID` on `.bing.com` and `.browserdefaults.microsoft.com`
- **Details:** Multiple first-party cookies are set/updated on periodic alarms (every alarm cycle) to maintain partner attribution. The BCEX cookie controls a market-specific experience flag.
- **Verdict:** First-party cookie management on the publisher's own domain. No cross-site tracking.

### 6. Extension-to-Extension Communication (QuickSearch Polling)
- **Severity:** LOW (informational)
- **Files:** `background.bundle.js` (extracted)
- **Code:** `chrome.runtime.sendMessage(t[e],{message:r.QuickSearchPollMessage},...)`
- **Details:** The extension polls a list of known Microsoft extension IDs (QuickSearchEnabledExtensionIds) to check if quick search or visual search is already active in another Microsoft extension. This prevents duplicate overlays. The extension IDs are hardcoded/configured, not discovered via `chrome.management`.
- **Verdict:** Legitimate coordination between Microsoft's own extensions. Not extension enumeration for malicious purposes.

### 7. `new Function("return this")` Usage
- **Severity:** FALSE POSITIVE
- **Files:** `background.bundle.js` (extracted)
- **Code:** `r.g=function(){if("object"==typeof globalThis)return globalThis;try{return this||new Function("return this")()}catch(e){...}}`
- **Details:** Standard webpack polyfill for accessing the global scope. This is a known pattern in webpack-bundled code.
- **Verdict:** False positive - webpack boilerplate.

### 8. First Search Notification Overlay
- **Severity:** LOW (informational)
- **Files:** `scripts/firstSearchNotificationContent.js`
- **Code:** Creates full-viewport iframe from `https://www.bing.com/browserextension/binghomepagesearchplus/firstsearchoverlay`
- **Details:** On the user's first Bing search after install, a full-screen iframe overlay is displayed from bing.com. It is dismissed on click/focus. This is a onboarding/welcome notification, not persistent.
- **Verdict:** Aggressive UX but not malicious. One-time display that is easily dismissed.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| `new Function("return this")` | background.bundle.js | Webpack globalThis polyfill |
| `innerHTML` (x3) | content.bundle.js | Quick search template rendering from bing.com HTML |
| `document.cookie` (x10 total) | Both bundles | Microsoft Aria SDK cookie management + Axios cookie helpers |
| `importScripts` reference | background.bundle.js | Feature detection check for WorkerGlobalScope, not dynamic loading |
| `keypress` listener | content.bundle.js | Dismisses quick search overlay on any keypress - not a keylogger |
| `fetch` calls | Both bundles | Bing search API, Aria telemetry, notification triggers, HMR manifest check |
| `XMLHttpRequest` | Both bundles | Fallback transport in Aria SDK for older environments |

## API Endpoints Table

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://go.microsoft.com/fwlink/?linkid=2243942` | Daily/install ping | GET | Base64-encoded: partner code, extension name, market, browser version, extension ID, event type, channel, DPC, LP market |
| `https://browserdefaults.microsoft.com/api/hpinst/InstrumentationTracking` | Install/FSN event tracking | POST (JSON) | Partner code, OS, market, browser, extension ID, channel, machine ID, browser version, current URL, event ID, BCEX |
| `https://{region}.pipe.aria.microsoft.com/Collector/3.0/` | Microsoft Aria telemetry | POST | Standard telemetry events (extension usage analytics) |
| `https://go.microsoft.com/fwlink/?linkid=2128904` | Welcome page redirect | GET (navigation) | Extension ID, partner code, browser, market, channel, machine ID |
| `https://go.microsoft.com/fwlink/?linkid=2138838` | Uninstall URL | GET (navigation) | Extension ID, market, machine ID, browser |
| `https://www.bing.com/notifications/trigger` | Notification fetch | GET | Extension name |
| `https://www.bing.com/notifications/extension/handle` | Extension status update | GET | Extension ID, action, install info |
| `https://www.bing.com/browserextension/binghomepagesearchplus/firstsearchoverlay` | First search overlay | GET (iframe) | None |
| `https://www.bing.com/search` | Search redirect target | GET (navigation) | User search query + partner/form codes |
| `https://www.bing.com/images/search` | Visual search | GET (navigation) | Image URL + form/PC codes |

## Data Flow Summary

1. **Install:** Extension generates random machine ID, reads partner/channel from browserdefaults.microsoft.com cookie, sends install ping to go.microsoft.com, opens welcome page, sets Bing cookies for partner attribution, sends instrumentation event to browserdefaults.microsoft.com.
2. **Periodic (alarm-based):** Every alarm cycle: refreshes _DPC, _NTPC, SRCHS cookies on bing.com, refreshes BCEX cookie, sends daily ping (event type "2") to go.microsoft.com, ensures redirect rules are active.
3. **Search:** User searches are redirected through declarativeNetRequest rules to include `pc=` and `form=` partner codes. No search content is intercepted or logged by the extension.
4. **Quick Search Overlay:** Content script (content.bundle.js) is injected into pages to provide a quick-search floating widget. Polls other Microsoft extensions to avoid duplicates. Sends search queries directly to bing.com. Uses Aria SDK for usage telemetry.
5. **Visual Search:** Right-click context menu for image search, sending image URL to bing.com visual search.
6. **Uninstall:** Sets uninstall URL to Microsoft feedback page with machine ID and market info.

## Overall Risk Assessment

**CLEAN**

This is a legitimate first-party Microsoft extension that performs its stated function: setting Bing as the default search engine and homepage, with additional quick-search and visual-search features. While it requests broad permissions (all-URLs host access, cookies, scripting), these are used appropriately for its search overlay and partner attribution features. All network communication is exclusively with Microsoft-owned domains (bing.com, microsoft.com, browserdefaults.microsoft.com, pipe.aria.microsoft.com). Telemetry is sent through Microsoft's standard Aria analytics pipeline. No evidence of malicious behavior, data harvesting, proxy infrastructure, third-party SDK injection, or unauthorized surveillance. The extension's invasiveness (cookie setting, URL rewriting, content script injection) is proportional to and consistent with its stated purpose as a search engine default setter with integrated search features.
