# Vulnerability Report: IE Tab

## Metadata
- **Extension Name:** IE Tab
- **Extension ID:** hehijbfgiekmjfkfjpbkbammjbdenadd
- **Version:** 18.12.12.1
- **Manifest Version:** 3
- **User Count:** ~4,000,000
- **Analysis Date:** 2026-02-08

## Executive Summary

IE Tab is a well-known browser extension that renders web pages using Internet Explorer's Trident engine via a native host helper application (Windows) or a remote RDP-based hosted solution (non-Windows). The extension has extensive permissions (`<all_urls>`, `cookies`, `webRequest`, `nativeMessaging`, `tabs`, etc.) that are justified by its core functionality of intercepting and redirecting URLs to an embedded IE rendering engine. The code is **not obfuscated** and is well-commented throughout.

While the permissions surface is very broad, the extension uses these capabilities in service of its stated purpose. There are **no signs of malicious behavior** such as data exfiltration, ad injection, residential proxy infrastructure, SDK injection, or remote kill switches. Several moderate security concerns exist around the architecture (externally_connectable configuration, arbitrary method dispatch patterns, and HTTP-based first-run URLs), but these are design choices typical of enterprise browser compatibility tools rather than indicators of malicious intent.

## Vulnerability Details

### 1. Overly Permissive `externally_connectable` Configuration
- **Severity:** MEDIUM
- **File:** `manifest.json` (lines 53-56)
- **Code:**
  ```json
  "externally_connectable": {
      "matches": ["*://*.ietab.net/*"],
      "ids": [ "*" ]
  }
  ```
- **Verdict:** The `"ids": ["*"]` allows **any other extension** to send messages to IE Tab via `chrome.runtime.sendMessage`. Combined with the `onExtApiRequest` handler in `background.js`, this means any extension could potentially call `GET_SETTING`, `SET_SETTING`, `GET_STORAGE`, `SET_STORAGE`, `RESET_ALL_SETTINGS`, and `TOGGLE_HOSTED`. This is a meaningful attack surface for extension-to-extension attacks. The web page surface is appropriately limited to `*.ietab.net`. **Low exploitability in practice** since it requires a malicious co-installed extension, but the `"*"` wildcard is unnecessarily broad.

### 2. Arbitrary Method/Property Dispatch in RemoteHostManager
- **Severity:** MEDIUM
- **File:** `js/remhost_manager.js` (lines 515-541)
- **Code:**
  ```javascript
  onRHProxyCall: function(msg, sender, fnResponse) {
      this._currentCallTabId = sender.tab.id;
      return this[msg.fnName](msg.arg, fnResponse);
  },
  onRHProxySetProp: function(msg, fnResponse) {
      this[msg.propName] = msg.value;
  },
  onRHProxyGetProp: function(msg, fnResponse) {
      // ... traverses dot-separated property paths
      fnResponse(obj[restName]);
  }
  ```
- **Verdict:** The `RH_CALL` message handler calls arbitrary methods on `RemoteHostManager` by name via `this[msg.fnName]()`. Similarly, `RH_SETPROP` sets arbitrary properties and `RH_GETPROP` reads them with dot-notation traversal. These messages originate from extension pages (iecontainer tabs), not web pages, but a content script compromise could escalate through this pattern. Same pattern exists in `background_proxy.js` (`BP_CALL` dispatches to `Background[name]()`).

### 3. BackgroundProxy Arbitrary Method Dispatch
- **Severity:** MEDIUM
- **File:** `js/background_proxy.js` (lines 27-41, 43-53)
- **Code:**
  ```javascript
  case 'BP_CALL':
      return this.call(msg.fnName, msg.arg, fnResponse);
  // ...
  call: function(name, arg, fnResponse) {
      // ...
      fnResponse(Background[name](arg));
  }
  ```
- **Verdict:** Any `chrome.runtime.sendMessage` with `type: 'BP_CALL'` can invoke arbitrary methods on the `Background` object. Since `externally_connectable.ids` is `"*"`, any co-installed extension could invoke `Background.openWithIETab()`, `Background.licensePing()`, or other methods. Risk is limited by the fact that these are mostly configuration and navigation functions.

### 4. HTTP URLs for First-Run and Navigation
- **Severity:** LOW
- **File:** `js/background.js` (lines 129-140, 1139, 1288)
- **Code:**
  ```javascript
  targetUrl = 'http://www.ietab.net/hostedfirstrun';
  // ...
  targetUrl = "http://www.ietab.net/thanks-installing-ie-tab";
  // ...
  chrome.runtime.setUninstallURL('http://www.ietab.net/ie-tab-alternatives');
  // ...
  targetUrl = "http://www.ietab.net/ie-tab-documentation?from=chromeurl";
  ```
- **Verdict:** Several navigation targets use HTTP instead of HTTPS, making them vulnerable to man-in-the-middle attacks. In practice, ietab.net likely redirects to HTTPS, but the initial request could be intercepted.

### 5. License Ping Leaks Extension ID and License Key
- **Severity:** LOW
- **File:** `js/background.js` (lines 243-284)
- **Code:**
  ```javascript
  var url = 'https://lping.ietab.net/logger/pingl?key=' + key + '&ext=' + id + '&hv=' + helperVersion + '&rt=0';
  ```
- **Verdict:** Daily license ping sends extension ID, license key, and helper version to `lping.ietab.net`. This is standard license validation behavior and uses HTTPS. The license key in URL parameters could appear in server logs but this is a common pattern for license verification.

### 6. License Data Sent to ietab.net via Image Pixel
- **Severity:** LOW
- **File:** `js/background.js` (lines 371-376)
- **Code:**
  ```javascript
  saveNewLicensee: function(data) {
      Settings.set('licensee', data.email);
      var img = new Image();
      img.src = 'https://www.ietab.net/logger/wslicense?info=' + encodeURIComponent(JSON.stringify(data));
  }
  ```
- **Verdict:** User email and license data sent to ietab.net via tracking pixel. This occurs only during explicit license validation flow initiated by the user, not silently. Standard for license management.

### 7. Google OAuth Token Used for License Validation
- **Severity:** LOW
- **File:** `js/background.js` (lines 378-413)
- **Code:**
  ```javascript
  chrome.identity.getAuthToken({ interactive: true }, function(token) {
      var req = new XMLHttpRequest();
      req.open('GET', CWS_LICENSE_API_URL + chrome.runtime.id);
      req.setRequestHeader('Authorization', 'Bearer ' + token);
  ```
- **Verdict:** Uses Chrome Web Store license API with Google OAuth. The token is also used to fetch user email for license tracking. This is the standard CWS licensing pattern.

### 8. Firebase API Key Exposed
- **Severity:** LOW (Known FP)
- **File:** `js/remhost_manager.js` (line 22)
- **Code:**
  ```javascript
  FIREBASE_API_KEY: 'AIzaSyAYdB3iIRB7ZVDDiBLX8_g4tc6hzdDCeFM',
  ```
- **Verdict:** Firebase public API key. These are designed to be public and are restricted by Firebase security rules. Not a vulnerability.

## False Positive Table

| Pattern | Location | Reason |
|---------|----------|--------|
| Firebase public API key | `remhost_manager.js:22` | Firebase API keys are public by design |
| Google Analytics tracking | `gatracking.js` | GA tracking code is commented out (`// ga('send', ...)`) -- not active |
| `importScripts()` in service worker | `background.js:1213-1244` | Standard MV3 service worker pattern for loading scripts |
| `document.createElement('script')` | `extapi_cs.js:36`, `ietabapi_cs.js:93` | Injecting extension's own web-accessible scripts into pages |
| `window.postMessage` | Multiple CS/WP files | Standard content-script to web-page communication pattern with origin checks |
| Cookie access | `cookies.js` | Session cookie sharing between IE engine instances -- core functionality |
| `chrome.cookies.set` for JWT | `remhost_manager.js:287-294` | Setting auth cookie for hosted IE Tab service on ietab.net domain |
| `<all_urls>` host permission | `manifest.json` | Required for URL interception/redirection -- core functionality |
| `webRequest`/`webRequestBlocking` | `manifest.json` | Required for auto-URL interception before navigation |
| Native messaging | Throughout | Core functionality -- communicates with IE Tab helper process |
| `chrome.tabs.query({})` | Multiple | Used for broadcasting messages to IE Tab container pages |

## API Endpoints Table

| Endpoint | Purpose | Data Sent |
|----------|---------|-----------|
| `https://lping.ietab.net/logger/pingl` | Daily license ping | License key, extension ID, helper version |
| `https://www.ietab.net/logger/wslicense` | License registration | User email, license data (JSON) |
| `https://www.googleapis.com/oauth2/v1/userinfo` | Get user email for license | Google OAuth token |
| `https://www.googleapis.com/chromewebstore/v1.1/userlicenses/` | CWS license validation | Google OAuth token |
| `https://securetoken.googleapis.com/v1/token` | Firebase JWT refresh | Refresh token |
| `https://hub.ietab.net/hubapi/userslots` | Remote host slot assignment | JWT cookie (authenticated) |
| `https://dynamodb.{region}.amazonaws.com/ping` | Datacenter latency test | Ping only (no user data) |
| `http://www.ietab.net/hostedfirstrun` | First-run page (hosted mode) | None (navigation only) |
| `http://www.ietab.net/thanks-installing-ie-tab` | First-run page (local mode) | None (navigation only) |
| `http://www.ietab.net/ie-tab-alternatives` | Uninstall survey | None (navigation only) |
| `net.ietab.ietabhelper.peruser` / `.perbox` | Native messaging host | IE Tab configuration, URLs, cookies |

## Data Flow Summary

1. **URL Interception:** The extension intercepts navigation via `declarativeNetRequest` session rules and `webRequest.onBeforeRequest`. Matched URLs are redirected to the extension's `nhc.htm` (native host container) or `redir.htm` intermediate page, which then opens the URL in the IE rendering engine via native messaging.

2. **Native Host Communication:** On Windows, the extension communicates with `ietabhelper.dat` (native host) via `chrome.runtime.connectNative()`. Messages include configuration (compatibility mode, settings), version checks, and cookie synchronization. The native host renders pages using IE's Trident engine.

3. **Remote Host (Hosted Mode):** On non-Windows platforms, the extension connects to `hub.ietab.net` to obtain an RDP session to a remote Windows server. Communication uses Myrtille (open-source HTML5 RDP client) over WebSocket/long-polling. A Firebase JWT handles authentication.

4. **Cookie Sync:** Session cookies from IE-rendered pages are captured by the native host, sent to the extension via native messaging, stored in `chrome.storage.session`, and broadcast to all other active native host instances.

5. **License Validation:** Daily ping to `lping.ietab.net` with license key. Optional CWS license validation via Google OAuth. License data stored locally.

6. **Enterprise Configuration:** Settings can be managed via Windows Group Policy (read from registry via native host), Chrome managed storage, or local extension storage. GPO settings refresh every 10 minutes.

7. **Extension API:** `ietab.net` web pages can communicate with the extension via `postMessage` (through content scripts), allowing the website to read/set extension settings. The IETabApi allows any website to request API access (with user prompt), enabling programmatic IE Tab opening.

## Overall Risk Assessment

**CLEAN**

IE Tab is a legitimate, long-standing browser extension that requires extensive permissions to fulfill its core purpose of rendering web pages in Internet Explorer's engine. The permissions surface is large but justified:

- `<all_urls>` + `webRequest` + `declarativeNetRequestWithHostAccess`: Required for URL interception and redirection
- `nativeMessaging`: Required for communication with the IE rendering helper
- `cookies`: Required for cookie synchronization between Chrome and IE sessions
- `tabs`: Required for URL redirection and container page management
- `storage`: Required for settings persistence

The code is unobfuscated, well-structured, and thoroughly commented. There is no evidence of:
- Data exfiltration beyond license validation
- Ad or coupon injection
- Residential proxy behavior
- Remote code execution or dynamic code loading from external sources
- Extension enumeration or killing
- Market intelligence SDK injection
- Keylogging or credential harvesting

The moderate security concerns (externally_connectable `ids: "*"`, arbitrary method dispatch) represent architectural design choices that could be hardened but do not indicate malicious intent. The HTTP URLs for first-run pages are a minor hygiene issue.
