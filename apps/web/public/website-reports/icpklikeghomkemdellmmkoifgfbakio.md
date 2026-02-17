# Security Analysis Report: anonymoX

**Extension ID:** `icpklikeghomkemdellmmkoifgfbakio`
**Version:** 1.7.8
**Manifest Version:** 3
**Users:** ~300,000
**Triage Classification:** SUSPECT (2 T1, 0 T2, 2 T3)

---

## Executive Summary

**Risk Level: LOW**

anonymoX is a legitimate proxy/VPN browser extension developed by a German company (anonymox.net). The extension provides HTTP/HTTPS proxy routing through their own gateway servers, with a freemium model (free tier + premium tier). The codebase is well-structured, uses Apache Thrift RPC for backend communication, and is not obfuscated. The triage flags (2 T1, 2 T3) are all **false positives** arising from standard UI code patterns and the Thrift library. There are no signs of malicious behavior such as data exfiltration, credential harvesting, keylogging, extension enumeration, or dynamic code injection.

---

## Triage Flag Verdicts

### T1 Flags (2 total)

| # | Flag Pattern | Location | Verdict | Explanation |
|---|---|---|---|---|
| 1 | `innerHTML` usage | `js/ui/popup.js:74`, `js/ui/gateway_list.js:98`, `js/ui/country_list.js:20` | **FALSE POSITIVE** | Used exclusively in popup UI code to render i18n translated text and to clear/rebuild gateway and country lists in the extension's own popup. The data source is `chrome.i18n.getMessage()` (trusted) or empty string clearing. No user-controlled or external data is injected via innerHTML. |
| 2 | `eval()` in Thrift library | `js/network/thrift.js:1096` | **FALSE POSITIVE** | This is the standard Apache Thrift JavaScript library (v0.20.0, Apache License 2.0). The `eval()` is a dead-code fallback in `readMessageBegin()` that only triggers if neither `JSON.parse` nor `jQuery.parseJSON` exist -- which never happens in any modern browser. It parses the extension's own Thrift RPC response, not external untrusted content. |

### T3 Flags (2 total)

| # | Flag Pattern | Location | Verdict | Explanation |
|---|---|---|---|---|
| 1 | `document.getElementById` / `querySelector` usage in content scripts | `js/contentscript/premiumlistener.js:1` | **FALSE POSITIVE** | This content script runs only on `anonymox.net` pages and looks for a single element (`#activateBtn`) to enable one-click premium activation. It does not scrape page content or harvest data. |
| 2 | jQuery injected on `<all_urls>` | manifest.json content_scripts (lines 43-241, 242-437) | **MINOR CONCERN** -- see detailed analysis below | jQuery 3.7.1 is injected as a content script on all URLs (except Google search pages). However, no accompanying content script logic is loaded alongside it. The `content_script.js` that contains ad-loading code is only injected programmatically via `chrome.scripting.executeScript` and only when `ADS_ENABLED` is set to `true`, which is hardcoded to `false`. This appears to be vestigial/unused infrastructure. |

---

## Architecture Overview

### File Structure
```
js/
  app.js                          -- Service worker entry point (module)
  listener.js                     -- Event listeners, message routing, alarms
  config.js                       -- Configuration constants
  network.js                      -- High-level network functions (getInfo, authPing)
  ad_cache.js                     -- Tab-based ad cache (currently unused)
  content_script.js               -- Ad content script (disabled, not auto-loaded)
  contentscript/
    premiumlistener.js            -- Premium activation button on anonymox.net
  network/
    thrift.js                     -- Apache Thrift JS library (v0.20.0)
    fetch_transport.js            -- Custom Thrift transport using fetch API
    client_types.js               -- Thrift-generated type definitions
    ClientService.js              -- Thrift-generated client service stubs
    state_initialization.js       -- Credential loading/initialization
    website_comm.js               -- Custom header injection for anonymox.net
  proxy/
    proxy.js                      -- PAC script proxy management
  storage/
    local.js                      -- chrome.storage.local wrapper
    session.js                    -- chrome.storage.session wrapper
  messaging/
    popup_handler.js              -- Popup message handlers
    options_handler.js            -- Options page message handlers
  helper/
    version_compare.js            -- Version comparison utilities
    storage_migration.js          -- MV2 to MV3 migration
    offscreen.js                  -- Offscreen document for localStorage migration
  ui/
    popup.js, country_list.js, gateway_list.js, status_toggle.js,
    icon.js, loading.js           -- Popup UI components
  libs/
    jquery-3.7.1.min.js           -- jQuery library
```

### Data Flow
1. On startup (`app.js`), the service worker clears existing proxy settings, loads persisted credentials from `chrome.storage.local`, and calls `Info7` on the backend to receive gateway list and configuration.
2. If no credentials exist, `GetAccount2` is called to obtain new anonymous credentials (user ID + password).
3. Gateway information is stored in session storage; the user selects a country/gateway via the popup.
4. When activated, a PAC script is set via `chrome.proxy.settings.set()` that routes traffic through the selected proxy gateway.
5. Proxy authentication is handled via `chrome.webRequest.onAuthRequired` using the stored credentials.
6. Every 15 minutes, gateway info is refreshed from the backend.

---

## Detailed Findings

### 1. Permissions Analysis

```json
"permissions": [
  "scripting",           -- Used for programmatic content script injection (ad system, currently disabled)
  "storage",             -- Extension state persistence
  "offscreen",           -- MV2->MV3 localStorage migration
  "alarms",              -- Periodic gateway refresh (15min)
  "activeTab",           -- Standard for popup-driven extensions
  "proxy",               -- Core functionality: PAC script proxy configuration
  "webRequest",          -- Proxy auth handler (onAuthRequired)
  "webRequestAuthProvider", -- Proxy auth credentials
  "declarativeNetRequest",  -- Custom header on anonymox.net requests
  "unlimitedStorage"     -- Large gateway lists
],
"host_permissions": [
  "http://*/*",
  "https://*/*"
]
```

**Assessment:** The permissions are broad but consistent with a proxy/VPN extension. The `http://*/*` and `https://*/*` host permissions are required for the PAC script proxy to function across all domains. The `webRequest` permission is used solely for `onAuthRequired` proxy authentication. `declarativeNetRequest` adds a single custom header (`X-AnonymoX-Capabilities: oneclickactivate`) to requests to `anonymox.net`.

### 2. Background Service Worker Analysis

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/app.js`

The service worker:
- Clears proxy on startup (line 10)
- Loads credentials and gateway data (lines 36-43)
- Calls `init()` to set up event listeners

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/listener.js`

Key observations:
- **Ad system is disabled:** `const ADS_ENABLED = false;` (line 17). The `webRequestListener` that would inject `content_script.js` is only registered when `ADS_ENABLED` is true (lines 74-79).
- **Hardcoded API key:** `const AGL_API_KEY = "safe-9e7h3845rc-shop"` (line 20) and `const AGL_CREATE_ARTICLE_ENDPOINT = "https://agentlemanslifestyle.com/wp-json/api/data"` (lines 18-19). These are declared but **never referenced anywhere in the code**. They appear to be dead code from a planned "SafeShop" feature.
- **Proxy auth handler** (lines 55-68): Registers `onAuthRequired` to automatically authenticate with proxy servers using stored credentials.
- **Periodic check** (lines 82-97): Every 15 minutes, refreshes gateway info from the backend.
- **DeclarativeNetRequest** (lines 99-123): Adds `X-AnonymoX-Capabilities: oneclickactivate` header to requests to `anonymox.net`.
- **onInstalled** (lines 196-213): Opens welcome page, initializes dismiss/approved lists, sets uninstall URL.

No evidence of:
- `chrome.management.getAll()` or `setEnabled()` (extension enumeration/killing)
- XHR/fetch monkey-patching
- Dynamic code loading from external sources
- Cookie access

### 3. Content Scripts Analysis

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/contentscript/premiumlistener.js`

```javascript
let buttonEl = document.getElementById("activateBtn");
if (buttonEl) {
  let port = chrome.runtime.connect({name: "premiumlistener"});
  buttonEl.addEventListener("click", function () {
    port.postMessage({
      activateCode: buttonEl.getAttribute("param1"),
    });
  });
}
```

This runs only on `https://anonymox.net/*` and `https://*.anonymox.net/*`. It simply listens for a click on the `#activateBtn` element to send a premium activation code to the background script. **No DOM scraping, keylogging, or data harvesting.**

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/content_script.js`

```javascript
const port = chrome.runtime.connect({name: "ad-channel"});
port.onMessage.addListener(handleMessage);
port.postMessage("load-ad");
```

This content script is **not automatically loaded**. It is only injected via `chrome.scripting.executeScript` when `ADS_ENABLED === true`, which is hardcoded to `false`. Even if it were loaded, it only logs messages and does not inject ads into pages. The `handleMessage` function body is entirely commented out.

**jQuery on all URLs:** jQuery 3.7.1 is loaded as a content script on all URLs. This is a standard library and by itself poses no security risk. No other content script code runs alongside it on arbitrary pages. This is likely legacy from the MV2 version or intended for the disabled ad system.

### 4. Proxy Configuration

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/proxy/proxy.js`

The proxy uses PAC scripts with proper exclusions:
- Direct connections for: plain hostnames, `anonymox.net`, `curopayments.net` (payment processor), `fritz.box`, `easy.box` (German router admin), `.spotilocal.com`, `127.0.0.1`
- Direct connections for RFC 1918 private IP ranges (192.168.x, 10.x, 172.16-31.x, etc.)
- All other traffic routed through the selected proxy gateway

The self-check mechanism (`authPing`) verifies connectivity through the proxy by routing only `.sc.nwi.anonymox.net` through the proxy first, then switching to full proxy mode.

### 5. Network Communication (Thrift RPC)

**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/network/fetch_transport.js`

All backend communication uses Apache Thrift binary protocol over HTTPS POST to `https://master.anonymox.net/chrome`. The API methods are:

| Method | Purpose | Data Sent |
|---|---|---|
| `GetAccount2` | Get anonymous credentials | referral code ID (default 0) |
| `Info7` | Get gateway list + config | user ID, password, client version, language |
| `ActivatePremium` | Activate premium code | code, user ID, password, language |
| `FreeTimeSync` | Sync free time usage | user ID, password, decrement flag |
| `FreeUserVerification` | Verify free user | user ID, password, verification ID+token |
| `Log` | Send log entry | type, section, message, user, versions |

**Assessment:** All communication is to first-party infrastructure. The data sent is limited to what is necessary for the VPN service. No browsing data, page content, or user-identifiable information (beyond the anonymous user ID) is transmitted.

---

## Network Map

| Domain | Protocol | Purpose | Evidence |
|---|---|---|---|
| `master.anonymox.net` | HTTPS (Thrift RPC) | Backend API server for gateway info, account management, premium activation | `js/config.js:39`, `js/network.js:12` |
| `nwi.anonymox.net` | HTTP | Network info endpoint | `js/config.js:40` |
| `sc.nwi.anonymox.net` | HTTP | Self-check domain (verifies proxy connectivity) | `js/config.js:41`, `js/network.js:18` |
| `*.anonymox.net` | HTTPS | Main website (welcome page, support, uninstall page) | `js/config.js:49` |
| `curopayments.net` | -- | Excluded from proxy (payment processor, direct connection) | `js/proxy/proxy.js:44` |
| `agentlemanslifestyle.com` | -- | **Dead code** - declared but never called | `js/listener.js:18-19` |
| Proxy gateway IPs | HTTP/HTTPS | Actual VPN proxy traffic routing | Dynamic, received from `Info7` response |

---

## Concerning Behaviors (Minor)

### 1. jQuery Injected on All URLs
**File:** `manifest.json:43-437`
**Severity:** Low

jQuery 3.7.1 is injected as a content script on `<all_urls>` (with Google search pages excluded in one set and included in another -- two separate injection sets). No application logic runs alongside it on arbitrary pages. This adds ~87KB of unused JavaScript to every web page, causing minor performance impact but no security risk. This is likely residual from the MV2 version or intended for the disabled ad system.

### 2. Dead Code: agentlemanslifestyle.com Endpoint
**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/listener.js:18-20`

```javascript
const AGL_CREATE_ARTICLE_ENDPOINT =
  "https://agentlemanslifestyle.com/wp-json/api/data";
const AGL_API_KEY = "safe-9e7h3845rc-shop";
```

These constants are declared but **never used anywhere** in the codebase. They appear related to a planned "SafeShop" feature (the uninstall URL references `/safeshop/uninstall/`). This is dead code with no runtime impact, but the presence of an API key for a third-party WordPress site is unusual.

### 3. eval() in Thrift Library
**File:** `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/network/thrift.js:1096`

```javascript
} else {
    this.robj = eval(received);
}
```

This is a dead-code fallback in the standard Apache Thrift 0.20.0 JavaScript library. The condition chain is: `JSONInt64.parse` -> `JSON.parse` -> `jQuery.parseJSON` -> `eval`. Since `JSON.parse` is available in all modern browsers, this branch is never reached. Additionally, the extension uses the custom `ThriftFetchTransport` which returns binary data, not JSON. The `eval` would only be reached in an impossibly old browser.

### 4. innerHTML Usage in Popup UI
**Files:**
- `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/ui/popup.js:74`
- `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/ui/gateway_list.js:98`
- `/home/acorn221/projects/cws-scraper/output/free_vpn_analysis/suspect/icpklikeghomkemdellmmkoifgfbakio/deobfuscated/js/ui/country_list.js:20`

In `popup.js:74`, innerHTML is used to set i18n text:
```javascript
el.innerHTML = text;
```
where `text` comes from `chrome.i18n.getMessage()` (trusted, from `_locales/` files).

In `gateway_list.js:98` and `country_list.js:20`, innerHTML is used to clear lists:
```javascript
this.idList.innerHTML = "";
this.countrySelectItems.innerHTML = "";
```

All usage is within the extension's own popup page, not in content scripts. No XSS risk.

---

## What the Extension Does NOT Do

- **No extension enumeration:** Does not use `chrome.management.getAll()` or `setEnabled()`
- **No cookie access:** Does not use `chrome.cookies` API or access `document.cookie`
- **No keylogging:** No `keydown`/`keypress`/`keyup` event listeners (except in jQuery library internals, which are not used maliciously)
- **No credential harvesting:** Does not scrape login forms or intercept POST data
- **No DOM scraping:** Content scripts do not read or exfiltrate page content
- **No ad injection** (currently): The ad system is hardcoded to disabled (`ADS_ENABLED = false`)
- **No XHR/fetch monkey-patching:** Does not intercept or modify web requests beyond proxy routing
- **No dynamic code loading:** Does not use `importScripts` with dynamic URLs or load remote scripts
- **No browsing history access:** Does not use `chrome.history` or `chrome.tabs` for surveillance
- **No data exfiltration:** Network communication is strictly limited to anonymox.net infrastructure for VPN functionality
- **No externally_connectable:** The manifest does not declare `externally_connectable`, so no external pages can message the extension

---

## Final Verdict

**Risk Level: LOW**

anonymoX is a legitimate proxy/VPN extension with a clean, well-organized, readable codebase. It uses standard technologies (Apache Thrift, jQuery, Chrome Proxy API) for its core VPN functionality. All four triage flags are false positives. The extension communicates exclusively with its own infrastructure (`anonymox.net`) using a well-defined Thrift RPC protocol that transmits only what is necessary for VPN service operation.

The only minor concerns are:
1. Injecting jQuery on all pages (performance waste, no security risk)
2. Dead code referencing a third-party WordPress API endpoint
3. The standard Thrift library containing a dead-code `eval()` fallback

None of these represent active threats. The extension does what it claims to do: provide proxy-based anonymous browsing through anonymoX's own gateway network.

**Recommendation:** Downgrade from SUSPECT to CLEAN/LOW. No further investigation needed.
