# Security Analysis Report: Infinite Dashboard

## Extension Metadata

- **Extension Name**: Infinite Dashboard - New Tab like no other
- **Extension ID**: meffljleomgifbbcffejnmhjagncfpbd
- **Version**: 4.1.1
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Infinite Dashboard is a new tab replacement extension that integrates ChatGPT functionality, custom bookmarks, and various productivity features. The extension exhibits **HIGH-RISK behavior** due to its extensive cookie harvesting capabilities, particularly targeting OpenAI/ChatGPT session data. While the extension's stated functionality includes ChatGPT integration, the implementation involves extracting and transmitting authentication cookies from chat.openai.com to facilitate API access, which represents a significant privacy and security concern. Additionally, the extension collects remote configuration from its backend API, modifies HTTP headers for OpenAI requests, and executes scripts across all websites.

**Risk Level: HIGH**

## Vulnerability Details

### 1. ChatGPT Cookie Harvesting and Session Hijacking

**Severity**: HIGH
**Files**: `js/background.js` (lines 1558-1689, 11682-11695)
**Code Evidence**:

```javascript
// Line 1558-1565: Harvesting ALL cookies from chat.openai.com
return _context7.next = 11, chrome.cookies.getAll({
    url: "https://chat.openai.com/"
});

case 11:
    return cookie = _context7.sent.map((function(cookie) {
        return "".concat(cookie.name, "=").concat(cookie.value);
    })).join("; "), _context7.next = 14, fetch("https://chat.openai.com/api/auth/session", {
        headers: {
            Cookie: cookie
        }
    });

// Line 11682-11695: Second instance of cookie harvesting
return _context17.next = 25, chrome.cookies.getAll({
    url: "https://chat.openai.com/"
});

case 25:
    return cookie = _context17.sent.map((function(cookie) {
        return "".concat(cookie.name, "=").concat(cookie.value);
    })).join("; "), _context17.next = 28, chrome.cookies.get({
        url: "https://openai.com/",
        name: "oai-did"
    });
```

**Verdict**: The extension systematically collects ALL cookies from chat.openai.com and uses them to authenticate API requests. While this is used for legitimate ChatGPT integration features, it represents sensitive data access. The extension extracts:
- All session cookies from chat.openai.com
- The oai-did (OpenAI device ID) cookie from openai.com
- Access tokens via `/api/auth/session` endpoint

This cookie data is used to make authenticated requests to OpenAI's backend API on behalf of the user, which could enable session hijacking if the extension were compromised.

### 2. Remote Configuration with Dynamic Code Execution Potential

**Severity**: MEDIUM
**Files**: `js/background.js` (lines 13395-13409)
**Code Evidence**:

```javascript
value: function() {
    var _this3 = this, $self = this, now = (chrome.runtime.getManifest().version, (new Date).getTime()), diff = now - this.config.mTime;
    this.config.mTime = now, diff < 12e5 && (this.config.lTime += diff), chrome.storage.local.set({
        config: this.config
    }), fetch("https://infinitetab.com/api/").then((function(resp) {
        return resp.json();
    })).then((function(res) {
        if (res) {
            for (var i in res) _this3.config[i] = res[i];
            chrome.storage.local.set({
                config: _this3.config
            }, (function() {}));
        }
    })), setTimeout((function() {
        $self.updateConfig();
    }), 9e5);
}
```

**Verdict**: The extension fetches configuration from `https://infinitetab.com/api/` every 15 minutes (900000ms) and dynamically updates local configuration values without validation. While no direct code execution was observed, this pattern allows the remote server to modify extension behavior. The config object could potentially include API endpoints, feature flags, or other parameters that influence extension functionality.

### 3. HTTP Header Manipulation for OpenAI Requests

**Severity**: MEDIUM
**Files**: `rules_1.json` (lines 1-46)
**Code Evidence**:

```json
{
  "id": 1,
  "action": {
    "type": "modifyHeaders",
    "requestHeaders": [
      {
        "operation": "set",
        "header": "origin",
        "value": "https://chat.openai.com"
      },
      {
        "operation": "set",
        "header": "referer",
        "value": "https://chat.openai.com"
      }
    ]
  },
  "condition": {
    "requestDomains": ["chat.openai.com"],
    "resourceTypes": ["xmlhttprequest"]
  }
}
```

**Verdict**: The extension modifies request headers (Origin and Referer) for XMLHttpRequests to chat.openai.com and tcr9i.chat.openai.com. This is done to bypass CORS restrictions when making API calls to OpenAI from the extension context. While this enables the ChatGPT integration feature, it could potentially be used to circumvent security controls.

### 4. Content Script Injection on All URLs

**Severity**: MEDIUM
**Files**: `manifest.json` (lines 15-25), `js/content.js`
**Code Evidence**:

```json
"content_scripts": [
    {
        "css": ["css/content.css"],
        "matches": ["<all_urls>"],
        "js": ["js/content.js"]
    },
    {
        "matches": ["<all_urls>"],
        "js": ["js/search-helper.js"]
    }
]
```

**Verdict**: The extension injects content scripts on ALL websites (`<all_urls>`). Analysis of `content.js` shows it implements a sidebar for bookmarks. The `search-helper.js` file is 26,729 lines (1.7MB) and contains bundled React code. While the observed functionality appears benign (bookmark sidebar display), the broad injection pattern increases attack surface. The content script does not appear to scrape page data, intercept forms, or perform keylogging based on pattern analysis.

### 5. Dynamic Script Execution Capabilities

**Severity**: MEDIUM
**Files**: `js/background.js` (lines 13232-13246, 13316-13319)
**Code Evidence**:

```javascript
// On install, inject scripts into all existing tabs
chrome.tabs.query({}, (function(tabs) {
    for (var i = 0; i < tabs.length; i++) matchUrl(tabs[i].url) && (chrome.scripting.executeScript({
        target: {
            tabId: tabs[i].id
        },
        files: [ "./js/content.js" ]
    }, (function() {
        chrome.runtime.lastError;
    })), chrome.scripting.insertCSS({
        target: {
            tabId: tabs[i].id
        },
        files: [ "./css/content.css" ]
    }

// For bookmark preview tabs
chrome.scripting.executeScript({
    target: {
        tabId: tab.id
    },
```

**Verdict**: The extension uses `chrome.scripting.executeScript` to inject scripts into tabs dynamically. This is used for legitimate purposes (enabling bookmark sidebar and preview functionality), but represents elevated privileges that could be abused if the extension were compromised.

### 6. OpenAI API Authentication Token Extraction

**Severity**: HIGH
**Files**: `js/background.js` (lines 1584-1594)
**Code Evidence**:

```javascript
if ((data = _context7.sent).accessToken) {
    _context7.next = 22;
    break;
}
throw new Error("UNAUTHORIZED");

case 22:
    return _context7.next = 24, Object(app_background_modules_config_index_js__WEBPACK_IMPORTED_MODULE_10__.setAccessToken)(data.accessToken);

case 24:
    return _context7.abrupt("return", data.accessToken);
```

**Verdict**: The extension extracts and stores OpenAI access tokens from the `/api/auth/session` endpoint. These tokens are stored locally and reused for making authenticated requests to OpenAI's backend API. This allows the extension to act as the user when communicating with ChatGPT, which could enable unauthorized API usage if tokens were exfiltrated.

### 7. Installation Telemetry to Remote Server

**Severity**: LOW
**Files**: `js/background.js` (lines 13417-13421)
**Code Evidence**:

```javascript
chrome.runtime.onInstalled.addListener((function(e) {
    fetch(app_util_api_js__WEBPACK_IMPORTED_MODULE_0__.API + "/jek/?vk=" + e.reason).then((function(reply) {
        return reply.json();
    })).then(app_util_functions_js__WEBPACK_IMPORTED_MODULE_1__.showNewFeaturesIfSet);
}));
```

**Verdict**: On installation/update, the extension sends a request to `https://infinitetab.com/api/jek/?vk=[reason]` where reason is the installation trigger (install, update, etc.). The response can trigger opening a new tab to show features. This is standard telemetry but does represent external communication.

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| `Function("r", "regeneratorRuntime = r")(runtime)` | background.js:189 | Babel regenerator runtime polyfill - standard transpilation artifact |
| `Function("return this")()` | background.js:696, 710 | Lodash/utility library pattern for getting global object reference |
| `atob()` / `btoa()` | background.js:116, 11766 | Base64 encoding/decoding for image processing and WebSocket data parsing - legitimate use |
| React `innerHTML` patterns | search-helper.js (React bundle) | React DOM manipulation - standard library functionality |
| `setTimeout` / `setInterval` | Multiple locations | Standard timer functions, not dynamic code execution |
| `String.fromCharCode` | background.js (multiple) | Buffer manipulation for OpenAI proof-of-work implementation - legitimate crypto/encoding |

## API Endpoints and External Communications

| Endpoint | Purpose | Data Transmitted | Risk Level |
|----------|---------|------------------|------------|
| `https://infinitetab.com/api/` | Remote configuration | None (GET request), receives config updates | MEDIUM |
| `https://infinitetab.com/api/jek/?vk=[reason]` | Installation telemetry | Installation reason (install/update/etc.) | LOW |
| `https://infinitetab.com/uninstall.html` | Uninstall survey | Set as uninstall URL | LOW |
| `https://chat.openai.com/api/auth/session` | ChatGPT authentication | Harvested cookies from chat.openai.com | HIGH |
| `https://chat.openai.com/backend-api/*` | ChatGPT API proxy | User prompts, conversation data, access tokens | HIGH |
| `https://api.openai.com/v1/chat/completions` | OpenAI API (API key mode) | User prompts, API key | HIGH |
| `https://mini.s-shot.ru/1366x890/400/jpeg/?[url]` | Screenshot service | URLs for bookmark preview generation | MEDIUM |

## Data Flow Summary

1. **ChatGPT Integration Flow**:
   - Extension requests optional `cookies` permission
   - When ChatGPT feature is used, extension harvests ALL cookies from chat.openai.com
   - Cookies sent to OpenAI's session endpoint to extract access token
   - Access token stored in `chrome.storage.local`
   - User ChatGPT conversations proxied through extension with stolen credentials
   - Conversation data (prompts, responses, conversation IDs) handled by extension

2. **Remote Configuration Flow**:
   - Every 15 minutes, extension fetches JSON from `https://infinitetab.com/api/`
   - Response merged into local config object without validation
   - Updated config stored in `chrome.storage.local`
   - Config values can influence ChatGPT API endpoints, feature availability

3. **Bookmark/Sidebar Flow**:
   - Content scripts injected on all websites
   - Bookmarks stored in `chrome.storage.local`
   - Sidebar dynamically generated with bookmark links and favicons
   - Screenshot service contacted for bookmark previews (third-party service)

4. **HTTP Header Modification**:
   - Declarative Net Request rules modify Origin/Referer headers
   - Applied to XMLHttpRequests targeting chat.openai.com domains
   - Enables CORS bypass for ChatGPT API calls from extension context

## Overall Risk Assessment

**RISK LEVEL: HIGH**

### Critical Concerns:
1. **Cookie Harvesting**: Systematic extraction of ALL cookies from chat.openai.com represents sensitive credential access
2. **Access Token Theft**: OpenAI access tokens extracted and stored, enabling session hijacking scenarios
3. **Broad Permissions**: Combination of `<all_urls>` content scripts, scripting permission, and cookies permission creates extensive attack surface
4. **Remote Configuration**: Unvalidated remote config updates could modify extension behavior dynamically
5. **Header Manipulation**: CORS bypass capabilities through header modification

### Mitigating Factors:
- Extension's ChatGPT integration is a stated feature, making cookie access expected (though not justified)
- No evidence of data exfiltration beyond the declared ChatGPT integration functionality
- No keyloggers, form interceptors, or credential stealers detected in content scripts
- No market intelligence SDKs (Sensor Tower, Pathmatics, etc.) detected
- No residential proxy infrastructure
- No extension enumeration/killing behavior

### Recommendations:
1. Users should carefully consider whether ChatGPT integration justifies granting access to OpenAI session credentials
2. The optional `cookies` permission should only be granted if ChatGPT features are desired
3. Remote configuration mechanism should validate/sanitize server responses
4. Content script injection scope should be limited to specific domains where sidebar is needed
5. Cookie access should be scoped to minimum necessary (specific cookie names vs. getAll())

## Conclusion

While Infinite Dashboard provides legitimate new tab customization and ChatGPT integration features, it employs HIGH-RISK techniques including comprehensive cookie harvesting, access token extraction, and remote configuration updates. The extension's broad permissions (all_urls, cookies, scripting) combined with OpenAI credential access creates significant security and privacy implications. Users of this extension are effectively granting it full access to their ChatGPT sessions, which could be abused if the extension developer's infrastructure were compromised or if the extension changed ownership.

The extension does not appear to be overtly malicious but represents a **high-privilege implementation** of features that could be accomplished with more privacy-preserving approaches.
