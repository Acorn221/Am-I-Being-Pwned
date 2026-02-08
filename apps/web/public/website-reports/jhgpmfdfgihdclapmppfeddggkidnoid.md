# Security Analysis Report: AdSparo - AdLibrary Ad Finder & Ad spy Tool

## Extension Metadata
- **Extension Name**: AdSparo - AdLibrary Ad Finder & Ad spy Tool
- **Extension ID**: jhgpmfdfgihdclapmppfeddggkidnoid
- **Version**: 1.0.20
- **User Count**: ~100,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

AdSparo is a legitimate marketing intelligence tool designed to help users browse and analyze Facebook ads from the Ad Library. The extension provides filtering capabilities, ad data extraction, and integration with the adsparo.com service.

**Overall Risk Level: MEDIUM**

The extension exhibits several security concerns primarily related to cookie access, JWT token handling, and data exfiltration to external servers. While the core functionality appears legitimate (Facebook Ad Library enhancement), the implementation raises privacy and security concerns around credential handling and user tracking.

## Vulnerability Details

### 1. JWT Token Cookie Harvesting - MEDIUM Severity

**Location**: `background.js` lines 1-12, 16-31

**Description**: The extension monitors and extracts JWT authentication cookies from adsparo.com and stores them in local storage.

**Code Evidence**:
```javascript
function checkUserLogin(e, o, t) {
  var r = t;
  chrome.cookies.get({
    url: host + "/adspy/index.php",
    name: "jwt"
  }, function(e) {
    var o = e && e.value ? e.value : 0;
    r({
      farewell: o
    })
  })
}

chrome.cookies.onChanged.addListener(function(e) {
  try {
    var o = host.match(/^https?\:\/\/([^\/?#]+)(?:[\/?#]|$)/i),
      t = o && o[1];
    if (t) {
      let o = e.cookie.domain;
      if (-1 !== o.indexOf(t)) {
        let o;
        "jwt" == e.cookie.name && (o = e.removed ? 0 : e.cookie.value, chrome.storage.local.set({
          jwt: o
        }, function() {}))
      }
    }
  } catch (e) {
    console.log("EXCEPTION :" + e.message)
  }
})
```

**Verdict**: MEDIUM RISK - While the extension only accesses cookies from its own domain (adsparo.com), the JWT token harvesting pattern is concerning. The extension could potentially access user authentication tokens. However, this appears limited to the extension's own service authentication rather than stealing third-party credentials.

### 2. Unauthorized Auto-Navigation on Install/Update - MEDIUM Severity

**Location**: `background.js` lines 32-50

**Description**: Extension automatically opens new tabs without user consent on installation and updates, sending installation tracking data to remote servers.

**Code Evidence**:
```javascript
chrome.runtime.onInstalled.addListener(function(e) {
  if ("install" == e.reason) {
    var o = chrome.runtime.getManifest().version;
    let e = host + "/adspy/chrome.php?install=1&version=" + o;
    chrome.tabs.create({
      url: e
    }), chrome.tabs.create({
      url: adlibrary
    })
  } else if ("update" == e.reason) {
    o = chrome.runtime.getManifest().version;
    console.log("Updated from " + e.previousVersion + " to " + o + "!");
    chrome.storage.local.set({
      status: !0
    }, function() {});
    let t = host + "/adspy/chrome.php?update=1&version=" + o;
    chrome.tabs.create({
      url: t
    })
  }
})

chrome.runtime.setUninstallURL(host + "/adspy/chrome.php?uninstall=1")
```

**Verdict**: MEDIUM RISK - Automatically opening tabs and pinging tracking endpoints on install/update/uninstall without user consent is intrusive. This sends installation telemetry to adsparo.com servers, potentially tracking extension usage patterns.

### 3. Data Exfiltration to External Server - MEDIUM Severity

**Location**: `ContentScript.js` (minified), `popup/popup.js` lines 2-12, 15-39

**Description**: Extension extracts Facebook ad data and sends it to adsparo.com APIs with user JWT tokens.

**API Endpoints Identified**:
- `https://adsparo.com/api/media/multicreate.php` - Create multiple ad records
- `https://adsparo.com/api/page/create.php` - Create page records
- `https://adsparo.com/api/favorited/createua.php` - Favorite ads
- `https://adsparo.com/api/user/checkj.php` - Validate JWT token
- `https://adsparo.com/api/user/note.php` - Fetch user notes/config
- `https://adsparo.com/api/media/getadbydomain.php` - Get ads by domain

**Code Evidence**:
```javascript
let o = myhost + "/api/media/multicreate.php",
  d = myhost + "/api/page/create.php",
  c = myhost + "/api/favorited/createua.php",
  u = myhost + "/adspy/favorite.php",
  g = myhost + "/adspy/login.php",
  h = myhost + "/api/user/checkj.php"
```

**Verdict**: MEDIUM RISK - The extension legitimately extracts Facebook Ad Library data (which is already public) and sends it to adsparo.com servers. This appears to be the core functionality. However, users should be aware that their browsing patterns on Facebook Ad Library are being tracked and sent to third-party servers.

### 4. Excessive Permissions for Scope - LOW Severity

**Location**: `manifest.json` lines 7, 34

**Description**: Extension requests `cookies` permission and host permissions to adsparo.com.

**Code Evidence**:
```json
"permissions": ["activeTab", "storage", "cookies"],
"host_permissions": ["*://adsparo.com/"]
```

**Verdict**: LOW RISK - The `cookies` permission is used only for adsparo.com JWT authentication. The scope is limited to the extension's own domain, not all sites. The `activeTab` permission is appropriately scoped.

### 5. Potential XSS via innerHTML Assignment - LOW Severity

**Location**: `popup/popup.js` line 222

**Description**: User-controlled domain names are inserted into the DOM via innerHTML without sanitization.

**Code Evidence**:
```javascript
"string" == typeof s && s.indexOf(".") > -1 && (document.getElementById("domainname").innerHTML = s, formdata = {
  weblink: s
})
```

**Verdict**: LOW RISK - While innerHTML is used, the input comes from the browser's current tab URL hostname, which is already trusted. The domain extraction logic includes basic validation. This is a false positive in most contexts, though stricter sanitization would be better practice.

### 6. Overly Permissive Web Accessible Resources - LOW Severity

**Location**: `manifest.json` lines 8-13

**Description**: All resources are made web accessible to all URLs.

**Code Evidence**:
```json
"web_accessible_resources": [
  {
    "resources": ["*"],
    "matches": ["<all_urls>"]
  }
]
```

**Verdict**: LOW RISK - This configuration allows any website to detect the extension's presence and access its resources. This could enable extension fingerprinting but doesn't expose sensitive functionality.

### 7. Remote Configuration Control - LOW Severity

**Location**: `ContentScript.js` line 43 (minified section referencing `/api/user/note.php`)

**Description**: Extension fetches remote configuration from adsparo.com that can modify extension behavior, including disabling features and changing DOM selectors.

**Code Evidence** (from deobfuscated ContentScript):
```javascript
$.ajax({
  url: myhost + "/api/user/note.php",
  headers: {"content-type": "text/plain;charset=UTF-8"},
  success: function(e) {
    if ("1" == e.success) {
      e.mydata.note.shownote && ($("#messagebar").first().html(e.mydata.note.info),
      $("#notebar").first().removeClass("hidden")),
      C = e.mydata.removeoneuse,
      e.mydata.tags.changetags && (
        T = e.mydata.tags.ad_description,
        j = e.mydata.tags.ad_thumbnail,
        // ... more DOM selector overrides
      ),
      (R = e.mydata.disable.disabled) && ea(!1);
      // ... extension can be remotely disabled
    }
  }
})
```

**Verdict**: LOW RISK - Remote configuration is common in extensions but poses risk if the server is compromised. The extension can be remotely disabled or have its behavior modified. However, this appears limited to UI/UX adjustments rather than malicious capabilities.

## False Positives

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| jQuery innerHTML usage | `jquery.js` various | Standard jQuery library internals, not exploitable in this context |
| MutationObserver in initialize.js | `initialize.js` entire file | Third-party library (jquery.initialize) for DOM change detection, legitimate use |
| chrome.storage usage | Multiple files | Standard extension storage for settings and JWT caching |
| $.ajax in popup | `popup/popup.js` | Legitimate API calls to extension's own backend service |

## API Endpoints Summary

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| `/api/media/multicreate.php` | Bulk create ad records | Ad ID, description, thumbnail, CTA links, country | Medium |
| `/api/page/create.php` | Create page records | Page username, title, image | Medium |
| `/api/favorited/createua.php` | Save favorite ads | Ad data with JWT auth | Medium |
| `/api/user/checkj.php` | Validate JWT token | JWT token | Low |
| `/api/user/note.php` | Fetch remote config | None (GET request) | Low |
| `/api/media/getadbydomain.php` | Get ads by domain | Domain name | Low |
| `/adspy/chrome.php` | Track install/update/uninstall | Extension version, event type | Medium |

## Data Flow Summary

1. **Installation Flow**:
   - Extension installed → Sends version to `/adspy/chrome.php?install=1&version=X`
   - Opens Facebook Ad Library in new tab
   - Opens adsparo.com login/dashboard page

2. **Authentication Flow**:
   - User logs into adsparo.com
   - JWT cookie is set by adsparo.com
   - Background script monitors cookie changes and copies JWT to `chrome.storage.local`
   - Popup and content scripts read JWT from storage for API authentication

3. **Facebook Ad Library Enhancement Flow**:
   - Content script injects on `facebook.com/ads/library/*`
   - Parses ad cards from DOM (ad ID, description, images, page info, etc.)
   - Sends extracted data to adsparo.com APIs with JWT auth
   - Displays enhanced UI with filtering, favorite buttons, and statistics

4. **Popup Flow**:
   - User opens popup on any website
   - Extension extracts current domain
   - Queries adsparo.com API for ads related to that domain
   - Displays results with download/edit/favorite options

## Privacy Concerns

1. **Browsing History Tracking**: The extension tracks which Facebook ads users view and sends this data to adsparo.com servers.

2. **Domain Tracking**: When users open the popup, the current website domain is sent to adsparo.com, potentially tracking browsing patterns.

3. **No Clear Privacy Policy**: The extension doesn't appear to have a visible privacy policy link in the popup or manifest.

4. **JWT Token Storage**: Authentication tokens are stored in local storage, which could be accessed by other malicious extensions with storage permissions.

## Recommendations

**For Users**:
- Understand that your Facebook Ad Library browsing activity is tracked and sent to adsparo.com
- Review the extension's privacy policy on adsparo.com before use
- Be aware of automatic tab opening on install/update

**For Developers**:
- Implement Content Security Policy (CSP) in manifest
- Use `textContent` instead of `innerHTML` for user-controlled data
- Restrict web_accessible_resources to specific files rather than wildcard
- Add privacy policy link in popup UI
- Consider user consent before auto-opening tabs on install
- Implement token encryption for stored JWT

## Overall Risk Assessment

**Risk Level: MEDIUM**

The extension is a legitimate marketing intelligence tool with a clear purpose. The primary security concerns are:

1. **Privacy implications** of tracking user behavior on Facebook Ad Library and current browsing domains
2. **JWT token harvesting** and storage, though limited to the extension's own authentication
3. **Intrusive install behavior** with automatic tab opening and tracking
4. **Remote configuration** that could modify extension behavior

The extension does NOT exhibit:
- Credential theft from Facebook or other sites
- Keylogging or form field interception
- Ad injection or content manipulation beyond Facebook Ad Library
- Cryptocurrency mining or residential proxy behavior
- Extension enumeration or killing of security software

**Verdict**: The extension is NOT malware but has MEDIUM privacy and security concerns. Users should be aware that their ad browsing patterns are tracked. The extension is suitable for marketing professionals who understand and accept this data collection.
