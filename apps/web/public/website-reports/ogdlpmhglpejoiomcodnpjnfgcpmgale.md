# Security Analysis Report: Custom Cursor for Chrome™

## Extension Metadata

- **Extension Name**: Custom Cursor for Chrome™
- **Extension ID**: ogdlpmhglpejoiomcodnpjnfgcpmgale
- **Version**: 3.3.5
- **User Count**: ~5,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Custom Cursor for Chrome™ is a legitimate cursor customization extension with **5 million users**. The extension allows users to apply custom cursor themes from a curated collection. Security analysis reveals that while the extension has **invasive permissions** and makes network calls to its backend, it operates **within the scope of its intended functionality**. The extension uses `localStorage` access in legacy code and injects content scripts on all pages, but does not exhibit malicious behavior such as data exfiltration, credential harvesting, or ad injection.

**Overall Risk Level**: **CLEAN**

The extension is invasive by design (requires `<all_urls>` to apply cursor styles), but serves its intended purpose without clear malicious behavior or exploitable vulnerabilities.

## Vulnerability & Security Findings

### 1. localStorage Access in Legacy Code

**Severity**: LOW
**Status**: FALSE POSITIVE (Legacy Code)
**File**: `/deobfuscated/libs/cursor_old.js`

**Details**:
The extension contains an older version of cursor library (`cursor_old.js`) that reads from `localStorage`:

```javascript
let csCursors = JSON.parse(localStorage.getItem('csCursors')),
    csPointers = JSON.parse(localStorage.getItem('csPointers'));
```

**Code Context** (lines 62-63):
```javascript
let csCursors = JSON.parse(localStorage.getItem('csCursors')),
    csPointers = JSON.parse(localStorage.getItem('csPointers'));
if (csCursors == null) csCursors = [];
if (csPointers == null) csPointers = [];
```

**Verdict**: This is a **false positive**. The file `cursor_old.js` appears to be legacy code not actively used by the extension. The active cursor library (`libs/cursor.js`) does not access localStorage and relies solely on `chrome.storage.local` API. This legacy code access is limited to reading user-specific cursor preferences with no evidence of accessing sensitive page data.

---

### 2. Content Script Injection on All URLs

**Severity**: MEDIUM (Expected Behavior)
**File**: `/deobfuscated/manifest.json`, `/deobfuscated/background.js`

**Details**:
The extension declares broad content script injection:

```json
"content_scripts": [{
   "all_frames": true,
   "js": ["content.js"],
   "matches": ["<all_urls>"]
}]
```

Additionally, on installation, the background script programmatically injects content scripts into all existing tabs:

**Code Context** (background.js, installation handler):
```javascript
chrome.tabs.query({}, (function(t){
    t.forEach((function(t){
        chrome.scripting.executeScript({
            target:{tabId:t.id},
            files:["content.js"]
        }, (function(){}))
    }))
}))
```

**Verdict**: **EXPECTED BEHAVIOR**. The extension's core functionality is to apply custom cursor styles to web pages, which inherently requires content script injection on all URLs. The content script (`content.js`) only manipulates CSS cursor styles via stylesheet injection and does not perform data harvesting or DOM manipulation beyond cursor customization. This is a standard pattern for cursor/theme extensions.

---

### 3. Network Communication with custom-cursor.com

**Severity**: LOW
**Files**: `/deobfuscated/background.js`

**Details**:
The extension makes network calls to the following endpoints:

1. **Installation tracking**:
   ```javascript
   chrome.tabs.create({
       url: "https://custom-cursor.com/successful_installation?utm_source=ext&utm_medium=install&utm_campaign=install_succesful"
   })
   ```

2. **Uninstall URL**:
   ```javascript
   chrome.runtime.setUninstallURL("https://custom-cursor.com/uninstall?utm_source=ext&utm_medium=uninstall&utm_campaign=uninstall")
   ```

3. **Notification API** (via alarm):
   ```javascript
   fetch("https://custom-cursor.com/api/notification/custom-cursor-helper/".concat(uid), {
       cors:"no-cors",
       method:"POST"
   })
   ```

4. **Collections data** (loaded locally from `/libs/collections.json`):
   ```javascript
   fetch("/libs/collections.json").then((function(t){return t.json()}))
   ```

**Verdict**: **CLEAN**. The network calls are limited to:
- Installation/uninstall tracking (standard analytics)
- Notification checks (appears to be for extension updates/announcements)
- Loading cursor collections from bundled JSON file

No user browsing data, credentials, or sensitive information is transmitted. The extension uses `cors: "no-cors"` which further limits data access from cross-origin responses.

---

### 4. Host Permissions: <all_urls>

**Severity**: MEDIUM (Required for Functionality)
**File**: `/deobfuscated/manifest.json`

**Details**:
```json
"host_permissions": ["*://*/*", "<all_urls>"]
```

**Verdict**: **REQUIRED FOR FUNCTIONALITY**. While invasive, this permission is necessary for the extension to apply custom cursor styles to all websites. The content script only injects CSS styles and does not access page content, cookies, or perform actions beyond cursor customization.

---

### 5. Dynamic Script Injection on Open Tabs

**Severity**: MEDIUM
**File**: `/deobfuscated/background.js`

**Details**:
On installation/update, the extension programmatically injects `content.js` into all currently open tabs:

```javascript
chrome.tabs.query({}, (function(t){
    t.forEach((function(t){
        chrome.scripting.executeScript({
            target:{tabId:t.id},
            files:["content.js"]
        })
    }))
}))
```

**Verdict**: **EXPECTED BEHAVIOR**. This is a common pattern for extensions that need to immediately apply functionality to existing tabs without requiring page reloads. The injected script only applies cursor styles and does not perform malicious actions.

---

### 6. Cursor Rotator Feature with Alarms

**Severity**: LOW
**File**: `/deobfuscated/background.js`

**Details**:
The extension implements a "cursor rotator" feature that can automatically change cursor themes based on:
- Time intervals (using `chrome.alarms` API)
- Page load count (tracks `counterTab` in storage)

**Code Context**:
```javascript
chrome.alarms.create("rotationTime", {periodInMinutes: r.value/60});
chrome.alarms.onAlarm.addListener(H);
```

**Verdict**: **BENIGN FEATURE**. This is a user-facing feature allowing automatic rotation of cursor themes. No evidence of this being used for surveillance or malicious timing-based attacks.

---

### 7. External Messaging from custom-cursor.com

**Severity**: LOW
**File**: `/deobfuscated/background.js`

**Details**:
The extension accepts external messages from `custom-cursor.com` domain:

```json
"externally_connectable": {
   "matches": ["*://*.custom-cursor.com/*"]
}
```

**Message Actions Supported**:
- `getInstalled` / `get_config`: Returns extension configuration
- `install_collection`: Installs cursor collection from website
- `set_config`: Updates cursor settings

**Verdict**: **EXPECTED BEHAVIOR**. This allows the official website to communicate with the extension for installing cursor packs directly from the web interface. The message handlers only modify cursor settings stored in `chrome.storage.local` and do not execute arbitrary code or access sensitive data.

---

## False Positive Summary

| Pattern | Location | Reason for False Positive |
|---------|----------|---------------------------|
| `localStorage` access | `libs/cursor_old.js` | Legacy unused code; only accesses cursor preferences, not page data |
| `innerHTML` usage | `libs/cursor.js`, `content.js` | Only used to inject CSS stylesheets (static strings), not user-controlled HTML |
| `<all_urls>` permission | `manifest.json` | Required for cursor styling functionality across all websites |
| `Function("return this")()` | `background.js` | Part of Webpack bundler polyfill (regenerator-runtime), not malicious code execution |

---

## API Endpoints & Network Activity

| Endpoint | Method | Purpose | Data Transmitted |
|----------|--------|---------|------------------|
| `https://custom-cursor.com/successful_installation` | GET | Installation tracking | UTM parameters only |
| `https://custom-cursor.com/uninstall` | GET | Uninstall tracking | UTM parameters only |
| `https://custom-cursor.com/api/notification/custom-cursor-helper/{uid}` | POST | Check for notifications | Extension UID only |
| `/libs/collections.json` | GET | Load cursor collections | Local file, no network |
| `https://cdn.custom-cursor.com/` | GET (indirect) | Cursor image assets | Loaded via CSS url() references |

**Notes**:
- No user browsing data, credentials, cookies, or sensitive information is transmitted
- Extension UID is generated locally (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx` UUID format)
- CDN loads cursor images referenced in cursor theme JSON

---

## Data Flow Summary

```
User Installs Extension
    ↓
Background Script Initializes
    ↓
Fetches /libs/collections.json (local)
    ↓
Opens Installation Success Page (custom-cursor.com)
    ↓
Stores Configuration in chrome.storage.local:
    - Selected cursor pack
    - User preferences (size, favorites, rotator settings)
    - Generated UID
    ↓
Content Script Injected on All Pages
    ↓
Reads chrome.storage.local for selected cursor
    ↓
Injects CSS <style> with cursor: url() rules
    ↓
Cursor Images Loaded from cdn.custom-cursor.com
```

**No sensitive data leaves the browser** except:
- Installation/uninstall analytics (standard practice)
- Notification checks with anonymous UID

---

## Permissions Analysis

### Declared Permissions

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `scripting` | Required to inject content scripts for cursor styling | MEDIUM |
| `storage` | Store user cursor preferences | LOW |
| `unlimitedStorage` | Store cursor theme data | LOW |
| `notifications` | Show notifications for updates/announcements | LOW |
| `alarms` | Cursor rotation timer feature | LOW |
| `<all_urls>` (host) | Apply cursor styles to all websites | MEDIUM |

### Content Security Policy

```json
"content_security_policy": {
   "isolated_world": "script-src 'self' 'unsafe-eval'; object-src 'self'"
}
```

**Note**: The use of `'unsafe-eval'` is concerning but likely required for the bundled React application in `popup.min.js`. This only applies to the extension's isolated world, not to web page contexts.

---

## Risk Assessment

### Overall Risk Level: **CLEAN**

**Rationale**:
While the extension has invasive permissions (`<all_urls>`, `scripting`), these are **strictly necessary for its core functionality** of applying custom cursor styles across all websites. Comprehensive code analysis reveals:

✅ **No malicious behavior detected**:
- No credential harvesting
- No cookie stealing
- No browsing history tracking
- No keylogger functionality
- No ad injection or content manipulation
- No proxy/VPN infrastructure
- No cryptocurrency mining
- No obfuscated malicious code

✅ **Network activity is benign**:
- Limited to installation tracking and notification checks
- No exfiltration of user data
- No communication with suspicious third-party domains

✅ **Code quality**:
- Uses modern Manifest V3
- Clean separation of concerns (background/content/popup)
- Legitimate bundled dependencies (regenerator-runtime, lodash debounce)
- No evidence of malware obfuscation beyond standard Webpack minification

⚠️ **Invasiveness justified by functionality**:
The extension requires extensive permissions to modify cursor appearance on all websites, which is its stated and sole purpose. This is analogous to theme extensions that require similar permissions.

---

## Recommendations

### For Users:
- The extension is **safe to use** for its intended purpose of cursor customization
- Be aware that it can see all pages you visit (required for cursor styling)
- Review the cursor rotation feature settings if privacy is a concern

### For Developers:
1. **Remove legacy code**: Delete `libs/cursor_old.js` to eliminate unnecessary localStorage access
2. **CSP hardening**: Consider removing `'unsafe-eval'` if possible by using a CSP-compliant build of React
3. **Minimize permissions**: Consider using optional host permissions that users can grant per-site
4. **Code cleanup**: Minified code in `background.js` and `popup.min.js` makes auditing difficult; consider providing source maps for transparency

---

## Conclusion

**Custom Cursor for Chrome™** is a **legitimate cursor customization extension** with no evidence of malicious behavior. The extension's invasive permissions are justified by its functionality, and all network activity is limited to benign analytics and asset loading. The extension serves its intended purpose without harvesting user data or performing unauthorized actions.

**Risk Level**: **CLEAN**

**Recommended Action**: Safe for continued use. No security concerns warrant removal or warning.
