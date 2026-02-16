# Security Analysis: Pushbullet (chlffgpmiacpedhhbkiomidkjlcfhogd)

**Risk Level:** MEDIUM
**Version:** 366
**User Count:** 300,000
**Analysis Date:** 2026-02-15

## Executive Summary

Pushbullet is a legitimate cross-device notification and messaging extension that enables users to send links, files, and messages between their devices. The extension has three postMessage event handlers in the bundled forge.min.js cryptography library that lack origin validation, creating a potential attack vector for cross-site scripting if malicious websites can interact with extension pages. The extension's core functionality of accessing tab information and sending it to Pushbullet servers is appropriate for its disclosed purpose, but the postMessage vulnerability represents a security concern that should be addressed.

## Vulnerability Analysis

### MEDIUM Severity Issues

#### 1. Unchecked postMessage Handlers (3 instances)

**Location:** `forge.min.js:1` (bundled cryptography library)

**Description:** The extension includes the forge.js cryptography library which contains three `window.addEventListener("message")` handlers without origin validation. These handlers listen for messages from any origin without checking `event.origin`, creating potential for malicious sites to send crafted messages to extension pages.

**Evidence:**
```javascript
// forge.min.js contains multiple instances of:
window.addEventListener("message", handler)
// Without any origin checking like:
// if (event.origin !== "https://trusted-domain.com") return;
```

**Impact:** If a malicious website can open or interact with an extension page (such as through web_accessible_resources or other vectors), it could potentially send crafted postMessage calls to trigger unintended behavior in the cryptography library. The actual exploitability depends on what these handlers do and whether they can be reached from untrusted contexts.

**Remediation:**
- Update forge.js to a version that includes origin checks on postMessage handlers
- Alternatively, patch the library to validate `event.origin` against a whitelist
- Ensure extension pages cannot be framed or accessed by untrusted sites

#### 2. Tab Information Access

**Location:** `panel-messaging-push.js:424-452`

**Description:** The extension queries active tab information including URL, title, and favicon to enable link sharing functionality.

**Evidence:**
```javascript
chrome.tabs.query({ 'active': true, 'lastFocusedWindow': true }, function(tabs) {
    var tab = tabs[0]
    if (!tab  || !tab.url || tab.url.indexOf('http') != 0) {
        removeLink.onclick()
        return
    }
    linkTitle.value = tab.title || ''
    linkUrl.value = tab.url || ''
    linkUrl.tabId = tab.id
    favicon.src = tab.favIconUrl || 'link.png'
})
```

**Impact:** This is legitimate functionality for a link-sharing extension. The extension accesses tab information only when the user explicitly clicks to share a link, and this data is sent to Pushbullet servers (disclosed in the extension's permissions). This matches the extension's stated purpose.

**Risk Level:** This is appropriate behavior for the extension's functionality and is disclosed through the activeTab permission and optional tabs permission.

#### 3. Local API Storage

**Location:** `main.js:64-79`

**Description:** The extension stores the Pushbullet API key in localStorage, retrieved from cookies.

**Evidence:**
```javascript
var getApiKey = function(done) {
    if (localStorage.apiKey) {
        done(localStorage.apiKey)
    } else {
        chrome.cookies.get({ 'url': 'https://www.pushbullet.com', 'name': 'api_key' }, function(cookie) {
            if (cookie && cookie.value) {
                localStorage.apiKey = cookie.value
                done(localStorage.apiKey)
            }
        })
    }
}
```

**Impact:** localStorage is accessible to content scripts if any are injected. However, this extension does not appear to inject content scripts, so the risk is limited. The API key is used for authenticated API calls to Pushbullet servers.

**Risk Level:** LOW - Standard practice for browser extensions, though storage.local would be more secure.

## Data Flow Analysis

### 1. Link Sharing Flow
- **Source:** `chrome.tabs.query` → current tab URL, title, favicon
- **Processing:** User clicks "add link" button in extension popup
- **Destination:** Pushbullet API (`https://api.pushbullet.com/v2/pushes`)
- **Purpose:** Send link to user's other devices or friends
- **Disclosed:** Yes (activeTab permission, extension description)

### 2. Authentication Flow
- **Source:** Cookie from pushbullet.com
- **Storage:** localStorage.apiKey
- **Usage:** Authorization header for all API requests
- **Security:** Bearer token authentication

### 3. Analytics Flow
- **Source:** Extension events (errors, feature usage)
- **Destination:** `https://zebra.pushbullet.com` (andrelytics)
- **Data:** Client type, version, language, platform, user_iden
- **Control:** Can be disabled via `disableAnalytics` setting

## Permissions Analysis

### Required Permissions
- **activeTab** - Used to access current tab URL/title for link sharing (appropriate)
- **contextMenus** - Adds right-click menu options for quick sharing (appropriate)
- **cookies** - Retrieves API key from pushbullet.com cookies (appropriate)
- **notifications** - Shows browser notifications for messages (appropriate)
- **idle** - Detects user activity for presence status (appropriate)

### Optional Permissions
- **tabs** - Full tab access when granted (disclosed, for advanced features)
- **https://*/***, **http://*/*** - Broad host permissions (disclosed, for web page interaction)

### Host Permissions
- **https://*.pushbullet.com/*** - API and web interface access (necessary)
- **http://localhost:20807/**** - Local server integration (documented feature)

## Code Quality Observations

### Positive
- Clean, readable code structure
- Proper error handling in API calls
- User can opt-out of analytics
- Timeout handling for network requests
- Signed-out cleanup removes sensitive data

### Concerns
- **Minified third-party library (forge.min.js)** contains postMessage vulnerabilities
- API key stored in localStorage instead of chrome.storage.local
- Obfuscated code detected by analyzer (likely just the minified forge library)

## Endpoints

The extension communicates with the following endpoints:

1. **https://api.pushbullet.com** - Primary API for pushes, user data
2. **https://api2.pushbullet.com** - Alternative API endpoint (feature-flagged)
3. **wss://stream-extension.pushbullet.com/websocket** - Real-time message stream
4. **https://update.pushbullet.com** - Feature flags and updates
5. **https://zebra.pushbullet.com** - Analytics endpoint
6. **http://localhost:20807** - Local server integration (optional)

All endpoints are legitimate Pushbullet infrastructure or documented local integration.

## Recommendations

### For Developer
1. **HIGH PRIORITY:** Update forge.js library to version with origin-checked postMessage handlers, or patch to add origin validation
2. **MEDIUM PRIORITY:** Migrate API key storage from localStorage to chrome.storage.local for better security isolation
3. **LOW PRIORITY:** Consider using chrome.identity for OAuth flow instead of cookie-based authentication

### For Users
- This extension is legitimate and performs as described
- The postMessage vulnerability is in a bundled library and may have limited exploitability
- Users should ensure they're installing from the official Chrome Web Store
- Review which optional permissions you grant (tabs, broad host permissions)

## Conclusion

Pushbullet is a legitimate, well-established cross-device messaging extension with appropriate permissions for its functionality. The primary security concern is the presence of unchecked postMessage handlers in the bundled forge.js cryptography library, which could potentially be exploited if extension pages can be accessed from untrusted contexts. This vulnerability warrants a **MEDIUM** risk rating. The extension's access to tab information and API communication are appropriate for its disclosed purpose and do not represent malicious behavior.

**Overall Risk:** MEDIUM
**Recommended Action:** Monitor for updates that address the postMessage vulnerability; continue using with awareness of the issue
