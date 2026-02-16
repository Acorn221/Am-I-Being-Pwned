# Security Analysis: Lusha - B2B Contact Finder (mcebeofpilippmndlpcghpmghcljajna)

## Extension Metadata
- **Name**: Lusha - Easily find B2B contact information
- **Extension ID**: mcebeofpilippmndlpcghpmghcljajna
- **Version**: 10.5.4
- **Manifest Version**: 3
- **Estimated Users**: ~400,000
- **Developer**: Lusha
- **Analysis Date**: 2026-02-15

## Executive Summary
Lusha is a legitimate B2B contact information finder extension that integrates with LinkedIn, Salesforce, and other platforms. The extension provides disclosed functionality to retrieve business contact details and sync with the Lusha service. Analysis revealed **MEDIUM** risk due to multiple postMessage handlers lacking origin validation, disclosed collection of extension storage data, and optional broad host permissions. The extension's core functionality is legitimate and disclosed, but security vulnerabilities could allow malicious websites to exploit message handlers. Static analysis detected one data flow from chrome.storage.local to network endpoints and six unvalidated postMessage handlers.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. Missing Origin Validation on postMessage Handlers (MEDIUM)
**Severity**: MEDIUM (6 instances)
**CWE**: CWE-346 (Origin Validation Error)
**Files**:
- `/deobfuscated/content.js` (lines 21160, 21462, 27673, 27766)
- `/deobfuscated/popup.js` (line 13164)
- `/deobfuscated/permission.js` (line 554)

**Analysis**:
The extension registers six window.message event listeners without validating event.origin, creating potential attack vectors for malicious websites to communicate with the extension.

**Code Evidence** (`popup.js`, line 13164):
```javascript
window.addEventListener('message', onToolbarIframeMessage, false);
```

**Handler Implementation** (`popup.js`, lines 13645-13280):
```javascript
var onToolbarIframeMessage = function (event) {
  if (!event || !event.data) {
    return;
  }

  var type = event.data.type;
  var payload = event.data.payload;

  switch(type) {
    case 'TOGGLE_SCOUT':
      // Handles scout toggle without origin check
      break;
    case 'SETTINGS_READY':
      // Handles settings without origin check
      break;
  }
}
```

**Handlers Identified**:
1. **content.js:21160** - Web Worker message handler for LZUTF8 compression/decompression (within worker context)
2. **content.js:21462** - Main content script iframe message handler
3. **content.js:27673** - Additional iframe communication handler
4. **content.js:27766** - Scout feature message handler
5. **popup.js:13164** - Toolbar iframe message handler
6. **permission.js:554** - Permission page message handler

**Mitigating Factors**:
- Most handlers communicate with extension-controlled iframes (plugin.lusha.com, calendar-plugin.lusha.com)
- One handler (line 21160) is within a Web Worker context for data compression (LZUTF8)
- Message handlers check for specific message structure before processing
- No evidence of sensitive data exposure through these handlers in current implementation

**Attack Scenario**:
A malicious website could craft postMessage events targeting these handlers. While the handlers expect specific message formats, lack of origin validation means untrusted origins could potentially:
- Trigger scout feature toggles
- Send malformed data to test for unexpected behavior
- Attempt to manipulate iframe communication flows

**Recommendation**:
Add origin validation to all postMessage handlers:
```javascript
window.addEventListener('message', function(event) {
  // Validate origin
  if (event.origin !== 'https://plugin.lusha.com' &&
      event.origin !== 'https://calendar-plugin.lusha.com') {
    return;
  }
  // Process message
});
```

**Verdict**: **MEDIUM SEVERITY** - While exploitability is limited by message structure requirements, the lack of origin validation violates security best practices and could enable exploitation if combined with other vulnerabilities.

---

### 2. Extension Storage Data Exfiltration (DISCLOSED BEHAVIOR)
**Severity**: LOW (Disclosed Functionality)
**Files**: `/deobfuscated/background.js` (lines 273-12734)

**Analysis**:
Static analysis detected a data flow from chrome.storage.local to fetch() network calls. This represents the extension's core functionality of syncing user data with Lusha services.

**Flow Path**:
```
SOURCE: background.js:273 - chrome.storage.local.get()
  → Transform through multiple jQuery utility functions
  → SINK: background.js:12734 - fetch(route, fetchOptions)
```

**Code Evidence** (`background.js`, line 273):
```javascript
storage = {
  get: function get(key, defaultValue) {
    return new Promise(function (resolve) {
      chrome.storage.local.get(key, function (value) {
        if (chrome.runtime.lastError) {
          throw new Error(chrome.runtime.lastError.message);
        }
        // ... resolve value
      });
    });
  }
}
```

**Network Handler** (`background.js`, lines 12715-12734):
```javascript
handleHttpRequest: function(payload) {
  var method = payload.method;
  var route = payload.route;
  var data = payload.data;
  var headers = Object.assign({}, payload.initialHeaders);

  var fetchOptions = {
    method: method,
    headers: headers,
    credentials: payload.withCookies ? 'include' : 'omit'
  };

  if (!['GET', 'HEAD'].includes(method) && data) {
    fetchOptions.body = JSON.stringify(data);
  }

  return fetch(route, fetchOptions);
}
```

**Endpoints Contacted**:
- `https://plugin-services.lusha.com/v2/user-plugin-versions` (version check)
- `https://plugin-services.lusha.com/api/v1/events/plugin-uninstall` (uninstall tracking)
- `https://dashboard.lusha.com/installed` (installation notification)
- Communication with `plugin.lusha.com` and `calendar-plugin.lusha.com` iframes

**Data Transmitted**:
- Extension version information
- User authentication tokens (stored in chrome.storage.local)
- Contact search requests (LinkedIn, Salesforce data)
- Extension configuration settings

**Privacy Disclosure**:
The extension's description states: "Get access to the world's most accurate global B2B data." This implies data collection and transmission to Lusha's services for contact enrichment, which requires user authentication and data sync.

**Verdict**: **LOW SEVERITY (Disclosed)** - This is expected behavior for a B2B contact finder that requires cloud service integration. Users install the extension explicitly to sync data with Lusha. However, the broad data access warrants transparency about what data is collected.

---

### 3. Optional Broad Host Permissions (USER CONSENT REQUIRED)
**Severity**: LOW (Gated by Permission Request)
**Manifest**: `optional_host_permissions`

**Analysis**:
The extension requests optional permission for `*://*/*` (all websites) to enable the "Scout" feature.

**Manifest Configuration**:
```json
"optional_host_permissions": [
  "https://*.lightning.force.com/*",
  "https://*.mail.google.com/*",
  "*://*/*"
]
```

**Permission Request Flow** (`background.js`, lines 12418-12453):
```javascript
case 'TOGGLE_SCOUT':
  if (message.data.enable) {
    var requiredPermissions = {
      permissions: ['scripting'],
      origins: ['*://*/*']
    };

    chrome.permissions.contains(requiredPermissions, function(result) {
      if (result) {
        Storage.set(IS_SCOUT_ENABLED_KEY, true);
        sendResponse({ scoutEnabled: true });
      } else {
        // Prompt user for permission
        chrome.permissions.request(requiredPermissions).then(function(granted) {
          if (granted) {
            Storage.set(IS_SCOUT_ENABLED_KEY, true);
            sendResponse({ permissionEnabled: true, scoutEnabled: true });
          }
        });
      }
    });
  }
```

**Scout Feature Purpose**:
The Scout feature appears to enable Lusha's contact lookup on websites beyond the default LinkedIn and Salesforce integrations, allowing users to find contact information on any website.

**Mitigating Factors**:
- Permission is optional, not requested at install time
- Requires explicit user action to enable Scout feature
- Chrome displays clear permission prompt to user
- Permission can be revoked by user at any time

**Verdict**: **LOW SEVERITY** - The broad permission is gated behind explicit user consent via Chrome's permission API. Users who enable Scout mode understand they're granting broad access. This follows Chrome's recommended pattern for optional permissions.

---

### 4. Content Security Policy Analysis (COMPLIANT)
**Severity**: N/A (No Issue)
**Manifest**: `content_security_policy`

**Analysis**:
The extension uses a restrictive Content Security Policy that prevents inline script execution and restricts resource loading.

**Manifest Configuration**:
```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'",
  "sandbox": "sandbox allow-scripts allow-popups allow-top-navigation"
}
```

**Security Posture**:
- `script-src 'self'` prevents inline scripts and external script loading
- `object-src 'self'` prevents external plugin content
- Sandbox directive properly isolates sandboxed pages
- No unsafe-eval or unsafe-inline directives

**Verdict**: **SECURE** - CSP configuration follows security best practices.

---

### 5. Web Accessible Resources (MINIMAL EXPOSURE)
**Severity**: N/A (No Issue)
**Manifest**: `web_accessible_resources`

**Analysis**:
The extension exposes minimal resources to web pages.

**Exposed Resources**:
```json
{
  "resources": [
    "frame.html",
    "images/lushaIcon.png",
    "images/lushaIcon2.png",
    "images/lushalogo.png",
    "images/lusha_loader.gif",
    "images/lushaBlueIcon.svg"
  ],
  "matches": ["<all_urls>"]
}
```

**Risk Assessment**:
- Only UI assets (HTML frame and images) are exposed
- No JavaScript files or sensitive data exposed
- frame.html is used for the extension's sidebar interface on LinkedIn/Salesforce
- Resources are necessary for extension functionality

**Verdict**: **SECURE** - Minimal necessary exposure with no security risk.

---

## Static Analysis Summary

**ext-analyzer Report**:
- **Risk Score**: 45/100
- **Exfiltration Flows**: 1 (chrome.storage → fetch)
- **Code Execution Flows**: 0
- **Open Message Handlers**: 6 (no origin validation)
- **Obfuscation Detected**: Yes (webpack bundling, not malicious)

**High-Level Findings**:
- 8 total findings detected by static analyzer
- 1 data exfiltration flow (disclosed functionality)
- 1 cross-component flow (messageData → innerHTML, within extension context)
- 6 postMessage handlers without origin validation (primary security concern)

---

## Permissions Analysis

**Required Permissions**:
- `tabs` - Used to inject content scripts on LinkedIn/Salesforce tabs
- `storage` - Stores user settings, authentication tokens, cached contact data
- `scripting` - Required for dynamic content script injection

**Host Permissions**:
- `https://*.lusha.co/*` - Communication with Lusha backend services
- `https://*.linkedin.com/*` - Content scripts for LinkedIn integration
- `https://*.salesforce.com/*` - Content scripts for Salesforce integration

**Optional Permissions** (Scout feature):
- `https://*.lightning.force.com/*` - Salesforce Lightning experience
- `https://*.mail.google.com/*` - Gmail integration
- `*://*/*` - Scout mode for any website (requires user consent)

**Assessment**: Permissions are appropriate for stated functionality. The broad optional permission is properly gated behind user consent.

---

## Network Communication Analysis

**Endpoints**:
1. **plugin.lusha.com** - Main iframe for extension UI
2. **plugin-services.lusha.com** - Backend API for contact data, version checks
3. **dashboard.lusha.com** - User dashboard, installation notifications
4. **calendar-plugin.lusha.com** - Calendar integration feature

**Communication Patterns**:
- Extension uses iframe-based architecture where UI is loaded from plugin.lusha.com
- Background service worker proxies HTTP requests for iframes (3rd-party cookie workaround)
- fetch() calls include credentials for authenticated requests
- Version check on extension startup
- Uninstall tracking (fires request to plugin-services.lusha.com on uninstall)

**Data Transmitted**:
- User authentication tokens
- LinkedIn/Salesforce profile data for contact enrichment
- Extension configuration (scout enabled, badge position, etc.)
- Usage telemetry (install/update/uninstall events)

---

## Behavioral Analysis

**Legitimate Functionality**:
1. **Contact Lookup**: Scrapes LinkedIn/Salesforce profiles and enriches with Lusha data
2. **Sidebar UI**: Injects iframe-based sidebar on supported platforms
3. **Scout Mode**: Optional feature for contact lookup on any website
4. **Salesforce/Gmail Integration**: Optional integrations for CRM workflows

**Tracking/Analytics**:
- Installation tracking (opens dashboard.lusha.com/installed)
- Version update tracking
- Uninstall URL set to plugin-services.lusha.com for uninstall tracking

**No Evidence Of**:
- Hidden data exfiltration beyond disclosed functionality
- Keylogging or credential theft
- Code injection attacks
- Cryptocurrency mining
- Malicious redirects

---

## Risk Classification

**Overall Risk: MEDIUM**

**Justification**:
- **Core Functionality**: Legitimate B2B tool with disclosed data collection
- **Primary Risk**: Six postMessage handlers lack origin validation (CWE-346)
- **Secondary Risk**: Broad optional permissions (properly gated)
- **Data Collection**: Disclosed and expected for contact enrichment service
- **User Base**: 400K users, enterprise tool from established vendor

**Not Classified as HIGH because**:
- No undisclosed data exfiltration detected
- No credential theft mechanisms
- Permissions are disclosed and necessary for stated functionality
- PostMessage vulnerabilities require specific attack conditions

**Not Classified as CLEAN because**:
- Multiple security vulnerabilities (postMessage origin validation)
- Broad data collection from LinkedIn/Salesforce
- Optional broad host permissions (even if properly gated)

---

## Recommendations

**For Developer (Lusha)**:
1. **High Priority**: Add event.origin validation to all six postMessage handlers
2. **Medium Priority**: Implement message authentication/signing for iframe communication
3. **Low Priority**: Consider reducing scope of optional permissions if Scout feature can be scoped

**For Users**:
1. Only install if you need B2B contact lookup functionality
2. Understand that the extension collects LinkedIn/Salesforce profile data
3. Only enable Scout mode if you need contact lookup on websites beyond LinkedIn/Salesforce
4. Review Chrome permissions to verify what data the extension can access

**For Security Researchers**:
1. Test postMessage handlers for exploitable message injection
2. Verify what data is transmitted to Lusha backends
3. Monitor network traffic when using on sensitive platforms

---

## Comparison to Similar Extensions

Lusha follows patterns common to B2B sales tools like ZoomInfo, Apollo.io, and Clearbit:
- Iframe-based UI architecture
- Disclosed data collection for contact enrichment
- Integration with LinkedIn, Salesforce, Gmail
- Optional broad permissions for extended functionality

The postMessage vulnerabilities are concerning but not unique to Lusha - many extensions with iframe-based architectures make the same mistake.

---

## Conclusion

Lusha is a **legitimate enterprise B2B tool** with **MEDIUM security risk** due to postMessage origin validation vulnerabilities. The extension's data collection is disclosed and necessary for its contact enrichment service. Users should be aware that the extension collects LinkedIn and Salesforce profile data and transmits it to Lusha's servers.

The primary security concern is the six unvalidated postMessage handlers, which could potentially be exploited by malicious websites. While current implementation shows no signs of active exploitation, the vulnerability should be remediated.

**Recommended for**: Enterprise users who need B2B contact lookup and trust Lusha with their data
**Not recommended for**: Privacy-focused users or those uncomfortable with LinkedIn/Salesforce data collection

---

## Technical Details

**Manifest Version**: 3
**Background**: Service Worker (background.js)
**Content Scripts**: content.js, assets.js (injected on LinkedIn/Salesforce)
**Web Accessible Resources**: frame.html, logo images
**Content Security Policy**: Restrictive (script-src 'self')
**Update URL**: Standard Chrome Web Store auto-update

**Code Quality**:
- Webpack bundled (appears obfuscated but is standard build process)
- Uses Babel runtime for async/await transforms
- jQuery embedded for DOM manipulation
- LZUTF8 library for data compression

**Last Updated**: 2026-02-09 (Version 10.5.4)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
