# Security Analysis Report: EverSync - Sync bookmarks, backup favorites

## Extension Metadata
- **Extension ID**: iohcojnlgnfbmjfjfkbhahhmppcggdog
- **Version**: 23.3.7
- **Users**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

EverSync is a legitimate bookmark and Speed Dial synchronization extension that syncs data to the vendor's cloud service (everhelper.pro). The extension exhibits **one CRITICAL security vulnerability** (wildcard `externally_connectable`), **one HIGH-severity issue** (chrome.management enumeration), and several MEDIUM-severity concerns around permissions and data handling. While the core functionality appears legitimate, the security posture presents significant attack surface risks.

**Overall Risk Level**: **HIGH**

The extension's primary security issues stem from overly permissive manifest configuration and broad permission scope rather than overtly malicious behavior. However, the wildcard `externally_connectable` creates severe attack surface exposure.

---

## Critical Vulnerabilities

### VULN-01: Wildcard externally_connectable - ANY Extension Can Message This Extension
**Severity**: CRITICAL
**Files**: `manifest.json`
**Lines**: 46-48

**Description**:
The manifest declares `"externally_connectable": { "ids": ["*"] }`, allowing **any Chrome extension** to send messages to EverSync and invoke its privileged functionality.

**Code Evidence**:
```json
"externally_connectable": {
    "ids": ["*"]
}
```

**Attack Scenarios**:
1. Malicious extension could invoke EverSync's bookmark/sync APIs via `chrome.runtime.sendMessage(extensionId, ...)`
2. Attackers could trigger sync operations, export bookmark data, or manipulate user settings
3. Content script controller accepts various actions including `getCurrentUsage`, `connect`, and custom events
4. Potential for unauthorized data exfiltration or manipulation through cross-extension messaging

**Content Script Message Handler** (`js/content-scripts/controller.js:3-74`):
```javascript
chrome.runtime.onMessage.addListener(function (msg, sender, callback) {
  if (msg.action) {
    if (msg.action.indexOf('event:') === 0) {
      // Fires arbitrary events based on incoming messages
      setTimeout(function () {
        fvdSynchronizer.Observer.fireEvent(msg.action, [msg.data]);
      }, timeout);
      return;
    }
    switch (msg.action) {
      case 'getCurrentUsage':
        // Returns sensitive driver usage statistics
        var result = {};
        // ... processes and returns data
        callback(result);
        return true;
      case 'connect':
        callback({});
        return true;
    }
  }
});
```

**Impact**: Any installed extension can interact with EverSync's privileged APIs, potentially accessing bookmark data, triggering syncs, or manipulating user configurations without user consent.

**Verdict**: CRITICAL VULNERABILITY - This defeats Chrome's extension isolation model and creates massive attack surface.

---

## High-Severity Issues

### VULN-02: Extension Enumeration via chrome.management.getAll
**Severity**: HIGH
**Files**: `js/Driver/Speeddial.js`
**Lines**: 2870-2882

**Description**:
EverSync uses `chrome.management.getAll()` to enumerate all installed extensions, ostensibly to locate the companion "FVD Speed Dial" extension. This reveals the user's complete extension inventory.

**Code Evidence**:
```javascript
function getSpeedDialId(callback) {
  chrome.management.getAll(function (results) {
    var id = null;
    results.forEach(function (extension) {
      if (
        extension.enabled &&
        (extension.name == fvdSpeedDialName || extension.id == fvdSpeedDialId)
      ) {
        id = extension.id;
      }
    });
    callback(id);
  });
}
```

**Also listens for extension installations** (`js/Driver/Speeddial.js:3307-3308`):
```javascript
chrome.management.onEnabled.addListener(installCallback);
chrome.management.onInstalled.addListener(installCallback);
```

**Context**:
- Extension looks for "Speed Dial [FVD] - New Tab Page, 3D, Sync..." (`llaficoajjainaijghjlofdfmbjpebpa`)
- Uses `chrome.management.getSelf()` to check version changes (`js/Utils.js:161`, `js/index.js:114`)

**Privacy Concern**: While seemingly benign (looking for companion extension), the `getAll()` call exposes the user's complete extension list. Combined with the wildcard `externally_connectable`, a malicious extension could query EverSync to learn about other installed extensions.

**Verdict**: HIGH - Extension enumeration is privacy-invasive. Legitimate use case exists (finding companion extension), but implementation exposes full extension inventory.

---

## Medium-Severity Issues

### VULN-03: Broad Host Permissions and Cookies Access
**Severity**: MEDIUM
**Files**: `manifest.json`, `js/Server/Sync.js`, `js/Background.js`
**Lines**: manifest.json:42-43, Server/Sync.js:33-51, 591-599

**Description**:
Extension requests broad permissions including `cookies`, `management`, `tabs`, `unlimitedStorage`, with host permissions for `https://everhelper.pro/*`.

**Manifest Permissions**:
```json
"permissions": ["storage", "bookmarks", "tabs", "management", "unlimitedStorage", "cookies"],
"host_permissions": ["https://everhelper.pro/*"]
```

**Cookie Access Patterns**:
- Reads authentication cookies (`auth`, `eversessionid`) from `https://everhelper.pro/client`
- Monitors cookie changes via `chrome.cookies.onChanged` to detect logout
- Removes auth cookies on logout

**Code Evidence** (`js/Server/Sync.js:591-599`):
```javascript
chrome.cookies.onChanged.addListener(function (changeInfo) {
  if (changeInfo.cause === 'expired_overwrite' && changeInfo.removed) {
    var cookie = changeInfo.cookie;
    if (cookie.name === AUTH_COOKIE_NAME) {
      fvdSynchronizer.Server.Sync.activityState(function (state) {
        if (state !== 'logged') {
          fvdSynchronizer.Observer.fireEvent('event:logout');
          fvdSynchronizer.Driver.Speeddial.onLogout();
        }
```

**Fallback Cookie Mechanism** (`js/Server/Sync.js:58-82`):
```javascript
this.getSessionIdFetch = function (name, cb) {
  const request = new Request('https://everhelper.pro/spec/cookie_state.php', params);
  fetch(request)
    .then((response) => response.json())
    .then((data) => {
      if (!data || typeof data != 'object' || !data[name]) {
        cb(false);
      } else {
        cb(data[name]);
      }
    })
```

**Concern**: The `cookies` permission is necessary for authentication, but combined with `tabs` and wildcard `externally_connectable`, increases attack surface. Proper use is observed (scoped to everhelper.pro), but broad permission set is concerning.

**Verdict**: MEDIUM - Permissions are used for legitimate sync functionality, but broad scope increases risk.

---

### VULN-04: Content Script postMessage Bridge with Wildcard Origin
**Severity**: MEDIUM
**Files**: `js/content-scripts/everhelper.js`
**Lines**: 1-41

**Description**:
Content script on `everhelper.pro` domains creates a postMessage bridge between web pages and the extension background, using wildcard origin (`'*'`).

**Code Evidence**:
```javascript
window.addEventListener('message', function (event) {
  if (event.source != window) {
    return;
  }
  if (event.data.data && event.data.type && event.data.type == 'EverHelperExtMessage') {
    var data = event.data.data;
    if (!data.action) {
      return;
    }
    chrome.runtime.sendMessage(data, function (response) {
      // ... process response
      window.postMessage({
        type: 'EverHelperExtMessage',
        responseToId: event.data.id,
        data: responseData,
        mark: mark,
      }, '*');  // <-- Wildcard origin
    });
  }
}, false);
```

**Content Script Injection Scope** (`manifest.json:14-26`):
```json
"content_scripts": [{
  "all_frames": true,
  "js": ["/js/content-scripts/everhelper.js"],
  "matches": [
    "*://everhelper.pro/*",
    "*://*.everhelper.pro/*",
    "*://everhelper.local/*",
    "*://nimbustest.com/*"
  ],
  "run_at": "document_start"
}]
```

**Concerns**:
- postMessage uses wildcard origin `'*'` instead of specific origin validation
- Accepts messages from `window` source without strict origin checking
- Message deduplication via `messageMarks` array (last 100 messages) suggests high volume
- `nimbustest.com` domain suggests testing domain left in production manifest

**Verdict**: MEDIUM - Scoped to vendor domains, but wildcard origin is bad practice. If vendor site is compromised, attackers could send arbitrary messages to extension.

---

### VULN-05: innerHTML Usage in Localizer
**Severity**: LOW
**Files**: `js/Localizer.js`
**Lines**: 15

**Description**:
Localizer module uses `innerHTML` to inject localized messages, though source is trusted (chrome.i18n).

**Code Evidence**:
```javascript
localizeCurrentPage: function () {
  const elements = document.querySelectorAll('*[msg]');
  for (let i = 0, len = elements.length; i != len; i++) {
    const element = elements[i];
    if (element.hasAttribute('msg_target')) {
      element.setAttribute(element.getAttribute('msg_target') || '', _(element.getAttribute('msg')));
    } else {
      element.innerHTML = _(element.getAttribute('msg'));  // <-- innerHTML
    }
    element.removeAttribute('msg');
  }
}
```

**Verdict**: FALSE POSITIVE / LOW - Source is `chrome.i18n.getMessage()` which returns trusted localized strings. Not a real XSS vector.

---

## False Positives

| Pattern | Location | Reason |
|---------|----------|--------|
| XMLHttpRequest/fetch hooks | N/A | NOT PRESENT - No XHR/fetch monkey-patching detected |
| jQuery XHR references | `js/_external/jquery-3.6.1.min.js` | Standard jQuery 3.6.1 library, not malicious hooks |
| `eval()` usage | N/A | NOT PRESENT - No dynamic code evaluation |
| Residential proxy patterns | N/A | NOT PRESENT - No proxy infrastructure |
| Ad injection | N/A | NOT PRESENT - No ad/coupon code |
| AI conversation scraping | N/A | NOT PRESENT - No AI platform targeting |
| Extension disabling/killing | N/A | NOT PRESENT - Management API used only for detection, not manipulation |

---

## API Endpoints and Data Flow

### Primary Backend Endpoints

| Endpoint | Purpose | Data Transmitted | Method |
|----------|---------|------------------|--------|
| `https://sync.everhelper.pro` | Main sync API | Bookmark/SpeedDial data, user auth | POST |
| `https://sync.everhelper.pro/{action}` | Action-specific endpoints | JSON-encoded requests with `_client_software: 'chrome_addon'` | POST |
| `https://everhelper.pro/client` | Admin panel / account management | Login credentials, user settings | GET/POST |
| `https://everhelper.pro/spec/cookie_state.php` | Cookie fallback mechanism | N/A (retrieves session cookies) | GET |
| `https://everhelper.pro/spec/clear_auth_cookie.php` | Cookie removal | N/A | DELETE |
| `https://everhelper.pro/auth/process.php` | Authentication endpoint | Login credentials | POST |
| `https://everhelper.pro/shareforpremium/can.php` | Premium share check | User auth state | POST |

### Custom Request Headers

```javascript
headers: {
  'EverHelper-Token': fvdSynchronizer.Server.Connection.getCurrentToken(),
  'X-Client-Version': chrome.runtime.getManifest().version,
  'Content-Type': 'application/json'
}
```

### Data Flow Summary

1. **Authentication Flow**:
   - User logs in via iframe to `everhelper.pro/auth/process.php`
   - Session cookies (`auth`, `eversessionid`) stored on `everhelper.pro` domain
   - Extension retrieves token via `user:getToken` API call
   - Token cached per session ID and included in subsequent requests via `EverHelper-Token` header

2. **Bookmark Sync Flow**:
   - Extension reads local bookmarks via `chrome.bookmarks` API
   - Data serialized and sent to `https://sync.everhelper.pro` with action `acquire_lock`, sync operations, `release_lock`
   - Server returns updated bookmarks which are merged/applied locally

3. **Speed Dial Sync Flow**:
   - Extension communicates with companion "FVD Speed Dial" extension via `chrome.runtime.connect()` port messaging
   - Dial/group data synced to server similarly to bookmarks
   - Custom backup system stores Speed Dial configs in server-side lists (`custom_sd_head`, `custom_sd_data`)

4. **File Upload Flow**:
   - Speed Dial backgrounds/images converted to blobs
   - Uploaded via `files:preupload` action with FormData multipart
   - Server returns temporary filename, embedded in backup metadata

---

## Data Exfiltration Assessment

### Bookmark/Browsing Data
- **Collected**: User bookmarks, Speed Dial URLs/titles, bookmark folder structure
- **Transmitted To**: `sync.everhelper.pro`
- **Purpose**: Legitimate sync functionality
- **User Consent**: Implicit (core feature of extension)
- **Encryption**: HTTPS only (no client-side E2E encryption observed)

### Extension Inventory
- **Collected**: All installed extensions (name, ID, enabled state)
- **Transmitted To**: Not transmitted to server (local use only for companion extension detection)
- **Privacy Impact**: HIGH if exposed via `externally_connectable` to malicious extensions

### User Credentials
- **Collected**: Email/password during login
- **Transmitted To**: `everhelper.pro/auth/process.php`, `everhelper.pro/client/login`
- **Storage**: Stored in chrome.storage.local as prefs, session managed via cookies

### No Evidence Of:
- Keystroke logging (no keydown/keyup listeners)
- Form data harvesting beyond login forms
- Third-party tracking pixels/beacons
- Residential proxy infrastructure
- Market intelligence SDKs (Sensor Tower, etc.)
- AI conversation scraping
- Browsing history collection beyond bookmarks

---

## CSP Analysis

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Verdict**: GOOD - Strict CSP allows only `'self'` scripts, no `'unsafe-eval'` or `'unsafe-inline'`. Prevents code injection into extension pages.

---

## Third-Party Libraries

| Library | Version | Purpose | Security Notes |
|---------|---------|---------|----------------|
| jQuery | 3.6.1 | DOM manipulation | Standard library, no modifications detected |
| URI.js | Custom | URL parsing | MIT/GPL licensed (medialize/URI.js) |
| Punycode.js | 1.2.4 | IDN handling | Standard library |
| Filer.js | Custom | File system abstraction | Apache 2.0 licensed |

**Verdict**: All libraries appear legitimate and unmodified.

---

## Remote Configuration / Kill Switches

**NOT DETECTED**: No evidence of remote configuration fetching, behavior modification based on server responses, or "kill switch" functionality. Sync behavior is static and defined in local code.

The only dynamic server interaction is sync data exchange and authentication state management.

---

## Overall Risk Assessment

### Risk Level: **HIGH**

### Risk Breakdown:
- **CRITICAL Issues**: 1 (wildcard `externally_connectable`)
- **HIGH Issues**: 1 (extension enumeration)
- **MEDIUM Issues**: 2 (broad permissions, postMessage origin)
- **LOW Issues**: 1 (innerHTML with trusted source)
- **FALSE POSITIVES**: Multiple known FP patterns avoided

### Key Concerns:
1. **Wildcard `externally_connectable`** is the most severe issue - ANY extension can message EverSync
2. **Extension enumeration** via `chrome.management.getAll()` reveals user's extension inventory
3. **Broad permission scope** (cookies, management, tabs) increases attack surface when combined with #1
4. **No end-to-end encryption** for bookmark data (HTTPS only)

### Positive Security Indicators:
- Strict CSP prevents code injection
- No XHR/fetch hooking or monkey-patching
- No ad injection, malware, or tracking SDKs
- No AI conversation scraping or market intelligence
- Legitimate business model (sync service)
- Standard Chrome APIs used appropriately for core functionality

---

## Recommendations

### For Users:
1. **CRITICAL**: Be aware that any installed extension can interact with EverSync due to wildcard `externally_connectable`
2. Review other installed extensions for trustworthiness
3. Understand that bookmark data is synced to vendor servers without E2E encryption
4. Consider the privacy implications of extension enumeration

### For Developers (EverSync Team):
1. **IMMEDIATELY** replace `"ids": ["*"]` with specific extension IDs (e.g., `["llaficoajjainaijghjlofdfmbjpebpa"]` for FVD Speed Dial only)
2. Remove `nimbustest.com` from content_scripts matches (appears to be test domain)
3. Replace wildcard origin in postMessage with specific origin check (e.g., `https://everhelper.pro`)
4. Consider implementing client-side encryption for bookmark data before transmission
5. Use `chrome.management.get(specificId)` instead of `getAll()` to reduce privacy exposure
6. Add sender validation in `chrome.runtime.onMessage` handler to verify message source

---

## Conclusion

EverSync is a **legitimate bookmark synchronization extension with concerning security vulnerabilities**. The core functionality appears benign and serves its stated purpose of syncing bookmarks/Speed Dials to the vendor's cloud service. However, the **wildcard `externally_connectable` configuration creates a CRITICAL security vulnerability** that allows any malicious extension to interact with EverSync's privileged APIs.

The extension does NOT exhibit malicious behavior patterns observed in malware (ad injection, tracking SDKs, AI scraping, proxy infrastructure, etc.), but the security posture requires immediate remediation of the externally_connectable issue.

**Risk Rating Justification**: Despite legitimate functionality, the CRITICAL wildcard `externally_connectable` vulnerability warrants a **HIGH** overall risk rating due to massive attack surface exposure.

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
