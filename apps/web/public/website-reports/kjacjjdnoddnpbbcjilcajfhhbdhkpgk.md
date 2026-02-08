# Security Analysis Report: Forest - stay focused, be present

## Extension Metadata
- **Extension ID**: kjacjjdnoddnpbbcjilcajfhhbdhkpgk
- **Extension Name**: Forest: stay focused, be present
- **Estimated Users**: ~900,000
- **Version**: 6.5.0
- **Manifest Version**: 3
- **Developer**: developer@forestapp.cc

---

## Executive Summary

Forest is a **CLEAN** productivity extension with a legitimate focus-timer and website blocking feature. The extension implements a gamified "tree planting" mechanism where users grow virtual trees during focused work sessions. If users visit blocked sites during a planting session, their tree dies. The extension includes user authentication with backend API synchronization for cross-device plant records.

**Risk Level**: **CLEAN**

After comprehensive analysis, no malicious behavior was identified. The extension follows legitimate productivity application patterns with standard OAuth-based authentication and user data synchronization.

---

## Vulnerability Assessment

### 1. XHR/Fetch Hooking
**Severity**: FALSE POSITIVE
**Status**: CLEAN

**Finding**:
Content script uses webext-bridge library for cross-context messaging (background ↔ content script communication).

**Evidence**:
```javascript
// src/content/index.js:9312-9315
onMessage(u) {
  return r = s
},
postMessage(u) {
  return hx(t), (await i).postMessage(s)
}
```

**Verdict**: This is the webext-bridge library's internal message routing system, NOT XHR/fetch interception. The extension does not hook XMLHttpRequest.prototype or window.fetch. This is standard inter-context messaging for Chrome extensions.

---

### 2. API Endpoints & Data Synchronization
**Severity**: INFORMATIONAL
**Status**: CLEAN

**API Domains**:
```javascript
// src/background/index.js:3373-3431
const Jn = {
  Global: "https://auth.seekrtech.com",
  China: "https://auth.upwardsware.com"
};

// API endpoints:
// Global: "https://c88fef96.forestapp.cc/api/v1"
// China: "https://forest-china.upwardsware.com/api/v1"
```

**Endpoints**:
- `oauth/tokens` - OAuth2 token refresh
- `tags` - User-defined planting tags
- `tree_types/unlocked` - Unlocked plant types
- `users/{id}/boost` - User boost status
- `users/{id}` - User profile
- `plants` - Plant record sync

**Authentication Flow**:
```javascript
// src/background/index.js:3395-3421
function Rs(s) {
  if (Os(s.serverRegion), s.accessToken && ks(s.accessToken), s.refreshToken) {
    ne = () => Is.post("oauth/tokens", {
      prefixUrl: e,
      json: {
        grant_type: "refresh_token",
        refresh_token: s.refreshToken
      }
    }).json()
  }
}
```

**Data Collected**:
- User ID, username, avatar URL
- Plant records (tree type, start time, end time, success/failure, tag, note)
- Tree statistics (health count, death count, coins)
- Unlocked plant types
- User-defined site allow/block lists

**Verdict**: CLEAN - Standard OAuth2 implementation with JWT token refresh. Data collection is limited to legitimate app functionality (focus session tracking). No excessive data harvesting observed.

---

### 3. Website Blocking Mechanism
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Implementation**:
```javascript
// src/content/index.js:16103-16110
async function lC(e) {
  switch (e) {
    case "Block":
      return (await Ou("blockList")).some(n => location.href.includes(n));
    case "Allow":
      return (await Ou("allowList")).some(n => location.href.includes(n)) === !1
  }
}
```

**Mechanism**:
1. User selects "Block" or "Allow" mode
2. User defines site lists in options page
3. During planting sessions, content script checks current URL against list
4. If blocked site detected → overlay blocks the page → tree dies if user gives up

**Storage**:
```javascript
// src/background/index.js:3300-3301
allowList: s.whiteList || [],
blockList: s.blackList || [],
```

**Verdict**: CLEAN - Simple URL substring matching stored in chrome.storage.local. No server-side URL tracking. User-controlled lists only.

---

### 4. Content Script DOM Manipulation
**Severity**: FALSE POSITIVE
**Status**: CLEAN

**Finding**:
Content script creates a shadow DOM overlay to display tree growth and blocking UI.

**Evidence**:
```javascript
// src/content/index.js:16029-16055
function Cy() {
  const e = document.querySelector(`#${Py}`) || iC(),
    t = e.shadowRoot || e.attachShadow({mode: "open"}),
    n = t.querySelector("head") || ky(t, "head", null),
    r = t.querySelector("#root") || ky(t, "div", "root");
  return {head: n, appContainer: r, remove: i}
}
```

**Verdict**: CLEAN - Uses shadow DOM for UI isolation. This is a React-based overlay that displays the growing tree and countdown timer. No malicious DOM scraping or manipulation observed.

---

### 5. Chrome Permissions Analysis
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Declared Permissions**:
```json
"permissions": [
  "scripting",
  "storage",
  "unlimitedStorage",
  "notifications",
  "activeTab",
  "tabs",
  "offscreen",
  "identity",
  "alarms"
]
```

**Usage**:
- `scripting` - Inject content scripts on extension updates (src/background/index.js:4996-5009)
- `storage` - Store user settings, plant records, auth tokens
- `unlimitedStorage` - Store plant history without quota limits
- `notifications` - Show success/failure notifications
- `activeTab` - Access current tab for blocking check
- `tabs` - Query tabs for content script injection
- `offscreen` - Keep service worker alive via offscreen document
- `identity` - OAuth authentication flow (chrome.identity.launchWebAuthFlow)
- `alarms` - Schedule token refresh 10 seconds before expiry

**Host Permissions**: `http://*/*`, `https://*/*` - Required for website blocking on all sites.

**Verdict**: CLEAN - All permissions are justified for core functionality. No overprivileged access.

---

### 6. Dynamic Code Execution
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Finding**:
JWT token decoding uses atob() for base64 decoding.

**Evidence**:
```javascript
// src/background/index.js:241-264
function js(s) {
  return decodeURIComponent(atob(s).replace(/(.)/g, (e, n) => {
    let t = n.charCodeAt(0).toString(16).toUpperCase();
    return t.length < 2 && (t = "0" + t), "%" + t
  }))
}
```

**Verdict**: CLEAN - Standard JWT base64url decoding. No eval(), Function(), or dynamic script injection observed.

---

### 7. Extension Enumeration / Killing
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: No chrome.management API usage detected. No extension enumeration or interference with other extensions.

**Verdict**: CLEAN

---

### 8. Keylogging / Input Monitoring
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: Content script uses keyboard event listeners only for React UI (Tab focus trapping in modals). No password field monitoring or keystroke logging.

**Evidence**:
```javascript
// src/content/index.js:2560-2565
n = i.bind(null, t, n, e), i = void 0,
!Ca || t !== "touchstart" && t !== "touchmove" && t !== "wheel" || (i = !0),
r ? i !== void 0 ? e.addEventListener(t, n, {capture: !0}) : e.addEventListener(t, n, !0)
```

**Verdict**: CLEAN - Standard React event delegation. No keylogger patterns.

---

### 9. Cookie Harvesting
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: No document.cookie access detected. No cookie manipulation or exfiltration.

**Verdict**: CLEAN

---

### 10. Third-Party SDKs
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: No Sensor Tower, Pathmatics, or other market intelligence SDKs detected. Code uses React, webext-bridge, and date-fns libraries only.

**Verdict**: CLEAN

---

### 11. Remote Configuration / Kill Switch
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: No remote config fetching observed. Extension behavior is client-controlled with server sync only for user data.

**Verdict**: CLEAN

---

### 12. Ad Injection / Affiliate
**Severity**: NOT PRESENT
**Status**: CLEAN

**Finding**: No ad injection, search manipulation, or affiliate link insertion detected.

**Verdict**: CLEAN

---

### 13. Offscreen Document Usage
**Severity**: INFORMATIONAL
**Status**: CLEAN

**Finding**:
Background service worker creates offscreen document to maintain persistent connection.

**Evidence**:
```javascript
// src/background/index.js:5024-5031
async function ot(s) {
  const e = chrome.runtime.getURL(s);
  await pt(e) || (fe ? await fe : (fe = chrome.offscreen.createDocument({
    url: s,
    reasons: [chrome.offscreen.Reason.BLOBS],
    justification: "To keep the service worker alive"
  }), await fe, fe = null))
}
```

**Verdict**: CLEAN - Legitimate workaround for MV3 service worker lifecycle limitations. Offscreen document posts "tick" messages every second to update timer state.

---

## False Positive Summary

| Pattern | Reason | Library/Framework |
|---------|--------|-------------------|
| postMessage | webext-bridge inter-context messaging | webext-bridge |
| addEventListener | React event delegation | React 18.2.0 |
| querySelector/DOM access | React shadow DOM mounting | React |
| atob/charCodeAt | JWT token decoding | jwt-decode pattern |
| keyboard events | React modal focus trapping | React |

---

## API Endpoints Table

| Endpoint | Method | Purpose | Data Sent | Data Received |
|----------|--------|---------|-----------|---------------|
| oauth/tokens | POST | Token refresh | refresh_token, grant_type | access_token, expires_in |
| tags | GET | Fetch user tags | - | Tag list (id, title, deleted) |
| tree_types/unlocked | GET | Fetch unlocked plants | - | Plant type IDs |
| users/{id}/boost | GET | User boost status | - | Boost times, rate |
| users/{id} | GET | User profile | - | Username, avatar, tree counts, coins |
| plants | POST | Sync plant record | Plant object (treeType, startTime, endTime, tag, note, isSuccess) | Synced plant with server ID |

---

## Data Flow Summary

### Authentication Flow
1. User initiates OAuth via chrome.identity.launchWebAuthFlow
2. Auth servers (seekrtech.com / upwardsware.com) return access + refresh tokens
3. Tokens stored in chrome.storage.local
4. Access token sent as Bearer header for API requests
5. Alarm scheduled for auto-refresh 10s before token expiry

### Planting Session Flow
1. User sets timer duration (10min - 2hr), selects plant type
2. Background script creates growing plant record with startTime + endTime
3. Content script checks current URL against block/allow list
4. If blocked site → overlay shown → user can give up (tree dies) or close tab
5. On timer expiration or give up → plant marked success/fail
6. Plant synced to server API (if user logged in)
7. Notification shown

### Data Storage (chrome.storage.local)
- User profile (id, name, avatar, coins, tree counts)
- Auth tokens (accessToken, refreshToken)
- Plant records array (each with plant object + syncStatus)
- Tags array (user-defined categories)
- Allow/block lists (user-defined URL strings)
- UI state (selectedPlantIndex, selectedPlantingDuration, serverRegion)

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

### Summary
Forest is a legitimate productivity extension with no malicious behavior. The extension:
- Uses OAuth2 authentication appropriately
- Syncs user data only for cross-device functionality
- Implements website blocking via simple URL substring matching
- Respects user privacy (no tracking beyond app functionality)
- Does not interfere with other extensions or browser behavior
- Contains no hidden SDKs, analytics, or data harvesting mechanisms

### Recommendations
- **For Users**: Extension is safe to use. Be aware that planting data syncs to forestapp.cc servers if logged in.
- **For Researchers**: Excellent example of a clean MV3 productivity extension.

### Developer Intent
Appears to be a legitimate focus/productivity tool by Seekrtech (makers of Forest mobile app). The Chrome extension is the web counterpart to their popular mobile application.

---

## Technical Notes

### Framework Stack
- React 18.2.0 (UI)
- webext-bridge (cross-context messaging)
- ky (HTTP client, wraps fetch)
- date-fns (date utilities)
- Vite/Rollup build system

### Content Security Policy
None explicitly defined (uses default MV3 CSP).

### Externally Connectable
```json
"externally_connectable": {
  "ids": ["*"],
  "matches": [
    "https://auth.seekrtech.com/*",
    "https://auth.upwardsware.com/*",
    "https://auth.staging.seekrtech.com/*"
  ]
}
```
Allows external websites to message the extension (OAuth redirect URLs only).

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Opus 4.6 (Automated Security Analysis)
**Analysis Duration**: Comprehensive static analysis of 5,264 lines (background), 16,111 lines (content script)
