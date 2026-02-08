# Security Analysis Report: Better History

## Extension Metadata
- **Extension ID**: egehpkpgpgooebopjihjmnpejnjafefi
- **Extension Name**: Better History | Manage, Export, and Delete History
- **User Count**: ~100,000 users
- **Version**: 7.0.0
- **Manifest Version**: 3
- **Author**: BetterLogic <Dev@betterlogic>

## Executive Summary

Better History is a browser history management extension that replaces the default Chrome history page with an enhanced interface. The extension provides legitimate history management functionality including search, export, and automatic deletion features. The code is primarily a React-based web application with standard Chrome extension APIs for history manipulation.

**Overall Risk Level: CLEAN**

The extension demonstrates good security practices with no evidence of malicious behavior, data exfiltration, or privacy violations. All network requests are limited to legitimate Google APIs (favicon service) and the extension's own website (betterhistory.io). The extension operates entirely locally and does not transmit browsing data to external servers.

## Vulnerability Analysis

### CLEAN FINDINGS

#### 1. Legitimate History Management
**Severity**: CLEAN
**Files**: `js/background.js`, `manifest.json`
**Description**: The extension legitimately uses Chrome history APIs for its stated purpose.

**Evidence**:
```javascript
// Lines 2209-2213 in background.js
const r = await Promise.all(t.map((e => o.default.history.search({
  text: e.domain,
  startTime: 0,
  maxResults: 99999
}))));
```

**Verdict**: This is the core functionality - searching and managing browser history as advertised. The extension uses standard `chrome.history` APIs appropriately.

---

#### 2. Local Data Storage (IndexedDB)
**Severity**: CLEAN
**Files**: `js/background.js` (lines 3218-3260)
**Description**: Extension uses IndexedDB for local statistics tracking.

**Evidence**:
```javascript
// Line 3218
const r = indexedDB.open(this.DB_NAME, this.DB_VERSION);
// Creates stores: activeTabDuration, domainSessions, browserSessions
```

**Verdict**: IndexedDB usage is for legitimate local analytics. No evidence of data exfiltration. User can disable stats tracking via settings (`enableStats` flag).

---

#### 3. Optional Host Permissions
**Severity**: CLEAN
**Files**: `manifest.json`
**Description**: Extension requests optional permissions for betterhistory.io domain.

**Evidence**:
```json
"optional_host_permissions": [
  "https://betterhistory.io/*",
  "https://*.betterhistory.io/*"
]
```

**Verdict**: Permissions are optional and only for the extension's own website (welcome page, uninstall page). No automatic granting or permission abuse detected.

---

#### 4. Script Injection for Media Detection
**Severity**: CLEAN
**Files**: `js/background.js` (lines 2419-2442, 2536-2548)
**Description**: Extension injects scripts to detect media playback for accurate time tracking.

**Evidence**:
```javascript
// Lines 2419-2441
function n() {
  const e = document.querySelectorAll("audio, video");
  // ...
  e.forEach((e => {
    e.addEventListener("play", (() => {
      chrome.runtime.sendMessage({
        type: "mediaStatus",
        status: "playing",
        url: window.location.href
      })
    }))
  }))
}
```

**Verdict**: Script injection only occurs when user grants optional scripting permissions for stats tracking. Only monitors media playback state (play/pause/ended) - no content scraping or manipulation. Requires user consent via optional permissions.

---

#### 5. Favicon API Usage
**Severity**: CLEAN
**Files**: `js/background.js` (line 4815)
**Description**: Extension uses Google's public favicon service.

**Evidence**:
```javascript
// Line 4815
r = `https://www.google.com/s2/favicons?domain=${t.hostname.replace(/^www\./,"")}&sz=32`;
```

**Verdict**: Standard practice for displaying favicons. Only sends domain names (not full URLs) to Google's public API. This is a common pattern in history/bookmark extensions.

---

#### 6. Blacklist/Whitelist Domain Filtering
**Severity**: CLEAN
**Files**: `js/background.js` (lines 2182-2240)
**Description**: Automatic deletion of blacklisted domains from browser history.

**Evidence**:
```javascript
// Lines 2192-2194
const {
  blacklistedDomains: e
} = await o.default.storage.local.get("blacklistedDomains");
// Deletes history entries matching blacklisted domains every 5 minutes
```

**Verdict**: User-controlled privacy feature. Allows users to automatically remove specific domains from their history. This is an advertised feature, not malicious behavior.

---

## False Positive Analysis

| Pattern | Context | Reason for False Positive |
|---------|---------|--------------------------|
| `eval: {}` | background.js:5070, popup.js:9904 | Webpack configuration object, not actual eval usage |
| `Function("return this")()` | popup.js:10663, history.js:19707 | Polyfill for globalThis in legacy environments (standard pattern) |
| `String.fromCharCode` | popup.js:1869, 1935, 2481 | React keyboard event handling (standard React DOM code) |
| `btoa` | popup.js:7287, history.js:77986, 83005 | Source map generation for CSS (webpack standard), base64 encoding for data URIs |
| `innerHTML` | popup.js:485, 946, 4457 | React SVG rendering (known safe pattern in React) |
| `chrome.scripting.executeScript` | background.js:2536, 2543 | Legitimate media detection after user grants optional permissions |
| `__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED` | Multiple files | React internal APIs (standard React library code) |

## API Endpoints

| Domain | Purpose | Data Sent | Privacy Impact |
|--------|---------|-----------|----------------|
| `https://www.google.com/s2/favicons` | Favicon fetching | Domain names only | Low - public API, no PII |
| `https://betterhistory.io/welcome/` | Welcome page | None | None - only on install |
| `https://betterhistory.io/uninstalled/` | Uninstall feedback | None | None - only on uninstall |
| `https://betterhistory.io/open-history/` | Redirect handler | None | None - redirects to chrome://history |

## Data Flow Summary

### Data Collection
- **Local Only**: Browsing history is accessed but never transmitted externally
- **Optional Stats**: Tab duration/session data stored in local IndexedDB (user can disable)
- **User Control**: `enableStats` flag controls all analytics features

### Data Storage
- **Chrome Storage API**: Extension settings (blacklist, preferences)
- **IndexedDB**: Time tracking statistics (optional, local only)
- **No Remote Storage**: All data remains on user's device

### Data Transmission
- **None**: Extension does not transmit browsing history or user data to external servers
- **Favicon API**: Only domain names sent to Google's public favicon service (standard practice)
- **Extension Website**: Opens betterhistory.io pages (welcome/uninstall) but sends no data

### Third-Party Dependencies
- **React**: UI framework (bundled, no CDN)
- **date-fns**: Date formatting library (bundled)
- **Radix UI**: UI components (bundled)
- **No Analytics SDKs**: No tracking/telemetry libraries detected

## Permissions Analysis

### Declared Permissions
```json
"permissions": [
  "favicon",          // Fetch favicons for URLs
  "tabs",             // Tab management (open/close extension tabs)
  "storage",          // Store user preferences
  "contextMenus",     // Context menu integration
  "history",          // Core functionality - read/delete history
  "sessions",         // Session restoration
  "unlimitedStorage", // IndexedDB for stats
  "alarms",           // Periodic cleanup scheduling
  "activeTab"         // Get active tab info
]
```

### Optional Permissions (User Consent Required)
```json
"optional_host_permissions": [
  "https://betterhistory.io/*",
  "https://*.betterhistory.io/*"
]
```

**Analysis**: Permissions are appropriate for the extension's functionality. No excessive permissions detected. Optional permissions require explicit user consent.

## Content Security Policy

**Not explicitly defined** - Uses Manifest V3 defaults:
- No external scripts allowed
- No inline scripts in HTML
- All code bundled and local

**Assessment**: Secure default CSP. All JavaScript is bundled locally with no external script loading.

## Background Script Analysis

### Key Components
1. **History Management**: Blacklist-based auto-deletion, manual cleanup
2. **Time Tracking**: Optional feature to track time spent on sites (local only)
3. **Database Service**: IndexedDB management for statistics
4. **Tab Management**: Opens/closes extension tabs on reload

### Security Observations
- No remote code execution
- No dynamic script loading
- No network requests for data exfiltration
- Proper error handling and logging
- Stats feature is opt-in and can be disabled

## Content Scripts

**Status**: No persistent content scripts declared in manifest

The extension only injects scripts when:
- User enables stats tracking
- User grants optional scripting permissions
- Script only monitors media playback state (not page content)

## Notable Code Patterns

### 1. Reload Handler (Lines 2017-2071)
The extension attempts to close old tabs and reopen chrome://history/ on reload. This is a UX feature to handle extension updates gracefully.

### 2. Cleanup Scheduling (Lines 2170-2181)
Automatic history deletion runs every 5 minutes for blacklisted domains. This is an advertised privacy feature.

### 3. Permission Checking (Lines 2564-2588)
Extension properly checks for optional permissions before using advanced features. Good security practice.

## Comparison with Known Malicious Patterns

| Malicious Pattern | Present? | Details |
|-------------------|----------|---------|
| Data exfiltration | ❌ No | No evidence of sending history data to external servers |
| Keylogging | ❌ No | No keyboard event capture beyond standard React input handling |
| Cookie harvesting | ❌ No | No cookie access detected |
| Ad injection | ❌ No | No DOM manipulation for ads |
| Proxy infrastructure | ❌ No | No webRequest or proxy APIs used |
| Extension enumeration | ❌ No | No attempts to detect other extensions |
| Remote configuration | ❌ No | No remote config fetching |
| Obfuscation | ⚠️ Minimal | Webpack bundling (standard build process, not malicious obfuscation) |

## Risk Assessment

### Privacy Impact: LOW
- No data collection beyond local statistics (optional)
- No transmission of browsing history
- User control over all features

### Security Impact: LOW
- No code execution vulnerabilities
- Proper permission model
- No external dependencies loaded at runtime

### User Trust: HIGH
- Transparent functionality
- Matches advertised features
- Optional permissions model
- Local-first architecture

## Recommendations

### For Users
1. ✅ Extension is safe to use as intended
2. Review blacklisted domains periodically
3. Disable stats tracking if concerned about local storage

### For Developers
1. Consider adding explicit CSP in manifest for transparency
2. Document data flows in privacy policy on betterhistory.io
3. Add user-facing explanation of optional permissions

## Conclusion

Better History is a **legitimate browser extension** that provides enhanced history management features. The code demonstrates good security practices:

- **No malicious behavior detected**
- **No data exfiltration**
- **Appropriate permission usage**
- **User control over features**
- **Local-first architecture**

The extension's network activity is limited to:
1. Fetching favicons from Google's public API (standard practice)
2. Opening welcome/uninstall pages on betterhistory.io (no data sent)

All browsing data remains on the user's device. The optional time-tracking feature stores data locally in IndexedDB and can be disabled.

**Final Verdict**: CLEAN - Extension is safe for use and does not pose security or privacy risks to users.

---

**Analysis Date**: 2026-02-07
**Analyzed Version**: 7.0.0
**Analyst**: Claude Sonnet 4.5
