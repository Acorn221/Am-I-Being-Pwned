# Security Analysis Report: Bookmarks clean up

## Extension Metadata
- **Extension ID**: oncbjlgldmiagjophlhobkogeladjijl
- **Extension Name**: Bookmarks clean up
- **Version**: 0.2.0
- **User Count**: ~200,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

**OVERALL RISK LEVEL: CLEAN**

Bookmarks clean up is a legitimate bookmark management utility with no evidence of malicious behavior. The extension provides functionality to remove duplicate bookmarks, check for broken links, merge folders, and clean up empty folders. All operations are performed locally using standard Chrome extension APIs. The extension requests optional host permissions only when needed for dead link checking and properly releases them when not in use. No data exfiltration, tracking, or suspicious network activity was identified.

## Detailed Analysis

### 1. Manifest Analysis

**Permissions Requested**:
- `activeTab` - Used for UI interaction
- `storage` - Used for storing user preferences
- `bookmarks` - Required for bookmark management operations
- `optional_host_permissions: ["http://*/*", "https://*/*"]` - Only requested on-demand for dead link checking

**Content Security Policy**:
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
Standard and secure CSP with no inline script execution or unsafe-eval.

**Background Service Worker**:
- Minimal background.js (30KB) using browser-polyfill for cross-browser compatibility
- Opens main interface when extension icon clicked
- Tracks usage count via `chrome.storage.sync`
- **Properly releases optional host permissions** on suspension via `chrome.runtime.onSuspend`

**VERDICT**: ✅ CLEAN - Appropriate permissions, secure CSP, proper permission lifecycle management

---

### 2. Background Script Analysis (`background.js`)

**Key Behaviors**:

1. **Extension Icon Click Handler** (lines 901-908):
   ```javascript
   r().action.onClicked.addListener((e => {
     r().tabs.create({
       url: r().runtime.getURL("index.html")
     }), r().storage.sync.get("runs").then((e => {
       r().storage.sync.set({
         runs: e.runs + 1 || 1
       })
     }))
   }))
   ```
   Opens internal index.html page and increments usage counter in sync storage.

2. **Permission Cleanup on Suspend** (lines 909-914):
   ```javascript
   r().runtime.onSuspend.addListener((() => {
     r().permissions.remove({
       permissions: [],
       origins: ["http://*/*", "https://*/*"]
     }), console.log("Unloading.")
   }))
   ```
   **Excellent security practice**: Releases optional host permissions when service worker unloads.

3. **Browser Polyfill** (lines 1-868):
   Standard webextension-polyfill library for cross-browser compatibility (Chrome/Firefox).

**Network Activity**: NONE - No fetch/XHR calls, no external API endpoints.

**VERDICT**: ✅ CLEAN - Minimal, well-designed background script with proper permission hygiene

---

### 3. Main Application Analysis (`main.js`, 18,505 lines)

**Architecture**:
- Vue.js 3 framework with Bootstrap 5.3.3 UI
- Lodash utility library
- PromisePool for concurrent async operations
- All code runs in extension context (index.html page), no content scripts

**Core Functionality**:

#### A. Duplicate Bookmark Detection (lines 18279-18314)
```javascript
async displayDups() {
  this.scanInProgress = !0, this.checkDead = !1;
  let e = await Ph().bookmarks.getTree(),
    t = {};
  e.map((e => this.processNode(e, t))),
  Object.keys(t).forEach((e => {
    t[e].length <= 1 ? delete t[e] : t[e].forEach((e => e.selected = !1))
  })),
  this.duplicates = { ...t },
  this.firstRun = !1, this.scanInProgress = !1
}
```
- Retrieves entire bookmark tree via `chrome.bookmarks.getTree()`
- Locally processes nodes to identify duplicates by URL
- No external data transmission

#### B. Dead Link Checking (lines 17640-17750)

**Permission Request** (lines 18275-18280):
```javascript
getExtraPermissions: async () => Ph().permissions.request({
  permissions: [],
  origins: ["http://*/*", "https://*/*"]
}),
async checkBookmarks() {
  await this.getExtraPermissions() ? this.checkDead = !0 :
    alert("This permissions is required for Broken URLs checker...")
}
```
**Properly requests user consent** before enabling dead link checker.

**Link Validation Logic** (lines 17640-17667):
```javascript
async function Wb(e) {
  try {
    const n = new AbortController;
    let r = setTimeout((() => {
      console.log("aborting", e.url, t), n.abort()
    }), window.pref.timeout);
    t.signal = n.signal;
    let o = await fetch(e.url, t).finally((() => clearTimeout(r)));
    if (!o.ok) throw TypeError(o.status);
    return o.status
  } catch (n) {
    // Retry logic with different methods (HEAD -> GET)
    // Retry with credentials: 'include'
  }
}
```
- **Legitimate use of fetch()** for HTTP HEAD/GET requests to check bookmark URLs
- Uses AbortController for timeout (default 15 seconds, user-configurable)
- Retries with GET if HEAD fails (common server behavior)
- **No response data is read or transmitted** - only HTTP status code checked
- Only checks bookmarks with `http:` or `https:` protocols (line 18219)

**Concurrent Checking** (lines 17748-17749):
```javascript
new($b())((() => i < r.length && !this.paused ? o(r[i++]) : null),
  window.pref.concurrency).start()
```
Uses PromisePool with configurable concurrency (default: 4 parallel requests).

#### C. Folder Management Operations (lines 18333-18378)
- `mergeBookmarksInFolder()`: Merges folders with identical names
- `removeEmptyFolders()`: Deletes folders without bookmarks
- Uses `chrome.bookmarks.move()` and `chrome.bookmarks.removeTree()`

#### D. Preferences System (lines 17939-18031)

**Default Configuration** (lines 17939-17944):
```javascript
let CA = {
  delay: 100,
  timeout: 15e3,  // 15 seconds
  concurrency: 4,
  exlcudedFolderIds: []
};
```
- Stored in `chrome.storage.sync` (user preferences)
- Allows users to exclude specific folders from operations
- Configurable timeout/concurrency for dead link checker

#### E. Donation UI (line 18207)
```javascript
const XA = [Us('<h3>How you can help</h3>...
  <a href="https://www.patreon.com/itwillnotbeasy" target="_blank">...
  Bitcoin: 15nfrmrCPYkLuW4ykURJTAd8TePwU2iW1R
  Ethereum: 0x89fC802BD7A5B0998A7C94dA9F5cF14d76594d2E
  Solana: 9xBkHT9yGub4D5q9yDoHMcLW7vhsF8ECFcPSuzU1MjnD
```
- **Non-intrusive donation modal** (not automatically shown)
- Patreon link + cryptocurrency addresses (BTC/ETH/SOL)
- **No payment processing in extension** - all external links

**VERDICT**: ✅ CLEAN - All operations local or with explicit user consent, no data harvesting

---

### 4. Options Page Analysis (`options.js`, 17,430 lines)

Similar architecture to main.js:
- Vue.js + Bootstrap for preferences UI
- Same browser-polyfill and library stack
- Provides settings interface for:
  - Timeout configuration
  - Concurrency settings
  - Folder exclusions
  - Dead link checker delay

**No additional network activity or suspicious code.**

**VERDICT**: ✅ CLEAN

---

## Security Findings Summary

### Vulnerabilities
**NONE IDENTIFIED**

### Suspicious Patterns
**NONE IDENTIFIED**

### False Positives Encountered

| Pattern | Location | Explanation |
|---------|----------|-------------|
| `disableTracking` | main.js:11279, 12814 | Vue 3 internal API for block tracking optimization, NOT user tracking |
| `setBlockTracking` | main.js:11007 | Vue 3 reactivity system API, NOT ad/content blocking |
| `Function("return this")()` | main.js:344, 4977 | Lodash globalThis polyfill for environments without window/global |
| `eval` references | background.js:219, main.js:4297 | Browser API metadata for devtools, NOT dynamic code execution |
| `.innerHTML` assignments | main.js:7384, 9850, 10732 | Vue 3 template compilation and SVG/MathML rendering |
| `addEventListener` calls | main.js:10024+, options.js | Standard Vue 3 event handling and Bootstrap UI interactions |
| `new Function()` | main.js:13956 | Vue 3 template compiler creating render functions from templates |

---

## API Endpoints & External Connections

| Type | URL/Domain | Purpose | Data Transmitted |
|------|------------|---------|------------------|
| Link to Patreon | https://www.patreon.com/itwillnotbeasy | Donation link | None (user clicks open external page) |
| Dead Link Checks | User's bookmark URLs (http/https) | Validate bookmark accessibility | HEAD/GET requests to bookmark URLs only |
| Cryptocurrency Addresses | BTC/ETH/SOL addresses in UI | Donation addresses | None (displayed for manual copying) |

**No telemetry, analytics, or data collection endpoints detected.**

---

## Data Flow Analysis

### Data Collection
**NONE** - Extension does not collect user data.

### Data Storage (Local Only)
1. **chrome.storage.sync**:
   - `runs`: Integer counter of extension launches (for internal stats)
   - `preferences`: JSON string with user preferences (timeout/concurrency/excluded folders)

### Data Transmission
**NONE** - No user data leaves the local machine except:
- HTTP HEAD/GET requests to bookmark URLs (only when user enables dead link checker with explicit permission)
- No bookmark URLs, titles, or metadata are sent to any third-party server

### Permission Usage
- `bookmarks`: Read/write/delete operations entirely local
- `storage`: Preferences stored in sync storage (synced via user's Google account if enabled)
- `activeTab`: Only used for UI context
- `http://*/*`, `https://*/*`: **Requested on-demand**, used only for dead link validation, **released on suspension**

---

## Risk Assessment

### Privacy Risk: **NONE**
- No tracking, telemetry, or analytics
- No third-party SDK integration
- No user data collection or transmission
- Optional host permissions properly scoped and released

### Security Risk: **NONE**
- Secure manifest v3 implementation
- Proper CSP with no unsafe-eval or inline scripts
- No dynamic code execution
- No code obfuscation
- No extension enumeration/killing behavior

### Functionality Risk: **LOW**
- Bookmark deletion operations are **user-initiated**
- Dead link checker makes real HTTP requests (expected behavior)
- Proper error handling and confirmation dialogs
- Excludable folders prevent accidental deletion

### Data Exfiltration Risk: **NONE**
- Zero external API endpoints
- No fetch/XHR to third-party servers
- Bookmark data never leaves local machine
- Dead link checker only validates URLs, doesn't read responses

---

## Overall Risk Rating: **CLEAN**

### Rationale
1. **Transparent Functionality**: Extension does exactly what it claims - manages bookmarks locally
2. **Proper Permission Model**: Requests minimal permissions, releases optional permissions when not needed
3. **No Tracking or Telemetry**: Zero data collection infrastructure
4. **Open Source Alignment**: Uses standard open-source libraries (Vue.js, Bootstrap, Lodash)
5. **User Control**: All operations require explicit user action (scan, remove, merge)
6. **Secure Implementation**: Manifest v3, strict CSP, no eval, no obfuscation
7. **Good Security Practices**: Permission cleanup on suspend, timeout handling, concurrent request limiting

### Comparison to Known Threats
Unlike previously analyzed malicious extensions (StayFree/StayFocusd, Urban VPN, Flash Copilot), this extension:
- ❌ No XHR/fetch hooking or interception
- ❌ No SDK injection (no Sensor Tower, no Pathmatics)
- ❌ No data harvesting or exfiltration
- ❌ No remote configuration or kill switches
- ❌ No extension enumeration or manipulation
- ❌ No hardcoded API keys or secrets
- ❌ No obfuscation or anti-analysis techniques
- ✅ All network requests (dead link checks) are legitimate and user-initiated
- ✅ Proper permission lifecycle management

---

## Recommendations

**For Users**: ✅ SAFE TO USE
- Extension provides legitimate utility for bookmark management
- Only grant host permissions if you want to use the dead link checker feature
- Review folder exclusions in settings before running bulk operations

**For Developers**: No concerns identified

**For Reviewers**: Extension exemplifies good security practices for bookmark management utilities

---

## Conclusion

Bookmarks clean up (oncbjlgldmiagjophlhobkogeladjijl) is a **clean, legitimate browser extension** with no malicious behavior, tracking, or privacy concerns. The extension properly manages permissions, operates entirely locally except for user-initiated dead link validation, and implements security best practices. The inclusion of donation information is non-intrusive and optional. This extension poses no security or privacy risk to users.

---

**Report Generated**: 2026-02-06
**Analyst**: Claude Opus 4.6 via CWS Security Pipeline
