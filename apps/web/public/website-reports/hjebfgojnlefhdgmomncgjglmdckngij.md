# SuperSorter Security Analysis Report

## Extension Metadata
- **Extension Name**: SuperSorter
- **Extension ID**: hjebfgojnlefhdgmomncgjglmdckngij
- **Version**: 1.0.6
- **User Count**: ~80,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

SuperSorter is a bookmark management extension that provides automated sorting, duplicate detection, and folder merging functionality. After comprehensive security analysis, the extension demonstrates **CLEAN** security posture with no malicious behavior detected. The extension operates entirely locally using Chrome's bookmarks API, with no external network communication. The code is well-structured, uses standard cryptographic libraries (CryptoJS) for local hashing operations, and follows security best practices for bookmark manipulation.

## Vulnerability Analysis

### 1. Network Activity - CLEAN
**Severity**: N/A
**Status**: No Issues Found

**Analysis**:
- No `fetch()`, `XMLHttpRequest`, or WebSocket connections detected
- No external API calls or remote servers contacted
- All operations are performed locally using Chrome extension APIs
- The only external reference is a PayPal donation link in the options page HTML (hardcoded, not dynamically loaded)

**Verdict**: CLEAN - Extension operates entirely offline

---

### 2. Permissions Analysis - CLEAN
**Severity**: N/A
**Status**: Appropriate

**Manifest Permissions**:
```json
"permissions": [
    "bookmarks",
    "storage",
    "alarms",
    "activeTab"
]
```

**Analysis**:
- `bookmarks`: Required for core functionality (sorting, duplicate detection)
- `storage`: Used for saving user preferences locally
- `alarms`: Used for automated sorting scheduling
- `activeTab`: Used to detect if bookmark manager is open (to prevent conflicts)
- No CSP defined (acceptable for MV3 with no inline scripts)
- No `webRequest`, `cookies`, or excessive permissions requested

**Verdict**: CLEAN - Minimal permissions appropriate for functionality

---

### 3. Code Execution Analysis - CLEAN
**Severity**: N/A
**Status**: No Dynamic Code

**Analysis**:
- No `eval()` usage detected
- No `Function()` constructor usage
- No dynamic script injection
- No `import()` for remote modules
- Bundled code uses standard webpack/module pattern
- CryptoJS library (legitimate AES/SHA256 implementation) included for hashing

**Verdict**: CLEAN - No dynamic code execution vectors

---

### 4. Data Collection & Privacy - CLEAN
**Severity**: N/A
**Status**: No Data Exfiltration

**Analysis**:
- Extension uses CryptoJS SHA256 to hash bookmark tree for change detection (local only)
- Hashes stored locally via `chrome.storage.local` API
- No bookmark data sent externally
- No analytics SDKs detected
- No tracking pixels or beacons
- Options page references PayPal donation (static link only)

**Storage Usage**:
```javascript
// Local storage keys used:
- "SuperSorterOptions" - User preferences
- "bookmark-tree-hash" - SHA256 hash for change detection
- "preferences-hash" - SHA256 hash of preferences
```

**Verdict**: CLEAN - All data stays local

---

### 5. Content Script Analysis - CLEAN
**Severity**: N/A
**Status**: No Content Scripts

**Analysis**:
- Extension defines no content scripts
- No DOM manipulation of web pages
- No `postMessage` listeners for cross-origin communication
- Service worker (`ss.js`) handles background operations only
- Options page (`opts.js`) operates in isolated extension context

**Verdict**: CLEAN - No web page interaction

---

### 6. Background Script Analysis - CLEAN
**Severity**: N/A
**Status**: Legitimate Operations

**Key Functions** (`ss.js`):
- Bookmark tree traversal and sorting
- Duplicate detection using URL/title comparison
- Empty folder cleanup
- Folder merging
- Alarm-based automated sorting
- Badge text updates for user feedback

**Cryptographic Usage**:
```javascript
// CryptoJS used for change detection hashing:
function Ln(n) {
  const i = Yn(n);
  return mn(JSON.stringify(i))  // SHA256 hash
}
```

**Chrome API Usage**:
- `chrome.bookmarks.*` - Read/write/move/delete bookmarks
- `chrome.storage.local.*` - Save preferences
- `chrome.action.*` - Update extension icon/badge
- `chrome.alarms.*` - Schedule automated sorting
- `chrome.tabs.*` - Detect if bookmark manager is open

**Verdict**: CLEAN - All operations legitimate for bookmark management

---

### 7. Obfuscation Analysis - ACCEPTABLE
**Severity**: N/A
**Status**: Standard Webpack Bundle

**Analysis**:
- Code is webpack bundled (standard practice)
- Variable names minified but not intentionally obfuscated
- Source maps provided (`ss.js.map`, `opts.js.map`)
- CryptoJS library follows standard implementation patterns
- No string encoding, base64 payloads, or anti-debugging code

**Verdict**: CLEAN - Standard production bundling

---

### 8. Update Mechanism - CLEAN
**Severity**: N/A
**Status**: Official Chrome Web Store

**Analysis**:
```json
"update_url": "https://clients2.google.com/service/update2/crx"
```

**Verdict**: CLEAN - Uses official CWS update channel

---

## False Positives Table

| Pattern | Location | Explanation |
|---------|----------|-------------|
| CryptoJS AES | `ss.js` lines 1-500 | Legitimate crypto library for SHA256 hashing (change detection) |
| PayPal URL | `options.html` line 2 | Hardcoded donation link, no dynamic loading |
| `chrome.tabs.query` | `ss.js` line 4259 | Checks if bookmark manager tab is open (user preference) |
| Webpack runtime | Both files | Standard module bundler output |

---

## API Endpoints / External Resources

| Resource | Type | Purpose | Risk |
|----------|------|---------|------|
| None detected | N/A | N/A | N/A |

**Note**: No external API endpoints or remote resources contacted during runtime.

---

## Data Flow Summary

```
User Interaction
    ↓
Options Page / Extension Icon Click
    ↓
Background Service Worker (ss.js)
    ↓
Chrome Bookmarks API (Local)
    ↓
Read Bookmark Tree → Sort → Detect Duplicates → Apply Changes
    ↓
Update chrome.storage.local (Preferences + Hashes)
    ↓
Update Extension Badge (User Feedback)
```

**Key Points**:
- All data processing occurs locally
- No external network calls
- No sensitive data leaves the browser
- User bookmarks never transmitted externally

---

## Overall Risk Assessment

**Risk Level**: **CLEAN**

**Rationale**:
1. ✅ No network communication
2. ✅ Minimal, appropriate permissions
3. ✅ No dynamic code execution
4. ✅ No data exfiltration
5. ✅ No suspicious obfuscation
6. ✅ No content script injection
7. ✅ Legitimate bookmark management operations
8. ✅ Uses official CWS updates
9. ✅ Open source cryptographic library (CryptoJS)
10. ✅ No tracking or analytics

**Conclusion**: SuperSorter is a legitimate bookmark utility extension with no security concerns. It performs all operations locally, requests only necessary permissions, and exhibits no malicious behavior. The extension is safe for use.

---

## Recommendations

None required. Extension follows security best practices.

---

## Technical Notes

- **Build System**: Webpack bundled
- **Libraries**: CryptoJS (AES, SHA256, Base64 encoding)
- **Architecture**: Manifest V3 service worker pattern
- **Code Quality**: Well-structured, proper error handling
- **Testing**: Extension includes source maps for debugging
