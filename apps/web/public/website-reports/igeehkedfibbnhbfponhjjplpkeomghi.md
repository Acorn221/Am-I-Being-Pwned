# Tabli - Chrome Extension Security Analysis

## Extension Metadata
- **Extension ID**: igeehkedfibbnhbfponhjjplpkeomghi
- **Name**: Tabli
- **Version**: 4.0.4
- **User Count**: ~50,000
- **Manifest Version**: 3
- **Description**: A simple, powerful tab manager

---

## Executive Summary

Tabli is a **CLEAN** extension with no identified security vulnerabilities or malicious behavior. The extension is a legitimate tab management tool that helps users organize browser tabs and windows. All code and functionality is consistent with the stated purpose. The extension uses appropriate permissions, follows security best practices, and contains no network communication, tracking, or data exfiltration mechanisms.

**Risk Level**: **CLEAN**

---

## Manifest Analysis

### Permissions
```json
"permissions": ["storage", "tabs", "bookmarks", "favicon"]
```

**Analysis**:
- `storage`: Used for persisting user preferences and window state (legitimate)
- `tabs`: Required for tab management functionality (legitimate)
- `bookmarks`: Used to save tab windows as bookmark folders (legitimate)
- `favicon`: Used to display tab favicons in the UI (legitimate)

All permissions are appropriate and minimal for a tab manager.

### Content Security Policy
No custom CSP defined - uses default MV3 CSP which is secure.

### Background Service Worker
```json
"background": {
    "service_worker": "js/service-worker.js"
}
```

Simple service worker that imports `common.bundle.js` and `bgHelper.bundle.js` - no suspicious behavior.

### Web Accessible Resources
```json
"web_accessible_resources": [
    {
        "resources": ["_favicon/*"],
        "matches": ["<all_urls>"],
        "extension_ids": ["*"]
    }
]
```

Only exposes favicon resources - appropriate for displaying tab favicons.

---

## Code Analysis

### Background Scripts

**File**: `js/service-worker.js`
- Simple entry point that imports bundle files
- No dynamic code execution
- No network requests

**File**: `js/bgHelper.bundle.js` (1.2MB, 4194 lines)
- Contains Lodash utility library (MIT licensed)
- Implements tab/window state management
- Registers message listeners for popup/popout communication
- Uses `chrome.commands`, `chrome.runtime.onMessage`, `chrome.runtime.onConnect` for legitimate inter-component communication
- No network calls, no external API communication

**File**: `js/common.bundle.js` (3.5MB, 26484 lines)
- Contains React, chrome-promise, and other UI libraries (all MIT licensed)
- Implements core tab management logic
- Uses Chrome APIs appropriately:
  - `chrome.windows.get/getAll/create/update` - window management
  - `chrome.tabs.create/remove/update` - tab management
  - `chrome.bookmarks.create/move/remove` - bookmark persistence
  - `chrome.storage.local.get/set` - preference storage

### UI Components

**Files**: `js/tabliPopup.bundle.js`, `js/tabliPopout.bundle.js`, `js/prefsPage.bundle.js`
- React-based UI components
- Handle user interactions and display tab/window state
- Send messages to background script via `chrome.runtime.sendMessage`
- No content manipulation, no DOM injection

### Third-Party Libraries

All libraries are legitimate and properly licensed:
- **React** (Facebook, MIT) - UI framework
- **Lodash** (OpenJS Foundation, MIT) - Utility library
- **Bootstrap** (v5.3.3, MIT) - CSS framework
- **chrome-promise** (Tomás Fox, MIT) - Promise wrapper for Chrome APIs
- **jQuery** (slim version) - For Bootstrap compatibility

---

## Vulnerability Assessment

### 1. Dynamic Code Execution - CLEAN ✓

**Patterns Searched**:
- `eval()`, `Function()`, `new Function()`
- `atob()`, `btoa()`, `exec()`

**Findings**:
```javascript
// bgHelper.bundle.js:143
Function("return this")()
```

**Verdict**: **FALSE POSITIVE**
- This is a standard polyfill pattern used by bundlers (Webpack/Parcel) to get the global object
- Used in multiple bundles: `bigRenderTest.bundle.js:93`, `tabliPopup.bundle.js:197`, `tabliPopout.bundle.js:60`, `prefsPage.bundle.js:439`
- No runtime code execution of untrusted content
- Context shows it's part of Lodash library initialization

### 2. Network Activity - CLEAN ✓

**Patterns Searched**:
- `fetch()`, `XMLHttpRequest`, `WebSocket`
- Network-related APIs

**Findings**: **NONE**
- Zero network requests in any code
- No external API calls
- No tracking/analytics
- No remote configuration

**Verdict**: **CLEAN** - Extension operates entirely offline

### 3. Data Exfiltration - CLEAN ✓

**Patterns Searched**:
- Cookie access
- `document.cookie`, `localStorage`, `sessionStorage`
- Data harvesting patterns

**Findings**: **NONE**
- No cookie access
- Only uses `chrome.storage.local` for user preferences (stored locally)
- No access to sensitive data outside tab metadata (title, URL, favicon)

**Verdict**: **CLEAN** - No data collection or exfiltration

### 4. Suspicious URLs - CLEAN ✓

**URLs Found**:
```javascript
// js/common.bundle.js:19421-19424
"https://medium.com/@antonycourtney/taming-tab-hell-with-tabli-83f080e32d17?source=friends_link&sk=d121d5ba0114d9eea9cd29a23e202d37"
"http://www.gettabli.com/tabli-usage.html"
"https://chrome.google.com/webstore/detail/tabli/igeehkedfibbnhbfponhjjplpkeomghi/reviews"
"mailto:tabli-feedback@gettabli.com"
```

**Verdict**: **CLEAN**
- All URLs are for documentation/support links
- Medium article about the extension
- Official product website
- Chrome Web Store review page
- Feedback email
- **None are accessed programmatically** - only displayed in UI for user to click

### 5. Extension Enumeration/Fingerprinting - CLEAN ✓

**Findings**: **NONE**
- No extension enumeration code
- No browser fingerprinting
- No competitor extension detection or interference

### 6. PostMessage/IPC Security - CLEAN ✓

**Pattern**: `postMessage` usage found in `bgHelper.bundle.js:4030`

**Context**:
```javascript
t.postMessage({
    type: "initialState",
    value: u
});
```

**Verdict**: **CLEAN**
- PostMessage only used for internal communication between service worker and popup/popout windows
- Uses structured message format with type/value
- No cross-origin messaging
- No external iframe communication

---

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `Function("return this")()` | bgHelper.bundle.js:143 | Webpack/bundler polyfill for global object | BENIGN |
| `new Function("return this")()` | Multiple bundles | Same polyfill pattern | BENIGN |
| `postMessage` | bgHelper.bundle.js:4030 | Internal state sync between components | BENIGN |
| `addEventListener` | bootstrap.bundle.js (multiple) | Bootstrap UI framework event handling | BENIGN |

---

## API Endpoints / External Communication

**No external API endpoints or network communication detected.**

The extension operates entirely locally using Chrome extension APIs.

---

## Data Flow Summary

```
User Action (Popup/Popout UI)
    ↓
chrome.runtime.sendMessage
    ↓
Background Service Worker (bgHelper.bundle.js)
    ↓
State Update (in-memory)
    ↓
chrome.storage.local (preferences only)
    ↓
chrome.tabs/windows/bookmarks APIs (browser operations)
    ↓
postMessage back to UI
    ↓
UI Update (React components)
```

**Data Stored**:
- User preferences (popout settings, theme, etc.) → `chrome.storage.local`
- No user browsing data, credentials, or PII collected

**Data Transmitted**:
- None - no network communication

---

## Permissions vs. Functionality Analysis

| Permission | Declared | Used | Purpose | Appropriate? |
|------------|----------|------|---------|--------------|
| storage | ✓ | ✓ | Store user preferences | ✓ YES |
| tabs | ✓ | ✓ | Manage/organize tabs | ✓ YES |
| bookmarks | ✓ | ✓ | Save tab windows as bookmarks | ✓ YES |
| favicon | ✓ | ✓ | Display tab favicons | ✓ YES |

**All permissions are necessary and used appropriately.**

---

## Build/Development Analysis

- Uses modern build tooling (Webpack/Parcel)
- Properly minified bundles with source map references removed
- LICENSE.txt files included for third-party libraries
- Code appears to be TypeScript compiled to JavaScript
- Uses React with hooks (modern development practices)
- No obfuscation beyond standard minification

---

## Overall Risk Assessment

### Risk Level: **CLEAN**

### Summary
Tabli is a legitimate, well-built tab management extension with no security issues. The extension:

✓ Uses only necessary permissions
✓ Contains no network communication
✓ Has no tracking or analytics
✓ Does not collect user data
✓ Contains no malicious code
✓ Uses standard, licensed libraries
✓ Follows Chrome extension best practices
✓ Migrated to Manifest V3

### Recommendation
**SAFE TO USE** - This extension poses no security or privacy risk to users.

---

## Technical Details

**Analyzed Files**: 20 JavaScript/JSON files
**Total Code Size**: ~5MB bundled JavaScript
**Primary Language**: TypeScript (compiled)
**UI Framework**: React 16.13.1+
**Build Tool**: Webpack (inferred from bundle structure)
**Last Updated**: April 1, 2025 (version 4.0.4)

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5 (Automated Security Analysis)
