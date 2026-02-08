# Vulnerability Analysis Report: FocusGuard - Free Site Blocker

## Extension Metadata
- **Extension Name**: FocusGuard - Free Site Blocker
- **Extension ID**: ifdepgnnjpnbkcgempionjablajancjc
- **Version**: 1.0.5
- **Users**: ~90,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

FocusGuard is a **CLEAN** productivity extension that implements legitimate site blocking and focus timer features. The extension uses React for UI rendering and appears to be a standard Pomodoro-style productivity tool. No malicious behavior, suspicious network activity, or privacy violations were detected. The extension follows Chrome extension best practices with appropriate use of permissions and secure local storage for user settings.

**Overall Risk Level: CLEAN**

## Detailed Analysis

### 1. Manifest Permissions Analysis

**Declared Permissions:**
- `tabs` - Used to query and update tab URLs for site blocking
- `storage` - Local data storage for user settings
- `unlimitedStorage` - For storing user configuration
- `alarms` - Timer functionality for focus/break cycles
- `favicon` - Display site icons
- `commands` - Keyboard shortcuts (Ctrl+Shift+Y, Ctrl+Shift+U)
- `contextMenus` - Add pages to block/exception lists
- `notifications` - User notifications for timer events
- `offscreen` - Audio playback for notification sounds

**Host Permissions:**
- `*://*/*` - Broad access required for site blocking functionality

**Verdict**: All permissions are justified and align with advertised functionality. The broad host permission is necessary for checking URLs against blocklists.

**Severity**: N/A (Legitimate)

### 2. Background Service Worker Analysis

**File**: `js/service_worker.js` (39KB)

**Key Functionality:**
- Manages focus timer sessions (start/stop/pause/resume)
- Creates Chrome alarms for timed sessions
- Blocks/unblocks tabs based on user configuration
- Handles badge colors for status indication
- Manages context menu items
- Sends notifications via offscreen API
- Validates URLs against user-defined blocklists/exceptions

**Network Activity**: None detected. No fetch/XHR calls present.

**Data Storage**: Uses chrome.storage.local exclusively for:
- User settings (sites to block, timer durations, preferences)
- Current session state (focusStatus, currentCycle, timeBeforePause)
- Default sites: youtube.com, facebook.com, instagram.com, web.whatsapp.com, twitter.com, reddit.com
- Optional password protection for blocking settings

**Critical Code Review:**
```javascript
// Line 401-421: Default settings - all stored locally
defaultSettings = {
    badge: true,
    cleanBlockPage: false,
    notification: true,
    audio: false,
    autoStart: false,
    exceptions: [],
    sites: ["youtube.com", "facebook.com", ...],
    tabIdsInBlock: [],
    time: 25,
    break: 5,
    serie: 2,
    mode: "focus",
    focusStatus: "waiting",
    siteBlockerPassword: "",
    installation_date: (new Date).getTime()
}
```

**Verdict**: Clean implementation with no suspicious behavior.

**Severity**: N/A (Legitimate)

### 3. Content Script Analysis

**File**: `js/checker.js` (2.3KB)

**Functionality:**
- Injects into all pages at document_start
- Monitors URL changes every 1 second
- Sends current URL to background via chrome.runtime.connect
- Uses two message channels: "focus-mode-channel" and "only-block-channel"

**Code Review:**
```javascript
// Lines 31-53: URL monitoring and reporting
this.myPort = chrome.runtime.connect({ name: "focus-mode-channel" });
this.myPort.postMessage({ url: window.location.href });
this.myPort1 = chrome.runtime.connect({ name: "only-block-channel" });
this.myPort1.postMessage({ url: window.location.href });
```

**Data Exfiltration Risk**: None. All messages stay within the extension (chrome.runtime.connect is local-only).

**Verdict**: Legitimate URL checking for site blocking functionality. No DOM manipulation, no data harvesting.

**Severity**: N/A (Legitimate)

### 4. UI Components Analysis

**Files Analyzed:**
- `popup.js` (490KB) - Extension popup interface
- `options.js` (447KB) - Settings page
- `block.js` (320KB) - Block page UI

**Framework**: React 18 (minified production build)

**External Resources**:
- Google Fonts API (fonts.googleapis.com) - CSS import only, no tracking
- SVG icons embedded as data URIs (no external requests)

**Functionality**:
- Timer controls (start/stop/pause/skip break)
- Site blocklist management (add/remove sites and exceptions)
- Password protection option (stored locally via chrome.storage)
- Audio/notification preferences
- Keyboard shortcut display

**Notable Security Features**:
- Password validation library included (password-validator)
- Input sanitization via React (prevents XSS)
- No eval() or Function() constructor usage
- No innerHTML manipulation outside React

**Verdict**: Standard React application with no security concerns.

**Severity**: N/A (Legitimate)

### 5. Offscreen Document

**File**: `offscreen.js` (190 bytes)

**Purpose**: Audio playback for notification sounds (bell.wav)

```javascript
chrome.runtime.onMessage.addListener((function(e) {
    "play" in e && (r = new Audio, r.src = o, r.volume = a, r.play());
}));
```

**Verdict**: Minimal implementation for Chrome MV3 audio playback requirement. No security issues.

**Severity**: N/A (Legitimate)

### 6. Potential Attack Vectors Investigated

| Attack Vector | Finding | Risk |
|--------------|---------|------|
| Remote code execution | No eval/Function/dynamic imports | ✅ Clean |
| Data exfiltration | No network requests detected | ✅ Clean |
| Cookie harvesting | No cookie access code | ✅ Clean |
| Keylogging | No keyboard event listeners | ✅ Clean |
| Extension enumeration | No chrome.management usage | ✅ Clean |
| XHR/fetch hooking | No prototype manipulation | ✅ Clean |
| Residential proxy | No proxy configuration | ✅ Clean |
| Ad injection | No DOM manipulation in content scripts | ✅ Clean |
| Analytics SDKs | No third-party SDKs detected | ✅ Clean |
| Remote config | No remote endpoints | ✅ Clean |

### 7. False Positives

| Pattern | Context | Explanation |
|---------|---------|-------------|
| React error URLs | `https://reactjs.org/docs/error-decoder.html` | Hardcoded error message URL in React library (never executed) |
| SVG namespace URIs | `http://www.w3.org/2000/svg` | XML namespace declarations (not network requests) |
| Google Fonts | `fonts.googleapis.com` | CSS @import for Lato font family (legitimate UI resource) |

### 8. API Endpoints

**External Endpoints**: None

**Chrome APIs Used**:
- chrome.storage.local - User settings persistence
- chrome.tabs - Query/update tabs for blocking
- chrome.alarms - Timer management
- chrome.notifications - User notifications
- chrome.contextMenus - Right-click menu options
- chrome.commands - Keyboard shortcuts
- chrome.offscreen - Audio playback
- chrome.runtime - Message passing (internal)

All API usage is appropriate and follows Chrome extension best practices.

### 9. Data Flow Summary

```
User Input (popup/options)
    ↓
chrome.storage.local (blocklist, settings)
    ↓
Service Worker (monitors settings changes)
    ↓
Content Script (checks current URL against blocklist)
    ↓
Service Worker (redirects to block page if match)
    ↓
Block Page (displays blocked site UI)
```

**External Data Flows**: None. All data remains on-device.

**Privacy Assessment**: Excellent. No telemetry, no analytics, no network requests.

## Overall Risk Assessment

**Risk Level: CLEAN**

FocusGuard is a legitimate productivity extension with no security vulnerabilities or privacy concerns. The extension:

✅ Uses all permissions appropriately for advertised features
✅ Stores all data locally with no external communication
✅ Does not manipulate page content beyond blocking functionality
✅ Does not inject ads, trackers, or malicious code
✅ Does not access sensitive user data (cookies, localStorage, etc.)
✅ Follows Chrome MV3 best practices
✅ Implements optional password protection for user safety

**Recommendation**: Safe for continued use. Extension provides genuine value without privacy trade-offs.

## Technical Notes

- **Build System**: Webpack/Babel (minified React bundles)
- **Code Quality**: Professional development patterns, no obfuscation beyond standard minification
- **Update URL**: Standard Chrome Web Store update channel
- **CSP**: None declared (relies on MV3 default CSP)

## Analyst Comments

This is a well-implemented focus timer extension with clean code and no red flags. The broad host_permissions declaration (`*://*/*`) may raise eyebrows, but is technically necessary for the site blocking feature to work across all domains. The extension could improve by using declarativeNetRequest for blocking instead of tab.update redirects, but the current approach is not malicious.

The presence of password protection and the option to exempt specific pages shows thoughtful UX design. No indicators of monetization, tracking, or data collection beyond core functionality.

---

**Analysis Completed**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Confidence Level**: High
