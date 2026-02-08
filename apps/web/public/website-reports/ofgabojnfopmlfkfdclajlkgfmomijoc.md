# FACEIT Lobby King Extension - Security Analysis Report

## Metadata

- **Extension Name**: FACEIT Lobby King Extension
- **Extension ID**: ofgabojnfopmlfkfdclajlkgfmomijoc
- **Version**: 1.2.0
- **Users**: ~40,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

The FACEIT Lobby King Extension is a gaming companion tool that provides match statistics and player analytics for FACEIT.com users. The extension displays lobby stats to help CS:GO/CS2 players make informed map veto decisions during competitive matches.

**Overall Risk Level: CLEAN**

This extension serves its legitimate gaming statistics purpose with appropriate permissions and transparent data handling. While it includes third-party analytics (Sentry) and makes network requests to FACEIT APIs, all behavior is consistent with its stated functionality. The extension does not exhibit malicious characteristics, does not harvest sensitive user data, and does not engage in deceptive practices.

## Vulnerability Details

### 1. Third-Party Error Tracking (Sentry)

**Severity**: LOW
**Files**: `content.js` (lines 21338-21340), `popup.js`
**Status**: Acceptable

**Description**:
The extension integrates Sentry error tracking with DSN:
```javascript
dsn: "https://744595388b78400cb2f90b469038fe29@o4504079983902720.ingest.sentry.io/4504079985344512",
tracesSampleRate: 0,
integrations: [new Qa]
```

**Code Evidence**:
```javascript
// content.js line 21338
window.addEventListener("load", (function() {
  Xi({
    dsn: "https://744595388b78400cb2f90b469038fe29@o4504079983902720.ingest.sentry.io/4504079985344512",
    tracesSampleRate: 0,
    integrations: [new Qa]
  })
}))
```

**Verdict**: The Sentry integration is configured with `tracesSampleRate: 0`, meaning performance tracing is disabled. Only error reports would be sent. This is a standard development practice for production applications and does not represent a security risk. The extension does not capture sensitive user data through Sentry.

---

### 2. FACEIT API Access

**Severity**: CLEAN
**Files**: `content.js` (lines 14245, 14260-14264)
**Status**: Legitimate functionality

**Description**:
The extension makes API calls to the official FACEIT API to retrieve match and user data:

**Code Evidence**:
```javascript
// content.js line 14245
fetch("https://www.faceit.com/api" + t)

// API wrapper functions
var Qn = function() {
    return Zn("/users/v1/sessions/me")
  },
  Xn = function(e) {
    return Zn("/match/v2/match/".concat(e))
  };
```

**Verdict**: CLEAN - The extension only accesses the FACEIT API to retrieve public match and player statistics, which is the core functionality described in the extension's purpose. The API calls are limited to:
- `/users/v1/sessions/me` - Get current user session
- `/match/v2/match/{id}` - Get match details

No sensitive data is exfiltrated, and all API interactions are with the legitimate FACEIT platform.

---

### 3. Embedded iFrame Communication

**Severity**: CLEAN
**Files**: `content.js` (lines 13844-13847, 10220)
**Status**: Legitimate feature

**Description**:
The extension injects an iframe to display statistics overlays:

**Code Evidence**:
```javascript
// content.js line 13844
id: "lobbyking-embed",
forwardRef: w,
className: D(!C && _.hidden, N && _.loading, C && !N && _.iframeOpen, _.iframe),
src: "".concat("https://lobbyking.app", "/").concat(d, "/lobby/").concat(o, "/embed?").concat(H),
```

**Verdict**: CLEAN - The iframe loads content from the extension's official website (lobbyking.app) to display player statistics. The postMessage communication is used for legitimate UI updates and data passing between the content script and the embedded stats viewer. The origin checking is properly implemented (lines 10033-10044).

---

### 4. Chrome Storage API Usage

**Severity**: CLEAN
**Files**: `content.js` (lines 14655-14658, 2425)
**Status**: Legitimate functionality

**Description**:
The extension uses Chrome storage for user preferences:

**Code Evidence**:
```javascript
// content.js line 2425
t.storage = "undefined" != typeof chrome && void 0 !== chrome.storage ?
  chrome.storage.local :
  function() {
    return window.localStorage
  }

// Form sync with storage
chrome.storage.onChanged.addListener(this._handleStorageChangeOnForm)
```

**Verdict**: CLEAN - The storage is used only for storing user settings and preferences (language, UI state, etc.). No sensitive data like passwords or cookies are accessed or stored.

---

### 5. DOM Manipulation and MutationObserver

**Severity**: CLEAN
**Files**: `content.js` (lines 21325-21328, 21300-21303)
**Status**: Required for functionality

**Description**:
The extension uses MutationObserver to detect DOM changes on FACEIT pages:

**Code Evidence**:
```javascript
// content.js line 21325
a.observe(document.body, {
  childList: !0,
  subtree: !0
});
```

**Verdict**: CLEAN - The MutationObserver is necessary to detect when lobby/match pages load dynamically on FACEIT.com so the extension can inject the appropriate statistics overlay. This is standard practice for content scripts that need to respond to single-page application navigation.

---

## False Positives

| Pattern | Location | Explanation |
|---------|----------|-------------|
| Sentry SDK hooks | content.js, popup.js | Standard error tracking SDK - known FP per CLAUDE.md |
| React SVG innerHTML | Throughout bundled React code | Standard React rendering - known FP per CLAUDE.md |
| Console hooking | content.js line 1251 | Part of Sentry SDK error capture - legitimate debugging |
| XMLHttpRequest wrapping | content.js lines 1296-1297 | Sentry SDK breadcrumb tracking - not malicious |
| fetch() wrapping | content.js lines 1344-1387 | Sentry SDK breadcrumb tracking - not malicious |
| localStorage/sessionStorage | content.js lines 20141-20186 | i18next language detection library - legitimate |
| addEventListener wrapping | content.js line 1264 | Sentry SDK event tracking - not malicious |
| String.fromCharCode | content.js line 2554 | LZString compression library - legitimate encoding |
| Function.prototype.apply.call | content.js line 2407 | Debug library console logging - not malicious |
| eval regex patterns | content.js lines 16532-16551 | Sentry stack trace parsing - not dynamic eval execution |

## API Endpoints Contacted

| Endpoint | Purpose | Risk Level | Data Sent |
|----------|---------|------------|-----------|
| https://www.faceit.com/api/users/v1/sessions/me | Get current user session | LOW | None (authenticated request) |
| https://www.faceit.com/api/match/v2/match/{id} | Retrieve match statistics | LOW | Match ID from URL |
| https://lobbyking.app/{lang}/lobby/{id}/embed | Load stats embed iframe | LOW | Match ID, window dimensions, UI preferences |
| https://fonts.googleapis.com/css2 | Load custom fonts | MINIMAL | None (CDN request) |
| https://o4504079983902720.ingest.sentry.io | Error reporting | LOW | Error stack traces (no PII) |

## Data Flow Summary

### Data Collection:
1. **FACEIT Match Data**: Extension reads the current URL on faceit.com to extract match/lobby IDs
2. **User Session**: Queries FACEIT API for the logged-in user's session data
3. **Match Statistics**: Fetches public match data from FACEIT API
4. **User Preferences**: Stores UI settings (language, tooltip states) in chrome.storage

### Data Processing:
1. Match data is parsed and formatted for display in the overlay
2. Player statistics are computed from FACEIT API responses
3. Data is passed to the lobbyking.app embed via postMessage for visualization

### Data Transmission:
1. **To FACEIT API**: Match IDs from current page URL
2. **To lobbyking.app**: Match data and user preferences for stats display
3. **To Sentry**: Error reports (no sensitive data, tracing disabled)

### Data Storage:
- **Chrome Storage (sync)**: User preferences, language settings
- **No credential storage**: Does not access or store passwords, cookies, or auth tokens beyond what FACEIT.com already provides

## Permissions Analysis

### Declared Permissions:
- `https://api.faceit.com/` - Required for API access to fetch match statistics
- `storage` - Required for saving user preferences

### Content Script Injection:
- Matches: `https://www.faceit.com/*`, `https://beta.faceit.com/*`
- Purpose: Inject stats overlay on FACEIT lobby pages

### Web Accessible Resources:
- `assets/**` - Images, fonts, and UI resources accessible to all URLs
- Risk: Minimal - only static assets, no executable code

**Assessment**: All permissions are minimal and directly necessary for the stated functionality. No excessive permissions requested.

## Content Security Policy

No CSP declared in manifest.json (MV3 default CSP applies). The extension does not use inline scripts or eval in ways that would violate CSP.

## Privacy & Data Handling

### Positive Findings:
- No credential harvesting detected
- No cookie theft mechanisms
- No keylogging functionality
- No XHR/fetch hooking for data interception (Sentry hooks are benign)
- No extension enumeration/fingerprinting
- No ad injection or coupon manipulation
- No residential proxy infrastructure
- No remote code execution capabilities

### Data Minimization:
The extension only accesses data necessary for its core functionality (match IDs, public player stats). It does not request access to:
- Browsing history
- Cookies beyond FACEIT.com domain
- Cross-origin requests outside FACEIT and lobbyking.app
- Clipboard data
- Microphone/camera
- Downloads or filesystem

## Code Quality Observations

1. **Bundled Dependencies**: Uses standard React, Sentry SDK, i18next, and other legitimate libraries
2. **Minification**: Code is production-bundled but not obfuscated beyond standard webpack minification
3. **No Anti-Analysis**: No attempts to detect debugging or analysis tools
4. **No Kill Switch**: No remote configuration that could disable or modify behavior
5. **Transparent Operation**: All network requests are to documented, expected endpoints

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification:

This extension is a legitimate gaming companion tool that transparently provides match statistics for FACEIT players. While it does require content script injection and makes external API calls, all behavior is directly related to its stated purpose.

**Why CLEAN and not LOW:**
1. All permissions are minimally scoped and necessary
2. No sensitive data collection beyond what's required for functionality
3. API calls are exclusively to the official FACEIT platform and the extension's own domain
4. No deceptive practices, hidden functionality, or malicious code patterns
5. Error tracking (Sentry) is configured conservatively with tracing disabled
6. Uses standard, legitimate libraries without suspicious modifications
7. No evidence of data exfiltration, user tracking beyond functional needs, or privacy violations

**Invasiveness Explanation**:
While the extension injects content scripts and embeds iframes on FACEIT pages, this is explicitly required for its core functionality (displaying stats overlays). The extension clearly serves its intended purpose without malicious side effects. Users installing this extension expect and desire the modifications it makes to FACEIT pages.

### Recommendations:
1. Consider adding a manifest CSP declaration for defense-in-depth
2. Document Sentry data collection in privacy policy (if not already present)
3. Minimize bundled dependencies to reduce attack surface (optional optimization)

### Conclusion:

The FACEIT Lobby King Extension is a clean, purpose-built tool that enhances the FACEIT competitive gaming experience. It exhibits no malicious behavior, respects user privacy within the bounds of its legitimate functionality, and uses permissions appropriately. Safe for use.
