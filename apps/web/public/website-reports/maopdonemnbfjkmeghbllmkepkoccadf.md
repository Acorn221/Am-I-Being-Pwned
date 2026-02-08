# Vulnerability Report: Dualless for Google Chrome

## Extension Metadata
- **Name**: Dualless for Google Chrome
- **Extension ID**: maopdonemnbfjkmeghbllmkepkoccadf
- **Version**: 3.1.0
- **User Count**: ~70,000
- **Manifest Version**: 3
- **Homepage**: https://dualless.pdfwork.com

## Executive Summary

Dualless is a window management utility extension that helps users arrange browser windows side-by-side across multiple displays. The extension has been thoroughly analyzed and is determined to be **CLEAN** with no security vulnerabilities or malicious behavior detected.

The extension operates entirely locally, uses minimal permissions appropriate to its functionality, contains no external network communication, no tracking/analytics, and implements standard window arrangement functionality without any suspicious code patterns.

## Vulnerability Analysis

### Network Communication
**Severity**: NONE
**Status**: CLEAN

**Finding**: No network communication detected.

**Evidence**:
- No `fetch()`, `XMLHttpRequest`, or network API calls found in any source files
- No external URLs in JavaScript code (only local links to Chrome Web Store and homepage)
- The only URLs found are:
  - `link.js:7`: Links to Chrome Web Store reviews or Microsoft Edge addons (generated dynamically based on extension ID)
  - `manifest.json`: Standard Chrome Web Store update URL

**Verdict**: The extension operates entirely offline and makes no network requests.

---

### Permissions Analysis
**Severity**: NONE
**Status**: CLEAN

**Permissions Requested**:
```json
"permissions": [ "system.display", "windows", "storage", "sidePanel" ]
```

**Analysis**:
- `system.display`: Necessary to query monitor information and screen dimensions
- `windows`: Required to arrange, resize, and manage browser windows
- `storage`: Used for saving user preferences (single screen policy, settings visibility)
- `sidePanel`: Provides UI in Chrome's side panel (MV3 feature)

**Verdict**: All permissions are minimal, justified, and directly related to core functionality. No sensitive permissions requested (no cookies, webRequest, tabs content access, etc.).

---

### Content Script Injection
**Severity**: NONE
**Status**: CLEAN

**Finding**: No content scripts or dynamic script injection.

**Evidence**:
- No `content_scripts` in manifest.json
- No `chrome.scripting.executeScript()` calls in background service
- Extension operates purely through browser windows API
- No DOM manipulation on web pages

**Verdict**: Extension does not interact with web page content at all.

---

### Dynamic Code Execution
**Severity**: NONE
**Status**: CLEAN

**Finding**: No dynamic code execution detected.

**Evidence**:
- No `eval()`, `Function()`, `new Function()` calls
- No `innerHTML` assignments (except in known false positive contexts)
- All code is static and loaded from extension files
- Material Web Components library uses standard Web Components APIs

**Verdict**: No dynamic code execution risks.

---

### Data Collection & Privacy
**Severity**: NONE
**Status**: CLEAN

**Finding**: No data collection, tracking, or privacy concerns.

**Evidence**:
- Settings stored only in `chrome.storage.local` (device-local)
- Settings data structure (`SettingsService.js`):
  ```javascript
  {
    states: [/* window layout presets */],
    distributeTab: false,
    singleScreenPrimary: false,
    hideSettings: false
  }
  ```
- No analytics SDKs (Google Analytics, Sentry, etc.)
- No telemetry or error reporting
- No tracking pixels or beacons
- No user identification

**Verdict**: Complete privacy. All data stays local.

---

### Extension Behavior Analysis
**Severity**: NONE
**Status**: CLEAN

**Core Functionality** (`WindowService.js`):
1. Queries existing browser windows
2. Creates new windows if needed for layouts
3. Resizes and positions windows based on screen dimensions
4. Minimizes extra windows
5. Displays temporary screen identifier overlays

**Screen Detection** (`ScreenService.js`):
- Uses `chrome.system.display.getInfo()` to detect monitors
- Checks for dual/multi-monitor setups

**Welcome Page** (`welcome.js`):
- Opens homepage on first install: `{homepage_url}/welcome`
- Sets uninstall URL: `{homepage_url}/uninstall`
- Standard extension onboarding pattern

**Verdict**: All behavior is legitimate and directly related to window management.

---

### Third-Party Libraries
**Severity**: NONE
**Status**: CLEAN

**Libraries Detected**:
- `materialweb.min.js` (497KB, 6863 lines): Google Material Web Components
- `bootstrap.min.css`: Bootstrap CSS framework
- `fontawesome`: Icon font library
- `roboto`: Google's Roboto font

**Analysis**:
- All libraries are legitimate, widely-used UI frameworks
- Material Web is Google's official web components library
- No suspicious code patterns in library usage
- Extension verified by Chrome Web Store (signed content hashes)

**Verdict**: Third-party libraries are safe and standard.

---

### Obfuscation Analysis
**Severity**: NONE
**Status**: CLEAN

**Finding**: Minimal obfuscation (standard minification only).

**Evidence**:
- Source code is readable and well-structured
- Variable names are minified in some files (standard build process)
- No string encoding, character substitution, or advanced obfuscation
- Logic flow is clear and straightforward
- Material Web library is minified (expected for production)

**Verdict**: No malicious obfuscation detected.

---

### Suspicious Patterns Check
**Severity**: NONE
**Status**: CLEAN

**Patterns Searched**:
- Extension killing/enumeration: NOT FOUND
- XHR/fetch hooking: NOT FOUND
- Proxy infrastructure: NOT FOUND
- Remote config/kill switches: NOT FOUND
- Market intelligence SDKs: NOT FOUND
- AI conversation scraping: NOT FOUND
- Ad/coupon injection: NOT FOUND
- Cookie harvesting: NOT FOUND
- Keyloggers: NOT FOUND
- postMessage manipulation: NOT FOUND

**Verdict**: No malicious patterns detected.

---

## False Positives

| Pattern | Location | Reason | Classification |
|---------|----------|--------|----------------|
| `innerHTML` usage | `common.js:52`, `common.js:68` | Localization helper setting translated text in DOM elements with `data-loc` attributes | Safe - controlled string replacement |
| Prototype modifications | `common.js` | Extends Element/String prototypes with helper methods (`.loc()`, `.setContent()`, etc.) | Benign - common pattern for utility methods |

---

## API Endpoints & External Domains

| Domain | Purpose | Risk Level |
|--------|---------|------------|
| `dualless.pdfwork.com` | Extension homepage (manifest) | LOW - informational only |
| `chromewebstore.google.com` | Review link (generated dynamically) | NONE - official store |
| `microsoftedge.microsoft.com` | Edge addons link (for Edge browser) | NONE - official store |
| `clients2.google.com/service/update2/crx` | Chrome Web Store update URL | NONE - standard CWS update mechanism |

**Note**: Extension code references these domains but does NOT make network requests to them. They are only used as href targets for user-clickable links.

---

## Data Flow Summary

```
User Interaction (Popup)
    ↓
SettingsService → chrome.storage.local (read/write user preferences)
    ↓
ScreenService → chrome.system.display.getInfo() (query monitor info)
    ↓
WindowService → chrome.windows API (arrange/resize windows)
    ↓
Local UI Update (no external communication)
```

**Data Sensitivity**: None - only window layout preferences stored locally.

---

## Code Quality Observations

**Positive Aspects**:
- Clean separation of concerns (Services pattern)
- Manifest V3 compliant (modern architecture)
- Uses ES6 modules
- Proper error handling in async operations
- Internationalization support (45 locales)
- Offline-capable (no external dependencies at runtime)

**Development Practices**:
- No console debugging left in production
- No commented-out suspicious code
- Proper use of Chrome APIs
- Follows extension best practices

---

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification**:
1. No network communication or external data transmission
2. Minimal permissions appropriate to functionality
3. No content script injection or page interaction
4. No data collection, tracking, or analytics
5. No dynamic code execution
6. No suspicious or obfuscated code patterns
7. Legitimate third-party libraries
8. Chrome Web Store verified signatures
9. Clean codebase with no malicious indicators

**Recommendation**: This extension is safe to use. It performs exactly what it advertises - window management across multiple displays - with no hidden functionality or privacy concerns.

---

## Conclusion

Dualless for Google Chrome is a legitimate, well-designed window management utility with no security vulnerabilities or malicious behavior. The extension operates entirely locally, requests only necessary permissions, and implements its functionality cleanly without any concerning patterns. It represents a good example of a privacy-respecting browser extension that does one thing well.
