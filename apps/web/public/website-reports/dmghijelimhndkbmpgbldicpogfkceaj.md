# Security Analysis: Dark Mode (dmghijelimhndkbmpgbldicpogfkceaj)

## Extension Metadata
- **Name**: Dark Mode
- **Extension ID**: dmghijelimhndkbmpgbldicpogfkceaj
- **Version**: 0.5.4
- **Manifest Version**: 3
- **Estimated Users**: ~2,000,000
- **Developer**: mybrowseraddon.com
- **Analysis Date**: 2026-02-14

## Executive Summary
Dark Mode is a legitimate dark theme extension with **MEDIUM** risk status. The extension provides comprehensive dark mode functionality for web pages through CSS manipulation and color inversion. While the core functionality is benign and serves its stated purpose, the extension contains a **postMessage handler vulnerability** that lacks origin validation, potentially allowing malicious websites to manipulate the extension's behavior through cross-frame messaging attacks.

The extension does not exfiltrate data, track users, or engage in malicious behavior. The <all_urls> host permission is justified for its dark mode functionality. The primary security concern is the exploitable postMessage handler.

**Overall Risk Assessment: MEDIUM**

## Vulnerability Assessment

### 1. postMessage Handler Without Origin Validation (MEDIUM)
**Severity**: MEDIUM
**Files**:
- `/data/content_script/inject.js` (lines 108-140, 969)

**Analysis**:
The extension registers a window message event listener without validating the message origin, allowing any webpage or malicious iframe to send crafted messages that trigger extension functionality.

**Code Evidence** (`data/content_script/inject.js:108-140`):
```javascript
"message": function (e) {
  if (e) {
    if (e.data) {
      if (e.data.from) {
        if (e.data.from === "native-dark-context-shadownode") {
          if (config.native.shadow.timeout) window.clearTimeout(config.native.shadow.timeout);
          config.native.shadow.timeout = window.setTimeout(function () {
            config.native.shadow.find.stylesheets(document.documentElement);
          }, 100);
        }
        //
        if (e.data.from === "native-dark-context-top-for-exclude") {
          if (e.data.darkness === true) {
            const options = {"frameId": e.data.frameId};
            config.apply.style({"loc": 10, "href_g": '', "href_c": '', "text_c": '', "text_n": '', "options": options});
          }
        }
        //
        if (e.data.from === "native-dark-context-iframe-for-exclude") {
          if (e.source) {
            if (e.source.postMessage) {
              e.source.postMessage({
                "frameId": e.data.frameId,
                "darkness": config.native.darkness,
                "from": "native-dark-context-top-for-exclude"
              }, '*');
            }
          }
        }
      }
    }
  }
},
```

**Registered at line 969**:
```javascript
window.addEventListener("message", config.message, false);
```

**Vulnerability Details**:
1. **No origin check**: The handler processes messages from any origin without validating `e.origin`
2. **Minimal input validation**: Only checks `e.data.from` string values, which can be easily spoofed
3. **Triggerable actions**: Malicious messages can:
   - Trigger `config.native.shadow.find.stylesheets()` to scan for stylesheets
   - Call `config.apply.style()` with controlled `frameId` parameter
   - Cause the extension to respond with internal state (`config.native.darkness`)

**Attack Scenario**:
A malicious website could inject an iframe and send crafted postMessage events:
```javascript
// Malicious page code
window.postMessage({
  from: "native-dark-context-top-for-exclude",
  darkness: true,
  frameId: 0
}, '*');
```

This would trigger `config.apply.style()` with attacker-controlled frameId, potentially causing unintended dark mode application or removal.

**Impact Assessment**:
- **Severity**: MEDIUM (not HIGH) because:
  - The exploit only affects visual rendering (dark mode application)
  - No sensitive data exposure or exfiltration possible
  - No code execution or privilege escalation
  - Requires active user browsing of a malicious site
  - Impact limited to cosmetic changes and potential UI confusion

**Remediation**:
Add origin validation to the message handler:
```javascript
"message": function (e) {
  // Validate origin - only accept messages from same origin or extension context
  if (e.origin !== window.location.origin && !e.origin.startsWith('chrome-extension://')) {
    return; // Reject cross-origin messages
  }
  // ... rest of handler
}
```

**Verdict**: **MEDIUM RISK** - Exploitable but limited impact scope.

---

### 2. Broad Host Permissions (<all_urls>)
**Severity**: N/A (Justified by Functionality)
**Manifest**: `manifest.json` line 8

**Analysis**:
The extension requests `<all_urls>` host permissions, which grants access to all websites.

**Code Evidence** (`manifest.json:8`):
```json
"host_permissions": ["<all_urls>"]
```

**Justification**:
This broad permission is **necessary and appropriate** for the extension's stated purpose:
1. Dark mode must be applied to all websites the user visits
2. Content scripts inject dark theme CSS into every page
3. The extension dynamically fetches and processes stylesheets from any domain

**Usage Verification**:
Analysis of `data/content_script/inject.js` and `data/content_script/resources/native.js` confirms permissions are used exclusively for:
- Injecting dark mode CSS styles
- Analyzing page stylesheets to invert colors
- Applying custom CSS rules based on page content
- Fetching cross-origin stylesheets for theme application

**Network Activity**:
All `fetch()` calls found (line 527 in `native.js`, line 86 in `common.js`) are for:
- **Same-origin stylesheet fetching** (with origin validation in native.js:525-526)
- **Extension resource loading** (explore.json for options page)
- **No external tracking or data exfiltration**

**Verdict**: **NOT MALICIOUS** - Broad permissions are functionally required and properly utilized.

---

## Functionality Analysis

### Core Features
1. **Dark Mode Application**:
   - Applies CSS-based dark themes to web pages
   - Supports multiple theme engines (native CSS inversion, custom themes, general themes)
   - Whitelisting/blacklisting of specific domains
   - Shadow DOM support with dynamic stylesheet detection

2. **Configuration Options**:
   - Color temperature adjustment overlay
   - Scheduled dark mode activation (using optional `alarms` permission)
   - Per-domain customization
   - Context menu integration for quick exclude/include

3. **Advanced CSS Manipulation**:
   - Dynamic stylesheet parsing and color inversion
   - CSS variable manipulation
   - Custom CSS rule injection
   - Background image darkening

### Legitimate Code Patterns

**1. Stylesheet Fetching** (`data/content_script/resources/native.js:524-548`):
```javascript
if (origin_1 === origin_2) {
  try {
    let response = await fetch(href, {"cache": "default"});
    // Process response for dark theme application
  } catch (e) {
    background.send("fetch", {"href": href, "index": index});
  }
} else {
  background.send("fetch", {"href": href, "index": index});
}
```
**Purpose**: Fetches stylesheets from the current page's origin to apply dark mode transformations. Cross-origin stylesheets are delegated to background script (which has necessary CORS permissions).

**2. Shadow DOM Hooking** (`data/content_script/page_context/inject.js:4-36`):
```javascript
Element.prototype.attachShadow = new Proxy(Element.prototype.attachShadow, {
  apply(target, self, args) {
    // Ensures shadow roots are set to mode: "open" for dark mode access
    if (args) {
      if (args[0]) {
        if (args[0].mode) {
          args[0].mode = "open";
        }
      }
    }
    return Reflect.apply(target, self, args);
  }
});
```
**Purpose**: Intercepts Shadow DOM creation to force open mode, allowing dark mode CSS to penetrate shadow boundaries. This is standard practice for theme extensions but could be flagged by security scanners.

**3. Temporary Dark Mode Flash Prevention** (`inject.js:141-179`):
```javascript
"temporarily": {
  "remove": function (delay, loc) {
    if (delay) {
      if (config.temporarily.timeout) window.clearTimeout(config.temporarily.timeout);
      config.temporarily.timeout = window.setTimeout(function () {
        document.documentElement.removeAttribute(config.temporarily.id.start);
        // ... remove temporary attributes
      }, delay);
    }
  }
}
```
**Purpose**: Manages temporary CSS attributes to prevent "white flash" during page load before dark mode applies.

---

## Network Communication Analysis

### Endpoints Contacted
1. **mybrowseraddon.com** (Developer website)
   - Referenced in `manifest.json` as `homepage_url`
   - Background script contains references for support/tutorial pages
   - **No evidence of active network calls to this domain**

2. **webbrowsertools.com** (Test page)
   - Referenced in `lib/config.js:9` as test URL for dark mode demo
   - Opened when user clicks "Test Dark Mode" in options
   - **User-initiated only, no automatic connections**

3. **Local Resource Fetching**:
   - `chrome.runtime.getURL()` for loading bundled CSS themes
   - Same-origin `fetch()` for page stylesheets (with origin validation)
   - Options page loads `explore/explore.json` (local extension file)

### Data Transmission Analysis
**No external data transmission detected.**

Comprehensive search for network patterns (`fetch`, `XMLHttpRequest`, `.send`, `.open`) revealed:
- All `fetch()` calls are for same-origin or extension-local resources
- Background script `fetch()` (common.js:86-96) only fetches URLs passed by content script for CORS bypass
- No analytics, tracking pixels, or telemetry
- No user data, browsing history, or tab URLs sent externally

**Verdict**: **CLEAN** - No data exfiltration or tracking behavior.

---

## Privacy Analysis

### Data Collection
**None detected.**

The extension:
- Stores user preferences in `chrome.storage.local` (whitelist, theme settings, schedule)
- Does not access cookies, localStorage, or IndexedDB from pages
- Does not log or transmit browsing history
- Does not fingerprint users

### Local Storage Usage
Review of `lib/common.js:268-380` (storage initialization) shows storage is used only for:
- User theme preferences (color schemes, CSS variables)
- Domain whitelists/blacklists
- UI settings (temporary flash prevention, schedule settings)
- **No identifiable user information**

### Permissions Justification
| Permission | Justification | Usage |
|------------|---------------|-------|
| `storage` | Required | Stores user preferences, whitelists, custom CSS |
| `contextMenus` | Convenience | Right-click menu for "Exclude from dark mode" |
| `<all_urls>` | Core feature | Injects dark mode CSS into all websites |
| `alarms` (optional) | Scheduling | Time-based dark mode activation/deactivation |

**Verdict**: **APPROPRIATE** - All permissions match stated functionality.

---

## Code Quality & Obfuscation

### Obfuscation Level
**Low to None**:
- Code is beautified and readable
- Variable names are descriptive (`config.apply.style`, `native.dark.engine`)
- Function logic is clear and well-structured
- No string encryption or control flow obfuscation
- Comments present (though minimal)

### Code Patterns
- **Well-organized**: Modular structure with separate files for content scripts, background, options
- **Standard practices**: Uses modern Chrome extension APIs (MV3, service worker)
- **Performance-conscious**: Debouncing, mutation observers, performance monitoring

**Verdict**: **CLEAN** - No signs of intentional obfuscation or code hiding.

---

## False Positive Flags

### 1. Shadow DOM Proxying (NOT MALICIOUS)
**Flagged by**: AST analyzers may flag `Element.prototype.attachShadow = new Proxy(...)`
**Explanation**: This is standard practice for theme extensions that need to apply styles inside Shadow DOM components. Forces shadow roots to open mode for CSS access.
**Verdict**: **FALSE POSITIVE**

### 2. Broad Host Permissions (NOT MALICIOUS)
**Flagged by**: Permission analysis tools flagging `<all_urls>`
**Explanation**: Functionally required for dark mode to work on all websites.
**Verdict**: **FALSE POSITIVE**

### 3. Message Event Listener (PARTIALLY TRUE)
**Flagged by**: Security scanners detecting `window.addEventListener("message")`
**Explanation**: While this IS a real vulnerability (missing origin check), the impact is limited to cosmetic changes, not data theft.
**Verdict**: **TRUE POSITIVE** (but MEDIUM severity, not HIGH)

---

## Comparison to Malicious Patterns

### What This Extension DOES NOT Do:
- No data exfiltration or external network calls
- No cookie theft or credential harvesting
- No code injection or script execution
- No cryptocurrency mining
- No ad injection or affiliate link manipulation
- No keylogging or form monitoring
- No remote code loading
- No fingerprinting or tracking
- No use of `eval()`, `Function()`, or `executeScript()` with dynamic code

### Benign Characteristics:
- Single, focused purpose (dark mode)
- Transparent functionality matching description
- No network activity beyond resource loading
- Minimal permissions for stated purpose
- No signs of obfuscation
- Developer identity (mybrowseraddon.com) consistent across extensions

---

## Recommendations

### For Users:
1. **Safe to use** with awareness of postMessage vulnerability
2. The extension performs its stated function without malicious side effects
3. Vulnerability has limited impact (cosmetic only)
4. Consider using on trusted sites only if highly security-conscious

### For Developer:
1. **CRITICAL**: Add origin validation to postMessage handler (lines 108-140 in inject.js)
2. Consider using `chrome.runtime.onMessage` instead of `window.postMessage` for extension-internal communication
3. Implement CSP (Content Security Policy) in manifest to prevent future injection risks
4. Add signature verification for inter-frame messages

### For Security Researchers:
1. Focus on postMessage handler as primary attack surface
2. Test cross-origin iframe message injection scenarios
3. Verify that Shadow DOM proxying doesn't expose unexpected attack vectors
4. Monitor for updates that may change security posture

---

## Conclusion

**Dark Mode (dmghijelimhndkbmpgbldicpogfkceaj)** is a **legitimate extension with MEDIUM risk** due to a single exploitable vulnerability. The extension serves its stated purpose (applying dark themes) without engaging in data collection, tracking, or malicious behavior. The <all_urls> permission is justified and properly utilized.

The postMessage handler vulnerability is the sole security concern, rated MEDIUM (not HIGH) because exploitation only affects visual rendering and does not compromise user data or system security. With 2 million users, this represents a significant attack surface for UI manipulation attacks, but the practical risk to users is limited.

**Final Verdict**: **MEDIUM RISK** - Functional dark mode extension with a fixable postMessage vulnerability. Recommended for use with awareness of the limitation.

---

## Technical Appendix

### Files Analyzed
- `manifest.json` - Extension metadata and permissions
- `background.js` - Service worker initialization
- `lib/common.js` - Background script core logic
- `lib/config.js` - Configuration constants
- `lib/chrome.js` - Chrome API wrappers
- `lib/runtime.js` - Runtime utilities
- `data/content_script/inject.js` - Main content script (969 lines)
- `data/content_script/resources/native.js` - Dark mode engine
- `data/content_script/page_context/inject.js` - Shadow DOM hook
- `data/options/options.js` - Options UI logic
- `data/rules/rules.js` - Site-specific theme rules

### Analysis Methodology
1. Static code analysis of deobfuscated JavaScript
2. Network endpoint enumeration via regex pattern matching
3. Permission justification through code flow tracing
4. postMessage handler security audit
5. Comparison against known malware patterns

### Tools Used
- ext-analyzer (Babel AST static analyzer)
- Manual code review
- Pattern matching for security indicators
