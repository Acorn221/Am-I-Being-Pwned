# ShowPassword Extension Security Analysis

## Metadata
- **Extension ID**: bbiclfnbhommljbjcoelobnnnibemabl
- **Extension Name**: ShowPassword
- **Version**: 1.2.1
- **Users**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

ShowPassword is a simple password visibility toggle utility that allows users to reveal password field contents through various interaction methods (mouseover, double-click, focus, or Ctrl key). The extension is **CLEAN** with minimal permissions and no malicious behavior detected.

**Key Findings:**
- No network activity or external API calls
- No data exfiltration mechanisms
- No XHR/fetch hooking or SDK injection
- Legitimate use of chrome.storage.sync for user preferences only
- Simple DOM manipulation limited to password field type toggling
- No obfuscation or suspicious code patterns
- Easter egg navigation to Wikipedia (benign)

**Overall Risk: CLEAN**

## Vulnerability Analysis

### V1: Keydown Event Listeners - FALSE POSITIVE
**Severity**: NONE
**Location**: `showPassword.js` (lines 30-34, 50-54, 66-70, 103-118), `options.js` (lines 59-67)
**Type**: Event Monitoring

**Finding:**
The extension registers keydown/keyup event listeners on password fields and the options page preview field. Analysis confirms these are for legitimate UI functionality only:

```javascript
// showPassword.js - Toggle password visibility on Enter key
tar.addEventListener('keydown', e => {
  if (e.keyCode === KEY_ENTER) {
    tar.type = 'password'
  }
}, false)

// ctrlKeyShift function - Ctrl key toggle behavior
tar.addEventListener('keyup', e => {
  if (e.keyCode === KEY_CTRL) {
    if (onlyCtrl) {
      isHide = !isHide
    } else {
      isHide = false
    }
    if (isHide) {
      tar.type = 'password'
    } else {
      tar.type = 'text'
    }
    notPressCtrl = true
    onlyCtrl = true
  }
}, false)
```

**Code Behavior:**
- Monitors Enter key to restore password masking on form submission
- Monitors Ctrl key for user-configurable visibility toggle
- No key value capture or logging
- No transmission of keyboard data
- Event handlers only modify `input.type` property

**Verdict**: BENIGN - Legitimate UI interaction for password visibility control. Not a keylogger.

---

### V2: MutationObserver DOM Monitoring - FALSE POSITIVE
**Severity**: NONE
**Location**: `showPassword.js` (lines 153-165)
**Type**: DOM Observation

**Finding:**
The extension uses a MutationObserver to detect dynamically added password fields:

```javascript
const docObserver = new MutationObserver(() => {
  // NOTE: Despite we can recursively check element from addNodes.
  // Benchmark shows that it is much fast to just use `querySelectorAll` to find password inputs
  modifyWeb()
})

docObserver.observe(doc.documentElement, {
  childList: true,
  subtree: true,
  // Some website add input with text type at first, then change its type to password.
  attributes: true,
  attributeFilter: ['type']
})
```

**Code Behavior:**
- Monitors DOM for new password fields (SPAs, dynamic forms)
- Watches for `type` attribute changes (text → password transitions)
- Only queries `input[type=password]` elements
- Uses WeakSet to track already-modified inputs (prevents duplicate handlers)
- No data extraction or exfiltration

**Verdict**: BENIGN - Standard pattern for content scripts operating on dynamic web pages.

---

### V3: Options Page Easter Egg - ANOMALY (BENIGN)
**Severity**: NONE
**Location**: `options.js` (lines 59-67)
**Type**: Unusual Behavior

**Finding:**
The options page preview password field contains an Easter egg:

```javascript
document.getElementById('passwordTest').addEventListener('keydown', e => {
  if (e.keyCode === KEY_ENTER) {
    if (document.getElementById('passwordTest').value.toLowerCase() === 'taiwan') {
      window.location = 'http://en.wikipedia.org/wiki/Taiwan'
    } else {
      window.location.reload()
    }
  }
}, false)
```

**Code Behavior:**
- If user types "taiwan" in the options page preview field and presses Enter, navigates to Taiwan Wikipedia article
- Otherwise reloads the options page
- Only executes in the extension's own options page context
- No security implications

**Verdict**: BENIGN - Harmless developer Easter egg. No security risk.

---

## False Positive Analysis

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| Keydown listeners | showPassword.js, options.js | UI control for Enter/Ctrl key password visibility toggle | FALSE POSITIVE |
| MutationObserver | showPassword.js:153-165 | Detects dynamically added password fields for functionality | FALSE POSITIVE |
| querySelectorAll | showPassword.js:126 | Legitimate selection of `input[type=password]` only | FALSE POSITIVE |
| chrome.storage.sync | showPassword.js:140, options.js:33,45 | Stores user preferences (behavior mode, hover delay) | FALSE POSITIVE |
| innerHTML usage | options.js:24 | Localization with chrome.i18n.getMessage (safe) | FALSE POSITIVE |

## API Endpoints & External Communications

| Endpoint | Purpose | Location | Risk |
|----------|---------|----------|------|
| http://en.wikipedia.org/wiki/Taiwan | Easter egg navigation | options.js:62 | NONE (user-triggered, benign) |

**No analytics, telemetry, or data collection endpoints detected.**

## Permissions Analysis

### Declared Permissions
```json
{
  "permissions": ["storage"]
}
```

**Assessment:**
- `storage`: Used legitimately for saving user preferences (interaction mode, hover delay)
- No host permissions beyond content script matches
- No webRequest, cookies, tabs, or other sensitive APIs
- Minimal attack surface

### Content Script Scope
```json
{
  "matches": ["http://*/*", "https://*/*"],
  "all_frames": true,
  "run_at": "document_end"
}
```

**Assessment:**
- Broad match required for password field modification across all sites
- `all_frames: true` allows operation in iframes (necessary for embedded login forms)
- `document_end` timing appropriate for DOM manipulation
- No host_permissions abuse

## Data Flow Summary

```
User Interaction
     ↓
Password Field Events (mouseover/dblclick/focus/ctrl)
     ↓
Toggle input.type between 'password' and 'text'
     ↓
chrome.storage.sync (behavior preference: 0-3, wait delay: 0-9999ms)
     ↓
No external transmission
```

**Data Retention:**
- User preferences stored in chrome.storage.sync (synced across user's devices)
- No password values captured, logged, or transmitted
- No cookies, localStorage, or external storage

**Third-Party Services:**
- None detected

## Security Checklist

| Check | Status | Notes |
|-------|--------|-------|
| XHR/fetch hooking | PASS | No network interception code |
| Extension enumeration/killing | PASS | No chrome.management API usage |
| Remote configuration | PASS | No external config fetching |
| Obfuscation | PASS | Clean, readable code with comments |
| Keylogger behavior | PASS | Key events only for UI control |
| Cookie/credential harvesting | PASS | No cookie or password value access |
| Ad/coupon injection | PASS | No DOM injection beyond password fields |
| Residential proxy infrastructure | PASS | No proxy-related code |
| Market intelligence SDKs | PASS | No third-party SDKs |
| AI conversation scraping | PASS | No content interception |
| Dynamic code execution | PASS | No eval/Function/script injection |
| Content Security Policy | N/A | No CSP (MV3, no background page) |

## Code Quality & Transparency

**Positive Indicators:**
- LGPL 2.1 license headers in options.js and options.html
- Clear copyright attribution (© 2014 yuSing)
- Inline comments explaining performance optimizations
- WeakSet usage for memory efficiency
- Clean, maintainable code structure
- Open-source project transparency

**Architecture:**
- Single content script (showPassword.js) injected on all pages
- Standalone options page (options.html, options.js)
- No background/service worker (no persistent background execution)
- 237 total lines of JavaScript

## Overall Risk Assessment

**Risk Level: CLEAN**

ShowPassword is a legitimate utility extension with transparent functionality. It provides a simple password visibility toggle feature with no malicious behavior, data collection, or security risks.

**Justification:**
1. No network activity or external communications (except benign Easter egg)
2. Minimal permissions appropriate for functionality
3. No data exfiltration mechanisms
4. Clean, well-documented open-source code
5. No third-party SDKs or analytics
6. Legitimate DOM manipulation limited to password field type toggling
7. Appropriate use of chrome.storage.sync for user preferences

**User Privacy:**
- Does not access password values (only toggles visibility via type attribute)
- Does not log or transmit any user data
- Preferences synced via Chrome's native storage mechanism

**Recommendations:**
- Extension is safe for use
- No security concerns identified
- Consider updating HTTP Wikipedia link to HTTPS in Easter egg (minor best practice)

**Comparison to Known Threats:**
Unlike malicious extensions in this research (Urban VPN, StayFree, VeePN), ShowPassword exhibits none of the red flags:
- No XHR/fetch hooking
- No extension enumeration
- No residential proxy patterns
- No market intelligence SDKs
- No obfuscation or hidden functionality
- No remote configuration capabilities

---

**Analysis completed**: 2026-02-06
**Analyst**: Claude Sonnet 4.5
**Codebase size**: 237 lines JavaScript, 2 files analyzed
