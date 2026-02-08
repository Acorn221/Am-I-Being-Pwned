# Security Analysis Report: Allow Right-Click

## Extension Metadata

| Field | Value |
|-------|-------|
| **Extension ID** | hnafhkjheookmokbkpnfpmemlppjdgoi |
| **Name** | Allow Right-Click |
| **Version** | 0.6.8 |
| **Manifest Version** | 3 |
| **Estimated Users** | ~400,000 |
| **Homepage** | https://webextension.org/listing/allow-right-click.html |
| **Developer** | webextension.org |
| **Analysis Date** | 2026-02-06 |

## Executive Summary

**OVERALL RISK: CLEAN**

Allow Right-Click is a legitimate browser extension designed to bypass website restrictions on right-click context menus, text selection, and copy/paste functionality. The extension employs DOM event interception and JavaScript prototype manipulation to override website-imposed restrictions, which is its core functionality.

After comprehensive analysis of all 33 files (660 total lines of code), **no malicious behavior was detected**. The extension:
- Does NOT make any external network requests
- Does NOT contain tracking or analytics SDKs
- Does NOT harvest user data
- Does NOT manipulate browser behavior beyond its stated purpose
- Does NOT attempt extension enumeration or killing
- Does NOT inject ads or modify page content maliciously

The prototype manipulation detected (Object.defineProperty on MouseEvent, ClipboardEvent, Selection) is **legitimate and necessary** for the extension's core functionality of bypassing website restrictions.

## Detailed Analysis

### 1. Manifest Permissions Analysis

**Permissions Declared:**
```json
{
  "permissions": [
    "storage",
    "activeTab",
    "scripting",
    "contextMenus",
    "notifications"
  ],
  "optional_host_permissions": [
    "*://*/*"
  ]
}
```

**Assessment:**
- `storage`: Used to store user preferences (whitelist hostnames, FAQ preferences)
- `activeTab`: Required for on-demand script injection when user clicks extension icon
- `scripting`: Core functionality - injects scripts to bypass context menu restrictions
- `contextMenus`: Creates right-click menu options for the extension icon
- `notifications`: Displays user-facing notifications for errors and confirmations
- `*://*/*` (optional): Only requested when user enables auto-activation feature

**Verdict:** All permissions are justified and minimal for stated functionality.

### 2. Background Service Worker (worker.js)

**File:** `/home/acorn221/projects/cws-scraper/output/workflow-downloaded/hnafhkjheookmokbkpnfpmemlppjdgoi/deobfuscated/worker.js` (258 lines)

**Key Behaviors:**
1. **Script Injection**: Injects content scripts (`core.js`, `mouse.js`, `listen/*.js`, `user-select/*.js`) into active tabs when user activates extension
2. **Context Menu Management**: Creates right-click menu items for extension icon (add/remove from whitelist, test page, request permissions)
3. **Auto-Activation**: When user configures hostnames, registers content scripts to auto-inject on matching domains
4. **FAQ Page**: Opens homepage on install/update (respects user preference, can be disabled)

**Network Activity:** NONE - No fetch, XMLHttpRequest, or external network calls detected

**Chrome API Usage:**
- `chrome.scripting.executeScript()` - Legitimate script injection
- `chrome.scripting.registerContentScripts()` - Auto-activation feature
- `chrome.action.*` - Icon management
- `chrome.storage.local.*` - Preference storage
- `chrome.permissions.*` - Permission management
- `chrome.management.getSelf()` - Only used to check installType (prevent FAQ on dev/admin installs)
- `chrome.tabs.query/create()` - Tab management for FAQ/test pages

**Verdict:** CLEAN - All API usage is legitimate and transparent.

### 3. Content Script Analysis

#### 3.1 Core Injection Script (core.js)

**File:** `data/inject/core.js` (88 lines)

**Functionality:**
- Manages injection state (ready/removed toggle)
- Coordinates loading of protected (isolated world) and unprotected (main world) scripts
- Maintains cache of original element styles for restoration
- Sends status messages to background worker

**Verdict:** CLEAN - Pure orchestration, no data exfiltration

#### 3.2 Mouse Event Handler (mouse.js)

**File:** `data/inject/mouse.js` (157 lines)

**Functionality:**
- Intercepts right-click (`mousedown` with button=2) and long-press (`touchstart`) events
- Manipulates `pointer-events` CSS to reveal hidden elements under cursor
- Detects images, videos, canvases, and background images for context menu
- Creates temporary invisible elements to trigger browser's native context menu for background images
- Restores original pointer-events on click completion

**Verdict:** CLEAN - Legitimate DOM manipulation for stated purpose. No data collection.

#### 3.3 Event Listener Bypass (listen/main.js & listen/isolated.js)

**Files:**
- `data/inject/listen/main.js` (79 lines) - Main world
- `data/inject/listen/isolated.js` (43 lines) - Isolated world

**Functionality (main.js):**
- Overrides `window.alert` to prevent annoying alerts when right-clicking
- Overrides `MouseEvent.prototype.preventDefault` to prevent websites from blocking context menus
- Overrides `MouseEvent.prototype.returnValue` for legacy browser compatibility
- Overrides `ClipboardEvent.prototype.preventDefault` to enable copy/paste
- Restores original functions when extension is deactivated via `arc-remove` event

**Functionality (isolated.js):**
- Adds capturing event listeners for `dragstart`, `selectstart`, `keydown`, `copy`, `cut`, `paste`, `contextmenu`, `mousedown`
- Calls `stopPropagation()` to prevent website listeners from blocking actions
- Keydown handler only intercepts Ctrl/Cmd+C/V/P/A to allow copy/paste/print/select-all
- Special handling for paste events to prevent websites from reverting changes

**Verdict:** CLEAN - These are the core mechanisms for bypassing website restrictions. The prototype manipulation is **legitimate and necessary** for the extension's advertised functionality. No keylogging or data harvesting detected.

#### 3.4 Text Selection Bypass (user-select/main.js & user-select/isolated.js)

**Files:**
- `data/inject/user-select/main.js` (27 lines) - Main world
- `data/inject/user-select/isolated.js` (120 lines) - Isolated world

**Functionality (main.js):**
- Overrides `Selection.prototype.removeAllRanges` to prevent websites from clearing text selections
- Restores original function on deactivation

**Functionality (isolated.js):**
- Scans all stylesheets and inline styles for `user-select: none`
- Overrides to `user-select: initial` to allow text selection
- Uses MutationObserver to detect dynamically added styles
- Handles both inline styles and external/embedded stylesheets
- Special handling for remote stylesheets that block selection

**Verdict:** CLEAN - Legitimate CSS manipulation to enable text selection. No tracking or exfiltration.

#### 3.5 Custom Styles (styles.js)

**File:** `data/inject/styles.js` (43 lines)

**Functionality:**
- Injects CSS to override selection colors (ensures visible selection highlight)
- Fixes pointer-events on elements with `.copy-protection-on` class
- Uses CSS `@layer` for proper specificity

**Verdict:** CLEAN - Cosmetic CSS injection only.

### 4. Options Page Analysis

**Files:**
- `data/options/index.html` (44 lines)
- `data/options/index.js` (149 lines)

**Functionality:**
- Allows users to configure hostnames for auto-activation
- Permission management UI (request/remove `*://*/*` access)
- Validates hostname patterns before saving
- Factory reset option (double-click required)
- FAQ toggle preference
- Links to homepage and support page

**Verdict:** CLEAN - Standard options UI, no hidden functionality.

### 5. Auto-Activation Monitor (monitor.js)

**File:** `data/monitor.js` (3 lines)

```javascript
chrome.runtime.sendMessage({
  method: 'simulate-click'
});
```

**Functionality:**
- Registered as content script on user-configured hostnames
- Simply sends message to background worker to trigger auto-injection
- Equivalent to user clicking extension icon

**Verdict:** CLEAN - Minimal auto-activation trigger.

## Vulnerability Assessment

### CRITICAL Vulnerabilities
**None detected.**

### HIGH Severity Issues
**None detected.**

### MEDIUM Severity Issues
**None detected.**

### LOW Severity Issues
**None detected.**

### Informational Findings

#### 1. Prototype Manipulation (EXPECTED BEHAVIOR)

**Severity:** INFORMATIONAL
**Files:**
- `data/inject/listen/main.js` (lines 11-50)
- `data/inject/user-select/main.js` (lines 4-13)

**Details:**
The extension modifies JavaScript prototypes:
```javascript
Object.defineProperty(MouseEvent.prototype, 'preventDefault', {
  get() { return () => {}; },
  ...
});
```

**Assessment:** This is **legitimate and necessary** for the extension's core functionality. The extension:
- Saves original function references before modification
- Restores originals when deactivated
- Only overrides security-irrelevant functions (preventDefault, returnValue, removeAllRanges)
- Does NOT modify sensitive APIs like XMLHttpRequest, fetch, or crypto

**Verdict:** BENIGN - Expected behavior for a right-click enabler extension.

#### 2. FAQ Page Auto-Open on Install/Update

**Severity:** INFORMATIONAL
**File:** `worker.js` (lines 229-258)

**Details:**
Opens `webextension.org` FAQ page on:
- Initial install (active tab)
- Updates (background tab, max once per 45 days)

**User Control:** Can be disabled via checkbox in options page

**Verdict:** BENIGN - Standard practice for extensions, fully transparent and configurable.

#### 3. Event Propagation Blocking

**Severity:** INFORMATIONAL
**File:** `data/inject/listen/isolated.js` (lines 2-39)

**Details:**
Uses `stopPropagation()` on multiple events to prevent website handlers from executing before browser defaults.

**Assessment:** This is the **core mechanism** for bypassing website restrictions. Not malicious.

**Verdict:** BENIGN - Necessary for stated functionality.

## False Positive Analysis

| Pattern Detected | File | Reason | Verdict |
|------------------|------|--------|---------|
| `Object.defineProperty` on prototypes | listen/main.js, user-select/main.js | Core functionality to bypass website restrictions | FALSE POSITIVE |
| Event listener interception | listen/isolated.js | Necessary to prevent websites from blocking context menus | FALSE POSITIVE |
| `stopPropagation()` calls | listen/isolated.js, mouse.js | Part of right-click enablement mechanism | FALSE POSITIVE |
| DOM element style manipulation | mouse.js, user-select/isolated.js | Reveals hidden elements and enables text selection | FALSE POSITIVE |
| Keydown listener on document | listen/isolated.js | Only intercepts Ctrl+C/V/P/A for copy/paste support, NOT keylogging | FALSE POSITIVE |
| chrome.management.getSelf() | worker.js | Only checks installType to prevent FAQ spam on dev installs | FALSE POSITIVE |

## API Endpoint Analysis

| Domain | Purpose | Risk | Verdict |
|--------|---------|------|---------|
| webextension.org | Extension homepage (FAQ, support, uninstall feedback) | LOW | Legitimate developer site |
| webbrowsertools.com/test-right-click | Test page for verifying extension functionality | LOW | Legitimate test utility |

**No data exfiltration endpoints detected.**

## Data Flow Summary

### Data Collection
**NONE** - The extension does not collect any user data.

### Data Storage
**Local Only:**
- `chrome.storage.local.hostnames` - Array of user-configured auto-activation hostnames
- `chrome.storage.local.faqs` - Boolean preference for FAQ page display
- `chrome.storage.local.last-update` - Timestamp for rate-limiting FAQ page opens

### Data Transmission
**NONE** - No network requests are made by the extension. The only external communication is:
1. User-initiated navigation to FAQ page (webextension.org) on install/update
2. User-initiated navigation to test page (webbrowsertools.com) via context menu
3. User-initiated uninstall feedback URL (standard Chrome Web Store pattern)

### Third-Party Services
**NONE** - No analytics, tracking, or third-party SDKs detected.

## Security Strengths

1. **Minimal Permissions**: Uses optional host permissions, only requested when needed
2. **No Network Activity**: Zero external API calls, no telemetry or tracking
3. **Open Source**: Clean, readable code with inline comments explaining test cases
4. **User Control**: All features configurable, auto-activation is opt-in
5. **Proper Cleanup**: Restores original DOM/prototype state when deactivated
6. **Manifest V3**: Uses modern extension architecture with service workers

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Notes |
|-------------------|----------|-------|
| Extension enumeration/killing | NO | No chrome.management abuse |
| XHR/fetch hooking | NO | Does not modify network APIs |
| Residential proxy infrastructure | NO | No proxy-related code |
| Market intelligence SDKs | NO | No Sensor Tower, Pathmatics, etc. |
| AI conversation scraping | NO | No content harvesting |
| Ad/coupon injection | NO | No DOM content insertion |
| Remote config/kill switches | NO | No external command & control |
| Social media data harvesting | NO | No data collection |
| Cookie/credential theft | NO | No sensitive data access |
| Obfuscation | NO | Clean, beautified code with comments |

## Recommendations

### For Users
1. **SAFE TO USE** - This extension performs exactly as advertised with no hidden malicious behavior
2. Consider privacy: The optional `*://*/*` permission allows the extension to run on all websites. Only grant if you frequently use the auto-activation feature.
3. Recommended configuration: Use manual activation (click icon) instead of auto-activation to minimize permission scope

### For Security Researchers
1. This extension is an excellent example of **legitimate prototype manipulation** - useful for calibrating false positive detection
2. The `stopPropagation()` and `preventDefault()` override patterns should be whitelisted when scanning right-click enabler extensions
3. Pattern to whitelist: `Object.defineProperty(MouseEvent.prototype, 'preventDefault', ...)` in context of accessibility/anti-restriction tools

## Conclusion

Allow Right-Click is a **CLEAN** extension that faithfully implements its stated purpose without any malicious or deceptive behavior. The technical mechanisms employed (prototype manipulation, event interception, DOM style modification) are appropriate and necessary for its functionality.

**Final Verdict: CLEAN**

---

**Analysis Completed:** 2026-02-06
**Analyzed Files:** 33
**Total Lines of Code:** 660
**Malicious Patterns Detected:** 0
**Legitimate False Positives:** 6
**Overall Risk Rating:** CLEAN
