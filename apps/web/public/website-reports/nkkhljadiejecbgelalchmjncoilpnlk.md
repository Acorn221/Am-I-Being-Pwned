# Video Speed Controller Security Analysis

## Extension Metadata
- **Extension ID**: nkkhljadiejecbgelalchmjncoilpnlk
- **Version**: 1.0.5
- **User Count**: ~400,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

Video Speed Controller is a **CLEAN** extension that provides legitimate video playback speed control functionality. The extension operates entirely client-side with no external network requests, no data exfiltration, and no malicious behavior. All code is straightforward and implements expected features: keyboard shortcuts for speed control, a UI overlay for video players, and user preferences stored locally.

**Risk Level: CLEAN**

The extension demonstrates good security practices including minimal permissions, no background scripts, and transparent functionality. The only network-related code opens the Chrome Web Store review page, which is benign promotional behavior.

## Detailed Analysis

### 1. Manifest Permissions & CSP

**Permissions Requested:**
```json
"permissions": ["storage"]
```

**Assessment**: ✅ CLEAN
- Only requests `storage` permission for saving user preferences
- No sensitive permissions (tabs, webRequest, cookies, management, declarativeNetRequest)
- No background scripts/service workers
- No external connectivity permissions

**Content Security Policy**: Default MV3 CSP (no custom modifications)

**Web Accessible Resources**: CSS files, images, fonts - all legitimate UI assets

### 2. Content Script Analysis (`js/cnt.js`)

**File**: `/deobfuscated/js/cnt.js` (390 lines)

**Functionality**: Core video speed control implementation

**Key Behaviors**:

1. **Settings Management** (Lines 5-21):
   - Stores user preferences: speed settings, keybindings, blacklist, UI options
   - Default blacklist includes Instagram, Twitter, Vine, Imgur, Teams (to avoid conflicts)
   - No hardcoded external domains

2. **Video Element Detection** (Lines 115-286):
   - Uses `querySelectorAll('video')` or `querySelectorAll('video,audio')` to find media elements
   - MutationObserver watches for dynamically added videos
   - Shadow DOM traversal for web components (line 123-133)
   - Iframe detection for cross-frame videos (lines 277-285)

3. **Speed Control UI** (Lines 179-218):
   - Creates Shadow DOM controller with speed buttons
   - Injects CSS via `chrome.runtime.getURL("styles/shade.css")`
   - Site-specific positioning for Amazon, Reddit, Facebook, HBO, Apple TV

4. **Keyboard Event Handling** (Lines 235-243):
   - Listens for keydown events for shortcuts (S/D/Z/X/R/G/V)
   - Checks modifiers to avoid conflicts (Alt, Ctrl, Meta, etc.)
   - Skips INPUT/TEXTAREA/contentEditable elements

5. **Playback Rate Manipulation** (Lines 299-314):
   - Direct `video.playbackRate` modification
   - CustomEvent dispatch for "ratechange" tracking
   - Saves speed to chrome.storage.sync

6. **Rate-Us Popup** (Lines 362-388):
   - Shows promotional dialog every 20 interactions (between count 5-50)
   - Opens Chrome Web Store review page on button click
   - Uses `window.open()` with extension review URL

**Verdict**: ✅ CLEAN
- No XHR/fetch requests
- No external API calls
- No data exfiltration
- No cookie access
- No extension enumeration
- All DOM manipulation is for legitimate UI overlay

### 3. Popup Script (`js/pp.js`)

**File**: `/deobfuscated/js/pp.js` (120 lines)

**Functionality**: Extension popup UI controls

**Key Behaviors**:

1. **Speed Controls** (Lines 70-118):
   - Increase/decrease buttons send messages to content script
   - Rewind/advance buttons trigger video seeking
   - Enable/disable toggle

2. **chrome.tabs.sendMessage Usage**:
   - Line 52: Triggers "showRateUsWindow" action
   - Lines 66, 80, 95, 105, 114: Control actions (reset, decrease, increase, rewind, advance)
   - All messages target active tab only
   - No sensitive tab data accessed

3. **Rate-Us Logic** (Lines 44-60):
   - Tracks interaction count in chrome.storage.local
   - Shows rate request at count % 20 == 5 (every 20th interaction at specific intervals)

**Verdict**: ✅ CLEAN
- Only communicates with own content scripts
- No external requests
- No sensitive API usage

### 4. Options Page (`js/options.js`)

**File**: `/deobfuscated/js/options.js` (239 lines)

**Functionality**: Settings configuration page

**Key Behaviors**:

1. **Keybinding Configuration** (Lines 107-126):
   - Captures keyboard input for custom shortcuts
   - Validates numeric inputs for speed/time values
   - Prevents invalid characters

2. **Blacklist Management** (Lines 136-150):
   - Accepts regex patterns for site blacklisting
   - Validates regex syntax before saving
   - Error display for invalid patterns

3. **Settings Persistence** (Lines 164-186):
   - Saves all settings to chrome.storage.sync
   - Removes deprecated legacy keys
   - Status message feedback

**Verdict**: ✅ CLEAN
- All operations local to extension
- No network activity
- No dynamic code execution

### 5. External Network Analysis

**HTTP(S) Endpoints Found**:

| URL | Location | Purpose | Risk |
|-----|----------|---------|------|
| `https://chrome.google.com/webstore/detail/${chrome.runtime.id}/reviews` | cnt.js:384 | Opens review page when user clicks "Rate now" | CLEAN - Promotional |
| `https://fonts.googleapis.com` | pp.html:1, options.html:1 | Google Fonts CDN (Nunito font) | CLEAN - Standard web fonts |
| `https://fonts.gstatic.com` | pp.html:1, options.html:1 | Google Fonts static assets | CLEAN - Standard web fonts |
| `https://popper.js.org` | bootstrap.min.js | Error message reference only (not loaded) | N/A - Comment text |

**Verdict**: ✅ CLEAN
- No data exfiltration endpoints
- No analytics/tracking servers
- No remote configuration
- Web Store review URL uses `chrome.runtime.id` (self-referential, cannot target other extensions)

### 6. Data Collection & Privacy

**Data Stored Locally**:
- User preferences (speed step, keybindings, opacity)
- Last used playback speed
- Per-video speed settings (keyed by `video.currentSrc`)
- Blacklist patterns
- Interaction count for rate-us prompt
- `isAlreadyRated` flag

**Data Transmitted**: NONE

**Verdict**: ✅ CLEAN
- No telemetry
- No user tracking
- No PII collection
- All storage local/sync only

### 7. Dynamic Code & Injection Risks

**Analysis**:
- ✅ No `eval()` usage
- ✅ No `Function()` constructor
- ✅ `setTimeout()`/`setInterval()` only with function references (not strings)
- ✅ `innerHTML` usage limited to:
  - Static UI templates (cnt.js:194, cnt.js:367, options.js:130)
  - Bootstrap library internal operations
- ✅ No remote script loading
- ✅ No external library CDNs (Bootstrap bundled locally)

**Verdict**: ✅ CLEAN

### 8. Chrome API Usage

**APIs Called**:

| API | Usage | Files | Risk |
|-----|-------|-------|------|
| `chrome.storage.sync` | Save/load user preferences | All JS files | CLEAN |
| `chrome.storage.local` | Track interaction count for rate-us | pp.js, cnt.js | CLEAN |
| `chrome.runtime.getURL()` | Load extension assets (CSS, images) | cnt.js:193, 222 | CLEAN |
| `chrome.runtime.id` | Build self-review URL | cnt.js:384 | CLEAN |
| `chrome.runtime.onMessage` | Listen for popup commands | cnt.js:361 | CLEAN |
| `chrome.tabs.query()` | Find active tab for messaging | pp.js | CLEAN |
| `chrome.tabs.sendMessage()` | Send control actions to content script | pp.js | CLEAN |

**NOT Used**:
- ❌ `chrome.management` (no extension enumeration)
- ❌ `chrome.webRequest`/`declarativeNetRequest` (no traffic interception)
- ❌ `chrome.cookies` (no cookie access)
- ❌ `chrome.debugger` (no debugging hooks)

**Verdict**: ✅ CLEAN

### 9. Code Obfuscation Assessment

**Minification Level**: Standard webpack/uglify minification
- Variable names shortened (e, t, n, s, i, a, o, r, d, c, l, p, u, m, v)
- Whitespace removed
- IIFE wrappers

**Obfuscation Indicators**: NONE
- No string encoding/encryption
- No control flow flattening
- No anti-debugging techniques
- Logic remains readable
- Bootstrap library is standard open-source code

**Verdict**: ✅ CLEAN - Standard build tool minification only

### 10. Site-Specific Behavior

The extension includes special-case DOM insertion logic for specific websites (cnt.js:203-217):

```javascript
case "www.amazon.com" == location.hostname:
case "www.reddit.com" == location.hostname:
case /hbogo\./.test(location.hostname):
  this.parent.parentElement.insertBefore(m, this.parent);
case "www.facebook.com" == location.hostname:
  // 7 levels up for Facebook's deep DOM nesting
case "tv.apple.com" == location.hostname:
  this.parent.parentNode.insertBefore(m, this.parent.parentNode.firstChild);
```

**Purpose**: Ensures UI overlay displays correctly on sites with unusual video player layouts

**Verdict**: ✅ CLEAN - Legitimate compatibility fixes

### 11. Suspicious Pattern Check

**Extension Enumeration**: ❌ Not present
**XHR/Fetch Hooking**: ❌ Not present
**Residential Proxy Infrastructure**: ❌ Not present
**Remote Configuration**: ❌ Not present
**Market Intelligence SDKs**: ❌ Not present (no Sensor Tower, Pathmatics, etc.)
**AI Conversation Scraping**: ❌ Not present
**Ad/Coupon Injection**: ❌ Not present
**Cookie Harvesting**: ❌ Not present
**Keylogging**: ❌ Not present (keyboard events only for shortcuts, skips text inputs)

**Verdict**: ✅ CLEAN

## False Positives Analysis

| Pattern | Occurrences | Context | Verdict |
|---------|-------------|---------|---------|
| `setTimeout()` | 6 | UI timeout handlers (hide status messages, debounce drag operations) | FP - Benign UI timing |
| `setInterval()` | 1 | Bootstrap carousel library | FP - Library code |
| `innerHTML` | 6 | Static UI template strings, Bootstrap library | FP - No user input injection |
| `insertAdjacentHTML` | 1 | Static rate-us dialog template (line 367) | FP - Hardcoded HTML |
| `addEventListener('keydown')` | 3 | Shortcut key handlers (skips INPUT/TEXTAREA) | FP - Not keylogging |
| `MutationObserver` | 2 | Detect dynamically added videos, attribute changes | FP - Legitimate DOM monitoring |
| `querySelector()` | Many | Find videos, UI elements | FP - Standard DOM access |

## API Endpoints Summary

| Endpoint | Method | Data Sent | Purpose |
|----------|--------|-----------|---------|
| N/A | N/A | N/A | No API calls |

**Note**: The extension makes ZERO network requests during operation.

## Data Flow Summary

```
User Interaction
    ↓
Keyboard Shortcut / Popup Button
    ↓
Content Script (cnt.js)
    ↓
video.playbackRate Modification
    ↓
chrome.storage.sync.set({lastSpeed})
    ↓
Local Storage Only (No Network)
```

**External Data**: None
**Data Exfiltration**: None
**Third-Party Services**: None

## Overall Risk Assessment

**CLEAN**

### Risk Breakdown
- **Data Exfiltration**: None
- **Privacy Invasion**: None
- **Malicious Intent**: None
- **Hidden Functionality**: None
- **Deceptive Behavior**: None

### Justification

1. **No Network Activity**: Extension operates entirely offline except for:
   - Loading Google Fonts in HTML pages (standard practice)
   - Opening Chrome Web Store review page when explicitly requested by user

2. **Minimal Permissions**: Only requests `storage` permission (necessary for saving preferences)

3. **Transparent Functionality**: All code implements documented features:
   - Video/audio playback speed control
   - Keyboard shortcuts
   - Visual speed indicator overlay
   - Site blacklisting

4. **No Sensitive API Access**: Does not use tabs, cookies, webRequest, management, or other sensitive APIs

5. **No Third-Party SDKs**: Uses only bundled Bootstrap UI library (standard open-source)

6. **No Data Collection**: Does not track user behavior, browsing history, or send telemetry

7. **Standard Code Quality**: Minified but not obfuscated, logic is straightforward

### Comparison to Known Malicious Patterns

Unlike extensions flagged as SUSPECT/HIGH RISK:
- ✅ No Sensor Tower / Pathmatics SDK
- ✅ No XHR/fetch hooking
- ✅ No extension enumeration/killing
- ✅ No remote configuration
- ✅ No ad injection
- ✅ No coupon engines
- ✅ No social media scraping
- ✅ No AI conversation harvesting
- ✅ No residential proxy infrastructure

### Rate-Us Prompt Analysis

The extension includes a promotional "Rate Us" dialog that appears:
- Every 20 interactions (when count % 20 == 5)
- Between counts 5-50 (stops after 3 prompts max)
- Only if user hasn't clicked "Rate now" before
- Allows "Maybe later" to dismiss

**Assessment**: Mildly promotional but not dark pattern. User can dismiss permanently by rating or waiting until count > 50.

## Recommendations

**For Users**: ✅ Safe to install and use
**For Security Teams**: ✅ No action required
**For Extension Review**: ✅ Approved - Clean extension

## Conclusion

Video Speed Controller (nkkhljadiejecbgelalchmjncoilpnlk) is a **legitimate, clean browser extension** with no security or privacy concerns. It provides exactly the functionality advertised—video playback speed control—without any hidden behavior, data collection, or malicious intent. The extension serves as a good example of minimal-permission, privacy-respecting browser extension development.

**Final Verdict: CLEAN**
