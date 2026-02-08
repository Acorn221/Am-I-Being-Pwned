# Security Analysis: Easy Auto Refresh (aabcgdmkeabbnleenpncegpcngjpnjkc)

## Extension Metadata
- **Name**: Easy Auto Refresh
- **Extension ID**: aabcgdmkeabbnleenpncegpcngjpnjkc
- **Version**: 6.5
- **Manifest Version**: 3
- **Estimated Users**: ~1,000,000
- **Developer**: ksoft (dummysoftware.com)
- **Analysis Date**: 2026-02-06

## Executive Summary
Easy Auto Refresh is a legitimate auto-refresh extension with **CLEAN** status. The extension provides page auto-refresh functionality with advanced features locked behind paid registration. Analysis revealed no malicious behavior, tracking mechanisms, or data exfiltration. The extension includes a keypress listener that could trigger false positives in automated scanners but serves only to detect user activity for resetting refresh timers. All network calls are limited to license validation and reminder notifications to the developer's website.

**Overall Risk Assessment: CLEAN**

## Vulnerability Assessment

### 1. Keypress Event Listener (FALSE POSITIVE)
**Severity**: N/A (Not a Vulnerability)
**Files**:
- `/scripts/keypress.js` (lines 1-31)
- `/scripts/background.js` (lines 177-184)

**Analysis**:
The extension injects a keypress listener on all pages via the content script `keypress.js`. This could be mistaken for a keylogger, but analysis reveals it serves a legitimate purpose:

**Code Evidence** (`keypress.js`):
```javascript
onKeyPress:function(e){
  var o=10,a=new Date;
  3<(o=null!=keyPressManager.lastSendMessageDate?
    (a-keyPressManager.lastSendMessageDate)/1e3:o)
  &&(keyPressManager.lastSendMessageDate=a,
     e=e||window.event,
     chrome.runtime.sendMessage({
       tabId:keyPressManager.tabId,
       action:"resetInterval"
     }))
}
```

**Purpose**: The listener detects ANY keypress (not capturing key values) and sends a "resetInterval" message to the background script if more than 3 seconds have elapsed since the last message. This resets the auto-refresh timer when the user is actively typing.

**Key Safety Indicators**:
- No key values captured (`e.keyCode` not logged)
- No data sent to external servers
- Only sends internal message to background script
- Throttled to 3-second minimum intervals
- Only message sent is `{tabId, action: "resetInterval"}`

**Verdict**: **NOT MALICIOUS** - This is user activity detection for timer management, not keylogging.

---

### 2. Registration Code Validation
**Severity**: N/A (Expected Behavior)
**Files**: `/scripts/register.js` (lines 1-49)

**Analysis**:
The extension uses a freemium model with registration code validation via POST request to developer's server.

**Code Evidence**:
```javascript
getUrlResponse("https://www.dummysoftware.com/cgi-bin/checkregcode_easyautorefresh2.pl",
  registrationCode,
  async function(response) {
    // Validates code and unlocks features
  }
)
```

**Data Transmitted**:
- Registration code only (user-provided string)
- No browsing data, URLs, or user identifiers
- Standard XMLHttpRequest POST

**Storage**:
- Validated codes stored in `chrome.storage.local` with XOR obfuscation (key: 7)
- Format: `"^O" + code + "0$"` (XOR encrypted)

**Verdict**: **NOT MALICIOUS** - Standard license validation mechanism.

---

### 3. Reminder/Upsell Notifications
**Severity**: N/A (Expected Behavior)
**Files**:
- `/scripts/popup.js` (lines 214-223)
- `/scripts/background.js` (lines 32-45)

**Analysis**:
The extension opens tabs to the developer's website for install/update notifications and periodic reminders (every 90 days) for unregistered users.

**Trigger Conditions**:
1. **Install**: Opens `https://www.dummysoftware.com/easy-auto-refresh/?action=install&new=6.5`
2. **Update**: Opens `https://www.dummysoftware.com/easy-auto-refresh/?action=update&old=X&new=6.5`
3. **90-Day Reminder** (unregistered only): Opens `https://www.dummysoftware.com/easy-auto-refresh/?action=reminder&de=[days_elapsed]`

**Data Transmitted**:
- Version numbers only
- Days elapsed since last reminder
- No user data, browsing history, or identifiers

**Verdict**: **NOT MALICIOUS** - Standard freemium upsell mechanism with minimal tracking.

---

### 4. Auto-Click Feature (Element Selector)
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/scripts/content.js` (lines 14-224)
- `/scripts/popup.js` (lines 187-206)

**Analysis**:
The extension allows users to select page elements to auto-click during refresh cycles (e.g., "Load More" buttons).

**Mechanism**:
1. User clicks "Find" button in popup
2. Content script enables click listener with crosshair cursor
3. User clicks target element on page
4. Script generates CSS selector using `createUniqueSelector()` function
5. Selector validated and stored in `chrome.storage.local`

**Code Evidence** (`content.js`, line 159):
```javascript
function createUniqueSelector(e, t = {}) {
  // Generates unique CSS selector for clicked element
  // Returns selector like "#myId" or ".myClass"
}
```

**Safety Indicators**:
- User-initiated feature (requires explicit interaction)
- Selector stored locally, not transmitted
- Validation feedback shown in popup UI
- No automatic data collection

**Verdict**: **NOT MALICIOUS** - User-controlled automation feature.

---

### 5. Notification Text Search
**Severity**: N/A (Legitimate Functionality)
**Files**:
- `/scripts/background.js` (lines 270-308)
- `/scripts/content.js` (lines 52-67)

**Analysis**:
The extension can search page content for keywords and show notifications when text is found/not found.

**Code Evidence** (`content.js`):
```javascript
if (-1 != t.action.indexOf("findText")) {
  var i = !1,
    a = t.action.replace("findText", "").trim();
  // Search for text using querySelector or regex
  var s = new RegExp(a, "i");
  i = (document.body.innerText || document.body.innerHTML).match(s)
  // Return boolean result
}
```

**Data Flow**:
1. User configures keyword in popup
2. Background script sends "findText" message after refresh
3. Content script searches page content
4. Returns boolean (found/not found) to background
5. Background shows local Chrome notification
6. **No data sent to external servers**

**Verdict**: **NOT MALICIOUS** - Local page monitoring feature.

---

## False Positive Patterns Identified

| Pattern | Location | Reason for FP | Actual Purpose |
|---------|----------|---------------|----------------|
| Keypress event listener | `keypress.js` | Could be mistaken for keylogger | User activity detection for timer reset |
| `document.querySelector()` calls | `content.js` | Could be mistaken for DOM scraping | Element selector generation for auto-click |
| XOR encryption | `register.js`, `data.js` | Could be mistaken for obfuscation | License code storage protection |
| Chrome notifications | `background.js` | Could be mistaken for surveillance | User-configured keyword alerts |
| Tab URL access | `background.js` | Could be mistaken for tracking | Refresh target identification |

## Network Activity Analysis

### External Endpoints

| Domain | Purpose | Data Transmitted | Frequency |
|--------|---------|------------------|-----------|
| `dummysoftware.com/cgi-bin/checkregcode_easyautorefresh2.pl` | License validation | Registration code (POST) | On-demand (user-initiated) |
| `dummysoftware.com/easy-auto-refresh/?action=install` | Install notification | Version number | Once per install |
| `dummysoftware.com/easy-auto-refresh/?action=update` | Update notification | Old/new version numbers | Once per update |
| `dummysoftware.com/easy-auto-refresh/?action=reminder` | 90-day reminder | Days elapsed | Every 90 days (unregistered) |
| `dummysoftware.com/temp/mp3/notification.mp3` | Default notification sound | None (audio download) | On-demand (user-triggered) |

### Data Flow Summary

**Data Collection**: NONE
**User Data Transmitted**: NONE
**Tracking/Analytics**: NONE
**Third-Party Services**: NONE

All network calls are limited to:
1. License validation (user-initiated, registration code only)
2. Marketing notifications (version numbers only)
3. Notification sound download (user-configured)

**No browsing data, URLs (beyond current tab for refresh), cookies, or user identifiers are transmitted.**

## Permission Analysis

| Permission | Justification | Risk Level |
|------------|---------------|------------|
| `tabs` | Required for tab refresh functionality | Low (core feature) |
| `browsingData` | Optional cache clearing before refresh | Low (user-controlled) |
| `notifications` | Chrome notifications for keyword alerts | Low (local only) |
| `storage` | Settings and license code storage | Low (local only) |
| `scripting` | Content script injection for auto-click | Low (functional) |
| `alarms` | Long-interval refresh timers (>60s) | Low (functional) |
| `host_permissions: <all_urls>` | Refresh any user-visited page | Medium (broad but necessary) |

**Assessment**: All permissions are justified and used appropriately for declared functionality.

## Content Security Policy
```json
No CSP declared in manifest.json (Manifest V3 default applies)
```
**Note**: Manifest V3 extensions have built-in CSP protections that prevent inline script execution and eval().

## Code Quality Observations

### Positive Indicators
1. No dynamic code execution (`eval()`, `Function()`)
2. No external script loading
3. No XHR/fetch hooking or monkey-patching
4. No extension enumeration or killing
5. No residential proxy infrastructure
6. No market intelligence SDKs
7. Clean separation of concerns (background, content, popup)
8. Minimal network activity
9. All data storage is local (`chrome.storage.local`)

### Obfuscation Level
**Low** - Variable names are minified (standard build process), but logic is straightforward. No deliberate obfuscation beyond license code XOR.

## Comparison to Known Malicious Patterns

| Malicious Pattern | Present? | Evidence |
|-------------------|----------|----------|
| Extension enumeration/killing | ✗ No | No `chrome.management` API usage |
| XHR/fetch hooking | ✗ No | No prototype modifications |
| Residential proxy infrastructure | ✗ No | No proxy configuration |
| AI conversation scraping | ✗ No | No API interception |
| Market intelligence SDKs | ✗ No | No Sensor Tower, Pathmatics, etc. |
| Ad/coupon injection | ✗ No | No DOM manipulation for ads |
| Remote config/kill switches | ✗ No | No remote code loading |
| Cookie harvesting | ✗ No | No cookie access |
| GA/analytics proxy bypass | ✗ No | No analytics manipulation |
| Hidden data exfiltration | ✗ No | All network calls are transparent |

## Overall Risk Assessment

### Risk Level: **CLEAN**

**Justification**:
1. **No malicious behavior detected** across all attack vectors
2. **Minimal network activity** limited to license validation and marketing
3. **No data exfiltration** - all user data stays local
4. **Transparent functionality** - all features match user expectations
5. **No tracking or surveillance** mechanisms
6. **Legitimate business model** (freemium with paid registration)

### Recommendations
- **No action required** - Extension operates as advertised
- Users concerned about keypress listener can be assured it only detects activity (not logging keys)
- Periodic marketing tabs (90-day reminder) are expected for unregistered users

### User Privacy Impact
**MINIMAL** - The extension only accesses:
- Current tab URL (for refresh target)
- Page content (only when user enables keyword notifications or auto-click)
- No cross-site tracking or data aggregation

## Technical Summary

**Lines of Code**: 1,373 (deobfuscated)
**External Dependencies**: None
**Third-Party Libraries**: None
**Remote Code Loading**: None
**Dynamic Code Execution**: None

## Conclusion

Easy Auto Refresh is a **clean, legitimate browser extension** that provides auto-refresh functionality with advanced features. The keypress listener that might trigger security scanners is benign - it only detects user activity to intelligently reset refresh timers, without capturing any key values. All network calls are transparent and limited to license validation and marketing. No user data is collected or transmitted.

**Final Verdict: CLEAN** - Safe for use with ~1M users.
