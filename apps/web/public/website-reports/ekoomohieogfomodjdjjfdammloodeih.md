# Security Analysis Report: Picture in Picture for Chrome

## Extension Metadata
- **Name**: Picture in Picture for Chrome
- **Extension ID**: ekoomohieogfomodjdjjfdammloodeih
- **Version**: 1.2.11
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Picture in Picture for Chrome is a **CLEAN** extension that provides legitimate picture-in-picture functionality for HTML5 videos. The extension has a minimal codebase (33 lines of functional JavaScript) with straightforward behavior: it finds the largest playing video on a page and enables browser-native picture-in-picture mode.

**Key Findings**:
- No network requests or external API calls
- No data collection or exfiltration
- No dynamic code execution
- No obfuscation beyond standard minification
- Appropriate permission usage (scripting + host_permissions for video detection)
- Strong CSP policy with no unsafe-eval or unsafe-inline
- No suspicious chrome.* API usage beyond standard messaging
- Zero malicious indicators

The extension operates entirely client-side using browser-native APIs and contains no privacy or security concerns.

## Vulnerability Analysis

### CLEAN: No Security Issues Detected

After comprehensive analysis of manifest permissions, background scripts, and content scripts, no vulnerabilities were identified. The extension:

1. Uses only browser-native `requestPictureInPicture()` API
2. Contains no network communication whatsoever
3. Implements minimal DOM access (read-only video element queries)
4. Uses standard Chrome extension messaging for icon clicks
5. Has no obfuscation beyond minification typical of modern build tools
6. Implements no data harvesting, tracking, or telemetry

## Permission Analysis

### Declared Permissions

| Permission | Justification | Risk Assessment |
|------------|--------------|-----------------|
| `scripting` | Required to inject content script that finds video elements | APPROPRIATE - Necessary for core functionality |
| `host_permissions: <all_urls>` | Required to operate on any page with videos | APPROPRIATE - Extension must work on all video sites |

### Content Security Policy
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
**Assessment**: Strong CSP with no unsafe-eval or unsafe-inline. Prevents code injection attacks.

## Code Analysis

### Background Script (`background.js`)
**Lines of Code**: 1 (minified)

```javascript
chrome.action.onClicked.addListener((async e=>{
  e.id&&await chrome.scripting.executeScript({
    target:{tabId:e.id,allFrames:!0},
    files:["script.js"]
  })
}));
```

**Behavior**:
- Listens for extension icon clicks
- Injects `script.js` into all frames of the active tab
- No network requests, storage access, or suspicious APIs

**Verdict**: CLEAN - Standard MV3 service worker pattern

### Content Script (`script.js`)
**Lines of Code**: 33

**Core Functions**:

1. **`findLargestPlayingVideo()`**
   - Queries all `<video>` elements on page
   - Filters by `readyState !== 0` (video has data)
   - Filters by `disablePictureInPicture === false`
   - Sorts by dimensions to find largest video
   - Returns largest playable video element

2. **`requestPictureInPicture(e)`**
   - Calls browser-native `e.requestPictureInPicture()`
   - Sets `__pip__` attribute to track PiP state
   - Listens for `leavepictureinpicture` event
   - Uses `ResizeObserver` to track video size changes

3. **`maybeUpdatePictureInPictureVideo()`**
   - Automatically switches to larger video if one becomes available
   - Unobserves previous video element

**Behavior**:
- Finds largest video and enters/exits PiP mode
- Sends simple `{message: "enter"}` to background (unused - no listener)
- No DOM manipulation beyond reading video elements
- No network requests or data exfiltration

**Verdict**: CLEAN - Pure video detection and PiP control

## API Endpoints & Network Activity

| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| N/A | No network activity detected | N/A | N/A |

**Assessment**: Extension makes ZERO network requests. All functionality is local.

## Data Flow Summary

```
User clicks extension icon
  → Background injects script.js into page
    → Content script queries DOM for <video> elements
      → Finds largest playing video
        → Calls browser-native requestPictureInPicture()
          → Browser enters PiP mode
            → Script tracks state with __pip__ attribute
              → ResizeObserver monitors for larger videos
```

**Data Collection**: NONE
**Data Transmission**: NONE
**External Communication**: NONE

## False Positive Analysis

| Finding | Explanation | Verdict |
|---------|-------------|---------|
| `getClientRects()[0] \|\| {...}` | Standard fallback pattern for video dimensions | SAFE |
| `chrome.runtime.sendMessage()` | Unused messaging (no listener in background) | BENIGN |
| `<all_urls>` permission | Required to detect videos on any site | APPROPRIATE |
| Minified code | Standard build output, not obfuscation | SAFE |

## Risk Assessment

### Overall Risk Level: **CLEAN**

### Risk Breakdown

| Category | Risk Level | Justification |
|----------|-----------|---------------|
| Network Exfiltration | NONE | Zero network requests |
| Data Harvesting | NONE | No cookie/storage/DOM data collection |
| Malicious APIs | NONE | Only uses video detection + PiP APIs |
| Code Injection | NONE | No eval/Function/dynamic execution |
| Obfuscation | NONE | Standard minification only |
| Privacy Violation | NONE | No tracking or telemetry |
| Permission Abuse | NONE | Appropriate permission usage |

### Confidence Level: **HIGH**

The extension's simplicity (33 lines), lack of network activity, and use of browser-native APIs provide high confidence in this assessment.

## Recommendations

1. **For Users**: This extension is safe to use. It provides legitimate functionality with no privacy or security concerns.

2. **For Developers**: Extension follows best practices:
   - Manifest V3 compliance
   - Minimal permission set
   - Strong CSP
   - No external dependencies
   - Clean, readable code

3. **For Researchers**: This is an example of a properly-scoped extension with appropriate permissions and no malicious behavior.

## Technical Details

**Analysis Coverage**:
- ✓ Manifest permissions and CSP
- ✓ Background service worker
- ✓ Content script injection patterns
- ✓ Network request detection (none found)
- ✓ Dynamic code execution patterns (none found)
- ✓ Data exfiltration vectors (none found)
- ✓ Chrome API usage patterns
- ✓ DOM manipulation patterns
- ✓ Obfuscation analysis

**Code Statistics**:
- Total JS files: 2
- Total JS lines: 34 (including minified background)
- Network requests: 0
- External dependencies: 0
- Suspicious patterns: 0

## Conclusion

Picture in Picture for Chrome is a **CLEAN** extension with legitimate functionality and zero security or privacy concerns. The extension:

- Performs only its stated function (enable PiP for videos)
- Makes no network requests
- Collects no user data
- Uses appropriate permissions
- Contains no malicious code patterns
- Has strong security policies

**Final Verdict**: CLEAN - Safe for use with no security recommendations needed.
