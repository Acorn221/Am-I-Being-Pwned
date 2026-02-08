# Security Analysis Report: Block YouTube Feed - Homepage, Sidebar Videos

## Extension Metadata
- **Extension ID**: lcpclaffcdiihapebmfgcmmplphbkjmd
- **Name**: Block YouTube Feed - Homepage, Sidebar Videos
- **Version**: 1.0.3
- **Users**: ~30,000
- **Author**: Unhook
- **Manifest Version**: 3

## Executive Summary

Block YouTube Feed is a simple, legitimate Chrome extension that hides YouTube's homepage feed, sidebar suggestions, and end screen recommendations. The extension is **CLEAN** with no security vulnerabilities or malicious behavior detected. It serves its stated purpose through CSS-based DOM manipulation without network requests, tracking, or invasive data collection.

## Manifest Analysis

### Permissions
```json
"permissions": ["storage"]
```

**Assessment**: Minimal permissions - only requests `storage` API for saving user preferences (which feed elements to hide). No excessive or suspicious permissions.

### Content Security Policy
- No custom CSP defined (uses Chrome's default MV3 CSP)
- **Verdict**: SAFE - relies on secure defaults

### Content Scripts
```json
"content_scripts": [{
  "css": ["css/content.css"],
  "js": ["content.js"],
  "all_frames": true,
  "matches": ["https://*.youtube.com/*", "https://*.youtube-nocookie.com/*"],
  "run_at": "document_start"
}]
```

**Assessment**:
- Scoped exclusively to YouTube domains
- `all_frames: true` is reasonable for YouTube's iframe structure
- `document_start` timing allows early CSS injection to prevent layout shifts
- **Verdict**: APPROPRIATE - legitimate use case for YouTube modification

## Code Analysis

### Background Script (background.js)
**File size**: 1 line (minified), ~350 characters

**Functionality**:
1. Detects browser API (Chrome vs Firefox)
2. Falls back to `storage.local` if `storage.sync` unavailable
3. Initializes default settings on install:
   - `f_hide_feed: true`
   - `f_hide_recommended: true`
   - `f_hide_endscreen: true`
4. Resets storage if settings keys mismatch

**Security Findings**: NONE
- No network requests
- No dynamic code execution
- No sensitive API usage
- Pure settings management

### Content Script (content.js)
**File size**: 27 lines

**Functionality**:
1. Retrieves user settings from storage
2. Sets HTML attributes on `documentElement` based on settings
3. Listens for storage changes and updates attributes dynamically

**Code snippet**:
```javascript
function s(e) {
  Object.keys(e).forEach((t => {
    r.setAttribute(t, e[t])  // Sets attributes like f_hide_feed="true"
  }))
}
```

**Security Findings**: NONE
- No DOM manipulation beyond setting attributes
- No event interception or form hijacking
- No network communication
- Pure CSS toggle mechanism via attributes

### Popup Script (popup.js)
**File size**: 33 lines

**Functionality**:
1. Loads settings from storage
2. Syncs checkbox states with saved preferences
3. Saves checkbox changes back to storage

**Security Findings**: NONE
- Standard settings UI logic
- No external communication
- No data exfiltration

### CSS (content.css)
**Functionality**: Hides YouTube elements using attribute selectors:
```css
html[f_hide_feed=true] ytd-browse[page-subtype=home] .ytd-rich-grid-renderer,
html[f_hide_recommended=true] #related,
html[f_hide_endscreen=true] .html5-endscreen
```

**Security Findings**: NONE - purely cosmetic hiding

## Vulnerability Assessment

### Network Security
| Check | Finding | Verdict |
|-------|---------|---------|
| Outbound network requests | None detected | ✓ PASS |
| XHR/Fetch hooking | Not present | ✓ PASS |
| Remote config loading | Not present | ✓ PASS |
| WebSocket connections | Not present | ✓ PASS |

### Privacy & Data Collection
| Check | Finding | Verdict |
|-------|---------|---------|
| Data exfiltration | None detected | ✓ PASS |
| Cookie harvesting | Not present | ✓ PASS |
| Keylogging | Not present | ✓ PASS |
| Analytics/tracking | None detected | ✓ PASS |
| Storage of sensitive data | Only boolean preferences | ✓ PASS |

### Malicious Behavior
| Check | Finding | Verdict |
|-------|---------|---------|
| Ad/coupon injection | Not present | ✓ PASS |
| Extension enumeration | Not present | ✓ PASS |
| Extension killing | Not present | ✓ PASS |
| SDK injection | Not present | ✓ PASS |
| Residential proxy | Not present | ✓ PASS |
| Remote kill switch | Not present | ✓ PASS |
| Code obfuscation | Standard webpack minification only | ✓ PASS |

### Code Integrity
| Check | Finding | Verdict |
|-------|---------|---------|
| Dynamic code execution | Not present | ✓ PASS |
| eval() usage | Not detected | ✓ PASS |
| Function() constructor | Not detected | ✓ PASS |
| Inline scripts | None | ✓ PASS |

## False Positives

| Pattern | Context | Verdict |
|---------|---------|---------|
| N/A | No suspicious patterns detected | CLEAN |

## API Endpoints

| Endpoint | Purpose | Verdict |
|----------|---------|---------|
| N/A | No external endpoints | CLEAN |

## Data Flow Summary

```
User Interaction (popup checkboxes)
    ↓
chrome.storage API (local/sync)
    ↓
Content script reads settings
    ↓
Sets HTML attributes on document root
    ↓
CSS hides matched elements
```

**Assessment**: Entirely local data flow with no external communication. Settings stored locally using standard Chrome storage APIs.

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification
1. **Minimal attack surface**: Only 60 lines of actual JavaScript code
2. **No network activity**: Zero external communication
3. **Appropriate permissions**: Only requests `storage` API
4. **Transparent functionality**: Does exactly what it claims (hides YouTube elements via CSS)
5. **No obfuscation**: Standard webpack minification, easily deobfuscated
6. **Open source lineage**: References "Unhook" extension (a well-known open-source YouTube customization tool)
7. **Privacy-respecting**: No telemetry, analytics, or data collection

### Comparison to Stated Purpose
The extension performs **exactly** its stated function: blocking YouTube feeds through CSS injection. No hidden functionality or malicious behavior detected.

### Recommendation
**SAFE FOR USE** - This extension represents a best-practice implementation of a YouTube customization tool with excellent security hygiene.

## Additional Notes

- Popup includes donation links to PayPal and references `removerecs@gmail.com` support email
- Extension promotes the more feature-rich "Unhook" extension in its popup footer
- Appears to be a simplified/lite version of the Unhook extension
- No third-party libraries or dependencies detected beyond standard browser APIs
