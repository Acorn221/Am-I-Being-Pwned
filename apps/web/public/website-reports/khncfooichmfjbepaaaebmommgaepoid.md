# Security Analysis Report: Unhook - Remove YouTube Recommended & Shorts

## Extension Metadata
- **Extension ID**: khncfooichmfjbepaaaebmommgaepoid
- **Name**: Unhook - Remove YouTube Recommended & Shorts
- **Version**: 1.6.8
- **User Count**: ~1,000,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-06

## Executive Summary

**Overall Risk Rating: CLEAN**

Unhook is a legitimate YouTube distraction-removal extension with **NO security vulnerabilities or malicious behavior detected**. The extension implements a straightforward UI-hiding mechanism using CSS and DOM manipulation exclusively on YouTube pages. All code is transparent, contains no network exfiltration, no tracking, no third-party SDKs, and no obfuscation beyond standard minification.

### Key Findings
- ✅ No data exfiltration or network calls
- ✅ No third-party analytics or tracking SDKs
- ✅ No XHR/fetch hooking or monkey-patching
- ✅ No extension enumeration or killing
- ✅ No credential harvesting or cookie stealing
- ✅ No ad injection or content manipulation
- ✅ No obfuscation or dynamic code execution
- ✅ No remote config or kill switches
- ✅ Minimal permissions (storage, webRequest for URL redirects only)
- ✅ Privacy-respecting (EULA explicitly states "No user information is collected, transmitted, or sold")

## Manifest Analysis

### Permissions Audit
```json
"permissions": ["storage", "webRequest"]
"host_permissions": ["https://www.youtube.com/*", "https://m.youtube.com/*"]
```

**Assessment**: Minimal and appropriate permissions
- `storage`: Used exclusively for storing user preferences (which elements to hide)
- `webRequest`: Used only for URL redirects (e.g., redirecting YouTube homepage to subscriptions page)
- `host_permissions`: Correctly scoped to YouTube domains only

### Content Security Policy
- No custom CSP defined (defaults to MV3 secure CSP)
- No external script sources
- No `unsafe-eval` or `unsafe-inline`

**Assessment**: Secure by default

### Web Accessible Resources
```json
"web_accessible_resources": [{
  "resources": ["/js/unhook-yt.js"],
  "matches": ["https://www.youtube.com/*", "https://m.youtube.com/*"]
}]
```

**Assessment**: Single script exposed for page context injection (required for DOM manipulation before YouTube's Polymer framework loads). Properly scoped to YouTube domains.

## Code Analysis

### Background Script (background.js - 120 lines)

**Purpose**: Manages extension state, user preferences, and URL redirects.

**Key Functions**:
1. **Storage Management** (lines 5-17):
   - Fallback mechanism from sync storage to local storage
   - No external transmission of stored data

2. **Default Settings** (lines 19-54):
   - Hardcoded UI hiding preferences (28 boolean flags)
   - Stored locally via chrome.storage API

3. **Icon Updates** (lines 56-66):
   - Updates extension icon based on on/off state
   - No exfiltration

4. **URL Redirects** (lines 111-119):
   - Uses `chrome.webRequest.onBeforeRequest` to redirect:
     - Trending/Explore → YouTube homepage
     - YouTube homepage → Subscriptions (if configured)
   - All redirects are local to YouTube domains
   - No external network calls

5. **Lifecycle URLs** (lines 70-73):
   - Opens `https://unhook.app/welcome` on install
   - Sets uninstall URL to `https://unhook.app/uninstall`
   - **Assessment**: Benign informational pages, no tracking parameters

**Verdict**: Clean. No suspicious behavior.

### Content Script (content.js - 47 lines)

**Purpose**: Bridges extension settings to page context.

**Key Functions**:
1. **Attribute Setting** (lines 16-19):
   - Reads settings from chrome.storage
   - Sets HTML attributes on `document.documentElement` (e.g., `hide_feed=true`)
   - CSS selectors in content.css use these attributes to hide elements

2. **Script Injection** (lines 24-27):
   ```javascript
   const e = document.createElement("script");
   e.src = o.runtime.getURL("js/unhook-yt.js");
   e.id = "unhook-yt";
   r.appendChild(e)
   ```
   - Injects unhook-yt.js into page context (required for YouTube's SPA navigation)
   - Source is local extension file, not external URL

3. **Settings Sync** (lines 37-40):
   - Listens to storage changes and updates attributes dynamically

**Verdict**: Clean. Standard content script pattern for UI customization.

### Unhook-YT Script (unhook-yt.js - 219 lines)

**Purpose**: Handles YouTube-specific DOM manipulation and player controls.

**Key Functions**:
1. **Autoplay Disabling** (lines 78-98):
   - Finds autoplay toggle button via `querySelector`
   - Clicks it to disable autoplay if enabled
   - Uses MutationObserver to handle dynamic DOM changes

2. **Annotations Disabling** (lines 20-75):
   - Manipulates YouTube player settings menu
   - Programmatically clicks annotation toggles
   - All logic is client-side DOM manipulation

3. **Logo Redirect Override** (lines 159-183):
   - Changes YouTube logo href from "/" to "/feed/subscriptions"
   - Uses event.stopPropagation to prevent default behavior
   - No network interception

4. **Notification Badge Removal** (lines 138-153):
   - Removes "(N) " prefix from page title via regex
   - Client-side cosmetic change only

5. **Cookie Check** (line 188):
   ```javascript
   -1 === document.cookie.indexOf("SAPISID=") && e.setAttribute("yt-signed-out", "")
   ```
   - **Assessment**: Checks for YouTube login cookie to adjust UI
   - Does NOT read/store/transmit cookie value
   - Only checks presence for signed-in/signed-out state

**Verdict**: Clean. All DOM manipulation is cosmetic and local.

### Popup Script (popup.js - 119 lines)

**Purpose**: Settings UI for user preferences.

**Key Functions**:
- Checkbox state management
- Syncs UI toggles to chrome.storage
- Tree view expansion/collapse logic
- Dark mode toggle

**Verdict**: Clean. Standard settings page with no external calls.

### Info Popup Script (info-popup.js - minified, 1 line)

**Purpose**: Loads dark mode preference for info pages (donate, troubleshoot).

**Code**:
```javascript
t.get(r,(n=>{o(t,...s)}))}((function(t){
  document.documentElement.setAttribute("dark_mode",t.popup_settings.dark_mode)
}),["popup_settings"])
```

**Verdict**: Clean. Simple cosmetic preference loading.

## Network Analysis

### External Domains Referenced

| Domain | Purpose | Context | Risk |
|--------|---------|---------|------|
| unhook.app | Developer website | Install welcome page, uninstall survey | CLEAN - No tracking params |
| fonts.googleapis.com | Google Fonts | Popup UI styling | CLEAN - Standard CDN |
| fonts.gstatic.com | Google Fonts preconnect | Performance optimization | CLEAN - Standard CDN |
| paypal.me | Donations | Donate page links | CLEAN - User-initiated |
| cash.app | Donations | Donate page links | CLEAN - User-initiated |
| docs.google.com | Feature requests | Support link to Google Form | CLEAN - User-initiated |
| removerecs@gmail.com | Support email | Troubleshoot page | CLEAN - mailto link |

**Assessment**: All external references are benign user-facing links. **Zero network calls from extension code.**

### API Endpoints

**No API endpoints found.** Extension makes zero network requests. All functionality is local DOM manipulation.

## Data Flow Analysis

```
User Preferences (chrome.storage.sync/local)
    ↓
background.js (reads settings)
    ↓
content.js (sets HTML attributes)
    ↓
content.css (hides elements via CSS selectors)
    ↓
unhook-yt.js (manipulates player/autoplay)
```

**Data Scope**: All data remains local to the browser. No external transmission.

**Storage Contents**:
- Boolean flags for each hide_* setting (28 settings)
- Popup UI preferences (dark_mode, tree expansion states)

**Assessment**: Fully privacy-respecting architecture.

## False Positive Analysis

| Pattern | File | Line | Explanation | Verdict |
|---------|------|------|-------------|---------|
| `document.cookie.indexOf("SAPISID=")` | unhook-yt.js | 188 | Checks YouTube login state (signed-in vs signed-out) to adjust UI. Does not read cookie value or transmit. | FALSE POSITIVE - Benign |
| `setTimeout` calls | unhook-yt.js | Multiple | Used for timing DOM element access after YouTube's SPA navigation. Standard pattern for MutationObserver delays. | FALSE POSITIVE - Benign |
| `document.createElement("script")` | content.js | 25 | Injects local extension script (unhook-yt.js) into page context. Required for YouTube Polymer manipulation. Source is local, not external. | FALSE POSITIVE - Standard pattern |

## Vulnerability Assessment

### Critical: None
### High: None
### Medium: None
### Low: None

## Security Best Practices Observed

✅ **Minimal Permissions**: Only requests storage and webRequest (for URL redirects)
✅ **No External Scripts**: All JavaScript is self-contained in extension package
✅ **No Analytics**: Zero tracking or telemetry code
✅ **No Obfuscation**: Code is minified but not obfuscated (standard build process)
✅ **Privacy Policy**: LICENSE.txt explicitly states no data collection
✅ **Manifest V3**: Uses latest manifest version with stricter security model
✅ **CSP Compliance**: No unsafe-eval, unsafe-inline, or external script sources
✅ **Scoped Permissions**: host_permissions limited to YouTube domains
✅ **No Dynamic Code**: No eval(), Function(), or dynamic imports
✅ **No XHR/Fetch Hooking**: Does not intercept network traffic
✅ **No Credential Access**: Does not access passwords or auth tokens

## Comparison with Malicious Patterns

| Malicious Pattern | Found in Unhook? | Evidence |
|-------------------|------------------|----------|
| Sensor Tower Pathmatics SDK | ❌ No | No ad-finder, no XHR/fetch hooks |
| AI conversation scraping | ❌ No | Only operates on YouTube |
| Extension enumeration | ❌ No | No chrome.management API usage |
| Residential proxy infrastructure | ❌ No | No proxy configuration |
| Remote config/kill switches | ❌ No | All config is local storage |
| Data exfiltration | ❌ No | Zero network calls from code |
| Ad injection | ❌ No | Only removes elements, never injects |
| Cookie harvesting | ❌ No | Only checks cookie presence, never reads values |
| Obfuscated payloads | ❌ No | Code is transparent minified JS |

## Data Collection Assessment

**Collected Data**: None
**Transmitted Data**: None
**Third-Party SDKs**: None
**Analytics/Tracking**: None

From LICENSE.txt:
> "No user information is collected, transmitted, or sold by the Software."

**Code Verification**: Confirmed. No network calls, no telemetry, no tracking pixels, no beacons.

## Developer Information

- **Author**: Unhook (removerecs@gmail.com)
- **Website**: unhook.app
- **Transparency**: Open about functionality, provides support email, GPL-style EULA
- **Monetization**: Voluntary donations only (no ads, no paid features)

## Risk Summary

### Attack Surface: MINIMAL
- Only interacts with YouTube pages
- No cross-origin communication
- No external API dependencies
- No privileged APIs used

### Privacy Impact: ZERO
- No data collection
- No tracking
- No user profiling
- Settings stored locally only

### Malicious Indicators: NONE
- No obfuscation beyond minification
- No suspicious network activity
- No extension killing
- No market intelligence SDKs
- No data harvesting

## Conclusion

**Unhook is a clean, privacy-respecting extension that delivers exactly what it advertises**: hiding distracting YouTube UI elements. The code is straightforward, uses minimal permissions appropriately, makes zero network calls, and contains no malicious patterns. The extension serves as an example of good security practices in extension development.

**Recommendation**: SAFE for use. No security concerns identified.

---

## Technical Notes

- Total LOC: 505 (all JavaScript)
- Obfuscation Level: Standard minification only
- Network Calls: 0 from code
- Third-Party Dependencies: 0
- Chrome APIs Used: storage, webRequest, runtime, tabs, action
- Storage Usage: Local user preferences only

## Appendix: File Inventory

```
/js/background.js       (120 lines) - Extension lifecycle, URL redirects
/js/content.js          (47 lines)  - Settings bridge, script injection
/js/unhook-yt.js        (219 lines) - YouTube DOM manipulation
/js/popup.js            (119 lines) - Settings UI logic
/js/info-popup.js       (minified)  - Dark mode loader
/css/content.css        (1 line)    - CSS selectors for hiding elements
/css/popup.css          (50 lines)  - Settings UI styles
/css/info-popup.css     (minimal)   - Info page styles
manifest.json           - Extension configuration
popup.html              - Settings page
donate.html             - Donation page (PayPal/Cash App links)
troubleshoot.html       - Support page
LICENSE.txt             - EULA with privacy statement
```

## Change Log
- 2026-02-06: Initial security analysis completed - CLEAN rating confirmed
