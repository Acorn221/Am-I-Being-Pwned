# Security Analysis Report: Advanced AdBlock - Ad Blocker

## Extension Metadata
- **Extension ID**: iplfdepgkbpdpgglchledcflbdnmppnj
- **Name**: Advanced AdBlock - Ad Blocker
- **Version**: 1.9.12
- **Users**: ~70,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Advanced AdBlock is a **CLEAN** extension that implements legitimate ad-blocking functionality using Chrome's declarativeNetRequest API and content script injection. The extension appears to be a rebranded fork of AdGuard's assistant component with custom UI and branding under "adaway.io". No malicious code, data exfiltration, or unauthorized tracking was identified during this analysis.

**Overall Risk Assessment: CLEAN**

The extension follows Chrome extension best practices, uses standard permissions appropriately, and does not exhibit suspicious behavior patterns typical of malware or unwanted software.

## Vulnerability Analysis

### 1. No Security Vulnerabilities Identified

**Severity**: N/A
**Status**: CLEAN
**Verdict**: No vulnerabilities found

After comprehensive analysis of the extension's codebase, no security vulnerabilities were identified. The extension:
- Does not perform data exfiltration
- Does not inject malicious scripts
- Does not track users beyond local extension functionality
- Does not communicate with suspicious domains
- Does not modify search results or inject affiliate links
- Does not steal cookies or credentials
- Does not enumerate other extensions

## Permissions Analysis

### Declared Permissions
```json
{
  "permissions": [
    "activeTab",
    "declarativeNetRequest",
    "webRequest",
    "scripting",
    "storage",
    "*://*.youtube.com/*"
  ],
  "host_permissions": [
    "*://*/*"
  ],
  "optional_host_permissions": [
    "<all_urls>"
  ]
}
```

### Permission Usage Assessment

| Permission | Usage | Legitimate? | Notes |
|------------|-------|-------------|-------|
| `activeTab` | Access current tab for UI operations | ✅ Yes | Standard for ad blockers |
| `declarativeNetRequest` | Block ads via static rulesets | ✅ Yes | Core functionality |
| `webRequest` | Monitor blocked requests for counter | ✅ Yes | Display-only, no interception |
| `scripting` | Inject assistant UI for element picker | ✅ Yes | User-initiated feature |
| `storage` | Save user preferences, rules, allowlist | ✅ Yes | Local storage only |
| `*://*.youtube.com/*` | YouTube-specific ad blocking | ✅ Yes | Common for ad blockers |
| `*://*/*` | Block ads on all sites | ✅ Yes | Required for ad blocking |

**Verdict**: All permissions are used appropriately for declared functionality.

## Code Analysis

### Background Script (background.js, 4,651 lines)

**Network Communication**:
- **Line 741**: `fetch("".concat(e, ".json"))` - Loads local ruleset files only (e.g., `/rulesets/main/default.json`)
- **Line 4403**: `o.runtime.setUninstallURL("https://adaway.io/uninstall/")` - Standard uninstall feedback page
- **Line 4480**: Opens `https://adaway.io/welcome` on first install

**Key Functions**:
1. **Ruleset Management**: Loads and enables declarativeNetRequest filter lists from local JSON files
2. **Blocked Request Counter**: Tracks number of blocked ads per tab (local storage only)
3. **User Rules Management**: Handles custom user-defined blocking rules
4. **Allowlist Management**: Manages sites where ad blocking is disabled
5. **Element Picker**: Injects assistant.js to allow users to manually select page elements to block

**Storage Operations**:
- All storage is local via `chrome.storage.local` and `chrome.storage.session`
- Stores: `darkTheme`, `modeLevel`, `userRules`, `allowlist`, `blockedRequestsCount`, `rulesetConfig`
- No remote synchronization or data transmission

### Content Scripts

**contentScript.js (3,011 lines)**:
- Bundles jQuery 3.7.1 (lines 1-200)
- Communicates with background script via `chrome.runtime.sendMessage` for:
  - Element picker initialization
  - Site filtering status queries
- No DOM manipulation except for element picker UI
- No data collection or exfiltration

**startAssistant.js (16 lines)**:
- Listens for right-click events to capture element selection
- Minimal script that launches the AdGuard-style element picker
- No privacy concerns

### Assistant Module (assistant.js, 4,990 lines)

This is a heavily modified fork of AdGuard's visual element selector:
- **Lines 3425-3438**: Uses `localStorage` only to migrate legacy settings (button position)
- **Line 3793**: `XMLHttpRequest` used for cache bypass on page reload (local only, no external requests)
- **Lines 3554, 4385-4387**: Contains references to AdGuard URLs (commented/unused legacy code)
- Implements interactive UI for selecting page elements to block

**Verdict**: Legitimate fork of open-source AdGuard assistant with no malicious modifications.

### Popup & Options Scripts

Both popup and options pages use standard Chrome extension APIs:
- Display blocked ad count from local storage
- Allow users to pause/resume protection
- Manage user rules and allowlist
- No external script loading or tracking

## Declarative Net Request Rulesets

The extension bundles **116 JSON ruleset files** totaling approximately 12MB:
- `default.json`: 3.8MB base filter list with 15,000+ rules
- Regional filters: 34 country-specific filter lists (bgr-0, chn-0, deu-0, fra-0, jpn-1, etc.)
- Annoyance filters: Cookie notices, overlays, social widgets
- Privacy filters: `adguard-spyware-url.json`, `dpollock-0.json`, `stevenblack-hosts.json`

**Sample Rules** (from default.json):
```json
{"action":{"type":"block"},"condition":{"urlFilter":"||greedseed.world/vpaid/ytvpaid.php"},"id":9,"priority":10}
{"action":{"type":"block"},"condition":{"urlFilter":"||topxxxlist.net/eroclick.js"},"id":4,"priority":10}
```

All rules use `type: "block"` action - no redirects, no header modifications, no cookie injection detected.

## False Positives

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| jQuery inclusion | contentScript.js:1-3000 | Bundled library v3.7.1 for DOM manipulation | ✅ Benign |
| `XMLHttpRequest` | assistant.js:3793 | Cache bypass for page reload after blocking | ✅ Benign |
| `localStorage` usage | assistant.js:3425 | Legacy settings migration | ✅ Benign |
| AdGuard URLs | assistant.js:3554 | Unused legacy constants from fork | ✅ Benign |
| `chrome.runtime.sendMessage` | Multiple files | Standard extension messaging | ✅ Benign |
| `globalEval` | contentScript.js:119 | jQuery's safe eval wrapper | ✅ Benign |

## External API Endpoints

| Domain | Purpose | Threat Level |
|--------|---------|--------------|
| adaway.io/uninstall | Uninstall feedback page | 🟢 Low - Standard practice |
| adaway.io/welcome | First-run welcome page | 🟢 Low - Standard practice |
| adaway.io/privacy | Privacy policy (linked from options) | 🟢 Low - Documentation |
| adaway.io/terms | Terms of service (linked from options) | 🟢 Low - Documentation |

**Note**: No analytics, telemetry, or tracking endpoints detected. No runtime network requests to third parties.

## Data Flow Summary

```
User Browsing
    ↓
declarativeNetRequest blocks ads (Chrome-native)
    ↓
webRequest.onErrorOccurred listener (read-only)
    ↓
Increment local counter → chrome.storage.local
    ↓
Display badge on extension icon (local only)
```

**No data leaves the user's machine.**

User-initiated actions:
1. **Element Picker**: User right-clicks → assistant.js injected → rule created → stored locally
2. **Manual Rules**: User adds rules via options page → stored in `chrome.storage.local.userRules`
3. **Allowlist**: User allowlists site → stored in `chrome.storage.local.allowlist`

## Privacy Assessment

✅ **No Analytics**: No Google Analytics, no tracking pixels, no telemetry
✅ **No Cookie Access**: Extension does not read or exfiltrate cookies
✅ **No User Profiling**: No behavioral tracking or fingerprinting
✅ **No External Communication**: All filtering happens locally via declarativeNetRequest
✅ **No Credential Harvesting**: No keylogging or form interception
✅ **No Extension Enumeration**: Does not detect other installed extensions

## Content Security Policy

**Status**: No CSP defined (manifest v3 defaults apply)
**Risk**: 🟢 Low - Chrome enforces strict CSP for MV3 extensions by default

Manifest v3 automatically prohibits:
- Remote code execution
- Inline scripts in extension pages
- `eval()` and `new Function()` (except in sandboxed contexts)

## Comparison to Known Threats

### ❌ Not Present:
- Proxy/VPN infrastructure (unlike SetupVPN/Urban VPN)
- Remote script loading
- Search hijacking
- Affiliate link injection
- Market intelligence SDKs (Sensor Tower, Pathmatics)
- AI conversation scraping
- Residential proxy functionality
- Extension killing/enumeration
- Dynamic code execution from remote servers

### ✅ Legitimate Patterns:
- Static ruleset-based ad blocking (similar to uBlock Origin)
- Visual element picker (similar to AdGuard/AdBlock Plus)
- Local storage for preferences
- Standard Chrome extension messaging

## Supply Chain Analysis

**Branding**: "Advanced AdBlock" / "adaway.io"
**Code Origin**: Fork of AdGuard Assistant (open source)
**Concerns**: 🟡 Minor - Branding suggests affiliation with "AdAway" (Android ad blocker) but domain ownership unclear

The extension appears to be a white-label/rebrand of AdGuard technology. This is common in the ad blocker space but creates potential confusion about developer identity.

## Recommendations

### For Users:
1. ✅ **Safe to Use**: No security concerns identified in current version
2. ⚠️ **Monitor Updates**: Watch for changes in permissions or behavior in future versions
3. ℹ️ **Alternative**: Consider uBlock Origin or official AdGuard if concerned about lesser-known developers

### For Platform:
1. ℹ️ **Branding Review**: Verify developer identity and relationship to "AdAway" project
2. ℹ️ **Filter List Source**: Confirm filter list origins and update mechanisms
3. ✅ **No Action Required**: Extension follows policies and poses no security threat

## Technical Details

### Architecture:
- **Filtering Engine**: declarativeNetRequest (Chrome-native, no JS execution)
- **UI Framework**: Vanilla JS + jQuery 3.7.1
- **Storage**: chrome.storage.local (encrypted by Chrome)
- **Build Process**: Likely webpack/bundler (minified but readable)

### Code Quality:
- Well-structured with clear separation of concerns
- Uses modern async/await patterns
- Proper error handling
- No obfuscation beyond standard minification

## Conclusion

**Advanced AdBlock - Ad Blocker is a CLEAN extension** that provides legitimate ad-blocking functionality without privacy violations, malware, or unwanted behavior. It uses Chrome's built-in filtering APIs appropriately and does not exhibit any of the red flags common in malicious extensions.

The extension is functionally equivalent to established ad blockers like AdBlock Plus or AdGuard, using standard techniques for content filtering and user interaction. All data processing occurs locally, and no user information is transmitted to external servers.

**Final Risk Rating: CLEAN**

---

**Analyst Notes**:
- No further investigation required
- Extension may be monitored for future updates
- Consider comparing filter list sources to ensure they match claimed sources (EasyList, AdGuard, etc.)
- Developer transparency could be improved (unclear relationship to AdAway/AdGuard projects)
