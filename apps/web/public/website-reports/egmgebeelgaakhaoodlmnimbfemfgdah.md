# Vulnerability Report: Redirect Blocker

## Extension Metadata
- **Extension Name**: Redirect Blocker
- **Extension ID**: egmgebeelgaakhaoodlmnimbfemfgdah
- **Version**: 3.4.2
- **User Count**: ~100,000
- **Manifest Version**: 3
- **Author**: Tyson3101 (https://github.com/Tyson3101/Redirect-Blocker)

## Executive Summary

Redirect Blocker is a legitimate Chrome extension designed to prevent malicious or annoying redirects by blocking new tab creation and same-tab navigation to unauthorized URLs. The extension operates through a whitelist mechanism where users can configure allowed URLs and saved URLs. After comprehensive security analysis, **no critical vulnerabilities or malicious behavior were identified**. The extension uses appropriate Chrome APIs within declared permissions, contains no network calls to external servers, no dynamic code execution, and no data exfiltration mechanisms.

The extension is open-source on GitHub and appears to be a genuine security tool for blocking unwanted redirects, commonly seen on streaming sites and ad-heavy pages.

## Vulnerability Details

### No Critical or High Severity Issues Found

After thorough analysis of the extension's codebase (981 total lines across 3 JavaScript files), no security vulnerabilities were detected.

**Areas Examined:**
1. ✅ Manifest permissions and Content Security Policy
2. ✅ Background service worker (422 lines)
3. ✅ Content script (237 lines)
4. ✅ Popup UI script (322 lines)
5. ✅ Network activity and API calls
6. ✅ Dynamic code execution patterns
7. ✅ Data handling and storage usage

### Security Characteristics

#### Manifest Analysis
```json
{
  "manifest_version": 3,
  "permissions": ["tabs", "storage"],
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["./dist/content.js"]
  }]
}
```

**Assessment**:
- **Permissions are minimal and appropriate** for the extension's functionality
- `tabs` permission needed to monitor and close redirect tabs
- `storage` permission used for saving user settings and extension state
- No dangerous permissions like `webRequest`, `cookies`, `history`, or `debugger`
- No `host_permissions` requesting access to specific domains
- Content script runs on `<all_urls>` which is necessary for same-tab redirect prevention

#### Background Script Analysis (background.js)

**Key Functions:**
1. **Tab Monitoring** (Lines 42-96): Listens to `chrome.tabs.onCreated` and checks if new tabs match whitelisted URLs, closing unauthorized ones
2. **URL Matching** (Lines 354-371): Normalizes URLs and checks against saved/allowed URL lists
3. **Storage Management** (Lines 188-209): Syncs settings and extension state using `chrome.storage.sync` and `chrome.storage.local`
4. **Keyboard Shortcuts** (Lines 210-240): Handles toggle messages from content script
5. **Service Worker Persistence** (Lines 316-322): Uses keepAlive interval to prevent service worker termination

**Verdict: CLEAN**
- No network requests (fetch/XMLHttpRequest)
- No dynamic code execution (eval/Function)
- No DOM manipulation beyond legitimate extension features
- Proper use of Chrome APIs within permissions scope
- Console logging throughout for debugging transparency

#### Content Script Analysis (content.js)

**Key Functions:**
1. **Keyboard Shortcut Listener** (Lines 28-75): Captures keydown events for Alt+Shift+S (toggle single tab) and Alt+Shift+A (toggle all tabs)
2. **Same-Tab Redirect Prevention** (Lines 96-153): Uses MutationObserver to detect new `<a>` tags and adds click event listeners that prevent navigation to non-whitelisted URLs
3. **URL Matching** (Lines 154-171): Local URL normalization function identical to background script

**Verdict: CLEAN**
- No data exfiltration
- No keylogging (only captures specific shortcut combinations)
- No cookie harvesting
- No postMessage communication with external origins
- MutationObserver usage is legitimate for detecting dynamically added links
- Event.preventDefault() used appropriately to block unwanted navigation

#### Popup Script Analysis (script.js)

**Key Functions:**
1. **UI State Management** (Lines 32-106): Handles toggle button clicks and extension mode switching
2. **Settings Management** (Lines 151-227): Saves user-configured URLs, shortcuts, and preferences to chrome.storage.sync
3. **Tab Enable/Disable** (Lines 276-289): Manages disabled tabs list

**Verdict: CLEAN**
- Pure UI logic with no external communication
- Settings stored locally using Chrome storage APIs
- URL validation using native URL constructor (Line 298)
- No injection of external scripts or resources

#### Network Activity

**Analysis Results:**
- ✅ Zero fetch() calls detected
- ✅ Zero XMLHttpRequest usage
- ✅ No WebSocket connections
- ✅ No external API endpoints
- ✅ No remote configuration loading
- ✅ No analytics or tracking pixels

**External Resources in HTML:**
- `popup.html` loads Font Awesome CSS from cdnjs.cloudflare.com (Line 5) - Standard icon library
- `install.html` loads Font Awesome CSS from cdnjs.cloudflare.com (Line 11) - Standard icon library
- `help.html` loads Font Awesome CSS from cdnjs.cloudflare.com (Line 11) - Standard icon library

These are legitimate, commonly used CDN resources for UI icons.

#### Data Flow Analysis

**Data Storage:**
1. **chrome.storage.sync** (synced across devices):
   - `settings.savedURLs`: User-configured URLs to auto-enable extension
   - `settings.allowedURLs`: User-configured URLs to allow redirects
   - `settings.tabExclusive`: Boolean for tab vs URL mode
   - `settings.preventSameTabRedirects`: Boolean preference
   - `settings.shortCutToggleSingleKeys`: Keyboard shortcut config
   - `settings.shortCutToggleAllKeys`: Keyboard shortcut config
   - `settings.onStartup`: Auto-enable on browser start

2. **chrome.storage.local** (device-specific):
   - `extensionTabs`: Array of tabs with extension enabled
   - `allTabsModeIsOn`: Boolean state
   - `disabledTabs`: Array of temporarily disabled tabs

**Data Flow Direction:**
- All data flows: User → Chrome Storage → Extension
- No outbound data transmission detected

#### Chrome API Usage

**Legitimate API Calls:**
- `chrome.tabs.query()` - Query open tabs
- `chrome.tabs.get()` - Get tab information
- `chrome.tabs.update()` - Switch active tab or focus tab
- `chrome.tabs.remove()` - Close redirect tabs (core functionality)
- `chrome.tabs.create()` - Opens install page on first run
- `chrome.windows.remove()` - Close popup windows that are redirects
- `chrome.windows.getCurrent()` - Get current window ID
- `chrome.storage.sync.get/set()` - User settings persistence
- `chrome.storage.local.get/set()` - Extension state management
- `chrome.runtime.sendMessage()` - Internal messaging between content script and background
- `chrome.runtime.onStartup` - Detect browser startup

All API usage is appropriate for the declared permissions and extension functionality.

## False Positive Analysis

| Pattern | Location | Verdict | Reason |
|---------|----------|---------|---------|
| `chrome.tabs.remove()` | background.js:88 | False Positive | Core functionality - removes unauthorized redirect tabs |
| `chrome.windows.remove()` | background.js:164 | False Positive | Blocks popup window redirects (legitimate security feature) |
| `MutationObserver` | content.js:119-141 | False Positive | Monitors DOM for new `<a>` tags to prevent same-tab redirects |
| `addEventListener("click")` | content.js:144 | False Positive | Prevents clicks on unauthorized redirect links |
| `<all_urls>` content script | manifest.json:23 | False Positive | Required to run same-tab redirect prevention on all sites |
| CDN resource loading | popup.html:5, install.html:11, help.html:11 | False Positive | Font Awesome icons from trusted CDN |

## API Endpoints / External Connections

| URL | Purpose | Risk Level |
|-----|---------|------------|
| https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css | Font Awesome icons for UI | LOW (Read-only CSS) |
| https://github.com/Tyson3101/Redirect-Blocker | Open source repository link | NONE (External link only) |
| https://youtube.com/@Tyson3101 | Author's YouTube channel | NONE (External link only) |
| https://chrome.google.com/webstore/detail/redirect-blocker/egmgebeelgaakhaoodlmnimbfemfgdah | Chrome Web Store listing | NONE (External link only) |

**No active network connections or API calls are made by the extension code.**

## Privacy Analysis

**Data Collection**: NONE
- No user data is transmitted outside the browser
- No analytics or telemetry
- No user tracking
- No PII collection

**Data Retention**: LOCAL ONLY
- All settings stored in Chrome's sync storage (encrypted by Chrome)
- No server-side storage
- User can clear all data by removing the extension

**Third-Party Sharing**: NONE

## Attack Surface Analysis

**Potential Attack Vectors (All Mitigated):**

1. ❌ **Malicious URL Injection**: User controls saved/allowed URL lists - no external URL injection possible
2. ❌ **XSS via Settings**: URLs validated using native URL() constructor before storage
3. ❌ **Extension Enumeration**: No evidence of detecting other extensions
4. ❌ **Content Script Injection**: Content script only prevents redirects, doesn't inject content
5. ❌ **Data Exfiltration**: No network calls, no postMessage to external origins

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification:
1. ✅ **No Malicious Behavior**: Extension performs exactly as advertised - blocks unwanted redirects
2. ✅ **No Data Exfiltration**: Zero network activity, no telemetry, no tracking
3. ✅ **Minimal Permissions**: Only requests `tabs` and `storage`, appropriate for functionality
4. ✅ **No Dynamic Code**: No eval(), Function(), or remote script loading
5. ✅ **Open Source**: Publicly available on GitHub for audit
6. ✅ **Transparent Operation**: Extensive console logging for debugging
7. ✅ **No Obfuscation**: Code is clean, readable, and well-structured
8. ✅ **Legitimate Use Case**: Addresses real problem (malicious redirects on streaming/torrent sites)
9. ✅ **No Anti-Detection**: No code to detect or evade security analysis
10. ✅ **No Monetization Schemes**: No ads, affiliate links, or sponsored content injection

### Code Quality:
- Well-commented with descriptive console logs
- Proper error handling with `.catch(() => null)` patterns
- No security anti-patterns detected
- Follows Chrome extension best practices for MV3

### User Safety:
- Users maintain full control over which URLs are whitelisted
- Extension can be easily toggled on/off per tab
- Default saved URLs include known streaming sites (soap2day, vipleague) - common redirect-heavy sites
- Clear UI for managing settings

## Recommendations

**For Users:**
- Extension appears safe to use for its intended purpose
- Review and customize saved/allowed URL lists in settings
- Be aware that extension runs on `<all_urls>` for same-tab redirect prevention

**For Developers:**
- Consider adding CSP to manifest for additional hardening
- Current implementation is secure and well-designed

## Conclusion

Redirect Blocker (egmgebeelgaakhaoodlmnimbfemfgdah) is a **legitimate, clean extension** with no security vulnerabilities or malicious behavior. It serves a valid security purpose by blocking potentially harmful redirects on ad-heavy and streaming websites. The extension is open-source, uses minimal permissions appropriately, and contains no data collection, tracking, or exfiltration mechanisms.

**FINAL VERDICT: CLEAN - Safe for continued use**
