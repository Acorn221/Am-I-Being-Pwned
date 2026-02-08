# Security Analysis Report: Copy URLs

## Extension Metadata
- **Name:** Copy URLs
- **Extension ID:** efkmnflmpgiklkehhoeiibnmdfffmmjk
- **Version:** 2.0.0.1
- **User Count:** ~50,000
- **Developer:** Melanto Ltd.
- **Homepage:** http://melanto.com/apps/copy-urls/
- **Manifest Version:** 3

## Executive Summary

Copy URLs is a simple utility extension that copies all open tab URLs to the clipboard in various formats (plain text, HTML, CSV, JSON, or custom templates). The extension has been thoroughly analyzed for security vulnerabilities and malicious behavior.

**Overall Risk Assessment: CLEAN**

The extension is well-implemented with minimal permissions, no external network communication, and straightforward functionality that matches its stated purpose. No evidence of malicious behavior, data exfiltration, or security vulnerabilities was identified.

## Permissions Analysis

### Declared Permissions
- `tabs` - Required to enumerate and read tab URLs and titles
- `clipboardWrite` - Required to copy formatted URLs to clipboard
- `storage` - Required to persist user settings/preferences

### Permission Assessment
All permissions are **minimally scoped** and directly necessary for the extension's core functionality:
- No content scripts injected into web pages
- No host permissions or broad web access
- No external connectivity permissions
- No privacy-invasive permissions (cookies, webRequest, etc.)

**Verdict:** ✅ CLEAN - Minimal and appropriate permission set

## Manifest Security Analysis

### Content Security Policy
- **Status:** Uses default MV3 CSP (no custom CSP defined)
- **Remote Code:** ❌ None - all code is bundled locally
- **External Resources:** ❌ None

### Key Configuration
- `incognito: "spanning"` - Extension works across incognito/normal windows
- `offline_enabled: true` - Functions without network connectivity
- No externally_connectable declared
- No host_permissions declared
- No content_scripts declared

**Verdict:** ✅ CLEAN - Secure manifest configuration

## Code Analysis

### Background Script (background.js)
**File:** `/deobfuscated/background.js` (68 lines)

**Functionality:**
1. Initializes default settings in chrome.storage.local on first install
2. Sets uninstall URL to `https://melanto.com/copy-urls-removed/`
3. Opens welcome page on install: `https://melanto.com/copy-urls/`
4. Sets "NEW" badge on installation
5. Listens for icon update messages

**Network Activity:**
- ❌ No XHR/fetch calls
- ❌ No WebSocket connections
- ❌ No dynamic code loading
- ✅ Only static navigation URLs (install/uninstall pages)

**Chrome API Usage:**
- `chrome.storage.local` - Settings persistence only
- `chrome.runtime.setUninstallURL()` - Standard uninstall feedback
- `chrome.tabs.create()` - Opens welcome page on install
- `chrome.action.setBadgeText()` - UI badge updates
- `chrome.runtime.onInstalled` - Standard lifecycle hook

**Verdict:** ✅ CLEAN - Standard extension lifecycle management

### Popup Script (index.js)
**File:** `/deobfuscated/index.js` (321 lines)

**Functionality:**
1. Loads and saves user preferences (output format, window selection)
2. Queries open tabs using chrome.tabs and chrome.windows APIs
3. Formats tab data (title + URL) according to user preferences
4. Renders formatted output to textarea for clipboard copy
5. Provides preset format templates (JSON, CSV, HTML, custom)

**Key Operations:**
- `chrome.windows.getCurrent()` / `chrome.windows.getAll()` - Enumerate windows
- `chrome.tabs.query()` - Get tabs in specified windows
- Tab URL filtering based on protocol (http/https vs chrome://)
- String template replacement (`{title}`, `{url}` placeholders)
- Local clipboard copy via `document.execCommand('copy')`

**Data Flow:**
1. User opens popup → settings loaded from chrome.storage.local
2. Extension queries tab URLs/titles → formats locally
3. Formatted text displayed in textarea → user copies to clipboard
4. **No external transmission** - all processing is local

**Security Observations:**
- ❌ No eval() or Function() constructor
- ❌ No dynamic script injection
- ❌ No external network calls
- ❌ No DOM manipulation of web pages
- ✅ Uses safe string replacement (no regex injection risk)
- ✅ URL parsing via native URL() constructor

**Verdict:** ✅ CLEAN - Safe local data formatting

### Third-Party Library (URI.js)
**File:** `/deobfuscated/URI.js` (2,453 lines)

**Library:** URI.js v1.19.2 by Rodney Rehm (MIT License)
- **Purpose:** URL parsing and manipulation library
- **Source:** http://medialize.github.io/URI.js/
- **Usage:** Referenced in index.html but appears unused in actual code
- **Assessment:** Legitimate open-source library, no malicious modifications detected

**Note:** The extension uses native `new URL()` constructor in index.js instead of URI.js, suggesting the library may be vestigial from earlier versions.

**Verdict:** ✅ CLEAN - Legitimate library (unused)

### HTML/CSS Files
**Files:** `index.html`, `index.css`

**Assessment:**
- Static UI elements only
- No inline scripts or external resource loads
- Standard form controls for settings
- Help link to `http://melanto.com/apps/copy-urls/help.html`

**Verdict:** ✅ CLEAN

## Threat Model Assessment

### Extension Enumeration/Killing
❌ **Not Present** - No code attempts to detect or disable other extensions

### XHR/Fetch Hooking
❌ **Not Present** - No content scripts, no web request interception

### Residential Proxy Infrastructure
❌ **Not Present** - No network connectivity, no proxy functionality

### Remote Configuration
❌ **Not Present** - All settings stored locally, no remote fetching

### Kill Switches
❌ **Not Present** - No remote control mechanisms

### Market Intelligence SDKs
❌ **Not Present** - No Sensor Tower, Pathmatics, or similar trackers

### AI Conversation Scraping
❌ **Not Present** - No content script access to web pages

### Ad/Coupon Injection
❌ **Not Present** - No content scripts or DOM manipulation

### Cookie Harvesting
❌ **Not Present** - No cookie permissions or access

### Keylogging
❌ **Not Present** - No input monitoring capabilities

### Data Exfiltration
❌ **Not Present** - No external network communication detected

### Code Obfuscation
✅ **Minimal** - Code is readable and properly formatted, standard minification only

## False Positives Analysis

| Pattern | Location | Assessment | Verdict |
|---------|----------|------------|---------|
| `document.execCommand('copy')` | index.js:200 | Standard clipboard API for MV3 popup context | False Positive |
| `new URL(tab.url)` | index.js:249, 302 | URL protocol parsing for filtering | False Positive |
| String template replacement | index.js:253, 305 | User-controlled format templates with `{url}` and `{title}` | False Positive |
| `chrome.tabs.create()` on install | background.js:39 | Standard welcome page behavior | False Positive |
| Uninstall URL | background.js:33 | Legitimate uninstall feedback mechanism | False Positive |

**Notes:**
- Custom format templates allow user-defined output but only process local tab data
- No injection risk as templates are not executed, only used for string replacement
- All data remains local within the extension context

## API Endpoints & External Connections

| URL | Purpose | Risk Level | Notes |
|-----|---------|------------|-------|
| https://melanto.com/copy-urls/ | Welcome page on install | Low | Static navigation, user-initiated |
| https://melanto.com/copy-urls-removed/ | Uninstall feedback | Low | Standard practice, no data sent |
| http://melanto.com/apps/copy-urls/help.html | Help documentation link | Low | User-initiated navigation |

**Network Communication:**
- ✅ No programmatic HTTP requests
- ✅ No telemetry or analytics
- ✅ No data transmission
- ✅ All URLs are for user navigation only

## Data Flow Summary

```
┌─────────────────┐
│  User clicks    │
│  extension icon │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Load settings   │
│ from local      │
│ storage         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Query tab URLs  │
│ via chrome.tabs │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Format locally  │
│ using templates │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Display in      │
│ popup textarea  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ User copies to  │
│ clipboard       │
└─────────────────┘
```

**Data Retention:** Settings only (format preferences) stored in chrome.storage.local
**External Transmission:** None
**Privacy Impact:** Minimal - only accesses tab metadata (URL/title) that user can already see

## Vulnerabilities & Security Issues

### Critical Severity
**None identified**

### High Severity
**None identified**

### Medium Severity
**None identified**

### Low Severity
**None identified**

### Informational

#### 1. Unused Library Dependency
- **Severity:** Informational
- **File:** URI.js (2,453 lines)
- **Details:** Large URI parsing library included but appears unused in actual code
- **Impact:** Minimal - increases extension size but no security risk
- **Recommendation:** Remove unused dependency to reduce attack surface and package size

#### 2. HTTP URLs in Metadata
- **Severity:** Informational
- **Files:** manifest.json, background.js, index.html
- **Details:** Developer website uses HTTP instead of HTTPS (melanto.com)
- **Impact:** Low - links are for navigation only, no sensitive data transmission
- **Recommendation:** Migrate to HTTPS for developer website

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Rationale
1. **Minimal Permissions:** Only requests tabs, clipboardWrite, and storage - all necessary for core functionality
2. **No Network Activity:** Extension operates entirely offline with no external communication
3. **No Content Scripts:** Cannot access or modify web page content
4. **Transparent Functionality:** Code behavior exactly matches extension description
5. **No Malicious Patterns:** No obfuscation, data exfiltration, tracking, or privacy violations
6. **Proper Isolation:** Operates only within extension popup context
7. **Standard Practices:** Follows Chrome extension best practices and MV3 guidelines

### User Privacy Impact
- ✅ Does not transmit browsing data
- ✅ Does not track user behavior
- ✅ Does not inject content into web pages
- ✅ Does not access cookies or authentication
- ✅ Settings stored locally only

### Compliance
- ✅ Manifest V3 compliant
- ✅ Minimal permission principle
- ✅ No policy violations detected
- ✅ Appropriate for stated functionality

## Conclusion

Copy URLs is a legitimate, well-implemented utility extension with no security concerns. The extension provides exactly the functionality described (copying tab URLs in various formats) without any privacy violations, malicious behavior, or unnecessary permissions. It serves as a good example of a minimal, focused Chrome extension.

**Recommendation:** Safe for continued use by end users.

---

**Analysis Date:** 2026-02-07
**Analyst:** Claude Sonnet 4.5
**Report Version:** 1.0
