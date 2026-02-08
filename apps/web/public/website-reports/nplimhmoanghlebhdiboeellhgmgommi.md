# Vulnerability Report: Tab Groups Extension

## Extension Metadata
- **Extension Name**: Tab Groups Extension
- **Extension ID**: nplimhmoanghlebhdiboeellhgmgommi
- **Version**: 1.0.10
- **User Count**: ~100,000
- **Author**: Guokai Han
- **Manifest Version**: 3

## Executive Summary

Tab Groups Extension is a Chrome browser tab management tool that enables users to organize, save, and automatically group tabs based on configurable rules. After comprehensive security analysis, this extension is **CLEAN** with no malicious behavior detected. The extension operates entirely offline with no network communication, uses standard Chrome APIs appropriately, and implements legitimate tab management functionality without privacy violations or data exfiltration.

**Overall Risk Level: CLEAN**

## Detailed Analysis

### Manifest Permissions Assessment

#### Declared Permissions
```json
"permissions": [
  "favicon",
  "storage",
  "contextMenus",
  "unlimitedStorage",
  "tabs",
  "tabGroups",
  "alarms"
],
"optional_permissions": ["notifications"],
"optional_host_permissions": ["file:///*"]
```

**Verdict**: ✅ **LEGITIMATE** - All permissions are justified for tab management functionality:
- `tabs` + `tabGroups`: Core functionality for managing Chrome tab groups
- `storage`: Saves user tab group configurations and snapshots locally
- `favicon`: Displays tab icons in the UI
- `contextMenus`: Adds right-click menu shortcuts
- `unlimitedStorage`: Allows unlimited saved tab groups
- `alarms`: Used only for clearing notifications after 1 minute
- `notifications` (optional): User notification for saved groups
- `file:///*` (optional): Allows managing file:// protocol tabs if user grants

No host permissions requested, no webRequest interception, no debugger access.

### Service Worker Analysis (sw.js)

#### Core Functionality
1. **Auto-grouping Engine**: Automatically groups tabs based on:
   - Domain matching (groups tabs from same domain)
   - User-defined regex/string rules (URL/title matching)
   - Manual user configuration

2. **Tab Management**: Implements 40+ keyboard shortcuts for:
   - Creating/collapsing/ungrouping tabs
   - Moving tabs between groups/windows
   - Saving/restoring tab group snapshots

3. **Public Suffix List Integration**: Uses WebAssembly module (`publicsuffixlist.js` library by gorhill) for accurate domain extraction
   - Source: https://github.com/gorhill/publicsuffixlist.js (GPLv3/APLv2)
   - WASM file reference: `wasm/publicsuffixlist.wasm` (not included in extension package, likely loaded from CDN)

#### Network Activity
**Verdict**: ✅ **NO NETWORK CALLS DETECTED**

Analysis of service worker reveals:
- Single `fetch()` call at line 347: `WebAssembly.compileStreaming(fetch(u))` where `u = new URL("wasm/publicsuffixlist.wasm", l.url)`
- This attempts to load a WASM module, but the file is NOT present in the extension package
- No XHR/fetch to external domains
- No remote configuration fetching
- No analytics/tracking endpoints
- No data exfiltration mechanisms

#### Storage Usage
- **chrome.storage.local**: Stores user's saved tab groups and individual tabs (export/import as JSON/HTML)
- **chrome.storage.sync**: Stores auto-grouping rules and user preferences (syncs across user's Chrome instances)
- **chrome.storage.session**: Caches sync storage for performance

All storage is local/synced through Chrome's native storage, no third-party servers involved.

### Popup/UI Scripts Analysis

#### popup.js (1,100 lines)
- Implements tab group management UI with Bootstrap framework
- Handles user interactions: group creation, tab organization, color assignment
- No DOM manipulation of external pages
- No postMessage communication with content scripts (none exist)
- No data collection beyond local tab metadata (title, URL, favicon)

#### group-store.js (279 lines)
**Storage Operations**:
- Snapshots tab groups with title, URL, favIconUrl
- Import/Export functionality: Generates JSON/HTML files for backup
- Data format: `{id, type, createTime, title, color, tabs[]}`
- Merge duplicate groups by name

**Verdict**: ✅ **SAFE** - All storage operations are local-only

#### rule-store.js (133 lines)
**Rule Management**:
- Stores user-defined grouping rules (regex/string matching on URL/title)
- Rule format: `{id, ruleName, groupName, groupColor, urlMatches[], titleMatches[], enabled}`
- Import/Export rules as JSON for backup

### Content Scripts
**Verdict**: ✅ **NONE PRESENT** - Extension has no content scripts, cannot inject code into web pages

### Security Concerns Investigated

#### 1. Extension Enumeration/Killing
**Status**: ❌ **NOT FOUND**
- No calls to `chrome.management` API
- No extension ID enumeration

#### 2. XHR/Fetch Hooking
**Status**: ❌ **NOT FOUND**
- No content scripts to hook into page JavaScript
- Service worker only uses fetch for WASM loading

#### 3. Residential Proxy Infrastructure
**Status**: ❌ **NOT FOUND**
- No proxy configuration
- No chrome.proxy API usage
- No network relay functionality

#### 4. Remote Config/Kill Switches
**Status**: ❌ **NOT FOUND**
- No remote endpoints contacted
- All configuration stored locally

#### 5. Market Intelligence SDKs
**Status**: ❌ **NOT FOUND**
- No Sensor Tower, Pathmatics, or similar SDKs
- No third-party tracking libraries

#### 6. AI Conversation Scraping
**Status**: ❌ **NOT FOUND**
- No content scripts to access page DOM
- No ChatGPT/Claude/Bard specific code

#### 7. Ad/Coupon Injection
**Status**: ❌ **NOT FOUND**
- No content scripts
- No DOM manipulation of external pages

#### 8. Cookie Harvesting
**Status**: ❌ **NOT FOUND**
- No chrome.cookies permission requested
- No cookie access code

#### 9. Dynamic Code Execution
**Status**: ✅ **LIMITED TO WASM** - Only legitimate use:
```javascript
// Line 347: Loading public suffix list WASM module
WebAssembly.compileStreaming(fetch(u))
```
- No `eval()`, `new Function()`, or `atob()`-based code execution
- Single `String.fromCharCode()` usage for Punycode encoding (line 24)

### Data Flow Summary

```
User Browser Tab Data (title, URL, favicon)
    ↓
chrome.tabs/tabGroups APIs
    ↓
Service Worker (sw.js) - Auto-grouping logic
    ↓
chrome.storage.local/sync - Local storage only
    ↓
Popup UI (popup.js) - Display/Management
    ↓
Export → JSON/HTML files (user-initiated, local download only)
```

**No external data transmission at any stage.**

## False Positives

| Pattern | Location | Explanation | Verdict |
|---------|----------|-------------|---------|
| `String.fromCharCode` | sw.js:24 | Punycode encoding for internationalized domain names (IDN) - part of publicsuffixlist.js library | Safe |
| `fetch()` | sw.js:347 | Attempts to load WASM module for domain parsing (file not present, falls back to JS implementation) | Safe |
| `innerHTML` usage | Popup UI | Bootstrap framework rendering trusted extension UI content only | Safe |

## API Endpoints

**None detected.** Extension operates entirely offline.

## Verified Chrome Store Metadata

Extension has valid Chrome Web Store signatures:
- Publisher signature present
- Webstore signature present
- Verified contents hash: `wEYKtKM64IPAo9ZcyrjIhfTSlCh6FmjHDotlyaq5A9k`

## Risk Assessment by Category

| Category | Risk Level | Details |
|----------|-----------|---------|
| Data Exfiltration | CLEAN | No network calls, no data leaves device |
| Privacy Violation | CLEAN | Only accesses tab metadata user can see |
| Malicious Code | CLEAN | No obfuscation, eval, or dynamic code loading |
| Permission Abuse | CLEAN | All permissions appropriately used |
| Third-party SDKs | CLEAN | Only uses open-source publicsuffixlist.js library |
| User Consent | CLEAN | Optional permissions properly gated |

## Overall Verdict

**RISK LEVEL: CLEAN**

Tab Groups Extension is a legitimate, privacy-respecting tab management tool with no malicious functionality. The extension:
- ✅ Operates entirely offline with no network communication
- ✅ Uses Chrome APIs only for stated tab management purposes
- ✅ Stores all data locally using standard Chrome storage APIs
- ✅ Has no content scripts and cannot access page content
- ✅ Requests minimal, justified permissions
- ✅ Provides genuine user value through tab organization features
- ✅ Uses open-source libraries (publicsuffixlist.js) for domain parsing
- ✅ Implements export/import for user data portability

This extension is safe for users and poses no security or privacy risks.

## Recommendations

For users:
- ✅ Safe to install and use
- Extension permissions are appropriate for functionality
- User data remains local to browser, not transmitted externally

For developers:
- Consider bundling the WASM file instead of attempting remote fetch (which fails anyway)
- Good code quality with clear separation of concerns
- Well-structured with Bootstrap UI framework

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Analysis Method**: Static code analysis, manifest review, API usage audit
