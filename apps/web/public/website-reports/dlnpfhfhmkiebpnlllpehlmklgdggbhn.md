# Vulnerability Report: Don't Close Window With Last Tab

## Extension Metadata
- **Extension ID**: dlnpfhfhmkiebpnlllpehlmklgdggbhn
- **Extension Name**: Don't Close Window With Last Tab
- **Version**: 0.11
- **User Count**: ~40,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-08

## Executive Summary

Don't Close Window With Last Tab is a simple browser behavior modification extension that prevents the Chrome browser window from closing when the last tab is closed. The extension operates purely through local tab management APIs with no network communication, third-party services, or data exfiltration. The codebase is minimal, transparent, and serves only its stated purpose.

**Overall Risk Assessment: CLEAN**

## Permissions Analysis

### Declared Permissions
- `tabs` - Required to monitor and manage tab lifecycle events
- `storage` - Used to persist user configuration options

### Permission Usage Assessment
Both permissions are essential for the extension's core functionality and are used appropriately:
- **tabs**: Monitors tab/window events (onUpdated, onRemoved, onActivated, etc.) to detect when the last tab is about to be closed and creates a pinned placeholder tab to prevent window closure
- **storage**: Stores user preferences (single_new_tab, new_tab_last, first_window, every_window) using chrome.storage.sync

**Verdict**: Minimal necessary permissions, no excessive access requests.

## Manifest Security Review

### Content Security Policy
- No custom CSP defined (uses Manifest V3 defaults)
- Default MV3 CSP is restrictive and secure

### External Resources
- No external scripts loaded
- Uses local browser-polyfill.js (Mozilla WebExtension Polyfill v0.9.0 from March 2022)
- No CDN dependencies
- No remote code execution vectors

**Verdict**: Secure manifest configuration.

## Code Analysis

### Background Script (background.js)
**File**: `background.js` (200 lines, 6.8 KB)

**Functionality**:
- Listens to tab/window lifecycle events
- Implements tab management logic to prevent window closure
- Creates/removes pinned "chrome://newtab/" tabs dynamically
- Loads user preferences from chrome.storage.sync

**Security Assessment**:
- No network requests (fetch, XMLHttpRequest, WebSocket)
- No dynamic code execution (eval, Function, new Function)
- No message passing to external contexts
- No chrome.debugger, chrome.webRequest, or chrome.proxy APIs
- Pure local state management with browser APIs
- All URLs hardcoded to chrome:// internal pages

**Code Patterns Observed**:
```javascript
// Configuration loading from storage
chrome.storage.sync.get({
    single_new_tab: false,
    new_tab_last: false,
    first_window: false,
    every_window: false
}, function(items) { ... });

// Tab management operations
await browser.tabs.create({"windowId": window.id, "index": 0, "pinned": true, "active": false, "url": newTabUrl});
await browser.tabs.remove(windowPinnedTabs[0].id);
await browser.tabs.update(window.tabs[1].id, {"active": true});
```

**Verdict**: Clean implementation, no malicious patterns detected.

### Options Page (options.js, options.html)
**Functionality**:
- Provides UI for configuring extension behavior
- Saves/restores preferences to chrome.storage.sync
- Simple checkbox/radio button interface

**Security Assessment**:
- No external content loaded
- No user input sanitization issues (only boolean values stored)
- No XSS vectors
- Inline styles only, no external CSS

**Verdict**: Safe configuration interface.

### Third-Party Dependencies

#### browser-polyfill.js
- **Source**: Mozilla WebExtension Polyfill v0.9.0 (March 2022)
- **Purpose**: Cross-browser compatibility layer (Chrome/Firefox)
- **Security**: Legitimate Mozilla library, no modifications detected
- **Verdict**: Safe dependency

## Vulnerability Findings

### None Detected

No security vulnerabilities, malicious behavior, or privacy concerns identified.

## False Positive Analysis

| Pattern | Location | Reason for Exclusion | Verdict |
|---------|----------|---------------------|---------|
| N/A | N/A | No suspicious patterns detected | CLEAN |

## API Endpoints & Network Activity

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| N/A | No network activity detected | N/A | NONE |

**Network Analysis**: Extension makes zero network requests. All functionality is local.

## Data Flow Summary

### Data Collection
- **User Preferences**: Boolean configuration flags (single_new_tab, new_tab_last, first_window, every_window)
- **Storage Location**: chrome.storage.sync (Chrome account sync storage)

### Data Processing
- Configuration values read on initialization and when changed
- Used to determine tab management behavior
- No PII, browsing history, or sensitive data accessed

### Data Transmission
- **None**: No data transmitted to external servers
- **Sync Storage**: Chrome's built-in sync mechanism may sync preferences across user's devices (standard Chrome behavior)

### Data Retention
- Configuration persists in chrome.storage.sync until user uninstalls extension or clears data

**Verdict**: Minimal local data usage, no privacy concerns.

## Behavioral Analysis

### Core Functionality
1. Monitors tab/window lifecycle events
2. When last tab in window is about to be closed, creates a pinned "New Tab" placeholder
3. Automatically removes placeholder when additional tabs are opened
4. Prevents accidental browser window closure

### User-Facing Behavior
- Transparent operation aligned with stated purpose
- User-configurable options for different prevention modes
- No hidden functionality detected

### Extension Enumeration/Interference
- No evidence of detecting or interfering with other extensions
- No chrome.management API usage

**Verdict**: Behavior matches description, no deceptive practices.

## Risk Assessment

### CRITICAL Vulnerabilities
None.

### HIGH Vulnerabilities
None.

### MEDIUM Vulnerabilities
None.

### LOW Vulnerabilities
None.

## Overall Verdict

**RISK LEVEL: CLEAN**

### Justification
Don't Close Window With Last Tab is a legitimate utility extension with a focused, benign purpose. The extension:

- Uses only necessary permissions (tabs, storage)
- Contains no network communication whatsoever
- Implements no tracking, analytics, or telemetry
- Does not access sensitive user data
- Has no obfuscation or anti-analysis techniques
- Operates transparently with user-visible effects
- Includes only a standard Mozilla polyfill as a dependency
- Contains clean, readable code with no malicious patterns

The extension serves its stated purpose of preventing accidental window closure and does nothing beyond that scope. It represents a minimal-risk utility extension appropriate for general use.

### Recommendations
- **For Users**: Safe to use. Extension does exactly what it claims.
- **For Security Teams**: No monitoring required. Clean utility extension.
- **For Developers**: Good example of a focused, non-intrusive extension.

## Code Quality Notes
- Well-structured, readable code
- Appropriate use of async/await patterns
- Includes debugging capability (disabled by default)
- Could benefit from more robust error handling in edge cases
- Some code redundancy could be refactored

---

**Analysis Completed**: 2026-02-08
**Analyst**: Claude Sonnet 4.5
**Confidence Level**: High
