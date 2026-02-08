# Vulnerability Report: Just a Clock - the Hours

## Metadata
- **Extension Name**: Just a Clock - the Hours
- **Extension ID**: agglgohcegmeeaccikjfmehncfomccpg
- **Version**: 0.93.7
- **Users**: ~10,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

"Just a Clock - the Hours" is a simple browser extension that displays the current time as an icon in the browser toolbar. The extension allows users to toggle between 12/24 hour formats and customize the clock appearance.

**Key Findings:**
- Clean, simple codebase with minimal attack surface
- No malicious behavior detected
- Minimal permissions (storage, alarms)
- Contains commented-out Google Analytics tracking code that is NOT active
- No network requests, dynamic code execution, or content script injection
- No obfuscation or suspicious patterns
- Completely offline functionality

The extension is functionally benign with no security vulnerabilities or malicious intent.

## Vulnerability Details

### 1. Inactive Google Analytics Code (INFO)
**Severity**: INFO
**Location**: `setHour.js` (lines 3-14), `options.js` (lines 1-12)
**Status**: FALSE POSITIVE

**Description:**
The extension contains Google Analytics tracking code that is commented out and non-functional:

```javascript
// Google Analytics
var _gaq = _gaq || [];
_gaq.push(
	['_setAccount', 'UA-66160817-3'],
	['_trackPageview']
);

// (function() {
//   var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
//   ga.src = 'https://ssl.google-analytics.com/ga.js';
//   var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
// })();
```

**Analysis:**
- The code that would load the Google Analytics library is completely commented out
- While `_gaq.push()` calls exist in the code, they have no effect without the GA script being loaded
- No network requests are made
- This appears to be legacy code from an earlier version that tracked usage statistics

**Verdict**: The tracking code is inactive and does not execute. No data is sent to Google Analytics or any other external service.

---

### 2. innerHTML Usage (INFO)
**Severity**: INFO
**Location**: `options.js` (line 72)
**Status**: FALSE POSITIVE

**Description:**
```javascript
objects[i].innerHTML = chrome.i18n.getMessage(objects[i].dataset.msg);
```

**Analysis:**
- Used only for internationalization (i18n) of UI text
- Data source is `chrome.i18n.getMessage()` which returns sanitized localized strings from the extension's `_locales` directory
- No user input or external data is involved
- Standard pattern for Chrome extension localization

**Verdict**: Safe usage for legitimate internationalization purposes.

## False Positives Summary

| Pattern | Location | Reason |
|---------|----------|--------|
| Google Analytics | setHour.js, options.js | Code is commented out and non-functional |
| innerHTML | options.js:72 | Safe i18n string insertion from chrome.i18n API |
| _gaq.push() calls | Multiple locations | No-op without GA script loaded |

## API Endpoints

**No external API endpoints detected.**

The extension makes no network requests and operates entirely offline.

## Data Flow Summary

### Data Storage (Local Only)
The extension uses `chrome.storage.local` to persist user preferences:
- `just_a_clock_hours` - Clock format (12 or 24 hour)
- `just_a_clock_color` - Text color preference (black or white)
- `just_a_clock_notify` - Desktop notification preference
- `just_a_clock_notify_duration` - Notification duration setting

### Data Processing
1. **Time Retrieval**: Uses JavaScript `Date()` object to get current time
2. **Icon Updates**: Updates toolbar icon every 6 seconds via `chrome.alarms` API
3. **User Settings**: Reads/writes preferences to local storage
4. **Localization**: Reads UI strings from bundled locale files

### No External Data Transmission
- No fetch/XMLHttpRequest calls
- No remote script loading
- No third-party SDK integration
- All functionality is self-contained

## Permission Analysis

### Requested Permissions
1. **storage** - Used to save user preferences (clock format, color, notifications)
   - **Justification**: Legitimate - persists user settings
   - **Risk**: None - only stores benign preferences

2. **alarms** - Used to trigger icon updates every 6 seconds
   - **Justification**: Legitimate - keeps clock display current
   - **Risk**: None - standard scheduling mechanism

### Missing High-Risk Permissions
The extension does NOT request:
- `tabs`, `webRequest`, `webNavigation` (no browsing tracking)
- `cookies` (no cookie access)
- `<all_urls>` or host permissions (no content script injection)
- `downloads`, `bookmarks`, `history` (no sensitive data access)

## Code Complexity Analysis

- **Total JavaScript Lines**: 258 (113 in setHour.js, 145 in options.js)
- **Obfuscation**: None
- **External Dependencies**: None
- **Dynamic Code Execution**: None (no eval, Function, or script injection)

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

### Justification
1. **No Malicious Behavior**: The extension performs exactly as described - displaying a clock icon
2. **Minimal Attack Surface**: Only 258 lines of straightforward, readable code
3. **No Network Activity**: Completely offline, no data exfiltration possible
4. **Appropriate Permissions**: Minimal permissions that match stated functionality
5. **No Obfuscation**: Code is clean and transparent
6. **No Privacy Concerns**: No tracking, analytics, or data collection
7. **No Suspicious Patterns**: No extension enumeration, proxy infrastructure, SDK injection, or other red flags

### Recommendations
- No security concerns identified
- Extension can be considered safe for user installation
- The commented-out Google Analytics code could be removed to further reduce confusion, but poses no active risk

### Notes
This extension represents a best-case scenario for browser extension security: minimal permissions, offline functionality, clean code, and transparent operation. It serves a simple utility purpose without any privacy or security implications.
