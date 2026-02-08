# Security Analysis Report: Time Zone Converter - Savvy Time

## Extension Metadata
- **Extension ID**: plhnjpnbkmdmooideifhkonobdkgbbof
- **Extension Name**: Time Zone Converter - Savvy Time
- **Version**: 1.10
- **User Count**: ~100,000 users
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Time Zone Converter - Savvy Time is a legitimate time zone conversion utility extension with a clean security profile. The extension uses minimal permissions (only `storage`), implements proper CSP, and contains no malicious functionality. The codebase consists primarily of a React-based frontend application with embedded city/timezone data and legitimate calendar integration features. No evidence of data exfiltration, malicious APIs, tracking, or security vulnerabilities was found.

**Overall Risk Level: CLEAN**

## Manifest Analysis

### Permissions Requested
- `storage` - Used for storing user preferences (time format, saved locations, theme)

### Content Security Policy
```json
"extension_pages": "script-src 'self'; object-src 'self'"
```
- **Assessment**: Strong CSP that only allows scripts from the extension itself
- **Verdict**: ✅ SECURE - No inline scripts or external resources allowed

### Declared Resources
- Single popup page (`index.html`)
- No background service worker
- No content scripts
- No host permissions

**Verdict**: ✅ MINIMAL ATTACK SURFACE - Extension only operates in popup context with no web page access

## Code Analysis

### JavaScript Files Analyzed
1. **js/app.b06c1a03.js** (223,817 lines) - Main application bundle
2. **js/409.f6a94a4d.js** (42,297 lines) - Vendor/library bundle (Emotion CSS-in-JS, React)

### Security-Relevant Findings

#### 1. Storage Usage (BENIGN)
**Location**: Lines 223280-223396 in app.b06c1a03.js

The extension uses `chrome.storage.sync` API for legitimate preferences storage:
- `timeFormat` - User's preferred time format (12h/24h)
- `userLocations` - Saved timezone locations
- `autoLocation` - Auto-location preference
- `themeMode` - Light/dark theme preference

**Code Sample**:
```javascript
chrome.storage.sync.get(["timeFormat"], function(a) {
  i(a.timeFormat)
})
```

**Verdict**: ✅ BENIGN - Standard settings storage, falls back to localStorage when chrome.storage unavailable

#### 2. External URL References (BENIGN)
**Location**: Throughout app.b06c1a03.js

All external URLs reference the legitimate Savvy Time website:
- `https://savvytime.com/converter` - Link to web version
- Calendar integration links (Google Calendar, Yahoo Calendar)

**Code Sample**:
```javascript
url: "https://savvytime.com/converter"
"https://www.google.com/calendar/render?action=TEMPLATE&text=" + ...
"https://calendar.yahoo.com/?v=60&title=" + ...
```

**Verdict**: ✅ BENIGN - No data transmission, only user-initiated links for calendar export

#### 3. DOM Manipulation (BENIGN)
**Location**: Lines 222000-222795 in app.b06c1a03.js

Standard UI framework operations:
- Event listeners for user interactions
- Dynamic HTML generation for timezone cards
- Calendar picker integration

**Verdict**: ✅ BENIGN - Normal React application behavior within popup context

#### 4. No Network Requests
**Analysis**: Extensive grep searches found NO:
- `fetch()` calls
- `XMLHttpRequest` usage
- `$.ajax()` or similar
- Remote script loading

**Verdict**: ✅ EXCELLENT - Extension is fully offline, no telemetry or tracking

#### 5. No Dynamic Code Execution
**Analysis**: No occurrences of:
- `eval()`
- `new Function()`
- `document.write()`
- Base64 decode/encode for code execution

**Verdict**: ✅ SECURE - No code injection vectors

### Library Analysis

**Vendor Bundle (409.f6a94a4d.js)** contains:
- Emotion CSS-in-JS library (React styling framework)
- Standard React helpers
- CSS autoprefixer utilities

**Verdict**: ✅ CLEAN - Standard frontend libraries, no obfuscation beyond webpack minification

### Data Flow

```
User Input (Timezone Selection)
    ↓
Chrome Storage Sync (Preferences)
    ↓
Local Processing (Time Calculations)
    ↓
UI Rendering (Popup Display)
```

**No External Data Transmission** - All processing is local

## False Positives Table

| Pattern | Context | Reason for Dismissal |
|---------|---------|---------------------|
| `document.getElementsByClassName` | UI framework code | Standard React/DOM manipulation |
| `window.addEventListener` | Event handling | Normal popup event listeners |
| `chrome.storage` | Settings persistence | Legitimate use of declared permission |
| URLs in strings | Calendar integration | User-initiated export links only |
| `.get()` / `.post()` matches | City name data | Part of timezone/city names like "Pereval's'k", not API calls |

## API Endpoints Table

| Endpoint | Purpose | Data Sent | Risk Level |
|----------|---------|-----------|------------|
| None | N/A | N/A | CLEAN |

**Note**: Extension operates entirely offline with no API communications.

## Architecture Summary

**Type**: Standalone popup application
**Framework**: React with Emotion CSS-in-JS
**Data Storage**: Chrome Storage Sync API (with localStorage fallback)
**Network Activity**: None (except user-initiated calendar export links)

**Core Functionality**:
1. Embedded timezone database (~200k+ city records)
2. Time zone conversion calculations (client-side)
3. Calendar export (ICS format generation)
4. User preference persistence

## Vulnerability Assessment

### Tested Attack Vectors

1. **Data Exfiltration**: ❌ Not Present
2. **Remote Code Loading**: ❌ Not Present
3. **API Key Exposure**: ❌ Not Applicable
4. **XSS Vectors**: ❌ Protected by CSP
5. **Credential Theft**: ❌ Not Applicable
6. **Extension Enumeration**: ❌ Not Present
7. **Proxy Infrastructure**: ❌ Not Present
8. **Market Intelligence SDKs**: ❌ Not Present
9. **AI Scraping**: ❌ Not Present
10. **Ad/Coupon Injection**: ❌ No content scripts

### Security Strengths

1. ✅ Minimal permissions (storage only)
2. ✅ Strong Content Security Policy
3. ✅ No network communications
4. ✅ No content scripts (cannot affect web pages)
5. ✅ Open-source framework usage
6. ✅ No obfuscation or anti-analysis techniques
7. ✅ Offline-first architecture

## Overall Risk Assessment

**Risk Level: CLEAN**

**Justification**:
- Extension has minimal permissions and no ability to access web page content
- No network communication or data exfiltration mechanisms
- Clean codebase with legitimate functionality
- Strong security boundaries (CSP, manifest v3)
- Transparent operation (user preferences only)

**Recommendation**: This extension poses no security risk to users. It is a well-designed, privacy-respecting utility that operates entirely offline.

## Technical Notes

- **Total Lines of Code**: 266,114 (mostly embedded timezone data)
- **Obfuscation Level**: Standard webpack minification only
- **External Dependencies**: React ecosystem libraries (benign)
- **Update Mechanism**: Standard Chrome Web Store auto-update
