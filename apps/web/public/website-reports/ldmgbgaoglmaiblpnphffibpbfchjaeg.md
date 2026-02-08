# Security Analysis Report: New TongWenTang

## Extension Metadata

- **Extension Name**: New TongWenTang
- **Extension ID**: ldmgbgaoglmaiblpnphffibpbfchjaeg
- **Version**: 2.4.0
- **User Count**: ~70,000
- **Author**: t7yang
- **Homepage**: https://github.com/tongwentang/tongwentang-extension
- **Manifest Version**: 3

## Executive Summary

New TongWenTang is a Chinese text conversion extension that converts between Simplified and Traditional Chinese characters. The extension is **CLEAN** with no evidence of malicious activity, tracking, or data exfiltration. The code is open-source, functionality matches the stated purpose, and permission usage is appropriate and minimal.

The extension uses legitimate browser APIs for text manipulation and provides keyboard shortcuts and context menus for user-initiated conversions. All network requests are limited to loading local dictionary files. No external connections, tracking services, or suspicious behaviors were detected.

## Vulnerability Analysis

### 1. Network Activity - CLEAN

**Severity**: N/A
**Files**: background.js
**Verdict**: CLEAN

**Analysis**:
- Only 1 fetch call detected in background.js
- Fetch is used exclusively for loading local dictionary files: `fetch("dictionaries/" + [type] + ".min.json")`
- No XMLHttpRequest usage
- No external URLs or remote endpoints
- No WebSocket connections
- Dictionaries verified as legitimate Chinese character mappings (s2t-char.min.json, s2t-phrase.min.json, t2s-char.min.json, t2s-phrase.min.json)

**Code Evidence**:
```javascript
// background.js - Local dictionary loading
fetch("dictionaries/".concat(e,"-").concat(t,".min.json"))
```

### 2. Dynamic Code Execution - CLEAN

**Severity**: N/A
**Files**: background.js, content.js, options.js
**Verdict**: CLEAN

**Analysis**:
- No eval() usage
- No Function() constructor
- No document.write()
- No setTimeout/setInterval with string eval
- Code is webpack-bundled (minified but not maliciously obfuscated)

### 3. Data Collection & Exfiltration - CLEAN

**Severity**: N/A
**Files**: background.js, content.js
**Verdict**: CLEAN

**Analysis**:
- No tracking or analytics services (Google Analytics, Mixpanel, Segment, etc.)
- No external data transmission
- Storage API used only for user preferences (1 get, 2 set operations)
- No cookie access (cookie permission not requested)
- Cookie API references are inert webextension-polyfill definitions only

**Storage Usage**:
- Stores user conversion preferences
- Stores custom dictionary entries
- All data remains local

### 4. Permissions Analysis - LOW RISK

**Severity**: LOW
**Files**: manifest.json
**Verdict**: APPROPRIATE

**Declared Permissions**:
- `contextMenus` - Right-click menu for text conversion
- `downloads` - Export/import preferences
- `notifications` - User notifications for conversion status
- `storage` - Save user preferences and custom dictionaries
- `tabs` - Query tabs for conversion (uses tabs.sendMessage, tabs.query only)
- `unlimitedStorage` - Store large dictionary files

**Optional Permissions**:
- `clipboardWrite` - Convert clipboard text to Traditional/Simplified
- `clipboardRead` - Read clipboard for conversion

**Analysis**:
All permissions are justified by core functionality:
- Context menus enable right-click conversion
- Clipboard permissions enable keyboard shortcut-based clipboard conversion (Shift+Alt+Z, Shift+Alt+X)
- Downloads enable preference backup/restore
- Storage needed for preferences and custom user dictionaries
- Notifications inform users of conversion completion

### 5. Content Security Policy - SECURE

**Severity**: N/A
**Files**: manifest.json
**Verdict**: SECURE

**Analysis**:
- No custom CSP defined (uses default secure policy)
- Default MV3 CSP prevents inline scripts and eval
- No unsafe-inline or unsafe-eval directives

### 6. Content Script Scope - EXPECTED

**Severity**: LOW (expected for functionality)
**Files**: manifest.json, content.js
**Verdict**: APPROPRIATE

**Analysis**:
- Runs on `<all_urls>` with all_frames: true
- Necessary for converting Chinese text on any webpage
- Uses MutationObserver to detect dynamic content changes
- Only manipulates text nodes (nodeValue), not HTML structure
- No DOM manipulation via innerHTML/outerHTML
- No event listeners for sensitive data (keypress, password fields)

**Functionality**:
- Monitors DOM for text content
- Converts characters using local dictionary lookups
- Updates text in-place without affecting page structure

### 7. Message Passing - CLEAN

**Severity**: N/A
**Files**: background.js, content.js
**Verdict**: CLEAN

**Analysis**:
- Uses chrome.runtime.sendMessage for internal extension communication
- No postMessage to external origins
- No externally_connectable manifest entry
- Communication limited to background ↔ content script

### 8. Obfuscation Analysis - ACCEPTABLE

**Severity**: N/A
**Files**: All .js files
**Verdict**: STANDARD BUILD

**Analysis**:
- Code is webpack-bundled (standard for modern extensions)
- Minified but not maliciously obfuscated
- No excessive hex encoding or unicode escapes
- Build process is transparent (open-source repository)
- Contains webextension-polyfill for cross-browser compatibility

## False Positive Analysis

| Pattern | Location | Classification | Reason |
|---------|----------|----------------|---------|
| cookie API references | background.js | False Positive | Part of webextension-polyfill API definitions, not active code |
| MutationObserver | content.js | False Positive | Required for detecting dynamic page content changes for conversion |
| tabs permission | manifest.json | False Positive | Used only for sendMessage and query, not for URL tracking |
| <all_urls> scope | manifest.json | False Positive | Required to convert Chinese text on any website |
| fetch calls | background.js | False Positive | Only loads local dictionary files, no external requests |

## API Endpoints & External Connections

**No external API endpoints or remote connections detected.**

| Type | URL | Purpose | Verdict |
|------|-----|---------|---------|
| Local | dictionaries/s2t-char.min.json | Simplified to Traditional character mappings | Legitimate |
| Local | dictionaries/s2t-phrase.min.json | Simplified to Traditional phrase mappings | Legitimate |
| Local | dictionaries/t2s-char.min.json | Traditional to Simplified character mappings | Legitimate |
| Local | dictionaries/t2s-phrase.min.json | Traditional to Simplified phrase mappings | Legitimate |

## Data Flow Summary

```
User Input (webpage text, keyboard shortcut, or clipboard)
    ↓
Content Script (detects Chinese text via MutationObserver)
    ↓
Message to Background Script
    ↓
Load Dictionary (local fetch to dictionaries/*.json)
    ↓
Character Conversion Logic
    ↓
Return Converted Text
    ↓
Update DOM Text Nodes (content.js)
    ↓
Optional: Notification (conversion complete)
```

**No external data transmission occurs at any stage.**

## Keyboard Shortcuts

The extension defines 4 keyboard shortcuts for user-initiated conversions:

1. `Shift+Alt+C` - Convert webpage Simplified → Traditional
2. `Shift+Alt+V` - Convert webpage Traditional → Simplified
3. `Shift+Alt+Z` - Convert clipboard Simplified → Traditional
4. `Shift+Alt+X` - Convert clipboard Traditional → Simplified

All operations are user-initiated and local-only.

## Open Source Verification

- **Repository**: https://github.com/tongwentang/tongwentang-extension
- **License**: Open source
- Extension behavior matches documented functionality
- No hidden features or undocumented network calls

## Risk Assessment

### Overall Risk Level: **CLEAN**

### Risk Breakdown:

- **Malware**: None detected
- **Data Exfiltration**: None detected
- **Tracking/Analytics**: None detected
- **Privacy Violations**: None detected
- **Excessive Permissions**: No
- **Code Execution**: No dangerous patterns
- **Network Requests**: Local only
- **Obfuscation**: Standard build tools

### Justification:

New TongWenTang is a legitimate, open-source utility extension with transparent functionality. The extension:

1. ✅ Performs only its stated purpose (Chinese text conversion)
2. ✅ Makes no external network requests
3. ✅ Includes no tracking or analytics
4. ✅ Uses permissions appropriately for functionality
5. ✅ Open source with verifiable code
6. ✅ No dynamic code execution or eval
7. ✅ No data collection or exfiltration
8. ✅ Standard webpack bundling (not malicious obfuscation)

The extension operates entirely locally, converting text using pre-loaded dictionary files. All user interactions are explicit (keyboard shortcuts, context menus, toolbar icon) with no background surveillance or data harvesting.

## Recommendations

**For Users**: This extension is safe to use. No security concerns identified.

**For Developers**: Continue maintaining open-source transparency. Consider adding:
- Subresource Integrity (SRI) for any future CDN resources
- Content Security Policy reporting endpoints for monitoring

## Conclusion

New TongWenTang is a **CLEAN** extension with no security vulnerabilities, malicious code, or privacy concerns. The extension performs legitimate Chinese text conversion using local dictionaries with appropriate permissions and no external connections. Recommended for use without restrictions.
