# Security Analysis Report: Change Case Extension

## Extension Metadata

- **Extension Name:** Change Case
- **Extension ID:** lpakoahdokkkonadfppfgmednkknpgbm
- **Version:** 2.6.1
- **User Count:** ~70,000
- **Author:** Bartosz Lorek
- **Homepage:** http://www.bartoszlorek.pl/

## Executive Summary

Change Case is a **CLEAN** extension that provides text case transformation utilities through context menus and keyboard shortcuts. The extension implements multiple text formatting options (uppercase, lowercase, camelCase, snake_case, etc.) for editable fields. Security analysis reveals no malicious behavior, no network communications, and minimal permissions usage. The codebase is well-structured with legitimate text processing logic and standard Chrome extension APIs.

## Vulnerability Analysis

### FINDING 1: No Security Issues Detected
**Severity:** N/A
**Verdict:** CLEAN

**Description:**
Comprehensive analysis of the extension's codebase reveals no security vulnerabilities, malicious behavior, or privacy concerns.

**Evidence:**

1. **No Network Activity**
   - No `fetch()`, `XMLHttpRequest`, or WebSocket connections
   - No external API endpoints or remote servers
   - Only URLs found are React framework references and W3C namespaces (legitimate)

2. **Minimal Permissions**
   ```json
   "permissions": ["contextMenus", "activeTab", "storage", "scripting"]
   ```
   - `contextMenus`: Creates right-click menu entries
   - `activeTab`: Required to inject content script on demand
   - `storage`: Stores user preferences (ignore/correct lists)
   - `scripting`: Injects content script when needed
   - No overprivileged permissions (no cookies, webRequest, tabs, etc.)

3. **Service Worker (Background Script)**
   - File: `service-worker.js` (88 lines)
   - Creates context menu items for text transformations
   - Injects content script only when user triggers action
   - Uses handshake pattern to check if script already injected
   - No dynamic code execution, no network calls

4. **Content Script**
   - File: `content-script.js` (787 lines)
   - Pure text transformation logic (camelCase, snake_case, etc.)
   - User preference support (ignore list, correct list)
   - DOM manipulation limited to selected text in editable fields
   - No data exfiltration, no keylogging, no tracking

5. **Options Page**
   - Built with React framework
   - Allows users to configure ignore/correct word lists
   - Uses `chrome.storage.sync` for preference storage
   - No external dependencies loaded at runtime

**Code Review Highlights:**

Service Worker - Context Menu Creation:
```javascript
chrome.runtime.onInstalled.addListener(t => {
  s.forEach((e, a) => {
    e === null ? chrome.contextMenus.create({
      contexts: ["editable"],
      id: `${a}_separator`,
      type: "separator"
    }) : chrome.contextMenus.create({
      contexts: ["editable"],
      id: e.name,
      title: e.text
    })
  })
})
```

Content Script - Message Handler:
```javascript
chrome.runtime.onMessage.addListener(T("change_case_handshake", async () => ({
  injected: !0
})));
chrome.runtime.onMessage.addListener(T("change_case_method", async ({
  name: u
}) => {
  let A = fu[u];
  // Text transformation logic
}));
```

**Assessment:** The extension functions exactly as advertised with no hidden functionality.

## False Positive Analysis

| Pattern | Location | Explanation |
|---------|----------|-------------|
| React SVG namespaces | options-page.js | Standard React framework namespace URLs (http://www.w3.org/1999/xlink, http://www.w3.org/2000/svg) |
| React error URLs | options-page.js | React error decoder URL (https://reactjs.org/docs/error-decoder.html) - not called, part of minified React |
| `componentWillReceiveProps` | options-page.js | Standard React lifecycle methods in minified React library |
| DOM manipulation | content-script.js | Legitimate text node modification for case conversion in editable fields |
| `chrome.storage.sync` | content-script.js | Proper storage API usage for user preferences (ignore/correct lists) |

## API Endpoints & External Connections

| Endpoint | Purpose | Assessment |
|----------|---------|------------|
| None | N/A | No external connections detected |

**Storage Usage:**
- `chrome.storage.sync` stores:
  - `ignoreList`: Words to preserve during transformation
  - `correctList`: Words to force-correct during transformation

## Data Flow Summary

```
User Action (Right-click/Keyboard)
    ↓
Service Worker receives command
    ↓
Injects content-script.js (if not present)
    ↓
Content script receives transformation method
    ↓
Reads selected text from DOM
    ↓
Applies text transformation (local processing)
    ↓
Updates text node in-place
    ↓
Re-selects transformed text
```

**Data Retention:**
- User preferences stored locally via `chrome.storage.sync`
- No text content stored or transmitted
- No analytics or telemetry

## Overall Risk Assessment

**RISK LEVEL: CLEAN**

**Justification:**
1. **No Malicious Code:** Zero evidence of malware, spyware, or data theft
2. **No Network Activity:** Extension operates entirely offline
3. **Appropriate Permissions:** Only requests necessary permissions for advertised functionality
4. **Transparent Behavior:** All functionality matches extension description
5. **No Obfuscation:** Code is minified but not obfuscated; logic is clear and auditable
6. **Privacy-Friendly:** No user data collection or tracking
7. **Legitimate Developer:** Bartosz Lorek with public homepage
8. **Open Source Libraries:** Uses standard React framework without modifications

**Recommendations:**
- No security concerns identified
- Safe for enterprise and personal use
- Extension can be whitelisted

## Technical Notes

- Manifest V3 compliant (service worker architecture)
- Text transformations implemented using standard JavaScript string methods
- DOM access limited to editable elements (`contenteditable`, `textarea`, `input`)
- No dynamic script loading or remote code execution
- No use of `eval()`, `Function()`, or similar dangerous patterns
- Content Security Policy: Default (not specified, uses Chrome defaults)

## Detailed Code Analysis

### Service Worker Deep Dive
**File:** `service-worker.js` (88 lines, 2.0KB)

The service worker implements a simple event-driven architecture:

1. **Context Menu Setup**: Creates 13 transformation options plus separators on installation
2. **Dynamic Injection**: Uses handshake pattern to avoid re-injecting content script
3. **Message Routing**: Forwards user commands to active tab's content script

**No suspicious patterns:**
- No `eval()`, `Function()`, or dynamic code execution
- No `setTimeout`/`setInterval` with string arguments
- No network calls (`fetch`, `XMLHttpRequest`, `WebSocket`)
- No external script loading
- No obfuscation beyond standard minification

### Content Script Deep Dive
**File:** `content-script.js` (787 lines, 42KB)

Implements 13 text transformation functions:
1. `upperCase` - Converts to UPPERCASE
2. `lowerCase` - Converts to lowercase
3. `titleCase` - Title Case With Proper Capitalization
4. `sentenceCase` - Sentence case with proper punctuation handling
5. `camelCase` - camelCase converter
6. `pascalCase` - PascalCase converter
7. `constantCase` - CONSTANT_CASE converter
8. `paramCase` - param-case converter
9. `snakeCase` - snake_case converter
10. `dotCase` - dot.case converter
11. `toggleCase` - tOGGLE cASE converter
12. `noAccents` - Removes diacritics (à → a, ñ → n)
13. `noCase` - Removes all case formatting

**Text Processing Logic:**
- Uses regex patterns for Unicode character detection
- Handles complex scripts (Latin, Cyrillic, Greek, etc.)
- Preserves user-defined exception words from preferences
- Operates only on selected text in editable contexts

**DOM Manipulation:**
- Limited to `input`, `textarea`, and `contentEditable` elements
- Uses proper DOM APIs (`setSelectionRange`, `createRange`, `getSelection`)
- Triggers `change` and `input` events for framework compatibility
- No form submission, no data harvesting

### Options Page Deep Dive
**File:** `options-page.js` (8,035 lines, 251KB - React bundle)

This is a production React 18 bundle containing:
- React core library
- React DOM renderer
- Classnames utility library
- Extension-specific settings UI

**Analysis:**
- All URLs are framework references (React error decoder, W3C namespaces)
- No analytics SDKs (no Google Analytics, Mixpanel, Amplitude, etc.)
- No tracking code or telemetry
- Single chrome API call: `chrome.tabs.create()` for opening help links
- Uses `chrome.storage.sync` for preferences only

**React-specific false positives identified:**
- `innerHTML` usage for SVG namespace handling (standard React behavior)
- Event propagation functions (`stopTracking`, `stopPropagation`)
- Synthetic event system references

## Security Checklist

| Security Concern | Status | Notes |
|-----------------|--------|-------|
| Remote code execution | ✅ CLEAN | No eval, Function, or dynamic imports |
| Network exfiltration | ✅ CLEAN | Zero network calls detected |
| Excessive permissions | ✅ CLEAN | Only 4 permissions, all justified |
| Data harvesting | ✅ CLEAN | No keyloggers, form interceptors, or data collection |
| Cookie theft | ✅ CLEAN | No cookie access permissions |
| Extension killing | ✅ CLEAN | No chrome.management API usage |
| Third-party SDKs | ✅ CLEAN | Only bundled React (legitimate) |
| Obfuscation | ✅ CLEAN | Standard minification only |
| Crypto mining | ✅ CLEAN | No WebAssembly or worker threads |
| Ad injection | ✅ CLEAN | No DOM injection beyond text transformation |
| Clickjacking | ✅ CLEAN | No iframe manipulation |
| XSS vectors | ✅ CLEAN | Proper text node handling |
| WebRequest interception | ✅ CLEAN | No webRequest permission |
| History access | ✅ CLEAN | No history permission |
| Bookmark theft | ✅ CLEAN | No bookmarks permission |
| Download monitoring | ✅ CLEAN | No downloads permission |

## Conclusion

Change Case is a **clean, legitimate productivity extension** with no security or privacy concerns. The extension provides text transformation utilities as advertised without any hidden functionality, data collection, or network communication. The codebase demonstrates good security practices with minimal permissions and local-only processing.

**Final Verdict: CLEAN**

---
**Analysis Completed:** 2026-02-07
**Analyst:** Claude Sonnet 4.5
**Risk Level:** CLEAN
