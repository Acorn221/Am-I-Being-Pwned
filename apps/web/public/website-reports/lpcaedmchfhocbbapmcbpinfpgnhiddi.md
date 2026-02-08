# Security Analysis Report: Google Keep Chrome Extension

## Extension Metadata

- **Extension Name**: Google Keep Chrome Extension
- **Extension ID**: lpcaedmchfhocbbapmcbpinfpgnhiddi
- **Version**: 4.26051.600.1
- **User Count**: ~8,000,000
- **Publisher**: keep-eng@google.com (Official Google)
- **Analysis Date**: 2026-02-08

## Executive Summary

The Google Keep Chrome Extension is an **official Google product** that allows users to save web content to Google Keep. This analysis found **NO MALICIOUS BEHAVIOR** and **NO CRITICAL VULNERABILITIES**. The extension is well-architected, uses appropriate security controls, and operates within the scope of its intended functionality.

The extension uses legitimate Google APIs (`play.google.com/log`, `googleapis.com/auth`), implements proper Content Security Policy, and restricts its operation to legitimate web pages (excludes chrome://, webstore URLs). All permissions are justified for the extension's core functionality.

**Overall Risk Assessment**: **CLEAN**

This extension serves its intended purpose as a legitimate Google product for saving web content to Keep notes. While it requires broad permissions, these are necessary for its clipboard and web content capture features, and there is no evidence of abuse or malicious behavior.

## Manifest Analysis

### Permissions Assessment

| Permission | Justification | Risk Level |
|------------|--------------|------------|
| `activeTab` | Required to capture current page content/screenshots | LOW - Standard for content capture |
| `identity` | OAuth authentication with Google account | LOW - Legitimate Google auth |
| `identity.email` | Display user email in extension UI | LOW - User identification |
| `contextMenus` | Right-click menu "Save to Keep" | LOW - Core feature |
| `tabs` | Query/manage tabs for content injection | LOW - Required for page access |
| `unlimitedStorage` | Offline storage for Keep notes | LOW - Justified for offline functionality |
| `scripting` | Inject content scripts for page parsing | LOW - Content capture feature |

### Host Permissions

```json
"host_permissions": ["file://*/*", "http://*/", "https://*/"]
```

**Analysis**: Broad host permissions are required to allow saving content from any web page. This is a legitimate use case for a note-taking extension. The extension explicitly **excludes** chrome:// pages and webstore URLs (see line 5355 in background.js):

```javascript
Ij = ["chrome://", "https://chrome.google.com/webstore",
      "https://chromewebstore.google.com/", "edge://"];
```

### Content Security Policy

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

**Verdict**: ✅ SECURE - No `unsafe-eval`, no `unsafe-inline`, no remote script sources.

## Code Analysis

### 1. Background Script (background.js)

**File**: `background.js` (207KB, minified Google Closure Compiler output)

#### Key Functionality

1. **Context Menu Integration** (lines 8566-8600)
   - Creates right-click menu items for saving content
   - Options: "Save to Keep", "Save selection to Keep", "Save image to Keep"
   - Proper event handlers with user interaction logging

2. **OAuth Token Management** (lines 8754-8762)
   - Uses `chrome.identity.getAuthToken()` for Google authentication
   - Implements token caching and removal
   - Standard Google OAuth flow

3. **Content Script Injection** (lines 8693-8708)
   - Injects `flags.js` and `injector.js` when user triggers save action
   - Only injects on user action (not automatic)
   - Passes page metadata (title, URL, favicon) to injected frame

4. **Tab Management** (lines 8773-8789)
   - Monitors tab updates to enable/disable extension icon
   - Disables on restricted pages (chrome://, webstore)
   - No surveillance or unauthorized tab access

#### Network Communication

All network requests go to **legitimate Google domains**:

- `https://play.google.com/log?format=json&hasfast=true` (line 8354) - Analytics/logging
- `https://www.googleapis.com/auth/*` - OAuth scopes (manifest)
- `https://www.gstatic.com/keep/backgrounds/*` - UI assets
- `https://keep.google.com` - Main app redirect

**Verdict**: ✅ All endpoints are official Google infrastructure.

### 2. Content Scripts (injector.js)

**File**: `injector.js` (53KB)

#### Functionality

1. **Iframe Injection** (lines 1932-1996)
   - Creates sandboxed iframe for Keep popup UI
   - Loads `chrome.runtime.getURL("index.html")` (local resource)
   - Implements proper sandboxing with `allow-same-origin allow-scripts allow-forms`

2. **Page Content Extraction** (lines 1895-1916)
   - Extracts `window.getSelection()` for selected text
   - Searches for `og:image` meta tags for page thumbnails
   - Finds largest image on page (minimum 128x128) as fallback

3. **Message Passing** (lines 1858-1930)
   - Bidirectional communication with background script
   - Handles user actions: show/hide popup, get selection, speak message
   - No unauthorized data exfiltration

**Verdict**: ✅ Standard content script behavior for note-taking functionality.

### 3. WASM Files (ink/)

**Files**:
- `ink/nothreads/ink.wasm` (WebAssembly binary)
- `ink/threads/ink.wasm` (WebAssembly binary with threading)

**Purpose**: Google's "Ink" handwriting recognition engine for drawing/sketching in Keep notes.

**Analysis**: These are legitimate Google components for stylus/touch input processing. The WASM loaders use standard Emscripten patterns with proper error handling.

**Verdict**: ✅ Legitimate Google ink/handwriting technology.

## Vulnerability Assessment

### Dynamic Code Execution

| Pattern | Location | Severity | Verdict |
|---------|----------|----------|---------|
| `eval()` | `keep_ba-prod_app_script_ltr.js:10798` | LOW | **FALSE POSITIVE** - JSON parsing in Google Closure Library |
| `Function()` constructor | Multiple files | LOW | **FALSE POSITIVE** - Google Closure Compiler bind polyfills |
| `postMessage` | `background.js:7901` | LOW | **CLEAN** - Internal extension messaging |

**Analysis**: The `eval()` usage is for JSON parsing in older Google Closure Library code (`return eval("(" + a + ")")`). Modern code uses `JSON.parse()`. This is a known pattern in legacy Google code and poses no security risk in the extension context.

### HTML Injection

| Pattern | Location | Verdict |
|---------|----------|---------|
| `innerHTML` | `injector.js:1959`, `keep_ba-prod_app_script_*.js` | **CLEAN** - Sanitized via Google's SafeHtml API |

**Analysis**: All `innerHTML` assignments go through Google's Safe HTML sanitizer (`xd(b)` function, line 1584 in app scripts). The code explicitly validates SafeHtml wrappers before unwrapping.

### Data Collection

**What is collected**:
1. User interactions (impressions, clicks) → Google analytics
2. Page metadata (title, URL, favicon) → For note context
3. Selected text → User-initiated for note content
4. Images → User-initiated for note attachments
5. OAuth tokens → Standard Google authentication

**Where it goes**: All telemetry goes to `play.google.com/log` (Google's internal analytics). No third-party domains.

**Verdict**: ✅ All data collection is **legitimate and expected** for a Google product.

## False Positive Analysis

| Finding | Reason for False Positive | Evidence |
|---------|---------------------------|----------|
| `eval()` in app scripts | Google Closure Library JSON parsing legacy code | Standard Google library pattern |
| `Function.prototype.bind` checks | Closure Compiler polyfill detection | Feature detection, not dynamic execution |
| WASM binaries | Google Ink handwriting engine | Legitimate Google technology |
| Broad host permissions | Required for "save from any page" functionality | Explicitly excludes restricted pages |
| `innerHTML` assignments | All sanitized via Google SafeHtml | Proper use of security API |

## API Endpoints

| Domain | Purpose | Security Assessment |
|--------|---------|---------------------|
| `play.google.com/log` | Client telemetry/analytics | ✅ Official Google analytics |
| `googleapis.com/auth/client_channel` | OAuth scope | ✅ Google authentication |
| `googleapis.com/auth/cclog` | OAuth scope | ✅ Google logging |
| `googleapis.com/auth/memento` | OAuth scope | ✅ Google Memento API |
| `keep.google.com` | Main Keep application | ✅ Official Google Keep |
| `gstatic.com/keep/backgrounds/*` | UI assets (thumbnails) | ✅ Google CDN |
| `fonts.gstatic.com` | Icon assets | ✅ Google Fonts CDN |
| `www.google.com/images/cleardot.gif` | Tracking pixel | ✅ Standard Google analytics |

## Data Flow Summary

```
User Action (click extension icon / context menu)
  ↓
Background Script (validates URL, checks permissions)
  ↓
Content Script Injection (injector.js into current tab)
  ↓
Page Content Extraction (selection, images, metadata)
  ↓
Display Keep Popup (sandboxed iframe)
  ↓
User Edits Note
  ↓
OAuth Authentication (chrome.identity API)
  ↓
Save to Google Keep (keep.google.com via Google APIs)
  ↓
Analytics (play.google.com/log)
```

**Security Controls**:
- ✅ User-initiated actions only
- ✅ Sandboxed iframe for UI
- ✅ Proper OAuth flow
- ✅ CSP prevents remote code execution
- ✅ Excludes restricted pages

## Security Best Practices Compliance

| Practice | Status | Evidence |
|----------|--------|----------|
| Principle of Least Privilege | ✅ PASS | All permissions justified for functionality |
| Content Security Policy | ✅ PASS | No unsafe-eval, unsafe-inline, or remote scripts |
| Input Validation | ✅ PASS | SafeHtml API for HTML content |
| Secure Communication | ✅ PASS | All HTTPS endpoints, OAuth authentication |
| Sandboxing | ✅ PASS | iframe with proper sandbox attributes |
| No Remote Code Loading | ✅ PASS | All scripts bundled with extension |

## Overall Risk Assessment

**Risk Level**: **CLEAN**

### Rationale

1. **Official Google Product**: Extension is developed and maintained by Google's Keep engineering team (keep-eng@google.com)
2. **No Malicious Behavior**: Zero indicators of malware, data theft, or unauthorized access
3. **Appropriate Permissions**: All permissions are necessary and used only for intended functionality
4. **Secure Implementation**: Proper CSP, sandboxing, input validation, and OAuth flows
5. **Legitimate Endpoints**: All network communication goes to official Google infrastructure
6. **Large User Base**: 8 million users with 4.0 rating indicates trust and stability
7. **No Privacy Violations**: Data collection limited to what's necessary for note-taking features

### Justification for CLEAN Rating

While the extension requires broad permissions (`<all_urls>`, `scripting`, `tabs`), this is **completely justified** for a web clipper/note-taking extension that must:
- Capture content from any website
- Extract selected text and images
- Create notes from any web page

The extension demonstrates **exemplary security practices**:
- Explicit exclusion of sensitive pages (chrome://, webstore)
- User-initiated actions only (no background surveillance)
- Proper sandboxing and isolation
- Official Google authentication and infrastructure

This is a **legitimate, well-designed extension** from a trusted publisher serving its intended purpose without any malicious or deceptive behavior.

## Recommendations

None required. This extension follows Google's security best practices and poses no security risk to users.

## Conclusion

The Google Keep Chrome Extension is a **CLEAN, legitimate browser extension** with no security vulnerabilities or malicious behavior. All permissions and functionality align with its purpose as an official Google product for saving web content to Keep notes. Users can safely install and use this extension.

---

**Analysis Completed**: 2026-02-08
**Analyst**: Security Review Agent
**Final Verdict**: **CLEAN**
