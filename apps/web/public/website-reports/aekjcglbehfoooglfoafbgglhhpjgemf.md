# Smart Copy Link - Security Analysis Report

## Extension Metadata
- **Extension Name**: Smart Copy Link
- **Extension ID**: aekjcglbehfoooglfoafbgglhhpjgemf
- **Version**: 1.0.2
- **User Count**: ~10,000 users
- **Manifest Version**: 3

## Executive Summary

Smart Copy Link is a productivity extension that allows users to copy tab links, parse links from web pages, and export them in various formats. The extension has **minimal security concerns** with appropriate permissions for its functionality. The only notable finding is telemetry data sent to a third-party domain during feedback submission, which is part of the intended feedback feature and includes appropriate metadata. No malicious behavior, code injection, or privacy violations were identified.

**Overall Risk Level**: **CLEAN**

## Manifest Analysis

### Permissions
```json
"permissions": [
  "bookmarks",
  "tabs",
  "storage"
],
"host_permissions": ["*://*/*"]
```

**Assessment**:
- `bookmarks`: Used for "Add to Bookmark" feature (legitimate)
- `tabs`: Required to query and copy tab URLs/titles (legitimate)
- `storage`: Used for user settings persistence (legitimate)
- `host_permissions`: Required for content scripts to work on all pages (necessary for link extraction)

### Content Security Policy
No custom CSP defined - uses default Manifest V3 policy.

### Background Service Worker
- Single background script: `background.js`
- No persistent background page
- Message-based communication with content scripts

## Vulnerability Analysis

### 1. Third-Party Data Transmission (LOW)

**Severity**: LOW
**Location**: `feedback/feedback.js:4916`
**Type**: Telemetry/Analytics

**Code**:
```javascript
Ji().post("https://extensions.extfun.com/api/soutu/feedback", l);
```

**Details**:
The extension sends feedback data to `extensions.extfun.com` when users submit feedback through the feedback form. The data includes:
- User email address (provided voluntarily)
- Feedback message (provided voluntarily)
- Extension version
- User agent string
- Browser language
- Screenshots (if uploaded by user)

**Verdict**: **FALSE POSITIVE / NOT MALICIOUS**
- This is part of the explicit "Leave Feedback" feature visible to users
- Users voluntarily provide email and message content
- The extension clearly prompts for feedback in the UI (messages.json confirms this)
- No sensitive data (passwords, cookies, browsing history) is collected
- Data transmission only occurs when user actively clicks "Send" in feedback form

### 2. Host Permissions Analysis

**Severity**: N/A
**Type**: Permission Scope

The extension declares `*://*/*` host permissions to inject content scripts on all pages. This is necessary for the core functionality:
- Link extraction from any webpage
- Area selection for bulk link copying
- Hover-to-copy functionality

**Verdict**: **CLEAN**
- Permissions match the stated functionality
- Content scripts only interact with DOM links (href attributes, titles)
- No sensitive data harvesting detected in content scripts

### 3. Content Script Behavior

**Files Analyzed**:
- `content/content.js` - Area selection and link extraction
- `content/ctrlcCopy.js` - Hover-to-copy functionality
- `content/jquery-2.0.3.min.js` - jQuery library (v2.0.3)

**Behavior**:
- Draws selection boxes on pages (visual feedback)
- Extracts link URLs and titles within selected area
- Implements keyboard shortcuts (Ctrl+Z + mouse drag)
- Auto-selects link on hover for quick copying
- Uses jQuery for DOM manipulation (standard library usage)

**Verdict**: **CLEAN**
- No keylogging, form interception, or credential harvesting
- No XHR/fetch hooks or proxy behavior
- No cookie access or local storage scraping beyond extension settings
- No ad injection or DOM manipulation beyond selection UI

### 4. Dynamic Code Execution Check

**Patterns Searched**:
- `eval()` - Found only in jQuery library (standard usage)
- `Function()` - Found only in Vue.js framework code (standard usage)
- `atob()` - Browser feature detection in Vue.js
- `fromCharCode()` - jQuery string parsing (standard)

**Verdict**: **CLEAN**
- No malicious obfuscation detected
- All dynamic code is from legitimate libraries (jQuery 2.0.3, Vue.js)
- No runtime code generation for malicious purposes

### 5. Network Activity Analysis

**API Endpoints Identified**:
| Endpoint | Purpose | Data Sent | Risk |
|----------|---------|-----------|------|
| `https://extensions.extfun.com/api/soutu/feedback` | User feedback submission | Email, message, version, UA, language, screenshots | LOW - Opt-in only |

**Verdict**: **CLEAN**
- Only one external endpoint (feedback)
- No data exfiltration to command & control servers
- No residential proxy infrastructure
- No market intelligence SDKs detected
- No analytics or tracking scripts beyond feedback

### 6. innerHTML Usage Analysis

**Severity**: N/A
**Type**: DOM Manipulation

Multiple uses of `innerHTML` detected, primarily in:
- jQuery library (DOM creation)
- Vue.js framework (template rendering)
- Content script (selection box rendering)

**Verdict**: **FALSE POSITIVE**
- All innerHTML usage is framework-standard (jQuery, Vue.js)
- No user-controlled input directly inserted via innerHTML
- Content script creates static UI elements only

## False Positive Summary

| Pattern | Location | Reason |
|---------|----------|--------|
| `eval()` | jquery-2.0.3.min.js | Standard jQuery library usage |
| `Function()` | opentab/opentab.js, Vue.js | Vue.js template compilation |
| `innerHTML` | Multiple files | jQuery/Vue.js DOM rendering |
| `Authorization` header | feedback.js | Axios HTTP library (not used) |
| `password` field | jquery-2.0.3.min.js | jQuery form type enumeration |
| Network call | feedback.js | Legitimate feedback feature |

## API Endpoints Table

| Endpoint | Method | Purpose | Data Transmitted | Trigger |
|----------|--------|---------|------------------|---------|
| `https://extensions.extfun.com/api/soutu/feedback` | POST | Feedback submission | email, msg, version, ua, lang, screenshots | User clicks "Send" in feedback form |

## Data Flow Summary

### Data Collection
- **Tab URLs/Titles**: Read from chrome.tabs API (stays local, copied to clipboard)
- **Webpage Links**: Extracted from page DOM (stays local, copied to clipboard)
- **User Settings**: Stored in chrome.storage.local (format preferences, shortcuts, colors)
- **Feedback Data**: Collected only when user submits feedback form

### Data Storage
- All user preferences stored locally via chrome.storage.local
- No IndexedDB usage
- No external cookies set

### Data Transmission
- **Feedback only**: Sent to extfun.com when user explicitly submits feedback
- No background telemetry
- No tracking pixels
- No third-party analytics

### Clipboard Operations
- Extension copies extracted links to system clipboard
- User-initiated action only (click "Copy" button)

## Chrome API Usage

| API | Purpose | Risk Level |
|-----|---------|------------|
| chrome.tabs.query | Get tab URLs/titles for copying | Low (appropriate) |
| chrome.tabs.create | Open new tab with extension page | Low (UI feature) |
| chrome.tabs.sendMessage | Communicate with content script | Low (standard) |
| chrome.runtime.sendMessage | Background-content communication | Low (standard) |
| chrome.storage.local | Store user preferences | Low (appropriate) |
| chrome.bookmarks | Add copied links to bookmarks | Low (feature) |
| chrome.runtime.getManifest | Get version for feedback | Low (metadata) |

## Overall Security Assessment

### Strengths
1. Manifest V3 compliance (modern security model)
2. Minimal permissions for stated functionality
3. No sensitive data collection or exfiltration
4. Transparent feedback mechanism
5. Local-only processing of links
6. No obfuscation or anti-analysis techniques
7. No extension enumeration or killing behavior
8. No proxy infrastructure or market intelligence SDKs

### Weaknesses
1. Very broad host permissions (`*://*/*`) - could be scoped down, but necessary for functionality
2. Third-party domain dependency (extfun.com) for feedback - minor privacy concern
3. Uses older jQuery version (2.0.3) - potential security updates available

### Privacy Considerations
- Extension can read all webpage links on every page (necessary for functionality)
- Feedback feature sends data to third party (user-initiated, transparent)
- No background data collection
- No tracking or profiling

## Risk Level: CLEAN

**Justification**:
Smart Copy Link performs its stated function (copying and managing webpage/tab links) without malicious behavior. While it requires broad permissions and makes one network call to a third-party domain, these are appropriate for the extension's functionality:

1. **Host permissions** are necessary to extract links from any webpage
2. **Network call** only occurs during user-initiated feedback submission
3. **No data harvesting**: Extension doesn't collect browsing history, credentials, or sensitive data
4. **No injection attacks**: No ad injection, coupon injection, or malicious content insertion
5. **No suspicious behavior**: No extension enumeration, XHR hooking, or proxy infrastructure

The extension serves its intended purpose (link management/copying) without side effects or hidden functionality. The feedback feature is transparent and opt-in.

## Recommendations

1. **For Users**: Safe to use. Be aware that feedback submissions are sent to extfun.com.
2. **For Developers**: Consider updating jQuery to latest version for security patches.
3. **For Store Review**: Extension is clean and functions as advertised.

---

**Analysis Date**: 2026-02-07
**Analyst**: Claude Sonnet 4.5
**Analysis Method**: Static code analysis, manifest review, network behavior analysis
