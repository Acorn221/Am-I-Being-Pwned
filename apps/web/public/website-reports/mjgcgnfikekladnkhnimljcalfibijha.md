# Security Analysis Report: DocHub - Sign PDF from Gmail

## Extension Metadata
- **Extension ID**: mjgcgnfikekladnkhnimljcalfibijha
- **Extension Name**: DocHub - Sign PDF from Gmail
- **Version**: 2.4.0
- **User Count**: ~400,000
- **Primary Function**: PDF signing and editing integration for Gmail
- **Analysis Date**: 2026-02-06

## Executive Summary

DocHub is a **CLEAN** extension with legitimate functionality for PDF signing and editing within Gmail. The extension provides direct integration with the dochub.com platform to enable users to sign PDF attachments from Gmail and import PDFs from Chrome's built-in viewer.

**Overall Risk Level**: **CLEAN**

The extension follows security best practices with:
- Legitimate, narrowly-scoped permissions
- Origin validation for external messaging
- No data exfiltration or tracking behavior
- No malicious SDK injection
- Clean CSP policy
- Transparent functionality matching its stated purpose

No significant security vulnerabilities or privacy concerns were identified.

---

## Manifest Analysis

### Permissions Overview
```json
{
  "host_permissions": ["<all_urls>"],
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/mail/*"],
      "js": ["js/vendor.js", "js/continually-wait-until-exists.js", "js/cs-gmail.js"]
    },
    {
      "matches": ["*://*/*.pdf"],
      "js": ["js/vendor.js", "js/continually-wait-until-exists.js", "js/cs-pdf-viewer.js"],
      "all_frames": true
    },
    {
      "matches": ["https://dochub.com/*", "https://production.dochub.com/*", ...],
      "js": ["js/continually-wait-until-exists.js", "js/cs-dochub-website.js"],
      "run_at": "document_start"
    }
  ]
}
```

### Permission Justification
- **host_permissions: <all_urls>**: Required for PDF viewer content script to match `*://*/*.pdf` patterns
- **Gmail content script**: Adds "Open in DocHub" button to PDF attachments in Gmail
- **PDF viewer content script**: Injects "Open in DocHub" button on Chrome's built-in PDF viewer
- **DocHub website content script**: Injects extension UUID into meta tag for platform integration

### Content Security Policy
```
script-src 'self'; object-src 'self'; frame-src 'self' https://dochub.com https://staging.dochub.com https://testing.dochub.com https://*.google.com https://localhost:9292/ https://localhost:4200/
```
**Assessment**: Secure CSP with no unsafe-eval, no unsafe-inline, properly restricted frame sources.

### Externally Connectable
```json
{
  "matches": [
    "https://localhost:9292/*",
    "https://localhost:4200/*",
    "https://dochub.com/*",
    "https://production.dochub.com/*",
    "https://staging.dochub.com/*",
    "https://testing.dochub.com/*"
  ]
}
```
**Assessment**: Appropriately restricted to DocHub domains only. Localhost entries are for development.

---

## Background Service Worker Analysis

**File**: `/js/background.js` (2001 bytes, minified)

### Key Functionality

1. **File Caching System**
   - Implements in-memory cache (Map) for PDF file data
   - Messages: `set-cache-file`, `read-cache-file`, `delete-cache-file`
   - Used to temporarily store PDFs during import workflow

2. **External Message Handling**
   ```javascript
   chrome.runtime.onMessageExternal.addListener(((r, i, a) => {
     if (i.origin !== e.Config.HOST) {  // Validates origin === "https://dochub.com"
       const e = "DocHub Chrome Extension: unexpected origin";
       return console.error(e), void a({ error: e })
     }
     // ... handle messages from dochub.com
   }))
   ```
   **Security Note**: Proper origin validation prevents unauthorized websites from accessing extension functionality.

3. **Message Relay**
   - Relays `gmail-draft-created` and `close-dce-gmail-iframe` messages between DocHub website and Gmail content script
   - No sensitive data interception

### Network Communication
- **Domains**: All communication restricted to `https://dochub.com`
- **No tracking/analytics**: No third-party analytics, tracking pixels, or telemetry
- **No data exfiltration**: File data stays in memory cache, only sent to DocHub when user explicitly clicks import button

**Verdict**: Clean background script with appropriate security controls.

---

## Content Script Analysis

### 1. Gmail Integration (`cs-gmail.js`)

**Injection Pattern**: Runs on `https://mail.google.com/mail/*` at document_end

**Key Behavior**:
1. **Button Injection**
   - Polls for Gmail attachment elements (`.aZo.N5jrZb`) every 500ms
   - Injects DocHub button with logo alongside Gmail's native buttons
   - Extracts attachment metadata: filename, messageId, attachment ID

2. **Modal Creation**
   ```javascript
   // Creates modal iframe when user clicks "Open in DocHub"
   const iframe = document.createElement("iframe");
   iframe.src = chrome.runtime.getURL("blank.html") +
                `?targetDhUrl=${encodeURIComponent(URL)}`;
   ```
   - Modal contains iframe pointing to `blank.html` (extension page)
   - `blank.html` loads `dh-launcher.js` which creates nested iframe to DocHub
   - URL parameters: email, gmail_message_uuid, filename, extension UUID, attachment ID

3. **Email Extraction**
   ```javascript
   function a() {
     return document.querySelector("title")?.innerText
                    ?.match(/([\S]+@[\S]+)(\s\-\s[^@]+$)/)?.[1] ?? ""
   }
   ```
   **Privacy Note**: Extracts user's Gmail address from page title to pre-fill on DocHub platform.

4. **Message Handlers**
   - Listens for `gmail-draft-created` to navigate to draft after signing
   - Listens for `close-dce-gmail-iframe` to close modal

**Security Assessment**:
- No keylogging
- No password/credential harvesting
- No XHR/fetch hooking
- No unauthorized data exfiltration
- Email extraction is for legitimate UX (pre-filling user's own email)

### 2. PDF Viewer Integration (`cs-pdf-viewer.js`)

**Injection Pattern**: Runs on `*://*/*.pdf` in all frames at document_end

**Key Behavior**:
1. **Button Injection**
   - Polls for `embed[type="application/pdf"]` every 500ms
   - Injects "Open in DocHub" button overlay on PDF viewer

2. **PDF Download & Hash**
   ```javascript
   const response = yield fetch(document.location.href, {
     method: "GET",
     mode: "same-origin",
     cache: "default"
   });
   const blob = yield response.blob();
   // MD5 hash computation using SparkMD5 library
   const md5Hash = yield hashBlob(blob);
   const dataUrl = yield readAsDataURL(blob);
   ```
   - Downloads PDF from current URL via fetch
   - Computes MD5 hash for deduplication
   - Converts to data URL for caching

3. **File Size Validation**
   ```javascript
   if (dataUrl.length > 31457280) {  // ~30 MB
     return void alert("Oops. This file exceeds 30 MB...");
   }
   ```

4. **Cache & Redirect**
   - Sends PDF data to background script via `set-cache-file` message
   - Redirects to `https://dochub.com/import-file?cfk=...&dceUuid=...`
   - DocHub retrieves cached file via `chrome.runtime.sendMessage`

**Security Assessment**:
- Legitimate PDF import workflow
- No unauthorized network requests (only fetches current PDF URL)
- No data sent to third parties
- File size limits prevent abuse

### 3. DocHub Website Integration (`cs-dochub-website.js`)

**Injection Pattern**: Runs on DocHub domains at document_start

**Key Behavior**:
```javascript
document.querySelector("head")?.appendChild(document.createElement("meta"))
  .setAttribute("name", "dce-uuid")
  .setAttribute("content", chrome.runtime.id)
```
- Injects extension UUID into page as meta tag
- Allows DocHub website to detect extension presence and communicate via `chrome.runtime.sendMessage`

**Security Assessment**: Clean, minimal integration code.

### 4. Launcher (`dh-launcher.js`)

**Key Behavior**:
```javascript
document.addEventListener("DOMContentLoaded", () => {
  const iframe = document.createElement("iframe");
  iframe.src = new URLSearchParams(window.location.search).get("targetDhUrl") ?? "";
  document.body.appendChild(iframe);
});
```
- Loaded by `blank.html` extension page
- Reads `targetDhUrl` query parameter and creates iframe
- Used as iframe wrapper for DocHub import flow

**Security Assessment**: Simple iframe wrapper, no security concerns.

---

## Vendor Library Analysis

**File**: `js/vendor.js` (24,461 bytes)

**Contents**:
- **SparkMD5 library**: Standard MD5 hashing library (blueimp/JavaScript-MD5)
- **TypeScript helper functions**: `__awaiter`, `__generator`, `__extends` etc. (tslib polyfills)

**License**: ISC License (permissive open source)

**Security Assessment**: Legitimate, well-known libraries. No obfuscation or malicious code.

---

## Vulnerability Analysis

### Finding 1: Email Address Extraction from Gmail
- **Severity**: LOW (Informational)
- **File**: `js/cs-gmail.js` line 36
- **Code**:
  ```javascript
  return document.querySelector("title")?.innerText
           ?.match(/([\S]+@[\S]+)(\s\-\s[^@]+$)/)?.[1] ?? ""
  ```
- **Behavior**: Extracts user's email address from Gmail page title
- **Purpose**: Pre-fills email on DocHub platform for UX
- **Data Flow**: Email → URL parameter → DocHub platform
- **Verdict**: **ACCEPTABLE** - User's own email address for their own account, disclosed in context of service integration

### Finding 2: host_permissions: <all_urls>
- **Severity**: LOW (Informational)
- **File**: `manifest.json`
- **Justification**: Required for `*://*/*.pdf` content script pattern (PDF viewer injection)
- **Risk**: Extension has technical capability to access all websites, but code review shows no abuse
- **Actual Usage**: Only actively injects on Gmail and PDF pages
- **Verdict**: **ACCEPTABLE** - Technically necessary for advertised PDF viewer functionality

---

## False Positives

| Pattern | Location | Reason | Verdict |
|---------|----------|--------|---------|
| `fetch()` usage | `cs-pdf-viewer.js:48` | Fetching current PDF URL for import (same-origin) | FALSE POSITIVE |
| InboxSDK reference | `cs-gmail.js:118` | Checking for InboxSDK modal classes to avoid conflicts | FALSE POSITIVE |
| Email extraction | `cs-gmail.js:36` | User's own email for UX pre-fill | FALSE POSITIVE |
| `chrome.runtime.id` | Multiple files | Extension UUID for platform integration, not fingerprinting | FALSE POSITIVE |

---

## API Endpoints & Data Flow

### Endpoints

| Domain | Purpose | Data Sent | Method |
|--------|---------|-----------|--------|
| `https://dochub.com/import-gmail-attachment` | Import PDF from Gmail | email, gmail_message_uuid, filename, dceUuid, attid, appSource timestamp | GET (URL params) |
| `https://dochub.com/import-file` | Import PDF from viewer | cfk (cache key), dceUuid | GET (URL params) |

### Data Flow Summary

**Gmail → DocHub Import Flow**:
1. User clicks DocHub button on Gmail attachment
2. Extension extracts: email, message ID, filename, attachment ID
3. Opens modal iframe to DocHub with parameters
4. DocHub downloads attachment directly from Gmail (user authenticated)
5. Extension closes modal, navigates to draft (if signing workflow)

**PDF Viewer → DocHub Import Flow**:
1. User clicks "Open in DocHub" on PDF
2. Extension fetches PDF blob from current URL
3. Computes MD5 hash, converts to data URL
4. Caches in background script memory
5. Redirects to DocHub with cache key
6. DocHub retrieves cached file via `chrome.runtime.sendMessage`
7. Background script deletes cache after retrieval

**No Third-Party Data Sharing**: All data flows directly to DocHub platform (first-party service).

---

## Attack Surface Assessment

### Extension Enumeration / Killing
- **Status**: NOT PRESENT
- No `chrome.management` API usage
- No extension enumeration behavior

### XHR/Fetch Hooking
- **Status**: NOT PRESENT
- No `XMLHttpRequest.prototype.send` patching
- No `window.fetch` hooking
- Legitimate fetch() call for same-origin PDF download only

### Residential Proxy Infrastructure
- **Status**: NOT PRESENT
- No proxy configuration
- No network request interception

### Remote Config / Kill Switches
- **Status**: NOT PRESENT
- No remote configuration loading
- No server-controlled behavior changes
- Hardcoded backend: `https://dochub.com`

### Market Intelligence SDKs
- **Status**: NOT PRESENT
- No Sensor Tower Pathmatics
- No ad-finder or tracking SDKs
- No conversation scraping

### AI Conversation Scraping
- **Status**: NOT PRESENT
- No ChatGPT/Claude/Gemini platform targeting
- No content extraction from AI platforms

### Ad/Coupon Injection
- **Status**: NOT PRESENT
- No ad insertion
- No coupon engines
- No search result manipulation

### Cookie/Credential Harvesting
- **Status**: NOT PRESENT
- No `chrome.cookies` API usage
- No password field monitoring
- No keylogging (no keydown/keypress listeners)

### Dynamic Code Execution
- **Status**: NOT PRESENT
- No `eval()` usage
- No `Function()` constructor
- No `innerHTML` with user input
- Clean minified code only

---

## Privacy Analysis

### Data Collection
- **Email Address**: Extracted from Gmail title, sent to DocHub (first-party)
- **Gmail Message IDs**: Used for attachment linking and draft navigation
- **Extension UUID**: Sent to DocHub for platform integration
- **PDF Files**: Temporarily cached in memory, sent to DocHub on user action

### Third-Party Sharing
- **None**: All data flows to DocHub (first-party service)
- No analytics platforms
- No tracking pixels
- No external SDKs

### User Consent
- Extension purpose is transparent (PDF signing service)
- Data sharing with DocHub is implicit in service model
- No dark patterns or pre-checked consent boxes

---

## Code Quality & Obfuscation

### Minification
- Code is **minified** (webpack bundled) but **NOT obfuscated**
- Variable names are short (`e`, `t`, `r`) due to minification, not intentional obfuscation
- Control flow is straightforward
- No string encoding, dead code injection, or anti-analysis techniques

### Build Tooling
- **Webpack**: Modern bundler for code splitting
- **TypeScript**: Type-safe development (tslib helpers present)
- Standard professional development practices

---

## Overall Risk Rating: CLEAN

### Risk Breakdown
- **Critical Risks**: 0
- **High Risks**: 0
- **Medium Risks**: 0
- **Low Risks**: 0 (informational findings only)
- **False Positives**: 4

### Summary
DocHub - Sign PDF from Gmail is a **legitimate productivity extension** with clean security posture. The extension:

- Implements its advertised functionality (PDF signing in Gmail) without hidden behavior
- Uses appropriate security controls (origin validation, CSP, permission scoping)
- Does not collect unnecessary data or share with third parties
- Contains no malicious SDKs, tracking, or data exfiltration
- Follows modern development best practices

**Recommendation**: **SAFE FOR USE**. No security concerns identified.

---

## Comparison to Known Malicious Patterns

Based on project memory of malicious VPN extensions analyzed:

| Malicious Pattern | DocHub Status |
|-------------------|---------------|
| Extension enumeration/killing (VeePN, Troywell, Urban VPN) | ✅ NOT PRESENT |
| XHR/fetch hooking for data harvesting (Urban VPN, StayFree, StayFocusd) | ✅ NOT PRESENT |
| Market intelligence SDKs (Sensor Tower Pathmatics) | ✅ NOT PRESENT |
| AI conversation scraping (StayFree, Flash Copilot) | ✅ NOT PRESENT |
| Ad/coupon injection (YouBoost, Troywell) | ✅ NOT PRESENT |
| Remote config kill switches (Troywell "thanos", YouBoost) | ✅ NOT PRESENT |
| GA proxy exclusion for IP tracking (VeePN) | ✅ NOT PRESENT |
| Session token reuse (Flash Copilot ChatGPT tokens) | ✅ NOT PRESENT |

DocHub exhibits **NONE** of the malicious patterns found in suspect VPN extensions.

---

## Technical Details

### File Manifest
```
/js/background.js           (2,001 bytes)  - Background service worker
/js/cs-gmail.js             (5,728 bytes)  - Gmail content script
/js/cs-pdf-viewer.js        (8,319 bytes)  - PDF viewer content script
/js/cs-dochub-website.js    (2,581 bytes)  - DocHub website integration
/js/dh-launcher.js          (250 bytes)    - Iframe launcher
/js/vendor.js               (24,461 bytes) - SparkMD5 + tslib
/js/continually-wait-until-exists.js (0 bytes) - Empty file
```

### Chrome API Usage
- `chrome.runtime.onInstalled` - Installation logging
- `chrome.runtime.onMessage` - Internal messaging
- `chrome.runtime.onMessageExternal` - DocHub website messaging (origin-validated)
- `chrome.runtime.getURL()` - Web accessible resource URLs
- `chrome.runtime.id` - Extension UUID
- `chrome.tabs.sendMessage()` - Tab messaging relay

**No sensitive APIs**: No cookies, storage, webRequest, management, or proxy APIs.

---

## Appendix: Code Snippets

### Origin Validation (background.js)
```javascript
chrome.runtime.onMessageExternal.addListener(((r, i, a) => {
  if (i.origin !== e.Config.HOST) {  // "https://dochub.com"
    const e = "DocHub Chrome Extension: unexpected origin";
    return console.error(e), void a({ error: e })
  }
  // ... authorized message handling
}))
```

### PDF Import Workflow (cs-pdf-viewer.js)
```javascript
// 1. Fetch PDF blob
const response = yield fetch(document.location.href, {
  method: "GET",
  mode: "same-origin",
  cache: "default"
});
const blob = yield response.blob();

// 2. Hash & encode
const md5Hash = yield hashBlob(blob);
const dataUrl = yield readAsDataURL(blob);

// 3. Cache in background
const message = {
  type: "set-cache-file",
  cachedFileKey: `cached-pdf-${md5Hash}`,
  data: { md5Hash, dataUrl, url }
};
chrome.runtime.sendMessage(message, () => {
  // 4. Redirect to DocHub
  document.location.href = "https://dochub.com/import-file?cfk=...&dceUuid=...";
});
```

---

**Analysis Completed**: 2026-02-06
**Analyst**: Claude Opus 4.6 (Automated Security Analysis)
**Confidence Level**: High (comprehensive code review completed)
