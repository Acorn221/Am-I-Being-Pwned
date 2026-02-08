# Vulnerability Assessment Report: Zoho Meeting Extension

## Extension Metadata
- **Extension Name**: Zoho Meeting
- **Extension ID**: ajnmfincdldfcodgpglmolicgglkdeof
- **Version**: 1.3.4
- **Approximate Users**: ~20,000
- **Manifest Version**: 3
- **Analysis Date**: 2026-02-07

## Executive Summary

Zoho Meeting is a legitimate Chrome extension developed by Zoho Corporation for web conferencing. The extension provides screen sharing capabilities, meeting management, and integration with Zoho's meeting platform.

**Primary Functionality**: The extension enables users to:
- Share screen/window for Zoho Meeting sessions
- Schedule and start meetings/webinars
- View upcoming meetings and webinars
- Quick access to Zoho Meeting features

**Security Posture**: The extension demonstrates good security practices with limited permissions, proper scope restriction to Zoho domains only, and legitimate functionality. All network calls are restricted to Zoho's infrastructure. No malicious behavior or vulnerabilities were identified.

**Overall Risk Level**: **CLEAN**

## Manifest Analysis

### Permissions Review
```json
"permissions": ["cookies"]
"host_permissions": [
  "https://*.zoho.com/*",
  "https://*.zoho.eu/*",
  "https://*.zoho.in/*",
  "https://*.zoho.com.au/*",
  "https://*.zoho.com.cn/*",
  "https://*.zoho.jp/*",
  "https://*.zohocloud.ca/*",
  "https://*.zoho.sa/*",
  "https://*.zohohq.in/*",
  "https://*.zoho.sg/*"
]
```

**Assessment**:
- ✅ Minimal permissions requested (only cookies)
- ✅ Host permissions strictly scoped to Zoho domains across regional variations
- ✅ No broad host permissions or excessive API access
- ✅ Appropriate for stated functionality

### Content Security Policy
- **CSP**: Not explicitly defined (uses MV3 defaults)
- **Verdict**: ACCEPTABLE - MV3 provides secure defaults

### Externally Connectable
```json
"externally_connectable": {
  "matches": [
    "https://*.zoho.com/*",
    "https://*.zoho.eu/*",
    // ... (all regional Zoho domains)
  ]
}
```

**Assessment**:
- ✅ Properly restricted to Zoho domains only
- ✅ Prevents arbitrary websites from communicating with extension
- ✅ Regional domain coverage appropriate for global service

## Code Analysis

### Background Script (background.mjs)

#### Screen Sharing Functionality
**Location**: Lines 7-99

**Purpose**: Handles Chrome Desktop Capture API for screen/window sharing

**Key Functions**:
1. `onMessageExternal` listener - Responds to screen sharing requests from Zoho websites
2. `getSourceID()` - Requests desktop capture via `chrome.desktopCapture.chooseDesktopMedia()`
3. `requestScreenSharing()` - Handles internal port-based screen sharing requests

**Security Assessment**:
- ✅ Only accepts messages from externally_connectable domains (Zoho websites)
- ✅ Uses official Chrome Desktop Capture API properly
- ✅ No dynamic code execution
- ✅ Proper origin validation through manifest constraints
- ✅ User must manually approve each screen share request via browser dialog

**Verdict**: SAFE - Standard implementation of Chrome screen sharing API with proper restrictions

#### Cookie Access for Authentication
**Location**: Lines 109-152

**Purpose**: Checks which Zoho domain the user is logged into by reading authentication cookies

```javascript
function getLoggedinDomain(callback) {
  for (var i = 0; i < SUPPORTED_DOMAINS.length; i++) {
    var domain = SUPPORTED_DOMAINS[i];
    domainIterator(domain, callback);
  }
}

function domainIterator(domain, callback) {
  chrome.cookies.get({ "url": SERVICE.ACCOUNTS + domain, "name": TICKET_NAME.IAM_ADT }, function(cookie) {
    chrome.cookies.get({ "url": SERVICE.ACCOUNTS + domain, "name": TICKET_NAME.IAM_BDT }, function(cookie) {
      if (cookie != null) {
        loginedDomain.push(domain);
      }
      // ...
    });
  });
}
```

**Security Assessment**:
- ✅ Only reads cookies from Zoho domains (accounts.zoho.*)
- ✅ Checks for specific authentication cookies (_iamadt, _iambdt)
- ✅ Used to determine which regional Zoho domain to connect to
- ✅ Does not exfiltrate cookies to third parties
- ✅ Legitimate use case for multi-region authentication

**Verdict**: SAFE - Appropriate use of cookie permission for auth state detection

#### Tab Management
**Location**: Lines 100-107

**Purpose**: Opens new tabs for Zoho Meeting URLs

```javascript
chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    if( request.message === "open_new_tab" ) {
      chrome.tabs.create({"url": request.url});
    }
  }
);
```

**Security Assessment**:
- ⚠️ No explicit URL validation in this code block
- ✅ However, only called from popup.js with hardcoded Zoho URLs
- ✅ No user-controlled input flows to this function

**Verdict**: SAFE - Internal use with controlled URLs

### Content Script (content.js)

**Location**: All 30 lines

**Purpose**: Message relay between web pages and extension background script for screen sharing

**Functionality**:
- Creates port connection to background script
- Relays screen sharing messages via window.postMessage
- Validates message source is the current window

**Security Assessment**:
- ✅ Only injected into Zoho domains (per manifest)
- ✅ Message source validation: `if (event.source != window) return;`
- ✅ Only relays specific message types (SS_ZM_UI_REQUEST, SS_ZM_UI_CANCEL)
- ✅ No DOM manipulation or data extraction
- ✅ No eval or dynamic code execution

**Verdict**: SAFE - Proper message relay with validation

### Popup Script (chrome-popup.js)

**Location**: 365 lines

**Purpose**: Extension popup UI for managing meetings/webinars

**Key Functionality**:
1. Fetches logged-in domain via background script
2. Retrieves user details and upcoming meetings/webinars
3. Displays UI with meeting list
4. Opens Zoho Meeting pages in new tabs

**Network Calls**:
All API calls are made to Zoho domains via jQuery AJAX:

```javascript
var DOMAIN = {
  meeting: "https://meetinglab.",  // + domain
  loginPage: "https://meeting.zoho.com/login.do",
  accounts:"https://accounts.zoho.com"
}

function apiGetMeeting(params, url, done, fail, always){
  $.ajax({
    url: url,
    data: params
  }).done(done).fail(fail).always(always);
}
```

**Endpoints Called**:
- `/api/v0/currentUser.json` - Get user details
- `/meeting/api/v0/extensionURLS` - Get extension URLs
- `/api/v0/{zsoid}/sessionList.json` - Get meeting/webinar lists
- Various meeting/webinar detail pages

**Security Assessment**:
- ✅ All URLs hardcoded to Zoho infrastructure
- ✅ No third-party API calls
- ✅ No dynamic URL construction from user input
- ✅ Standard jQuery AJAX without credentials manipulation
- ✅ No XHR/fetch hooking
- ✅ No credential harvesting

**DOM Manipulation**:
```javascript
function listSessions(isWebinar, sessionList) {
  sessionList.forEach(function(session){
    var topicElem = document.createElement("p");
    topicElem.innerText = session.topic;  // Safe - uses innerText not innerHTML
    // ...
  });
}
```

- ✅ Uses `document.createElement()` and `.innerText` - safe from XSS
- ✅ No use of `.innerHTML` with user data
- ✅ No script injection vectors

**Verdict**: SAFE - Legitimate Zoho Meeting integration with proper security practices

### Utility Script (util.js)

**Location**: 37 lines

**Purpose**: Constants and API helper function

**Security Assessment**:
- ✅ Only defines constants and wrapper function
- ✅ No dynamic code or suspicious patterns

**Verdict**: SAFE

### Third-Party Library (jquery-3.2.1.min.js)

**Version**: 3.2.1 (Released March 2017)

**Security Notes**:
- ⚠️ jQuery 3.2.1 is outdated (current is 3.7.x)
- Known CVE: CVE-2020-11022 (XSS in htmlPrefilter) - **However, extension does not use vulnerable patterns**
- Extension uses safe DOM methods (`.text()`, `.append()` with elements)

**Verdict**: LOW RISK - Outdated library but not exploited in this codebase

### UI Scroll Library (ui.zscroll.js)

**Purpose**: Custom scrollbar implementation

**Security Assessment**:
- ✅ Standard jQuery UI widget pattern
- ✅ No network calls or external communication
- ✅ Pure UI functionality

**Verdict**: SAFE

## Threat Assessment

### ❌ Extension Enumeration/Killing
**Status**: NOT PRESENT
- No code attempts to detect or disable other extensions

### ❌ XHR/Fetch Hooking
**Status**: NOT PRESENT
- No manipulation of native browser APIs
- No monkey-patching of XMLHttpRequest or fetch

### ❌ Residential Proxy Infrastructure
**Status**: NOT PRESENT
- No proxy-related code
- No traffic routing or relay mechanisms

### ❌ Remote Config/Kill Switches
**Status**: NOT PRESENT
- No remote configuration loading
- No kill switch mechanism
- Extension behavior is static

### ❌ Market Intelligence SDKs
**Status**: NOT PRESENT
- No Sensor Tower, Pathmatics, or similar SDKs detected
- No analytics beyond Zoho's own services

### ❌ AI Conversation Scraping
**Status**: NOT PRESENT
- No DOM scraping or content extraction from other sites
- Only operates on Zoho domains

### ❌ Ad/Coupon Injection
**Status**: NOT PRESENT
- No content injection into web pages
- Content script only relays messages

### ❌ Keylogging
**Status**: NOT PRESENT
- No keyboard event listeners
- No input field monitoring

### ❌ Cookie Harvesting/Exfiltration
**Status**: NOT PRESENT (Benign Use Only)
- Cookie access limited to reading Zoho auth cookies
- Used only to determine logged-in domain
- No exfiltration to third parties

### ❌ Obfuscation
**Status**: NOT PRESENT
- Code is readable and well-commented
- No minification beyond jQuery library
- No string encoding or obfuscation techniques

## False Positives

| Pattern | Location | Classification | Reason |
|---------|----------|----------------|--------|
| `chrome.cookies.get()` | background.mjs:122-123 | BENIGN | Reading own service auth cookies to determine user's regional domain |
| jQuery 3.2.1 | jquery-3.2.1.min.js | LOW RISK | Outdated library but not exploited; only safe methods used |
| `window.postMessage` | content.js:14, 28 | BENIGN | Standard cross-context messaging for screen sharing API |
| Dynamic DOM creation | chrome-popup.js:267-297 | BENIGN | Uses safe methods (.createElement, .innerText) |

## API Endpoints

All endpoints are Zoho-owned infrastructure:

| Endpoint | Purpose | Method | Data Sent |
|----------|---------|--------|-----------|
| `https://accounts.zoho.{domain}` | Check auth cookies | Cookie Read | N/A (read only) |
| `https://meetinglab.zoho.{domain}/api/v0/currentUser.json` | Get user details | GET | None |
| `https://meetinglab.zoho.{domain}/meeting/api/v0/extensionURLS` | Get extension config | GET | None |
| `https://meetinglab.zoho.{domain}/api/v0/{zsoid}/sessionList.json` | Get meeting/webinar list | GET | count, index, zuid, sessionType, listtype |
| `https://meetinglab.zoho.{domain}/meeting-start` | Start meeting | Navigation | src=chrome_extension |
| `https://meeting.zoho.com/login.do` | Login page | Navigation | None |

**Assessment**:
- ✅ All endpoints are Zoho-owned
- ✅ No third-party data collection
- ✅ No tracking or analytics services
- ✅ HTTPS only

## Data Flow Summary

1. **Extension Installation**
   - Requests cookie permission and Zoho host permissions
   - No immediate data collection

2. **Popup Activation**
   - Queries Zoho auth cookies across regional domains
   - Connects to user's active Zoho domain
   - Fetches user details and meeting list from Zoho API
   - Displays in popup UI

3. **Screen Sharing**
   - Zoho website requests screen share via `onMessageExternal`
   - Extension triggers Chrome's native desktop capture dialog
   - User approves/denies in browser UI
   - Stream ID returned to Zoho website if approved

4. **Data Destinations**
   - All data stays within Zoho infrastructure
   - No third-party services
   - No external analytics

## Overall Risk Assessment

**RISK LEVEL**: **CLEAN**

### Justification

**Legitimate Functionality**:
- Extension serves its stated purpose: Zoho Meeting integration
- All features directly support video conferencing workflow
- No hidden or deceptive functionality

**Security Strengths**:
- Minimal permission footprint (only cookies)
- Properly scoped to Zoho domains exclusively
- Uses official Chrome APIs correctly (desktopCapture)
- No dynamic code execution
- No obfuscation
- No third-party data collection
- Proper message source validation

**Minor Concerns (Non-Critical)**:
- jQuery 3.2.1 is outdated, but not exploited in this codebase
- Could benefit from dependency updates

**Privacy Assessment**:
- Cookie access limited to Zoho auth cookies for legitimate auth state detection
- No tracking across non-Zoho sites
- No PII collection beyond what user provides to Zoho Meeting service
- Data handling consistent with Zoho's privacy policy

### Recommendation

**VERDICT**: CLEAN - Safe for use

This extension is a legitimate tool from Zoho Corporation with appropriate security controls. It demonstrates good security practices including:
- Minimal permissions
- Strict domain scoping
- No third-party communication
- Proper use of Chrome APIs
- Transparent functionality

**Suggested Improvements**:
1. Update jQuery to latest 3.x version (3.7.x) to eliminate potential CVE exposure
2. Add explicit URL validation in tab creation handler
3. Consider adding subresource integrity checks for external resources (Google Fonts)

**No security remediation required.**
